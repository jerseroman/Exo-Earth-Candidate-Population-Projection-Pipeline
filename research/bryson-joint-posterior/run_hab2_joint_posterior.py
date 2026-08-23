#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from the Bryson DR25 occurrence implementation identified in
# MODIFICATIONS_BRYSON.md. Roman Jerše's modifications remain under GPL-2.0-only.
# Modified by Roman Jerše on 2026-08-21; see MODIFICATIONS_BRYSON.md.
"""Re-run the Bryson et al. Model-1 hab2 joint posterior.

This is a clean, seeded implementation of the public notebook
``insolation/computeOccurrencefixedTeff_uncertainty.ipynb`` from
``stevepur/DR25-occurrence-public`` at commit
``d200f54b6f0df49e0dae530e69983cdce5397bfb``.

The source notebook pools MCMC samples over reliability/measurement-error
realisations.  This runner can either preserve the notebook's measurement-error
construction exactly or use the v4 quantile-matched two-sided correction.  It
records the selected mode, random seed, trial-level diagnostics, a complete
post-perturbation domain audit, input checksums, and source-versus-manuscript
parameter ordering.

Important parameter-order convention
------------------------------------
The Bryson implementation stores theta as::

    [F0, beta_inst, alpha_radius, gamma]

although internal local variable names in ``rateModels3D.py`` are reversed for
its two spatial exponents.  Output tables additionally provide manuscript
order::

    [F0, alpha_radius, beta_inst, gamma]

This runner does not treat independently sampled marginal summaries as a joint
posterior and does not combine the constant- and zero-completeness branches.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

import emcee
import numpy as np
import pandas as pd
from astropy.io import fits
from scipy.interpolate import interp2d
from scipy.optimize import minimize

from measurement_error import (
    LEGACY_SOURCE_MIXTURE,
    MEASUREMENT_ERROR_MODES,
    measurement_error_metadata,
    perturb_planets,
)
from mcmc_convergence import run_production_chain

BRYSON_COMMIT = "d200f54b6f0df49e0dae530e69983cdce5397bfb"
PUBLISHED = {
    "constant": {
        "F0": 1.107,
        "alpha": -1.082,
        "beta": -0.839,
        "gamma": -2.671,
    },
    "zero": {
        "F0": 1.590,
        "alpha": -1.175,
        "beta": -1.195,
        "gamma": -1.376,
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.floating, np.integer)):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def lnlike(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    """Poisson log-likelihood copied from the public notebook."""
    theta = np.asarray(theta, dtype=float)
    norm = 0.0
    with np.errstate(all="ignore"):
        for index in range(cs.nTemp):
            rate = model.rateModel(
                cs.period2D,
                cs.rp2D,
                np.asarray(teff_means[index]),
                cs.periodRange,
                cs.rpRange,
                cs.tempRange,
                theta,
            )
            population = rate * sum_comp[:, :, index]
            population = 0.5 * (population[:-1, :-1] + population[1:, 1:])
            norm += float(np.sum(population * cs.vol2D))

        point_rate = model.rateModel(
            np.asarray(koi_flux),
            np.asarray(koi_radius),
            np.asarray(koi_teff),
            cs.periodRange,
            cs.rpRange,
            cs.tempRange,
            theta,
        )
        result = float(np.sum(np.log(point_rate)) - norm)
    return result if np.isfinite(result) else -np.inf


def lnprior(theta, model):
    bounds = model.getBounds()
    for value, (lower, upper) in zip(theta, bounds):
        if lower > value or value >= upper:
            return -np.inf
    # The public notebook returns 1.0 rather than 0.0; retain it because the
    # additive constant does not alter the posterior.
    return 1.0


def lnprob(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    prior = lnprior(theta, model)
    if not np.isfinite(prior):
        return -np.inf
    return prior + lnlike(
        theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model
    )


def nll(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    value = lnlike(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model)
    return -value if np.isfinite(value) else 1.0e15


def load_completeness(path: Path, cs):
    with fits.open(path, memmap=False) as hdulist:
        cumulative = np.asarray(hdulist[0].data)
        header = hdulist[0].header
        prob_teff = cumulative[3:, :, :]

        n_period = int(header["NPER"])
        n_radius = int(header["NRP"])
        max_flux = float(header["MAXFLX"])
        min_flux = float(header["MINFLX"])
        min_radius = float(header["MINRP"])
        max_radius = float(header["MAXRP"])
        n_teff = int(header["NTEFF"])
        mean_teff = np.array(
            [float(header[f"MEANT{index}"]) for index in range(n_teff)],
            dtype=float,
        )

    flux_grid = np.linspace(max_flux, min_flux, n_period)
    radius_grid = np.linspace(min_radius, max_radius, n_radius)
    summed_teff = np.zeros((cs.nPeriod, cs.nRp, n_teff), dtype=float)
    for index in range(n_teff):
        # scipy.interp2d is intentionally retained under a pinned SciPy version
        # to match the source notebook's interpolation convention.
        interpolator = interp2d(flux_grid, radius_grid, prob_teff[index, :, :])
        summed_teff[:, :, index] = np.transpose(
            interpolator(cs.period1D, cs.rp1D)
        )
    return summed_teff, mean_teff


def safe_initial_positions(center: np.ndarray, bounds, n_walkers: int) -> np.ndarray:
    positions = center[None, :] + 1.0e-5 * np.random.randn(n_walkers, len(center))
    for index, (lower, upper) in enumerate(bounds):
        epsilon = max(1.0e-10, 1.0e-10 * max(1.0, abs(upper - lower)))
        positions[:, index] = np.clip(
            positions[:, index], lower + epsilon, upper - epsilon
        )
    return positions


def quantile_summary(samples: np.ndarray) -> dict[str, dict[str, float]]:
    # Source theta order: F0, beta_inst, alpha_radius, gamma.
    manuscript = {
        "F0": samples[:, 0],
        "alpha": samples[:, 2],
        "beta": samples[:, 1],
        "gamma": samples[:, 3],
    }
    summary: dict[str, dict[str, float]] = {}
    for name, values in manuscript.items():
        q025, q16, q50, q84, q975 = np.quantile(
            values, [0.025, 0.16, 0.5, 0.84, 0.975]
        )
        summary[name] = {
            "q2.5": float(q025),
            "q16": float(q16),
            "q50": float(q50),
            "q84": float(q84),
            "q97.5": float(q975),
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bryson-root", required=True, type=Path)
    parser.add_argument("--stellar-catalog", required=True, type=Path)
    parser.add_argument("--pc-catalog", required=True, type=Path)
    parser.add_argument("--completeness", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument(
        "--mcmc-seed-offset",
        type=int,
        default=0,
        help=(
            "Optional offset that separates the MCMC random stream from the "
            "outer reliability/measurement realization. Zero preserves the "
            "legacy single-stream behavior."
        ),
    )
    parser.add_argument("--trials", type=int, default=4)
    parser.add_argument("--burnin", type=int, default=60)
    parser.add_argument("--steps", type=int, default=200)
    parser.add_argument("--thin", type=int, default=2)
    parser.add_argument("--walkers", type=int, default=8)
    parser.add_argument(
        "--adaptive-production",
        action="store_true",
        help=(
            "Extend production in check-interval chunks until the requested "
            "chain-length/tau and successive-tau stability gates pass."
        ),
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Maximum adaptive production steps per realization.",
    )
    parser.add_argument("--check-interval", type=int, default=1000)
    parser.add_argument("--tau-multiple", type=float, default=100.0)
    parser.add_argument("--tau-relative-tolerance", type=float, default=0.05)
    parser.add_argument("--tau-stability-checks", type=int, default=2)
    parser.add_argument(
        "--period-max-days",
        type=float,
        default=None,
        help="Optional source-period cutoff. Omit to reproduce the no-suffix archived run.",
    )
    parser.add_argument("--run-label", default="pilot")
    parser.add_argument(
        "--measurement-error-mode",
        choices=MEASUREMENT_ERROR_MODES,
        default=LEGACY_SOURCE_MIXTURE,
        help=(
            "Measurement-error construction. The default preserves the public "
            "notebook exactly; v4 corrected runs must explicitly select "
            "quantile_matched_two_sided."
        ),
    )
    args = parser.parse_args()

    if args.trials <= 0 or args.burnin <= 0 or args.steps <= 0 or args.thin <= 0:
        parser.error("trials, burnin, steps, and thin must all be positive")
    if args.walkers < 8 or args.walkers % 2:
        parser.error("walkers must be an even integer of at least 8")
    if args.check_interval <= 0:
        parser.error("check-interval must be positive")
    if args.tau_multiple <= 0.0:
        parser.error("tau-multiple must be positive")
    if not 0.0 < args.tau_relative_tolerance < 1.0:
        parser.error("tau-relative-tolerance must be between zero and one")
    if args.tau_stability_checks <= 0:
        parser.error("tau-stability-checks must be positive")
    if args.adaptive_production:
        if args.max_steps is None:
            parser.error("--max-steps is required with --adaptive-production")
        if args.max_steps < args.steps:
            parser.error("max-steps must be at least steps")
    maximum_steps = args.max_steps if args.max_steps is not None else args.steps

    started = time.time()
    root = args.bryson_root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(root / "completenessContours"))
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "insolation"))
    import rateModels3D as rm3d  # type: ignore  # noqa: E402

    cs = rm3d.compSpace(
        periodName="Instellation",
        periodUnits="Iearth",
        periodRange=(0.2, 2.2),
        nPeriod=61,
        radiusName="Radius",
        radiusUnits="Rearth",
        rpRange=(0.5, 2.5),
        nRp=61,
        tempName="Teff",
        tempUnits="K",
        tempRange=(3900, 6300),
        nTemp=10,
    )
    model = rm3d.triplePowerLawTeffAvg(cs)

    stellar = pd.read_csv(args.stellar_catalog)
    base_kois = pd.read_csv(args.pc_catalog)
    base_kois = pd.merge(
        base_kois,
        stellar[["kepid", "logg"]],
        left_on="kepid_x",
        right_on="kepid",
        how="inner",
    ).reset_index(drop=True)
    base_kois["source_row"] = np.arange(len(base_kois), dtype=int)

    summed_teff, mean_teff = load_completeness(args.completeness, cs)

    chain_rows: list[list[Any]] = []
    planet_rows: list[list[Any]] = []
    audit_frames: list[pd.DataFrame] = []
    diagnostics: list[dict[str, Any]] = []
    pooled: list[np.ndarray] = []

    for trial in range(args.trials):
        trial_seed = int(args.seed + 1_000_003 * trial)
        np.random.seed(trial_seed)
        trial_start = time.time()
        perturbation = perturb_planets(
            base_kois,
            rng=np.random,
            instellation_range=cs.periodRange,
            radius_range=cs.rpRange,
            teff_range=cs.tempRange,
            period_max_days=args.period_max_days,
            mode=args.measurement_error_mode,
        )
        selected = perturbation.retained
        if len(selected) < 4:
            raise RuntimeError(
                f"Trial {trial} retained only {len(selected)} candidates; cannot fit four parameters."
            )

        trial_audit = perturbation.audit.copy()
        trial_audit.insert(0, "trial_seed", trial_seed)
        trial_audit.insert(0, "trial", trial)
        trial_audit.insert(0, "measurement_error_mode", args.measurement_error_mode)
        trial_audit.insert(0, "run_label", args.run_label)
        trial_audit.insert(0, "branch", args.branch)
        audit_frames.append(trial_audit)

        koi_flux = np.asarray(selected.perturbed_flux, dtype=float)
        koi_radius = np.asarray(selected.perturbed_radius, dtype=float)
        koi_teff = np.asarray(selected.perturbed_teff, dtype=float)

        initial = np.asarray(model.initRateModel(), dtype=float)
        likelihood_args = (
            cs,
            koi_flux,
            koi_radius,
            koi_teff,
            summed_teff,
            mean_teff,
            model,
        )
        optimum = minimize(
            nll,
            initial,
            method="L-BFGS-B",
            bounds=model.getBounds(),
            args=likelihood_args,
        )
        if not np.all(np.isfinite(optimum.x)):
            raise RuntimeError(f"Trial {trial} produced a non-finite optimizer state")

        ndim = len(optimum.x)
        n_walkers = args.walkers
        if n_walkers < 2 * ndim:
            raise RuntimeError(
                f"Need at least {2 * ndim} walkers for {ndim} dimensions"
            )
        mcmc_seed = int(trial_seed + args.mcmc_seed_offset)
        if args.mcmc_seed_offset:
            np.random.seed(mcmc_seed)
        positions = safe_initial_positions(
            np.asarray(optimum.x, dtype=float), model.getBounds(), n_walkers
        )
        sampler = emcee.EnsembleSampler(
            n_walkers,
            ndim,
            lnprob,
            args=likelihood_args,
        )
        state = sampler.run_mcmc(positions, args.burnin, progress=False)
        sampler.reset()
        _, tau, converged, convergence_checks = run_production_chain(
            sampler,
            state,
            minimum_steps=args.steps,
            adaptive=args.adaptive_production,
            maximum_steps=maximum_steps,
            check_interval=args.check_interval,
            tau_multiple=args.tau_multiple,
            relative_tolerance=args.tau_relative_tolerance,
            required_stable_checks=args.tau_stability_checks,
        )
        production_steps_completed = int(sampler.iteration)

        chain = sampler.get_chain(thin=args.thin)
        log_probability = sampler.get_log_prob(thin=args.thin)
        flat = chain.reshape((-1, ndim))
        pooled.append(flat)

        ess = None
        if tau is not None:
            tau_array = np.asarray(tau, dtype=float)
            if np.all(np.isfinite(tau_array)) and np.all(tau_array > 0.0):
                ess = [
                    float(n_walkers * production_steps_completed / value)
                    for value in tau_array
                ]

        for step_index in range(chain.shape[0]):
            for walker in range(chain.shape[1]):
                theta = chain[step_index, walker, :]
                # Source order is F0, beta_inst, alpha_radius, gamma.
                chain_rows.append(
                    [
                        args.branch,
                        args.run_label,
                        trial,
                        trial_seed,
                        mcmc_seed,
                        step_index * args.thin,
                        walker,
                        float(log_probability[step_index, walker]),
                        float(theta[0]),
                        float(theta[2]),
                        float(theta[1]),
                        float(theta[3]),
                        float(theta[1]),
                        float(theta[2]),
                    ]
                )

        for _, row in selected.iterrows():
            planet_rows.append(
                [
                    args.branch,
                    args.run_label,
                    trial,
                    trial_seed,
                    int(row.source_row),
                    str(row.get("kepoi_name", "")),
                    float(row.totalReliability),
                    float(row.koi_period),
                    float(row.perturbed_flux),
                    float(row.perturbed_radius),
                    float(row.perturbed_teff),
                ]
            )

        diagnostics.append(
            {
                "trial": trial,
                "seed": trial_seed,
                "perturbation_seed": trial_seed,
                "mcmc_seed": mcmc_seed,
                "measurement_error_mode": args.measurement_error_mode,
                "selected_after_domain": int(len(selected)),
                "perturbation_counts": perturbation.counts,
                "optimizer_success": bool(optimum.success),
                "optimizer_status": int(optimum.status),
                "optimizer_message": str(optimum.message),
                "optimizer_fun": float(optimum.fun),
                "optimizer_theta_source_order": [float(value) for value in optimum.x],
                "mean_acceptance_fraction": float(np.mean(sampler.acceptance_fraction)),
                "acceptance_fraction_by_walker": [
                    float(value) for value in sampler.acceptance_fraction
                ],
                "autocorrelation_time": tau,
                "effective_sample_size_source_order": ess,
                "production_steps_completed": production_steps_completed,
                "adaptive_production": bool(args.adaptive_production),
                "converged": bool(converged) if args.adaptive_production else None,
                "convergence_checks": convergence_checks,
                "runtime_seconds": float(time.time() - trial_start),
            }
        )
        print(
            json.dumps(
                {
                    "branch": args.branch,
                    "trial": trial,
                    "measurement_error_mode": args.measurement_error_mode,
                    "selected": len(selected),
                    "optimizer_success": bool(optimum.success),
                    "acceptance": float(np.mean(sampler.acceptance_fraction)),
                    "production_steps": production_steps_completed,
                    "converged": (
                        bool(converged) if args.adaptive_production else None
                    ),
                }
            ),
            flush=True,
        )

    pooled_samples = np.concatenate(pooled, axis=0)
    posterior = quantile_summary(pooled_samples)
    published = PUBLISHED[args.branch]
    comparison = {
        name: {
            "published_marginal_median": float(published[name]),
            "rerun_q50": float(posterior[name]["q50"]),
            "difference": float(posterior[name]["q50"] - published[name]),
        }
        for name in ("F0", "alpha", "beta", "gamma")
    }

    chain_path = out / f"joint_posterior_{args.branch}_{args.run_label}.csv"
    with chain_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "branch",
                "run_label",
                "trial",
                "trial_seed",
                "mcmc_seed",
                "production_step",
                "walker",
                "log_probability",
                "F0",
                "alpha",
                "beta",
                "gamma",
                "source_theta1_beta_inst",
                "source_theta2_alpha_radius",
            ]
        )
        writer.writerows(chain_rows)

    planets_path = out / f"perturbed_planets_{args.branch}_{args.run_label}.csv"
    with planets_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "branch",
                "run_label",
                "trial",
                "trial_seed",
                "source_row",
                "kepoi_name",
                "total_reliability",
                "koi_period_days",
                "perturbed_flux",
                "perturbed_radius_rearth",
                "perturbed_teff_K",
            ]
        )
        writer.writerows(planet_rows)

    audit_path = out / f"perturbation_audit_{args.branch}_{args.run_label}.csv"
    pd.concat(audit_frames, ignore_index=True).to_csv(audit_path, index=False)

    diagnostics_path = out / f"trial_diagnostics_{args.branch}_{args.run_label}.json"
    diagnostics_path.write_text(
        json.dumps(diagnostics, indent=2, default=jsonable), encoding="utf-8"
    )

    summary = {
        "status": "pilot_only" if "pilot" in args.run_label else "production",
        "scientific_interpretation": (
            "A source-faithful newly seeded rerun of the public Bryson likelihood; "
            "not the missing historical chain or a bitwise reproduction of the "
            "published stochastic run."
            if args.measurement_error_mode == LEGACY_SOURCE_MIXTURE
            else
            "A newly seeded corrected variant of the public Bryson likelihood, "
            "using quantile-matched two-sided measurement perturbations and all "
            "three post-perturbation source-domain filters; not the missing "
            "historical chain."
        ),
        "source_repository": "stevepur/DR25-occurrence-public",
        "source_commit": BRYSON_COMMIT,
        "branch": args.branch,
        "run_label": args.run_label,
        "parameter_order_source": ["F0", "beta_inst", "alpha_radius", "gamma"],
        "parameter_order_manuscript": ["F0", "alpha_radius", "beta_inst", "gamma"],
        "period_cutoff_days": args.period_max_days,
        "measurement_error": measurement_error_metadata(args.measurement_error_mode),
        "base_seed": args.seed,
        "mcmc_seed_offset": args.mcmc_seed_offset,
        "trials": args.trials,
        "walkers": args.walkers,
        "burnin_steps": args.burnin,
        "production_steps": (
            args.steps if not args.adaptive_production else None
        ),
        "production_steps_requested_minimum": args.steps,
        "production_steps_requested_maximum": maximum_steps,
        "production_steps_completed": [
            int(entry["production_steps_completed"]) for entry in diagnostics
        ],
        "adaptive_production": {
            "enabled": bool(args.adaptive_production),
            "check_interval": args.check_interval,
            "tau_multiple": args.tau_multiple,
            "tau_relative_tolerance": args.tau_relative_tolerance,
            "required_consecutive_stable_checks": args.tau_stability_checks,
            "converged_realizations": int(
                sum(bool(entry.get("converged")) for entry in diagnostics)
            ),
        },
        "thin": args.thin,
        "pooled_sample_count": int(len(pooled_samples)),
        "posterior_quantiles": posterior,
        "comparison_with_archived_published_marginal_medians": comparison,
        "trial_diagnostics_file": diagnostics_path.name,
        "perturbation_audit_file": audit_path.name,
        "input_files": {
            "stellar_catalog": {
                "path": str(args.stellar_catalog),
                "sha256": sha256(args.stellar_catalog),
            },
            "pc_catalog": {
                "path": str(args.pc_catalog),
                "sha256": sha256(args.pc_catalog),
            },
            "completeness": {
                "path": str(args.completeness),
                "sha256": sha256(args.completeness),
            },
        },
        "runtime_seconds": float(time.time() - started),
        "software": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "emcee": emcee.__version__,
        },
        "limitations": [
            *(
                ["Pilot settings are for code and data-path validation, not publication inference."]
                if "pilot" in args.run_label
                else []
            ),
            "The public snapshot contains no serialized historical posterior chain.",
            *(
                ["Fixed-length MCMC convergence must be assessed after aggregation."]
                if not args.adaptive_production
                else []
            ),
            "The two completeness branches remain separate model scenarios.",
        ],
    }
    summary_path = out / f"posterior_summary_{args.branch}_{args.run_label}.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=jsonable), encoding="utf-8"
    )

    manifest_targets = [
        chain_path,
        planets_path,
        audit_path,
        diagnostics_path,
        summary_path,
    ]
    manifest_path = out / f"SHA256SUMS_{args.branch}_{args.run_label}.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_targets),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
