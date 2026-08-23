#!/usr/bin/env python3
"""Propagate a Bryson Model-1 joint posterior through the frozen JJ estimator.

The host rows are collapsed exactly, not binned, onto their distinct ``Teff``
values after assigning the composite-trapezoid radial measure over 7--9 kpc.
The canonical provider has 539 values; alternative audited selectors must
declare their own expected count. This preserves the row-level estimator while
permitting vectorized posterior propagation.

Input posterior rows must contain the correlated columns
``F0, alpha, beta, gamma`` in manuscript order.  Constant- and
zero-completeness branches are processed separately.  The output intervals
therefore quantify occurrence-posterior uncertainty conditional on the frozen
JJ/PARSEC/TAMS/HZ model stack; they do not include host-model, climate,
multiplicity, or source-to-target transport systematics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from clustered_monte_carlo import (
    cluster_bootstrap_quantile_mcse,
    contiguous_batch_quantile_mcse,
)

SOURCE_RADIUS = (0.5, 2.5)
SOURCE_INSTELLATION = (0.2, 2.2)
SOURCE_TEMPERATURE = (3900.0, 6300.0)
TEFF_BREAK = 5117.0
TEFF_EXPONENT = (3.16, 4.49)
TEFF_COEFFICIENT = (10.0 ** -11.839, 10.0 ** -16.769)

RUNAWAY_1MEARTH = (
    1.107,
    1.332e-4,
    1.580e-8,
    -8.308e-12,
    -1.931e-15,
)
MAXIMUM_GREENHOUSE = (
    0.356,
    6.171e-5,
    1.698e-9,
    -3.198e-12,
    -5.575e-16,
)

PLUGIN_VECTORS = {
    "constant": (1.107, -1.082, -0.839, -2.671),
    "zero": (1.590, -1.175, -1.195, -1.376),
}
PLUGIN_REFERENCE = {
    "constant": {
        "Lambda_HZ": 105716685.0799,
        "Lambda_EE": 3376462.6740,
    },
    "zero": {
        "Lambda_HZ": 176342234.5714,
        "Lambda_EE": 4708017.0197,
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def power_integral(lower, upper, exponent):
    """Integral of x**exponent with a stable logarithmic limit at -1."""
    lower = np.asarray(lower, dtype=float)
    upper = np.asarray(upper, dtype=float)
    exponent = np.asarray(exponent, dtype=float)
    shifted = exponent + 1.0
    with np.errstate(all="ignore"):
        regular = (
            np.power(upper, shifted) - np.power(lower, shifted)
        ) / shifted
    return np.where(
        np.abs(shifted) < 1.0e-8,
        np.log(upper / lower),
        regular,
    )


def seff(teff: np.ndarray, coefficients) -> np.ndarray:
    delta = teff - 5780.0
    s0, a, b, c, d = coefficients
    return s0 + a * delta + b * delta**2 + c * delta**3 + d * delta**4


def collapse_host_measure(
    path: Path,
    expected_distinct_temperatures: int | None = 539,
) -> pd.DataFrame:
    required = {"R_kpc", "Teff_K", "N_surface_pc-2"}
    hosts = pd.read_csv(path, usecols=list(required))
    if set(hosts.columns) != required:
        raise RuntimeError(f"Host columns do not match {sorted(required)}")
    hosts = hosts.loc[(hosts.R_kpc >= 7.0) & (hosts.R_kpc <= 9.0)].copy()
    nodes = np.sort(hosts.R_kpc.unique())
    if not np.array_equal(nodes, np.array([7.0, 7.5, 8.0, 8.5, 9.0])):
        raise RuntimeError(f"Unexpected 7--9 kpc radial nodes: {nodes}")

    coefficients = np.empty(len(nodes), dtype=float)
    coefficients[0] = 0.5 * (nodes[1] - nodes[0])
    coefficients[-1] = 0.5 * (nodes[-1] - nodes[-2])
    coefficients[1:-1] = 0.5 * (nodes[2:] - nodes[:-2])
    coefficient_map = dict(zip(nodes, coefficients))

    radial_coefficient = hosts.R_kpc.map(coefficient_map).to_numpy(dtype=float)
    hosts["integrated_host_weight"] = (
        hosts["N_surface_pc-2"].to_numpy(dtype=float)
        * radial_coefficient
        * 2.0
        * math.pi
        * hosts.R_kpc.to_numpy(dtype=float)
        * 1.0e6
    )
    collapsed = (
        hosts.groupby("Teff_K", as_index=False, sort=True)
        .integrated_host_weight.sum()
        .sort_values("Teff_K")
        .reset_index(drop=True)
    )
    if (
        expected_distinct_temperatures is not None
        and len(collapsed) != expected_distinct_temperatures
    ):
        raise RuntimeError(
            "Expected "
            f"{expected_distinct_temperatures} exact distinct host temperatures, "
            f"found {len(collapsed)}"
        )
    if not np.isfinite(collapsed.to_numpy(dtype=float)).all():
        raise RuntimeError("Non-finite collapsed host measure")
    if np.any(collapsed.integrated_host_weight < 0):
        raise RuntimeError("Negative collapsed host weight")
    return collapsed


def temperature_normalization(gamma: np.ndarray) -> np.ndarray:
    t0, t1 = SOURCE_TEMPERATURE
    lower = TEFF_COEFFICIENT[0] * power_integral(
        t0, TEFF_BREAK, gamma + TEFF_EXPONENT[0]
    )
    upper = TEFF_COEFFICIENT[1] * power_integral(
        TEFF_BREAK, t1, gamma + TEFF_EXPONENT[1]
    )
    return (lower + upper) / (t1 - t0)


def propagate_chunk(
    samples: pd.DataFrame,
    teff: np.ndarray,
    host_weight: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    f0 = samples.F0.to_numpy(dtype=float)[:, None]
    alpha = samples.alpha.to_numpy(dtype=float)[:, None]
    beta = samples.beta.to_numpy(dtype=float)[:, None]
    gamma = samples.gamma.to_numpy(dtype=float)[:, None]

    teff_matrix = teff[None, :]
    geometric = np.where(
        teff_matrix <= TEFF_BREAK,
        TEFF_COEFFICIENT[0] * teff_matrix ** TEFF_EXPONENT[0],
        TEFF_COEFFICIENT[1] * teff_matrix ** TEFF_EXPONENT[1],
    )
    temperature_factor = (
        geometric
        * np.power(teff_matrix, gamma)
        / temperature_normalization(gamma)
    )

    radius_denominator = power_integral(
        SOURCE_RADIUS[0], SOURCE_RADIUS[1], alpha
    )
    radius_hz = (
        power_integral(0.5, 1.5, alpha) / radius_denominator
    )
    radius_ee = (
        power_integral(0.9, 1.1, alpha) / radius_denominator
    )

    inner = seff(teff, RUNAWAY_1MEARTH)
    outer = seff(teff, MAXIMUM_GREENHOUSE)
    instellation_denominator = power_integral(
        SOURCE_INSTELLATION[0], SOURCE_INSTELLATION[1], beta
    )
    instellation_hz = (
        power_integral(outer[None, :], inner[None, :], beta)
        / instellation_denominator
    )

    lower_ee = np.maximum(0.9, outer)
    upper_ee = np.minimum(1.1, inner)
    instellation_ee = np.where(
        upper_ee[None, :] > lower_ee[None, :],
        power_integral(lower_ee[None, :], upper_ee[None, :], beta)
        / instellation_denominator,
        0.0,
    )

    weighted_hz = np.sum(
        host_weight[None, :] * temperature_factor * instellation_hz,
        axis=1,
    )
    weighted_ee = np.sum(
        host_weight[None, :] * temperature_factor * instellation_ee,
        axis=1,
    )
    lambda_hz = f0[:, 0] * radius_hz[:, 0] * weighted_hz
    lambda_ee = f0[:, 0] * radius_ee[:, 0] * weighted_ee
    return lambda_hz, lambda_ee


def quantiles(values: np.ndarray) -> dict[str, float]:
    q025, q16, q50, q84, q975 = np.quantile(
        values, [0.025, 0.16, 0.50, 0.84, 0.975]
    )
    return {
        "q2.5": float(q025),
        "q16": float(q16),
        "q50": float(q50),
        "q84": float(q84),
        "q97.5": float(q975),
    }


def validate_plugin(
    branch: str,
    teff: np.ndarray,
    host_weight: np.ndarray,
) -> dict[str, Any]:
    f0, alpha, beta, gamma = PLUGIN_VECTORS[branch]
    frame = pd.DataFrame(
        {"F0": [f0], "alpha": [alpha], "beta": [beta], "gamma": [gamma]}
    )
    lambda_hz, lambda_ee = propagate_chunk(frame, teff, host_weight)
    calculated = {
        "Lambda_HZ": float(lambda_hz[0]),
        "Lambda_EE": float(lambda_ee[0]),
    }
    comparison = {}
    for name, value in calculated.items():
        reference = PLUGIN_REFERENCE[branch][name]
        relative = (value - reference) / reference
        comparison[name] = {
            "calculated": value,
            "reference": reference,
            "relative_difference": float(relative),
        }
        if abs(relative) > 1.0e-10:
            raise RuntimeError(
                f"Plug-in validation failed for {branch} {name}: {relative}"
            )
    return comparison


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", required=True, type=Path)
    parser.add_argument("--samples", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--cluster-bootstrap-replicates", type=int, default=1000)
    parser.add_argument("--bootstrap-seed", type=int, default=2026082102)
    parser.add_argument("--inner-chain-batches", type=int, default=8)
    parser.add_argument(
        "--expected-distinct-host-temperatures",
        type=int,
        default=539,
        help="Fail unless the exact collapsed host-temperature count matches.",
    )
    parser.add_argument(
        "--expected-host-count",
        type=float,
        default=263061992.36674237,
        help="Fail unless the integrated 7--9 kpc host count matches.",
    )
    parser.add_argument(
        "--skip-canonical-plugin-validation",
        action="store_true",
        help=(
            "Skip the frozen canonical plug-in anchors for an explicitly named "
            "alternative host-selector sensitivity."
        ),
    )
    parser.add_argument(
        "--host-selection-label",
        default="canonical PARSEC-TAMS selector",
    )
    args = parser.parse_args()

    started = time.time()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    collapsed = collapse_host_measure(
        args.hosts,
        expected_distinct_temperatures=args.expected_distinct_host_temperatures,
    )
    collapsed_path = out / "collapsed_host_temperature_measure.csv"
    collapsed.to_csv(collapsed_path, index=False)
    teff = collapsed.Teff_K.to_numpy(dtype=float)
    host_weight = collapsed.integrated_host_weight.to_numpy(dtype=float)
    n_star = float(np.sum(host_weight))
    if abs(n_star - args.expected_host_count) / args.expected_host_count > 1.0e-10:
        raise RuntimeError(f"Frozen host-count validation failed: {n_star}")

    if args.skip_canonical_plugin_validation:
        plugin_validation = {
            "status": "not_applicable_to_alternative_host_selector",
            "host_selection_label": args.host_selection_label,
        }
    else:
        plugin_validation = validate_plugin(args.branch, teff, host_weight)

    samples = pd.read_csv(args.samples)
    required = {"F0", "alpha", "beta", "gamma"}
    missing = required.difference(samples.columns)
    if missing:
        raise RuntimeError(f"Missing posterior columns: {sorted(missing)}")
    if "branch" in samples.columns:
        branches = set(samples.branch.astype(str))
        if branches != {args.branch}:
            raise RuntimeError(f"Posterior branch mismatch: {branches}")
    if not np.isfinite(samples.loc[:, list(required)].to_numpy(dtype=float)).all():
        raise RuntimeError("Non-finite joint-posterior sample")
    if "global_trial" not in samples.columns:
        raise RuntimeError(
            "Posterior samples must retain global_trial for cluster-aware uncertainty"
        )
    realization_counts = samples.groupby("global_trial", sort=True).size().to_numpy()
    if len(realization_counts) < 2 or not np.all(
        realization_counts == realization_counts[0]
    ):
        raise RuntimeError("Posterior outer realizations do not have equal weights")

    output_frames: list[pd.DataFrame] = []
    for start in range(0, len(samples), args.chunk_size):
        stop = min(start + args.chunk_size, len(samples))
        chunk = samples.iloc[start:stop].copy()
        lambda_hz, lambda_ee = propagate_chunk(chunk, teff, host_weight)
        chunk["N_star"] = n_star
        chunk["mean_f_HZ"] = lambda_hz / n_star
        chunk["mean_f_EE"] = lambda_ee / n_star
        chunk["Lambda_HZ"] = lambda_hz
        chunk["Lambda_EE"] = lambda_ee
        chunk["Lambda_EE_over_Lambda_HZ"] = lambda_ee / lambda_hz
        output_frames.append(chunk)

    draws = pd.concat(output_frames, ignore_index=True)
    draws_path = out / f"galactic_posterior_draws_{args.branch}.csv.gz"
    draws.to_csv(draws_path, index=False, compression="gzip")

    quantities = (
        "mean_f_HZ",
        "mean_f_EE",
        "Lambda_HZ",
        "Lambda_EE",
        "Lambda_EE_over_Lambda_HZ",
    )
    cluster_bootstrap_mcse = cluster_bootstrap_quantile_mcse(
        draws,
        quantities,
        "global_trial",
        args.cluster_bootstrap_replicates,
        args.bootstrap_seed,
    )
    inner_chain_mcse = contiguous_batch_quantile_mcse(
        draws,
        quantities,
        "global_trial",
        args.inner_chain_batches,
    )
    summary = {
        "status": (
            "occurrence-posterior propagation conditional on the declared "
            f"host selector ({args.host_selection_label}) and 1-Mearth "
            "conservative-HZ model"
        ),
        "branch": args.branch,
        "source_posterior_samples": {
            "path": str(args.samples),
            "sha256": sha256(args.samples),
            "row_count": int(len(samples)),
            "outer_realizations": int(len(realization_counts)),
            "equal_samples_per_outer_realization": int(realization_counts[0]),
        },
        "host_rows": {
            "path": str(args.hosts),
            "sha256": sha256(args.hosts),
            "N_star_7_9_kpc": n_star,
            "exact_distinct_Teff_values": int(len(collapsed)),
            "host_selection_label": args.host_selection_label,
            "collapsed_measure_file": collapsed_path.name,
            "collapsed_measure_sha256": sha256(collapsed_path),
        },
        "plugin_validation": plugin_validation,
        "posterior_quantiles": {
            name: quantiles(draws[name].to_numpy(dtype=float))
            for name in quantities
        },
        "posterior_quantile_monte_carlo_error": {
            "outer_realization_cluster_bootstrap": cluster_bootstrap_mcse,
            "outer_realization_cluster_bootstrap_replicates": (
                args.cluster_bootstrap_replicates
            ),
            "outer_realization_cluster_bootstrap_seed": args.bootstrap_seed,
            "inner_chain_contiguous_batch_mcse": inner_chain_mcse,
            "inner_chain_batches": args.inner_chain_batches,
            "interpretation": (
                "The bootstrap resamples complete reliability/measurement "
                "realizations. Posterior rows are never treated as independent "
                "outer Monte Carlo draws."
            ),
        },
        "runtime_seconds": float(time.time() - started),
        "software": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
        "included_uncertainty": (
            "Bryson occurrence-parameter, reliability, and catalog-measurement "
            "uncertainty represented by the supplied correlated joint samples"
        ),
        "excluded_systematics": [
            "JJ Galactic-population normalization and parameter uncertainty",
            "isochrone-family uncertainty",
            "TAMS-selector transport and metallicity dependence",
            "planet-mass and climate-model uncertainty",
            "multiplicity mismatch",
            "age, metallicity, alpha-enhancement, and Galactic-environment occurrence transport",
            "uncertainty between the two completeness model branches",
        ],
    }
    summary_path = out / f"galactic_posterior_summary_{args.branch}.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    targets = [collapsed_path, draws_path, summary_path]
    manifest_path = out / f"SHA256SUMS_galactic_{args.branch}.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in targets),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
