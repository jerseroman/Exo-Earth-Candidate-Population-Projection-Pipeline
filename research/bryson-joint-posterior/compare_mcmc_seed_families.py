#!/usr/bin/env python3
"""Gate independent MCMC streams on identical corrected outer realizations."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from aggregate_hab2_joint_posterior import load_strict_json
from clustered_monte_carlo import equalize_realizations, quantile_summary

PARAMETERS = ("F0", "alpha", "beta", "gamma")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def comparable_frame(path: Path, sort_columns: list[str]) -> pd.DataFrame:
    frame = pd.read_csv(path).drop(columns=["run_label"], errors="ignore")
    return frame.sort_values(sort_columns).reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-families", type=int, default=2)
    parser.add_argument("--max-quantile-width-fraction", type=float, default=0.15)
    args = parser.parse_args()

    root = args.root.resolve()
    out = args.out.resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise RuntimeError("Seed-stability output directory must be absent or empty")
    out.mkdir(parents=True, exist_ok=True)
    chain_paths = sorted(
        root.rglob(f"joint_posterior_{args.branch}_corrected-pilot-seed-*.csv")
    )
    if len(chain_paths) != args.expected_families:
        raise RuntimeError(
            f"Expected {args.expected_families} seed families, found {len(chain_paths)}"
        )
    samples_per_outer_realization = min(
        int(count)
        for path in chain_paths
        for count in pd.read_csv(path, usecols=["trial"]).groupby("trial").size()
    )

    families: dict[str, dict[str, Any]] = {}
    trial_seed_reference: list[int] | None = None
    planet_reference: pd.DataFrame | None = None
    audit_reference: pd.DataFrame | None = None
    all_chains: list[pd.DataFrame] = []
    manifest_targets: list[Path] = []

    for chain_path in chain_paths:
        chain = pd.read_csv(chain_path)
        equalized_chain = equalize_realizations(
            chain.sort_values(["trial", "production_step", "walker"]),
            "trial",
            samples_per_outer_realization,
        )
        labels = set(chain.run_label.astype(str))
        if len(labels) != 1:
            raise RuntimeError(f"Multiple run labels in {chain_path}")
        label = next(iter(labels))
        trial_seeds = sorted(int(value) for value in chain.trial_seed.unique())
        if trial_seed_reference is None:
            trial_seed_reference = trial_seeds
        elif trial_seeds != trial_seed_reference:
            raise RuntimeError("Seed families did not use identical outer realizations")

        planet_paths = list(root.rglob(f"perturbed_planets_{args.branch}_{label}.csv"))
        audit_paths = list(root.rglob(f"perturbation_audit_{args.branch}_{label}.csv"))
        diagnostic_paths = list(
            root.rglob(f"trial_diagnostics_{args.branch}_{label}.json")
        )
        if not (len(planet_paths) == len(audit_paths) == len(diagnostic_paths) == 1):
            raise RuntimeError(f"Incomplete pilot artifacts for {label}")

        copied_chain = out / chain_path.name
        copied_planets = out / planet_paths[0].name
        copied_audit = out / audit_paths[0].name
        copied_diagnostics = out / diagnostic_paths[0].name
        for source, destination in (
            (chain_path, copied_chain),
            (planet_paths[0], copied_planets),
            (audit_paths[0], copied_audit),
            (diagnostic_paths[0], copied_diagnostics),
        ):
            shutil.copyfile(source, destination)
            manifest_targets.append(destination)

        planets = comparable_frame(planet_paths[0], ["trial", "source_row"])
        audit = comparable_frame(audit_paths[0], ["trial", "source_row"])
        if planet_reference is None:
            planet_reference = planets
            audit_reference = audit
        else:
            pd.testing.assert_frame_equal(planets, planet_reference, check_exact=True)
            pd.testing.assert_frame_equal(audit, audit_reference, check_exact=True)

        diagnostics = load_strict_json(diagnostic_paths[0])
        failed = [entry["trial"] for entry in diagnostics if not entry.get("converged")]
        if failed:
            raise RuntimeError(f"Non-converged trials in {label}: {failed}")
        families[label] = {
            "chain_file": copied_chain.name,
            "chain_sha256": sha256(copied_chain),
            "diagnostics_file": copied_diagnostics.name,
            "diagnostics_sha256": sha256(copied_diagnostics),
            "planets_file": copied_planets.name,
            "planets_sha256": sha256(copied_planets),
            "perturbation_audit_file": copied_audit.name,
            "perturbation_audit_sha256": sha256(copied_audit),
            "mcmc_seeds": sorted(int(value) for value in chain.mcmc_seed.unique()),
            "production_steps": [
                int(entry["production_steps_completed"]) for entry in diagnostics
            ],
            "posterior_quantiles": {
                name: quantile_summary(equalized_chain[name].to_numpy(dtype=float))
                for name in PARAMETERS
            },
        }
        all_chains.append(equalized_chain)

    mcmc_seed_sets = [tuple(entry["mcmc_seeds"]) for entry in families.values()]
    if len(set(mcmc_seed_sets)) != len(mcmc_seed_sets):
        raise RuntimeError("MCMC seed families are not independent")

    combined = pd.concat(all_chains, ignore_index=True)
    stability: dict[str, Any] = {}
    labels = list(families)
    gate_failures: list[str] = []
    for parameter in PARAMETERS:
        combined_summary = quantile_summary(combined[parameter].to_numpy(dtype=float))
        width = combined_summary["q84"] - combined_summary["q16"]
        if not np.isfinite(width) or width <= 0.0:
            raise RuntimeError(f"Invalid combined 68-percent width for {parameter}")
        differences = {}
        maximum_fraction = 0.0
        for quantile in ("q16", "q50", "q84"):
            values = [families[label]["posterior_quantiles"][parameter][quantile] for label in labels]
            difference = float(max(values) - min(values))
            fraction = float(difference / width)
            differences[quantile] = {
                "absolute_family_range": difference,
                "fraction_of_combined_q16_q84_width": fraction,
            }
            maximum_fraction = max(maximum_fraction, fraction)
        passed = maximum_fraction <= args.max_quantile_width_fraction
        if not passed:
            gate_failures.append(parameter)
        stability[parameter] = {
            "combined_quantiles": combined_summary,
            "family_differences": differences,
            "maximum_width_fraction": maximum_fraction,
            "passed": passed,
        }

    report = {
        "schema_version": 2,
        "status": "pass" if not gate_failures else "fail",
        "branch": args.branch,
        "outer_realizations_identical_across_families": True,
        "independent_mcmc_seed_families": True,
        "all_trials_converged": True,
        "equalized_samples_per_outer_realization": samples_per_outer_realization,
        "maximum_allowed_quantile_width_fraction": args.max_quantile_width_fraction,
        "adaptive_production_policy": {
            "requested_minimum_steps": 3000,
            "requested_maximum_steps": 20000,
            "check_interval": 1000,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
            "walkers": 16,
            "runner_thin": 20,
        },
        "families": families,
        "stability": stability,
        "gate_failures": gate_failures,
    }
    report_path = out / f"mcmc_seed_stability_{args.branch}.json"
    report_path.write_text(
        json.dumps(report, indent=2, allow_nan=False), encoding="utf-8"
    )
    manifest_targets.append(report_path)
    manifest_path = out / f"SHA256SUMS_mcmc_seed_stability_{args.branch}.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_targets),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, allow_nan=False))
    if gate_failures:
        raise RuntimeError(
            f"MCMC seed-family stability failed for {gate_failures}"
        )


if __name__ == "__main__":
    main()
