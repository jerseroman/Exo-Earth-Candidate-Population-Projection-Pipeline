#!/usr/bin/env python3
"""Validate and checksum the corrected v4 numerical result set."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from measurement_error import QUANTILE_MATCHED_TWO_SIDED

PARAMETERS = ("F0", "alpha", "beta", "gamma")
GALACTIC_QUANTITIES = (
    "mean_f_HZ",
    "mean_f_EE",
    "Lambda_HZ",
    "Lambda_EE",
    "Lambda_EE_over_Lambda_HZ",
)
QUANTILES = ("q2.5", "q16", "q50", "q84", "q97.5")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_ordered_quantiles(name: str, summary: dict[str, Any]) -> None:
    values = np.asarray([summary[key] for key in QUANTILES], dtype=float)
    if not np.all(np.isfinite(values)) or np.any(np.diff(values) < 0.0):
        raise RuntimeError(f"Invalid ordered quantiles for {name}: {values}")


def mcse_fraction(
    quantiles: dict[str, float],
    mcse: dict[str, Any],
    component: str,
) -> float:
    width = float(quantiles["q84"] - quantiles["q16"])
    if width <= 0.0:
        raise RuntimeError("Non-positive q16--q84 width")
    if component == "outer":
        error = float(mcse["q50"]["standard_error"])
    else:
        error = float(mcse["q50"])
    return error / width


def validate_aggregate(branch: str, data: dict[str, Any]) -> dict[str, Any]:
    if data["branch"] != branch:
        raise RuntimeError(f"Aggregate branch mismatch for {branch}")
    if data["measurement_error"]["mode"] != QUANTILE_MATCHED_TWO_SIDED:
        raise RuntimeError(f"Non-corrected measurement mode in {branch}")
    if data["total_trials"] != 400:
        raise RuntimeError(f"Expected 400 outer realizations for {branch}")
    diagnostics = data["diagnostics"]
    required_counts = (
        diagnostics["adaptive_realizations"],
        diagnostics["adaptive_realizations_converged"],
        diagnostics["realizations_with_estimable_autocorrelation"],
    )
    if required_counts != (400, 400, 400):
        raise RuntimeError(f"Incomplete adaptive convergence for {branch}: {required_counts}")
    if diagnostics["optimizer_failures"] != 0:
        raise RuntimeError(f"Optimizer failures in {branch}")

    mc = data["posterior_quantile_monte_carlo_error"]
    if mc["outer_realization_cluster_bootstrap_replicates"] < 1000:
        raise RuntimeError("Too few outer-realization bootstrap replicates")
    checks: dict[str, Any] = {}
    for parameter in PARAMETERS:
        quantiles = data["posterior_quantiles"][parameter]
        validate_ordered_quantiles(f"{branch}:{parameter}", quantiles)
        outer_fraction = mcse_fraction(
            quantiles,
            mc["outer_realization_cluster_bootstrap"][parameter],
            "outer",
        )
        inner_fraction = mcse_fraction(
            quantiles,
            mc["inner_chain_contiguous_batch_mcse"][parameter],
            "inner",
        )
        ess = diagnostics["estimated_chain_ess_by_source_parameter"][parameter]
        if float(ess["minimum_per_realization"]) < 1000.0:
            raise RuntimeError(f"Insufficient minimum ESS for {branch}:{parameter}")
        if outer_fraction > 0.10 or inner_fraction > 0.05:
            raise RuntimeError(
                f"MCSE gate failed for {branch}:{parameter}: "
                f"outer={outer_fraction}, inner={inner_fraction}"
            )
        checks[parameter] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
            "minimum_ess_per_realization": float(ess["minimum_per_realization"]),
        }
    return checks


def validate_galactic(branch: str, data: dict[str, Any]) -> dict[str, Any]:
    if data["branch"] != branch:
        raise RuntimeError(f"Galactic branch mismatch for {branch}")
    source = data["source_posterior_samples"]
    if source["outer_realizations"] != 400:
        raise RuntimeError(f"Galactic posterior lacks 400 clusters for {branch}")
    for quantity, values in data["plugin_validation"].items():
        if abs(float(values["relative_difference"])) > 1.0e-10:
            raise RuntimeError(f"Plug-in validation failed for {branch}:{quantity}")

    mc = data["posterior_quantile_monte_carlo_error"]
    checks: dict[str, Any] = {}
    for quantity in GALACTIC_QUANTITIES:
        quantiles = data["posterior_quantiles"][quantity]
        validate_ordered_quantiles(f"{branch}:{quantity}", quantiles)
        outer_fraction = mcse_fraction(
            quantiles,
            mc["outer_realization_cluster_bootstrap"][quantity],
            "outer",
        )
        inner_fraction = mcse_fraction(
            quantiles,
            mc["inner_chain_contiguous_batch_mcse"][quantity],
            "inner",
        )
        if outer_fraction > 0.10 or inner_fraction > 0.05:
            raise RuntimeError(
                f"Propagation MCSE gate failed for {branch}:{quantity}: "
                f"outer={outer_fraction}, inner={inner_fraction}"
            )
        checks[quantity] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
        }
    return checks


def main() -> None:
    parser = argparse.ArgumentParser()
    for branch in ("constant", "zero"):
        parser.add_argument(f"--{branch}-aggregate", required=True, type=Path)
        parser.add_argument(f"--{branch}-galactic", required=True, type=Path)
        parser.add_argument(f"--{branch}-seed-stability", required=True, type=Path)
    parser.add_argument("--host-summary", required=True, type=Path)
    parser.add_argument("--tams-convergence", required=True, type=Path)
    parser.add_argument("--host-tams-audit", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs: dict[str, Path] = {}
    aggregates: dict[str, dict[str, Any]] = {}
    galactic: dict[str, dict[str, Any]] = {}
    gates: dict[str, Any] = {}
    for branch in ("constant", "zero"):
        aggregate_path = getattr(args, f"{branch}_aggregate")
        galactic_path = getattr(args, f"{branch}_galactic")
        stability_path = getattr(args, f"{branch}_seed_stability")
        inputs[f"{branch}_aggregate"] = aggregate_path
        inputs[f"{branch}_galactic"] = galactic_path
        inputs[f"{branch}_seed_stability"] = stability_path
        aggregates[branch] = load_json(aggregate_path)
        galactic[branch] = load_json(galactic_path)
        stability = load_json(stability_path)
        if stability.get("status") != "pass" or not stability.get("all_trials_converged"):
            raise RuntimeError(f"MCMC seed stability did not pass for {branch}")
        gates[branch] = {
            "aggregate": validate_aggregate(branch, aggregates[branch]),
            "galactic": validate_galactic(branch, galactic[branch]),
            "seed_stability": "pass",
        }

    host = load_json(args.host_summary)
    if abs(float(host["N_G_hosts_age_ge_4p57_R7_9"]) - 263061992.36674237) > 0.1:
        raise RuntimeError("Frozen JJ host count mismatch")
    convergence = load_json(args.tams_convergence)
    if not convergence.get("pass"):
        raise RuntimeError("TAMS radial convergence gate is not marked PASS")
    for quantity, comparison in convergence["comparisons"]["lineweaver_7_9"]["0.5_to_0.25"].items():
        if abs(float(comparison["delta_fraction"])) >= 0.01:
            raise RuntimeError(f"TAMS radial convergence failed for {quantity}")
    host_tams_audit = load_json(args.host_tams_audit)
    if host_tams_audit.get("status") not in {
        "PASS_WITH_INVALID_METALLICITY_TEST_EXCLUDED",
        "PASS",
    }:
        raise RuntimeError("Host/TAMS audit did not pass")
    metallicity_audit = host_tams_audit.get("metallicity_dependent_TAMS_audit", {})
    if metallicity_audit.get("status") != "FAIL":
        raise RuntimeError(
            "Expected the invalid archived metallicity-TAMS surface to be rejected"
        )

    inputs.update(
        {
            "host_summary": args.host_summary,
            "tams_convergence": args.tams_convergence,
            "host_tams_audit": args.host_tams_audit,
        }
    )
    freeze = {
        "status": "PASS",
        "scope": (
            "Corrected Bryson occurrence posterior and conditional Galactic "
            "propagation; constant and zero completeness remain separate scenarios."
        ),
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in inputs.items()
        },
        "gates": gates,
        "host_model": {
            "N_star_7_9_kpc": host["N_G_hosts_age_ge_4p57_R7_9"],
            "provider": host["host_provider_id"],
            "tams_radial_convergence": "PASS",
            "metallicity_dependent_tams_role": (
                "EXCLUDED: archived differential surface is invalid; a valid "
                "metallicity-dependent low-mass TAMS sensitivity remains open"
            ),
            "metallicity_dependent_tams_audit": metallicity_audit,
            "native_solar_selector_without_5200_anchor_fractional_change_vs_canonical": (
                host_tams_audit["low_temperature_anchor_dependence"]
                ["native_selector_fractional_change_vs_canonical"]
            ),
        },
        "posterior_parameters": {
            branch: aggregates[branch]["posterior_quantiles"]
            for branch in ("constant", "zero")
        },
        "galactic_results": {
            branch: galactic[branch]["posterior_quantiles"]
            for branch in ("constant", "zero")
        },
    }
    freeze_path = out / "V4_NUMERICAL_FREEZE.json"
    with freeze_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(freeze, handle, indent=2)
        handle.write("\n")

    with (out / "v4_parameter_quantiles.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["branch", "parameter", *QUANTILES])
        for branch in ("constant", "zero"):
            for parameter in PARAMETERS:
                values = aggregates[branch]["posterior_quantiles"][parameter]
                writer.writerow([branch, parameter, *(values[key] for key in QUANTILES)])

    with (out / "v4_galactic_quantiles.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["branch", "quantity", *QUANTILES])
        for branch in ("constant", "zero"):
            for quantity in GALACTIC_QUANTITIES:
                values = galactic[branch]["posterior_quantiles"][quantity]
                writer.writerow([branch, quantity, *(values[key] for key in QUANTILES)])

    markdown = [
        "# V4 numerical freeze\n",
        "**Status: PASS.** The corrected measurement model, adaptive MCMC, "
        "whole-realization bootstrap, and conditional Galactic propagation "
        "passed their declared gates.\n",
        "The constant- and zero-completeness branches are separate model "
        "scenarios and are not combined into an uncertainty interval.\n",
    ]
    with (out / "V4_NUMERICAL_FREEZE.md").open(
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write("\n".join(markdown))
    print(json.dumps(freeze, indent=2))


if __name__ == "__main__":
    main()
