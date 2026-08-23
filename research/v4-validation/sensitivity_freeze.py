#!/usr/bin/env python3
"""Freeze audited v4 numerical sensitivities without combining unlike risks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fractional_change(comparison: float, reference: float) -> float:
    if reference == 0.0:
        raise ValueError("Cannot form a fractional change from a zero reference")
    return comparison / reference - 1.0


def require_close(name: str, value: float, reference: float, tolerance: float) -> None:
    if abs(value - reference) > tolerance:
        raise RuntimeError(f"{name} mismatch: {value} versus {reference}")


def validate_artifact_manifest(
    manifest_path: Path, artifact_root: Path, required_names: set[str]
) -> dict[str, str]:
    declared: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split(maxsplit=1)
        declared[Path(relative.strip()).name] = digest.lower()
    missing = required_names.difference(declared)
    if missing:
        raise RuntimeError(f"Sensitivity artifact manifest lacks: {sorted(missing)}")
    for name in required_names:
        actual = sha256(artifact_root / name)
        if actual != declared[name]:
            raise RuntimeError(
                f"Sensitivity artifact checksum mismatch for {name}: "
                f"{actual} versus {declared[name]}"
            )
    return {name: declared[name] for name in sorted(required_names)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--constant-galactic", required=True, type=Path)
    parser.add_argument("--zero-galactic", required=True, type=Path)
    parser.add_argument("--legacy-measurement-galactic", required=True, type=Path)
    parser.add_argument("--host-tams-audit", required=True, type=Path)
    parser.add_argument("--dr25-audit", required=True, type=Path)
    parser.add_argument("--tams-convergence", required=True, type=Path)
    parser.add_argument("--sensitivity-artifact-root", required=True, type=Path)
    parser.add_argument("--sensitivity-artifact-manifest", required=True, type=Path)
    parser.add_argument("--artifact-run-id", required=True, type=int)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifact_root = args.sensitivity_artifact_root.resolve()
    required_artifacts = {
        "bryson_model_form_sensitivity.json",
        "hz_sensitivity_results.json",
        "tams_all_branch_results.json",
    }
    artifact_hashes = validate_artifact_manifest(
        args.sensitivity_artifact_manifest,
        artifact_root,
        required_artifacts,
    )

    constant = load_json(args.constant_galactic)
    zero = load_json(args.zero_galactic)
    legacy_measurement = load_json(args.legacy_measurement_galactic)
    host = load_json(args.host_tams_audit)
    dr25 = load_json(args.dr25_audit)
    convergence = load_json(args.tams_convergence)
    model_form = load_json(artifact_root / "bryson_model_form_sensitivity.json")
    hz = load_json(artifact_root / "hz_sensitivity_results.json")
    branches = load_json(artifact_root / "tams_all_branch_results.json")

    if constant.get("branch") != "constant" or zero.get("branch") != "zero":
        raise RuntimeError("Canonical Galactic branch mismatch")
    if legacy_measurement.get("branch") != "constant":
        raise RuntimeError("Legacy measurement propagation is not constant branch")
    if host.get("status") != "PASS_WITH_INVALID_METALLICITY_TEST_EXCLUDED":
        raise RuntimeError("Host/TAMS gate is not frozen in its accepted state")
    if dr25.get("status") != "FAIL_LOCAL_EMPIRICAL_SUPPORT":
        raise RuntimeError("DR25 local-support finding changed unexpectedly")
    if not convergence.get("pass"):
        raise RuntimeError("TAMS radial convergence did not pass")
    if model_form.get("experiment") != "Bryson_model_form_sensitivity":
        raise RuntimeError("Unexpected model-form artifact")
    if hz.get("experiment") != "HZ_inner_boundary_and_planet_mass_sensitivity":
        raise RuntimeError("Unexpected HZ sensitivity artifact")

    require_close(
        "model-form baseline Lambda_EE",
        float(model_form["models"]["model1"]["Lambda_earth10"]),
        3376462.6740267,
        0.01,
    )
    require_close(
        "HZ baseline Lambda_EE",
        float(hz["baseline"]["Lambda_earth10"]),
        3376462.6740267,
        0.01,
    )

    constant_q50 = float(constant["posterior_quantiles"]["Lambda_EE"]["q50"])
    zero_q50 = float(zero["posterior_quantiles"]["Lambda_EE"]["q50"])
    legacy_measurement_q50 = float(
        legacy_measurement["posterior_quantiles"]["Lambda_EE"]["q50"]
    )
    host_legacy = host["posterior_legacy_selector"]
    lineweaver = branches["masks"]["lineweaver_7_9"]
    baseline_plugin = float(
        lineweaver["branches"]["CHZ_constant"]["Lambda_earth10"]
    )

    rows: list[dict[str, Any]] = []

    def add(
        category: str,
        sensitivity: str,
        basis: str,
        reference: float | None,
        comparison: float | None,
        change: float | None,
        status: str,
        interpretation: str,
    ) -> None:
        rows.append(
            {
                "category": category,
                "sensitivity": sensitivity,
                "basis": basis,
                "reference_Lambda_EE": reference,
                "comparison_Lambda_EE": comparison,
                "fractional_change": change,
                "percent_change": None if change is None else 100.0 * change,
                "status": status,
                "interpretation": interpretation,
            }
        )

    add(
        "measurement",
        "legacy measurement-error propagation",
        "posterior q50, constant completeness",
        constant_q50,
        legacy_measurement_q50,
        fractional_change(legacy_measurement_q50, constant_q50),
        "PASS_SENSITIVITY",
        "Source-faithful legacy measurement propagation; not the v4 primary model.",
    )
    add(
        "completeness",
        "zero versus constant completeness",
        "separate posterior-scenario q50 values",
        constant_q50,
        zero_q50,
        fractional_change(zero_q50, constant_q50),
        "SCENARIO_NOT_INTERVAL",
        "Alternative completeness models remain separate scenarios.",
    )
    for branch in ("constant", "zero"):
        canonical_q50 = float(
            constant_q50 if branch == "constant" else zero_q50
        )
        legacy_q50 = float(
            host_legacy[branch]["legacy_quantiles"]["Lambda_EE"]["q50"]
        )
        add(
            "host selector",
            f"legacy fixed-logg selector ({branch})",
            "posterior q50 on alternative host measure",
            canonical_q50,
            legacy_q50,
            fractional_change(legacy_q50, canonical_q50),
            "MODEL_SENSITIVITY",
            "Changes both host normalization and temperature weighting.",
        )
    native_delta = host["low_temperature_anchor_dependence"][
        "native_selector_fractional_change_vs_canonical"
    ]["Lambda_EE_plugin"]
    add(
        "TAMS selector",
        "native solar curve without the 5200 K anchor",
        "canonical plug-in",
        baseline_plugin,
        baseline_plugin * (1.0 + float(native_delta)),
        float(native_delta),
        "PASS",
        "Native low-mass nodes reproduce the selected population exactly.",
    )

    radial_comparison = convergence["comparisons"]["lineweaver_7_9"][
        "0.5_to_0.25"
    ]["Lambda_earth10"]
    coarse = float(radial_comparison["coarse"])
    fine = float(radial_comparison["fine"])
    add(
        "numerics",
        "radial grid 0.5 to 0.25 kpc",
        "canonical plug-in",
        coarse,
        fine,
        fractional_change(fine, coarse),
        "PASS",
        "Below the predeclared one-percent convergence tolerance.",
    )

    model2 = float(model_form["models"]["model2"]["Lambda_earth10"])
    add(
        "occurrence model form",
        "Bryson Model 2 versus Model 1",
        "published point-estimate plug-ins",
        baseline_plugin,
        model2,
        fractional_change(model2, baseline_plugin),
        "POINT_ESTIMATE_ONLY",
        "Does not supply a Model-2 posterior or cover arbitrary functional forms.",
    )

    perturbations = {
        float(item["inner_flux_scale"]): item
        for item in hz["inner_boundary_perturbations"]
    }
    for scale in (0.95, 0.99, 1.01, 1.05):
        item = perturbations[scale]
        comparison = float(item["Lambda_earth10"])
        add(
            "climate boundary",
            f"runaway-greenhouse flux scale {scale:.2f}",
            "canonical point-estimate plug-in",
            baseline_plugin,
            comparison,
            fractional_change(comparison, baseline_plugin),
            "NUMERICAL_PERTURBATION",
            "A boundary perturbation, not a probability distribution.",
        )

    masses = {
        float(item["planet_mass_Mearth"]): item
        for item in hz["planet_mass_prescriptions"]
    }
    for mass in (0.1, 5.0):
        comparison = float(masses[mass]["Lambda_earth10"])
        add(
            "planet mass / climate",
            f"Kopparapu runaway boundary for {mass:g} Earth masses",
            "published point-estimate plug-in",
            baseline_plugin,
            comparison,
            fractional_change(comparison, baseline_plugin),
            "ALTERNATIVE_PRESCRIPTION",
            "Changes the climate boundary; it is not a planet-mass population model.",
        )

    optimistic = float(
        lineweaver["branches"]["OHZ_constant"]["Lambda_earth10"]
    )
    add(
        "HZ definition",
        "optimistic versus conservative HZ",
        "constant-completeness point-estimate plug-in",
        baseline_plugin,
        optimistic,
        fractional_change(optimistic, baseline_plugin),
        "ALTERNATIVE_ESTIMAND",
        "Recent-Venus/early-Mars boundaries define a different HZ estimand.",
    )

    weighted = float(lineweaver["branches"]["CHZ_constant"]["RT_L2"])
    add(
        "temperature weighting",
        "JJ-weighted versus uniform 5300--6000 K average",
        "constant-completeness point-estimate ratio",
        1.0,
        weighted,
        weighted - 1.0,
        "PASS_SENSITIVITY",
        "A denominator-weighting diagnostic, not a host-normalization change.",
    )

    for mask_name in ("broad_solar_annulus_6_10", "full_JJ_4_14"):
        mask = branches["masks"][mask_name]
        comparison = float(mask["branches"]["CHZ_constant"]["Lambda_earth10"])
        add(
            "spatial domain",
            mask["label"],
            "constant-completeness point-estimate plug-in",
            baseline_plugin,
            comparison,
            fractional_change(comparison, baseline_plugin),
            "ALTERNATIVE_ESTIMAND",
            "Changes the Galactic integration domain and therefore the estimand.",
        )

    add(
        "DR25 local support",
        "direct candidates in the exact target",
        "nominal and 400 corrected realizations per branch",
        None,
        None,
        None,
        "FAIL_LOCAL_EMPIRICAL_SUPPORT",
        "Zero nominal candidates; median zero and more than 95 percent zero-count trials.",
    )
    add(
        "metallicity-dependent TAMS",
        "archived differential surface",
        "low-mass phase-7 coverage audit",
        None,
        None,
        None,
        "FAIL_EXCLUDED_OPEN_SYSTEMATIC",
        "Invalid quantitative result excluded; no replacement value is available.",
    )
    add(
        "unmodeled host/transport risk",
        "JJ normalization, isochrone family, radial migration, occurrence transport",
        "not parameterized",
        None,
        None,
        None,
        "OPEN",
        "No defensible probability distribution is available for combination.",
    )

    input_paths = {
        "constant_galactic": args.constant_galactic,
        "zero_galactic": args.zero_galactic,
        "legacy_measurement_galactic": args.legacy_measurement_galactic,
        "host_tams_audit": args.host_tams_audit,
        "dr25_audit": args.dr25_audit,
        "tams_convergence": args.tams_convergence,
        "sensitivity_artifact_manifest": args.sensitivity_artifact_manifest,
    }
    result = {
        "status": "SENSITIVITY_REGISTER_FROZEN",
        "scientific_readiness": "CONDITIONAL_MODEL_PROJECTION_ONLY",
        "scope": (
            "Audited one-at-a-time numerical, scenario, model, climate, host, "
            "and spatial sensitivities for manuscript v4."
        ),
        "artifact_run": {
            "github_actions_run_id": args.artifact_run_id,
            "repository": "jerseroman/are-we-alone-in-the-universe",
            "workflow_path": ".github/workflows/jj-g-host-export.yml",
            "head_sha": "f9cbe74bfd791ebfb26dc48ff39d54f37dea263d",
            "url": (
                "https://github.com/jerseroman/are-we-alone-in-the-universe/"
                f"actions/runs/{args.artifact_run_id}"
            ),
            "maximum_mcmc_steps": None,
            "run_provenance_record": "provenance/RUN_PROVENANCE.json",
            "validated_artifact_files": artifact_hashes,
        },
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in input_paths.items()
        },
        "canonical_posterior_q50": {
            "constant_Lambda_EE": constant_q50,
            "zero_Lambda_EE": zero_q50,
        },
        "sensitivities": rows,
        "combination_policy": (
            "Do not add, envelope, or combine these entries into one uncertainty "
            "interval. They mix posterior scenarios, point-estimate perturbations, "
            "alternative estimands, categorical failures, and open systematics."
        ),
        "manuscript_policy": (
            "Report the posterior conditionally, show major sensitivities "
            "separately, and foreground the zero local DR25 support finding."
        ),
    }

    result_path = output / "V4_SENSITIVITY_FREEZE.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")

    table_path = output / "v4_sensitivity_register.csv"
    with table_path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    manifest_path = output / "SHA256SUMS_v4_sensitivity_freeze.txt"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{sha256(result_path)}  {result_path.name}\n")
        handle.write(f"{sha256(table_path)}  {table_path.name}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
