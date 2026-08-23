#!/usr/bin/env python3
"""Independently audit and freeze the selected v4 statistical artifacts.

This script is deliberately separate from the MCMC and propagation code. It
does not calculate a new posterior. It verifies downloaded GitHub Actions
artifacts, their internal manifests, the committed numerical freeze, and the
reported convergence/ESS/MCSE and Galactic medians.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
from pathlib import Path
from typing import Any


PARAMETERS = ("F0", "alpha", "beta", "gamma")
GALACTIC_QUANTITIES = (
    "mean_f_HZ",
    "mean_f_EE",
    "Lambda_HZ",
    "Lambda_EE",
    "Lambda_EE_over_Lambda_HZ",
)
BRANCH_FILES = {
    "constant": {
        "posterior_dir": "constant-posterior",
        "aggregate": "joint_posterior_constant_aggregate_summary.json",
        "diagnostics": "trial_diagnostics_constant_full.jsonl",
        "posterior_manifest": "SHA256SUMS_constant_aggregate.txt",
        "galactic_dir": "constant-galactic",
        "galactic": "galactic_posterior_summary_constant.json",
        "galactic_manifest": "SHA256SUMS_galactic_constant.txt",
        "stability_dir": "constant-seed-stability",
        "stability": "mcmc_seed_stability_constant.json",
        "freeze_aggregate_key": "constant_aggregate",
        "freeze_galactic_key": "constant_galactic",
        "freeze_stability_key": "constant_seed_stability",
        "step_ceiling": 20000,
    },
    "zero": {
        "posterior_dir": "zero-posterior",
        "aggregate": "joint_posterior_zero_aggregate_summary.json",
        "diagnostics": "trial_diagnostics_zero_full.jsonl",
        "posterior_manifest": "SHA256SUMS_zero_aggregate.txt",
        "galactic_dir": "zero-galactic",
        "galactic": "galactic_posterior_summary_zero.json",
        "galactic_manifest": "SHA256SUMS_galactic_zero.txt",
        "stability_dir": "zero-seed-stability",
        "stability": "mcmc_seed_stability_zero.json",
        "freeze_aggregate_key": "zero_aggregate",
        "freeze_galactic_key": "zero_galactic",
        "freeze_stability_key": "zero_seed_stability",
        "step_ceiling": 30000,
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def require_close(actual: float, expected: float, *, atol: float, label: str) -> None:
    if not math.isclose(actual, expected, rel_tol=0.0, abs_tol=atol):
        raise RuntimeError(f"{label}: expected {expected!r}, got {actual!r}")


def verify_manifest(path: Path) -> dict[str, str]:
    verified: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, name = line.split(maxsplit=1)
        name = name.strip().lstrip("*")
        target = path.parent / name
        require(target.is_file(), f"Manifest target missing: {target}")
        actual = sha256(target)
        require(actual == expected, f"Checksum mismatch: {target}")
        verified[name] = actual
    require(bool(verified), f"Empty checksum manifest: {path}")
    return verified


def q50_mcse_fraction(
    quantiles: dict[str, float],
    mcse: dict[str, Any],
    *,
    outer: bool,
) -> float:
    width = float(quantiles["q84"]) - float(quantiles["q16"])
    require(width > 0.0, "Non-positive q16--q84 width")
    error = float(mcse["q50"]["standard_error"] if outer else mcse["q50"])
    return error / width


def read_diagnostics(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    require(len(rows) == 400, f"Expected 400 diagnostic rows in {path}, got {len(rows)}")
    require(
        sorted(int(row["global_trial"]) for row in rows) == list(range(400)),
        f"Non-contiguous global trials in {path}",
    )
    return rows


def maximum_seed_stability_fraction(data: dict[str, Any]) -> float:
    fractions = [
        float(detail["fraction_of_combined_q16_q84_width"])
        for parameter in data["stability"].values()
        for detail in parameter["family_differences"].values()
    ]
    require(bool(fractions), "Seed-stability record has no comparison fractions")
    return max(fractions)


def load_committed_lambda_q50(path: Path) -> dict[str, float]:
    result: dict[str, float] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["quantity"] == "Lambda_EE":
                result[row["branch"]] = float(row["q50"])
    require(set(result) == {"constant", "zero"}, "Committed Lambda_EE rows are incomplete")
    return result


def audit_branch(
    branch: str,
    artifact_root: Path,
    frozen: dict[str, Any],
    committed_lambda_q50: dict[str, float],
) -> dict[str, Any]:
    files = BRANCH_FILES[branch]
    posterior_dir = artifact_root / files["posterior_dir"]
    galactic_dir = artifact_root / files["galactic_dir"]
    stability_dir = artifact_root / files["stability_dir"]
    aggregate_path = posterior_dir / files["aggregate"]
    diagnostics_path = posterior_dir / files["diagnostics"]
    galactic_path = galactic_dir / files["galactic"]
    stability_path = stability_dir / files["stability"]

    posterior_manifest = verify_manifest(posterior_dir / files["posterior_manifest"])
    galactic_manifest = verify_manifest(galactic_dir / files["galactic_manifest"])
    for freeze_key, target in (
        (files["freeze_aggregate_key"], aggregate_path),
        (files["freeze_galactic_key"], galactic_path),
        (files["freeze_stability_key"], stability_path),
    ):
        expected = frozen["inputs"][freeze_key]["sha256"]
        require(sha256(target) == expected, f"Frozen input mismatch for {freeze_key}")

    aggregate = load_json(aggregate_path)
    galactic = load_json(galactic_path)
    stability = load_json(stability_path)
    diagnostics = read_diagnostics(diagnostics_path)

    require(aggregate["branch"] == branch, f"Aggregate branch mismatch: {branch}")
    require(galactic["branch"] == branch, f"Galactic branch mismatch: {branch}")
    require(stability["branch"] == branch, f"Stability branch mismatch: {branch}")
    require(
        aggregate["measurement_error"]["mode"] == "quantile_matched_two_sided",
        f"Non-corrected measurement mode: {branch}",
    )
    require(int(aggregate["total_trials"]) == 400, f"Wrong trial count: {branch}")
    summary_diagnostics = aggregate["diagnostics"]
    for key in (
        "realizations_with_estimable_autocorrelation",
        "adaptive_realizations",
        "adaptive_realizations_converged",
    ):
        require(int(summary_diagnostics[key]) == 400, f"{branch}: {key} is not 400")
    require(int(summary_diagnostics["optimizer_failures"]) == 0, f"{branch}: optimizer failures")
    require(all(bool(row["adaptive_production"]) for row in diagnostics), f"{branch}: non-adaptive row")
    require(all(bool(row["converged"]) for row in diagnostics), f"{branch}: unconverged row")
    require(all(bool(row["optimizer_success"]) for row in diagnostics), f"{branch}: optimizer failure row")
    require(
        all(row["measurement_error_mode"] == "quantile_matched_two_sided" for row in diagnostics),
        f"{branch}: mixed measurement-error mode",
    )
    steps = [int(row["production_steps_completed"]) for row in diagnostics]
    require(max(steps) <= int(files["step_ceiling"]), f"{branch}: step ceiling exceeded")

    parameter_checks: dict[str, Any] = {}
    posterior_mcse = aggregate["posterior_quantile_monte_carlo_error"]
    for parameter in PARAMETERS:
        quantiles = aggregate["posterior_quantiles"][parameter]
        ess = summary_diagnostics["estimated_chain_ess_by_source_parameter"][parameter]
        outer_fraction = q50_mcse_fraction(
            quantiles,
            posterior_mcse["outer_realization_cluster_bootstrap"][parameter],
            outer=True,
        )
        inner_fraction = q50_mcse_fraction(
            quantiles,
            posterior_mcse["inner_chain_contiguous_batch_mcse"][parameter],
            outer=False,
        )
        require(float(ess["minimum_per_realization"]) >= 1000.0, f"{branch}:{parameter} ESS")
        require(outer_fraction <= 0.10, f"{branch}:{parameter} outer MCSE")
        require(inner_fraction <= 0.05, f"{branch}:{parameter} inner MCSE")
        parameter_checks[parameter] = {
            "minimum_ess_per_realization": float(ess["minimum_per_realization"]),
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
        }

    galactic_checks: dict[str, Any] = {}
    galactic_mcse = galactic["posterior_quantile_monte_carlo_error"]
    for quantity in GALACTIC_QUANTITIES:
        quantiles = galactic["posterior_quantiles"][quantity]
        outer_fraction = q50_mcse_fraction(
            quantiles,
            galactic_mcse["outer_realization_cluster_bootstrap"][quantity],
            outer=True,
        )
        inner_fraction = q50_mcse_fraction(
            quantiles,
            galactic_mcse["inner_chain_contiguous_batch_mcse"][quantity],
            outer=False,
        )
        require(outer_fraction <= 0.10, f"{branch}:{quantity} outer propagation MCSE")
        require(inner_fraction <= 0.05, f"{branch}:{quantity} inner propagation MCSE")
        galactic_checks[quantity] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
        }

    require(stability.get("status") == "pass", f"{branch}: seed stability failed")
    require(bool(stability.get("all_trials_converged")), f"{branch}: pilot trials did not converge")
    maximum_stability_fraction = maximum_seed_stability_fraction(stability)
    require(
        maximum_stability_fraction <= float(stability["maximum_allowed_quantile_width_fraction"]),
        f"{branch}: seed-family stability threshold exceeded",
    )

    host_count = float(galactic["host_rows"]["N_star_7_9_kpc"])
    mean_f_ee_q50 = float(galactic["posterior_quantiles"]["mean_f_EE"]["q50"])
    lambda_q50 = float(galactic["posterior_quantiles"]["Lambda_EE"]["q50"])
    recomputed_lambda_q50 = host_count * mean_f_ee_q50
    require_close(
        recomputed_lambda_q50,
        lambda_q50,
        atol=1.0e-6,
        label=f"{branch} Lambda_EE=N_star*mean_f_EE",
    )
    require_close(
        committed_lambda_q50[branch],
        lambda_q50,
        atol=1.0e-9,
        label=f"{branch} committed Lambda_EE q50",
    )

    return {
        "status": "PASS",
        "selected_realizations": 400,
        "measurement_error_mode": aggregate["measurement_error"]["mode"],
        "convergence": {
            "estimable_autocorrelation": int(summary_diagnostics["realizations_with_estimable_autocorrelation"]),
            "adaptive": int(summary_diagnostics["adaptive_realizations"]),
            "converged": int(summary_diagnostics["adaptive_realizations_converged"]),
            "optimizer_failures": int(summary_diagnostics["optimizer_failures"]),
            "production_steps": {
                "minimum": min(steps),
                "median": statistics.median(steps),
                "maximum": max(steps),
                "declared_ceiling": int(files["step_ceiling"]),
            },
        },
        "parameter_ess_mcse": parameter_checks,
        "galactic_mcse": galactic_checks,
        "seed_family_stability": {
            "status": stability["status"],
            "maximum_observed_quantile_shift_fraction_of_q16_q84_width": maximum_stability_fraction,
            "maximum_allowed": float(stability["maximum_allowed_quantile_width_fraction"]),
        },
        "headline_median_origin": {
            "N_star_7_9_kpc": host_count,
            "mean_f_EE_q50": mean_f_ee_q50,
            "recomputed_Lambda_EE_q50": recomputed_lambda_q50,
            "artifact_Lambda_EE_q50": lambda_q50,
            "reported_million_3dp": round(lambda_q50 / 1.0e6, 3),
            "identity": "Lambda_EE_q50 = N_star_7_9_kpc * mean_f_EE_q50",
        },
        "verified_internal_manifests": {
            "posterior": posterior_manifest,
            "galactic": galactic_manifest,
        },
        "freeze_input_hashes": {
            "aggregate": sha256(aggregate_path),
            "galactic": sha256(galactic_path),
            "seed_stability": sha256(stability_path),
        },
    }


def write_markdown(path: Path, audit: dict[str, Any]) -> None:
    constant = audit["branches"]["constant"]
    zero = audit["branches"]["zero"]
    lines = [
        "# V4 statistical baseline audit",
        "",
        "**Status: PASS.** This is an independent verification of the selected",
        "downloaded GitHub Actions artifacts. No MCMC or propagation result was",
        "recomputed or changed.",
        "",
        "## Selected production lineage",
        "",
        "- Constant branch: 400 converged realizations from the successful constant",
        "  aggregate job inside Actions run `32472776218`. The workflow itself is",
        "  correctly recorded as failed because its zero aggregate failed the original",
        "  20,000-step ceiling; that failed zero artifact is excluded.",
        "- Zero branch: 400 converged realizations from the clean 30,000-step-ceiling",
        "  rerun `32506666772`, with identical seeds and unchanged convergence gates.",
        "- Constant Galactic propagation: run `32527877921`.",
        "- Seed-family pilot: run `32470830404`.",
        "",
        "## Frozen provenance",
        "",
        f"- Source Actions repository: `{audit['source_actions_repository']}`.",
        f"- Run-provenance record: `{audit['run_provenance_record']}`.",
        f"- Source checkout before this audit: `{audit['source_checkout_commit']}`.",
        f"- Committed numerical-freeze record SHA-256: `{audit['committed_numerical_freeze_sha256']}`.",
        f"- GitHub Actions evidence snapshot SHA-256: `{audit['github_actions_evidence_sha256']}`.",
        "",
        "| Selected artifact | Run ID | Artifact ID | GitHub archive SHA-256 |",
        "|---|---:|---:|---|",
    ]
    for name, artifact in audit["selected_artifacts"].items():
        lines.append(
            f"| {name} | {artifact['run_id']} | {artifact['artifact_id']} | "
            f"`{artifact['github_archive_digest'].removeprefix('sha256:')}` |"
        )
    lines.extend(
        [
            "",
            "| Branch | Aggregate summary SHA-256 | Galactic summary SHA-256 | Seed-stability SHA-256 |",
            "|---|---|---|---|",
        ]
    )
    for branch, data in (("constant", constant), ("zero", zero)):
        hashes = data["freeze_input_hashes"]
        lines.append(
            f"| {branch} | `{hashes['aggregate']}` | `{hashes['galactic']}` | "
            f"`{hashes['seed_stability']}` |"
        )
    lines.extend(
        [
        "",
        "## Reproduced gates",
        "",
        "| Branch | Converged | Step min/median/max | Minimum ESS | Largest parameter outer MCSE | Largest Galactic outer MCSE |",
        "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for branch, data in (("constant", constant), ("zero", zero)):
        convergence = data["convergence"]
        min_ess = min(item["minimum_ess_per_realization"] for item in data["parameter_ess_mcse"].values())
        max_parameter_mcse = max(item["outer_q50_mcse_fraction_of_q16_q84_width"] for item in data["parameter_ess_mcse"].values())
        max_galactic_mcse = max(item["outer_q50_mcse_fraction_of_q16_q84_width"] for item in data["galactic_mcse"].values())
        steps = convergence["production_steps"]
        lines.append(
            f"| {branch} | {convergence['converged']}/400 | "
            f"{steps['minimum']}/{steps['median']:g}/{steps['maximum']} | "
            f"{min_ess:.1f} | {100.0 * max_parameter_mcse:.3f}% | "
            f"{100.0 * max_galactic_mcse:.3f}% |"
        )
    lines.extend(
        [
            "",
            "All 800 selected realizations therefore pass the declared adaptive",
            "convergence gate. This statement refers to 400 constant realizations from",
            "the successful constant artifact plus 400 zero realizations from the",
            "successful extended rerun; it does not describe run `32472776218` as a",
            "globally successful workflow.",
            "",
            "## Headline medians",
            "",
            "| Branch | N_star | median mean f_EE | product Lambda_EE | Reported |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for branch, data in (("constant", constant), ("zero", zero)):
        origin = data["headline_median_origin"]
        lines.append(
            f"| {branch} | {origin['N_star_7_9_kpc']:.8f} | "
            f"{origin['mean_f_EE_q50']:.17g} | "
            f"{origin['artifact_Lambda_EE_q50']:.17g} | "
            f"{origin['reported_million_3dp']:.3f} million |"
        )
    lines.extend(
        [
            "",
            "The values 3.224 million and 4.572 million are direct rounded products",
            "of the frozen 7--9 kpc host count and the corresponding branch-specific",
            "posterior median mean occurrence. They are not newly fitted values.",
            "",
            "## Freeze rule",
            "",
            "These audited artifacts are the v4 statistical baseline. Manuscript,",
            "figure, bibliography, and production changes must not alter the frozen",
            "CSV/JSON values. Any numerical change requires a new statistical rerun, a",
            "new audit record, and a new release candidate.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--frozen-json", required=True, type=Path)
    parser.add_argument("--galactic-csv", required=True, type=Path)
    parser.add_argument("--github-evidence", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    artifact_root = args.artifact_root.resolve()
    frozen = load_json(args.frozen_json)
    github_evidence = load_json(args.github_evidence)
    require(frozen.get("status") == "PASS", "Committed numerical freeze is not PASS")
    require(
        github_evidence.get("repository") == "jerseroman/are-we-alone-in-the-universe",
        "Historical Actions evidence has the wrong or missing source repository",
    )
    require(
        github_evidence.get("run_provenance_record") == "provenance/RUN_PROVENANCE.json",
        "Historical Actions evidence does not point to the authoritative run map",
    )
    expected_run_metadata = {
        "pilot_seed_stability": (20000, ".github/workflows/bryson-v4-corrected-pilot.yml"),
        "initial_production": (20000, ".github/workflows/bryson-v4-corrected-production.yml"),
        "zero_extended_rerun": (30000, ".github/workflows/bryson-v4-corrected-zero-extended.yml"),
        "constant_galactic_propagation": (None, ".github/workflows/bryson-v4-propagate-constant.yml"),
    }
    for run_name, (ceiling, workflow_path) in expected_run_metadata.items():
        run = github_evidence["actions_runs"][run_name]
        require(run.get("maximum_mcmc_steps") == ceiling, f"Wrong MCMC ceiling: {run_name}")
        require(run.get("workflow_path") == workflow_path, f"Wrong workflow path: {run_name}")
        require(
            run.get("url")
            == f"https://github.com/jerseroman/are-we-alone-in-the-universe/actions/runs/{run['id']}",
            f"Wrong or missing Actions URL: {run_name}",
        )
    require(
        github_evidence["actions_runs"]["initial_production"]["conclusion"] == "failure",
        "Initial production run must not be mislabeled as globally successful",
    )
    require(
        github_evidence["actions_runs"]["initial_production"]["selected_successful_job"]["conclusion"] == "success",
        "Selected constant aggregate job was not successful",
    )
    require(
        github_evidence["actions_runs"]["zero_extended_rerun"]["conclusion"] == "success",
        "Zero extended rerun was not successful",
    )
    committed_lambda_q50 = load_committed_lambda_q50(args.galactic_csv)
    branches = {
        branch: audit_branch(branch, artifact_root, frozen, committed_lambda_q50)
        for branch in ("constant", "zero")
    }
    require(
        sum(int(branch["selected_realizations"]) for branch in branches.values()) == 800,
        "Selected realization total is not 800",
    )
    audit = {
        "schema_version": 1,
        "status": "PASS",
        "baseline_label": "exoearth-v4-statistical-baseline-20260822",
        "scope": "Read-only audit of the selected corrected posterior and conditional Galactic-propagation artifacts.",
        "source_actions_repository": github_evidence["repository"],
        "run_provenance_record": github_evidence["run_provenance_record"],
        "source_checkout_commit": github_evidence["source_checkout_commit"],
        "numerical_freeze_commits": github_evidence["numerical_freeze_commits"],
        "github_actions_evidence_sha256": sha256(args.github_evidence),
        "committed_numerical_freeze_sha256": sha256(args.frozen_json),
        "committed_galactic_csv_sha256": sha256(args.galactic_csv),
        "selected_realizations_total": 800,
        "actions_runs": github_evidence["actions_runs"],
        "selected_artifacts": github_evidence["selected_artifacts"],
        "branches": branches,
        "freeze_rule": "No later manuscript or figure edit may alter these numerical values without a new statistical rerun and a new baseline audit.",
    }

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    audit_path = out / "V4_STATISTICAL_BASELINE_AUDIT.json"
    audit_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_markdown(out / "V4_STATISTICAL_BASELINE_AUDIT.md", audit)
    checksum_entries = {
        "V4_STATISTICAL_BASELINE_AUDIT.json": sha256(audit_path),
        "V4_STATISTICAL_BASELINE_AUDIT.md": sha256(out / "V4_STATISTICAL_BASELINE_AUDIT.md"),
        Path(os.path.relpath(args.github_evidence.resolve(), out)).as_posix(): sha256(args.github_evidence),
        Path(os.path.relpath(args.frozen_json.resolve(), out)).as_posix(): sha256(args.frozen_json),
        Path(os.path.relpath(args.galactic_csv.resolve(), out)).as_posix(): sha256(args.galactic_csv),
    }
    checksum_path = out / "SHA256SUMS_v4_statistical_baseline.txt"
    checksum_path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksum_entries.items()),
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
