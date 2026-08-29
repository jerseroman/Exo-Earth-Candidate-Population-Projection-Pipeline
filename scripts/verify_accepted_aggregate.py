#!/usr/bin/env python3
"""Fail closed unless an aggregate artifact passed the production gate."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PARAMETERS = ("F0", "alpha", "beta", "gamma")
ROOT = Path(__file__).resolve().parents[1]
DATA_LOCKS = ROOT / "provenance" / "DATA_LOCKS.json"
BRYSON_REPOSITORY = "stevepur/DR25-occurrence-public"
BRYSON_SOURCE_RELATIVE_PATH = "insolation/rateModels3D.py"
V404_ACCEPTANCE_PROFILE = "v4.0.4-production"
V404_ZERO_EXTENDED_PROFILE = "v4.0.4-zero-extended"
V404_SCALE = {
    "shards": 16,
    "trials_per_shard": 25,
    "total_trials": 400,
    "walkers": 16,
    "burnin_steps": 1000,
    "production_steps_requested_minimum": 3000,
    "runner_thin": 20,
    "equalized_samples_per_realization": 1024,
    "full_sample_count": 409600,
    "propagation_stride_within_each_realization": 2,
    "galactic_propagation_sample_count": 204800,
}
EXPECTED_MCSE_KEYS = {
    "outer_q50_mcse_fraction_of_q16_q84_width",
    "inner_q50_mcse_fraction_of_q16_q84_width",
}


def fail(message: str) -> None:
    raise SystemExit(f"ACCEPTED AGGREGATE FAIL: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_dict(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} is missing or invalid")
    return value


def require_finite_number(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} is missing or not a JSON number")
    numeric = float(value)
    if not math.isfinite(numeric):
        fail(f"{description} is not finite")
    return numeric


def require_exact_integer(value: Any, expected: int, description: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        fail(f"{description} must equal integer {expected}; found {value!r}")


def data_locks() -> dict[str, Any]:
    try:
        registry = json.loads(DATA_LOCKS.read_text(encoding="utf-8"))
        locks = registry["locks"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        fail(f"cannot read DATA_LOCKS.json: {error}")
    if not isinstance(locks, dict):
        fail("DATA_LOCKS.json has an invalid locks object")
    return locks


def expected_bryson_source_sha256() -> str:
    locks = data_locks()
    try:
        expected = str(locks["bryson_rate_models_3d"]["expected_sha256"]).lower()
    except (KeyError, TypeError) as error:
        fail(f"Bryson source lock is incomplete: {error}")
    if not SHA256_RE.fullmatch(expected):
        fail("Bryson source lock is not a valid SHA-256")
    return expected


def expected_input_sha256(branch: str) -> dict[str, str]:
    locks = data_locks()
    lock_ids = {
        "stellar_catalog": "bryson_stellar_catalog_extracted",
        "pc_catalog": "bryson_pc_catalog",
        "completeness": (
            "completeness_constant" if branch == "constant" else "completeness_zero"
        ),
    }
    try:
        expected = {
            key: str(locks[lock_id]["expected_sha256"]).lower()
            for key, lock_id in lock_ids.items()
        }
    except (KeyError, TypeError) as error:
        fail(f"scientific input locks are incomplete: {error}")
    if any(not SHA256_RE.fullmatch(value) for value in expected.values()):
        fail("a scientific input lock is not a valid SHA-256")
    return expected


def expected_aggregate_files(branch: str) -> set[str]:
    return {
        f"joint_posterior_{branch}_full.csv.gz",
        f"joint_posterior_{branch}_for_galactic_propagation.csv.gz",
        f"joint_posterior_{branch}_correlation.csv",
        f"trial_diagnostics_{branch}_full.jsonl",
        f"joint_posterior_{branch}_aggregate_summary.json",
        f"perturbation_audit_{branch}_full.csv.gz",
    }


def verify_manifest(root: Path, branch: str) -> dict[str, str]:
    manifest = root / f"SHA256SUMS_{branch}_aggregate.txt"
    if not manifest.is_file() or manifest.is_symlink():
        fail(f"missing safe aggregate manifest: {manifest}")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), 1
    ):
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match is None:
            fail(f"invalid manifest line {line_number}: {line!r}")
        name = match.group(2).replace("\\", "/")
        while name.startswith("./"):
            name = name[2:]
        if not name or "/" in name or name in entries:
            fail(f"unsafe or duplicate aggregate-manifest path: {name!r}")
        entries[name] = match.group(1)

    expected_files = expected_aggregate_files(branch)
    if set(entries) != expected_files:
        fail(
            "aggregate manifest does not contain the exact canonical file set: "
            f"expected={sorted(expected_files)}, found={sorted(entries)}"
        )
    actual_files = {
        path.name
        for path in root.iterdir()
        if path.is_file() and not path.is_symlink() and path.name != manifest.name
    }
    if set(entries) != actual_files:
        fail(
            "aggregate manifest file set differs from artifact contents: "
            f"manifest={sorted(entries)}, files={sorted(actual_files)}"
        )
    for name, expected in entries.items():
        path = root / name
        actual = sha256(path)
        if actual != expected:
            fail(f"SHA-256 mismatch for {name}: {actual} != {expected}")
    return entries


def verify_mcse_record(gate: dict[str, Any]) -> None:
    mcse = require_dict(gate.get("q50_mcse_by_parameter"), "q50 MCSE record")
    if set(mcse) != set(PARAMETERS):
        fail("q50 MCSE record does not cover all four occurrence parameters")
    for parameter in PARAMETERS:
        record = require_dict(mcse.get(parameter), f"q50 MCSE record for {parameter}")
        if set(record) != EXPECTED_MCSE_KEYS:
            fail(f"q50 MCSE record for {parameter} has an invalid field set")
        outer = require_finite_number(
            record["outer_q50_mcse_fraction_of_q16_q84_width"],
            f"outer q50 MCSE fraction for {parameter}",
        )
        inner = require_finite_number(
            record["inner_q50_mcse_fraction_of_q16_q84_width"],
            f"inner q50 MCSE fraction for {parameter}",
        )
        if outer < 0.0 or outer > 0.10:
            fail(f"outer q50 MCSE fraction for {parameter} is outside [0, 0.10]")
        if inner < 0.0 or inner > 0.05:
            fail(f"inner q50 MCSE fraction for {parameter} is outside [0, 0.05]")


def verify_locked_inputs(summary: dict[str, Any], branch: str) -> None:
    observed = require_dict(
        summary.get("locked_input_sha256"), "locked scientific-input hashes"
    )
    expected = expected_input_sha256(branch)
    if set(observed) != set(expected):
        fail(
            "locked scientific-input key set mismatch: "
            f"expected={sorted(expected)}, found={sorted(observed)}"
        )
    for key, expected_hash in expected.items():
        actual = observed.get(key)
        if not isinstance(actual, str) or actual.lower() != expected_hash:
            fail(f"locked scientific-input SHA-256 mismatch for {key}")


def verify_propagation_csv(root: Path, branch: str) -> None:
    path = root / f"joint_posterior_{branch}_for_galactic_propagation.csv.gz"
    expected_header = ["branch", "global_trial", *PARAMETERS]
    counts = [0] * V404_SCALE["total_trials"]
    row_count = 0
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != expected_header:
                fail(
                    "propagation CSV header mismatch: "
                    f"expected={expected_header}, found={reader.fieldnames}"
                )
            for row_number, row in enumerate(reader, 2):
                if set(row) != set(expected_header) or row.get("branch") != branch:
                    fail(f"invalid propagation CSV row {row_number}")
                raw_trial = row.get("global_trial", "")
                if not re.fullmatch(r"0|[1-9][0-9]*", raw_trial):
                    fail(f"invalid global_trial at propagation CSV row {row_number}")
                trial = int(raw_trial)
                if trial >= len(counts):
                    fail(f"out-of-range global_trial at propagation CSV row {row_number}")
                counts[trial] += 1
                for parameter in PARAMETERS:
                    try:
                        value = float(row[parameter])
                    except (TypeError, ValueError) as error:
                        fail(
                            f"invalid {parameter} at propagation CSV row {row_number}: "
                            f"{error}"
                        )
                    if not math.isfinite(value):
                        fail(f"non-finite {parameter} at propagation CSV row {row_number}")
                row_count += 1
    except (OSError, UnicodeError, csv.Error) as error:
        fail(f"cannot validate propagation CSV: {error}")
    expected_rows = V404_SCALE["galactic_propagation_sample_count"]
    if row_count != expected_rows:
        fail(f"propagation CSV row count mismatch: {row_count} != {expected_rows}")
    expected_per_trial = math.ceil(
        V404_SCALE["equalized_samples_per_realization"]
        / V404_SCALE["propagation_stride_within_each_realization"]
    )
    if any(count != expected_per_trial for count in counts):
        fail("propagation CSV does not represent every realization equally")


def verify_summary(
    root: Path, branch: str, expected_source_sha256: str, entries: dict[str, str]
) -> None:
    summary_name = f"joint_posterior_{branch}_aggregate_summary.json"
    propagation_name = f"joint_posterior_{branch}_for_galactic_propagation.csv.gz"
    for required in (summary_name, propagation_name):
        if required not in entries:
            fail(f"aggregate manifest lacks required file: {required}")

    try:
        summary = json.loads((root / summary_name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read aggregate summary: {error}")
    if not isinstance(summary, dict) or summary.get("branch") != branch:
        fail("aggregate summary branch mismatch")
    if summary.get("source_repository") != BRYSON_REPOSITORY:
        fail("aggregate source-repository mismatch")
    if summary.get("period_cutoff_days") is not None:
        fail("aggregate unexpectedly applies a source-period cutoff")

    gate = require_dict(
        summary.get("production_acceptance_gate"),
        "production_acceptance_gate",
    )
    if gate.get("required") is not True or gate.get("accepted") is not True:
        fail("production acceptance gate is not explicitly required and accepted")
    profile = gate.get("profile")
    allowed_profiles = {V404_ACCEPTANCE_PROFILE}
    if branch == "zero":
        allowed_profiles.add(V404_ZERO_EXTENDED_PROFILE)
    if profile not in allowed_profiles:
        fail(f"aggregate acceptance profile is not valid for branch {branch!r}")
    if gate.get("expected_bryson_source_sha256") != expected_source_sha256:
        fail("production gate Bryson source SHA-256 mismatch")
    minimum_ess = require_finite_number(
        gate.get("minimum_ess_per_realization"), "production ESS threshold"
    )
    outer_limit = require_finite_number(
        gate.get("maximum_outer_q50_mcse_fraction_of_q16_q84_width"),
        "outer q50 MCSE threshold",
    )
    inner_limit = require_finite_number(
        gate.get("maximum_inner_q50_mcse_fraction_of_q16_q84_width"),
        "inner q50 MCSE threshold",
    )
    if minimum_ess != 1000.0:
        fail("v4.0.4 production ESS threshold must equal 1000")
    if outer_limit != 0.10:
        fail("v4.0.4 outer q50 MCSE threshold must equal 0.10")
    if inner_limit != 0.05:
        fail("v4.0.4 inner q50 MCSE threshold must equal 0.05")
    verify_mcse_record(gate)

    provenance = require_dict(summary.get("source_provenance"), "source provenance")
    if provenance.get("verified_for_every_shard") is not True:
        fail("Bryson source was not verified for every shard")
    if provenance.get("expected_source_file_sha256") != expected_source_sha256:
        fail("aggregate source-provenance SHA-256 mismatch")
    if provenance.get("source_file_relative_path") != BRYSON_SOURCE_RELATIVE_PATH:
        fail("aggregate source-provenance path mismatch")
    methods = provenance.get("verification_methods")
    allowed_methods = {
        "git_head_source_bytes",
        "explicit_cli_sha256",
        "artifact_sha256_manifest",
    }
    if (
        not isinstance(methods, list)
        or not methods
        or len(methods) != len(set(methods))
        or any(method not in allowed_methods for method in methods)
    ):
        fail("aggregate source-provenance methods are invalid")
    verify_locked_inputs(summary, branch)
    environment_sha256 = str(summary.get("numerical_environment_sha256", ""))
    if not SHA256_RE.fullmatch(environment_sha256):
        fail("aggregate summary lacks a valid numerical-environment SHA-256")

    measurement_error = require_dict(
        summary.get("measurement_error"), "measurement-error metadata"
    )
    if measurement_error.get("mode") != "quantile_matched_two_sided":
        fail("aggregate did not use corrected two-sided measurement-error propagation")
    if summary.get("parameter_order") != [
        "F0",
        "alpha_radius",
        "beta_inst",
        "gamma",
    ]:
        fail("aggregate parameter order mismatch")
    for key, expected in V404_SCALE.items():
        require_exact_integer(summary.get(key), expected, key)

    seed_schedule = require_dict(
        summary.get("runner_seed_schedule"), "runner seed schedule"
    )
    if set(seed_schedule) != {
        "base_seed_by_shard",
        "trial_seed_increment",
        "mcmc_seed_offset",
    }:
        fail("runner seed schedule has an invalid field set")
    expected_base_seeds = [
        2026082200 + (100000 if branch == "zero" else 0) + shard * 1000
        for shard in range(V404_SCALE["shards"])
    ]
    if seed_schedule.get("base_seed_by_shard") != expected_base_seeds:
        fail("runner base-seed schedule mismatch")
    require_exact_integer(
        seed_schedule.get("trial_seed_increment"),
        1_000_003,
        "trial seed increment",
    )
    require_exact_integer(
        seed_schedule.get("mcmc_seed_offset"),
        500000003,
        "MCMC seed offset",
    )

    policy = require_dict(
        gate.get("adaptive_production_policy"), "adaptive production policy"
    )
    expected_policy_keys = {
        "requested_minimum_steps",
        "check_interval",
        "tau_multiple",
        "tau_relative_tolerance",
        "required_consecutive_stable_checks",
        "requested_maximum_steps",
    }
    if set(policy) != expected_policy_keys:
        fail("adaptive production policy has an invalid field set")
    require_exact_integer(
        policy.get("requested_minimum_steps"), 3000, "adaptive minimum steps"
    )
    require_exact_integer(policy.get("check_interval"), 1000, "adaptive check interval")
    if require_finite_number(policy.get("tau_multiple"), "adaptive tau multiple") != 100.0:
        fail("adaptive tau multiple must equal 100")
    if (
        require_finite_number(
            policy.get("tau_relative_tolerance"), "adaptive tau tolerance"
        )
        != 0.05
    ):
        fail("adaptive tau tolerance must equal 0.05")
    require_exact_integer(
        policy.get("required_consecutive_stable_checks"),
        2,
        "required consecutive stable checks",
    )
    maximum_steps = policy.get("requested_maximum_steps")
    expected_maximum_steps = (
        30000 if profile == V404_ZERO_EXTENDED_PROFILE else 20000
    )
    if (
        isinstance(maximum_steps, bool)
        or not isinstance(maximum_steps, int)
        or maximum_steps != expected_maximum_steps
    ):
        fail(
            "adaptive maximum steps do not match the declared acceptance profile"
        )
    completed_quantiles = summary.get("production_steps_completed_q16_q50_q84")
    if not isinstance(completed_quantiles, list) or len(completed_quantiles) != 3:
        fail("completed-step quantiles are missing or invalid")
    completed = [
        require_finite_number(value, "completed-step quantile")
        for value in completed_quantiles
    ]
    if completed != sorted(completed) or any(
        value < 3000.0 or value > maximum_steps for value in completed
    ):
        fail("completed-step quantiles violate the adaptive production policy")

    mcse_metadata = require_dict(
        summary.get("posterior_quantile_monte_carlo_error"),
        "posterior quantile Monte Carlo error",
    )
    require_exact_integer(
        mcse_metadata.get("outer_realization_cluster_bootstrap_replicates"),
        1000,
        "outer bootstrap replicates",
    )
    require_exact_integer(
        mcse_metadata.get("outer_realization_cluster_bootstrap_seed"),
        2026082101,
        "outer bootstrap seed",
    )
    require_exact_integer(
        mcse_metadata.get("inner_chain_batches"), 8, "inner chain batches"
    )
    verify_propagation_csv(root, branch)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--expected-bryson-source-sha256", required=True)
    args = parser.parse_args()

    expected_source_sha256 = args.expected_bryson_source_sha256.strip().lower()
    if not SHA256_RE.fullmatch(expected_source_sha256):
        parser.error(
            "expected-bryson-source-sha256 must be exactly 64 hexadecimal characters"
        )
    locked_source_sha256 = expected_bryson_source_sha256()
    if expected_source_sha256 != locked_source_sha256:
        fail(
            "CLI Bryson source SHA-256 does not match DATA_LOCKS.json: "
            f"{expected_source_sha256} != {locked_source_sha256}"
        )
    root = args.artifact_root.resolve()
    if not root.is_dir():
        fail(f"aggregate artifact root is not a directory: {root}")
    entries = verify_manifest(root, args.branch)
    verify_summary(root, args.branch, expected_source_sha256, entries)
    print(
        f"PASS accepted {args.branch} aggregate "
        f"({len(entries)} manifest-locked files)"
    )


if __name__ == "__main__":
    main()
