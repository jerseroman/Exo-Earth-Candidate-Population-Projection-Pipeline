#!/usr/bin/env python3
"""Aggregate seeded Bryson hab2 posterior shards.

Every outer reliability/measurement realization contributes the same number of
post-burn samples, preserving the equal-mixture convention of the public
Bryson notebook.  The constant- and zero-completeness branches are aggregated
separately and are never merged into an implicit model-averaged posterior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from clustered_monte_carlo import (
    DETERMINISTIC_GZIP_COMPRESSION,
    cluster_bootstrap_quantile_mcse,
    contiguous_batch_quantile_mcse,
    equalize_realizations,
    quantile_summary,
)
from measurement_error import (
    LEGACY_SOURCE_MIXTURE,
    MEASUREMENT_ERROR_MODES,
    QUANTILE_MATCHED_TWO_SIDED,
)

PARAMETERS = ("F0", "alpha", "beta", "gamma")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DATA_LOCKS_PATH = REPOSITORY_ROOT / "provenance" / "DATA_LOCKS.json"
BRYSON_REPOSITORY = "stevepur/DR25-occurrence-public"
BRYSON_SOURCE_RELATIVE_PATH = "insolation/rateModels3D.py"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PRODUCTION_MINIMUM_ESS = 1000.0
PRODUCTION_MAXIMUM_OUTER_MCSE_FRACTION = 0.10
PRODUCTION_MAXIMUM_INNER_MCSE_FRACTION = 0.05
PRODUCTION_MINIMUM_BOOTSTRAP_REPLICATES = 1000
PRODUCTION_MINIMUM_INNER_BATCHES = 8
CUSTOM_ACCEPTANCE_PROFILE = "custom-quality-gate"
V404_ACCEPTANCE_PROFILE = "v4.0.4-production"
V404_ZERO_EXTENDED_PROFILE = "v4.0.4-zero-extended"
V404_RELEASE_PROFILES = {V404_ACCEPTANCE_PROFILE, V404_ZERO_EXTENDED_PROFILE}
V404_PROFILE_VALUES = {
    "expected_shards": 16,
    "trials_per_shard": 25,
    "walkers": 16,
    "steps": 3000,
    "runner_thin": 20,
    "samples_per_realization": 1024,
    "cluster_bootstrap_replicates": 1000,
    "bootstrap_seed": 2026082101,
    "inner_chain_batches": 8,
    "propagation_stride": 2,
}
ARCHIVED = {
    "constant": {
        "q16": [0.665, -1.934, -1.139, -4.242],
        "q50": [1.107, -1.082, -0.839, -2.671],
        "q84": [1.988, -0.142, -0.517, -1.084],
    },
    "zero": {
        "q16": [0.887, -2.048, -1.550, -3.152],
        "q50": [1.590, -1.175, -1.195, -1.376],
        "q84": [3.149, -0.219, -0.824, 0.467],
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-shards", type=int, default=8)
    parser.add_argument("--trials-per-shard", type=int, default=50)
    parser.add_argument("--walkers", type=int, default=8)
    parser.add_argument("--steps", type=int, default=2000)
    parser.add_argument("--runner-thin", type=int, default=10)
    parser.add_argument(
        "--samples-per-realization",
        type=int,
        default=None,
        help=(
            "For adaptive chains, deterministically select this many evenly "
            "spaced post-burn rows from every realization."
        ),
    )
    parser.add_argument(
        "--require-all-converged",
        action="store_true",
        help=(
            "Enable the production acceptance gate: require every adaptive "
            "realization to pass its tau gate and optimizer, require finite "
            "per-parameter ESS at or above --minimum-ess-per-realization, and "
            "require finite outer/inner q50 MCSE diagnostics within their "
            "configured fractions of the q16--q84 width."
        ),
    )
    parser.add_argument(
        "--acceptance-profile",
        choices=(
            CUSTOM_ACCEPTANCE_PROFILE,
            V404_ACCEPTANCE_PROFILE,
            V404_ZERO_EXTENDED_PROFILE,
        ),
        default=CUSTOM_ACCEPTANCE_PROFILE,
        help=(
            "Name the acceptance contract. The two v4.0.4 release profiles "
            "additionally fix the complete release-scale aggregation setup; "
            "the default custom-quality-gate cannot pass the downstream release verifier."
        ),
    )
    parser.add_argument(
        "--minimum-ess-per-realization",
        type=float,
        default=1000.0,
        help=(
            "Minimum finite ESS required for every parameter in every "
            "realization when --require-all-converged is set (default: 1000)."
        ),
    )
    parser.add_argument(
        "--maximum-outer-q50-mcse-fraction",
        type=float,
        default=0.10,
        help=(
            "Maximum outer-realization q50 MCSE divided by posterior q16--q84 "
            "width under the production gate (default: 0.10)."
        ),
    )
    parser.add_argument(
        "--maximum-inner-q50-mcse-fraction",
        type=float,
        default=0.05,
        help=(
            "Maximum inner-chain q50 MCSE divided by posterior q16--q84 width "
            "under the production gate (default: 0.05)."
        ),
    )
    parser.add_argument("--cluster-bootstrap-replicates", type=int, default=0)
    parser.add_argument("--bootstrap-seed", type=int, default=2026082101)
    parser.add_argument("--inner-chain-batches", type=int, default=0)
    parser.add_argument(
        "--expected-measurement-error-mode",
        choices=MEASUREMENT_ERROR_MODES,
        default=None,
        help="Fail unless every shard used this measurement-error mode.",
    )
    parser.add_argument(
        "--expected-bryson-source-sha256",
        default=None,
        metavar="SHA256",
        help=(
            "Exact independently locked SHA-256 of the Bryson rateModels3D.py "
            "source. Required by the production acceptance gate."
        ),
    )
    parser.add_argument(
        "--propagation-stride",
        type=int,
        default=5,
        help="Additional within-realization thinning for Galactic propagation only.",
    )
    args = parser.parse_args()
    if args.expected_shards <= 0 or args.trials_per_shard <= 0:
        parser.error("expected-shards and trials-per-shard must be positive")
    if args.walkers <= 0 or args.steps <= 0 or args.runner_thin <= 0:
        parser.error("walkers, steps, and runner-thin must be positive")
    if args.propagation_stride <= 0:
        parser.error("propagation-stride must be positive")
    if (
        not np.isfinite(args.minimum_ess_per_realization)
        or args.minimum_ess_per_realization <= 0.0
    ):
        parser.error("minimum-ess-per-realization must be finite and positive")
    for name in (
        "maximum_outer_q50_mcse_fraction",
        "maximum_inner_q50_mcse_fraction",
    ):
        value = float(getattr(args, name))
        if not np.isfinite(value) or value < 0.0:
            parser.error(f"{name.replace('_', '-')} must be finite and non-negative")
    if args.require_all_converged:
        if args.minimum_ess_per_realization < PRODUCTION_MINIMUM_ESS:
            parser.error(
                "the production gate requires minimum-ess-per-realization "
                f">= {PRODUCTION_MINIMUM_ESS:g}"
            )
        if (
            args.maximum_outer_q50_mcse_fraction
            > PRODUCTION_MAXIMUM_OUTER_MCSE_FRACTION
        ):
            parser.error(
                "the production gate requires maximum-outer-q50-mcse-fraction "
                f"<= {PRODUCTION_MAXIMUM_OUTER_MCSE_FRACTION:g}"
            )
        if (
            args.maximum_inner_q50_mcse_fraction
            > PRODUCTION_MAXIMUM_INNER_MCSE_FRACTION
        ):
            parser.error(
                "the production gate requires maximum-inner-q50-mcse-fraction "
                f"<= {PRODUCTION_MAXIMUM_INNER_MCSE_FRACTION:g}"
            )
        if (
            args.cluster_bootstrap_replicates
            < PRODUCTION_MINIMUM_BOOTSTRAP_REPLICATES
        ):
            parser.error(
                "--require-all-converged requires at least "
                f"{PRODUCTION_MINIMUM_BOOTSTRAP_REPLICATES} "
                "--cluster-bootstrap-replicates"
            )
        if args.inner_chain_batches < PRODUCTION_MINIMUM_INNER_BATCHES:
            parser.error(
                "--require-all-converged requires at least "
                f"{PRODUCTION_MINIMUM_INNER_BATCHES} --inner-chain-batches"
            )
        if args.expected_bryson_source_sha256 is None:
            parser.error(
                "--require-all-converged requires "
                "--expected-bryson-source-sha256"
            )
    if args.expected_bryson_source_sha256 is not None:
        args.expected_bryson_source_sha256 = (
            args.expected_bryson_source_sha256.strip().lower()
        )
        if not SHA256_RE.fullmatch(args.expected_bryson_source_sha256):
            parser.error(
                "expected-bryson-source-sha256 must be exactly 64 "
                "hexadecimal characters"
            )
    if args.acceptance_profile in V404_RELEASE_PROFILES:
        if not args.require_all_converged:
            parser.error(
                f"--acceptance-profile {V404_ACCEPTANCE_PROFILE} requires "
                "--require-all-converged"
            )
        if (
            args.acceptance_profile == V404_ZERO_EXTENDED_PROFILE
            and args.branch != "zero"
        ):
            parser.error(
                f"--acceptance-profile {V404_ZERO_EXTENDED_PROFILE} is valid "
                "only for the zero-completeness branch"
            )
        mismatches = {
            key: (expected, getattr(args, key))
            for key, expected in V404_PROFILE_VALUES.items()
            if getattr(args, key) != expected
        }
        expected_source = expected_bryson_source_sha256()
        if args.expected_bryson_source_sha256 != expected_source:
            mismatches["expected_bryson_source_sha256"] = (
                expected_source,
                args.expected_bryson_source_sha256,
            )
        exact_values = {
            "minimum_ess_per_realization": PRODUCTION_MINIMUM_ESS,
            "maximum_outer_q50_mcse_fraction": (
                PRODUCTION_MAXIMUM_OUTER_MCSE_FRACTION
            ),
            "maximum_inner_q50_mcse_fraction": (
                PRODUCTION_MAXIMUM_INNER_MCSE_FRACTION
            ),
            "expected_measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED,
        }
        mismatches.update(
            {
                key: (expected, getattr(args, key))
                for key, expected in exact_values.items()
                if getattr(args, key) != expected
            }
        )
        if mismatches:
            parser.error(
                f"{V404_ACCEPTANCE_PROFILE} profile mismatch: {mismatches}"
            )
    return args


def qsummary(values: np.ndarray) -> dict[str, float]:
    return quantile_summary(values)


def parse_shard(label: str) -> int:
    match = re.fullmatch(r"production-shard-(\d+)", label)
    if match is None:
        raise RuntimeError(f"Unexpected production run label: {label!r}")
    return int(match.group(1))


def index_shard_artifacts(
    paths: list[Path], filename_pattern: str, artifact_name: str
) -> dict[int, Path]:
    """Index artifact paths by the exact shard ID encoded in their filename."""

    pattern = re.compile(filename_pattern)
    indexed: dict[int, Path] = {}
    for path in paths:
        match = pattern.fullmatch(path.name)
        if match is None:
            raise RuntimeError(f"Unexpected {artifact_name} filename: {path.name!r}")
        shard = int(match.group(1))
        if shard in indexed:
            raise RuntimeError(
                f"Duplicate {artifact_name} shard ID {shard}: "
                f"{indexed[shard]} and {path}"
            )
        indexed[shard] = path
    return indexed


def require_exact_shard_ids(
    indexed: dict[int, Path], expected_shards: int, artifact_name: str
) -> None:
    """Require exactly shard IDs 0..expected_shards-1, not merely a file count."""

    expected = set(range(expected_shards))
    observed = set(indexed)
    if observed != expected:
        raise RuntimeError(
            f"{artifact_name} shard IDs mismatch: expected {sorted(expected)}, "
            f"found {sorted(observed)}; missing {sorted(expected - observed)}, "
            f"unexpected {sorted(observed - expected)}"
        )


def require_exact_trial_ids(
    values: Any, trials_per_shard: int, context: str
) -> set[int]:
    """Require exact integer trial IDs 0..trials_per_shard-1."""

    raw_values = list(values)
    if not raw_values:
        raise RuntimeError(f"Invalid non-integer trial IDs in {context}")
    observed = {
        exact_integer_value(value, "trial", context) for value in raw_values
    }
    expected = set(range(trials_per_shard))
    if observed != expected:
        raise RuntimeError(
            f"Trial IDs mismatch in {context}: expected {sorted(expected)}, "
            f"found {sorted(observed)}"
        )
    return observed


def unique_integer(frame: pd.DataFrame, column: str, context: str) -> int:
    """Return one exact finite integer value shared by all rows in a group."""

    if column not in frame.columns:
        raise RuntimeError(f"Missing {column} in {context}")
    values = frame[column].tolist()
    if not values:
        raise RuntimeError(f"Invalid {column} in {context}")
    unique = {
        exact_integer_value(value, column, context) for value in values
    }
    if len(unique) != 1:
        raise RuntimeError(f"Multiple {column} values in {context}: {sorted(unique)}")
    return next(iter(unique))


def exact_integer_value(value: Any, key: str, context: str) -> int:
    """Parse an integer without lossy IEEE-754 conversion."""

    if isinstance(value, bool):
        raise RuntimeError(f"Missing or invalid {key} in {context}")
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[+-]?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if isinstance(value, (float, np.floating)):
        numeric = float(value)
        if (
            np.isfinite(numeric)
            and numeric == np.floor(numeric)
            and abs(numeric) <= 2**53
        ):
            return int(numeric)
    raise RuntimeError(f"Missing or invalid {key} in {context}")


def diagnostic_integer(entry: dict[str, Any], key: str, context: str) -> int:
    """Read a required exact finite integer from one diagnostic record."""

    if key not in entry:
        raise RuntimeError(f"Missing or invalid {key} in {context}")
    return exact_integer_value(entry[key], key, context)


def validate_shard_source_provenance(
    summary: dict[str, Any], context: str, expected_sha256: str
) -> dict[str, Any]:
    """Require a verified, byte-identical Bryson source record for one shard."""

    provenance = summary.get("source_provenance")
    if not isinstance(provenance, dict) or provenance.get("verified") is not True:
        raise RuntimeError(f"Missing verified Bryson source provenance in {context}")
    if summary.get("source_repository") != BRYSON_REPOSITORY:
        raise RuntimeError(f"Unexpected Bryson source repository in {context}")
    if provenance.get("source_repository") != BRYSON_REPOSITORY:
        raise RuntimeError(f"Provenance repository mismatch in {context}")

    source_file = provenance.get("source_file")
    if not isinstance(source_file, dict):
        raise RuntimeError(f"Missing Bryson source-file provenance in {context}")
    if source_file.get("relative_path") != BRYSON_SOURCE_RELATIVE_PATH:
        raise RuntimeError(f"Bryson source relative-path mismatch in {context}")
    actual_sha256 = str(source_file.get("sha256", "")).strip().lower()
    if not SHA256_RE.fullmatch(actual_sha256) or actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"Bryson source SHA-256 mismatch in {context}: expected "
            f"{expected_sha256}, found {actual_sha256!r}"
        )

    method = provenance.get("verification_method")
    if method not in {
        "git_head_source_bytes",
        "explicit_cli_sha256",
        "artifact_sha256_manifest",
    }:
        raise RuntimeError(
            f"Unsupported Bryson source verification method in {context}: {method!r}"
        )
    commit = provenance.get("source_commit")
    if commit is not None:
        commit = str(commit).strip().lower()
        if not GIT_COMMIT_RE.fullmatch(commit):
            raise RuntimeError(f"Invalid Bryson source commit in {context}")
    if summary.get("source_commit") != commit:
        raise RuntimeError(f"Summary/provenance source-commit mismatch in {context}")

    return {
        "verification_method": method,
        "source_commit": commit,
        "source_file_sha256": actual_sha256,
    }


def finite_number(value: Any, key: str, context: str) -> float:
    """Read one required finite non-boolean number."""

    if isinstance(value, bool):
        raise RuntimeError(f"Missing or invalid {key} in {context}")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"Missing or invalid {key} in {context}") from error
    if not np.isfinite(numeric):
        raise RuntimeError(f"Missing or invalid {key} in {context}")
    return numeric


def validate_adaptive_summary_policy(
    summaries: list[dict[str, Any]], args: argparse.Namespace
) -> dict[str, Any]:
    """Require a common, sufficiently strict adaptive-MCMC policy."""

    policies: list[dict[str, Any]] = []
    for shard, summary in enumerate(summaries):
        context = f"summary shard {shard}"
        raw = summary.get("adaptive_production")
        if not isinstance(raw, dict) or raw.get("enabled") is not True:
            raise RuntimeError(f"Adaptive production policy missing in {context}")
        policy = {
            "requested_minimum_steps": args.steps,
            "check_interval": diagnostic_integer(raw, "check_interval", context),
            "tau_multiple": finite_number(raw.get("tau_multiple"), "tau_multiple", context),
            "tau_relative_tolerance": finite_number(
                raw.get("tau_relative_tolerance"),
                "tau_relative_tolerance",
                context,
            ),
            "required_consecutive_stable_checks": diagnostic_integer(
                raw,
                "required_consecutive_stable_checks",
                context,
            ),
            "requested_maximum_steps": diagnostic_integer(
                summary,
                "production_steps_requested_maximum",
                context,
            ),
        }
        converged_realizations = diagnostic_integer(
            raw, "converged_realizations", context
        )
        if converged_realizations != args.trials_per_shard:
            raise RuntimeError(
                f"Converged-realization count mismatch in {context}: "
                f"{converged_realizations} != {args.trials_per_shard}"
            )
        if policy["check_interval"] <= 0:
            raise RuntimeError(f"Invalid adaptive check interval in {context}")
        if policy["tau_multiple"] < 100.0:
            raise RuntimeError(f"Adaptive tau multiple is below 100 in {context}")
        if not 0.0 < policy["tau_relative_tolerance"] <= 0.05:
            raise RuntimeError(
                f"Adaptive tau tolerance is outside (0, 0.05] in {context}"
            )
        if policy["required_consecutive_stable_checks"] < 2:
            raise RuntimeError(
                f"Adaptive stable-check requirement is below two in {context}"
            )
        if policy["requested_maximum_steps"] < args.steps:
            raise RuntimeError(f"Adaptive maximum is below minimum in {context}")
        policies.append(policy)
    if any(policy != policies[0] for policy in policies[1:]):
        raise RuntimeError("Adaptive production policy differs across shards")
    if args.acceptance_profile in V404_RELEASE_PROFILES:
        expected_maximum = (
            30000
            if args.acceptance_profile == V404_ZERO_EXTENDED_PROFILE
            else 20000
        )
        expected_policy = {
            "requested_minimum_steps": 3000,
            "check_interval": 1000,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
            "requested_maximum_steps": expected_maximum,
        }
        if policies[0] != expected_policy:
            raise RuntimeError(
                f"{args.acceptance_profile} adaptive policy mismatch: "
                f"expected {expected_policy}, found {policies[0]}"
            )
    return policies[0]


def validate_convergence_evidence(
    entry: dict[str, Any], policy: dict[str, Any]
) -> None:
    """Recompute the final adaptive convergence decision from serialized checks."""

    global_trial = int(entry["global_trial"])
    context = f"global trial {global_trial}"
    completed = diagnostic_integer(entry, "production_steps_completed", context)
    if completed < policy["requested_minimum_steps"]:
        raise RuntimeError(f"Completed steps are below the declared minimum in {context}")
    if completed > policy["requested_maximum_steps"]:
        raise RuntimeError(f"Completed steps exceed the declared maximum in {context}")
    checks = entry.get("convergence_checks")
    required = policy["required_consecutive_stable_checks"]
    if not isinstance(checks, list) or len(checks) < required + 1:
        raise RuntimeError(f"Incomplete convergence checks in {context}")
    interval = policy["check_interval"]
    expected_check_steps: list[int] = []
    scheduled_step = 0
    while scheduled_step < policy["requested_maximum_steps"]:
        scheduled_step = min(
            scheduled_step + interval,
            policy["requested_maximum_steps"],
        )
        if scheduled_step >= policy["requested_minimum_steps"]:
            expected_check_steps.append(scheduled_step)
        if scheduled_step >= completed:
            break
    if not expected_check_steps or expected_check_steps[-1] != completed:
        raise RuntimeError(f"Completed steps violate the adaptive schedule in {context}")
    if len(checks) != len(expected_check_steps):
        raise RuntimeError(f"Incomplete convergence-check schedule in {context}")

    previous_steps = -1
    previous_tau: np.ndarray | None = None
    recomputed_streak = 0
    for index, raw_check in enumerate(checks):
        if not isinstance(raw_check, dict):
            raise RuntimeError(f"Invalid convergence check in {context}")
        check_context = f"{context}, convergence check {index}"
        steps = diagnostic_integer(raw_check, "production_steps", check_context)
        if steps != expected_check_steps[index]:
            raise RuntimeError(f"Invalid convergence-check schedule in {context}")
        if (
            steps <= previous_steps
            or steps < policy["requested_minimum_steps"]
            or steps > completed
        ):
            raise RuntimeError(f"Invalid convergence-check step sequence in {context}")
        previous_steps = steps

        raw_tau = raw_check.get("autocorrelation_time")
        if raw_tau is None:
            current_tau = np.asarray([], dtype=float)
            valid_tau = False
        else:
            try:
                current_tau = np.asarray(raw_tau, dtype=float)
            except (TypeError, ValueError) as error:
                raise RuntimeError(
                    f"Invalid autocorrelation time in {check_context}"
                ) from error
            valid_tau = bool(
                current_tau.shape == (4,)
                and np.all(np.isfinite(current_tau))
                and np.all(current_tau > 0.0)
            )
            if not valid_tau:
                raise RuntimeError(f"Invalid autocorrelation time in {check_context}")

        recomputed_length_ok = bool(
            valid_tau and np.all(steps >= policy["tau_multiple"] * current_tau)
        )
        recomputed_stable = False
        recomputed_relative_change: float | None = None
        if valid_tau and previous_tau is not None:
            relative_change = np.abs(current_tau - previous_tau) / current_tau
            recomputed_relative_change = float(np.max(relative_change))
            recomputed_stable = bool(
                recomputed_relative_change <= policy["tau_relative_tolerance"]
            )

        if raw_check.get("length_ok") is not recomputed_length_ok:
            raise RuntimeError(f"Convergence length gate mismatch in {check_context}")
        if raw_check.get("stable") is not recomputed_stable:
            raise RuntimeError(f"Convergence stability gate mismatch in {check_context}")
        declared_relative_change = raw_check.get("max_relative_tau_change")
        if recomputed_relative_change is None:
            if declared_relative_change is not None:
                raise RuntimeError(
                    f"Convergence tau-change mismatch in {check_context}"
                )
        else:
            declared_change = finite_number(
                declared_relative_change,
                "max_relative_tau_change",
                check_context,
            )
            if not np.isclose(
                declared_change,
                recomputed_relative_change,
                rtol=1.0e-12,
                atol=1.0e-12,
            ):
                raise RuntimeError(
                    f"Convergence tau-change mismatch in {check_context}"
                )

        if recomputed_length_ok and recomputed_stable:
            recomputed_streak += 1
        else:
            recomputed_streak = 0
        declared_streak = diagnostic_integer(
            raw_check, "stable_check_streak", check_context
        )
        if declared_streak != recomputed_streak:
            raise RuntimeError(f"Convergence stable-streak mismatch in {check_context}")
        if recomputed_streak >= required and index != len(checks) - 1:
            raise RuntimeError(
                f"Convergence checks continue after the stopping gate in {context}"
            )
        if valid_tau:
            previous_tau = current_tau

    final = checks[-1]
    if previous_steps != completed:
        raise RuntimeError(f"Final convergence check does not match completed steps in {context}")
    if final.get("length_ok") is not True or final.get("stable") is not True:
        raise RuntimeError(f"Final convergence check is not accepted in {context}")
    if recomputed_streak != required:
        raise RuntimeError(f"Insufficient stable convergence checks in {context}")

    try:
        final_tau = np.asarray(final.get("autocorrelation_time"), dtype=float)
        diagnostic_tau = np.asarray(entry.get("autocorrelation_time"), dtype=float)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"Invalid final autocorrelation time in {context}") from error
    if (
        final_tau.shape != (4,)
        or diagnostic_tau.shape != (4,)
        or not np.all(np.isfinite(final_tau))
        or np.any(final_tau <= 0.0)
        or not np.allclose(final_tau, diagnostic_tau, rtol=1.0e-12, atol=1.0e-12)
    ):
        raise RuntimeError(f"Final autocorrelation-time mismatch in {context}")
    if not np.all(completed >= policy["tau_multiple"] * final_tau):
        raise RuntimeError(f"Recomputed chain-length/tau gate failed in {context}")
    relative_change = finite_number(
        final.get("max_relative_tau_change"),
        "max_relative_tau_change",
        context,
    )
    if relative_change < 0.0 or relative_change > policy["tau_relative_tolerance"]:
        raise RuntimeError(f"Final tau-stability tolerance failed in {context}")


def expected_input_sha256(branch: str) -> dict[str, str]:
    """Load branch-specific locked runner input hashes from DATA_LOCKS.json."""

    try:
        registry = json.loads(DATA_LOCKS_PATH.read_text(encoding="utf-8"))
        locks = registry["locks"]
        lock_ids = {
            "stellar_catalog": "bryson_stellar_catalog_extracted",
            "pc_catalog": "bryson_pc_catalog",
            "completeness": (
                "completeness_constant" if branch == "constant" else "completeness_zero"
            ),
        }
        expected = {
            key: str(locks[lock_id]["expected_sha256"]).lower()
            for key, lock_id in lock_ids.items()
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot load production input locks: {error}") from error
    if any(not SHA256_RE.fullmatch(value) for value in expected.values()):
        raise RuntimeError("Invalid SHA-256 in the production input-lock registry")
    return expected


def expected_bryson_source_sha256() -> str:
    """Load the independently locked Bryson likelihood-source hash."""

    try:
        registry = json.loads(DATA_LOCKS_PATH.read_text(encoding="utf-8"))
        expected = str(
            registry["locks"]["bryson_rate_models_3d"]["expected_sha256"]
        ).lower()
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot load the Bryson source lock: {error}") from error
    if not SHA256_RE.fullmatch(expected):
        raise RuntimeError("Invalid Bryson source SHA-256 in the data-lock registry")
    return expected


def validate_summary_input_locks(
    summary: dict[str, Any], expected: dict[str, str], context: str
) -> None:
    """Bind every shard summary to the branch-specific locked scientific inputs."""

    input_files = summary.get("input_files")
    if not isinstance(input_files, dict) or set(input_files) != set(expected):
        raise RuntimeError(f"Input-file provenance mismatch in {context}")
    for key, expected_sha256 in expected.items():
        record = input_files.get(key)
        if not isinstance(record, dict):
            raise RuntimeError(f"Missing input-file provenance for {key} in {context}")
        actual = str(record.get("sha256", "")).strip().lower()
        if actual != expected_sha256:
            raise RuntimeError(
                f"Locked input SHA-256 mismatch for {key} in {context}: "
                f"{actual!r} != {expected_sha256}"
            )


def verify_complete_shard_manifest(directory: Path, required_names: set[str]) -> str:
    """Verify a shard's complete file manifest and return its environment hash."""

    manifest = directory / "SHA256SUMS_complete.txt"
    if not manifest.is_file() or manifest.is_symlink():
        raise RuntimeError(f"Missing safe complete shard manifest in {directory}")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), 1
    ):
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match is None:
            raise RuntimeError(f"Invalid complete-manifest line {line_number} in {manifest}")
        name = match.group(2).replace("\\", "/")
        while name.startswith("./"):
            name = name[2:]
        if not name or "/" in name or name in entries:
            raise RuntimeError(f"Unsafe or duplicate manifest path {name!r} in {manifest}")
        entries[name] = match.group(1)

    actual_files = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and not path.is_symlink() and path.name != manifest.name
    }
    if set(entries) != actual_files or not required_names.issubset(actual_files):
        raise RuntimeError(
            f"Complete shard manifest file-set mismatch in {directory}: "
            f"manifest={sorted(entries)}, files={sorted(actual_files)}"
        )
    for name, expected_sha in entries.items():
        actual_sha = sha256(directory / name)
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"Complete shard manifest SHA-256 mismatch for {directory / name}"
            )
    environment = directory / "numerical_environment.txt"
    if not environment.is_file():
        raise RuntimeError(f"Missing numerical_environment.txt in {directory}")
    return sha256(environment)


def require_unique_diagnostic_seeds(diagnostics: list[dict[str, Any]]) -> None:
    """Reject duplicated outer or MCMC random streams across realizations."""

    for label, keys in (
        ("perturbation", ("perturbation_seed", "seed")),
        ("MCMC", ("mcmc_seed",)),
    ):
        observed: dict[int, int] = {}
        for entry in diagnostics:
            global_trial = int(entry["global_trial"])
            key = next((candidate for candidate in keys if candidate in entry), keys[0])
            value = diagnostic_integer(entry, key, f"global trial {global_trial}")
            if value in observed:
                raise RuntimeError(
                    f"Duplicate {label} seed {value} for global trials "
                    f"{observed[value]} and {global_trial}"
                )
            observed[value] = global_trial


def validate_chain_realization_structure(
    frame: pd.DataFrame,
    diagnostic: dict[str, Any],
    walkers: int,
    runner_thin: int,
    context: str,
) -> None:
    """Bind each chain table to its declared completed production length."""

    completed = diagnostic_integer(
        diagnostic, "production_steps_completed", context
    )
    retained_steps = completed // runner_thin
    if retained_steps <= 0:
        raise RuntimeError(f"No retained production steps in {context}")
    expected_rows = walkers * retained_steps
    if len(frame) != expected_rows:
        raise RuntimeError(
            f"Chain row count mismatch in {context}: expected {expected_rows} "
            f"from {completed} completed steps, {walkers} walkers, and thin "
            f"{runner_thin}; found {len(frame)}"
        )

    expected_step_ids = set(range(0, retained_steps * runner_thin, runner_thin))
    observed_step_ids = require_exact_integer_set(
        frame, "production_step", expected_step_ids, context
    )
    expected_walker_ids = set(range(walkers))
    observed_walker_ids = require_exact_integer_set(
        frame, "walker", expected_walker_ids, context
    )
    if observed_step_ids != expected_step_ids or observed_walker_ids != expected_walker_ids:
        raise RuntimeError(f"Unexpected chain coordinates in {context}")
    coordinates = frame.loc[:, ["production_step", "walker"]]
    if coordinates.duplicated().any() or len(coordinates) != (
        len(expected_step_ids) * len(expected_walker_ids)
    ):
        raise RuntimeError(f"Duplicate or incomplete chain coordinates in {context}")
    if "log_probability" not in frame.columns:
        raise RuntimeError(f"Missing log_probability in {context}")
    log_probability = pd.to_numeric(
        frame["log_probability"], errors="coerce"
    ).to_numpy(dtype=float)
    if not np.all(np.isfinite(log_probability)):
        raise RuntimeError(f"Non-finite log_probability in {context}")


def require_exact_integer_set(
    frame: pd.DataFrame, column: str, expected: set[int], context: str
) -> set[int]:
    """Return one exact finite integer coordinate set from a chain group."""

    if column not in frame.columns:
        raise RuntimeError(f"Missing {column} in {context}")
    values = frame[column].tolist()
    if not values:
        raise RuntimeError(f"Invalid {column} in {context}")
    observed = {
        exact_integer_value(value, column, context) for value in values
    }
    if observed != expected:
        raise RuntimeError(
            f"{column} IDs mismatch in {context}: expected {sorted(expected)}, "
            f"found {sorted(observed)}"
        )
    return observed


def effective_sample_size(
    entry: dict[str, Any],
    walkers: int,
    fallback_steps: int,
    *,
    require_explicit: bool = False,
) -> np.ndarray | None:
    """Return a validated four-parameter ESS vector or ``None``."""

    try:
        tau = np.asarray(entry.get("autocorrelation_time"), dtype=float)
        completed = exact_integer_value(
            entry.get("production_steps_completed", fallback_steps),
            "production_steps_completed",
            "ESS diagnostic",
        )
    except (TypeError, ValueError, RuntimeError):
        return None
    if (
        tau.shape != (4,)
        or not np.all(np.isfinite(tau))
        or np.any(tau <= 0.0)
        or completed <= 0.0
    ):
        return None
    derived = walkers * completed / tau
    explicit = entry.get("effective_sample_size_source_order")
    if explicit is None:
        if require_explicit:
            return None
        ess = derived
    else:
        try:
            ess = np.asarray(explicit, dtype=float)
        except (TypeError, ValueError):
            return None
    if ess.shape != (4,) or not np.all(np.isfinite(ess)) or np.any(ess <= 0.0):
        return None
    if not np.allclose(ess, derived, rtol=1.0e-12, atol=1.0e-12):
        return None
    return ess


def validate_production_diagnostics(
    diagnostics: list[dict[str, Any]],
    args: argparse.Namespace,
    adaptive_policy: dict[str, Any],
) -> None:
    """Apply fail-closed optimizer, convergence, tau, and ESS acceptance gates."""

    nonadaptive = [
        int(entry["global_trial"])
        for entry in diagnostics
        if entry.get("adaptive_production") is not True
    ]
    if nonadaptive:
        raise RuntimeError(
            "--require-all-converged was requested but these global trials did "
            f"not use adaptive production: {nonadaptive}"
        )
    unconverged = [
        int(entry["global_trial"])
        for entry in diagnostics
        if entry.get("converged") is not True
    ]
    if unconverged:
        raise RuntimeError(
            f"Adaptive convergence failed for global trials {unconverged}"
        )
    optimizer_failures = [
        int(entry["global_trial"])
        for entry in diagnostics
        if entry.get("optimizer_success") is not True
    ]
    if optimizer_failures:
        raise RuntimeError(
            f"Optimizer failed for global trials {optimizer_failures}"
        )

    invalid_tau: list[int] = []
    invalid_ess: list[int] = []
    low_ess: list[tuple[int, float]] = []
    for entry in diagnostics:
        global_trial = int(entry["global_trial"])
        validate_convergence_evidence(entry, adaptive_policy)
        try:
            tau = np.asarray(entry.get("autocorrelation_time"), dtype=float)
        except (TypeError, ValueError):
            tau = np.asarray([], dtype=float)
        if tau.shape != (4,) or not np.all(np.isfinite(tau)) or np.any(tau <= 0.0):
            invalid_tau.append(global_trial)
        try:
            completed_steps = diagnostic_integer(
                entry,
                "production_steps_completed",
                f"global trial {global_trial}",
            )
        except RuntimeError:
            completed_steps = 0
        if completed_steps <= 0:
            invalid_ess.append(global_trial)
            continue
        ess = effective_sample_size(
            entry,
            args.walkers,
            args.steps,
            require_explicit=True,
        )
        if ess is None:
            invalid_ess.append(global_trial)
            continue
        minimum = float(np.min(ess))
        if minimum < args.minimum_ess_per_realization:
            low_ess.append((global_trial, minimum))
    if invalid_tau:
        raise RuntimeError(
            "Missing, non-finite, or non-positive autocorrelation time for "
            f"global trials {invalid_tau}"
        )
    if invalid_ess:
        raise RuntimeError(
            f"Missing, non-finite, or non-positive ESS for global trials {invalid_ess}"
        )
    if low_ess:
        raise RuntimeError(
            "Minimum ESS below "
            f"{args.minimum_ess_per_realization:g} for global trials {low_ess}"
        )


def validate_mcse_acceptance(
    quantiles: dict[str, dict[str, float]],
    outer_mcse: dict[str, dict[str, dict[str, float]]] | None,
    inner_mcse: dict[str, dict[str, float]] | None,
    args: argparse.Namespace,
) -> dict[str, dict[str, float]]:
    """Require finite q50 MCSE fractions within the configured production gates."""

    if outer_mcse is None or inner_mcse is None:
        raise RuntimeError(
            "Production acceptance requires both outer and inner q50 MCSE diagnostics"
        )
    accepted: dict[str, dict[str, float]] = {}
    for parameter in PARAMETERS:
        try:
            q16 = float(quantiles[parameter]["q16"])
            q84 = float(quantiles[parameter]["q84"])
            outer = float(outer_mcse[parameter]["q50"]["standard_error"])
            inner = float(inner_mcse[parameter]["q50"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                f"Missing q50 MCSE diagnostic for {parameter}"
            ) from error
        width = q84 - q16
        values = np.asarray([q16, q84, width, outer, inner], dtype=float)
        if not np.all(np.isfinite(values)) or width <= 0.0 or outer < 0.0 or inner < 0.0:
            raise RuntimeError(
                f"Non-finite or invalid q50 MCSE diagnostic for {parameter}: "
                f"q16={q16}, q84={q84}, outer={outer}, inner={inner}"
            )
        outer_fraction = outer / width
        inner_fraction = inner / width
        if outer_fraction > args.maximum_outer_q50_mcse_fraction:
            raise RuntimeError(
                f"Outer q50 MCSE gate failed for {parameter}: {outer_fraction} > "
                f"{args.maximum_outer_q50_mcse_fraction}"
            )
        if inner_fraction > args.maximum_inner_q50_mcse_fraction:
            raise RuntimeError(
                f"Inner q50 MCSE gate failed for {parameter}: {inner_fraction} > "
                f"{args.maximum_inner_q50_mcse_fraction}"
            )
        accepted[parameter] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": float(outer_fraction),
            "inner_q50_mcse_fraction_of_q16_q84_width": float(inner_fraction),
        }
    return accepted


def resolve_measurement_error_mode(
    summaries: list[dict[str, Any]], expected_mode: str | None = None
) -> tuple[str, dict[str, Any]]:
    """Reject mixed shard modes and return their common interpretation."""

    shard_modes: set[str] = set()
    explicit_metadata: list[dict[str, Any]] = []
    for summary in summaries:
        metadata = summary.get("measurement_error")
        if metadata is None:
            mode = LEGACY_SOURCE_MIXTURE
        elif isinstance(metadata, dict) and metadata.get("mode") in MEASUREMENT_ERROR_MODES:
            mode = str(metadata["mode"])
            explicit_metadata.append(metadata)
        else:
            raise RuntimeError("Invalid measurement-error metadata in shard summary")
        shard_modes.add(mode)

    if len(shard_modes) != 1:
        raise RuntimeError(f"Cannot mix measurement-error modes: {sorted(shard_modes)}")
    mode = next(iter(shard_modes))
    if expected_mode is not None and mode != expected_mode:
        raise RuntimeError(
            f"Measurement-error mode mismatch: expected {expected_mode!r}, found {mode!r}"
        )
    if explicit_metadata:
        metadata = explicit_metadata[0]
    else:
        metadata = {
            "mode": LEGACY_SOURCE_MIXTURE,
            "metadata_inferred_from_pre_v4_shard_summaries": True,
        }
    return mode, metadata


def validate_diagnostic_modes(
    diagnostics: list[dict[str, Any]], expected_mode: str
) -> None:
    """Require trial diagnostics to agree with the shard summaries."""

    diagnostic_modes = {
        str(entry.get("measurement_error_mode", LEGACY_SOURCE_MIXTURE))
        for entry in diagnostics
    }
    if diagnostic_modes != {expected_mode}:
        raise RuntimeError(
            "Diagnostic measurement-error modes do not match shard summaries: "
            f"{sorted(diagnostic_modes)} versus {expected_mode!r}"
        )


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    chain_paths = sorted(
        root.rglob(f"joint_posterior_{args.branch}_production-shard-*.csv")
    )
    diagnostics_paths = sorted(
        root.rglob(f"trial_diagnostics_{args.branch}_production-shard-*.json")
    )
    summary_paths = sorted(
        root.rglob(f"posterior_summary_{args.branch}_production-shard-*.json")
    )
    audit_paths = sorted(
        root.rglob(f"perturbation_audit_{args.branch}_production-shard-*.csv")
    )
    escaped_branch = re.escape(args.branch)
    chains_by_shard = index_shard_artifacts(
        chain_paths,
        rf"joint_posterior_{escaped_branch}_production-shard-(\d+)\.csv",
        "chain",
    )
    diagnostics_by_shard = index_shard_artifacts(
        diagnostics_paths,
        rf"trial_diagnostics_{escaped_branch}_production-shard-(\d+)\.json",
        "diagnostic",
    )
    summaries_by_shard = index_shard_artifacts(
        summary_paths,
        rf"posterior_summary_{escaped_branch}_production-shard-(\d+)\.json",
        "summary",
    )
    audits_by_shard = index_shard_artifacts(
        audit_paths,
        rf"perturbation_audit_{escaped_branch}_production-shard-(\d+)\.csv",
        "perturbation-audit",
    )
    require_exact_shard_ids(chains_by_shard, args.expected_shards, "Chain")
    require_exact_shard_ids(
        diagnostics_by_shard, args.expected_shards, "Diagnostic"
    )
    require_exact_shard_ids(summaries_by_shard, args.expected_shards, "Summary")

    locked_input_hashes = (
        expected_input_sha256(args.branch) if args.require_all_converged else None
    )
    shard_summaries: list[dict[str, Any]] = []
    validated_source_provenance: list[dict[str, Any]] = []
    for shard in range(args.expected_shards):
        path = summaries_by_shard[shard]
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary.get("branch") != args.branch:
            raise RuntimeError(f"Summary branch mismatch in {path}")
        expected_label = f"production-shard-{shard}"
        if summary.get("run_label") != expected_label:
            raise RuntimeError(
                f"Summary run-label mismatch in {path}: expected "
                f"{expected_label!r}, found {summary.get('run_label')!r}"
            )
        expected_diagnostics_name = diagnostics_by_shard[shard].name
        if summary.get("trial_diagnostics_file") != expected_diagnostics_name:
            raise RuntimeError(
                f"Summary/diagnostic pairing mismatch in {path}: expected "
                f"{expected_diagnostics_name!r}, found "
                f"{summary.get('trial_diagnostics_file')!r}"
            )
        if summary.get("period_cutoff_days") is not None:
            raise RuntimeError(f"Unexpected period cutoff in {path}")
        if (
            args.require_all_converged
            and summary.get("status") != "production_candidate"
        ):
            raise RuntimeError(
                f"Summary is not a production candidate in {path}: "
                f"found {summary.get('status')!r}"
            )
        if args.require_all_converged:
            assignment = summary.get("status_assignment")
            if not isinstance(assignment, dict) or assignment != {
                "method": "explicit_cli",
                "run_label_used_for_status": False,
            }:
                raise RuntimeError(
                    f"Invalid production status assignment in {path}: {assignment!r}"
                )
        expected_summary_values = {
            "trials": args.trials_per_shard,
            "walkers": args.walkers,
            "production_steps_requested_minimum": args.steps,
            "thin": args.runner_thin,
        }
        if args.acceptance_profile in V404_RELEASE_PROFILES:
            expected_summary_values.update(
                {
                    "base_seed": (
                        2026082200
                        + (100000 if args.branch == "zero" else 0)
                        + shard * 1000
                    ),
                    "mcmc_seed_offset": 500000003,
                    "burnin_steps": 1000,
                    "production_steps_requested_maximum": (
                        30000
                        if args.acceptance_profile == V404_ZERO_EXTENDED_PROFILE
                        else 20000
                    ),
                }
            )
        for key, expected in expected_summary_values.items():
            value = summary.get(key)
            if (
                value != expected
                or isinstance(value, bool)
                or not isinstance(value, int)
            ):
                raise RuntimeError(
                    f"Summary {key} mismatch in {path}: expected {expected!r}, "
                    f"found {value!r}"
                )
        if args.expected_bryson_source_sha256 is not None:
            validated_source_provenance.append(
                validate_shard_source_provenance(
                    summary,
                    str(path),
                    args.expected_bryson_source_sha256,
                )
            )
        if locked_input_hashes is not None:
            validate_summary_input_locks(
                summary, locked_input_hashes, str(path)
            )
        shard_summaries.append(summary)

    measurement_error_mode, measurement_error = resolve_measurement_error_mode(
        shard_summaries, args.expected_measurement_error_mode
    )
    adaptive_policy = (
        validate_adaptive_summary_policy(shard_summaries, args)
        if args.require_all_converged
        else None
    )

    diagnostics: list[dict[str, Any]] = []
    diagnostic_trials_by_shard: dict[int, dict[int, dict[str, Any]]] = {}
    for shard in range(args.expected_shards):
        path = diagnostics_by_shard[shard]
        entries = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise RuntimeError(f"Diagnostic shard is not a list in {path}")
        if len(entries) != args.trials_per_shard:
            raise RuntimeError(
                f"Diagnostic trial count mismatch in {path}: expected "
                f"{args.trials_per_shard}, found {len(entries)}"
            )
        require_exact_trial_ids(
            [entry.get("trial") if isinstance(entry, dict) else None for entry in entries],
            args.trials_per_shard,
            str(path),
        )
        trial_map: dict[int, dict[str, Any]] = {}
        for raw_entry in entries:
            if not isinstance(raw_entry, dict):
                raise RuntimeError(f"Invalid diagnostic entry in {path}")
            entry = dict(raw_entry)
            trial = diagnostic_integer(entry, "trial", str(path))
            if trial in trial_map:
                raise RuntimeError(f"Duplicate diagnostic trial {trial} in {path}")
            perturbation_key = (
                "perturbation_seed" if "perturbation_seed" in entry else "seed"
            )
            perturbation_seed = diagnostic_integer(
                entry, perturbation_key, f"{path}:trial {trial}"
            )
            if "seed" in entry and diagnostic_integer(
                entry, "seed", f"{path}:trial {trial}"
            ) != perturbation_seed:
                raise RuntimeError(f"Diagnostic seed mismatch in {path}:trial {trial}")
            if "perturbation_seed" in entry and diagnostic_integer(
                entry, "perturbation_seed", f"{path}:trial {trial}"
            ) != perturbation_seed:
                raise RuntimeError(
                    f"Diagnostic perturbation-seed mismatch in {path}:trial {trial}"
                )
            mcmc_seed = diagnostic_integer(
                entry, "mcmc_seed", f"{path}:trial {trial}"
            )
            if args.acceptance_profile in V404_RELEASE_PROFILES:
                base_seed = diagnostic_integer(
                    shard_summaries[shard],
                    "base_seed",
                    f"summary shard {shard}",
                )
                mcmc_offset = diagnostic_integer(
                    shard_summaries[shard],
                    "mcmc_seed_offset",
                    f"summary shard {shard}",
                )
                expected_perturbation_seed = base_seed + 1_000_003 * trial
                expected_mcmc_seed = expected_perturbation_seed + mcmc_offset
                if perturbation_seed != expected_perturbation_seed:
                    raise RuntimeError(
                        f"v4.0.4 perturbation-seed schedule mismatch in "
                        f"{path}:trial {trial}"
                    )
                if mcmc_seed != expected_mcmc_seed:
                    raise RuntimeError(
                        f"v4.0.4 MCMC-seed schedule mismatch in "
                        f"{path}:trial {trial}"
                    )
            entry["shard"] = shard
            entry["trial"] = trial
            entry["global_trial"] = (
                shard * args.trials_per_shard + trial
            )
            trial_map[trial] = entry
            diagnostics.append(entry)
        diagnostic_trials_by_shard[shard] = trial_map
    if len(diagnostics) != args.expected_shards * args.trials_per_shard:
        raise RuntimeError(
            f"Diagnostic realization count {len(diagnostics)} is incomplete"
        )
    validate_diagnostic_modes(diagnostics, measurement_error_mode)
    adaptive_entries = [
        entry for entry in diagnostics if entry.get("adaptive_production") is True
    ]
    converged_count = int(
        sum(entry.get("converged") is True for entry in adaptive_entries)
    )
    if args.require_all_converged:
        require_unique_diagnostic_seeds(diagnostics)
        if adaptive_policy is None:
            raise RuntimeError("Missing adaptive production policy")
        validate_production_diagnostics(diagnostics, args, adaptive_policy)
        for shard, summary in enumerate(shard_summaries):
            declared_completed = summary.get("production_steps_completed")
            if not isinstance(declared_completed, list) or len(
                declared_completed
            ) != args.trials_per_shard:
                raise RuntimeError(
                    "Summary production_steps_completed mismatch in "
                    f"{summaries_by_shard[shard]}"
                )
            expected_completed = [
                diagnostic_integer(
                    diagnostic_trials_by_shard[shard][trial],
                    "production_steps_completed",
                    f"diagnostic shard {shard}:trial {trial}",
                )
                for trial in range(args.trials_per_shard)
            ]
            if declared_completed != expected_completed:
                raise RuntimeError(
                    "Summary/diagnostic completed-step mismatch for shard "
                    f"{shard}: {declared_completed!r} != {expected_completed!r}"
                )

    audit_declarations = [
        summary.get("perturbation_audit_file") for summary in shard_summaries
    ]
    declared_audits = [isinstance(value, str) and bool(value) for value in audit_declarations]
    if args.require_all_converged and not all(declared_audits):
        raise RuntimeError(
            "Production acceptance requires every shard perturbation-audit artifact"
        )
    if any(declared_audits) and not all(declared_audits):
        raise RuntimeError(
            "Shard summaries inconsistently declare perturbation-audit artifacts"
        )
    summaries_require_audit = all(declared_audits)
    if summaries_require_audit:
        require_exact_shard_ids(
            audits_by_shard, args.expected_shards, "Perturbation-audit"
        )
        for shard, declared in enumerate(audit_declarations):
            if declared != audits_by_shard[shard].name:
                raise RuntimeError(
                    "Summary/perturbation-audit pairing mismatch for shard "
                    f"{shard}: expected {audits_by_shard[shard].name!r}, "
                    f"found {declared!r}"
                )
    elif audits_by_shard:
        raise RuntimeError(
            "Perturbation-audit CSVs are present but shard summaries do not declare them"
        )

    numerical_environment_hashes: list[str] = []
    if args.require_all_converged:
        for shard in range(args.expected_shards):
            paths = {
                chains_by_shard[shard],
                diagnostics_by_shard[shard],
                summaries_by_shard[shard],
                audits_by_shard[shard],
            }
            parents = {path.parent.resolve() for path in paths}
            if len(parents) != 1:
                raise RuntimeError(f"Shard {shard} artifacts are not co-located")
            directory = next(iter(parents))
            numerical_environment_hashes.append(
                verify_complete_shard_manifest(
                    directory,
                    {path.name for path in paths} | {"numerical_environment.txt"},
                )
            )
        if len(set(numerical_environment_hashes)) != 1:
            raise RuntimeError(
                "Numerical environment differs across production shards"
            )

    full_audit_path: Path | None = None
    if summaries_require_audit:
        audit_frames: list[pd.DataFrame] = []
        for expected_shard in range(args.expected_shards):
            path = audits_by_shard[expected_shard]
            frame = pd.read_csv(path)
            if set(frame.branch.astype(str)) != {args.branch}:
                raise RuntimeError(f"Audit branch mismatch in {path}")
            modes = set(frame.measurement_error_mode.astype(str))
            if modes != {measurement_error_mode}:
                raise RuntimeError(
                    f"Audit measurement-error mode mismatch in {path}: {modes}"
                )
            labels = set(frame.run_label.astype(str))
            if len(labels) != 1:
                raise RuntimeError(f"Multiple audit run labels in {path}: {labels}")
            shard = parse_shard(next(iter(labels)))
            if shard != expected_shard:
                raise RuntimeError(
                    f"Audit filename/run-label shard mismatch in {path}: "
                    f"filename={expected_shard}, run_label={shard}"
                )
            require_exact_trial_ids(frame.trial, args.trials_per_shard, str(path))
            for trial in range(args.trials_per_shard):
                group = frame.loc[pd.to_numeric(frame.trial) == trial]
                trial_seed = unique_integer(
                    group, "trial_seed", f"{path}:trial {trial}"
                )
                diagnostic = diagnostic_trials_by_shard[shard][trial]
                expected_seed = diagnostic_integer(
                    diagnostic,
                    (
                        "perturbation_seed"
                        if "perturbation_seed" in diagnostic
                        else "seed"
                    ),
                    f"diagnostic shard {shard}:trial {trial}",
                )
                if trial_seed != expected_seed:
                    raise RuntimeError(
                        f"Audit/diagnostic trial_seed mismatch for shard {shard}, "
                        f"trial {trial}: {trial_seed} != {expected_seed}"
                    )
            frame.insert(3, "shard", shard)
            frame.insert(5, "global_trial", shard * args.trials_per_shard + frame.trial)
            audit_frames.append(frame)
        full_audit = pd.concat(audit_frames, ignore_index=True)
        full_audit.sort_values(["global_trial", "source_row"], inplace=True)
        full_audit.reset_index(drop=True, inplace=True)
        full_audit_path = out / f"perturbation_audit_{args.branch}_full.csv.gz"
        full_audit.to_csv(
            full_audit_path,
            index=False,
            compression=DETERMINISTIC_GZIP_COMPRESSION,
        )

    fixed_samples_per_trial = args.walkers * (args.steps // args.runner_thin)
    frames: list[pd.DataFrame] = []

    for expected_shard in range(args.expected_shards):
        path = chains_by_shard[expected_shard]
        frame = pd.read_csv(path)
        if (
            args.samples_per_realization is None
            and len(frame) != args.trials_per_shard * fixed_samples_per_trial
        ):
            raise RuntimeError(
                f"Unexpected row count {len(frame)} in {path}; expected "
                f"{args.trials_per_shard * fixed_samples_per_trial}"
            )
        if set(frame.branch.astype(str)) != {args.branch}:
            raise RuntimeError(f"Branch mismatch in {path}")
        labels = set(frame.run_label.astype(str))
        if len(labels) != 1:
            raise RuntimeError(f"Multiple run labels in {path}: {labels}")
        label = next(iter(labels))
        shard = parse_shard(label)
        if shard != expected_shard:
            raise RuntimeError(
                f"Chain filename/run-label shard mismatch in {path}: "
                f"filename={expected_shard}, run_label={shard}"
            )
        require_exact_trial_ids(frame.trial, args.trials_per_shard, str(path))
        counts = frame.groupby("trial", sort=False).size().to_numpy()
        if args.samples_per_realization is None:
            if not np.all(counts == fixed_samples_per_trial):
                raise RuntimeError(f"Unequal mixture weights in {path}")
        elif np.any(counts < args.samples_per_realization):
            raise RuntimeError(
                f"A realization in {path} has fewer than "
                f"{args.samples_per_realization} retained MCMC rows"
            )
        for trial in range(args.trials_per_shard):
            group = frame.loc[pd.to_numeric(frame.trial) == trial]
            trial_seed = unique_integer(
                group, "trial_seed", f"{path}:trial {trial}"
            )
            mcmc_seed = unique_integer(
                group, "mcmc_seed", f"{path}:trial {trial}"
            )
            diagnostic = diagnostic_trials_by_shard[shard][trial]
            if args.require_all_converged:
                validate_chain_realization_structure(
                    group,
                    diagnostic,
                    args.walkers,
                    args.runner_thin,
                    f"chain shard {shard}:trial {trial}",
                )
            expected_trial_seed = diagnostic_integer(
                diagnostic,
                (
                    "perturbation_seed"
                    if "perturbation_seed" in diagnostic
                    else "seed"
                ),
                f"diagnostic shard {shard}:trial {trial}",
            )
            expected_mcmc_seed = diagnostic_integer(
                diagnostic,
                "mcmc_seed",
                f"diagnostic shard {shard}:trial {trial}",
            )
            if trial_seed != expected_trial_seed:
                raise RuntimeError(
                    f"Chain/diagnostic trial_seed mismatch for shard {shard}, "
                    f"trial {trial}: {trial_seed} != {expected_trial_seed}"
                )
            if mcmc_seed != expected_mcmc_seed:
                raise RuntimeError(
                    f"Chain/diagnostic mcmc_seed mismatch for shard {shard}, "
                    f"trial {trial}: {mcmc_seed} != {expected_mcmc_seed}"
                )
        frame.insert(2, "shard", shard)
        frame.insert(4, "global_trial", shard * args.trials_per_shard + frame.trial)
        frames.append(frame)

    full = pd.concat(frames, ignore_index=True)
    if full.global_trial.nunique() != args.expected_shards * args.trials_per_shard:
        raise RuntimeError("Global trial identifiers are incomplete or duplicated")
    if not np.isfinite(full.loc[:, PARAMETERS].to_numpy(dtype=float)).all():
        raise RuntimeError("Non-finite posterior values detected")

    full.sort_values(
        ["global_trial", "production_step", "walker"], inplace=True
    )
    full.reset_index(drop=True, inplace=True)
    if args.samples_per_realization is not None:
        full = equalize_realizations(
            full, "global_trial", args.samples_per_realization
        )
        samples_per_trial = args.samples_per_realization
    else:
        samples_per_trial = fixed_samples_per_trial
    expected_total = (
        args.expected_shards * args.trials_per_shard * samples_per_trial
    )
    if len(full) != expected_total:
        raise RuntimeError(f"Aggregate row count {len(full)} != {expected_total}")
    full_path = out / f"joint_posterior_{args.branch}_full.csv.gz"
    full.to_csv(
        full_path,
        index=False,
        compression=DETERMINISTIC_GZIP_COMPRESSION,
    )

    # Preserve equal representation from every outer realization when creating
    # the smaller sample file used by the Galactic propagation stage.
    within_trial_row = full.groupby("global_trial", sort=False).cumcount()
    propagation = full.loc[
        within_trial_row.mod(args.propagation_stride).eq(0)
    ].copy()
    propagation.reset_index(drop=True, inplace=True)
    expected_propagation = (
        args.expected_shards
        * args.trials_per_shard
        * int(np.ceil(samples_per_trial / args.propagation_stride))
    )
    if len(propagation) != expected_propagation:
        raise RuntimeError(
            f"Propagation sample count {len(propagation)} != {expected_propagation}"
        )
    propagation_path = out / f"joint_posterior_{args.branch}_for_galactic_propagation.csv.gz"
    propagation.loc[
        :, ["branch", "global_trial", "F0", "alpha", "beta", "gamma"]
    ].to_csv(
        propagation_path,
        index=False,
        compression=DETERMINISTIC_GZIP_COMPRESSION,
    )

    values = full.loc[:, PARAMETERS].to_numpy(dtype=float)
    quantiles = {
        name: qsummary(values[:, index])
        for index, name in enumerate(PARAMETERS)
    }
    cluster_bootstrap_mcse = None
    if args.cluster_bootstrap_replicates:
        cluster_bootstrap_mcse = cluster_bootstrap_quantile_mcse(
            full,
            PARAMETERS,
            "global_trial",
            args.cluster_bootstrap_replicates,
            args.bootstrap_seed,
        )
    inner_chain_mcse = None
    if args.inner_chain_batches:
        inner_chain_mcse = contiguous_batch_quantile_mcse(
            full,
            PARAMETERS,
            "global_trial",
            args.inner_chain_batches,
        )
    mcse_acceptance = None
    if args.require_all_converged:
        mcse_acceptance = validate_mcse_acceptance(
            quantiles,
            cluster_bootstrap_mcse,
            inner_chain_mcse,
            args,
        )
    correlation = pd.DataFrame(
        np.corrcoef(values, rowvar=False), index=PARAMETERS, columns=PARAMETERS
    )
    correlation_path = out / f"joint_posterior_{args.branch}_correlation.csv"
    correlation.to_csv(correlation_path, index=True)

    archived = ARCHIVED[args.branch]
    comparison: dict[str, dict[str, float]] = {}
    for index, name in enumerate(PARAMETERS):
        comparison[name] = {
            "reconstructed_q16": quantiles[name]["q16"],
            "reconstructed_q50": quantiles[name]["q50"],
            "reconstructed_q84": quantiles[name]["q84"],
            "archived_q16_from_printed_summary": float(archived["q16"][index]),
            "archived_q50_from_printed_summary": float(archived["q50"][index]),
            "archived_q84_from_printed_summary": float(archived["q84"][index]),
            "median_difference": float(
                quantiles[name]["q50"] - archived["q50"][index]
            ),
        }

    acceptance = np.asarray(
        [entry["mean_acceptance_fraction"] for entry in diagnostics], dtype=float
    )
    runtime = np.asarray(
        [entry["runtime_seconds"] for entry in diagnostics], dtype=float
    )
    candidate_count = np.asarray(
        [entry["selected_after_domain"] for entry in diagnostics], dtype=float
    )
    optimizer_failures = int(
        sum(entry.get("optimizer_success") is not True for entry in diagnostics)
    )

    source_names = ("F0", "beta", "alpha", "gamma")
    tau_rows: list[np.ndarray] = []
    ess_rows: list[np.ndarray] = []
    for entry in diagnostics:
        try:
            array = np.asarray(entry.get("autocorrelation_time"), dtype=float)
        except (TypeError, ValueError):
            array = np.asarray([], dtype=float)
        if array.shape == (4,) and np.all(np.isfinite(array)) and np.all(array > 0):
            tau_rows.append(array)
        ess_array = effective_sample_size(entry, args.walkers, args.steps)
        if ess_array is not None:
            ess_rows.append(ess_array)
    tau_summary = None
    ess_summary = None
    if tau_rows:
        tau_matrix = np.vstack(tau_rows)
        # emcee reports tau in production steps for source order
        # F0, beta_inst, alpha_radius, gamma.
        tau_summary = {
            name: {
                "q16": float(np.quantile(tau_matrix[:, index], 0.16)),
                "q50": float(np.quantile(tau_matrix[:, index], 0.50)),
                "q84": float(np.quantile(tau_matrix[:, index], 0.84)),
            }
            for index, name in enumerate(source_names)
        }
    if ess_rows:
        ess_matrix = np.vstack(ess_rows)
        ess_summary = {
            name: {
                "minimum_per_realization": float(np.min(ess_matrix[:, index])),
                "q16_per_realization": float(np.quantile(ess_matrix[:, index], 0.16)),
                "median_per_realization": float(np.median(ess_matrix[:, index])),
                "sum_over_realizations": float(np.sum(ess_matrix[:, index])),
            }
            for index, name in enumerate(source_names)
        }

    diagnostics_path = out / f"trial_diagnostics_{args.branch}_full.jsonl"
    with diagnostics_path.open("w", encoding="utf-8") as handle:
        for entry in diagnostics:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    source_commits = [
        record["source_commit"] for record in validated_source_provenance
    ]
    common_source_commit = (
        source_commits[0]
        if source_commits and all(value == source_commits[0] for value in source_commits)
        else None
    )
    aggregate_summary = {
        "status": (
            "new seeded no-period-cutoff reconstruction; not the missing "
            "historical Bryson chain"
        ),
        "source_repository": BRYSON_REPOSITORY,
        "source_commit": common_source_commit,
        "source_provenance": {
            "verified_for_every_shard": bool(
                len(validated_source_provenance) == args.expected_shards
            ),
            "expected_source_file_sha256": args.expected_bryson_source_sha256,
            "source_file_relative_path": BRYSON_SOURCE_RELATIVE_PATH,
            "verification_methods": sorted(
                {
                    record["verification_method"]
                    for record in validated_source_provenance
                }
            ),
        },
        "locked_input_sha256": locked_input_hashes,
        "numerical_environment_sha256": (
            numerical_environment_hashes[0]
            if numerical_environment_hashes
            else None
        ),
        "branch": args.branch,
        "period_cutoff_days": None,
        "measurement_error": measurement_error,
        "production_acceptance_gate": {
            "profile": args.acceptance_profile,
            "required": bool(args.require_all_converged),
            "accepted": bool(
                args.require_all_converged and mcse_acceptance is not None
            ),
            "expected_bryson_source_sha256": (
                args.expected_bryson_source_sha256
            ),
            "minimum_ess_per_realization": args.minimum_ess_per_realization,
            "maximum_outer_q50_mcse_fraction_of_q16_q84_width": (
                args.maximum_outer_q50_mcse_fraction
            ),
            "maximum_inner_q50_mcse_fraction_of_q16_q84_width": (
                args.maximum_inner_q50_mcse_fraction
            ),
            "q50_mcse_by_parameter": mcse_acceptance,
            "adaptive_production_policy": adaptive_policy,
        },
        "mixture_definition": (
            "equal number of deterministically spaced post-burn ensemble "
            "samples from every reliability and measurement-error realization"
        ),
        "parameter_order": ["F0", "alpha_radius", "beta_inst", "gamma"],
        "shards": args.expected_shards,
        "trials_per_shard": args.trials_per_shard,
        "total_trials": args.expected_shards * args.trials_per_shard,
        "walkers": args.walkers,
        "burnin_steps": int(shard_summaries[0]["burnin_steps"]),
        "production_steps_requested_minimum": args.steps,
        "production_steps_completed_q16_q50_q84": [
            float(value)
            for value in np.quantile(
                np.asarray(
                    [
                        entry.get("production_steps_completed", args.steps)
                        for entry in diagnostics
                    ],
                    dtype=float,
                ),
                [0.16, 0.50, 0.84],
            )
        ],
        "runner_thin": args.runner_thin,
        "runner_seed_schedule": {
            "base_seed_by_shard": [
                summary.get("base_seed") for summary in shard_summaries
            ],
            "trial_seed_increment": 1_000_003,
            "mcmc_seed_offset": shard_summaries[0].get("mcmc_seed_offset"),
        },
        "equalized_samples_per_realization": samples_per_trial,
        "full_sample_count": int(len(full)),
        "propagation_stride_within_each_realization": args.propagation_stride,
        "galactic_propagation_sample_count": int(len(propagation)),
        "perturbation_audit_file": (
            full_audit_path.name if full_audit_path is not None else None
        ),
        "posterior_quantiles": quantiles,
        "posterior_quantile_monte_carlo_error": {
            "outer_realization_cluster_bootstrap": cluster_bootstrap_mcse,
            "outer_realization_cluster_bootstrap_replicates": (
                args.cluster_bootstrap_replicates
            ),
            "outer_realization_cluster_bootstrap_seed": args.bootstrap_seed,
            "inner_chain_contiguous_batch_mcse": inner_chain_mcse,
            "inner_chain_batches": args.inner_chain_batches,
            "interpretation": (
                "Whole outer realizations, not posterior rows, are resampled. "
                "The separate contiguous-block estimate diagnoses residual "
                "within-chain Monte Carlo error while retaining every outer realization."
            ),
        },
        "comparison_with_archived_printed_marginal_summary": comparison,
        "correlation_matrix_file": correlation_path.name,
        "diagnostics": {
            "optimizer_failures": optimizer_failures,
            "acceptance_fraction_q16_q50_q84": [
                float(value)
                for value in np.quantile(acceptance, [0.16, 0.50, 0.84])
            ],
            "runtime_seconds_per_realization_q16_q50_q84": [
                float(value)
                for value in np.quantile(runtime, [0.16, 0.50, 0.84])
            ],
            "candidate_count_q16_q50_q84": [
                float(value)
                for value in np.quantile(candidate_count, [0.16, 0.50, 0.84])
            ],
            "realizations_with_estimable_autocorrelation": len(tau_rows),
            "realizations_with_valid_effective_sample_size": len(ess_rows),
            "adaptive_realizations": len(adaptive_entries),
            "adaptive_realizations_converged": converged_count,
            "autocorrelation_time_by_source_parameter": tau_summary,
            "estimated_chain_ess_by_source_parameter": ess_summary,
        },
        "scientific_limits": [
            "This is a new reproducible rerun, not the unavailable historical chain.",
            "Each outer realization has its own conditional posterior; the pooled result is a mixture.",
            "The completeness branches remain separate model scenarios.",
            "Host-model and transport systematics are not included in these occurrence-only intervals.",
        ],
    }
    summary_path = out / f"joint_posterior_{args.branch}_aggregate_summary.json"
    summary_path.write_text(
        json.dumps(aggregate_summary, indent=2), encoding="utf-8"
    )

    manifest_targets = [
        full_path,
        propagation_path,
        correlation_path,
        diagnostics_path,
        summary_path,
    ]
    if full_audit_path is not None:
        manifest_targets.append(full_audit_path)
    manifest_path = out / f"SHA256SUMS_{args.branch}_aggregate.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_targets),
        encoding="utf-8",
    )
    print(json.dumps(aggregate_summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
