#!/usr/bin/env python3
"""Validate and checksum the corrected v4 numerical result set."""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import importlib
import json
import math
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pandas as pd

from clustered_monte_carlo import (
    cluster_bootstrap_quantile_mcse,
    contiguous_batch_quantile_mcse,
    equalize_realizations,
)
from measurement_error import LEGACY_SOURCE_MIXTURE, QUANTILE_MATCHED_TWO_SIDED

VALIDATION_DIR = Path(__file__).resolve().parents[1] / "v4-validation"
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

from host_tams_audit import (  # noqa: E402
    EXPECTED_HOST_STATUS,
    FileSnapshot,
    RETRACTED_METALLICITY_ANCHOR_NAME,
    _load_python_module_from_snapshot,
    _require_exact_bool,
    _require_finite_nonnegative,
    _require_finite_number,
    _require_integer,
    _require_mapping,
    _require_positive_integer,
    _snapshot_exact_manifest_root,
    load_json_bytes,
    load_json_snapshot,
    load_json_value_bytes,
    read_csv_bytes,
    read_file_snapshot,
    release_safe_evidence,
    validate_fresh_propagation_set,
    validate_parent_artifact,
    validate_posterior_artifact,
    validate_tams_radial_convergence_root,
    verify_attested_output_roots,
    verify_host_artifact_contract_binding,
    verify_local_run_attestation_binding,
    verify_metallicity_audit_root,
    verify_radial_ssp_contract_binding,
)

PARAMETERS = ("F0", "alpha", "beta", "gamma")
GALACTIC_QUANTITIES = (
    "mean_f_HZ",
    "mean_f_EE",
    "Lambda_HZ",
    "Lambda_EE",
    "Lambda_EE_over_Lambda_HZ",
)
QUANTILES = ("q2.5", "q16", "q50", "q84", "q97.5")
HOST_AUDIT_NAME = "host_tams_audit.json"
HOST_SELECTOR_TABLE_NAME = "host_selector_sensitivity.csv"
HOST_AUDIT_MANIFEST_NAME = "SHA256SUMS_host_tams_audit.txt"
NUMERICAL_FREEZE_MANIFEST_NAME = "SHA256SUMS_v4_numerical_freeze.txt"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
HOST_START_CHALLENGE_NAME = "HOST_RUN_START_CHALLENGE.json"
V404_ACCEPTANCE_PROFILE = "v4.0.4-production"
V404_ZERO_EXTENDED_PROFILE = "v4.0.4-zero-extended"
V404_LEGACY_SENSITIVITY_PROFILE = "v4.0.4-legacy-measurement-sensitivity"
FULL_POSTERIOR_COLUMNS = (
    "branch",
    "run_label",
    "shard",
    "trial",
    "global_trial",
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
)
PROPAGATION_POSTERIOR_COLUMNS = (
    "branch",
    "global_trial",
    "F0",
    "alpha",
    "beta",
    "gamma",
)
EXPECTED_FULL_ROW_COUNT = 409_600
EXPECTED_FULL_SAMPLES_PER_REALIZATION = 1024
EXPECTED_OUTER_REALIZATIONS = 400
EXPECTED_PROPAGATION_ROW_COUNT = 204_800
EXPECTED_PROPAGATION_SAMPLES_PER_REALIZATION = 512
PILOT_CHAIN_COLUMNS = (
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
)
PILOT_PLANET_COLUMNS = (
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
)
PILOT_AUDIT_COLUMNS = (
    "branch",
    "run_label",
    "measurement_error_mode",
    "trial",
    "trial_seed",
    "source_row",
    "kepoi_name",
    "kepid_x",
    "totalReliability",
    "koi_period",
    "gaia_iso_insol",
    "gaia_iso_insol_errm",
    "gaia_iso_insol_errp",
    "gaia_iso_prad",
    "gaia_iso_prad_errm",
    "gaia_iso_prad_errp",
    "teff",
    "teff_err2",
    "teff_err1",
    "perturbed_flux",
    "perturbed_radius",
    "perturbed_teff",
    "instellation_in_source_domain",
    "radius_in_source_domain",
    "teff_in_source_domain",
    "period_passes_optional_cutoff",
    "teff_filter_active",
    "retained_by_active_policy",
    "audit_status",
)
FULL_PERTURBATION_AUDIT_COLUMNS = (
    "branch",
    "run_label",
    "measurement_error_mode",
    "shard",
    "trial",
    "global_trial",
    "trial_seed",
    *PILOT_AUDIT_COLUMNS[5:],
)
PILOT_DIAGNOSTIC_KEYS = {
    "trial",
    "seed",
    "perturbation_seed",
    "mcmc_seed",
    "measurement_error_mode",
    "selected_after_domain",
    "perturbation_counts",
    "optimizer_success",
    "optimizer_status",
    "optimizer_message",
    "optimizer_fun",
    "optimizer_theta_source_order",
    "mean_acceptance_fraction",
    "acceptance_fraction_by_walker",
    "autocorrelation_time",
    "effective_sample_size_source_order",
    "production_steps_completed",
    "adaptive_production",
    "converged",
    "convergence_checks",
    "runtime_seconds",
}
PILOT_PERTURBATION_COUNT_KEYS = {
    "n_catalog_rows",
    "n_reliability_selected_before_domain",
    "n_outside_instellation_source_domain",
    "n_outside_radius_source_domain",
    "n_outside_teff_source_domain",
    "n_outside_any_of_three_source_domains",
    "n_failing_optional_period_cutoff",
    "n_retained_by_active_policy",
    "n_retained_with_teff_outside_source_domain",
}


def validate_external_evidence_lock(
    path: Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
    label: str,
) -> FileSnapshot:
    """Capture one external post-qualification input against an explicit lock."""

    if not isinstance(expected_sha256, str) or not SHA256_PATTERN.fullmatch(
        expected_sha256
    ):
        raise RuntimeError(f"{label} expected SHA-256 is not lowercase 64-hex")
    if (
        isinstance(expected_size_bytes, bool)
        or not isinstance(expected_size_bytes, int)
        or expected_size_bytes <= 0
    ):
        raise RuntimeError(f"{label} expected size must be a positive integer")
    snapshot = read_file_snapshot(path, label)
    if (
        snapshot.sha256 != expected_sha256
        or snapshot.size_bytes != expected_size_bytes
    ):
        raise RuntimeError(f"{label} differs from its explicit external evidence lock")
    return snapshot


def recheck_external_evidence_locks(
    snapshots: dict[str, FileSnapshot],
) -> None:
    for label, snapshot in snapshots.items():
        current = read_file_snapshot(snapshot.path, label)
        if (
            current.data != snapshot.data
            or current.sha256 != snapshot.sha256
            or current.size_bytes != snapshot.size_bytes
        ):
            raise RuntimeError(f"{label} changed after its validated snapshot")


def _safe_report_leaf(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        raise RuntimeError(f"{label} is not one portable report filename")
    return value


def _report_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"(?:sha256:)?[0-9a-f]{64}", value
    ) is None:
        raise RuntimeError(f"{label} is not a SHA-256 report identifier")
    return value


def validate_external_contract_report_pair(
    role: str,
    contract_snapshot: FileSnapshot,
    report_snapshot: FileSnapshot,
) -> dict[str, Any]:
    """Bind one accepted external contract to the exact supplied public report."""

    contract = load_json_bytes(contract_snapshot.data, f"{role} external contract")
    report = load_json_bytes(report_snapshot.data, f"{role} external report")
    collection_name = "candidates" if role == "local" else "artifact_sets"
    candidates = contract.get(collection_name)
    if not isinstance(candidates, list):
        raise RuntimeError(f"{role} external contract candidate collection is invalid")
    accepted = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("production_accepted") is True
    ]
    if len(accepted) != 1:
        raise RuntimeError(
            f"{role} external contract must contain exactly one production-accepted candidate"
        )
    candidate = accepted[0]
    candidate_id = candidate.get("id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise RuntimeError(f"{role} accepted candidate id is invalid")
    if role == "local":
        reference = candidate.get("accepted_report")
        if not isinstance(reference, dict) or set(reference) != {
            "report_id",
            "sha256",
            "size_bytes",
        }:
            raise RuntimeError("local accepted-report lock schema changed")
        report_id = _report_identifier(report.get("report_id"), "local report id")
        expected = {
            "report_id": report_id,
            "sha256": report_snapshot.sha256,
            "size_bytes": report_snapshot.size_bytes,
        }
        if reference != expected:
            raise RuntimeError("local public report differs from its accepted contract lock")
    else:
        reference = candidate.get("qualification_report")
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise RuntimeError(f"{role} qualification-report lock schema changed")
        report_name = _safe_report_leaf(
            reference.get("path"), f"{role} qualification-report path"
        )
        expected_path = contract_snapshot.path.parent / report_name
        if report_snapshot.path != expected_path.resolve():
            raise RuntimeError(
                f"{role} qualification report is not the contract-relative locked file"
            )
        if reference.get("sha256") != report_snapshot.sha256:
            raise RuntimeError(
                f"{role} qualification report differs from its accepted contract lock"
            )
        report_id = _report_identifier(
            report.get("qualification_id"), f"{role} qualification id"
        )
    return {
        "candidate_id": candidate_id,
        "contract_sha256": contract_snapshot.sha256,
        "contract_size_bytes": contract_snapshot.size_bytes,
        "report_id": report_id,
        "report_sha256": report_snapshot.sha256,
        "report_size_bytes": report_snapshot.size_bytes,
    }


def _source_record_identity(value: Any, label: str) -> dict[str, Any]:
    record = _require_mapping(value, label)
    archive = _require_mapping(record.get("source_archive"), f"{label} archive")
    identity = {
        "commit": record.get("commit_sha"),
        "tree": record.get("git_tree_sha"),
        "archive_sha256": archive.get("sha256"),
        "archive_size_bytes": archive.get("size_bytes"),
    }
    if not isinstance(identity["commit"], str) or GIT_SHA_PATTERN.fullmatch(
        identity["commit"]
    ) is None:
        raise RuntimeError(f"{label} commit is not lowercase 40-hex")
    if not isinstance(identity["tree"], str) or GIT_SHA_PATTERN.fullmatch(
        identity["tree"]
    ) is None:
        raise RuntimeError(f"{label} tree is not lowercase 40-hex")
    if not isinstance(identity["archive_sha256"], str) or SHA256_PATTERN.fullmatch(
        identity["archive_sha256"]
    ) is None:
        raise RuntimeError(f"{label} archive SHA-256 is invalid")
    if (
        isinstance(identity["archive_size_bytes"], bool)
        or not isinstance(identity["archive_size_bytes"], int)
        or identity["archive_size_bytes"] <= 0
    ):
        raise RuntimeError(f"{label} archive size is invalid")
    return identity


def _source_state_identity(value: Any, label: str) -> dict[str, Any]:
    state = _require_mapping(value, label)
    public = _source_record_identity(state.get("public_source"), f"{label} public")
    private = _source_record_identity(state.get("private_source"), f"{label} private")
    if public != private:
        raise RuntimeError(f"{label} public/private computational sources differ")
    return public


def _canonical_base64_json(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{label} is not base64 text")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise RuntimeError(f"{label} is not canonical base64") from error
    if base64.b64encode(data).decode("ascii") != value:
        raise RuntimeError(f"{label} is not canonical base64")
    return load_json_bytes(data, label)


def host_qualification_source_identity(report: dict[str, Any]) -> dict[str, Any]:
    repetitions = report.get("fresh_repetitions")
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        raise RuntimeError("host qualification report must contain two repetitions")
    identities: list[dict[str, Any]] = []
    for index, repetition in enumerate(repetitions):
        item = _require_mapping(repetition, f"host repetition {index}")
        embedded = _require_mapping(
            item.get("embedded_signed_evidence"),
            f"host repetition {index} embedded evidence",
        )
        challenge = _canonical_base64_json(
            embedded.get(HOST_START_CHALLENGE_NAME),
            f"host repetition {index} start challenge",
        )
        identities.append(
            _source_state_identity(
                challenge.get("source_state"),
                f"host repetition {index} source state",
            )
        )
    if identities[0] != identities[1]:
        raise RuntimeError("host qualification repetitions use mixed computational sources")
    return identities[0]


def radial_qualification_source_identity(report: dict[str, Any]) -> dict[str, Any]:
    triplets = report.get("triplets")
    if not isinstance(triplets, list) or len(triplets) != 2:
        raise RuntimeError("radial qualification report must contain two triplets")
    identities = [
        _source_state_identity(
            _require_mapping(item, f"radial triplet {index}").get("source_provenance"),
            f"radial triplet {index} source state",
        )
        for index, item in enumerate(triplets)
    ]
    if identities[0] != identities[1]:
        raise RuntimeError("radial qualification triplets use mixed computational sources")
    return identities[0]


def age_qualification_source_identity(report: dict[str, Any]) -> dict[str, Any]:
    state = _source_state_identity(
        report.get("source_state"), "age qualification source state"
    )
    repetitions = report.get("fresh_repetitions")
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        raise RuntimeError("age qualification report must contain two repetitions")
    for index, repetition in enumerate(repetitions):
        item = _require_mapping(repetition, f"age repetition {index}")
        if (
            _source_state_identity(
                item.get("source_state"), f"age repetition {index} source state"
            )
            != state
        ):
            raise RuntimeError("age qualification repetitions use mixed sources")
    return state


def local_qualification_source_identity(
    contract: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    candidates = contract.get("candidates")
    if not isinstance(candidates, list):
        raise RuntimeError("local external contract candidate collection is invalid")
    accepted = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("production_accepted") is True
    ]
    if len(accepted) != 1:
        raise RuntimeError("local external contract lacks one accepted candidate")
    lock = _require_mapping(accepted[0].get("source_lock"), "local source lock")
    identity = {
        "commit": lock.get("commit"),
        "tree": lock.get("tree"),
        "archive_sha256": lock.get("archive_sha256"),
        "archive_size_bytes": lock.get("archive_size_bytes"),
    }
    if not isinstance(identity["commit"], str) or GIT_SHA_PATTERN.fullmatch(
        identity["commit"]
    ) is None:
        raise RuntimeError("local source-lock commit is invalid")
    if not isinstance(identity["tree"], str) or GIT_SHA_PATTERN.fullmatch(
        identity["tree"]
    ) is None:
        raise RuntimeError("local source-lock tree is invalid")
    if not isinstance(identity["archive_sha256"], str) or SHA256_PATTERN.fullmatch(
        identity["archive_sha256"]
    ) is None:
        raise RuntimeError("local source-lock archive SHA-256 is invalid")
    if (
        isinstance(identity["archive_size_bytes"], bool)
        or not isinstance(identity["archive_size_bytes"], int)
        or identity["archive_size_bytes"] <= 0
    ):
        raise RuntimeError("local source-lock archive size is invalid")
    public_projection = {
        "commit": report.get("source_commit"),
        "tree": report.get("source_tree"),
        "archive_sha256": report.get("source_archive_sha256"),
        "archive_size_bytes": report.get("source_archive_size_bytes"),
    }
    if public_projection != identity:
        raise RuntimeError("local public report differs from its exact source lock")
    return identity


def host_source_lock_from_local_contract(
    contract: dict[str, Any], computational_source: dict[str, Any]
) -> dict[str, Any]:
    """Project the accepted local source lock into the host verifier schema."""

    candidates = contract.get("candidates")
    if not isinstance(candidates, list):
        raise RuntimeError("local contract candidate collection is invalid")
    accepted = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("production_accepted") is True
    ]
    if len(accepted) != 1:
        raise RuntimeError("local contract lacks one accepted source lock")
    lock = _require_mapping(accepted[0].get("source_lock"), "local source lock")
    public_repository = lock.get("public_repository")
    private_repository = lock.get("private_repository")
    if not isinstance(public_repository, str) or not public_repository:
        raise RuntimeError("local public repository lock is invalid")
    if not isinstance(private_repository, str) or not private_repository:
        raise RuntimeError("local private repository lock is invalid")

    def project(repository: str) -> dict[str, Any]:
        return {
            "repository": repository,
            "commit_sha": computational_source["commit"],
            "git_tree_sha": computational_source["tree"],
            "source_archive_sha256": computational_source["archive_sha256"],
            "source_archive_size_bytes": computational_source[
                "archive_size_bytes"
            ],
        }

    return {
        "public_source": project(public_repository),
        "private_source": project(private_repository),
    }


def require_identical_computational_source(
    sources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if set(sources) != {"host", "age", "radial", "local"}:
        raise RuntimeError("all host/age/radial/local source identities are required")
    expected = sources["local"]
    for role, source in sources.items():
        if source != expected:
            raise RuntimeError(
                f"mixed computational source: {role} qualification differs from local production"
            )
    return dict(expected)


def seed_stability_target_names(branch: str) -> tuple[str, ...]:
    names: list[str] = []
    for number in (1, 2):
        label = f"corrected-pilot-seed-{number}"
        names.extend(
            [
                f"joint_posterior_{branch}_{label}.csv",
                f"perturbed_planets_{branch}_{label}.csv",
                f"perturbation_audit_{branch}_{label}.csv",
                f"trial_diagnostics_{branch}_{label}.json",
            ]
        )
    names.append(f"mcmc_seed_stability_{branch}.json")
    return tuple(names)


def aggregate_target_names(branch: str) -> tuple[str, ...]:
    return (
        f"joint_posterior_{branch}_full.csv.gz",
        f"joint_posterior_{branch}_for_galactic_propagation.csv.gz",
        f"joint_posterior_{branch}_correlation.csv",
        f"trial_diagnostics_{branch}_full.jsonl",
        f"joint_posterior_{branch}_aggregate_summary.json",
        f"perturbation_audit_{branch}_full.csv.gz",
        f"raw_unthinned_chain_audit_{branch}.json",
    )


def validate_aggregate_artifact_root(
    artifact_root: Path, branch: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, FileSnapshot]]:
    """Verify the accepted aggregate and capture its exact manifest bytes."""

    scripts = Path(__file__).resolve().parents[2] / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    verifier, verifier_source = _load_python_module_from_snapshot(
        scripts / "verify_accepted_aggregate.py",
        module_name="_freeze_verify_accepted_aggregate",
        label="accepted-aggregate verifier implementation",
    )
    root_arg = Path(artifact_root)
    manifest_name = f"SHA256SUMS_{branch}_aggregate.txt"
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        root_arg,
        manifest_name=manifest_name,
        target_names=aggregate_target_names(branch),
        label=f"{branch} accepted aggregate",
    )
    root = root_arg.resolve()
    # The existing production verifier is path-oriented.  Run it on a private
    # copy made solely from the bytes captured above so a root swap between its
    # manifest and summary reads cannot validate a different artifact set.
    try:
        with tempfile.TemporaryDirectory(prefix=f"verify-{branch}-aggregate-") as temporary:
            stable_root = Path(temporary)
            (stable_root / manifest_name).write_bytes(manifest_snapshot.data)
            for name, snapshot in snapshots.items():
                (stable_root / name).write_bytes(snapshot.data)
            expected_source = verifier.expected_bryson_source_sha256()
            verifier_entries = verifier.verify_manifest(stable_root, branch)
            verifier.verify_summary(
                stable_root, branch, expected_source, verifier_entries
            )
    except SystemExit as error:
        raise RuntimeError(f"Accepted aggregate verification failed: {error}") from error
    summary_name = f"joint_posterior_{branch}_aggregate_summary.json"
    propagation_name = (
        f"joint_posterior_{branch}_for_galactic_propagation.csv.gz"
    )
    full_name = f"joint_posterior_{branch}_full.csv.gz"
    diagnostics_name = f"trial_diagnostics_{branch}_full.jsonl"
    correlation_name = f"joint_posterior_{branch}_correlation.csv"
    audit_name = f"perturbation_audit_{branch}_full.csv.gz"
    raw_chain_audit_name = f"raw_unthinned_chain_audit_{branch}.json"
    summary = load_json_bytes(
        snapshots[summary_name].data, f"{branch} accepted aggregate summary"
    )
    return summary, {
        "artifact_root": str(root),
        "manifest_path": str(root / manifest_name),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
        "summary_sha256": snapshots[summary_name].sha256,
        "full_samples_sha256": snapshots[full_name].sha256,
        "propagation_samples_sha256": snapshots[propagation_name].sha256,
        "diagnostics_sha256": snapshots[diagnostics_name].sha256,
        "correlation_sha256": snapshots[correlation_name].sha256,
        "perturbation_audit_sha256": snapshots[audit_name].sha256,
        "raw_chain_audit_sha256": snapshots[raw_chain_audit_name].sha256,
        "verifier_implementation_sha256": verifier_source.sha256,
    }, {
        "full": snapshots[full_name],
        "propagation": snapshots[propagation_name],
        "diagnostics": snapshots[diagnostics_name],
        "correlation": snapshots[correlation_name],
        "perturbation_audit": snapshots[audit_name],
        "raw_chain_audit": snapshots[raw_chain_audit_name],
        "manifest": manifest_snapshot,
    }


def validate_likelihood_grid_root(
    artifact_root: Path,
    *,
    branch: str,
    full_snapshot: FileSnapshot,
    aggregate_manifest_snapshot: FileSnapshot,
    rate_model_source_snapshot: FileSnapshot,
    completeness_snapshot: FileSnapshot,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify one grid audit against the exact full-posterior bytes frozen here."""

    manifest_name = "SHA256SUMS_likelihood_grid_convergence.txt"
    selected_name = "selected_joint_parameter_points.csv"
    report_name = "LIKELIHOOD_GRID_CONVERGENCE.json"
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        Path(artifact_root),
        manifest_name=manifest_name,
        target_names=(selected_name, report_name),
        label=f"{branch} likelihood-grid convergence audit",
    )
    module, module_snapshot = _load_python_module_from_snapshot(
        Path(__file__).resolve().parent / "likelihood_grid_convergence.py",
        module_name=f"_freeze_likelihood_grid_convergence_{branch}",
        label="likelihood-grid verifier implementation",
    )
    with tempfile.TemporaryDirectory(prefix=f"freeze-likelihood-{branch}-") as temporary:
        temporary_root = Path(temporary)
        stable_artifact = temporary_root / "artifact"
        stable_artifact.mkdir()
        (stable_artifact / manifest_name).write_bytes(manifest_snapshot.data)
        for name, snapshot in snapshots.items():
            (stable_artifact / name).write_bytes(snapshot.data)
        stable_posterior = temporary_root / full_snapshot.path.name
        stable_aggregate_manifest = temporary_root / aggregate_manifest_snapshot.path.name
        stable_posterior.write_bytes(full_snapshot.data)
        stable_aggregate_manifest.write_bytes(aggregate_manifest_snapshot.data)
        stable_rate_model = temporary_root / rate_model_source_snapshot.path.name
        stable_completeness = temporary_root / completeness_snapshot.path.name
        stable_rate_model.write_bytes(rate_model_source_snapshot.data)
        stable_completeness.write_bytes(completeness_snapshot.data)
        report = module.verify_likelihood_grid_artifact(
            stable_artifact,
            branch=branch,
            posterior_path=stable_posterior,
            aggregate_manifest_path=stable_aggregate_manifest,
            rate_model_source_path=stable_rate_model,
            completeness_path=stable_completeness,
        )
    if report.get("status") != "PASS" or report.get("branch") != branch:
        raise RuntimeError(f"Likelihood-grid convergence did not pass for {branch}")
    return report, {
        "artifact_root": str(Path(artifact_root).resolve()),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {name: snapshot.sha256 for name, snapshot in snapshots.items()},
        "verifier_implementation_sha256": module_snapshot.sha256,
        "full_posterior_sha256": full_snapshot.sha256,
        "aggregate_manifest_sha256": aggregate_manifest_snapshot.sha256,
        "rate_model_source_sha256": rate_model_source_snapshot.sha256,
        "completeness_sha256": completeness_snapshot.sha256,
    }


def validate_catalog_perturbation_replay(
    *,
    branch: str,
    aggregate_root: Path,
    perturbation_audit_snapshot: FileSnapshot,
    diagnostics_snapshot: FileSnapshot,
    pc_catalog_snapshot: FileSnapshot,
    stellar_catalog_snapshot: FileSnapshot,
    data_locks_snapshot: FileSnapshot,
    measurement_error_mode: str = QUANTILE_MATCHED_TWO_SIDED,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replay every catalog perturbation from locked source-catalog bytes.

    The replay helper receives only stable private copies of the exact files
    captured by this freeze.  Its returned hashes are then cross-checked
    against those snapshots, binding the independent catalog reconstruction to
    the same aggregate bytes that are admitted by the numerical freeze.
    """

    module, module_snapshot = _load_python_module_from_snapshot(
        Path(__file__).resolve().parent / "catalog_perturbation_audit.py",
        module_name=f"_freeze_catalog_perturbation_audit_{branch}",
        label="catalog perturbation replay implementation",
    )
    with tempfile.TemporaryDirectory(prefix=f"freeze-catalog-{branch}-") as temporary:
        stable = Path(temporary)
        stable_aggregate = stable / "aggregate"
        stable_aggregate.mkdir()
        stable_audit = stable_aggregate / f"perturbation_audit_{branch}_full.csv.gz"
        stable_diagnostics = (
            stable_aggregate / f"trial_diagnostics_{branch}_full.jsonl"
        )
        stable_pc = stable / pc_catalog_snapshot.path.name
        stable_stellar = stable / stellar_catalog_snapshot.path.name
        stable_locks = stable / "DATA_LOCKS.json"
        stable_audit.write_bytes(perturbation_audit_snapshot.data)
        stable_diagnostics.write_bytes(diagnostics_snapshot.data)
        stable_pc.write_bytes(pc_catalog_snapshot.data)
        stable_stellar.write_bytes(stellar_catalog_snapshot.data)
        stable_locks.write_bytes(data_locks_snapshot.data)
        report = module.verify_catalog_perturbations(
            branch=branch,
            aggregate_root=stable_aggregate,
            pc_catalog=stable_pc,
            stellar_catalog=stable_stellar,
            data_locks_path=stable_locks,
            expected_trials=EXPECTED_OUTER_REALIZATIONS,
            measurement_error_mode=measurement_error_mode,
        )

    expected_identity = {
        "status": "PASS",
        "branch": branch,
        "measurement_error_mode": measurement_error_mode,
        "trials_verified": EXPECTED_OUTER_REALIZATIONS,
    }
    if any(report.get(key) != value for key, value in expected_identity.items()):
        raise RuntimeError(f"Catalog perturbation replay identity failed for {branch}")
    aggregate_inputs = report.get("aggregate_inputs")
    locked_inputs = report.get("locked_inputs")
    if not isinstance(aggregate_inputs, dict) or not isinstance(locked_inputs, dict):
        raise RuntimeError(f"Catalog perturbation replay evidence is incomplete for {branch}")
    expected_hashes = {
        ("aggregate_inputs", "perturbation_audit"): perturbation_audit_snapshot.sha256,
        ("aggregate_inputs", "trial_diagnostics"): diagnostics_snapshot.sha256,
        ("locked_inputs", module.PC_LOCK_ID): pc_catalog_snapshot.sha256,
        ("locked_inputs", module.STELLAR_LOCK_ID): stellar_catalog_snapshot.sha256,
    }
    containers = {
        "aggregate_inputs": aggregate_inputs,
        "locked_inputs": locked_inputs,
    }
    for (container_name, record_name), expected_hash in expected_hashes.items():
        record = containers[container_name].get(record_name)
        if not isinstance(record, dict) or record.get("sha256") != expected_hash:
            raise RuntimeError(
                f"Catalog perturbation replay hash binding failed for {branch}: "
                f"{record_name}"
            )
    data_locks = report.get("data_locks")
    verifier_source = report.get("verifier_source")
    if (
        not isinstance(data_locks, dict)
        or data_locks.get("sha256") != data_locks_snapshot.sha256
        or not isinstance(verifier_source, dict)
        or verifier_source.get("sha256") != module_snapshot.sha256
    ):
        raise RuntimeError(f"Catalog perturbation replay provenance failed for {branch}")
    return report, {
        "status": "PASS",
        "artifact_root": str(Path(aggregate_root).resolve()),
        "audit_id": report.get("audit_id"),
        "trials_verified": report.get("trials_verified"),
        "audit_rows_verified": report.get("audit_rows_verified"),
        "seed_schedule_sha256": report.get("seed_schedule_sha256"),
        "count_projection_sha256": report.get("count_projection_sha256"),
        "perturbation_audit_sha256": perturbation_audit_snapshot.sha256,
        "diagnostics_sha256": diagnostics_snapshot.sha256,
        "pc_catalog_sha256": pc_catalog_snapshot.sha256,
        "stellar_catalog_sha256": stellar_catalog_snapshot.sha256,
        "data_locks_sha256": data_locks_snapshot.sha256,
        "verifier_implementation_sha256": module_snapshot.sha256,
        "exact_catalog_replay": True,
    }


def sha256(path: Path) -> str:
    return read_file_snapshot(path, "SHA-256 input").sha256


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise RuntimeError(f"Non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> dict[str, Any]:
    value, _ = load_json_snapshot(path, f"JSON input {path}")
    return value


def validate_host_tams_audit_root(
    artifact_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    root_arg = Path(artifact_root)
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        root_arg,
        manifest_name=HOST_AUDIT_MANIFEST_NAME,
        target_names=(HOST_AUDIT_NAME, HOST_SELECTOR_TABLE_NAME),
        label="host/TAMS audit",
    )
    root = root_arg.resolve()
    audit_path = root / HOST_AUDIT_NAME
    audit = load_json_bytes(snapshots[HOST_AUDIT_NAME].data, "host/TAMS audit")
    if RETRACTED_METALLICITY_ANCHOR_NAME.encode("utf-8") in snapshots[
        HOST_AUDIT_NAME
    ].data:
        raise RuntimeError("Host/TAMS audit references the retracted metallicity anchor")
    if audit.get("status") != EXPECTED_HOST_STATUS:
        raise RuntimeError(
            f"Host/TAMS audit status must be exactly {EXPECTED_HOST_STATUS}"
        )
    if audit.get("metallicity_correction_policy") != {
        "applied": False,
        "publishable": False,
        "role": "EXCLUDED_OPEN_SYSTEMATIC",
        "interpretation": (
            "The independently verified differential correction is not "
            "publishable, is not applied to the host selector, and remains "
            "an explicit host-model systematic."
        ),
    }:
        raise RuntimeError("Host/TAMS metallicity correction policy changed")
    return audit, {
        "artifact_root": str(root),
        "manifest_path": str(root / HOST_AUDIT_MANIFEST_NAME),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
    }


def cross_check_fresh_freeze_inputs(
    host_audit: dict[str, Any],
    propagation_roots: dict[tuple[str, str], Path],
    propagation_evidence: dict[str, Any],
    metallicity_report: dict[str, Any],
    metallicity_evidence: dict[str, Any],
    parent_evidence: dict[str, Any],
    host_contract_evidence: dict[str, Any],
) -> None:
    input_names = {
        ("canonical", "constant"): "canonical_constant",
        ("canonical", "zero"): "canonical_zero",
        ("legacy", "constant"): "legacy_constant",
        ("legacy", "zero"): "legacy_zero",
    }
    host_inputs = host_audit.get("inputs")
    if not isinstance(host_inputs, dict):
        raise RuntimeError("Host/TAMS audit inputs are missing")
    audited_contract = host_inputs.get("host_artifact_contract")
    if not isinstance(audited_contract, dict):
        raise RuntimeError("Host/TAMS audit lacks accepted host-contract evidence")
    for key in (
        "contract_sha256",
        "contract_verifier_sha256",
        "manifest_sha256",
        "artifact_set_id",
        "representation_match",
        "production_accepted",
        "raw_parent_projection_sha256",
        "qualification_reports",
    ):
        if audited_contract.get(key) != host_contract_evidence.get(key):
            raise RuntimeError(f"Host/TAMS contract evidence mismatch: {key}")
    for key, input_name in input_names.items():
        record = host_inputs.get(input_name)
        if not isinstance(record, dict):
            raise RuntimeError(f"Host/TAMS audit lacks input record {input_name}")
        selector, branch = key
        current = propagation_evidence[selector][branch]
        if record.get("sha256") != current["summary_sha256"]:
            raise RuntimeError(f"Host/TAMS propagation summary mismatch: {input_name}")
        if record.get("manifest_sha256") != current["manifest_sha256"]:
            raise RuntimeError(f"Host/TAMS propagation manifest mismatch: {input_name}")

    parent_record = host_inputs.get("parent")
    if not isinstance(parent_record, dict):
        raise RuntimeError("Host/TAMS audit lacks its parent input record")
    for key in ("filename", "sha256", "size_bytes", "row_count"):
        if parent_record.get(key) != parent_evidence.get(key):
            raise RuntimeError(f"Host/TAMS parent input mismatch: {key}")
    for key in ("feh_min", "feh_max"):
        if not math.isclose(
            _require_finite_number(parent_record.get(key), f"host parent {key}"),
            _require_finite_number(parent_evidence.get(key), f"current parent {key}"),
            rel_tol=0.0,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(f"Host/TAMS parent input mismatch: {key}")

    for branch in ("constant", "zero"):
        record = host_inputs.get(f"{branch}_posterior_samples")
        current = propagation_evidence["canonical"][branch]["posterior_artifact"]
        if not isinstance(record, dict) or any(
            record.get(key) != current.get(key)
            for key in ("sha256", "size_bytes", "row_count")
        ):
            raise RuntimeError(f"Host/TAMS posterior artifact mismatch: {branch}")
    for selector in ("canonical", "legacy"):
        record = host_inputs.get(f"{selector}_hosts")
        current = propagation_evidence[selector]["constant"]["host_artifact"]
        if not isinstance(record, dict) or any(
            record.get(key) != current.get(key)
            for key in ("sha256", "size_bytes", "row_count")
        ):
            raise RuntimeError(f"Host/TAMS host-row artifact mismatch: {selector}")

    verified_metallicity = host_audit.get("verified_metallicity_artifact")
    if not isinstance(verified_metallicity, dict):
        raise RuntimeError("Host/TAMS verified metallicity evidence is missing")
    for key in ("report_sha256", "native_solar_tams_points_sha256"):
        if verified_metallicity.get(key) != metallicity_evidence.get(key):
            raise RuntimeError(f"Host/TAMS metallicity cross-hash mismatch: {key}")
    if host_audit.get("metallicity_dependent_TAMS_audit") != metallicity_report:
        raise RuntimeError("Host/TAMS embedded metallicity report is not current")
    native_input = host_inputs.get("native_solar_tams_points")
    if not isinstance(native_input, dict) or native_input.get("sha256") != (
        metallicity_evidence["native_solar_tams_points_sha256"]
    ):
        raise RuntimeError("Host/TAMS native-solar input hash is not current")
    derived = host_audit.get("derived_collapsed_host_measures")
    if not isinstance(derived, dict) or set(derived) != {"canonical", "legacy"}:
        raise RuntimeError("Host/TAMS derived host-measure evidence is missing")
    for selector in ("canonical", "legacy"):
        record = derived.get(selector)
        current = propagation_evidence[selector]["constant"]
        if (
            not isinstance(record, dict)
            or record.get("csv_sha256") != current["collapsed_host_sha256"]
            or record.get("row_count") != current["distinct_host_temperatures"]
            or abs(float(record.get("N_star")) - float(current["host_count"])) > 0.1
        ):
            raise RuntimeError(
                f"Host/TAMS derived host measure is not current for {selector}"
            )


def validate_ordered_quantiles(name: str, summary: dict[str, Any]) -> None:
    if not isinstance(summary, dict) or set(summary) != set(QUANTILES):
        raise RuntimeError(f"Invalid quantile schema for {name}")
    values = np.asarray(
        [_require_finite_number(summary[key], f"{name}:{key}") for key in QUANTILES],
        dtype=float,
    )
    if not np.all(np.isfinite(values)) or np.any(np.diff(values) < 0.0):
        raise RuntimeError(f"Invalid ordered quantiles for {name}: {values}")


def mcse_fraction(
    quantiles: dict[str, float],
    mcse: dict[str, Any],
    component: str,
) -> float:
    width = float(quantiles["q84"] - quantiles["q16"])
    if not np.isfinite(width) or width <= 0.0:
        raise RuntimeError("Non-positive q16--q84 width")
    if component == "outer":
        q50 = mcse.get("q50")
        if not isinstance(q50, dict):
            raise RuntimeError("Outer q50 MCSE must be an object")
        error = _require_finite_nonnegative(
            q50.get("standard_error"), "outer q50 MCSE"
        )
    elif component == "inner":
        error = _require_finite_nonnegative(mcse.get("q50"), "inner q50 MCSE")
    else:
        raise RuntimeError(f"Unsupported MCSE component: {component}")
    return error / width


def validate_aggregate(
    branch: str,
    data: dict[str, Any],
    *,
    expected_measurement_mode: str = QUANTILE_MATCHED_TWO_SIDED,
    expected_acceptance_profile: str | None = None,
) -> dict[str, Any]:
    if data.get("branch") != branch:
        raise RuntimeError(f"Aggregate branch mismatch for {branch}")
    measurement = data.get("measurement_error")
    if not isinstance(measurement, dict):
        raise RuntimeError(f"Aggregate measurement-error record is missing for {branch}")
    if expected_measurement_mode not in {
        QUANTILE_MATCHED_TWO_SIDED,
        LEGACY_SOURCE_MIXTURE,
    }:
        raise RuntimeError("Unsupported expected measurement-error mode")
    if measurement.get("mode") != expected_measurement_mode:
        raise RuntimeError(f"Unexpected measurement mode in {branch}")
    _require_exact_bool(
        measurement.get("source_faithful"),
        expected_measurement_mode == LEGACY_SOURCE_MIXTURE,
        f"{branch} source_faithful",
    )
    _require_exact_bool(
        measurement.get("post_perturbation_teff_filter"),
        expected_measurement_mode == QUANTILE_MATCHED_TWO_SIDED,
        f"{branch} post-perturbation Teff filter",
    )
    expected_counts = {
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
    for key, expected in expected_counts.items():
        if _require_integer(data.get(key), f"{branch} {key}") != expected:
            raise RuntimeError(f"Unexpected aggregate {key} for {branch}")
    if data.get("parameter_order") != ["F0", "alpha_radius", "beta_inst", "gamma"]:
        raise RuntimeError(f"Aggregate parameter order changed for {branch}")
    if _require_integer(data.get("total_trials"), f"{branch} total_trials") != 400:
        raise RuntimeError(f"Expected 400 outer realizations for {branch}")
    source_provenance = data.get("source_provenance")
    if not isinstance(source_provenance, dict):
        raise RuntimeError(f"Aggregate source provenance is missing for {branch}")
    _require_exact_bool(
        source_provenance.get("verified_for_every_shard"),
        True,
        f"{branch} source provenance",
    )
    acceptance_gate = data.get("production_acceptance_gate")
    if not isinstance(acceptance_gate, dict):
        raise RuntimeError(f"Production acceptance gate is missing for {branch}")
    _require_exact_bool(
        acceptance_gate.get("required"), True, f"{branch} acceptance required"
    )
    _require_exact_bool(
        acceptance_gate.get("accepted"), True, f"{branch} acceptance result"
    )
    profile = acceptance_gate.get("profile")
    if expected_acceptance_profile is None:
        allowed_profiles = {V404_ACCEPTANCE_PROFILE}
        if branch == "zero":
            allowed_profiles.add(V404_ZERO_EXTENDED_PROFILE)
    else:
        allowed_profiles = {expected_acceptance_profile}
    if profile not in allowed_profiles:
        raise RuntimeError(f"Unexpected aggregate acceptance profile for {branch}")
    if expected_measurement_mode == LEGACY_SOURCE_MIXTURE and (
        branch != "constant" or profile != V404_LEGACY_SENSITIVITY_PROFILE
    ):
        raise RuntimeError("Legacy measurement sensitivity profile binding failed")
    raw_gate = data.get("raw_unthinned_chain_acceptance_gate")
    if not isinstance(raw_gate, dict):
        raise RuntimeError(f"Raw unthinned-chain gate is missing for {branch}")
    _require_exact_bool(raw_gate.get("required"), True, f"{branch} raw gate required")
    _require_exact_bool(raw_gate.get("verified"), True, f"{branch} raw gate verified")
    _require_exact_bool(
        raw_gate.get("raw_files_copied_to_public_artifact"),
        False,
        f"{branch} public raw-chain exclusion",
    )
    if _require_integer(
        raw_gate.get("trials_verified"), f"{branch} raw-chain trial count"
    ) != 400:
        raise RuntimeError(f"Incomplete raw-chain audit for {branch}")
    for key in (
        "global_trial_identity_sha256",
        "evidence_report_sha256",
        "audit_helper_sha256",
    ):
        value = raw_gate.get(key)
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RuntimeError(f"Invalid raw-chain {key} for {branch}")
    minimum_ess_gate = _require_finite_number(
        acceptance_gate.get("minimum_ess_per_realization"),
        f"{branch} configured minimum ESS",
    )
    if minimum_ess_gate < 1000.0:
        raise RuntimeError(f"Aggregate ESS acceptance gate weakened for {branch}")
    diagnostics = data.get("diagnostics")
    if not isinstance(diagnostics, dict):
        raise RuntimeError(f"Aggregate diagnostics are missing for {branch}")
    required_counts = (
        _require_integer(diagnostics.get("adaptive_realizations"), "adaptive realizations"),
        _require_integer(
            diagnostics.get("adaptive_realizations_converged"),
            "converged adaptive realizations",
        ),
        _require_integer(
            diagnostics.get("realizations_with_estimable_autocorrelation"),
            "realizations with estimable autocorrelation",
        ),
        _require_integer(
            diagnostics.get("realizations_with_valid_effective_sample_size"),
            "realizations with valid effective sample size",
        ),
    )
    if required_counts != (400, 400, 400, 400):
        raise RuntimeError(f"Incomplete adaptive convergence for {branch}: {required_counts}")
    if _require_integer(diagnostics.get("optimizer_failures"), "optimizer failures") != 0:
        raise RuntimeError(f"Optimizer failures in {branch}")

    mc = data.get("posterior_quantile_monte_carlo_error")
    if not isinstance(mc, dict):
        raise RuntimeError(f"Aggregate MCSE diagnostics are missing for {branch}")
    if set(mc) != {
        "outer_realization_cluster_bootstrap",
        "outer_realization_cluster_bootstrap_replicates",
        "outer_realization_cluster_bootstrap_seed",
        "inner_chain_contiguous_batch_mcse",
        "inner_chain_batches",
        "interpretation",
    }:
        raise RuntimeError(f"Aggregate MCSE schema changed for {branch}")
    if _require_integer(
        mc.get("outer_realization_cluster_bootstrap_replicates"),
        "aggregate bootstrap replicate count",
    ) != 1000:
        raise RuntimeError("Aggregate bootstrap replicate count changed")
    if _require_integer(
        mc.get("outer_realization_cluster_bootstrap_seed"),
        "aggregate bootstrap seed",
    ) != 2026082101:
        raise RuntimeError("Aggregate bootstrap seed changed")
    if _require_integer(mc.get("inner_chain_batches"), "aggregate inner-chain batches") != 8:
        raise RuntimeError("Aggregate inner-chain batch count changed")
    outer_root = mc.get("outer_realization_cluster_bootstrap")
    inner_root = mc.get("inner_chain_contiguous_batch_mcse")
    if (
        not isinstance(outer_root, dict)
        or not isinstance(inner_root, dict)
        or set(outer_root) != set(PARAMETERS)
        or set(inner_root) != set(PARAMETERS)
    ):
        raise RuntimeError(f"Aggregate MCSE parameter set changed for {branch}")
    q50_gate = acceptance_gate.get("q50_mcse_by_parameter")
    if not isinstance(q50_gate, dict) or set(q50_gate) != set(PARAMETERS):
        raise RuntimeError(f"Aggregate acceptance MCSE record changed for {branch}")
    tau_root = diagnostics.get("autocorrelation_time_by_source_parameter")
    if not isinstance(tau_root, dict) or set(tau_root) != set(PARAMETERS):
        raise RuntimeError(f"Aggregate autocorrelation parameter set changed for {branch}")
    checks: dict[str, Any] = {}
    for parameter in PARAMETERS:
        posterior_quantiles = data.get("posterior_quantiles")
        if not isinstance(posterior_quantiles, dict) or set(posterior_quantiles) != set(PARAMETERS):
            raise RuntimeError(f"Aggregate posterior parameter set changed for {branch}")
        quantiles = posterior_quantiles[parameter]
        validate_ordered_quantiles(f"{branch}:{parameter}", quantiles)
        outer_fraction = mcse_fraction(
            quantiles,
            outer_root[parameter],
            "outer",
        )
        inner_fraction = mcse_fraction(
            quantiles,
            inner_root[parameter],
            "inner",
        )
        outer_parameter = _require_mapping(
            outer_root[parameter], f"{branch}:{parameter} outer MCSE"
        )
        inner_parameter = _require_mapping(
            inner_root[parameter], f"{branch}:{parameter} inner MCSE"
        )
        if set(outer_parameter) != set(QUANTILES) or set(inner_parameter) != set(
            QUANTILES
        ):
            raise RuntimeError(f"Aggregate MCSE quantile set changed for {branch}:{parameter}")
        for quantile in QUANTILES:
            interval = _require_mapping(
                outer_parameter[quantile],
                f"{branch}:{parameter}:{quantile} outer MCSE",
            )
            if set(interval) != {
                "standard_error",
                "bootstrap_q2.5",
                "bootstrap_q97.5",
            }:
                raise RuntimeError(
                    f"Aggregate outer MCSE schema changed for {branch}:{parameter}:{quantile}"
                )
            _require_finite_nonnegative(
                interval.get("standard_error"),
                f"{branch}:{parameter}:{quantile} standard error",
            )
            lower = _require_finite_number(
                interval.get("bootstrap_q2.5"),
                f"{branch}:{parameter}:{quantile} bootstrap lower",
            )
            upper = _require_finite_number(
                interval.get("bootstrap_q97.5"),
                f"{branch}:{parameter}:{quantile} bootstrap upper",
            )
            if lower > upper:
                raise RuntimeError(
                    f"Aggregate bootstrap interval is reversed for {branch}:{parameter}:{quantile}"
                )
            _require_finite_nonnegative(
                inner_parameter.get(quantile),
                f"{branch}:{parameter}:{quantile} inner MCSE",
            )
        accepted_mcse = _require_mapping(
            q50_gate[parameter], f"{branch}:{parameter} accepted q50 MCSE"
        )
        if set(accepted_mcse) != {
            "outer_q50_mcse_fraction_of_q16_q84_width",
            "inner_q50_mcse_fraction_of_q16_q84_width",
        }:
            raise RuntimeError(f"Aggregate accepted MCSE schema changed for {branch}:{parameter}")
        if not math.isclose(
            _require_finite_nonnegative(
                accepted_mcse["outer_q50_mcse_fraction_of_q16_q84_width"],
                f"{branch}:{parameter} accepted outer fraction",
            ),
            outer_fraction,
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ) or not math.isclose(
            _require_finite_nonnegative(
                accepted_mcse["inner_q50_mcse_fraction_of_q16_q84_width"],
                f"{branch}:{parameter} accepted inner fraction",
            ),
            inner_fraction,
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(f"Aggregate accepted MCSE is inconsistent for {branch}:{parameter}")
        ess_root = diagnostics.get("estimated_chain_ess_by_source_parameter")
        if not isinstance(ess_root, dict) or set(ess_root) != set(PARAMETERS):
            raise RuntimeError(f"Aggregate ESS parameter set changed for {branch}")
        ess = ess_root[parameter]
        if not isinstance(ess, dict) or set(ess) != {
            "minimum_per_realization",
            "q16_per_realization",
            "median_per_realization",
            "sum_over_realizations",
        }:
            raise RuntimeError(f"Aggregate ESS entry is malformed for {branch}:{parameter}")
        for key, value in ess.items():
            _require_finite_nonnegative(value, f"{branch}:{parameter} ESS {key}")
        tau = _require_mapping(tau_root[parameter], f"{branch}:{parameter} autocorrelation")
        if set(tau) != {"q16", "q50", "q84"}:
            raise RuntimeError(f"Aggregate autocorrelation schema changed for {branch}:{parameter}")
        tau_values = [
            _require_finite_nonnegative(tau[key], f"{branch}:{parameter} tau {key}")
            for key in ("q16", "q50", "q84")
        ]
        if tau_values != sorted(tau_values):
            raise RuntimeError(f"Aggregate autocorrelation quantiles are unordered for {branch}:{parameter}")
        minimum_ess = _require_finite_nonnegative(
            ess.get("minimum_per_realization"),
            f"{branch}:{parameter} minimum ESS",
        )
        if minimum_ess < 1000.0:
            raise RuntimeError(f"Insufficient minimum ESS for {branch}:{parameter}")
        if outer_fraction > 0.10 or inner_fraction > 0.05:
            raise RuntimeError(
                f"MCSE gate failed for {branch}:{parameter}: "
                f"outer={outer_fraction}, inner={inner_fraction}"
            )
        checks[parameter] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
            "minimum_ess_per_realization": minimum_ess,
        }
    return checks


def validate_full_posterior_artifact(
    snapshot: FileSnapshot, *, branch: str
) -> pd.DataFrame:
    """Validate the exact 400 x 1024 manifest-bound aggregate posterior."""

    frame = read_csv_bytes(
        snapshot.data,
        f"{branch} full aggregate posterior",
        compressed=True,
        float_precision="round_trip",
    )
    if tuple(frame.columns) != FULL_POSTERIOR_COLUMNS:
        raise RuntimeError(f"Full aggregate posterior columns changed for {branch}")
    numeric_columns = [
        name for name in FULL_POSTERIOR_COLUMNS if name not in {"branch", "run_label"}
    ]
    for column in numeric_columns:
        frame[column] = pd.to_numeric(frame[column], errors="raise")
    if not np.isfinite(frame[numeric_columns].to_numpy(dtype=float)).all():
        raise RuntimeError(f"Full aggregate posterior contains non-finite values for {branch}")
    integer_columns = (
        "shard",
        "trial",
        "global_trial",
        "trial_seed",
        "mcmc_seed",
        "production_step",
        "walker",
    )
    for column in integer_columns:
        values = frame[column].to_numpy(dtype=float)
        if np.any(values < 0.0) or not np.array_equal(
            values, values.astype(np.int64).astype(float)
        ):
            raise RuntimeError(f"Full aggregate {column} is not exactly non-negative integer")
        frame[column] = values.astype(np.int64)
    if set(frame.branch.astype(str)) != {branch}:
        raise RuntimeError(f"Full aggregate branch mismatch for {branch}")
    global_trial = frame.global_trial.to_numpy(dtype=np.int64)
    shard = frame.shard.to_numpy(dtype=np.int64)
    trial = frame.trial.to_numpy(dtype=np.int64)
    if not np.array_equal(global_trial, shard * 25 + trial):
        raise RuntimeError(f"Full aggregate shard/trial identity failed for {branch}")
    expected_labels = np.asarray(
        [f"production-shard-{value}" for value in shard], dtype=object
    )
    if not np.array_equal(frame.run_label.astype(str).to_numpy(), expected_labels):
        raise RuntimeError(f"Full aggregate run-label identity failed for {branch}")
    counts = frame.groupby("global_trial", sort=True).size()
    if not np.array_equal(
        counts.index.to_numpy(dtype=np.int64),
        np.arange(EXPECTED_OUTER_REALIZATIONS, dtype=np.int64),
    ) or not np.all(
        counts.to_numpy(dtype=np.int64) == EXPECTED_FULL_SAMPLES_PER_REALIZATION
    ):
        raise RuntimeError(f"Full aggregate does not contain exact 400 x 1024 layout for {branch}")
    if len(frame) != EXPECTED_FULL_ROW_COUNT:
        raise RuntimeError(f"Full aggregate row count changed for {branch}")
    order = frame.loc[:, ["global_trial", "production_step", "walker"]].to_numpy(
        dtype=np.int64
    )
    expected_order = np.lexsort((order[:, 2], order[:, 1], order[:, 0]))
    if not np.array_equal(expected_order, np.arange(len(frame), dtype=np.int64)):
        raise RuntimeError(f"Full aggregate row order changed for {branch}")
    if frame.duplicated(["global_trial", "production_step", "walker"]).any():
        raise RuntimeError(f"Full aggregate contains duplicate chain coordinates for {branch}")
    if not np.array_equal(
        frame.source_theta1_beta_inst.to_numpy(dtype=float),
        frame.beta.to_numpy(dtype=float),
    ) or not np.array_equal(
        frame.source_theta2_alpha_radius.to_numpy(dtype=float),
        frame.alpha.to_numpy(dtype=float),
    ):
        raise RuntimeError(f"Full aggregate source-parameter aliases changed for {branch}")
    return frame


def _compare_quantiles_to_frame(
    branch: str,
    data: dict[str, Any],
    key: str,
    frame: pd.DataFrame,
) -> None:
    reported = data.get(key)
    if not isinstance(reported, dict) or set(reported) != set(PARAMETERS):
        raise RuntimeError(f"Aggregate {key} parameter set changed for {branch}")
    probabilities = [0.025, 0.16, 0.50, 0.84, 0.975]
    for parameter in PARAMETERS:
        declared = reported[parameter]
        validate_ordered_quantiles(f"{branch}:{key}:{parameter}", declared)
        actual = np.quantile(frame[parameter].to_numpy(dtype=float), probabilities)
        expected = np.asarray([declared[name] for name in QUANTILES], dtype=float)
        if not np.allclose(actual, expected, rtol=1.0e-12, atol=1.0e-12):
            raise RuntimeError(
                f"Aggregate {key} does not match its actual sample: "
                f"{branch}:{parameter}"
            )


def _compare_aggregate_mcse_to_full(
    branch: str, data: dict[str, Any], full: pd.DataFrame
) -> None:
    mcse = _require_mapping(
        data.get("posterior_quantile_monte_carlo_error"),
        f"{branch} aggregate MCSE",
    )
    declared_outer = _require_mapping(
        mcse.get("outer_realization_cluster_bootstrap"),
        f"{branch} aggregate outer MCSE",
    )
    declared_inner = _require_mapping(
        mcse.get("inner_chain_contiguous_batch_mcse"),
        f"{branch} aggregate inner MCSE",
    )
    recomputed_outer = cluster_bootstrap_quantile_mcse(
        full, PARAMETERS, "global_trial", 1000, 2026082101
    )
    recomputed_inner = contiguous_batch_quantile_mcse(
        full, PARAMETERS, "global_trial", 8
    )
    for parameter in PARAMETERS:
        for quantile in QUANTILES:
            observed_interval = _require_mapping(
                declared_outer[parameter][quantile],
                f"{branch}:{parameter}:{quantile} outer MCSE",
            )
            expected_interval = recomputed_outer[parameter][quantile]
            for field in ("standard_error", "bootstrap_q2.5", "bootstrap_q97.5"):
                observed = _require_finite_number(
                    observed_interval.get(field),
                    f"{branch}:{parameter}:{quantile}:{field}",
                )
                if not math.isclose(
                    observed,
                    expected_interval[field],
                    rel_tol=1.0e-12,
                    abs_tol=1.0e-12,
                ):
                    raise RuntimeError(
                        f"Aggregate outer MCSE does not match full posterior: "
                        f"{branch}:{parameter}:{quantile}:{field}"
                    )
            observed_inner = _require_finite_nonnegative(
                declared_inner[parameter].get(quantile),
                f"{branch}:{parameter}:{quantile} inner MCSE",
            )
            if not math.isclose(
                observed_inner,
                recomputed_inner[parameter][quantile],
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            ):
                raise RuntimeError(
                    f"Aggregate inner MCSE does not match full posterior: "
                    f"{branch}:{parameter}:{quantile}"
                )


def validate_aggregate_posterior_artifacts(
    branch: str,
    data: dict[str, Any],
    full_snapshot: FileSnapshot,
    propagation_snapshot: FileSnapshot,
) -> tuple[dict[str, Any], pd.DataFrame]:
    """Recompute full/propagation quantiles, stride relation, and full MCSE."""

    full = validate_full_posterior_artifact(full_snapshot, branch=branch)
    propagation, _, _ = validate_posterior_artifact(
        propagation_snapshot, branch=branch
    )
    within = full.groupby("global_trial", sort=False).cumcount().to_numpy()
    expected_propagation = full.loc[
        within % 2 == 0, list(PROPAGATION_POSTERIOR_COLUMNS)
    ].reset_index(drop=True)
    if len(expected_propagation) != len(propagation) or not np.array_equal(
        expected_propagation.branch.astype(str).to_numpy(),
        propagation.branch.astype(str).to_numpy(),
    ) or not np.array_equal(
        expected_propagation.loc[:, PROPAGATION_POSTERIOR_COLUMNS[1:]].to_numpy(
            dtype=float
        ),
        propagation.loc[:, PROPAGATION_POSTERIOR_COLUMNS[1:]].to_numpy(dtype=float),
    ):
        raise RuntimeError(
            f"{branch} propagation posterior is not the exact stride-2 subset of full"
        )
    _compare_quantiles_to_frame(branch, data, "posterior_quantiles", full)
    _compare_quantiles_to_frame(
        branch,
        data,
        "galactic_propagation_posterior_quantiles",
        propagation,
    )
    _compare_aggregate_mcse_to_full(branch, data, full)
    return {
        "full_sha256": full_snapshot.sha256,
        "full_row_count": len(full),
        "propagation_sha256": propagation_snapshot.sha256,
        "propagation_row_count": len(propagation),
        "propagation_stride": 2,
    }, full


def _require_numeric_vector(
    value: Any, length: int, label: str, *, nonnegative: bool = False
) -> np.ndarray:
    if not isinstance(value, list) or len(value) != length:
        raise RuntimeError(f"{label} must be a {length}-element JSON array")
    numbers = np.asarray(
        [_require_finite_number(item, f"{label}[{index}]") for index, item in enumerate(value)],
        dtype=float,
    )
    if nonnegative and np.any(numbers < 0.0):
        raise RuntimeError(f"{label} must be non-negative")
    return numbers


def _compare_numeric_record(
    observed: Any, expected: dict[str, float], label: str
) -> None:
    record = _require_mapping(observed, label)
    if set(record) != set(expected):
        raise RuntimeError(f"{label} field set changed")
    for key, expected_value in expected.items():
        actual = _require_finite_number(record.get(key), f"{label}:{key}")
        if not math.isclose(
            actual, expected_value, rel_tol=1.0e-12, abs_tol=1.0e-12
        ):
            raise RuntimeError(f"{label}:{key} does not match diagnostics JSONL")


def validate_aggregate_diagnostics_artifact(
    branch: str,
    data: dict[str, Any],
    diagnostics_snapshot: FileSnapshot,
    full: pd.DataFrame,
) -> dict[str, Any]:
    """Recompute convergence, ESS, tau, and summary counts from JSONL bytes."""

    try:
        lines = diagnostics_snapshot.data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{branch} diagnostics JSONL is not valid UTF-8") from error
    if len(lines) != EXPECTED_OUTER_REALIZATIONS or any(not line for line in lines):
        raise RuntimeError(f"{branch} diagnostics JSONL must contain exactly 400 lines")
    entries = [
        load_json_bytes(line.encode("utf-8"), f"{branch} diagnostic line {index}")
        for index, line in enumerate(lines, start=1)
    ]
    expected_keys = {
        "trial",
        "seed",
        "perturbation_seed",
        "mcmc_seed",
        "measurement_error_mode",
        "selected_after_domain",
        "perturbation_counts",
        "optimizer_success",
        "optimizer_status",
        "optimizer_message",
        "optimizer_fun",
        "optimizer_theta_source_order",
        "mean_acceptance_fraction",
        "acceptance_fraction_by_walker",
        "autocorrelation_time",
        "effective_sample_size_source_order",
        "production_steps_completed",
        "adaptive_production",
        "converged",
        "convergence_checks",
        "runtime_seconds",
        "shard",
        "global_trial",
    }
    schedule = _require_mapping(data.get("runner_seed_schedule"), "runner seed schedule")
    if set(schedule) != {
        "base_seed_by_shard",
        "trial_seed_increment",
        "mcmc_seed_offset",
    }:
        raise RuntimeError("Runner seed-schedule schema changed")
    base_seeds = schedule.get("base_seed_by_shard")
    if (
        not isinstance(base_seeds, list)
        or len(base_seeds) != 16
        or any(isinstance(value, bool) or not isinstance(value, int) for value in base_seeds)
    ):
        raise RuntimeError("Runner base-seed schedule is malformed")
    trial_increment = _require_integer(
        schedule.get("trial_seed_increment"), "runner trial-seed increment"
    )
    mcmc_offset = _require_integer(
        schedule.get("mcmc_seed_offset"), "runner MCMC-seed offset"
    )
    if trial_increment != 1_000_003 or mcmc_offset != 500_000_003:
        raise RuntimeError("Runner seed schedule changed")

    by_global: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if set(entry) != expected_keys:
            raise RuntimeError(f"{branch} diagnostic entry schema changed")
        shard = _require_integer(entry.get("shard"), "diagnostic shard")
        trial = _require_integer(entry.get("trial"), "diagnostic trial")
        global_trial = _require_integer(
            entry.get("global_trial"), "diagnostic global_trial"
        )
        if (
            not 0 <= shard < 16
            or not 0 <= trial < 25
            or global_trial != shard * 25 + trial
            or global_trial in by_global
        ):
            raise RuntimeError(f"{branch} diagnostic shard/trial identity failed")
        expected_seed = base_seeds[shard] + trial_increment * trial
        if (
            _require_integer(entry.get("seed"), "diagnostic seed") != expected_seed
            or _require_integer(
                entry.get("perturbation_seed"), "diagnostic perturbation seed"
            )
            != expected_seed
            or _require_integer(entry.get("mcmc_seed"), "diagnostic MCMC seed")
            != expected_seed + mcmc_offset
        ):
            raise RuntimeError(f"{branch} diagnostic seed schedule failed")
        if entry.get("measurement_error_mode") != QUANTILE_MATCHED_TWO_SIDED:
            raise RuntimeError(f"{branch} diagnostic measurement mode changed")
        _require_exact_bool(entry.get("optimizer_success"), True, "optimizer success")
        _require_exact_bool(entry.get("adaptive_production"), True, "adaptive production")
        _require_exact_bool(entry.get("converged"), True, "adaptive convergence")
        _require_integer(entry.get("optimizer_status"), "optimizer status")
        if not isinstance(entry.get("optimizer_message"), str):
            raise RuntimeError("Optimizer message must be a string")
        _require_finite_number(entry.get("optimizer_fun"), "optimizer objective")
        _require_numeric_vector(
            entry.get("optimizer_theta_source_order"), 4, "optimizer theta"
        )
        acceptance = _require_finite_number(
            entry.get("mean_acceptance_fraction"), "mean acceptance fraction"
        )
        if not 0.0 <= acceptance <= 1.0:
            raise RuntimeError("Mean acceptance fraction is outside [0,1]")
        walker_acceptance = _require_numeric_vector(
            entry.get("acceptance_fraction_by_walker"),
            16,
            "walker acceptance fractions",
        )
        if np.any((walker_acceptance < 0.0) | (walker_acceptance > 1.0)):
            raise RuntimeError("Walker acceptance fraction is outside [0,1]")
        if not math.isclose(
            acceptance,
            float(np.mean(walker_acceptance)),
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(
                "Mean acceptance fraction differs from the per-walker evidence"
            )
        _require_numeric_vector(
            entry.get("autocorrelation_time"), 4, "autocorrelation time"
        )
        _require_numeric_vector(
            entry.get("effective_sample_size_source_order"),
            4,
            "effective sample size",
            nonnegative=True,
        )
        _require_positive_integer(
            entry.get("selected_after_domain"), "selected candidate count"
        )
        _require_finite_nonnegative(entry.get("runtime_seconds"), "diagnostic runtime")
        if not isinstance(entry.get("perturbation_counts"), dict):
            raise RuntimeError("Diagnostic perturbation_counts must be an object")
        checks = entry.get("convergence_checks")
        if not isinstance(checks, list):
            raise RuntimeError("Diagnostic convergence checks must be a list")
        for raw_check in checks:
            check = _require_mapping(raw_check, "diagnostic convergence check")
            if set(check) != {
                "production_steps",
                "autocorrelation_time",
                "length_ok",
                "stable",
                "max_relative_tau_change",
                "stable_check_streak",
            }:
                raise RuntimeError("Diagnostic convergence-check schema changed")
        by_global[global_trial] = entry
    if set(by_global) != set(range(EXPECTED_OUTER_REALIZATIONS)):
        raise RuntimeError(f"{branch} diagnostic global-trial set is incomplete")

    gate = _require_mapping(data.get("production_acceptance_gate"), "acceptance gate")
    policy = _require_mapping(gate.get("adaptive_production_policy"), "adaptive policy")
    aggregate_module, aggregate_source = _load_python_module_from_snapshot(
        Path(__file__).resolve().parent / "aggregate_hab2_joint_posterior.py",
        module_name="_freeze_aggregate_hab2_joint_posterior",
        label="aggregate diagnostics implementation",
    )
    ordered_entries = [by_global[index] for index in range(EXPECTED_OUTER_REALIZATIONS)]
    aggregate_module.validate_production_diagnostics(
        ordered_entries,
        SimpleNamespace(
            walkers=16,
            steps=3000,
            minimum_ess_per_realization=1000.0,
        ),
        policy,
    )

    # Bind the equalized chain rows to each diagnostic's exact random streams.
    if np.any(full.production_step.to_numpy(dtype=np.int64) % 20 != 0) or np.any(
        (full.walker.to_numpy(dtype=np.int64) < 0)
        | (full.walker.to_numpy(dtype=np.int64) >= 16)
    ):
        raise RuntimeError(f"{branch} full-chain coordinate policy changed")
    for global_trial, group in full.groupby("global_trial", sort=True):
        entry = by_global[int(global_trial)]
        if (
            set(group.trial_seed.to_numpy(dtype=np.int64))
            != {_require_integer(entry["perturbation_seed"], "diagnostic seed")}
            or set(group.mcmc_seed.to_numpy(dtype=np.int64))
            != {_require_integer(entry["mcmc_seed"], "diagnostic MCMC seed")}
            or int(group.production_step.max())
            >= _require_integer(entry["production_steps_completed"], "completed steps")
        ):
            raise RuntimeError(f"{branch} full chain is not bound to diagnostic {global_trial}")

    diagnostics_summary = _require_mapping(data.get("diagnostics"), "diagnostics summary")
    if set(diagnostics_summary) != {
        "optimizer_failures",
        "acceptance_fraction_q16_q50_q84",
        "runtime_seconds_per_realization_q16_q50_q84",
        "candidate_count_q16_q50_q84",
        "realizations_with_estimable_autocorrelation",
        "realizations_with_valid_effective_sample_size",
        "adaptive_realizations",
        "adaptive_realizations_converged",
        "autocorrelation_time_by_source_parameter",
        "estimated_chain_ess_by_source_parameter",
    }:
        raise RuntimeError("Aggregate diagnostics-summary schema changed")
    scalar_counts = {
        "optimizer_failures": 0,
        "realizations_with_estimable_autocorrelation": EXPECTED_OUTER_REALIZATIONS,
        "realizations_with_valid_effective_sample_size": EXPECTED_OUTER_REALIZATIONS,
        "adaptive_realizations": EXPECTED_OUTER_REALIZATIONS,
        "adaptive_realizations_converged": EXPECTED_OUTER_REALIZATIONS,
    }
    for key, expected in scalar_counts.items():
        if _require_integer(diagnostics_summary.get(key), key) != expected:
            raise RuntimeError(f"Aggregate diagnostics count mismatch: {key}")
    for key, source in (
        (
            "acceptance_fraction_q16_q50_q84",
            [entry["mean_acceptance_fraction"] for entry in ordered_entries],
        ),
        (
            "runtime_seconds_per_realization_q16_q50_q84",
            [entry["runtime_seconds"] for entry in ordered_entries],
        ),
        (
            "candidate_count_q16_q50_q84",
            [entry["selected_after_domain"] for entry in ordered_entries],
        ),
    ):
        observed = _require_numeric_vector(diagnostics_summary.get(key), 3, key)
        expected = np.quantile(np.asarray(source, dtype=float), [0.16, 0.50, 0.84])
        if not np.allclose(observed, expected, rtol=1.0e-12, atol=1.0e-12):
            raise RuntimeError(f"Aggregate diagnostic quantiles mismatch: {key}")
    completed_observed = _require_numeric_vector(
        data.get("production_steps_completed_q16_q50_q84"),
        3,
        "completed-step quantiles",
    )
    completed_expected = np.quantile(
        np.asarray([entry["production_steps_completed"] for entry in ordered_entries]),
        [0.16, 0.50, 0.84],
    )
    if not np.allclose(
        completed_observed, completed_expected, rtol=1.0e-12, atol=1.0e-12
    ):
        raise RuntimeError("Completed-step quantiles do not match diagnostics JSONL")

    tau_matrix = np.vstack(
        [np.asarray(entry["autocorrelation_time"], dtype=float) for entry in ordered_entries]
    )
    ess_matrix = np.vstack(
        [
            aggregate_module.effective_sample_size(
                entry, 16, 3000, require_explicit=True
            )
            for entry in ordered_entries
        ]
    )
    source_names = ("F0", "beta", "alpha", "gamma")
    tau_root = _require_mapping(
        diagnostics_summary.get("autocorrelation_time_by_source_parameter"),
        "autocorrelation summary",
    )
    ess_root = _require_mapping(
        diagnostics_summary.get("estimated_chain_ess_by_source_parameter"),
        "ESS summary",
    )
    if set(tau_root) != set(source_names) or set(ess_root) != set(source_names):
        raise RuntimeError("Diagnostic source-parameter set changed")
    for index, parameter in enumerate(source_names):
        _compare_numeric_record(
            tau_root[parameter],
            {
                "q16": float(np.quantile(tau_matrix[:, index], 0.16)),
                "q50": float(np.quantile(tau_matrix[:, index], 0.50)),
                "q84": float(np.quantile(tau_matrix[:, index], 0.84)),
            },
            f"{branch}:{parameter} tau summary",
        )
        _compare_numeric_record(
            ess_root[parameter],
            {
                "minimum_per_realization": float(np.min(ess_matrix[:, index])),
                "q16_per_realization": float(np.quantile(ess_matrix[:, index], 0.16)),
                "median_per_realization": float(np.median(ess_matrix[:, index])),
                "sum_over_realizations": float(np.sum(ess_matrix[:, index])),
            },
            f"{branch}:{parameter} ESS summary",
        )
    return {
        "sha256": diagnostics_snapshot.sha256,
        "row_count": len(entries),
        "all_optimizer_success": True,
        "all_converged": True,
        "all_ess_at_least_1000": True,
        "validator_implementation_sha256": aggregate_source.sha256,
    }


def validate_aggregate_perturbation_audit(
    branch: str,
    audit_snapshot: FileSnapshot,
    diagnostics_snapshot: FileSnapshot,
    *,
    expected_measurement_mode: str = QUANTILE_MATCHED_TWO_SIDED,
) -> tuple[dict[str, Any], pd.DataFrame]:
    """Recompute every per-realization perturbation count from audit-row bytes."""

    audit = read_csv_bytes(
        audit_snapshot.data,
        f"{branch} aggregate perturbation audit",
        compressed=True,
        float_precision="round_trip",
    )
    if tuple(audit.columns) != FULL_PERTURBATION_AUDIT_COLUMNS or not len(audit):
        raise RuntimeError(f"Aggregate perturbation-audit schema/size changed for {branch}")
    for column in ("shard", "trial", "global_trial", "trial_seed", "source_row"):
        audit[column] = _require_exact_integer_column(
            audit, column, f"{branch} aggregate perturbation audit"
        )
    if expected_measurement_mode not in {
        QUANTILE_MATCHED_TWO_SIDED,
        LEGACY_SOURCE_MIXTURE,
    } or (expected_measurement_mode == LEGACY_SOURCE_MIXTURE and branch != "constant"):
        raise RuntimeError("Unsupported aggregate perturbation-audit measurement mode")
    if set(audit.branch.astype(str)) != {branch} or audit.measurement_error_mode.astype(
        str
    ).ne(expected_measurement_mode).any():
        raise RuntimeError(f"Aggregate perturbation-audit identity changed for {branch}")
    if not np.array_equal(
        audit.global_trial.to_numpy(dtype=np.int64),
        audit.shard.to_numpy(dtype=np.int64) * 25
        + audit.trial.to_numpy(dtype=np.int64),
    ) or set(audit.global_trial.to_numpy(dtype=np.int64)) != set(
        range(EXPECTED_OUTER_REALIZATIONS)
    ):
        raise RuntimeError(f"Aggregate perturbation-audit trial identity failed for {branch}")
    expected_labels = np.asarray(
        [f"production-shard-{value}" for value in audit.shard], dtype=object
    )
    if not np.array_equal(audit.run_label.astype(str).to_numpy(), expected_labels):
        raise RuntimeError(f"Aggregate perturbation-audit run labels changed for {branch}")
    coordinates = audit.loc[:, ["global_trial", "source_row"]].to_numpy(dtype=np.int64)
    if not np.array_equal(
        np.lexsort((coordinates[:, 1], coordinates[:, 0])),
        np.arange(len(audit), dtype=np.int64),
    ) or audit.duplicated(["global_trial", "source_row"]).any():
        raise RuntimeError(f"Aggregate perturbation-audit order/uniqueness failed for {branch}")

    numeric_columns = [
        "kepid_x",
        "totalReliability",
        "koi_period",
        "gaia_iso_insol",
        "gaia_iso_insol_errm",
        "gaia_iso_insol_errp",
        "gaia_iso_prad",
        "gaia_iso_prad_errm",
        "gaia_iso_prad_errp",
        "teff",
        "teff_err2",
        "teff_err1",
        "perturbed_flux",
        "perturbed_radius",
        "perturbed_teff",
    ]
    for column in numeric_columns:
        audit[column] = pd.to_numeric(audit[column], errors="raise")
    if not np.isfinite(audit[numeric_columns].to_numpy(dtype=float)).all():
        raise RuntimeError(f"Aggregate perturbation audit contains non-finite values for {branch}")
    if np.any((audit.totalReliability < 0.0) | (audit.totalReliability > 1.0)):
        raise RuntimeError(f"Aggregate perturbation-audit reliability is outside [0,1]")
    boolean_columns = (
        "instellation_in_source_domain",
        "radius_in_source_domain",
        "teff_in_source_domain",
        "period_passes_optional_cutoff",
        "teff_filter_active",
        "retained_by_active_policy",
    )
    flags = {
        name: _require_exact_boolean_column(audit, name, "aggregate perturbation audit")
        for name in boolean_columns
    }
    expected_teff_filter = expected_measurement_mode == QUANTILE_MATCHED_TWO_SIDED
    if not np.all(flags["teff_filter_active"] == expected_teff_filter) or not flags[
        "period_passes_optional_cutoff"
    ].all():
        raise RuntimeError(f"Aggregate perturbation audit policy changed for {branch}")
    reconstructed_retained = (
        flags["instellation_in_source_domain"]
        & flags["radius_in_source_domain"]
        & flags["period_passes_optional_cutoff"]
    )
    if expected_teff_filter:
        reconstructed_retained &= flags["teff_in_source_domain"]
    if not np.array_equal(reconstructed_retained, flags["retained_by_active_policy"]):
        raise RuntimeError(f"Aggregate perturbation retained flags are inconsistent for {branch}")
    expected_status: list[str] = []
    for flux_ok, radius_ok, teff_ok, period_ok, retained in zip(
        flags["instellation_in_source_domain"],
        flags["radius_in_source_domain"],
        flags["teff_in_source_domain"],
        flags["period_passes_optional_cutoff"],
        reconstructed_retained,
    ):
        reasons: list[str] = []
        if not flux_ok:
            reasons.append("instellation_outside_source_domain")
        if not radius_ok:
            reasons.append("radius_outside_source_domain")
        if not teff_ok:
            reasons.append(
                "teff_outside_source_domain"
                if expected_teff_filter
                else "teff_outside_source_domain_not_filtered_in_legacy"
            )
        if not period_ok:
            reasons.append("period_above_optional_cutoff")
        if retained and not reasons:
            reasons.append("retained")
        expected_status.append(";".join(reasons))
    if audit.audit_status.astype(str).tolist() != expected_status:
        raise RuntimeError(f"Aggregate perturbation audit statuses are inconsistent for {branch}")

    try:
        diagnostic_lines = diagnostics_snapshot.data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Aggregate diagnostics JSONL is not UTF-8") from error
    diagnostics = {
        _require_integer(entry.get("global_trial"), "diagnostic global_trial"): entry
        for entry in (
            load_json_bytes(line.encode("utf-8"), f"{branch} diagnostic audit binding")
            for line in diagnostic_lines
        )
    }
    if set(diagnostics) != set(range(EXPECTED_OUTER_REALIZATIONS)):
        raise RuntimeError(f"Aggregate diagnostics trial set changed for {branch}")
    for global_trial, group in audit.groupby("global_trial", sort=True):
        index = int(global_trial)
        entry = diagnostics[index]
        positions = group.index.to_numpy(dtype=np.int64)
        group_flags = {name: values[positions] for name, values in flags.items()}
        all_three = (
            group_flags["instellation_in_source_domain"]
            & group_flags["radius_in_source_domain"]
            & group_flags["teff_in_source_domain"]
        )
        recomputed = {
            "n_reliability_selected_before_domain": len(group),
            "n_outside_instellation_source_domain": int(
                np.sum(~group_flags["instellation_in_source_domain"])
            ),
            "n_outside_radius_source_domain": int(
                np.sum(~group_flags["radius_in_source_domain"])
            ),
            "n_outside_teff_source_domain": int(
                np.sum(~group_flags["teff_in_source_domain"])
            ),
            "n_outside_any_of_three_source_domains": int(np.sum(~all_three)),
            "n_failing_optional_period_cutoff": int(
                np.sum(~group_flags["period_passes_optional_cutoff"])
            ),
            "n_retained_by_active_policy": int(
                np.sum(group_flags["retained_by_active_policy"])
            ),
            "n_retained_with_teff_outside_source_domain": int(
                np.sum(
                    group_flags["retained_by_active_policy"]
                    & ~group_flags["teff_in_source_domain"]
                )
            ),
        }
        counts = _require_mapping(entry.get("perturbation_counts"), "diagnostic perturbation counts")
        if set(counts) != PILOT_PERTURBATION_COUNT_KEYS:
            raise RuntimeError("Aggregate diagnostic perturbation-count schema changed")
        if any(_require_integer(counts[key], key) != value for key, value in recomputed.items()):
            raise RuntimeError(f"Aggregate perturbation counts differ for global trial {index}")
        if _require_integer(counts.get("n_catalog_rows"), "catalog row count") < len(group):
            raise RuntimeError("Aggregate catalog row count is below selected rows")
        if (
            _require_integer(entry.get("selected_after_domain"), "selected count")
            != recomputed["n_retained_by_active_policy"]
            or set(group.trial_seed.to_numpy(dtype=np.int64))
            != {_require_integer(entry.get("perturbation_seed"), "diagnostic seed")}
        ):
            raise RuntimeError(f"Aggregate perturbation audit is not bound to diagnostic {index}")
    return {
        "sha256": audit_snapshot.sha256,
        "row_count": len(audit),
        "outer_realizations": EXPECTED_OUTER_REALIZATIONS,
        "all_counts_recomputed": True,
    }, audit


def validate_aggregate_correlation_artifact(
    branch: str,
    data: dict[str, Any],
    correlation_snapshot: FileSnapshot,
    full: pd.DataFrame,
) -> dict[str, Any]:
    expected_name = f"joint_posterior_{branch}_correlation.csv"
    if data.get("correlation_matrix_file") != expected_name:
        raise RuntimeError(f"Aggregate correlation filename changed for {branch}")
    correlation = read_csv_bytes(
        correlation_snapshot.data,
        f"{branch} aggregate correlation matrix",
        index_col=0,
        float_precision="round_trip",
    )
    if tuple(correlation.columns) != PARAMETERS or tuple(
        correlation.index.astype(str)
    ) != PARAMETERS:
        raise RuntimeError(f"Aggregate correlation schema changed for {branch}")
    observed = correlation.to_numpy(dtype=float)
    expected = np.corrcoef(full.loc[:, PARAMETERS].to_numpy(dtype=float), rowvar=False)
    if not np.isfinite(observed).all() or not np.allclose(
        observed, expected, rtol=1.0e-12, atol=1.0e-12
    ):
        raise RuntimeError(f"Aggregate correlation matrix does not match full posterior")
    return {"sha256": correlation_snapshot.sha256, "dimension": 4}


def validate_seed_stability_artifact_root(
    artifact_root: Path, branch: str
) -> tuple[dict[str, Any], dict[str, FileSnapshot], dict[str, Any]]:
    manifest_name = f"SHA256SUMS_mcmc_seed_stability_{branch}.txt"
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        Path(artifact_root),
        manifest_name=manifest_name,
        target_names=seed_stability_target_names(branch),
        label=f"{branch} seed-stability audit",
    )
    report_name = f"mcmc_seed_stability_{branch}.json"
    report = load_json_bytes(snapshots[report_name].data, f"{branch} seed-stability report")
    return report, snapshots, {
        "artifact_root": str(Path(artifact_root).resolve()),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
    }


def _require_exact_integer_column(
    frame: pd.DataFrame, column: str, label: str
) -> np.ndarray:
    try:
        values = pd.to_numeric(frame[column], errors="raise").to_numpy(dtype=float)
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"{label} {column} is not numeric") from error
    if (
        not np.isfinite(values).all()
        or np.any(values < 0.0)
        or not np.array_equal(values, values.astype(np.int64).astype(float))
    ):
        raise RuntimeError(f"{label} {column} is not an exact non-negative integer")
    return values.astype(np.int64)


def _require_exact_boolean_column(
    frame: pd.DataFrame, column: str, label: str
) -> np.ndarray:
    result: list[bool] = []
    for index, value in enumerate(frame[column].tolist()):
        if isinstance(value, (bool, np.bool_)):
            result.append(bool(value))
        elif isinstance(value, str) and value in {"True", "False"}:
            result.append(value == "True")
        else:
            raise RuntimeError(
                f"{label} {column} row {index} is not an exact CSV boolean"
            )
    return np.asarray(result, dtype=bool)


def _quantile_record(values: np.ndarray) -> dict[str, float]:
    vector = np.asarray(values, dtype=float)
    if vector.ndim != 1 or not len(vector) or not np.isfinite(vector).all():
        raise RuntimeError("Cannot derive quantiles from an invalid sample")
    return {
        name: float(value)
        for name, value in zip(
            QUANTILES, np.quantile(vector, [0.025, 0.16, 0.50, 0.84, 0.975])
        )
    }


def _require_quantile_record_equal(
    observed: Any, expected: dict[str, float], label: str
) -> None:
    validate_ordered_quantiles(label, observed)
    for quantile in QUANTILES:
        if not math.isclose(
            _require_finite_number(observed[quantile], f"{label}:{quantile}"),
            expected[quantile],
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(f"{label}:{quantile} differs from the chain bytes")


def _validate_pilot_family_artifacts(
    *,
    branch: str,
    family_name: str,
    family: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    expected_trial_seeds: list[int],
    expected_mcmc_seeds: list[int],
    policy: dict[str, Any],
    aggregate_module: Any,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, list[int]]:
    """Bind one seed-family report to its chain, diagnostics and outer draws."""

    chain = read_csv_bytes(
        snapshots[family["chain_file"]].data,
        f"{branch}:{family_name} pilot chain",
        float_precision="round_trip",
    )
    if tuple(chain.columns) != PILOT_CHAIN_COLUMNS or not len(chain):
        raise RuntimeError(f"Pilot chain schema/size changed for {branch}:{family_name}")
    numeric_columns = [
        column for column in PILOT_CHAIN_COLUMNS if column not in {"branch", "run_label"}
    ]
    for column in numeric_columns:
        chain[column] = pd.to_numeric(chain[column], errors="raise")
    if not np.isfinite(chain[numeric_columns].to_numpy(dtype=float)).all():
        raise RuntimeError(f"Pilot chain contains non-finite values for {branch}:{family_name}")
    for column in (
        "trial",
        "trial_seed",
        "mcmc_seed",
        "production_step",
        "walker",
    ):
        chain[column] = _require_exact_integer_column(
            chain, column, f"{branch}:{family_name} pilot chain"
        )
    if set(chain.branch.astype(str)) != {branch} or set(
        chain.run_label.astype(str)
    ) != {family_name}:
        raise RuntimeError(f"Pilot chain identity changed for {branch}:{family_name}")
    if set(chain.trial.to_numpy(dtype=np.int64)) != {0, 1, 2}:
        raise RuntimeError(f"Pilot chain trial set changed for {branch}:{family_name}")
    order = chain.loc[:, ["trial", "production_step", "walker"]].to_numpy(
        dtype=np.int64
    )
    if not np.array_equal(
        np.lexsort((order[:, 2], order[:, 1], order[:, 0])),
        np.arange(len(chain), dtype=np.int64),
    ) or chain.duplicated(["trial", "production_step", "walker"]).any():
        raise RuntimeError(f"Pilot chain coordinates/order changed for {branch}:{family_name}")
    if not np.array_equal(
        chain.source_theta1_beta_inst.to_numpy(dtype=float),
        chain.beta.to_numpy(dtype=float),
    ) or not np.array_equal(
        chain.source_theta2_alpha_radius.to_numpy(dtype=float),
        chain.alpha.to_numpy(dtype=float),
    ):
        raise RuntimeError(f"Pilot source-parameter aliases changed for {branch}:{family_name}")

    diagnostic_value = load_json_value_bytes(
        snapshots[family["diagnostics_file"]].data,
        f"{branch}:{family_name} pilot diagnostics",
    )
    if not isinstance(diagnostic_value, list) or len(diagnostic_value) != 3:
        raise RuntimeError(f"Pilot diagnostics must contain three trials for {branch}:{family_name}")
    diagnostics: list[dict[str, Any]] = []
    for expected_trial, raw in enumerate(diagnostic_value):
        entry = _require_mapping(raw, f"{branch}:{family_name} diagnostic {expected_trial}")
        if set(entry) != PILOT_DIAGNOSTIC_KEYS:
            raise RuntimeError(f"Pilot diagnostic schema changed for {branch}:{family_name}")
        trial = _require_integer(entry.get("trial"), "pilot diagnostic trial")
        if trial != expected_trial:
            raise RuntimeError(f"Pilot diagnostic order changed for {branch}:{family_name}")
        if (
            _require_integer(entry.get("seed"), "pilot seed")
            != expected_trial_seeds[trial]
            or _require_integer(entry.get("perturbation_seed"), "pilot perturbation seed")
            != expected_trial_seeds[trial]
            or _require_integer(entry.get("mcmc_seed"), "pilot MCMC seed")
            != expected_mcmc_seeds[trial]
        ):
            raise RuntimeError(f"Pilot diagnostic seed schedule changed for {branch}:{family_name}")
        if entry.get("measurement_error_mode") != QUANTILE_MATCHED_TWO_SIDED:
            raise RuntimeError(f"Pilot measurement-error mode changed for {branch}:{family_name}")
        _require_exact_bool(entry.get("optimizer_success"), True, "pilot optimizer success")
        _require_exact_bool(entry.get("adaptive_production"), True, "pilot adaptive production")
        _require_exact_bool(entry.get("converged"), True, "pilot convergence")
        _require_integer(entry.get("optimizer_status"), "pilot optimizer status")
        if not isinstance(entry.get("optimizer_message"), str):
            raise RuntimeError("Pilot optimizer message must be a string")
        _require_finite_number(entry.get("optimizer_fun"), "pilot optimizer objective")
        _require_numeric_vector(entry.get("optimizer_theta_source_order"), 4, "pilot optimizer theta")
        walker_acceptance = _require_numeric_vector(
            entry.get("acceptance_fraction_by_walker"), 16, "pilot walker acceptance"
        )
        if np.any((walker_acceptance < 0.0) | (walker_acceptance > 1.0)):
            raise RuntimeError("Pilot walker acceptance is outside [0,1]")
        mean_acceptance = _require_finite_number(
            entry.get("mean_acceptance_fraction"), "pilot mean acceptance"
        )
        if not 0.0 <= mean_acceptance <= 1.0 or not math.isclose(
            mean_acceptance,
            float(np.mean(walker_acceptance)),
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError("Pilot mean acceptance is not derived from its walkers")
        tau = _require_numeric_vector(entry.get("autocorrelation_time"), 4, "pilot tau")
        ess = _require_numeric_vector(
            entry.get("effective_sample_size_source_order"), 4, "pilot ESS"
        )
        if np.any(tau <= 0.0) or np.any(ess <= 0.0):
            raise RuntimeError("Pilot tau/ESS must be positive")
        _require_positive_integer(entry.get("selected_after_domain"), "pilot selected count")
        _require_finite_nonnegative(entry.get("runtime_seconds"), "pilot runtime")
        counts = _require_mapping(entry.get("perturbation_counts"), "pilot perturbation counts")
        if set(counts) != PILOT_PERTURBATION_COUNT_KEYS:
            raise RuntimeError("Pilot perturbation-count schema changed")
        for key, value in counts.items():
            _require_integer(value, f"pilot perturbation count {key}")
            if value < 0:
                raise RuntimeError(f"Pilot perturbation count {key} is negative")
        enriched = dict(entry)
        enriched["global_trial"] = trial
        diagnostics.append(enriched)

    core_policy = {
        key: policy[key]
        for key in (
            "requested_minimum_steps",
            "requested_maximum_steps",
            "check_interval",
            "tau_multiple",
            "tau_relative_tolerance",
            "required_consecutive_stable_checks",
        )
    }
    aggregate_module.validate_production_diagnostics(
        diagnostics,
        SimpleNamespace(walkers=16, steps=3000, minimum_ess_per_realization=0.0),
        core_policy,
    )

    reported_steps = family.get("production_steps")
    actual_steps = [
        _require_integer(entry["production_steps_completed"], "pilot completed steps")
        for entry in diagnostics
    ]
    if reported_steps != actual_steps:
        raise RuntimeError(f"Pilot production-step report differs for {branch}:{family_name}")
    for trial, group in chain.groupby("trial", sort=True):
        index = int(trial)
        completed = actual_steps[index]
        if completed % 20:
            raise RuntimeError(f"Pilot completed steps are not divisible by thin=20")
        if set(group.trial_seed.to_numpy(dtype=np.int64)) != {
            expected_trial_seeds[index]
        } or set(group.mcmc_seed.to_numpy(dtype=np.int64)) != {
            expected_mcmc_seeds[index]
        }:
            raise RuntimeError(f"Pilot chain seed binding failed for {branch}:{family_name}")
        expected_steps = np.arange(0, completed, 20, dtype=np.int64)
        observed_steps = np.sort(group.production_step.unique())
        if not np.array_equal(observed_steps, expected_steps):
            raise RuntimeError(f"Pilot chain step schedule changed for {branch}:{family_name}")
        per_step = group.groupby("production_step", sort=True).walker.agg(list)
        if any(sorted(int(value) for value in walkers) != list(range(16)) for walkers in per_step):
            raise RuntimeError(f"Pilot chain walker layout changed for {branch}:{family_name}")

    planets = read_csv_bytes(
        snapshots[family["planets_file"]].data,
        f"{branch}:{family_name} perturbed planets",
        float_precision="round_trip",
    )
    audit = read_csv_bytes(
        snapshots[family["perturbation_audit_file"]].data,
        f"{branch}:{family_name} perturbation audit",
        float_precision="round_trip",
    )
    if tuple(planets.columns) != PILOT_PLANET_COLUMNS or tuple(audit.columns) != PILOT_AUDIT_COLUMNS:
        raise RuntimeError(f"Pilot outer-realization artifact schema changed for {branch}:{family_name}")
    for frame, frame_label in ((planets, "planets"), (audit, "audit")):
        if set(frame.branch.astype(str)) != {branch} or set(
            frame.run_label.astype(str)
        ) != {family_name}:
            raise RuntimeError(f"Pilot {frame_label} identity changed for {branch}:{family_name}")
        frame["trial"] = _require_exact_integer_column(
            frame, "trial", f"{branch}:{family_name} {frame_label}"
        )
        frame["trial_seed"] = _require_exact_integer_column(
            frame, "trial_seed", f"{branch}:{family_name} {frame_label}"
        )
        frame["source_row"] = _require_exact_integer_column(
            frame, "source_row", f"{branch}:{family_name} {frame_label}"
        )
        if set(frame.trial.to_numpy(dtype=np.int64)) != {0, 1, 2}:
            raise RuntimeError(f"Pilot {frame_label} trial set changed for {branch}:{family_name}")
        if frame.duplicated(["trial", "source_row"]).any():
            raise RuntimeError(f"Pilot {frame_label} contains duplicate source rows")
        for trial, group in frame.groupby("trial", sort=True):
            if set(group.trial_seed.to_numpy(dtype=np.int64)) != {
                expected_trial_seeds[int(trial)]
            }:
                raise RuntimeError(f"Pilot {frame_label} trial-seed binding failed")

    planet_numeric = [
        "total_reliability",
        "koi_period_days",
        "perturbed_flux",
        "perturbed_radius_rearth",
        "perturbed_teff_K",
    ]
    audit_numeric = [
        "kepid_x",
        "totalReliability",
        "koi_period",
        "gaia_iso_insol",
        "gaia_iso_insol_errm",
        "gaia_iso_insol_errp",
        "gaia_iso_prad",
        "gaia_iso_prad_errm",
        "gaia_iso_prad_errp",
        "teff",
        "teff_err2",
        "teff_err1",
        "perturbed_flux",
        "perturbed_radius",
        "perturbed_teff",
    ]
    for frame, columns, label in (
        (planets, planet_numeric, "pilot planets"),
        (audit, audit_numeric, "pilot audit"),
    ):
        for column in columns:
            frame[column] = pd.to_numeric(frame[column], errors="raise")
        if not np.isfinite(frame[columns].to_numpy(dtype=float)).all():
            raise RuntimeError(f"{label} contains non-finite values")
    if np.any((planets.total_reliability < 0.0) | (planets.total_reliability > 1.0)):
        raise RuntimeError("Pilot planet reliability is outside [0,1]")
    if np.any((audit.totalReliability < 0.0) | (audit.totalReliability > 1.0)):
        raise RuntimeError("Pilot audit reliability is outside [0,1]")
    if audit.measurement_error_mode.astype(str).ne(QUANTILE_MATCHED_TWO_SIDED).any():
        raise RuntimeError("Pilot audit measurement-error mode changed")
    boolean_columns = (
        "instellation_in_source_domain",
        "radius_in_source_domain",
        "teff_in_source_domain",
        "period_passes_optional_cutoff",
        "teff_filter_active",
        "retained_by_active_policy",
    )
    audit_flags = {
        column: _require_exact_boolean_column(audit, column, "pilot audit")
        for column in boolean_columns
    }
    if not audit_flags["teff_filter_active"].all() or not audit_flags[
        "period_passes_optional_cutoff"
    ].all():
        raise RuntimeError("Pilot corrected/no-period-cutoff policy changed")
    reconstructed_retained = (
        audit_flags["instellation_in_source_domain"]
        & audit_flags["radius_in_source_domain"]
        & audit_flags["teff_in_source_domain"]
        & audit_flags["period_passes_optional_cutoff"]
    )
    if not np.array_equal(reconstructed_retained, audit_flags["retained_by_active_policy"]):
        raise RuntimeError("Pilot audit retained flag is inconsistent")
    expected_status: list[str] = []
    for flux_ok, radius_ok, teff_ok, period_ok, retained in zip(
        audit_flags["instellation_in_source_domain"],
        audit_flags["radius_in_source_domain"],
        audit_flags["teff_in_source_domain"],
        audit_flags["period_passes_optional_cutoff"],
        reconstructed_retained,
    ):
        reasons: list[str] = []
        if not flux_ok:
            reasons.append("instellation_outside_source_domain")
        if not radius_ok:
            reasons.append("radius_outside_source_domain")
        if not teff_ok:
            reasons.append("teff_outside_source_domain")
        if not period_ok:
            reasons.append("period_above_optional_cutoff")
        if retained and not reasons:
            reasons.append("retained")
        expected_status.append(";".join(reasons))
    if audit.audit_status.astype(str).tolist() != expected_status:
        raise RuntimeError("Pilot audit status is inconsistent with its flags")

    for trial, trial_audit in audit.groupby("trial", sort=True):
        index = int(trial)
        entry = diagnostics[index]
        flags = {name: values[trial_audit.index.to_numpy()] for name, values in audit_flags.items()}
        all_three = (
            flags["instellation_in_source_domain"]
            & flags["radius_in_source_domain"]
            & flags["teff_in_source_domain"]
        )
        expected_counts = {
            "n_reliability_selected_before_domain": len(trial_audit),
            "n_outside_instellation_source_domain": int(
                np.sum(~flags["instellation_in_source_domain"])
            ),
            "n_outside_radius_source_domain": int(np.sum(~flags["radius_in_source_domain"])),
            "n_outside_teff_source_domain": int(np.sum(~flags["teff_in_source_domain"])),
            "n_outside_any_of_three_source_domains": int(np.sum(~all_three)),
            "n_failing_optional_period_cutoff": int(
                np.sum(~flags["period_passes_optional_cutoff"])
            ),
            "n_retained_by_active_policy": int(
                np.sum(flags["retained_by_active_policy"])
            ),
            "n_retained_with_teff_outside_source_domain": int(
                np.sum(
                    flags["retained_by_active_policy"]
                    & ~flags["teff_in_source_domain"]
                )
            ),
        }
        counts = entry["perturbation_counts"]
        if any(counts[key] != value for key, value in expected_counts.items()):
            raise RuntimeError(f"Pilot perturbation counts differ from audit trial {index}")
        catalog_rows = counts["n_catalog_rows"]
        if catalog_rows < len(trial_audit):
            raise RuntimeError("Pilot catalog row count is below the selected-row count")
        if entry["selected_after_domain"] != expected_counts["n_retained_by_active_policy"]:
            raise RuntimeError("Pilot selected count differs from the audit")
        trial_planets = planets.loc[planets.trial == index].sort_values("source_row")
        retained_audit = trial_audit.loc[
            flags["retained_by_active_policy"]
        ].sort_values("source_row")
        if len(trial_planets) != len(retained_audit):
            raise RuntimeError("Pilot retained planet count differs from audit")
        if not np.array_equal(
            trial_planets.source_row.to_numpy(dtype=np.int64),
            retained_audit.source_row.to_numpy(dtype=np.int64),
        ) or trial_planets.kepoi_name.astype(str).tolist() != retained_audit.kepoi_name.astype(str).tolist():
            raise RuntimeError("Pilot retained planet identities differ from audit")
        for planet_column, audit_column in (
            ("total_reliability", "totalReliability"),
            ("koi_period_days", "koi_period"),
            ("perturbed_flux", "perturbed_flux"),
            ("perturbed_radius_rearth", "perturbed_radius"),
            ("perturbed_teff_K", "perturbed_teff"),
        ):
            if not np.array_equal(
                trial_planets[planet_column].to_numpy(dtype=float),
                retained_audit[audit_column].to_numpy(dtype=float),
            ):
                raise RuntimeError(f"Pilot retained planet {planet_column} differs from audit")

    normalized_planets = planets.drop(columns=["run_label"]).sort_values(
        ["trial", "source_row"]
    ).reset_index(drop=True)
    normalized_audit = audit.drop(columns=["run_label"]).sort_values(
        ["trial", "source_row"]
    ).reset_index(drop=True)
    return chain, normalized_planets, normalized_audit, actual_steps


def validate_seed_stability(
    branch: str,
    data: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
) -> dict[str, Any]:
    """Recompute the seed-family gate from manifest-bound pilot artifacts."""

    expected_keys = {
        "schema_version",
        "status",
        "branch",
        "outer_realizations_identical_across_families",
        "independent_mcmc_seed_families",
        "all_trials_converged",
        "equalized_samples_per_outer_realization",
        "maximum_allowed_quantile_width_fraction",
        "adaptive_production_policy",
        "families",
        "stability",
        "gate_failures",
    }
    if set(data) != expected_keys:
        raise RuntimeError(f"Seed-stability schema changed for {branch}")
    if _require_integer(data.get("schema_version"), "seed-stability schema") != 2:
        raise RuntimeError(f"Seed-stability schema version changed for {branch}")
    if data.get("status") != "pass" or data.get("branch") != branch:
        raise RuntimeError(f"MCMC seed stability did not pass for {branch}")
    for key in (
        "outer_realizations_identical_across_families",
        "independent_mcmc_seed_families",
        "all_trials_converged",
    ):
        _require_exact_bool(data.get(key), True, f"{branch} seed stability {key}")
    equalized_samples = _require_positive_integer(
        data.get("equalized_samples_per_outer_realization"),
        f"{branch} equalized seed-family samples",
    )
    maximum_allowed = _require_finite_nonnegative(
        data.get("maximum_allowed_quantile_width_fraction"),
        f"{branch} seed-family width threshold",
    )
    if not math.isclose(maximum_allowed, 0.15, rel_tol=0.0, abs_tol=1.0e-15):
        raise RuntimeError(f"Seed-family threshold changed for {branch}")
    failures = data.get("gate_failures")
    if failures != []:
        raise RuntimeError(f"MCMC seed stability has gate failures for {branch}")
    families = data.get("families")
    expected_family_names = {"corrected-pilot-seed-1", "corrected-pilot-seed-2"}
    if not isinstance(families, dict) or set(families) != expected_family_names:
        raise RuntimeError(f"Exactly two seed families are required for {branch}")
    seed_sets: list[tuple[int, ...]] = []
    policy = _require_mapping(
        data.get("adaptive_production_policy"),
        f"{branch} pilot adaptive-production policy",
    )
    expected_policy = {
        "requested_minimum_steps": 3000,
        "requested_maximum_steps": 20000,
        "check_interval": 1000,
        "tau_multiple": 100.0,
        "tau_relative_tolerance": 0.05,
        "required_consecutive_stable_checks": 2,
        "walkers": 16,
        "runner_thin": 20,
    }
    if policy != expected_policy:
        raise RuntimeError(f"Pilot adaptive-production policy changed for {branch}")
    expected_snapshot_names = set(seed_stability_target_names(branch))
    if set(snapshots) != expected_snapshot_names:
        raise RuntimeError(f"Seed-stability snapshot set changed for {branch}")
    validated_chains: dict[str, pd.DataFrame] = {}
    equalized_chains: dict[str, pd.DataFrame] = {}
    normalized_planets: dict[str, pd.DataFrame] = {}
    normalized_audits: dict[str, pd.DataFrame] = {}
    aggregate_module, aggregate_source = _load_python_module_from_snapshot(
        Path(__file__).resolve().parent / "aggregate_hab2_joint_posterior.py",
        module_name="_freeze_seed_aggregate_hab2_joint_posterior",
        label="seed-stability diagnostics implementation",
    )
    for family_name, family in families.items():
        if not isinstance(family_name, str) or not family_name or not isinstance(family, dict):
            raise RuntimeError(f"Malformed seed family for {branch}")
        if set(family) != {
            "chain_file",
            "chain_sha256",
            "diagnostics_file",
            "diagnostics_sha256",
            "planets_file",
            "planets_sha256",
            "perturbation_audit_file",
            "perturbation_audit_sha256",
            "mcmc_seeds",
            "production_steps",
            "posterior_quantiles",
        }:
            raise RuntimeError(f"Seed-family schema changed for {branch}:{family_name}")
        if not isinstance(family.get("chain_file"), str) or not family["chain_file"]:
            raise RuntimeError(f"Seed-family chain path is missing for {branch}:{family_name}")
        expected_files = {
            "chain_file": f"joint_posterior_{branch}_{family_name}.csv",
            "diagnostics_file": f"trial_diagnostics_{branch}_{family_name}.json",
            "planets_file": f"perturbed_planets_{branch}_{family_name}.csv",
            "perturbation_audit_file": f"perturbation_audit_{branch}_{family_name}.csv",
        }
        for file_key, expected_name in expected_files.items():
            if family.get(file_key) != expected_name:
                raise RuntimeError(
                    f"Seed-family filename changed for {branch}:{family_name}:{file_key}"
                )
            hash_key = file_key.replace("_file", "_sha256")
            digest = family.get(hash_key)
            if (
                not isinstance(digest, str)
                or not SHA256_PATTERN.fullmatch(digest)
                or snapshots[expected_name].sha256 != digest
            ):
                raise RuntimeError(
                    f"Seed-family hash mismatch for {branch}:{family_name}:{file_key}"
                )
        seeds = family.get("mcmc_seeds")
        if (
            not isinstance(seeds, list)
            or not seeds
            or any(isinstance(value, bool) or not isinstance(value, int) for value in seeds)
            or seeds != sorted(set(seeds))
        ):
            raise RuntimeError(f"Malformed MCMC seed set for {branch}:{family_name}")
        family_number = int(family_name.rsplit("-", 1)[1])
        base_seed = 2026082101 + (100000 if branch == "zero" else 0)
        offset = 500000003 if family_number == 1 else 900000007
        expected_seeds = [base_seed + offset + trial * 1_000_003 for trial in range(3)]
        if seeds != expected_seeds:
            raise RuntimeError(f"MCMC seed schedule changed for {branch}:{family_name}")
        steps = family.get("production_steps")
        if (
            not isinstance(steps, list)
            or len(steps) != 3
            or any(
                isinstance(step, bool)
                or not isinstance(step, int)
                or step < 3000
                or step > 20000
                or step % 1000
                for step in steps
            )
        ):
            raise RuntimeError(f"Pilot production steps changed for {branch}:{family_name}")
        family_quantiles = family.get("posterior_quantiles")
        if not isinstance(family_quantiles, dict) or set(family_quantiles) != set(PARAMETERS):
            raise RuntimeError(f"Seed-family parameter set changed for {branch}:{family_name}")
        for parameter in PARAMETERS:
            validate_ordered_quantiles(
                f"{branch}:{family_name}:{parameter}", family_quantiles[parameter]
            )
        expected_trial_seeds = [
            base_seed + trial * 1_000_003 for trial in range(3)
        ]
        (
            validated_chains[family_name],
            normalized_planets[family_name],
            normalized_audits[family_name],
            _actual_steps,
        ) = _validate_pilot_family_artifacts(
            branch=branch,
            family_name=family_name,
            family=family,
            snapshots=snapshots,
            expected_trial_seeds=expected_trial_seeds,
            expected_mcmc_seeds=expected_seeds,
            policy=policy,
            aggregate_module=aggregate_module,
        )
        seed_sets.append(tuple(seeds))
    if len(set(seed_sets)) != len(seed_sets):
        raise RuntimeError(f"MCMC seed families are not independent for {branch}")
    ordered_family_names = sorted(families)
    try:
        pd.testing.assert_frame_equal(
            normalized_planets[ordered_family_names[0]],
            normalized_planets[ordered_family_names[1]],
            check_exact=True,
            check_dtype=True,
        )
        pd.testing.assert_frame_equal(
            normalized_audits[ordered_family_names[0]],
            normalized_audits[ordered_family_names[1]],
            check_exact=True,
            check_dtype=True,
        )
    except AssertionError as error:
        raise RuntimeError(
            f"Pilot outer realizations differ between MCMC seed families for {branch}"
        ) from error
    actual_equalized_samples = min(
        int(count)
        for frame in validated_chains.values()
        for count in frame.groupby("trial", sort=True).size().to_numpy()
    )
    if actual_equalized_samples != equalized_samples:
        raise RuntimeError(
            f"Seed-stability equalized sample count differs from actual chains for {branch}"
        )
    for family_name, chain in validated_chains.items():
        equalized = equalize_realizations(
            chain.sort_values(["trial", "production_step", "walker"]),
            "trial",
            equalized_samples,
        )
        equalized_chains[family_name] = equalized
        for parameter in PARAMETERS:
            _require_quantile_record_equal(
                families[family_name]["posterior_quantiles"][parameter],
                _quantile_record(equalized[parameter].to_numpy(dtype=float)),
                f"{branch}:{family_name}:{parameter} posterior quantiles",
            )
    combined_equalized = pd.concat(
        [equalized_chains[name] for name in ordered_family_names], ignore_index=True
    )
    stability = data.get("stability")
    if not isinstance(stability, dict) or set(stability) != set(PARAMETERS):
        raise RuntimeError(f"Seed-stability parameter set changed for {branch}")
    for parameter, record in stability.items():
        if not isinstance(record, dict) or set(record) != {
            "combined_quantiles",
            "family_differences",
            "maximum_width_fraction",
            "passed",
        }:
            raise RuntimeError(f"Malformed seed-stability record for {branch}:{parameter}")
        _require_exact_bool(record.get("passed"), True, f"{branch}:{parameter} seed gate")
        maximum = _require_finite_nonnegative(
            record.get("maximum_width_fraction"),
            f"{branch}:{parameter} seed width fraction",
        )
        if maximum > maximum_allowed:
            raise RuntimeError(f"Seed-family gate failed for {branch}:{parameter}")
        combined = record.get("combined_quantiles")
        validate_ordered_quantiles(
            f"{branch}:{parameter} combined seed quantiles",
            combined,
        )
        _require_quantile_record_equal(
            combined,
            _quantile_record(combined_equalized[parameter].to_numpy(dtype=float)),
            f"{branch}:{parameter} combined seed quantiles",
        )
        width = _require_finite_number(combined["q84"], "combined q84") - _require_finite_number(
            combined["q16"], "combined q16"
        )
        if width <= 0.0:
            raise RuntimeError(f"Combined seed width is non-positive for {branch}:{parameter}")
        differences = record.get("family_differences")
        if not isinstance(differences, dict) or set(differences) != {"q16", "q50", "q84"}:
            raise RuntimeError(f"Seed-family difference schema changed for {branch}:{parameter}")
        recomputed_fractions: list[float] = []
        for quantile in ("q16", "q50", "q84"):
            difference = _require_mapping(
                differences[quantile],
                f"{branch}:{parameter}:{quantile} family difference",
            )
            if set(difference) != {
                "absolute_family_range",
                "fraction_of_combined_q16_q84_width",
            }:
                raise RuntimeError(
                    f"Seed-family difference fields changed for {branch}:{parameter}:{quantile}"
                )
            family_values = [
                _require_finite_number(
                    families[name]["posterior_quantiles"][parameter][quantile],
                    f"{branch}:{name}:{parameter}:{quantile}",
                )
                for name in sorted(families)
            ]
            actual_range = max(family_values) - min(family_values)
            reported_range = _require_finite_nonnegative(
                difference["absolute_family_range"],
                f"{branch}:{parameter}:{quantile} family range",
            )
            reported_fraction = _require_finite_nonnegative(
                difference["fraction_of_combined_q16_q84_width"],
                f"{branch}:{parameter}:{quantile} family fraction",
            )
            if not math.isclose(
                reported_range, actual_range, rel_tol=1.0e-12, abs_tol=1.0e-12
            ) or not math.isclose(
                reported_fraction,
                actual_range / width,
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            ):
                raise RuntimeError(
                    f"Seed-family difference is inconsistent for {branch}:{parameter}:{quantile}"
                )
            recomputed_fractions.append(reported_fraction)
        if not math.isclose(
            maximum,
            max(recomputed_fractions),
            rel_tol=1.0e-12,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(f"Seed-family maximum is inconsistent for {branch}:{parameter}")
    return {
        "status": "pass",
        "family_count": len(families),
        "equalized_samples_per_outer_realization": equalized_samples,
        "maximum_allowed_quantile_width_fraction": maximum_allowed,
        "diagnostics_validator_sha256": aggregate_source.sha256,
        "validated_artifact_sha256": {
            name: snapshots[name].sha256 for name in seed_stability_target_names(branch)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    for branch in ("constant", "zero"):
        parser.add_argument(f"--{branch}-aggregate-root", required=True, type=Path)
        parser.add_argument(f"--{branch}-seed-stability-root", required=True, type=Path)
        parser.add_argument(
            f"--{branch}-likelihood-grid-root", required=True, type=Path
        )
        for selector in ("canonical", "legacy"):
            parser.add_argument(
                f"--{selector}-{branch}-artifact-root", required=True, type=Path
            )
    parser.add_argument("--canonical-hosts", required=True, type=Path)
    parser.add_argument("--legacy-hosts", required=True, type=Path)
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--host-artifact-contract", required=True, type=Path)
    parser.add_argument("--host-qualification-report", required=True, type=Path)
    parser.add_argument(
        "--expected-host-artifact-contract-sha256", required=True
    )
    parser.add_argument(
        "--expected-host-artifact-contract-size-bytes", required=True, type=int
    )
    parser.add_argument(
        "--expected-host-qualification-report-sha256", required=True
    )
    parser.add_argument(
        "--expected-host-qualification-report-size-bytes", required=True, type=int
    )
    parser.add_argument("--age-cut-ssp-contract", required=True, type=Path)
    parser.add_argument(
        "--age-cut-ssp-qualification-report", required=True, type=Path
    )
    parser.add_argument("--expected-age-cut-ssp-contract-sha256", required=True)
    parser.add_argument(
        "--expected-age-cut-ssp-contract-size-bytes", required=True, type=int
    )
    parser.add_argument(
        "--expected-age-cut-ssp-qualification-report-sha256", required=True
    )
    parser.add_argument(
        "--expected-age-cut-ssp-qualification-report-size-bytes",
        required=True,
        type=int,
    )
    parser.add_argument("--host-artifact-root", required=True, type=Path)
    parser.add_argument("--host-summary", required=True, type=Path)
    parser.add_argument("--rate-model-source", required=True, type=Path)
    parser.add_argument("--pc-catalog", required=True, type=Path)
    parser.add_argument("--stellar-catalog", required=True, type=Path)
    parser.add_argument("--constant-completeness", required=True, type=Path)
    parser.add_argument("--zero-completeness", required=True, type=Path)
    parser.add_argument("--tams-convergence-root", required=True, type=Path)
    parser.add_argument("--radial-ssp-contract", required=True, type=Path)
    parser.add_argument(
        "--radial-ssp-qualification-report", required=True, type=Path
    )
    parser.add_argument("--expected-radial-ssp-contract-sha256", required=True)
    parser.add_argument(
        "--expected-radial-ssp-contract-size-bytes", required=True, type=int
    )
    parser.add_argument(
        "--expected-radial-ssp-qualification-report-sha256", required=True
    )
    parser.add_argument(
        "--expected-radial-ssp-qualification-report-size-bytes",
        required=True,
        type=int,
    )
    parser.add_argument("--local-run-attestation-contract", required=True, type=Path)
    parser.add_argument(
        "--expected-local-run-attestation-contract-sha256", required=True
    )
    parser.add_argument(
        "--expected-local-run-attestation-contract-size-bytes",
        required=True,
        type=int,
    )
    parser.add_argument("--local-run-attestation-candidate", required=True)
    parser.add_argument("--local-run-public-report", required=True, type=Path)
    parser.add_argument("--expected-local-run-public-report-sha256", required=True)
    parser.add_argument(
        "--expected-local-run-public-report-size-bytes", required=True, type=int
    )
    parser.add_argument("--local-run-public-source-repo", required=True, type=Path)
    parser.add_argument("--local-run-private-source-repo", required=True, type=Path)
    parser.add_argument("--local-run-plan", required=True, type=Path)
    parser.add_argument("--local-run-runtime-manifest", required=True, type=Path)
    parser.add_argument("--local-run-output-root", required=True, type=Path)
    parser.add_argument("--local-run-evidence-dir", required=True, type=Path)
    parser.add_argument("--local-run-execution-root", required=True, type=Path)
    parser.add_argument(
        "--local-run-execution-environment",
        required=True,
        choices=("local_ubuntu_22_04_wsl2",),
    )
    parser.add_argument("--local-run-git-executable", required=True, type=Path)
    parser.add_argument("--local-run-ssh-keygen-executable", required=True, type=Path)
    parser.add_argument("--host-tams-audit-root", required=True, type=Path)
    parser.add_argument("--metallicity-audit-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    external_snapshots = {
        "external host acceptance contract": validate_external_evidence_lock(
            args.host_artifact_contract,
            expected_sha256=args.expected_host_artifact_contract_sha256,
            expected_size_bytes=args.expected_host_artifact_contract_size_bytes,
            label="external host acceptance contract",
        ),
        "external host qualification report": validate_external_evidence_lock(
            args.host_qualification_report,
            expected_sha256=args.expected_host_qualification_report_sha256,
            expected_size_bytes=args.expected_host_qualification_report_size_bytes,
            label="external host qualification report",
        ),
        "external age-cut SSP acceptance contract": validate_external_evidence_lock(
            args.age_cut_ssp_contract,
            expected_sha256=args.expected_age_cut_ssp_contract_sha256,
            expected_size_bytes=args.expected_age_cut_ssp_contract_size_bytes,
            label="external age-cut SSP acceptance contract",
        ),
        "external age-cut SSP qualification report": validate_external_evidence_lock(
            args.age_cut_ssp_qualification_report,
            expected_sha256=args.expected_age_cut_ssp_qualification_report_sha256,
            expected_size_bytes=(
                args.expected_age_cut_ssp_qualification_report_size_bytes
            ),
            label="external age-cut SSP qualification report",
        ),
        "external radial SSP acceptance contract": validate_external_evidence_lock(
            args.radial_ssp_contract,
            expected_sha256=args.expected_radial_ssp_contract_sha256,
            expected_size_bytes=args.expected_radial_ssp_contract_size_bytes,
            label="external radial SSP acceptance contract",
        ),
        "external radial SSP qualification report": validate_external_evidence_lock(
            args.radial_ssp_qualification_report,
            expected_sha256=args.expected_radial_ssp_qualification_report_sha256,
            expected_size_bytes=(
                args.expected_radial_ssp_qualification_report_size_bytes
            ),
            label="external radial SSP qualification report",
        ),
        "external local-run acceptance contract": validate_external_evidence_lock(
            args.local_run_attestation_contract,
            expected_sha256=args.expected_local_run_attestation_contract_sha256,
            expected_size_bytes=args.expected_local_run_attestation_contract_size_bytes,
            label="external local-run acceptance contract",
        ),
        "external local-run public report": validate_external_evidence_lock(
            args.local_run_public_report,
            expected_sha256=args.expected_local_run_public_report_sha256,
            expected_size_bytes=args.expected_local_run_public_report_size_bytes,
            label="external local-run public report",
        ),
    }
    external_pairs = {
        "host": validate_external_contract_report_pair(
            "host",
            external_snapshots["external host acceptance contract"],
            external_snapshots["external host qualification report"],
        ),
        "age": validate_external_contract_report_pair(
            "age",
            external_snapshots["external age-cut SSP acceptance contract"],
            external_snapshots["external age-cut SSP qualification report"],
        ),
        "radial": validate_external_contract_report_pair(
            "radial",
            external_snapshots["external radial SSP acceptance contract"],
            external_snapshots["external radial SSP qualification report"],
        ),
        "local": validate_external_contract_report_pair(
            "local",
            external_snapshots["external local-run acceptance contract"],
            external_snapshots["external local-run public report"],
        ),
    }

    out = args.out.resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise RuntimeError("Numerical-freeze output directory must be absent or empty")
    local_contract_document = load_json_bytes(
        external_snapshots["external local-run acceptance contract"].data,
        "external local-run acceptance contract",
    )
    local_report_document = load_json_bytes(
        external_snapshots["external local-run public report"].data,
        "external local-run public report",
    )
    computational_sources = {
        "local": local_qualification_source_identity(
            local_contract_document, local_report_document
        )
    }
    expected_host_source_lock = host_source_lock_from_local_contract(
        local_contract_document, computational_sources["local"]
    )
    local_run_evidence = verify_local_run_attestation_binding(
        args.local_run_attestation_contract,
        candidate_id=args.local_run_attestation_candidate,
        public_report_path=args.local_run_public_report,
        expected_contract_sha256=args.expected_local_run_attestation_contract_sha256,
        expected_contract_size_bytes=(
            args.expected_local_run_attestation_contract_size_bytes
        ),
        expected_public_report_sha256=args.expected_local_run_public_report_sha256,
        expected_public_report_size_bytes=(
            args.expected_local_run_public_report_size_bytes
        ),
        expected_computational_source=computational_sources["local"],
        public_source_repo=args.local_run_public_source_repo,
        private_source_repo=args.local_run_private_source_repo,
        plan_path=args.local_run_plan,
        runtime_manifest_path=args.local_run_runtime_manifest,
        output_root=args.local_run_output_root,
        evidence_dir=args.local_run_evidence_dir,
        execution_root=args.local_run_execution_root,
        execution_environment=args.local_run_execution_environment,
        git_executable=args.local_run_git_executable,
        ssh_keygen_executable=args.local_run_ssh_keygen_executable,
    )
    if local_run_evidence.get("computational_source") != computational_sources[
        "local"
    ]:
        raise RuntimeError(
            "local binding returned a computational source different from its accepted evidence"
        )
    local_run_evidence.update(
        {
            **external_pairs["local"],
            "computational_source": dict(computational_sources["local"]),
        }
    )
    age_verifier, age_verifier_snapshot = _load_python_module_from_snapshot(
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "verify_age_cut_ssp_contract.py",
        module_name="_numerical_freeze_age_ssp_contract",
        label="age-cut SSP contract verifier",
    )
    age_contract, _age_contract_check_snapshot = age_verifier.load_contract(
        args.age_cut_ssp_contract
    )
    age_candidate = age_verifier.accepted_candidate(age_contract)
    age_report_document = load_json_bytes(
        external_snapshots["external age-cut SSP qualification report"].data,
        "external age-cut SSP qualification report",
    )
    age_verifier.validate_report_document(
        age_report_document, age_contract, age_candidate
    )
    computational_sources["age"] = age_qualification_source_identity(
        age_report_document
    )
    external_pairs["age"].update(
        {
            "contract_verifier_sha256": age_verifier_snapshot.sha256,
            "computational_source": dict(computational_sources["age"]),
        }
    )
    signed_output_files = local_run_evidence.pop("_signed_output_files", None)
    if not isinstance(signed_output_files, dict):
        raise RuntimeError("Signed local-run output map is unavailable")
    attested_roots = {
        "corrected_constant_aggregate": args.constant_aggregate_root,
        "corrected_zero_aggregate": args.zero_aggregate_root,
        "constant_seed_stability": args.constant_seed_stability_root,
        "zero_seed_stability": args.zero_seed_stability_root,
        "constant_likelihood_grid": args.constant_likelihood_grid_root,
        "zero_likelihood_grid": args.zero_likelihood_grid_root,
        "host_tams_audit": args.host_tams_audit_root,
        "metallicity_tams_audit": args.metallicity_audit_root,
        **{
            f"{selector}_{branch}_propagation": getattr(
                args, f"{selector}_{branch}_artifact_root"
            )
            for selector in ("canonical", "legacy")
            for branch in ("constant", "zero")
        },
    }
    preconsumption_attestation = verify_attested_output_roots(
        args.local_run_output_root, attested_roots, signed_output_files
    )
    input_snapshots: dict[str, FileSnapshot] = {}
    aggregates: dict[str, dict[str, Any]] = {}
    aggregate_root_evidence: dict[str, dict[str, Any]] = {}
    full_posterior_paths: dict[str, FileSnapshot] = {}
    posterior_paths: dict[str, FileSnapshot] = {}
    diagnostics_paths: dict[str, FileSnapshot] = {}
    correlation_paths: dict[str, FileSnapshot] = {}
    aggregate_manifest_paths: dict[str, FileSnapshot] = {}
    perturbation_audit_paths: dict[str, FileSnapshot] = {}
    for branch in ("constant", "zero"):
        aggregate_samples: dict[str, FileSnapshot]
        (
            aggregates[branch],
            aggregate_root_evidence[branch],
            aggregate_samples,
        ) = validate_aggregate_artifact_root(
            getattr(args, f"{branch}_aggregate_root"), branch
        )
        full_posterior_paths[branch] = aggregate_samples["full"]
        posterior_paths[branch] = aggregate_samples["propagation"]
        diagnostics_paths[branch] = aggregate_samples["diagnostics"]
        correlation_paths[branch] = aggregate_samples["correlation"]
        aggregate_manifest_paths[branch] = aggregate_samples["manifest"]
        perturbation_audit_paths[branch] = aggregate_samples["perturbation_audit"]
    rate_model_source_snapshot = read_file_snapshot(
        args.rate_model_source, "locked Bryson rate-model source"
    )
    completeness_snapshots = {
        branch: read_file_snapshot(
            getattr(args, f"{branch}_completeness"),
            f"locked {branch} completeness FITS",
        )
        for branch in ("constant", "zero")
    }
    catalog_snapshots = {
        "pc_catalog": read_file_snapshot(
            args.pc_catalog, "locked Bryson planet-candidate catalog"
        ),
        "stellar_catalog": read_file_snapshot(
            args.stellar_catalog, "locked Bryson stellar catalog"
        ),
        "data_locks": read_file_snapshot(
            Path(__file__).resolve().parents[2] / "provenance" / "DATA_LOCKS.json",
            "scientific data-lock registry",
        ),
    }
    input_snapshots.update(catalog_snapshots)
    propagation_roots = {
        (selector, branch): getattr(args, f"{selector}_{branch}_artifact_root")
        for selector in ("canonical", "legacy")
        for branch in ("constant", "zero")
    }
    host_paths = {
        "canonical": args.canonical_hosts,
        "legacy": args.legacy_hosts,
    }
    (
        _parent,
        _parent_masks,
        parent_collapsed,
        parent_host_frames,
        parent_snapshot,
        parent_evidence,
    ) = validate_parent_artifact(args.parent)
    (
        _host_contract_result,
        host_contract_evidence,
        contract_host_summary_snapshot,
    ) = verify_host_artifact_contract_binding(
        args.host_artifact_contract,
        args.host_artifact_root,
        parent_host_frames["canonical"],
        expected_contract_sha256=args.expected_host_artifact_contract_sha256,
        expected_contract_size_bytes=args.expected_host_artifact_contract_size_bytes,
        expected_qualification_report_sha256=(
            args.expected_host_qualification_report_sha256
        ),
        expected_qualification_report_size_bytes=(
            args.expected_host_qualification_report_size_bytes
        ),
        expected_source_lock=expected_host_source_lock,
        qualification_report_path=args.host_qualification_report,
    )
    host_report_document = load_json_bytes(
        external_snapshots["external host qualification report"].data,
        "external host qualification report",
    )
    computational_sources["host"] = host_qualification_source_identity(
        host_report_document
    )
    if host_contract_evidence.get("computational_source") != computational_sources[
        "host"
    ]:
        raise RuntimeError(
            "host binding returned a computational source different from its signed report"
        )
    host_contract_evidence.update(
        {
            **external_pairs["host"],
            "computational_source": dict(computational_sources["host"]),
        }
    )
    propagation_summaries, propagation_evidence = validate_fresh_propagation_set(
        propagation_roots,
        posterior_paths=posterior_paths,
        host_paths=host_paths,
        parent_collapsed=parent_collapsed,
        parent_host_frames=parent_host_frames,
    )
    host_tams_audit, host_tams_root_evidence = validate_host_tams_audit_root(
        args.host_tams_audit_root
    )
    metallicity_report, metallicity_evidence = verify_metallicity_audit_root(
        args.metallicity_audit_root,
        parent_evidence=parent_evidence,
    )
    cross_check_fresh_freeze_inputs(
        host_tams_audit,
        propagation_roots,
        propagation_evidence,
        metallicity_report,
        metallicity_evidence,
        parent_evidence,
        host_contract_evidence,
    )
    input_snapshots["parent"] = parent_snapshot
    for branch in ("constant", "zero"):
        posterior = propagation_evidence["canonical"][branch]["posterior_artifact"]
        if posterior_paths[branch].sha256 != posterior["sha256"]:
            raise RuntimeError(f"{branch} aggregate posterior is not the propagation input")
        input_snapshots[f"{branch}_full_posterior_samples"] = full_posterior_paths[
            branch
        ]
        input_snapshots[f"{branch}_posterior_samples"] = posterior_paths[branch]
    for selector in ("canonical", "legacy"):
        host_record = propagation_evidence[selector]["constant"]["host_artifact"]
        input_snapshots[f"{selector}_hosts"] = read_file_snapshot(
            host_paths[selector], f"{selector} host freeze input"
        )
        if input_snapshots[f"{selector}_hosts"].sha256 != host_record["sha256"]:
            raise RuntimeError(f"{selector} hosts changed after propagation validation")

    gates: dict[str, Any] = {}
    for branch in ("constant", "zero"):
        stability, stability_snapshots, stability_root_evidence = (
            validate_seed_stability_artifact_root(
                getattr(args, f"{branch}_seed_stability_root"), branch
            )
        )
        aggregate_gate = validate_aggregate(branch, aggregates[branch])
        posterior_artifact_gate, full_frame = validate_aggregate_posterior_artifacts(
            branch,
            aggregates[branch],
            full_posterior_paths[branch],
            posterior_paths[branch],
        )
        diagnostics_gate = validate_aggregate_diagnostics_artifact(
            branch,
            aggregates[branch],
            diagnostics_paths[branch],
            full_frame,
        )
        perturbation_audit_gate, _perturbation_audit = (
            validate_aggregate_perturbation_audit(
                branch,
                perturbation_audit_paths[branch],
                diagnostics_paths[branch],
            )
        )
        correlation_gate = validate_aggregate_correlation_artifact(
            branch,
            aggregates[branch],
            correlation_paths[branch],
            full_frame,
        )
        likelihood_report, likelihood_root_evidence = validate_likelihood_grid_root(
            getattr(args, f"{branch}_likelihood_grid_root"),
            branch=branch,
            full_snapshot=full_posterior_paths[branch],
            aggregate_manifest_snapshot=aggregate_manifest_paths[branch],
            rate_model_source_snapshot=rate_model_source_snapshot,
            completeness_snapshot=completeness_snapshots[branch],
        )
        catalog_replay, catalog_replay_evidence = (
            validate_catalog_perturbation_replay(
                branch=branch,
                aggregate_root=getattr(args, f"{branch}_aggregate_root"),
                perturbation_audit_snapshot=perturbation_audit_paths[branch],
                diagnostics_snapshot=diagnostics_paths[branch],
                pc_catalog_snapshot=catalog_snapshots["pc_catalog"],
                stellar_catalog_snapshot=catalog_snapshots["stellar_catalog"],
                data_locks_snapshot=catalog_snapshots["data_locks"],
            )
        )
        gates[branch] = {
            "aggregate": aggregate_gate,
            "aggregate_posterior_artifacts": posterior_artifact_gate,
            "aggregate_diagnostics_artifact": diagnostics_gate,
            "aggregate_perturbation_audit": perturbation_audit_gate,
            "catalog_perturbation_replay": {
                "status": catalog_replay["status"],
                "audit_id": catalog_replay["audit_id"],
                "trials_verified": catalog_replay["trials_verified"],
                "audit_rows_verified": catalog_replay["audit_rows_verified"],
                "exact_catalog_replay": True,
            },
            "aggregate_correlation_artifact": correlation_gate,
            "canonical_galactic": propagation_evidence["canonical"][branch]["mcse"],
            "legacy_galactic": propagation_evidence["legacy"][branch]["mcse"],
            "seed_stability": validate_seed_stability(
                branch, stability, stability_snapshots
            ),
            "likelihood_grid_convergence": {
                "status": likelihood_report["status"],
                "selected_points": likelihood_report["selected_points"],
                "results": likelihood_report["results"],
            },
        }
        aggregate_root_evidence[branch]["seed_stability"] = stability_root_evidence
        aggregate_root_evidence[branch]["likelihood_grid_convergence"] = (
            likelihood_root_evidence
        )
        aggregate_root_evidence[branch]["catalog_perturbation_replay"] = (
            catalog_replay_evidence
        )

    host, host_snapshot = load_json_snapshot(args.host_summary, "JJ host summary")
    input_snapshots["host_summary"] = host_snapshot
    if host_snapshot.sha256 != contract_host_summary_snapshot.sha256:
        raise RuntimeError("JJ host summary is not the contract-accepted summary")
    host_count = _require_finite_nonnegative(
        host.get("N_G_hosts_age_ge_4p57_R7_9"), "JJ host count"
    )
    if abs(host_count - 263061992.36674237) > 0.1:
        raise RuntimeError("Frozen JJ host count mismatch")
    if not isinstance(host.get("host_provider_id"), str) or not host["host_provider_id"]:
        raise RuntimeError("JJ host provider id is missing")
    convergence, convergence_root_evidence = validate_tams_radial_convergence_root(
        args.tams_convergence_root
    )
    radial_ssp_evidence = verify_radial_ssp_contract_binding(
        args.radial_ssp_contract,
        args.radial_ssp_qualification_report,
        args.tams_convergence_root,
        expected_contract_sha256=args.expected_radial_ssp_contract_sha256,
        expected_contract_size_bytes=args.expected_radial_ssp_contract_size_bytes,
        expected_qualification_report_sha256=(
            args.expected_radial_ssp_qualification_report_sha256
        ),
        expected_qualification_report_size_bytes=(
            args.expected_radial_ssp_qualification_report_size_bytes
        ),
        expected_computational_source=computational_sources["local"],
    )
    radial_report_document = load_json_bytes(
        external_snapshots["external radial SSP qualification report"].data,
        "external radial SSP qualification report",
    )
    computational_sources["radial"] = radial_qualification_source_identity(
        radial_report_document
    )
    if radial_ssp_evidence.get("computational_source") != computational_sources[
        "radial"
    ]:
        raise RuntimeError(
            "radial binding returned a computational source different from its signed report"
        )
    radial_ssp_evidence.update(
        {
            **external_pairs["radial"],
            "computational_source": dict(computational_sources["radial"]),
        }
    )
    computational_source = require_identical_computational_source(
        computational_sources
    )
    canonical_host_count = float(
        propagation_evidence["canonical"]["constant"]["host_count"]
    )
    if abs(host_count - canonical_host_count) > 0.1:
        raise RuntimeError("Canonical host summary and fresh propagation disagree")
    postconsumption_attestation = verify_attested_output_roots(
        args.local_run_output_root, attested_roots, signed_output_files
    )
    if postconsumption_attestation != preconsumption_attestation:
        raise RuntimeError("Signed production artifacts changed while being consumed")
    local_run_evidence["consumed_output_recheck"] = postconsumption_attestation
    recheck_external_evidence_locks(external_snapshots)
    freeze = {
        "status": "PASS",
        "scope": (
            "Corrected Bryson occurrence posterior and conditional Galactic "
            "propagation; constant and zero completeness remain separate scenarios."
        ),
        "computational_source": computational_source,
        "external_post_qualification_evidence": external_pairs,
        "inputs": {
            name: {
                "path": str(snapshot.path),
                "sha256": snapshot.sha256,
                "size_bytes": snapshot.size_bytes,
            }
            for name, snapshot in input_snapshots.items()
        },
        "propagation_artifact_roots": {
            f"{selector}_{branch}": propagation_evidence[selector][branch]
            for selector in ("canonical", "legacy")
            for branch in ("constant", "zero")
        },
        "artifact_roots": {
            "accepted_aggregates": aggregate_root_evidence,
            "host_tams_audit": host_tams_root_evidence,
            "metallicity_tams_audit": metallicity_evidence,
            "host_artifact_contract": host_contract_evidence,
            "tams_radial_convergence": convergence_root_evidence,
            "radial_ssp_qualification": radial_ssp_evidence,
            "signed_local_production_run": local_run_evidence,
        },
        "gates": gates,
        "fresh_host_selector_propagation": propagation_evidence,
        "host_model": {
            "N_star_7_9_kpc": host_count,
            "provider": host["host_provider_id"],
            "tams_radial_convergence": "PASS",
            "radial_ssp_private_rederivation": "PASS",
            "metallicity_dependent_tams_role": (
                "NOT_APPLIED_OPEN_SYSTEMATIC: the independently verified "
                "metallicity correction is not publishable and is excluded"
            ),
            "metallicity_dependent_tams_audit": metallicity_report,
            "metallicity_correction_applied": False,
            "native_solar_selector_without_5200_anchor_fractional_change_vs_canonical": (
                host_tams_audit["low_temperature_anchor_dependence"]
                ["native_selector_fractional_change_vs_canonical"]
            ),
        },
        "posterior_parameters": {
            branch: aggregates[branch]["posterior_quantiles"]
            for branch in ("constant", "zero")
        },
        "galactic_propagation_posterior_parameters": {
            branch: aggregates[branch][
                "galactic_propagation_posterior_quantiles"
            ]
            for branch in ("constant", "zero")
        },
        "galactic_results": {
            selector: {
                branch: propagation_summaries[(selector, branch)][
                    "posterior_quantiles"
                ]
                for branch in ("constant", "zero")
            }
            for selector in ("canonical", "legacy")
        },
    }
    freeze = release_safe_evidence(freeze)
    out.mkdir(parents=True, exist_ok=True)
    freeze_path = out / "V4_NUMERICAL_FREEZE.json"
    with freeze_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(freeze, handle, indent=2, allow_nan=False)
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
                values = propagation_summaries[("canonical", branch)][
                    "posterior_quantiles"
                ][quantity]
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
    freeze_targets = (
        freeze_path,
        out / "v4_parameter_quantiles.csv",
        out / "v4_galactic_quantiles.csv",
        out / "V4_NUMERICAL_FREEZE.md",
    )
    (out / NUMERICAL_FREEZE_MANIFEST_NAME).write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in freeze_targets),
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(freeze, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
