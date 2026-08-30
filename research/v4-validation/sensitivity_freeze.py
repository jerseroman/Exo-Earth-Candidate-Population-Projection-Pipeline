#!/usr/bin/env python3
"""Freeze audited v4 numerical sensitivities without combining unlike risks."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from host_tams_audit import (
    EXPECTED_HOST_STATUS,
    FileSnapshot,
    METALLICITY_REPORT_NAME,
    RETRACTED_METALLICITY_ANCHOR_NAME,
    _require_exact_bool,
    _require_finite_nonnegative,
    _require_finite_number,
    _require_integer,
    _require_mapping,
    _load_python_module_from_snapshot,
    _snapshot_exact_manifest_root,
    load_json_bytes,
    load_json_snapshot,
    read_file_snapshot,
    release_safe_evidence,
    require_host_rows_equal_parent,
    validate_fresh_propagation_summary,
    validate_fresh_propagation_set,
    validate_host_artifact,
    validate_parent_artifact,
    validate_posterior_artifact,
    validate_tams_radial_convergence,
    validate_tams_radial_convergence_root,
    verify_attested_output_roots,
    verify_host_artifact_contract_binding,
    verify_local_run_attestation_binding,
    verify_metallicity_audit_root,
    verify_radial_ssp_contract_binding,
)


HOST_AUDIT_NAME = "host_tams_audit.json"
HOST_SELECTOR_TABLE_NAME = "host_selector_sensitivity.csv"
HOST_AUDIT_MANIFEST_NAME = "SHA256SUMS_host_tams_audit.txt"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
HOST_START_CHALLENGE_NAME = "HOST_RUN_START_CHALLENGE.json"
SENSITIVITY_MANIFEST_NAME = "SHA256SUMS_sensitivity_artifacts.txt"
RUN_PROVENANCE_NAME = "RUN_PROVENANCE.json"
SENSITIVITY_ARTIFACT_NAMES = (
    "bryson_model_form_sensitivity.json",
    "hz_sensitivity_results.json",
    "tams_all_branch_results.json",
    RUN_PROVENANCE_NAME,
)
DR25_PUBLIC_MANIFEST_NAME = "SHA256SUMS_dr25_support_public.txt"
DR25_PUBLIC_FILES = ("dr25_support_audit.json", "dr25_target_counts_by_trial.csv")
EXPECTED_PRODUCTION_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production"
)
EXPECTED_PRODUCTION_REPOSITORY_ID = 1_342_924_728
EXPECTED_PRODUCTION_WORKFLOW_PATH = ".github/workflows/jj-g-host-export.yml"
EXPECTED_PRODUCTION_WORKFLOW_REF = (
    f"{EXPECTED_PRODUCTION_REPOSITORY}/{EXPECTED_PRODUCTION_WORKFLOW_PATH}"
    "@refs/heads/main"
)
EXPECTED_PRODUCTION_ARTIFACT_NAME = "jj-g-host-export-padova-dr05-tams-canonical"
EXPECTED_RELEASE_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
)
EXPECTED_RELEASE_REPOSITORY_ID = 1_343_894_071


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
        if reference != {
            "report_id": report_id,
            "sha256": report_snapshot.sha256,
            "size_bytes": report_snapshot.size_bytes,
        }:
            raise RuntimeError("local public report differs from its accepted contract lock")
    else:
        reference = candidate.get("qualification_report")
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise RuntimeError(f"{role} qualification-report lock schema changed")
        report_name = _safe_report_leaf(
            reference.get("path"), f"{role} qualification-report path"
        )
        if report_snapshot.path != (
            contract_snapshot.path.parent / report_name
        ).resolve():
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
        embedded = _require_mapping(
            _require_mapping(repetition, f"host repetition {index}").get(
                "embedded_signed_evidence"
            ),
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
    if {
        "commit": report.get("source_commit"),
        "tree": report.get("source_tree"),
        "archive_sha256": report.get("source_archive_sha256"),
        "archive_size_bytes": report.get("source_archive_size_bytes"),
    } != identity:
        raise RuntimeError("local public report differs from its exact source lock")
    return identity


def host_source_lock_from_local_contract(
    contract: dict[str, Any], computational_source: dict[str, Any]
) -> dict[str, Any]:
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


def _load_repository_module_bytes(
    path: Path,
    *,
    module_name: str,
) -> tuple[ModuleType, FileSnapshot]:
    """Execute one stable source snapshot while preserving its repository path."""

    snapshot = read_file_snapshot(path, f"stable Python module {module_name}")
    module = ModuleType(module_name)
    module.__file__ = str(Path(path).resolve())
    module.__package__ = ""
    module.__dict__["__builtins__"] = __builtins__
    code = compile(snapshot.data, module.__file__, "exec", dont_inherit=True)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        raise
    return module, snapshot


def fractional_change(comparison: float, reference: float) -> float:
    comparison_value = _require_finite_number(comparison, "fractional-change comparison")
    reference_value = _require_finite_number(reference, "fractional-change reference")
    if reference_value == 0.0:
        raise ValueError("Cannot form a fractional change from a zero reference")
    return comparison_value / reference_value - 1.0


def require_close(name: str, value: float, reference: float, tolerance: float) -> None:
    actual = _require_finite_number(value, name)
    expected = _require_finite_number(reference, f"{name} reference")
    maximum = _require_finite_number(tolerance, f"{name} tolerance")
    if maximum < 0.0:
        raise RuntimeError(f"{name} tolerance must be non-negative")
    if abs(actual - expected) > maximum:
        raise RuntimeError(f"{name} mismatch: {actual} versus {expected}")


def validated_radial_delta(record: dict[str, Any]) -> tuple[float, float, float]:
    radial_comparison = _require_mapping(
        record.get("Lambda_earth10"), "TAMS Lambda_EE convergence"
    )
    coarse = _require_finite_nonnegative(
        radial_comparison.get("coarse"), "coarse Lambda_EE"
    )
    fine = _require_finite_nonnegative(radial_comparison.get("fine"), "fine Lambda_EE")
    if fine == 0.0:
        raise RuntimeError("Fine-grid Lambda_EE must be positive")
    radial_delta = _require_finite_number(
        radial_comparison.get("delta_fraction"), "TAMS radial Lambda_EE delta"
    )
    if not math.isclose(
        radial_delta,
        (fine - coarse) / fine,
        rel_tol=1.0e-12,
        abs_tol=1.0e-12,
    ) or abs(radial_delta) >= 0.01:
        raise RuntimeError("TAMS radial Lambda_EE convergence fields are inconsistent")
    return coarse, fine, radial_delta


def validate_artifact_manifest(
    manifest_path: Path, artifact_root: Path, required_names: set[str]
) -> tuple[dict[str, FileSnapshot], FileSnapshot]:
    root_arg = Path(artifact_root)
    if root_arg.is_symlink():
        raise RuntimeError("Sensitivity artifact root must not be a symlink")
    root = root_arg.resolve()
    expected_manifest = root / SENSITIVITY_MANIFEST_NAME
    if Path(manifest_path).resolve() != expected_manifest:
        raise RuntimeError(
            f"Sensitivity manifest must be the direct artifact-root file "
            f"{SENSITIVITY_MANIFEST_NAME}"
        )
    if set(required_names) != set(SENSITIVITY_ARTIFACT_NAMES):
        raise RuntimeError("Sensitivity artifact target set changed")
    return _snapshot_exact_manifest_root(
        root_arg,
        manifest_name=SENSITIVITY_MANIFEST_NAME,
        target_names=SENSITIVITY_ARTIFACT_NAMES,
        label="sensitivity artifacts",
    )


def validate_host_tams_root(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root_arg = Path(root)
    artifact_root = root_arg.resolve()
    if root_arg.is_symlink() or not artifact_root.is_dir():
        raise RuntimeError(f"Host/TAMS artifact root is not a directory: {artifact_root}")
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        root_arg,
        manifest_name=HOST_AUDIT_MANIFEST_NAME,
        target_names=(HOST_AUDIT_NAME, HOST_SELECTOR_TABLE_NAME),
        label="host/TAMS audit",
    )
    manifest_path = artifact_root / HOST_AUDIT_MANIFEST_NAME
    host = load_json_bytes(snapshots[HOST_AUDIT_NAME].data, "host/TAMS audit")
    if RETRACTED_METALLICITY_ANCHOR_NAME.encode("utf-8") in snapshots[
        HOST_AUDIT_NAME
    ].data:
        raise RuntimeError("Host/TAMS audit references the retracted metallicity anchor")
    if host.get("status") != EXPECTED_HOST_STATUS:
        raise RuntimeError(f"Host/TAMS status must be exactly {EXPECTED_HOST_STATUS}")
    return host, {
        "artifact_root": str(artifact_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
    }


def _git_checkout_evidence(checkout: Path, label: str) -> dict[str, Any]:
    root_arg = Path(checkout)
    if root_arg.is_symlink() or not root_arg.is_dir():
        raise RuntimeError(f"{label} checkout must be a non-symlink directory")
    root = root_arg.resolve()

    def git(*arguments: str) -> bytes:
        process = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            message = process.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Cannot inspect {label} checkout: {message}")
        return process.stdout

    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError(f"{label} checkout is not clean")
    head = git("rev-parse", "HEAD").decode("ascii").strip()
    tree = git("rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        raise RuntimeError(f"{label} checkout does not use 40-hex Git objects")
    tree_listing = git("ls-tree", "-r", "-z", "--full-tree", tree)
    if not tree_listing:
        raise RuntimeError(f"{label} Git tree is empty")
    archive = git("archive", "--format=tar", "HEAD")
    if not archive:
        raise RuntimeError(f"{label} source archive is empty")
    return {
        "checkout": root,
        "head_sha": head,
        "tree_sha": tree,
        "tree_sha256": hashlib.sha256(tree_listing).hexdigest(),
        "source_archive_sha256": hashlib.sha256(archive).hexdigest(),
    }


def _verify_exact_output_manifest(path: Path) -> tuple[FileSnapshot, dict[str, Any]]:
    manifest_snapshot = read_file_snapshot(path, "production output manifest")
    try:
        lines = manifest_snapshot.data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Production output manifest is not UTF-8") from error
    if not lines:
        raise RuntimeError("Production output manifest is empty")
    names: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None:
            raise RuntimeError(
                f"Malformed production output-manifest line {line_number}: {line!r}"
            )
        names.append(match.group(2))
    if len(names) != len(set(names)) or Path(path).name in names:
        raise RuntimeError("Production output manifest has duplicate/self targets")
    snapshots, stable_manifest = _snapshot_exact_manifest_root(
        Path(path).parent,
        manifest_name=Path(path).name,
        target_names=tuple(names),
        label="production output artifact",
    )
    if stable_manifest.sha256 != manifest_snapshot.sha256:
        raise RuntimeError("Production output manifest changed while it was verified")
    return stable_manifest, {
        "filename": stable_manifest.path.name,
        "sha256": stable_manifest.sha256,
        "size_bytes": stable_manifest.size_bytes,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
    }


def _verify_runtime_manifest(path: Path) -> tuple[FileSnapshot, dict[str, Any]]:
    snapshot = read_file_snapshot(path, "numerical runtime manifest")
    report = load_json_bytes(snapshot.data, "numerical runtime manifest")
    expected_keys = {
        "schema_version",
        "status",
        "python",
        "python_executable",
        "platform",
        "machine",
        "numpy_version",
        "numpy_cpu_baseline",
        "numpy_cpu_dispatch_build",
        "selected_cpu_features",
        "environment",
    }
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise RuntimeError("Numerical runtime-manifest schema changed")
    repository_root = Path(__file__).resolve().parents[2]
    verifier, verifier_snapshot = _load_python_module_from_snapshot(
        repository_root / "scripts" / "verify_numerical_runtime.py",
        module_name="_sensitivity_verify_numerical_runtime",
        label="numerical runtime verifier",
    )
    if report.get("schema_version") != 1 or report.get("status") != "PASS":
        raise RuntimeError("Numerical runtime manifest did not pass")
    if report.get("numpy_version") != verifier.EXPECTED_NUMPY_VERSION:
        raise RuntimeError("Numerical runtime NumPy version changed")
    verifier.validate_environment(_require_mapping(report.get("environment"), "runtime env"))
    verifier.validate_cpu_features(
        _require_mapping(report.get("selected_cpu_features"), "runtime CPU features")
    )
    for key in (
        "python",
        "python_executable",
        "platform",
        "machine",
    ):
        if not isinstance(report.get(key), str) or not report[key]:
            raise RuntimeError(f"Numerical runtime field is missing: {key}")
    for key in ("numpy_cpu_baseline", "numpy_cpu_dispatch_build"):
        values = report.get(key)
        if not isinstance(values, list) or not all(
            isinstance(value, str) and value for value in values
        ):
            raise RuntimeError(f"Numerical runtime field is malformed: {key}")
    return snapshot, {
        "filename": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "verifier_sha256": verifier_snapshot.sha256,
    }


def validate_run_provenance(
    snapshot: FileSnapshot,
    *,
    execution_mode: str,
    production_checkout: Path,
    release_checkout: Path,
    source_archive: Path | None = None,
    os_runtime_manifest: Path | None = None,
    command_plan: Path | None = None,
    production_artifact: Path | None = None,
    production_run_id: int | None = None,
    production_run_attempt: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    record = load_json_bytes(snapshot.data, "sensitivity RUN_PROVENANCE.json")
    if set(record) != {
        "schema_version",
        "execution_mode",
        "production",
        "release",
        "conclusion",
        "maximum_mcmc_steps",
    }:
        raise RuntimeError("Sensitivity run-provenance schema changed")
    production_git = _git_checkout_evidence(production_checkout, "production")
    release_git = _git_checkout_evidence(release_checkout, "release")
    if (
        production_git["tree_sha"] != release_git["tree_sha"]
        or production_git["tree_sha256"] != release_git["tree_sha256"]
    ):
        raise RuntimeError("Production and public release trees are not content-identical")
    release = {
        "repository": EXPECTED_RELEASE_REPOSITORY,
        "repository_id": EXPECTED_RELEASE_REPOSITORY_ID,
        "head_sha": release_git["head_sha"],
        "tree_sha": release_git["tree_sha"],
        "tree_sha256": release_git["tree_sha256"],
    }
    if execution_mode == "local_ubuntu_22_04_wsl2":
        if source_archive is None or os_runtime_manifest is None or command_plan is None:
            raise RuntimeError("Local provenance requires archive, runtime, and command-plan files")
        if production_artifact is not None or any(
            value is not None for value in (production_run_id, production_run_attempt)
        ):
            raise RuntimeError("Local provenance must not claim GitHub Actions fields")
        source_archive_snapshot = read_file_snapshot(source_archive, "production source archive")
        if source_archive_snapshot.sha256 != production_git["source_archive_sha256"]:
            raise RuntimeError("Production source archive is not exact `git archive HEAD` bytes")
        runtime_snapshot, runtime_evidence = _verify_runtime_manifest(os_runtime_manifest)
        command_plan_snapshot = read_file_snapshot(
            command_plan, "signed local production command plan"
        )
        production = {
            "repository": EXPECTED_PRODUCTION_REPOSITORY,
            "repository_id": EXPECTED_PRODUCTION_REPOSITORY_ID,
            "private_commit": production_git["head_sha"],
            "tree_sha": production_git["tree_sha"],
            "tree_sha256": production_git["tree_sha256"],
            "source_archive_sha256": source_archive_snapshot.sha256,
            "os_runtime_manifest_sha256": runtime_snapshot.sha256,
            "command_plan_sha256": command_plan_snapshot.sha256,
            "artifact_name": EXPECTED_PRODUCTION_ARTIFACT_NAME,
        }
        mode_evidence = {
            "source_archive": {
                "filename": source_archive_snapshot.path.name,
                "sha256": source_archive_snapshot.sha256,
                "size_bytes": source_archive_snapshot.size_bytes,
            },
            "os_runtime_manifest": runtime_evidence,
            "command_plan": {
                "filename": command_plan_snapshot.path.name,
                "sha256": command_plan_snapshot.sha256,
                "size_bytes": command_plan_snapshot.size_bytes,
            },
        }
    elif execution_mode == "github_actions":
        if (
            isinstance(production_run_id, bool)
            or not isinstance(production_run_id, int)
            or production_run_id <= 0
            or isinstance(production_run_attempt, bool)
            or not isinstance(production_run_attempt, int)
            or production_run_attempt <= 0
        ):
            raise RuntimeError("Production run id and attempt must be positive integers")
        if any(value is not None for value in (source_archive, os_runtime_manifest, command_plan)):
            raise RuntimeError("GitHub Actions provenance must not claim local-run fields")
        if production_artifact is None:
            raise RuntimeError("GitHub Actions provenance requires the downloaded artifact")
        artifact_snapshot = read_file_snapshot(production_artifact, "GitHub Actions artifact")
        artifact_digest = f"sha256:{artifact_snapshot.sha256}"
        production = {
            "repository": EXPECTED_PRODUCTION_REPOSITORY,
            "repository_id": EXPECTED_PRODUCTION_REPOSITORY_ID,
            "workflow_path": EXPECTED_PRODUCTION_WORKFLOW_PATH,
            "workflow_ref": EXPECTED_PRODUCTION_WORKFLOW_REF,
            "workflow_sha": production_git["head_sha"],
            "head_sha": production_git["head_sha"],
            "tree_sha": production_git["tree_sha"],
            "tree_sha256": production_git["tree_sha256"],
            "run_id": production_run_id,
            "run_attempt": production_run_attempt,
            "artifact_name": EXPECTED_PRODUCTION_ARTIFACT_NAME,
            "upstream_artifact_digest": artifact_digest,
        }
        mode_evidence = {
            "downloaded_artifact": {
                "filename": artifact_snapshot.path.name,
                "sha256": artifact_snapshot.sha256,
                "size_bytes": artifact_snapshot.size_bytes,
            }
        }
    else:
        raise RuntimeError("Unknown sensitivity execution mode")
    expected = {
        "schema_version": 4 if execution_mode == "local_ubuntu_22_04_wsl2" else 3,
        "execution_mode": execution_mode,
        "production": production,
        "release": release,
        "conclusion": "success",
        "maximum_mcmc_steps": None,
    }
    if record != expected:
        raise RuntimeError("Sensitivity run provenance does not match the requested run")
    return record, {
        "filename": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "production_git": {
            key: value for key, value in production_git.items() if key != "checkout"
        },
        "release_git": {
            key: value for key, value in release_git.items() if key != "checkout"
        },
        **mode_evidence,
    }


def cross_check_host_tams_audit(
    host: dict[str, Any],
    propagation_roots: dict[tuple[str, str], Path],
    propagation_evidence: dict[str, Any],
    metallicity_report: dict[str, Any],
    metallicity_evidence: dict[str, Any],
    parent_evidence: dict[str, Any],
    host_contract_evidence: dict[str, Any],
) -> None:
    """Bind sensitivity inputs to the independently reconstructed host audit."""

    host_inputs = _require_mapping(host.get("inputs"), "host/TAMS inputs")
    audited_contract = _require_mapping(
        host_inputs.get("host_artifact_contract"),
        "host/TAMS host-artifact contract",
    )
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
    names = {
        ("canonical", "constant"): "canonical_constant",
        ("canonical", "zero"): "canonical_zero",
        ("legacy", "constant"): "legacy_constant",
        ("legacy", "zero"): "legacy_zero",
    }
    for (selector, branch), name in names.items():
        record = _require_mapping(host_inputs.get(name), f"host/TAMS input {name}")
        current = propagation_evidence[selector][branch]
        if record.get("sha256") != current["summary_sha256"]:
            raise RuntimeError(f"Host/TAMS propagation summary mismatch: {name}")
        if record.get("manifest_sha256") != current["manifest_sha256"]:
            raise RuntimeError(f"Host/TAMS propagation manifest mismatch: {name}")

    for branch in ("constant", "zero"):
        record = _require_mapping(
            host_inputs.get(f"{branch}_posterior_samples"),
            f"host/TAMS {branch} posterior input",
        )
        current = propagation_evidence["canonical"][branch]["posterior_artifact"]
        for key in ("sha256", "size_bytes", "row_count"):
            if record.get(key) != current.get(key):
                raise RuntimeError(f"Host/TAMS posterior mismatch: {branch}:{key}")
    for selector in ("canonical", "legacy"):
        record = _require_mapping(
            host_inputs.get(f"{selector}_hosts"), f"host/TAMS {selector} hosts"
        )
        current = propagation_evidence[selector]["constant"]["host_artifact"]
        for key in ("sha256", "size_bytes", "row_count"):
            if record.get(key) != current.get(key):
                raise RuntimeError(f"Host/TAMS host-row mismatch: {selector}:{key}")

    parent_record = _require_mapping(host_inputs.get("parent"), "host/TAMS parent input")
    for key in ("filename", "sha256", "size_bytes", "row_count"):
        if parent_record.get(key) != parent_evidence.get(key):
            raise RuntimeError(f"Host/TAMS parent mismatch: {key}")
    for key in ("feh_min", "feh_max"):
        if not math.isclose(
            _require_finite_number(parent_record.get(key), f"host/TAMS parent {key}"),
            _require_finite_number(parent_evidence.get(key), f"current parent {key}"),
            rel_tol=0.0,
            abs_tol=1.0e-12,
        ):
            raise RuntimeError(f"Host/TAMS parent mismatch: {key}")

    verified_metallicity = _require_mapping(
        host.get("verified_metallicity_artifact"),
        "host/TAMS metallicity evidence",
    )
    for key in ("report_sha256", "native_solar_tams_points_sha256"):
        if verified_metallicity.get(key) != metallicity_evidence.get(key):
            raise RuntimeError(f"Host/TAMS metallicity cross-hash mismatch: {key}")
    if host.get("metallicity_dependent_TAMS_audit") != metallicity_report:
        raise RuntimeError("Host/TAMS metallicity report is not current")
    derived = _require_mapping(
        host.get("derived_collapsed_host_measures"),
        "host/TAMS derived host measures",
    )
    if set(derived) != {"canonical", "legacy"}:
        raise RuntimeError("Host/TAMS derived selector set changed")
    for selector in ("canonical", "legacy"):
        record = _require_mapping(derived.get(selector), f"derived {selector} host measure")
        current = propagation_evidence[selector]["constant"]
        if (
            record.get("csv_sha256") != current["collapsed_host_sha256"]
            or _require_integer(record.get("row_count"), f"derived {selector} rows")
            != current["distinct_host_temperatures"]
            or not math.isclose(
                _require_finite_number(record.get("N_star"), f"derived {selector} N_star"),
                _require_finite_number(current["host_count"], f"current {selector} N_star"),
                rel_tol=0.0,
                abs_tol=0.1,
            )
        ):
            raise RuntimeError(f"Host/TAMS derived host measure changed for {selector}")


def validate_dr25_local_support(data: dict[str, Any]) -> dict[str, Any]:
    """Require the numerical evidence supporting the sparse-local-support finding."""

    if data.get("status") != "FAIL_LOCAL_EMPIRICAL_SUPPORT":
        raise RuntimeError("DR25 local-support finding changed unexpectedly")
    nominal = _require_mapping(data.get("nominal_support"), "DR25 nominal support")
    target = _require_mapping(
        nominal.get("earth_analog_target"), "DR25 nominal Earth-analog target"
    )
    if _require_integer(target.get("candidate_count"), "DR25 nominal candidate count") != 0:
        raise RuntimeError("DR25 nominal Earth-analog candidate count is not zero")
    corrected = _require_mapping(
        data.get("corrected_measurement_realizations"),
        "DR25 corrected measurement realizations",
    )
    if set(corrected) != {"constant", "zero"}:
        raise RuntimeError("DR25 corrected branch set changed")
    evidence: dict[str, Any] = {}
    for branch in ("constant", "zero"):
        record = _require_mapping(corrected[branch], f"DR25 corrected {branch}")
        if _require_integer(
            record.get("realization_count"), f"DR25 {branch} realization count"
        ) != 400:
            raise RuntimeError(f"DR25 {branch} does not contain 400 realizations")
        counts = _require_mapping(
            record.get("earth_analog_target_candidates"),
            f"DR25 {branch} Earth-analog counts",
        )
        quantiles = _require_mapping(
            counts.get("quantiles"), f"DR25 {branch} Earth-analog quantiles"
        )
        q50 = _require_finite_number(quantiles.get("q50"), f"DR25 {branch} q50")
        fraction_zero = _require_finite_number(
            counts.get("fraction_zero"), f"DR25 {branch} zero fraction"
        )
        if q50 != 0.0 or not 0.95 < fraction_zero <= 1.0:
            raise RuntimeError(f"DR25 {branch} sparse-support evidence changed")
        evidence[branch] = {
            "realization_count": 400,
            "q50": q50,
            "fraction_zero": fraction_zero,
        }
    return {"nominal_candidate_count": 0, "corrected": evidence}


def verify_sensitivity_rederivation(
    artifact_snapshots: dict[str, FileSnapshot],
    *,
    parent_snapshot: FileSnapshot,
    canonical_hosts_snapshot: FileSnapshot,
) -> dict[str, Any]:
    """Re-run every accepted scientific sensitivity from its exact raw table bytes."""

    repository_root = Path(__file__).resolve().parents[2]
    source_root = repository_root / "research" / "jj-host-export"
    jobs = (
        (
            "recalc_all_branches_tams.py",
            "tams_all_branch_results.json",
            parent_snapshot,
        ),
        (
            "hz_boundary_sensitivity.py",
            "hz_sensitivity_results.json",
            canonical_hosts_snapshot,
        ),
        (
            "bryson_model_form_sensitivity.py",
            "bryson_model_form_sensitivity.json",
            canonical_hosts_snapshot,
        ),
    )
    expected_names = {output_name for _, output_name, _ in jobs}
    if not expected_names.issubset(artifact_snapshots):
        raise RuntimeError("Sensitivity artifact set lacks a rederivable scientific JSON")
    evidence: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="sensitivity-rederive-") as temporary:
        stable_root = Path(temporary)
        for index, (source_name, output_name, input_snapshot) in enumerate(jobs):
            source_snapshot = read_file_snapshot(
                source_root / source_name, f"sensitivity producer {source_name}"
            )
            job_root = stable_root / f"job-{index}"
            job_root.mkdir()
            stable_source = job_root / source_name
            stable_input = job_root / input_snapshot.path.name
            output_root = job_root / "output"
            stable_source.write_bytes(source_snapshot.data)
            stable_input.write_bytes(input_snapshot.data)
            process = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(stable_source),
                    "--input",
                    str(stable_input),
                    "--out",
                    str(output_root),
                ],
                cwd=job_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if process.returncode != 0:
                message = process.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"Sensitivity rederivation failed for {output_name}: {message}"
                )
            derived_snapshot = read_file_snapshot(
                output_root / output_name, f"rederived {output_name}"
            )
            derived = load_json_bytes(derived_snapshot.data, f"rederived {output_name}")
            declared = load_json_bytes(
                artifact_snapshots[output_name].data, f"declared {output_name}"
            )
            if derived != declared:
                raise RuntimeError(
                    f"Sensitivity artifact is not exactly rederived from raw inputs: {output_name}"
                )
            evidence[output_name] = {
                "producer": source_name,
                "producer_sha256": source_snapshot.sha256,
                "raw_input_filename": input_snapshot.path.name,
                "raw_input_sha256": input_snapshot.sha256,
                "declared_sha256": artifact_snapshots[output_name].sha256,
                "rederived_sha256": derived_snapshot.sha256,
                "exact_json_match": True,
            }
    return evidence


def verify_aggregate_audits_for_dr25(
    aggregate_roots: dict[str, Path],
    *,
    pc_catalog: Path,
    stellar_catalog: Path,
) -> tuple[dict[str, FileSnapshot], dict[str, Any]]:
    """Bind DR25 to the semantically verified accepted perturbation audits."""

    repository_root = Path(__file__).resolve().parents[2]
    bryson_root = repository_root / "research" / "bryson-joint-posterior"
    if str(bryson_root) not in sys.path:
        sys.path.insert(0, str(bryson_root))
    module, module_snapshot = _load_python_module_from_snapshot(
        bryson_root / "freeze_v4_numerical_results.py",
        module_name="_sensitivity_accepted_aggregate_verifier",
        label="accepted aggregate semantic verifier",
    )
    pc_snapshot = read_file_snapshot(pc_catalog, "locked DR25 PC catalog")
    stellar_snapshot = read_file_snapshot(
        stellar_catalog, "locked DR25 stellar catalog"
    )
    data_locks_snapshot = read_file_snapshot(
        repository_root / "provenance" / "DATA_LOCKS.json",
        "scientific data-lock registry",
    )
    audit_snapshots: dict[str, FileSnapshot] = {}
    evidence: dict[str, Any] = {"verifier_sha256": module_snapshot.sha256, "branches": {}}
    for branch in ("constant", "zero"):
        aggregate, root_evidence, snapshots = module.validate_aggregate_artifact_root(
            aggregate_roots[branch], branch
        )
        module.validate_aggregate(branch, aggregate)
        posterior_gate, full = module.validate_aggregate_posterior_artifacts(
            branch,
            aggregate,
            snapshots["full"],
            snapshots["propagation"],
        )
        diagnostics_gate = module.validate_aggregate_diagnostics_artifact(
            branch,
            aggregate,
            snapshots["diagnostics"],
            full,
        )
        audit_gate, _audit = module.validate_aggregate_perturbation_audit(
            branch,
            snapshots["perturbation_audit"],
            snapshots["diagnostics"],
        )
        catalog_replay, catalog_replay_evidence = (
            module.validate_catalog_perturbation_replay(
                branch=branch,
                aggregate_root=aggregate_roots[branch],
                perturbation_audit_snapshot=snapshots["perturbation_audit"],
                diagnostics_snapshot=snapshots["diagnostics"],
                pc_catalog_snapshot=pc_snapshot,
                stellar_catalog_snapshot=stellar_snapshot,
                data_locks_snapshot=data_locks_snapshot,
            )
        )
        audit_snapshots[branch] = snapshots["perturbation_audit"]
        evidence["branches"][branch] = {
            "aggregate_manifest_sha256": snapshots["manifest"].sha256,
            "accepted_root": root_evidence,
            "posterior_gate": posterior_gate,
            "diagnostics_gate": diagnostics_gate,
            "perturbation_audit_gate": audit_gate,
            "catalog_perturbation_replay": catalog_replay_evidence,
            "catalog_replay_audit_id": catalog_replay["audit_id"],
        }
    return audit_snapshots, evidence


def verify_legacy_measurement_aggregate(
    aggregate_root: Path,
    *,
    pc_catalog: Path,
    stellar_catalog: Path,
) -> tuple[FileSnapshot, dict[str, Any]]:
    """Require a complete accepted legacy aggregate before propagation."""

    repository_root = Path(__file__).resolve().parents[2]
    bryson_root = repository_root / "research" / "bryson-joint-posterior"
    if str(bryson_root) not in sys.path:
        sys.path.insert(0, str(bryson_root))
    module, module_snapshot = _load_python_module_from_snapshot(
        bryson_root / "freeze_v4_numerical_results.py",
        module_name="_sensitivity_legacy_accepted_aggregate_verifier",
        label="legacy accepted aggregate semantic verifier",
    )
    aggregate, root_evidence, snapshots = module.validate_aggregate_artifact_root(
        aggregate_root, "constant"
    )
    aggregate_gate = module.validate_aggregate(
        "constant",
        aggregate,
        expected_measurement_mode=module.LEGACY_SOURCE_MIXTURE,
        expected_acceptance_profile=module.V404_LEGACY_SENSITIVITY_PROFILE,
    )
    posterior_gate, full = module.validate_aggregate_posterior_artifacts(
        "constant",
        aggregate,
        snapshots["full"],
        snapshots["propagation"],
    )
    diagnostics_gate = module.validate_aggregate_diagnostics_artifact(
        "constant",
        aggregate,
        snapshots["diagnostics"],
        full,
    )
    perturbation_gate, _audit = module.validate_aggregate_perturbation_audit(
        "constant",
        snapshots["perturbation_audit"],
        snapshots["diagnostics"],
        expected_measurement_mode=module.LEGACY_SOURCE_MIXTURE,
    )
    correlation_gate = module.validate_aggregate_correlation_artifact(
        "constant",
        aggregate,
        snapshots["correlation"],
        full,
    )
    pc_snapshot = read_file_snapshot(pc_catalog, "locked DR25 PC catalog")
    stellar_snapshot = read_file_snapshot(
        stellar_catalog, "locked DR25 stellar catalog"
    )
    data_locks_snapshot = read_file_snapshot(
        repository_root / "provenance" / "DATA_LOCKS.json",
        "scientific data-lock registry",
    )
    replay, replay_evidence = module.validate_catalog_perturbation_replay(
        branch="constant",
        aggregate_root=aggregate_root,
        perturbation_audit_snapshot=snapshots["perturbation_audit"],
        diagnostics_snapshot=snapshots["diagnostics"],
        pc_catalog_snapshot=pc_snapshot,
        stellar_catalog_snapshot=stellar_snapshot,
        data_locks_snapshot=data_locks_snapshot,
        measurement_error_mode=module.LEGACY_SOURCE_MIXTURE,
    )
    return snapshots["propagation"], {
        "verifier_sha256": module_snapshot.sha256,
        "accepted_root": root_evidence,
        "aggregate_gate": aggregate_gate,
        "posterior_gate": posterior_gate,
        "diagnostics_gate": diagnostics_gate,
        "perturbation_audit_gate": perturbation_gate,
        "correlation_gate": correlation_gate,
        "catalog_perturbation_replay": replay_evidence,
        "catalog_replay_audit_id": replay["audit_id"],
        "measurement_error_mode": module.LEGACY_SOURCE_MIXTURE,
        "acceptance_profile": module.V404_LEGACY_SENSITIVITY_PROFILE,
    }


def verify_dr25_support_root(
    artifact_root: Path,
    *,
    pc_catalog: Path,
    stellar_catalog: Path,
    audit_snapshots: dict[str, FileSnapshot],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Re-run the public DR25 support result from locked catalogs and audits."""

    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        artifact_root,
        manifest_name=DR25_PUBLIC_MANIFEST_NAME,
        target_names=DR25_PUBLIC_FILES,
        label="public DR25 support artifact",
    )
    pc_snapshot = read_file_snapshot(pc_catalog, "locked DR25 PC catalog")
    stellar_snapshot = read_file_snapshot(stellar_catalog, "locked DR25 stellar catalog")
    repository_root = Path(__file__).resolve().parents[2]
    producer_snapshot = read_file_snapshot(
        repository_root / "research" / "v4-validation" / "dr25_support_audit.py",
        "DR25 support producer",
    )
    with tempfile.TemporaryDirectory(prefix="dr25-support-rederive-") as temporary:
        stable = Path(temporary)
        source_path = stable / "dr25_support_audit.py"
        pc_path = stable / pc_snapshot.path.name
        stellar_path = stable / stellar_snapshot.path.name
        source_path.write_bytes(producer_snapshot.data)
        pc_path.write_bytes(pc_snapshot.data)
        stellar_path.write_bytes(stellar_snapshot.data)
        audit_paths: dict[str, Path] = {}
        for branch, snapshot in audit_snapshots.items():
            path = stable / snapshot.path.name
            path.write_bytes(snapshot.data)
            audit_paths[branch] = path
        output = stable / "output"
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                str(source_path),
                "--pc-catalog",
                str(pc_path),
                "--stellar-catalog",
                str(stellar_path),
                "--constant-audit",
                str(audit_paths["constant"]),
                "--zero-audit",
                str(audit_paths["zero"]),
                "--out",
                str(output),
            ],
            cwd=stable,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            message = process.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"DR25 support rederivation failed: {message}")
        derived_root = output / "public"
        derived, derived_manifest = _snapshot_exact_manifest_root(
            derived_root,
            manifest_name=DR25_PUBLIC_MANIFEST_NAME,
            target_names=DR25_PUBLIC_FILES,
            label="rederived public DR25 support artifact",
        )
        for name in DR25_PUBLIC_FILES:
            if derived[name].data != snapshots[name].data:
                raise RuntimeError(f"Public DR25 artifact is not rederived: {name}")
        if derived_manifest.data != manifest_snapshot.data:
            raise RuntimeError("Public DR25 manifest is not rederived")
    report = load_json_bytes(snapshots["dr25_support_audit.json"].data, "DR25 support audit")
    validate_dr25_local_support(report)
    return report, {
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {name: snapshot.sha256 for name, snapshot in snapshots.items()},
        "producer_sha256": producer_snapshot.sha256,
        "pc_catalog_sha256": pc_snapshot.sha256,
        "stellar_catalog_sha256": stellar_snapshot.sha256,
        "aggregate_audit_sha256": {
            branch: snapshot.sha256 for branch, snapshot in audit_snapshots.items()
        },
        "exact_rederivation": True,
    }


def verify_age_cut_root(
    artifact_root: Path,
    *,
    jj_root: Path,
    ssp_repetition_root: Path,
    canonical_host_root: Path,
    age_ssp_contract: Path,
    ssp_qualification_report: Path,
    host_artifact_contract: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Re-run the age-threshold audit through both accepted contracts."""

    repository_root = Path(__file__).resolve().parents[2]
    scripts_root = repository_root / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_paths = {
        "verify_age_cut_ssp_contract": scripts_root
        / "verify_age_cut_ssp_contract.py",
        "verify_host_artifact_contract": scripts_root
        / "verify_host_artifact_contract.py",
        "verify_age_cut_sensitivity": scripts_root
        / "verify_age_cut_sensitivity.py",
    }
    previous = {name: sys.modules.get(name) for name in module_paths}
    loaded: dict[str, ModuleType] = {}
    snapshots: dict[str, FileSnapshot] = {}
    try:
        for name, path in module_paths.items():
            loaded[name], snapshots[name] = _load_repository_module_bytes(
                path, module_name=name
            )
        age_verifier = loaded["verify_age_cut_sensitivity"]
        report = age_verifier._verify_age_cut_artifact(
            artifact_root,
            jj_root=jj_root,
            run_dir=ssp_repetition_root,
            canonical_host_root=canonical_host_root,
            age_ssp_contract=age_ssp_contract,
            ssp_qualification_report=ssp_qualification_report,
            host_artifact_contract=host_artifact_contract,
            expected_jj_commit=age_verifier.JJ_SHA,
            require_repository_contract_paths=False,
        )
    finally:
        for name, old_module in previous.items():
            if old_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old_module

    artifact_snapshots, artifact_manifest = _snapshot_exact_manifest_root(
        artifact_root,
        manifest_name="SHA256SUMS_age_cut_sensitivity.txt",
        target_names=(
            "AGE_CUT_SENSITIVITY.json",
            "age_cut_radial.csv",
            "JJ_SSP_INPUT_SHA256SUMS.txt",
        ),
        label="accepted age-cut sensitivity",
    )
    if report.get("status") != "PASS":
        raise RuntimeError("Age-cut sensitivity did not pass both accepted contracts")
    contract_snapshot = read_file_snapshot(
        age_ssp_contract, "accepted age-cut SSP contract"
    )
    qualification_snapshot = read_file_snapshot(
        ssp_qualification_report, "accepted age-cut SSP qualification report"
    )
    host_contract_snapshot = read_file_snapshot(
        host_artifact_contract, "accepted host-artifact contract"
    )
    return report, {
        "status": "PASS",
        "manifest_sha256": artifact_manifest.sha256,
        "validated_files": {
            name: snapshot.sha256
            for name, snapshot in artifact_snapshots.items()
        },
        "verifier_source_sha256": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
        "age_ssp_contract_sha256": contract_snapshot.sha256,
        "ssp_qualification_report_sha256": qualification_snapshot.sha256,
        "host_artifact_contract_sha256": host_contract_snapshot.sha256,
        "accepted_ssp_repetition_rederived": True,
        "row_level_host_output_emitted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    for selector in ("canonical", "legacy"):
        for branch in ("constant", "zero"):
            parser.add_argument(
                f"--{selector}-{branch}-artifact-root", required=True, type=Path
            )
    parser.add_argument("--constant-posterior-samples", required=True, type=Path)
    parser.add_argument("--zero-posterior-samples", required=True, type=Path)
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
    parser.add_argument("--host-artifact-root", required=True, type=Path)
    parser.add_argument("--age-cut-artifact-root", required=True, type=Path)
    parser.add_argument("--age-cut-jj-root", required=True, type=Path)
    parser.add_argument(
        "--age-cut-ssp-repetition-root", required=True, type=Path
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
    parser.add_argument(
        "--legacy-measurement-aggregate-root", required=True, type=Path
    )
    parser.add_argument("--legacy-measurement-artifact-root", required=True, type=Path)
    parser.add_argument("--legacy-measurement-posterior-samples", required=True, type=Path)
    parser.add_argument("--host-tams-audit-root", required=True, type=Path)
    parser.add_argument("--metallicity-audit-root", required=True, type=Path)
    parser.add_argument("--constant-aggregate-root", required=True, type=Path)
    parser.add_argument("--zero-aggregate-root", required=True, type=Path)
    parser.add_argument("--dr25-audit-root", required=True, type=Path)
    parser.add_argument("--dr25-pc-catalog", required=True, type=Path)
    parser.add_argument("--dr25-stellar-catalog", required=True, type=Path)
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
    parser.add_argument("--sensitivity-artifact-root", required=True, type=Path)
    parser.add_argument(
        "--execution-mode",
        required=True,
        choices=("local_ubuntu_22_04_wsl2", "github_actions"),
    )
    parser.add_argument("--production-checkout", required=True, type=Path)
    parser.add_argument("--release-checkout", required=True, type=Path)
    parser.add_argument("--production-run-id", type=int)
    parser.add_argument("--production-run-attempt", type=int)
    parser.add_argument("--production-artifact", type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--os-runtime-manifest", type=Path)
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

    output = args.out.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise RuntimeError("Sensitivity-freeze output directory must be absent or empty")
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
    signed_output_files = local_run_evidence.pop("_signed_output_files", None)
    if not isinstance(signed_output_files, dict):
        raise RuntimeError("Signed local-run output map is unavailable")
    attested_roots = {
        "corrected_constant_aggregate": args.constant_aggregate_root,
        "corrected_zero_aggregate": args.zero_aggregate_root,
        "legacy_constant_aggregate": args.legacy_measurement_aggregate_root,
        "legacy_measurement_propagation": args.legacy_measurement_artifact_root,
        "host_tams_audit": args.host_tams_audit_root,
        "metallicity_tams_audit": args.metallicity_audit_root,
        "dr25_support": args.dr25_audit_root,
        "sensitivity_artifacts": args.sensitivity_artifact_root,
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
    artifact_root = args.sensitivity_artifact_root
    artifact_snapshots, sensitivity_manifest_snapshot = validate_artifact_manifest(
        artifact_root / SENSITIVITY_MANIFEST_NAME,
        artifact_root,
        set(SENSITIVITY_ARTIFACT_NAMES),
    )
    run_provenance, run_provenance_evidence = validate_run_provenance(
        artifact_snapshots[RUN_PROVENANCE_NAME],
        execution_mode=args.execution_mode,
        production_checkout=args.production_checkout,
        release_checkout=args.release_checkout,
        production_run_id=args.production_run_id,
        production_run_attempt=args.production_run_attempt,
        production_artifact=args.production_artifact,
        source_archive=args.source_archive,
        os_runtime_manifest=args.os_runtime_manifest,
        command_plan=args.local_run_plan,
    )
    if args.execution_mode == "local_ubuntu_22_04_wsl2":
        production_binding = _require_mapping(
            run_provenance.get("production"), "local sensitivity production binding"
        )
        expected_local_binding = {
            "source_archive_sha256": local_run_evidence.get("source_archive_sha256"),
            "command_plan_sha256": local_run_evidence.get("command_plan_sha256"),
            "os_runtime_manifest_sha256": local_run_evidence.get(
                "numerical_runtime_manifest_sha256"
            ),
        }
        for field, expected_value in expected_local_binding.items():
            if production_binding.get(field) != expected_value:
                raise RuntimeError(
                    f"Sensitivity provenance and signed local run disagree: {field}"
                )

    propagation_roots = {
        (selector, branch): getattr(args, f"{selector}_{branch}_artifact_root")
        for selector in ("canonical", "legacy")
        for branch in ("constant", "zero")
    }
    posterior_paths = {
        "constant": args.constant_posterior_samples,
        "zero": args.zero_posterior_samples,
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
        _contract_host_summary_snapshot,
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
    constant = propagation_summaries[("canonical", "constant")]
    zero = propagation_summaries[("canonical", "zero")]
    (
        legacy_accepted_posterior_snapshot,
        legacy_accepted_aggregate_evidence,
    ) = verify_legacy_measurement_aggregate(
        args.legacy_measurement_aggregate_root,
        pc_catalog=args.dr25_pc_catalog,
        stellar_catalog=args.dr25_stellar_catalog,
    )
    (
        legacy_posterior_frame,
        legacy_posterior_snapshot,
        legacy_posterior_evidence,
    ) = validate_posterior_artifact(
        args.legacy_measurement_posterior_samples,
        branch="constant",
    )
    if legacy_posterior_snapshot.sha256 != legacy_accepted_posterior_snapshot.sha256:
        raise RuntimeError(
            "Legacy measurement propagation posterior is not the accepted legacy aggregate"
        )
    (
        legacy_measurement_host_frame,
        legacy_measurement_host_collapsed,
        legacy_measurement_host_snapshot,
        legacy_measurement_host_evidence,
    ) = validate_host_artifact(args.canonical_hosts, selector="canonical")
    require_host_rows_equal_parent(
        legacy_measurement_host_frame,
        parent_host_frames["canonical"],
        selector="canonical",
    )
    if legacy_measurement_host_snapshot.sha256 != propagation_evidence["canonical"][
        "constant"
    ]["host_sha256"]:
        raise RuntimeError("Legacy-measurement propagation uses a different canonical host file")
    legacy_measurement, legacy_measurement_evidence = validate_fresh_propagation_summary(
        args.legacy_measurement_artifact_root,
        branch="constant",
        selector="canonical",
        posterior_snapshot=legacy_posterior_snapshot,
        posterior_frame=legacy_posterior_frame,
        host_snapshot=legacy_measurement_host_snapshot,
        host_frame=legacy_measurement_host_frame,
        host_collapsed=legacy_measurement_host_collapsed,
        parent_collapsed=parent_collapsed["canonical"],
    )
    if legacy_posterior_snapshot.sha256 == propagation_evidence["canonical"][
        "constant"
    ]["posterior_sample_sha256"]:
        raise RuntimeError("Legacy measurement sensitivity reuses the corrected posterior")
    host, host_root_evidence = validate_host_tams_root(args.host_tams_audit_root)
    metallicity_report, metallicity_evidence = verify_metallicity_audit_root(
        args.metallicity_audit_root,
        parent_evidence=parent_evidence,
    )
    aggregate_audit_snapshots, aggregate_audit_evidence = (
        verify_aggregate_audits_for_dr25(
            {
                "constant": args.constant_aggregate_root,
                "zero": args.zero_aggregate_root,
            },
            pc_catalog=args.dr25_pc_catalog,
            stellar_catalog=args.dr25_stellar_catalog,
        )
    )
    dr25, dr25_root_evidence = verify_dr25_support_root(
        args.dr25_audit_root,
        pc_catalog=args.dr25_pc_catalog,
        stellar_catalog=args.dr25_stellar_catalog,
        audit_snapshots=aggregate_audit_snapshots,
    )
    age_cut, age_cut_root_evidence = verify_age_cut_root(
        args.age_cut_artifact_root,
        jj_root=args.age_cut_jj_root,
        ssp_repetition_root=args.age_cut_ssp_repetition_root,
        canonical_host_root=args.host_artifact_root,
        age_ssp_contract=args.age_cut_ssp_contract,
        ssp_qualification_report=args.age_cut_ssp_qualification_report,
        host_artifact_contract=args.host_artifact_contract,
    )
    age_report_document = load_json_bytes(
        external_snapshots["external age-cut SSP qualification report"].data,
        "external age-cut SSP qualification report",
    )
    computational_sources["age"] = age_qualification_source_identity(
        age_report_document
    )
    age_cut_root_evidence.update(
        {
            **external_pairs["age"],
            "computational_source": dict(computational_sources["age"]),
        }
    )
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
    model_form = load_json_bytes(
        artifact_snapshots["bryson_model_form_sensitivity.json"].data,
        "Bryson model-form sensitivity",
    )
    hz = load_json_bytes(
        artifact_snapshots["hz_sensitivity_results.json"].data,
        "HZ sensitivity",
    )
    branches = load_json_bytes(
        artifact_snapshots["tams_all_branch_results.json"].data,
        "TAMS all-branch sensitivity",
    )
    sensitivity_rederivation_evidence = verify_sensitivity_rederivation(
        artifact_snapshots,
        parent_snapshot=parent_snapshot,
        canonical_hosts_snapshot=legacy_measurement_host_snapshot,
    )

    if constant.get("branch") != "constant" or zero.get("branch") != "zero":
        raise RuntimeError("Canonical Galactic branch mismatch")
    if legacy_measurement.get("branch") != "constant":
        raise RuntimeError("Legacy measurement propagation is not constant branch")
    cross_check_host_tams_audit(
        host,
        propagation_roots,
        propagation_evidence,
        metallicity_report,
        metallicity_evidence,
        parent_evidence,
        host_contract_evidence,
    )
    dr25_support_evidence = validate_dr25_local_support(dr25)
    final_radial_comparison = convergence_root_evidence["gate"]
    if model_form.get("experiment") != "Bryson_model_form_sensitivity":
        raise RuntimeError("Unexpected model-form artifact")
    if hz.get("experiment") != "HZ_inner_boundary_and_planet_mass_sensitivity":
        raise RuntimeError("Unexpected HZ sensitivity artifact")

    models = _require_mapping(model_form.get("models"), "model-form models")
    model1 = _require_mapping(models.get("model1"), "model-form model1")
    model2_record = _require_mapping(models.get("model2"), "model-form model2")
    hz_baseline = _require_mapping(hz.get("baseline"), "HZ baseline")
    branch_masks = _require_mapping(branches.get("masks"), "TAMS branch masks")
    lineweaver = _require_mapping(
        branch_masks.get("lineweaver_7_9"), "lineweaver 7--9 kpc branch"
    )
    lineweaver_branches = _require_mapping(
        lineweaver.get("branches"), "lineweaver branches"
    )
    chz_constant = _require_mapping(
        lineweaver_branches.get("CHZ_constant"), "lineweaver CHZ constant"
    )

    require_close(
        "model-form baseline Lambda_EE",
        _require_finite_nonnegative(model1.get("Lambda_earth10"), "model1 Lambda_EE"),
        3376462.6740267,
        0.01,
    )
    require_close(
        "HZ baseline Lambda_EE",
        _require_finite_nonnegative(hz_baseline.get("Lambda_earth10"), "HZ baseline Lambda_EE"),
        3376462.6740267,
        0.01,
    )

    constant_q50 = _require_finite_nonnegative(
        constant["posterior_quantiles"]["Lambda_EE"]["q50"],
        "constant Lambda_EE q50",
    )
    zero_q50 = _require_finite_nonnegative(
        zero["posterior_quantiles"]["Lambda_EE"]["q50"],
        "zero Lambda_EE q50",
    )
    legacy_measurement_q50 = _require_finite_nonnegative(
        legacy_measurement["posterior_quantiles"]["Lambda_EE"]["q50"],
        "legacy-measurement Lambda_EE q50",
    )
    host_legacy = {
        branch: {
            "legacy_quantiles": propagation_summaries[("legacy", branch)][
                "posterior_quantiles"
            ]
        }
        for branch in ("constant", "zero")
    }
    baseline_plugin = _require_finite_nonnegative(
        chz_constant.get("Lambda_earth10"), "lineweaver baseline Lambda_EE"
    )
    require_close(
        "TAMS branch baseline Lambda_EE", baseline_plugin, 3376462.6740267, 0.01
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
        canonical_q50 = constant_q50 if branch == "constant" else zero_q50
        legacy_q50 = _require_finite_nonnegative(
            host_legacy[branch]["legacy_quantiles"]["Lambda_EE"]["q50"],
            f"legacy-host {branch} Lambda_EE q50",
        )
        add(
            "host selector",
            f"legacy 4.3 < logg < 7 selector ({branch})",
            "posterior q50 on alternative host measure",
            canonical_q50,
            legacy_q50,
            fractional_change(legacy_q50, canonical_q50),
            "MODEL_SENSITIVITY",
            "Changes both host normalization and temperature weighting.",
        )
    low_temperature = _require_mapping(
        host.get("low_temperature_anchor_dependence"),
        "host low-temperature anchor dependence",
    )
    native_changes = _require_mapping(
        low_temperature.get("native_selector_fractional_change_vs_canonical"),
        "native-selector fractional changes",
    )
    native_delta = _require_finite_number(
        native_changes.get("Lambda_EE_plugin"), "native-selector Lambda_EE change"
    )
    if native_delta <= -1.0:
        raise RuntimeError("Native-selector fractional change implies a negative population")
    add(
        "TAMS selector",
        "native solar curve without the 5200 K anchor",
        "canonical plug-in",
        baseline_plugin,
        baseline_plugin * (1.0 + native_delta),
        native_delta,
        "PASS",
        "Native low-mass nodes reproduce the selected population exactly.",
    )

    coarse, fine, radial_delta = validated_radial_delta(final_radial_comparison)
    add(
        "numerics",
        "radial grid 0.5 to 0.25 kpc",
        "canonical plug-in",
        coarse,
        fine,
        radial_delta,
        "PASS",
        "Below the predeclared one-percent convergence tolerance.",
    )

    model2 = _require_finite_nonnegative(
        model2_record.get("Lambda_earth10"), "model2 Lambda_EE"
    )
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

    perturbation_rows = hz.get("inner_boundary_perturbations")
    if not isinstance(perturbation_rows, list):
        raise RuntimeError("HZ inner-boundary perturbations must be a list")
    perturbations: dict[float, dict[str, Any]] = {}
    for index, raw_item in enumerate(perturbation_rows):
        item = _require_mapping(raw_item, f"HZ perturbation {index}")
        scale = _require_finite_number(item.get("inner_flux_scale"), "HZ flux scale")
        if scale in perturbations:
            raise RuntimeError(f"Duplicate HZ flux scale: {scale}")
        perturbations[scale] = item
    if set(perturbations) != {0.95, 0.99, 1.0, 1.01, 1.05}:
        raise RuntimeError("HZ perturbation scale set changed")
    require_close(
        "HZ unit-scale Lambda_EE",
        _require_finite_nonnegative(
            perturbations[1.0].get("Lambda_earth10"), "HZ unit-scale Lambda_EE"
        ),
        baseline_plugin,
        0.01,
    )
    for scale in (0.95, 0.99, 1.01, 1.05):
        item = perturbations[scale]
        comparison = _require_finite_nonnegative(
            item.get("Lambda_earth10"), f"HZ scale {scale} Lambda_EE"
        )
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

    mass_rows = hz.get("planet_mass_prescriptions")
    if not isinstance(mass_rows, list):
        raise RuntimeError("HZ planet-mass prescriptions must be a list")
    masses: dict[float, dict[str, Any]] = {}
    for index, raw_item in enumerate(mass_rows):
        item = _require_mapping(raw_item, f"planet-mass prescription {index}")
        mass = _require_finite_number(item.get("planet_mass_Mearth"), "planet mass")
        if mass in masses:
            raise RuntimeError(f"Duplicate planet-mass prescription: {mass}")
        masses[mass] = item
    if set(masses) != {0.1, 1.0, 5.0}:
        raise RuntimeError("Planet-mass prescription set changed")
    require_close(
        "HZ one-Earth-mass Lambda_EE",
        _require_finite_nonnegative(
            masses[1.0].get("Lambda_earth10"), "one-Earth-mass Lambda_EE"
        ),
        baseline_plugin,
        0.01,
    )
    for mass in (0.1, 5.0):
        comparison = _require_finite_nonnegative(
            masses[mass].get("Lambda_earth10"), f"{mass:g}-Earth-mass Lambda_EE"
        )
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

    ohz_constant = _require_mapping(
        lineweaver_branches.get("OHZ_constant"), "lineweaver OHZ constant"
    )
    optimistic = _require_finite_nonnegative(
        ohz_constant.get("Lambda_earth10"), "optimistic-HZ Lambda_EE"
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

    weighted = _require_finite_number(
        chz_constant.get("RT_L2"), "lineweaver temperature-weight ratio"
    )
    if weighted <= 0.0:
        raise RuntimeError("Temperature-weight ratio must be positive")
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
        mask = _require_mapping(branch_masks.get(mask_name), f"TAMS mask {mask_name}")
        mask_branches = _require_mapping(mask.get("branches"), f"{mask_name} branches")
        mask_chz = _require_mapping(
            mask_branches.get("CHZ_constant"), f"{mask_name} CHZ constant"
        )
        comparison = _require_finite_nonnegative(
            mask_chz.get("Lambda_earth10"), f"{mask_name} Lambda_EE"
        )
        mask_label = mask.get("label")
        if not isinstance(mask_label, str) or not mask_label:
            raise RuntimeError(f"{mask_name} label is missing")
        add(
            "spatial domain",
            mask_label,
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
        "independently verified differential correction",
        "fresh artifact-root verification",
        None,
        None,
        None,
        "NOT_PUBLISHABLE_NOT_APPLIED_OPEN_SYSTEMATIC",
        "The correction is not applied; metallicity dependence remains an open systematic.",
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

    input_records = {
        "parent": {
            "path": str(parent_snapshot.path),
            "sha256": parent_snapshot.sha256,
            "size_bytes": parent_snapshot.size_bytes,
        },
        "constant_posterior_samples": propagation_evidence["canonical"]["constant"][
            "posterior_artifact"
        ],
        "zero_posterior_samples": propagation_evidence["canonical"]["zero"][
            "posterior_artifact"
        ],
        "canonical_hosts": propagation_evidence["canonical"]["constant"][
            "host_artifact"
        ],
        "legacy_hosts": propagation_evidence["legacy"]["constant"]["host_artifact"],
        "legacy_measurement_posterior_samples": legacy_posterior_evidence,
        "legacy_measurement_accepted_aggregate": legacy_accepted_aggregate_evidence,
        "legacy_measurement_canonical_hosts": legacy_measurement_host_evidence,
        "dr25_audit": dr25_root_evidence,
        "age_cut_sensitivity": age_cut_root_evidence,
        "tams_convergence": convergence_root_evidence,
        "radial_ssp_qualification": radial_ssp_evidence,
        "sensitivity_artifact_manifest": {
            "path": str(sensitivity_manifest_snapshot.path),
            "sha256": sensitivity_manifest_snapshot.sha256,
            "size_bytes": sensitivity_manifest_snapshot.size_bytes,
        },
    }
    postconsumption_attestation = verify_attested_output_roots(
        args.local_run_output_root, attested_roots, signed_output_files
    )
    if postconsumption_attestation != preconsumption_attestation:
        raise RuntimeError("Signed production artifacts changed while being consumed")
    local_run_evidence["consumed_output_recheck"] = postconsumption_attestation
    recheck_external_evidence_locks(external_snapshots)
    result = {
        "status": "SENSITIVITY_REGISTER_FROZEN",
        "scientific_readiness": "CONDITIONAL_MODEL_PROJECTION_ONLY",
        "computational_source": computational_source,
        "external_post_qualification_evidence": external_pairs,
        "scope": (
            "Audited one-at-a-time numerical, scenario, model, climate, host, "
            "and spatial sensitivities for manuscript v4."
        ),
        "artifact_run": {
            **run_provenance,
            "run_provenance_artifact": run_provenance_evidence,
            "manifest_sha256": sensitivity_manifest_snapshot.sha256,
            "validated_artifact_files": {
                name: snapshot.sha256
                for name, snapshot in artifact_snapshots.items()
            },
        },
        "inputs": input_records,
        "artifact_roots": {
            "host_tams_audit": host_root_evidence,
            "metallicity_tams_audit": metallicity_evidence,
            "host_artifact_contract": host_contract_evidence,
            "tams_radial_convergence": convergence_root_evidence,
            "radial_ssp_qualification": radial_ssp_evidence,
            "signed_local_production_run": local_run_evidence,
            "legacy_measurement_accepted_aggregate": (
                legacy_accepted_aggregate_evidence
            ),
            "legacy_measurement_propagation": legacy_measurement_evidence,
            "sensitivity_rederivation": sensitivity_rederivation_evidence,
            "accepted_aggregate_audits": aggregate_audit_evidence,
            "dr25_support": dr25_root_evidence,
            "age_cut_sensitivity": age_cut_root_evidence,
        },
        "fresh_host_selector_propagation": propagation_evidence,
        "canonical_posterior_q50": {
            "constant_Lambda_EE": constant_q50,
            "zero_Lambda_EE": zero_q50,
        },
        "dr25_local_support_evidence": dr25_support_evidence,
        "age_threshold_sensitivity": age_cut,
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

    result = release_safe_evidence(result)
    output.mkdir(parents=True, exist_ok=True)
    result_path = output / "V4_SENSITIVITY_FREEZE.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
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
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
