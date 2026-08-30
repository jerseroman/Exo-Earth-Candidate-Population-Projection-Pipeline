#!/usr/bin/env python3
"""Fail closed unless an aggregate artifact passed the production gate."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import importlib.util
import json
import math
import os
import re
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, NamedTuple


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PARAMETERS = ("F0", "alpha", "beta", "gamma")
QUANTILE_NAMES = ("q2.5", "q16", "q50", "q84", "q97.5")
QUANTILE_PROBABILITIES = (0.025, 0.16, 0.50, 0.84, 0.975)
FULL_COLUMNS = (
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
PROPAGATION_COLUMNS = ("branch", "global_trial", *PARAMETERS)
ROOT = Path(__file__).resolve().parents[1]
DATA_LOCKS = ROOT / "provenance" / "DATA_LOCKS.json"
BRYSON_REPOSITORY = "stevepur/DR25-occurrence-public"
BRYSON_SOURCE_RELATIVE_PATH = "insolation/rateModels3D.py"
V404_ACCEPTANCE_PROFILE = "v4.0.4-production"
V404_ZERO_EXTENDED_PROFILE = "v4.0.4-zero-extended"
V404_LEGACY_SENSITIVITY_PROFILE = "v4.0.4-legacy-measurement-sensitivity"
RAW_CHAIN_SCHEMA_VERSION = 1
RAW_CHAIN_FORMAT = "exoearth_raw_chain_le_f64_v1"
RAW_CHAIN_STORAGE_POLICY = "PRIVATE_NOT_FOR_PUBLIC_RELEASE"
RAW_CHAIN_HEADER_SIZE_BYTES = 76
RAW_CHAIN_PAYLOAD_FIELDS = 5
RAW_CHAIN_FLOAT_SIZE_BYTES = 8
RAW_CHAIN_HELPER = (
    ROOT / "research" / "bryson-joint-posterior" / "raw_chain_evidence.py"
)
CATALOG_AUDIT_HELPER = (
    ROOT
    / "research"
    / "bryson-joint-posterior"
    / "catalog_perturbation_audit.py"
)
MAX_CATALOG_AUDIT_HELPER_BYTES = 1_000_000
MAX_DATA_LOCKS_BYTES = 8_000_000
MAX_AGGREGATE_MANIFEST_BYTES = 1_000_000
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


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _has_reparse_point(value: os.stat_result) -> bool:
    """Return true for Windows reparse points, including junction-like objects."""

    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


class StableRegularFile(NamedTuple):
    """Metadata for the exact bytes consumed through one source descriptor."""

    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int, int]
    data: bytes | None


def _snapshot_regular_file(
    path: Path,
    description: str,
    *,
    destination: Path | None = None,
    capture_bytes: bool = False,
    maximum_bytes: int | None = None,
) -> StableRegularFile:
    """Read one non-link regular file once, optionally copying the same bytes."""

    candidate = Path(path)
    try:
        path_before = os.lstat(candidate)
    except OSError as error:
        fail(f"cannot inspect {description}: {error}")
    if (
        stat.S_ISLNK(path_before.st_mode)
        or _has_reparse_point(path_before)
        or not stat.S_ISREG(path_before.st_mode)
    ):
        fail(f"{description} must be a regular non-link file")
    if maximum_bytes is not None and path_before.st_size > maximum_bytes:
        fail(f"{description} exceeds {maximum_bytes} bytes")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        fail(f"cannot open {description}: {error}")

    writer = None
    try:
        descriptor_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or _has_reparse_point(descriptor_before)
            or _file_identity(descriptor_before) != _file_identity(path_before)
        ):
            fail(f"{description} changed before its stable snapshot")
        if destination is not None:
            try:
                writer = Path(destination).open("xb")
            except OSError as error:
                fail(f"cannot create private snapshot for {description}: {error}")

        digest = hashlib.sha256()
        captured: list[bytes] | None = [] if capture_bytes else None
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if maximum_bytes is not None and total > maximum_bytes:
                fail(f"{description} exceeds {maximum_bytes} bytes")
            digest.update(block)
            if captured is not None:
                captured.append(block)
            if writer is not None:
                writer.write(block)

        if writer is not None:
            writer.flush()
            os.fsync(writer.fileno())
            if writer.tell() != total:
                fail(f"private snapshot size mismatch for {description}")
        descriptor_after = os.fstat(descriptor)
        try:
            path_after = os.lstat(candidate)
        except OSError as error:
            fail(f"{description} disappeared after its stable snapshot: {error}")
        identity = _file_identity(descriptor_before)
        if (
            identity != _file_identity(descriptor_after)
            or identity != _file_identity(path_before)
            or identity != _file_identity(path_after)
            or stat.S_ISLNK(path_after.st_mode)
            or _has_reparse_point(path_after)
            or not stat.S_ISREG(path_after.st_mode)
            or total != descriptor_before.st_size
        ):
            fail(f"{description} changed during its stable snapshot")
        return StableRegularFile(
            sha256=digest.hexdigest(),
            size_bytes=total,
            identity=identity,
            data=None if captured is None else b"".join(captured),
        )
    finally:
        if writer is not None:
            writer.close()
        os.close(descriptor)


def read_stable_regular_file(
    path: Path,
    description: str,
    *,
    maximum_bytes: int,
) -> tuple[bytes, str]:
    """Return one single-FD, non-symlink file snapshot and its SHA-256."""

    snapshot = _snapshot_regular_file(
        path,
        description,
        capture_bytes=True,
        maximum_bytes=maximum_bytes,
    )
    if snapshot.data is None:
        fail(f"internal stable-byte capture failed for {description}")
    return snapshot.data, snapshot.sha256


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


def _reject_json_constant(token: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {token}")


def _parse_finite_json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key is forbidden: {key!r}")
        result[key] = value
    return result


def strict_json_text(text: str, description: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except json.JSONDecodeError as error:
        fail(f"cannot parse {description}: {error}")


def measurement_mode_for_profile(branch: str, summary: dict[str, Any]) -> str:
    """Return the only measurement mode permitted by the accepted profile."""

    gate = require_dict(
        summary.get("production_acceptance_gate"), "production acceptance gate"
    )
    profile = gate.get("profile")
    if profile == V404_LEGACY_SENSITIVITY_PROFILE:
        if branch != "constant":
            fail("legacy measurement sensitivity is restricted to the constant branch")
        expected = "legacy_source_mixture"
    elif profile in {V404_ACCEPTANCE_PROFILE, V404_ZERO_EXTENDED_PROFILE}:
        expected = "quantile_matched_two_sided"
    else:
        fail("aggregate acceptance profile cannot select a catalog replay mode")
    measurement = require_dict(
        summary.get("measurement_error"), "measurement-error metadata"
    )
    if measurement.get("mode") != expected:
        fail("aggregate measurement-error mode does not match its acceptance profile")
    return expected


def _load_catalog_audit_module(
    snapshot_path: Path, source_sha256: str
) -> Any:
    module_name = f"_accepted_catalog_perturbation_audit_{source_sha256[:16]}"
    spec = importlib.util.spec_from_file_location(module_name, snapshot_path)
    if spec is None or spec.loader is None:
        fail("cannot construct the catalog perturbation audit module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        fail(f"cannot load stable catalog perturbation audit helper: {error}")
    finally:
        sys.modules.pop(module_name, None)
    required = {
        "verify_catalog_perturbations",
        "CatalogAuditError",
        "PC_LOCK_ID",
        "STELLAR_LOCK_ID",
    }
    if any(not hasattr(module, name) for name in required):
        fail("catalog perturbation audit helper has an incomplete API")
    return module


def _require_sha256(value: Any, description: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{description} is not a lowercase SHA-256")
    return value


def _require_positive_integer(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{description} is not a positive integer")
    return value


def validate_catalog_replay_report(
    report: Any,
    *,
    branch: str,
    measurement_error_mode: str,
    summary: dict[str, Any],
    entries: dict[str, str],
    pc_catalog: Path,
    stellar_catalog: Path,
    data_locks_sha256: str,
    data_locks_size: int,
    helper_sha256: str,
    helper_size: int,
) -> dict[str, Any]:
    """Bind the independent 400-realization replay to accepted inputs."""

    expected_keys = {
        "audit_id",
        "schema_version",
        "status",
        "branch",
        "measurement_error_mode",
        "trials_verified",
        "merged_catalog_rows",
        "audit_rows_verified",
        "locked_inputs",
        "data_locks",
        "verifier_source",
        "aggregate_inputs",
        "seed_schedule_sha256",
        "count_projection_sha256",
        "verification_scope",
    }
    if not isinstance(report, dict) or set(report) != expected_keys:
        fail("catalog perturbation replay report schema mismatch")
    require_exact_integer(report.get("schema_version"), 1, "catalog replay schema")
    require_exact_integer(report.get("trials_verified"), 400, "catalog replay trials")
    if (
        report.get("status") != "PASS"
        or report.get("branch") != branch
        or report.get("measurement_error_mode") != measurement_error_mode
    ):
        fail("catalog perturbation replay identity mismatch")
    _require_positive_integer(
        report.get("merged_catalog_rows"), "catalog replay merged row count"
    )
    _require_positive_integer(
        report.get("audit_rows_verified"), "catalog replay audit row count"
    )
    for key in ("seed_schedule_sha256", "count_projection_sha256"):
        _require_sha256(report.get(key), f"catalog replay {key}")
    expected_scope = (
        "exact source merge, reliability selection, asymmetric draws, domain "
        "masks, row identities, source fields, perturbed values, audit statuses, "
        "and per-realization counts"
    )
    if report.get("verification_scope") != expected_scope:
        fail("catalog perturbation replay scope changed")

    locked = require_dict(report.get("locked_inputs"), "catalog replay locked inputs")
    if set(locked) != {"bryson_pc_catalog", "bryson_stellar_catalog_extracted"}:
        fail("catalog replay locked-input set changed")
    summary_locks = require_dict(
        summary.get("locked_input_sha256"), "aggregate locked scientific inputs"
    )
    expected_catalogs = {
        "bryson_pc_catalog": (Path(pc_catalog).name, summary_locks.get("pc_catalog")),
        "bryson_stellar_catalog_extracted": (
            Path(stellar_catalog).name,
            summary_locks.get("stellar_catalog"),
        ),
    }
    for lock_id, (filename, expected_hash) in expected_catalogs.items():
        record = require_dict(locked.get(lock_id), f"catalog replay {lock_id}")
        if set(record) != {"filename", "sha256", "size_bytes"}:
            fail(f"catalog replay {lock_id} schema changed")
        if (
            record.get("filename") != filename
            or record.get("sha256") != expected_hash
        ):
            fail(f"catalog replay {lock_id} binding mismatch")
        _require_sha256(record.get("sha256"), f"catalog replay {lock_id} hash")
        _require_positive_integer(
            record.get("size_bytes"), f"catalog replay {lock_id} size"
        )

    locks_record = require_dict(report.get("data_locks"), "catalog replay DATA_LOCKS")
    if set(locks_record) != {"filename", "sha256", "size_bytes"} or locks_record != {
        "filename": "DATA_LOCKS.json",
        "sha256": data_locks_sha256,
        "size_bytes": data_locks_size,
    }:
        fail("catalog replay DATA_LOCKS binding mismatch")
    helper_record = require_dict(
        report.get("verifier_source"), "catalog replay verifier source"
    )
    if set(helper_record) != {"sha256", "size_bytes"} or helper_record != {
        "sha256": helper_sha256,
        "size_bytes": helper_size,
    }:
        fail("catalog replay helper source binding mismatch")

    aggregate_inputs = require_dict(
        report.get("aggregate_inputs"), "catalog replay aggregate inputs"
    )
    expected_aggregate_names = {
        "perturbation_audit": f"perturbation_audit_{branch}_full.csv.gz",
        "trial_diagnostics": f"trial_diagnostics_{branch}_full.jsonl",
    }
    if set(aggregate_inputs) != set(expected_aggregate_names):
        fail("catalog replay aggregate-input set changed")
    for role, filename in expected_aggregate_names.items():
        record = require_dict(
            aggregate_inputs.get(role), f"catalog replay aggregate {role}"
        )
        if set(record) != {"filename", "sha256", "size_bytes"}:
            fail(f"catalog replay aggregate {role} schema changed")
        if (
            record.get("filename") != filename
            or record.get("sha256") != entries.get(filename)
        ):
            fail(f"catalog replay aggregate {role} binding mismatch")
        _require_positive_integer(
            record.get("size_bytes"), f"catalog replay aggregate {role} size"
        )

    body = {key: value for key, value in report.items() if key != "audit_id"}
    recomputed_audit_id = "sha256:" + hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if report.get("audit_id") != recomputed_audit_id:
        fail("catalog perturbation replay audit ID mismatch")
    return report


def verify_catalog_perturbation_replay(
    *,
    root: Path,
    branch: str,
    summary: dict[str, Any],
    entries: dict[str, str],
    pc_catalog: Path,
    stellar_catalog: Path,
) -> dict[str, Any]:
    """Load the independent helper from stable bytes and replay 400 trials."""

    measurement_error_mode = measurement_mode_for_profile(branch, summary)
    helper_bytes, helper_sha256 = read_stable_regular_file(
        CATALOG_AUDIT_HELPER,
        "catalog perturbation audit helper",
        maximum_bytes=MAX_CATALOG_AUDIT_HELPER_BYTES,
    )
    locks_bytes, locks_sha256 = read_stable_regular_file(
        DATA_LOCKS,
        "DATA_LOCKS.json",
        maximum_bytes=MAX_DATA_LOCKS_BYTES,
    )
    with tempfile.TemporaryDirectory(prefix="accepted-catalog-replay-") as temporary:
        private = Path(temporary)
        helper_snapshot = private / CATALOG_AUDIT_HELPER.name
        locks_snapshot = private / DATA_LOCKS.name
        try:
            with helper_snapshot.open("xb") as handle:
                handle.write(helper_bytes)
            with locks_snapshot.open("xb") as handle:
                handle.write(locks_bytes)
        except OSError as error:
            fail(f"cannot create stable catalog replay snapshots: {error}")
        module = _load_catalog_audit_module(helper_snapshot, helper_sha256)
        try:
            report = module.verify_catalog_perturbations(
                branch=branch,
                aggregate_root=root,
                pc_catalog=Path(pc_catalog),
                stellar_catalog=Path(stellar_catalog),
                data_locks_path=locks_snapshot,
                expected_trials=400,
                measurement_error_mode=measurement_error_mode,
            )
        except module.CatalogAuditError as error:
            fail(f"catalog perturbation replay failed: {error}")
    return validate_catalog_replay_report(
        report,
        branch=branch,
        measurement_error_mode=measurement_error_mode,
        summary=summary,
        entries=entries,
        pc_catalog=Path(pc_catalog),
        stellar_catalog=Path(stellar_catalog),
        data_locks_sha256=locks_sha256,
        data_locks_size=len(locks_bytes),
        helper_sha256=helper_sha256,
        helper_size=len(helper_bytes),
    )


def data_locks() -> dict[str, Any]:
    try:
        registry = strict_json_text(
            DATA_LOCKS.read_text(encoding="utf-8"), "DATA_LOCKS.json"
        )
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
        f"raw_unthinned_chain_audit_{branch}.json",
    }


def _parse_aggregate_manifest_bytes(data: bytes, branch: str) -> dict[str, str]:
    """Parse the exact manifest bytes captured by the stable-root snapshot."""

    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"aggregate manifest is not valid UTF-8: {error}")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
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
    return entries


def _inspect_exact_flat_root(
    root: Path,
    expected_names: set[str],
    description: str,
) -> tuple[
    tuple[int, int, int, int, int, int],
    dict[str, tuple[int, int, int, int, int, int]],
]:
    """Return identities for one exact, flat, non-link directory tree."""

    candidate = Path(root)
    try:
        root_info = os.lstat(candidate)
    except OSError as error:
        fail(f"cannot inspect {description}: {error}")
    if (
        stat.S_ISLNK(root_info.st_mode)
        or _has_reparse_point(root_info)
        or not stat.S_ISDIR(root_info.st_mode)
    ):
        fail(f"{description} must be an existing non-link directory")
    try:
        children = list(candidate.iterdir())
    except OSError as error:
        fail(f"cannot enumerate {description}: {error}")
    actual_names = [path.name for path in children]
    if len(actual_names) != len(set(actual_names)) or set(actual_names) != expected_names:
        fail(
            f"{description} must be an exact flat tree; file set differs: "
            f"expected={sorted(expected_names)}, found={sorted(actual_names)}"
        )
    identities: dict[str, tuple[int, int, int, int, int, int]] = {}
    unsafe_children: list[str] = []
    for path in children:
        try:
            info = os.lstat(path)
        except OSError as error:
            fail(f"cannot inspect {description} child {path.name}: {error}")
        if (
            stat.S_ISLNK(info.st_mode)
            or _has_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
        ):
            unsafe_children.append(path.name)
        identities[path.name] = _file_identity(info)
    if unsafe_children:
        fail(
            f"{description} must be an exact flat tree of regular files; "
            f"unsafe or nested entries={sorted(unsafe_children)}"
        )
    return _file_identity(root_info), identities


def snapshot_exact_aggregate_root(
    source_root: Path,
    branch: str,
    destination_root: Path,
) -> dict[str, str]:
    """Copy and bind one immutable exact-flat-root aggregate snapshot."""

    source = Path(source_root)
    destination = Path(destination_root)
    manifest_name = f"SHA256SUMS_{branch}_aggregate.txt"
    expected_files = expected_aggregate_files(branch)
    expected_tree = expected_files | {manifest_name}
    root_before, children_before = _inspect_exact_flat_root(
        source, expected_tree, "aggregate artifact root"
    )
    try:
        destination.mkdir(parents=False, exist_ok=False)
    except OSError as error:
        fail(f"cannot create private aggregate snapshot root: {error}")

    manifest_snapshot = _snapshot_regular_file(
        source / manifest_name,
        "aggregate manifest",
        destination=destination / manifest_name,
        capture_bytes=True,
        maximum_bytes=MAX_AGGREGATE_MANIFEST_BYTES,
    )
    if manifest_snapshot.data is None:
        fail("internal aggregate-manifest snapshot capture failed")
    entries = _parse_aggregate_manifest_bytes(manifest_snapshot.data, branch)
    for name in sorted(expected_files):
        snapshot = _snapshot_regular_file(
            source / name,
            f"aggregate artifact {name}",
            destination=destination / name,
        )
        if snapshot.sha256 != entries[name]:
            fail(
                f"SHA-256 mismatch for {name}: "
                f"{snapshot.sha256} != {entries[name]}"
            )

    root_after, children_after = _inspect_exact_flat_root(
        source, expected_tree, "aggregate artifact root"
    )
    if root_after != root_before or children_after != children_before:
        fail("aggregate artifact root changed while its stable snapshot was captured")
    _inspect_exact_flat_root(
        destination, expected_tree, "private aggregate snapshot root"
    )
    return entries


def verify_manifest(root: Path, branch: str) -> dict[str, str]:
    """Verify one exact flat manifest root through stable single-FD reads."""

    candidate = Path(root)
    manifest_name = f"SHA256SUMS_{branch}_aggregate.txt"
    expected_files = expected_aggregate_files(branch)
    expected_tree = expected_files | {manifest_name}
    root_before, children_before = _inspect_exact_flat_root(
        candidate, expected_tree, "aggregate artifact root"
    )
    manifest_snapshot = _snapshot_regular_file(
        candidate / manifest_name,
        "aggregate manifest",
        capture_bytes=True,
        maximum_bytes=MAX_AGGREGATE_MANIFEST_BYTES,
    )
    if manifest_snapshot.data is None:
        fail("internal aggregate-manifest stable read failed")
    entries = _parse_aggregate_manifest_bytes(manifest_snapshot.data, branch)
    for name, expected in entries.items():
        snapshot = _snapshot_regular_file(
            candidate / name, f"aggregate artifact {name}"
        )
        if snapshot.sha256 != expected:
            fail(f"SHA-256 mismatch for {name}: {snapshot.sha256} != {expected}")
    root_after, children_after = _inspect_exact_flat_root(
        candidate, expected_tree, "aggregate artifact root"
    )
    if root_after != root_before or children_after != children_before:
        fail("aggregate artifact root changed during manifest verification")
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


def verify_raw_chain_audit(
    root: Path,
    branch: str,
    summary: dict[str, Any],
    entries: dict[str, str],
) -> None:
    """Verify public evidence that all private raw chains passed recomputation."""

    gate = require_dict(
        summary.get("raw_unthinned_chain_acceptance_gate"),
        "raw unthinned-chain acceptance gate",
    )
    expected_gate_keys = {
        "required",
        "verified",
        "schema_version",
        "format",
        "trials_verified",
        "global_trial_identity_sha256",
        "evidence_report_file",
        "evidence_report_sha256",
        "audit_helper_file",
        "audit_helper_sha256",
        "raw_files_copied_to_public_artifact",
    }
    if set(gate) != expected_gate_keys:
        fail("raw unthinned-chain gate has an invalid field set")
    if gate.get("required") is not True or gate.get("verified") is not True:
        fail("raw unthinned-chain gate is not required and verified")
    require_exact_integer(
        gate.get("schema_version"),
        RAW_CHAIN_SCHEMA_VERSION,
        "raw-chain schema version",
    )
    require_exact_integer(
        gate.get("trials_verified"),
        V404_SCALE["total_trials"],
        "raw-chain verified trial count",
    )
    if gate.get("format") != RAW_CHAIN_FORMAT:
        fail("raw-chain binary format mismatch")
    if gate.get("raw_files_copied_to_public_artifact") is not False:
        fail("raw-chain bytes were not explicitly excluded from the public artifact")
    report_name = f"raw_unthinned_chain_audit_{branch}.json"
    if gate.get("evidence_report_file") != report_name or report_name not in entries:
        fail("raw-chain evidence report binding mismatch")
    if gate.get("evidence_report_sha256") != entries[report_name]:
        fail("raw-chain evidence report SHA-256 mismatch")
    if gate.get("audit_helper_file") != RAW_CHAIN_HELPER.name:
        fail("raw-chain audit helper filename mismatch")
    if RAW_CHAIN_HELPER.is_symlink() or not RAW_CHAIN_HELPER.is_file():
        fail("raw-chain audit helper is missing or unsafe")
    helper_hash = sha256(RAW_CHAIN_HELPER)
    if gate.get("audit_helper_sha256") != helper_hash:
        fail("raw-chain audit helper SHA-256 mismatch")
    identity_hash = gate.get("global_trial_identity_sha256")
    if not isinstance(identity_hash, str) or not SHA256_RE.fullmatch(identity_hash):
        fail("raw-chain global identity digest is invalid")

    try:
        report = strict_json_text(
            (root / report_name).read_text(encoding="utf-8"),
            "raw unthinned-chain audit report",
        )
    except (OSError, UnicodeError) as error:
        fail(f"cannot read raw unthinned-chain audit report: {error}")
    expected_report_keys = {
        "schema_version",
        "status",
        "branch",
        "format",
        "storage_policy",
        "parameter_order_source",
        "payload_field_order",
        "audit_algorithm",
        "audit_helper_file",
        "audit_helper_sha256",
        "adaptive_production_policy",
        "trials_verified",
        "expected_global_trials",
        "global_trial_identity_sha256",
        "bundles",
        "trials",
        "raw_files_copied_to_public_artifact",
    }
    if not isinstance(report, dict) or set(report) != expected_report_keys:
        fail("raw unthinned-chain audit report schema mismatch")
    expected_report_values = {
        "schema_version": RAW_CHAIN_SCHEMA_VERSION,
        "status": "PASS",
        "branch": branch,
        "format": RAW_CHAIN_FORMAT,
        "storage_policy": RAW_CHAIN_STORAGE_POLICY,
        "parameter_order_source": ["F0", "beta_inst", "alpha_radius", "gamma"],
        "payload_field_order": [
            "F0",
            "beta_inst",
            "alpha_radius",
            "gamma",
            "log_probability",
        ],
        "audit_helper_file": RAW_CHAIN_HELPER.name,
        "audit_helper_sha256": helper_hash,
        "trials_verified": V404_SCALE["total_trials"],
        "expected_global_trials": V404_SCALE["total_trials"],
        "global_trial_identity_sha256": identity_hash,
        "raw_files_copied_to_public_artifact": False,
    }
    if any(report.get(key) != value for key, value in expected_report_values.items()):
        fail("raw unthinned-chain audit report identity mismatch")
    if not isinstance(report.get("audit_algorithm"), str) or not report[
        "audit_algorithm"
    ]:
        fail("raw-chain audit algorithm is missing")

    policy = require_dict(
        report.get("adaptive_production_policy"),
        "raw-chain adaptive production policy",
    )
    accepted_policy = require_dict(
        require_dict(
            summary.get("production_acceptance_gate"),
            "production acceptance gate",
        ).get("adaptive_production_policy"),
        "accepted adaptive production policy",
    )
    if policy != accepted_policy:
        fail("raw-chain and aggregate adaptive policies differ")

    bundles = report.get("bundles")
    if not isinstance(bundles, list) or len(bundles) != V404_SCALE["shards"]:
        fail("raw-chain bundle audit set is incomplete")
    bundle_keys = {
        "shard",
        "run_label",
        "index_file",
        "index_sha256",
        "manifest_file",
        "manifest_sha256",
        "trial_count",
    }
    for expected_shard, bundle in enumerate(bundles):
        if not isinstance(bundle, dict) or set(bundle) != bundle_keys:
            fail("raw-chain bundle audit schema mismatch")
        require_exact_integer(bundle.get("shard"), expected_shard, "raw bundle shard")
        require_exact_integer(
            bundle.get("trial_count"),
            V404_SCALE["trials_per_shard"],
            "raw bundle trial count",
        )
        label = f"production-shard-{expected_shard}"
        if (
            bundle.get("run_label") != label
            or bundle.get("index_file")
            != f"raw_chain_index_{branch}_{label}.json"
            or bundle.get("manifest_file")
            != f"SHA256SUMS_raw_chain_{branch}_{label}.txt"
        ):
            fail("raw-chain bundle filename identity mismatch")
        for key in ("index_sha256", "manifest_sha256"):
            value = bundle.get(key)
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                fail(f"invalid raw-chain bundle {key}")

    trials = report.get("trials")
    if not isinstance(trials, list) or len(trials) != V404_SCALE["total_trials"]:
        fail("raw-chain trial audit set is incomplete")
    trial_keys = {
        "global_trial",
        "shard",
        "run_label",
        "trial",
        "trial_seed",
        "mcmc_seed",
        "raw_chain_file",
        "raw_chain_sha256",
        "raw_chain_size_bytes",
        "production_steps",
        "walkers",
        "recomputed_autocorrelation_time_source_order",
        "recomputed_effective_sample_size_source_order",
        "recomputed_convergence_checks",
        "first_accepted_steps",
        "converged",
        "serialized_thinned_chain_match",
    }
    identity_projection: list[dict[str, Any]] = []
    observed_raw_hashes: set[str] = set()
    for expected_global_trial, trial_record in enumerate(trials):
        if not isinstance(trial_record, dict) or set(trial_record) != trial_keys:
            fail("raw-chain trial audit schema mismatch")
        shard, trial = divmod(
            expected_global_trial, V404_SCALE["trials_per_shard"]
        )
        for key, expected in (
            ("global_trial", expected_global_trial),
            ("shard", shard),
            ("trial", trial),
            ("walkers", V404_SCALE["walkers"]),
        ):
            require_exact_integer(
                trial_record.get(key), expected, f"raw trial {key}"
            )
        label = f"production-shard-{shard}"
        expected_trial_seed = 2026082200 + (
            100000 if branch == "zero" else 0
        ) + shard * 1000 + 1_000_003 * trial
        expected_mcmc_seed = expected_trial_seed + 500000003
        if (
            trial_record.get("run_label") != label
            or trial_record.get("trial_seed") != expected_trial_seed
            or trial_record.get("mcmc_seed") != expected_mcmc_seed
            or trial_record.get("raw_chain_file")
            != f"raw_production_chain_{branch}_{label}_trial-{trial:03d}.bin"
        ):
            fail("raw-chain trial identity or seed schedule mismatch")
        raw_hash = trial_record.get("raw_chain_sha256")
        if not isinstance(raw_hash, str) or not SHA256_RE.fullmatch(raw_hash):
            fail("raw-chain trial SHA-256 is invalid")
        if raw_hash in observed_raw_hashes:
            fail("raw-chain trial SHA-256 is duplicated across trial identities")
        observed_raw_hashes.add(raw_hash)
        size_bytes = trial_record.get("raw_chain_size_bytes")
        production_steps = trial_record.get("production_steps")
        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
            or isinstance(production_steps, bool)
            or not isinstance(production_steps, int)
            or production_steps < V404_SCALE["production_steps_requested_minimum"]
            or production_steps > accepted_policy["requested_maximum_steps"]
        ):
            fail("raw-chain trial size or completed-step count is invalid")
        expected_size_bytes = RAW_CHAIN_HEADER_SIZE_BYTES + (
            production_steps
            * V404_SCALE["walkers"]
            * RAW_CHAIN_PAYLOAD_FIELDS
            * RAW_CHAIN_FLOAT_SIZE_BYTES
        )
        if size_bytes != expected_size_bytes:
            fail("raw-chain trial size does not match its exact binary schema")
        if (
            trial_record.get("converged") is not True
            or trial_record.get("serialized_thinned_chain_match") is not True
            or trial_record.get("first_accepted_steps") != production_steps
        ):
            fail("raw-chain trial did not pass its first stopping gate")
        tau = trial_record.get("recomputed_autocorrelation_time_source_order")
        ess = trial_record.get("recomputed_effective_sample_size_source_order")
        checks = trial_record.get("recomputed_convergence_checks")
        if (
            not isinstance(tau, list)
            or len(tau) != 4
            or not isinstance(ess, list)
            or len(ess) != 4
            or not isinstance(checks, list)
            or not checks
        ):
            fail("raw-chain recomputed tau/ESS/checkpoint evidence is incomplete")
        checkpoint_keys = {
            "production_steps",
            "autocorrelation_time",
            "length_ok",
            "stable",
            "max_relative_tau_change",
            "stable_check_streak",
        }
        expected_checkpoint_steps = list(
            range(
                accepted_policy["requested_minimum_steps"],
                production_steps + 1,
                accepted_policy["check_interval"],
            )
        )
        if len(checks) != len(expected_checkpoint_steps):
            fail("raw-chain checkpoint count does not match the adaptive schedule")
        previous_tau: list[float] | None = None
        stable_streak = 0
        for checkpoint_index, (checkpoint, expected_steps) in enumerate(
            zip(checks, expected_checkpoint_steps)
        ):
            if not isinstance(checkpoint, dict) or set(checkpoint) != checkpoint_keys:
                fail("raw-chain checkpoint schema mismatch")
            require_exact_integer(
                checkpoint.get("production_steps"),
                expected_steps,
                f"raw checkpoint {checkpoint_index} production steps",
            )
            checkpoint_tau = checkpoint.get("autocorrelation_time")
            if checkpoint_tau is None:
                current_tau = None
                length_ok = False
                stable = False
                relative_change = None
            else:
                if not isinstance(checkpoint_tau, list) or len(checkpoint_tau) != 4:
                    fail("raw-chain checkpoint tau has an invalid shape")
                current_tau = [
                    require_finite_number(
                        value, f"raw checkpoint {checkpoint_index} tau"
                    )
                    for value in checkpoint_tau
                ]
                if any(value <= 0.0 for value in current_tau):
                    fail("raw-chain checkpoint tau is not positive")
                length_ok = all(
                    expected_steps >= accepted_policy["tau_multiple"] * value
                    for value in current_tau
                )
                relative_change = (
                    None
                    if previous_tau is None
                    else max(
                        abs(current - previous) / current
                        for current, previous in zip(current_tau, previous_tau)
                    )
                )
                stable = bool(
                    relative_change is not None
                    and relative_change
                    <= accepted_policy["tau_relative_tolerance"]
                )
            if checkpoint.get("length_ok") is not length_ok:
                fail("raw-chain checkpoint length decision is inconsistent")
            if checkpoint.get("stable") is not stable:
                fail("raw-chain checkpoint stability decision is inconsistent")
            declared_change = checkpoint.get("max_relative_tau_change")
            if relative_change is None:
                if declared_change is not None:
                    fail("raw-chain checkpoint relative tau change is inconsistent")
            else:
                observed_change = require_finite_number(
                    declared_change,
                    f"raw checkpoint {checkpoint_index} relative tau change",
                )
                if not math.isclose(
                    observed_change,
                    relative_change,
                    rel_tol=1.0e-12,
                    abs_tol=1.0e-12,
                ):
                    fail("raw-chain checkpoint relative tau change is inconsistent")
            stable_streak = stable_streak + 1 if length_ok and stable else 0
            require_exact_integer(
                checkpoint.get("stable_check_streak"),
                stable_streak,
                f"raw checkpoint {checkpoint_index} stable streak",
            )
            if (
                stable_streak
                >= accepted_policy["required_consecutive_stable_checks"]
                and checkpoint_index != len(checks) - 1
            ):
                fail("raw-chain checkpoints continue after the first accepted gate")
            if current_tau is not None:
                previous_tau = current_tau
        for index, (tau_value, ess_value) in enumerate(zip(tau, ess)):
            tau_number = require_finite_number(tau_value, f"raw tau {index}")
            ess_number = require_finite_number(ess_value, f"raw ESS {index}")
            if tau_number <= 0.0 or not math.isclose(
                ess_number,
                V404_SCALE["walkers"] * production_steps / tau_number,
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            ):
                fail("raw-chain recomputed ESS does not match steps/walkers/tau")
            if ess_number < require_finite_number(
                require_dict(
                    summary.get("production_acceptance_gate"),
                    "production acceptance gate",
                ).get("minimum_ess_per_realization"),
                "production ESS threshold",
            ):
                fail("raw-chain recomputed ESS is below the production threshold")
        final_check = require_dict(checks[-1], "raw-chain final checkpoint")
        if (
            final_check.get("production_steps") != production_steps
            or final_check.get("autocorrelation_time") != tau
            or final_check.get("length_ok") is not True
            or final_check.get("stable") is not True
            or final_check.get("stable_check_streak")
            != accepted_policy["required_consecutive_stable_checks"]
        ):
            fail("raw-chain final checkpoint is inconsistent")
        identity_projection.append(
            {
                key: trial_record[key]
                for key in (
                    "global_trial",
                    "shard",
                    "trial",
                    "run_label",
                    "trial_seed",
                    "mcmc_seed",
                    "raw_chain_sha256",
                )
            }
        )
    recomputed_identity_hash = hashlib.sha256(
        json.dumps(
            identity_projection,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if recomputed_identity_hash != identity_hash:
        fail("raw-chain global identity digest does not match its trial map")


def _parse_nonnegative_integer(raw: Any, description: str) -> int:
    text = str(raw)
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        fail(f"{description} is not a canonical non-negative integer: {text!r}")
    return int(text)


def _linear_quantiles(values: list[float]) -> dict[str, float]:
    if not values:
        fail("cannot compute quantiles of an empty posterior")
    ordered = sorted(values)
    maximum_index = len(ordered) - 1
    result: dict[str, float] = {}
    for name, probability in zip(QUANTILE_NAMES, QUANTILE_PROBABILITIES):
        rank = maximum_index * probability
        lower = int(math.floor(rank))
        upper = int(math.ceil(rank))
        fraction = rank - lower
        result[name] = (
            ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction
        )
    return result


def _verify_quantile_record(
    summary: dict[str, Any], key: str, values: dict[str, list[float]]
) -> None:
    record = require_dict(summary.get(key), key)
    if set(record) != set(PARAMETERS):
        fail(f"{key} does not contain the exact parameter set")
    for parameter in PARAMETERS:
        declared = require_dict(record.get(parameter), f"{key}:{parameter}")
        if set(declared) != set(QUANTILE_NAMES):
            fail(f"{key}:{parameter} does not contain the exact quantile set")
        actual = _linear_quantiles(values[parameter])
        previous = -math.inf
        for name in QUANTILE_NAMES:
            observed = require_finite_number(
                declared.get(name), f"{key}:{parameter}:{name}"
            )
            if observed < previous:
                fail(f"{key}:{parameter} quantiles are unordered")
            previous = observed
            if not math.isclose(
                observed, actual[name], rel_tol=1.0e-12, abs_tol=1.0e-12
            ):
                fail(f"{key}:{parameter}:{name} does not match its CSV")


def verify_full_and_propagation_csv(
    root: Path, branch: str, summary: dict[str, Any]
) -> None:
    """Bind full/posterior summaries and the stride-2 propagation sample."""

    full_path = root / f"joint_posterior_{branch}_full.csv.gz"
    propagation_path = (
        root / f"joint_posterior_{branch}_for_galactic_propagation.csv.gz"
    )
    full_counts = [0] * V404_SCALE["total_trials"]
    propagation_counts = [0] * V404_SCALE["total_trials"]
    full_values = {parameter: [] for parameter in PARAMETERS}
    propagation_values = {parameter: [] for parameter in PARAMETERS}
    full_row_count = 0
    propagation_row_count = 0
    previous_coordinate: tuple[int, int, int] | None = None
    try:
        with gzip.open(
            full_path, "rt", encoding="utf-8", newline=""
        ) as full_handle, gzip.open(
            propagation_path, "rt", encoding="utf-8", newline=""
        ) as propagation_handle:
            full_reader = csv.DictReader(full_handle)
            propagation_reader = csv.DictReader(propagation_handle)
            if full_reader.fieldnames != list(FULL_COLUMNS):
                fail(
                    "full posterior CSV header mismatch: "
                    f"expected={list(FULL_COLUMNS)}, found={full_reader.fieldnames}"
                )
            if propagation_reader.fieldnames != list(PROPAGATION_COLUMNS):
                fail(
                    "propagation CSV header mismatch: "
                    f"expected={list(PROPAGATION_COLUMNS)}, "
                    f"found={propagation_reader.fieldnames}"
                )
            for row_number, row in enumerate(full_reader, 2):
                if set(row) != set(FULL_COLUMNS) or row.get("branch") != branch:
                    fail(f"invalid full posterior CSV row {row_number}")
                shard = _parse_nonnegative_integer(row.get("shard"), "shard")
                trial = _parse_nonnegative_integer(row.get("trial"), "trial")
                global_trial = _parse_nonnegative_integer(
                    row.get("global_trial"), "global_trial"
                )
                _parse_nonnegative_integer(row.get("trial_seed"), "trial_seed")
                _parse_nonnegative_integer(row.get("mcmc_seed"), "mcmc_seed")
                production_step = _parse_nonnegative_integer(
                    row.get("production_step"), "production_step"
                )
                walker = _parse_nonnegative_integer(row.get("walker"), "walker")
                if (
                    shard >= V404_SCALE["shards"]
                    or trial >= V404_SCALE["trials_per_shard"]
                    or global_trial != shard * V404_SCALE["trials_per_shard"] + trial
                    or row.get("run_label") != f"production-shard-{shard}"
                ):
                    fail(f"full posterior identity mismatch at row {row_number}")
                if global_trial >= len(full_counts):
                    fail(f"out-of-range global_trial at full posterior row {row_number}")
                coordinate = (global_trial, production_step, walker)
                if previous_coordinate is not None and coordinate <= previous_coordinate:
                    fail(
                        "full posterior coordinates are not in strict canonical "
                        f"(global_trial, production_step, walker) order at row {row_number}"
                    )
                previous_coordinate = coordinate
                within_trial = full_counts[global_trial]
                full_counts[global_trial] += 1
                try:
                    log_probability = float(row["log_probability"])
                except (TypeError, ValueError) as error:
                    fail(f"invalid log_probability at full posterior row {row_number}: {error}")
                if not math.isfinite(log_probability):
                    fail(f"non-finite log_probability at full posterior row {row_number}")
                for parameter in PARAMETERS:
                    try:
                        value = float(row[parameter])
                    except (TypeError, ValueError) as error:
                        fail(
                            f"invalid {parameter} at full posterior row {row_number}: "
                            f"{error}"
                        )
                    if not math.isfinite(value):
                        fail(f"non-finite {parameter} at full posterior row {row_number}")
                    full_values[parameter].append(value)
                if float(row["source_theta1_beta_inst"]) != float(row["beta"]):
                    fail(f"beta source-order alias mismatch at full posterior row {row_number}")
                if float(row["source_theta2_alpha_radius"]) != float(row["alpha"]):
                    fail(f"alpha source-order alias mismatch at full posterior row {row_number}")

                if within_trial % V404_SCALE[
                    "propagation_stride_within_each_realization"
                ] == 0:
                    propagated = next(propagation_reader, None)
                    if propagated is None:
                        fail("propagation CSV ended before the stride-derived sample")
                    propagation_row_count += 1
                    if (
                        set(propagated) != set(PROPAGATION_COLUMNS)
                        or propagated.get("branch") != branch
                        or any(
                            propagated[column] != row[column]
                            for column in PROPAGATION_COLUMNS
                        )
                    ):
                        fail(
                            "propagation row is not the exact stride-derived full row "
                            f"at propagation row {propagation_row_count + 1}"
                        )
                    propagation_trial = _parse_nonnegative_integer(
                        propagated.get("global_trial"),
                        "propagation global_trial",
                    )
                    if propagation_trial >= len(propagation_counts):
                        fail(
                            "out-of-range global_trial at propagation row "
                            f"{propagation_row_count + 1}"
                        )
                    propagation_counts[propagation_trial] += 1
                    for parameter in PARAMETERS:
                        propagation_values[parameter].append(
                            float(propagated[parameter])
                        )
                full_row_count += 1
            if next(propagation_reader, None) is not None:
                fail("propagation CSV contains rows beyond the stride-derived sample")
    except (OSError, UnicodeError, csv.Error, TypeError, ValueError, OverflowError) as error:
        fail(f"cannot validate full/propagation CSVs: {error}")
    if full_row_count != V404_SCALE["full_sample_count"]:
        fail(
            f"full posterior row count mismatch: {full_row_count} != "
            f"{V404_SCALE['full_sample_count']}"
        )
    if any(
        count != V404_SCALE["equalized_samples_per_realization"]
        for count in full_counts
    ):
        fail("full posterior does not represent every realization equally")
    if propagation_row_count != V404_SCALE["galactic_propagation_sample_count"]:
        fail(
            f"propagation CSV row count mismatch: {propagation_row_count} != "
            f"{V404_SCALE['galactic_propagation_sample_count']}"
        )
    expected_propagation_per_trial = math.ceil(
        V404_SCALE["equalized_samples_per_realization"]
        / V404_SCALE["propagation_stride_within_each_realization"]
    )
    if any(count != expected_propagation_per_trial for count in propagation_counts):
        fail("propagation CSV does not represent every realization equally")
    _verify_quantile_record(summary, "posterior_quantiles", full_values)
    _verify_quantile_record(
        summary,
        "galactic_propagation_posterior_quantiles",
        propagation_values,
    )


def verify_summary(
    root: Path, branch: str, expected_source_sha256: str, entries: dict[str, str]
) -> dict[str, Any]:
    summary_name = f"joint_posterior_{branch}_aggregate_summary.json"
    propagation_name = f"joint_posterior_{branch}_for_galactic_propagation.csv.gz"
    for required in (summary_name, propagation_name):
        if required not in entries:
            fail(f"aggregate manifest lacks required file: {required}")

    try:
        summary = strict_json_text(
            (root / summary_name).read_text(encoding="utf-8"),
            "aggregate summary",
        )
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
    else:
        allowed_profiles.add(V404_LEGACY_SENSITIVITY_PROFILE)
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

    measurement_mode_for_profile(branch, summary)
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
    verify_full_and_propagation_csv(root, branch, summary)
    verify_raw_chain_audit(root, branch, summary, entries)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--expected-bryson-source-sha256", required=True)
    parser.add_argument("--pc-catalog", required=True, type=Path)
    parser.add_argument("--stellar-catalog", required=True, type=Path)
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
    source_root = Path(args.artifact_root)
    with tempfile.TemporaryDirectory(
        prefix=f"accepted-{args.branch}-aggregate-snapshot-"
    ) as temporary:
        stable_root = Path(temporary) / "aggregate"
        entries = snapshot_exact_aggregate_root(
            source_root,
            args.branch,
            stable_root,
        )
        summary = verify_summary(
            stable_root,
            args.branch,
            expected_source_sha256,
            entries,
        )
        catalog_report = verify_catalog_perturbation_replay(
            root=stable_root,
            branch=args.branch,
            summary=summary,
            entries=entries,
            pc_catalog=args.pc_catalog,
            stellar_catalog=args.stellar_catalog,
        )
    print(
        f"PASS accepted {args.branch} aggregate "
        f"({len(entries)} manifest-locked files; "
        f"{catalog_report['trials_verified']} catalog replays)"
    )


if __name__ == "__main__":
    main()
