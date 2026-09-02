#!/usr/bin/env python3
"""Fail-closed local v4.0.4 MCMC, aggregation, and propagation controller.

The controller is intentionally limited to the expensive posterior portion of
the release.  It consumes already qualified host artifacts and locked external
inputs, runs only from an extracted byte-identical source archive, retains
pilots, shard products, logs, and raw chains below private roots, and writes
only release-safe qualification audits, accepted aggregates, and Galactic
propagations below the public root.

It does not freeze release metadata or publish anything.
"""

from __future__ import annotations

import os as _bootstrap_os
import sys as _bootstrap_sys


if __name__ == "__main__" and not _bootstrap_sys.flags.isolated:
    _flags = ["-I", "-B"]
    if _bootstrap_sys.flags.optimize:
        _flags.append("-" + "O" * _bootstrap_sys.flags.optimize)
    _bootstrap_os.execv(
        _bootstrap_sys.executable,
        [
            _bootstrap_sys.executable,
            *_flags,
            _bootstrap_os.path.abspath(__file__),
            *_bootstrap_sys.argv[1:],
        ],
    )

import argparse
import ast
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
SOURCE_ARCHIVE_MAX_BYTES = 256_000_000
EXPECTED_BRYSON_SOURCE_SHA256 = (
    "0bb479b0c94c4f793b95e4fa1e853973805c54d3de7e2a2acc2e51c05b70a586"
)
EXPECTED_PRODUCTION_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production"
)
EXPECTED_PRODUCTION_REPOSITORY_ID = 1_342_924_728
EXPECTED_RELEASE_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
)
EXPECTED_RELEASE_REPOSITORY_ID = 1_343_894_071
EXPECTED_SENSITIVITY_ARTIFACT_NAME = "jj-g-host-export-padova-dr05-tams-canonical"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMMAND_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

CORRECTED_MODE = "quantile_matched_two_sided"
LEGACY_MODE = "legacy_source_mixture"
CANONICAL_HOST_NAME = "jj_g_hosts_raw_eligible_padova.csv"
LEGACY_HOST_NAME = "jj_g_hosts_raw_eligible_padova_legacy_logg43.csv"
PARENT_HOST_NAME = "jj_g_hosts_parent_prelogg_padova.csv"
HOST_CONTRACT_NAME = "HOST_ARTIFACT_CONTRACT_v4_0_4.json"

NUMERICAL_ENVIRONMENT = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
REQUIRED_RUNTIME_PINS = {
    "astropy": "5.3.4",
    "emcee": "3.1.6",
    "numpy": "1.23.5",
    "pandas": "1.5.3",
    "scipy": "1.10.1",
}

PILOT_TRIALS = 3
SHARDS = 16
TRIALS_PER_SHARD = 25
MAXIMUM_PARALLEL_SHARDS = 4
PLAN_LABEL = "v4.0.4-local-production"
PLAN_COMMAND_ID = "run-v404-local-production"
RECOVERY_PLAN_LABEL = "v4.0.4-local-production-recover-mcmc"
RECOVERY_PLAN_COMMAND_ID = "run-v404-local-production-recover-mcmc"
RECOVERY_CONTRACT_ID = "mcmc-recovery-artifact-v4.0.4"
RECOVERY_COPY_POLICY = "byte-copy-no-links"
RECOVERY_CONTRACT_SCHEMA_VERSION = 2
DONOR_ATTESTATION_CONTRACT_ID = "local-production-run-v4.0.4"
DONOR_START_NAMESPACE = "exoearth-local-production-start-v4.0.4"
DONOR_START_SIGNER_ID = "v404-local-attestor-a"
DONOR_START_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF6o39g15REJBdvRMh21U9DUs+spMaeeIVw7seFaqWwi "
    "v4.0.4-local-attestor-a"
)
DONOR_START_NAME = "LOCAL_RUN_START_CHALLENGE.json"
DONOR_START_SIGNATURE_NAME = f"{DONOR_START_NAME}.sig"
DONOR_STDOUT_NAME = "COMMAND_000_run-v404-local-production.stdout.bin"
DONOR_STDERR_NAME = "COMMAND_000_run-v404-local-production.stderr.bin"
DONOR_EVIDENCE_FILES = (
    DONOR_START_NAME,
    DONOR_START_SIGNATURE_NAME,
    DONOR_STDOUT_NAME,
    DONOR_STDERR_NAME,
)
RECOVERY_MCMC_SOURCE_PREFIX = "research/bryson-joint-posterior/"
RECOVERY_MCMC_SOURCE_FIXED_PATHS = (
    "provenance/DATA_LOCKS.json",
    "requirements.in",
    "requirements.txt",
    "scripts/verify_dependency_lock.py",
    "scripts/verify_numerical_runtime.py",
)
DONOR_CANDIDATE_ID = "v4.0.4-local-production-pending"
RECOVERY_WORK_FILE_COUNT = 384
RECOVERY_RAW_FILE_COUNT = 1_296
RECOVERY_TOTAL_FILE_COUNT = 1_680
RECOVERY_WORK_SIZE_BYTES = 3_498_332_085
RECOVERY_RAW_SIZE_BYTES = 10_002_742_894
RECOVERY_TOTAL_SIZE_BYTES = 13_501_074_979
RECOVERY_WORK_TREE_SHA256 = (
    "971459488817641a29032aa36bfe37581a8a276ef3dd5ee11b7b07a307a05118"
)
RECOVERY_RAW_TREE_SHA256 = (
    "98bb6ba382ccb626372a21b8dbf741e7b4fc6298e4104de0fb30b012052570d9"
)
RECOVERY_MCMC_POLICY_SHA256 = (
    "206968f982cccee67caa00a6b23442602716289cc17d0304fedac38ac376a59e"
)
TRACKED_CONTROLLER_PATH = "scripts/run_v404_local_production.py"
ATTESTATION_VALIDATOR_NAME = "verify_local_run_attestation.py"
RECOVERY_MCMC_POLICY_ASSIGNMENTS = (
    "CORRECTED_MODE",
    "LEGACY_MODE",
    "NUMERICAL_ENVIRONMENT",
    "REQUIRED_RUNTIME_PINS",
    "PILOT_TRIALS",
    "SHARDS",
    "TRIALS_PER_SHARD",
    "MAXIMUM_PARALLEL_SHARDS",
    "WALKERS",
    "BURNIN",
    "MINIMUM_STEPS",
    "RUNNER_THIN",
    "CHECK_INTERVAL",
    "TAU_MULTIPLE",
    "TAU_RELATIVE_TOLERANCE",
    "TAU_STABILITY_CHECKS",
    "MCMC_SEED_OFFSET_A",
    "MCMC_SEED_OFFSET_B",
    "CONSTANT_PILOT_SEED",
    "ZERO_PILOT_SEED",
    "PRODUCTION_BASE_SEED",
    "PRODUCTION_ZERO_OFFSET",
    "SAMPLES_PER_REALIZATION",
    "BOOTSTRAP_REPLICATES",
    "AGGREGATION_BOOTSTRAP_SEED",
    "PROPAGATION_BOOTSTRAP_SEED",
    "INNER_CHAIN_BATCHES",
    "PROPAGATION_STRIDE",
    "VARIANTS",
)
RECOVERY_MCMC_POLICY_FUNCTIONS = (
    "runner_output_names",
    "raw_output_names",
    "runner_argv",
    "aggregate_argv",
    "accepted_verifier_argv",
    "propagation_argv",
    "create_numerical_environment",
    "stage_metallicity_audit",
    "create_bryson_projection",
    "run_pilots",
    "run_production_shards",
    "aggregate_and_verify",
    "reverify_accepted_aggregates",
    "propagate_variant",
    "run_likelihood_grid_audits",
    "run_dr25_support_audit",
    "run_host_tams_audit",
    "run_sensitivity_artifacts",
)
RECOVERY_CONTROLLER_ALLOWED_CLASSES = (
    "Configuration",
    "RecoveryContractBinding",
    "RecoveryImportEvidence",
)
RECOVERY_CONTROLLER_ALLOWED_FUNCTIONS = (
    "_add_recovery_arguments",
    "_exact_object",
    "_load_module_from_snapshot",
    "_matches_recovery_evidence",
    "_parse_recovery_manifest",
    "_recovery_mcmc_policy_snapshot",
    "_recovery_controller_invariant_snapshot",
    "_recovery_tree_paths",
    "_source_archive_member_bytes",
    "_stable_copy_recovery_file",
    "_validate_recovery_donor_trees",
    "_validate_recovery_evidence",
    "_validate_recovery_import_policy",
    "_validate_recovery_policy",
    "_validate_recovery_qualification",
    "_validate_recovery_self_id",
    "_validate_source_transition",
    "_write_exclusive_captured_bytes",
    "build_plan_document",
    "configuration_from_args",
    "ensure_exact_tree",
    "enumerate_plain_tree",
    "execute",
    "finalize_public_output",
    "import_recovery_shards",
    "inspect_source_archive",
    "load_strict_json",
    "load_strict_json_bytes",
    "local_production_run_argv",
    "main",
    "parser",
    "recheck_recovery_import",
    "recovery_enabled",
    "snapshot_plain_directory_chain",
    "validate_configuration",
    "validate_recovery_contract",
    "validate_recovery_lineage",
    "write_local_command_plan",
)
WALKERS = 16
BURNIN = 1000
MINIMUM_STEPS = 3000
RUNNER_THIN = 20
CHECK_INTERVAL = 1000
TAU_MULTIPLE = 100.0
TAU_RELATIVE_TOLERANCE = 0.05
TAU_STABILITY_CHECKS = 2
MCMC_SEED_OFFSET_A = 500_000_003
MCMC_SEED_OFFSET_B = 900_000_007
CONSTANT_PILOT_SEED = 2_026_082_101
ZERO_PILOT_SEED = 2_026_182_101
PRODUCTION_BASE_SEED = 2_026_082_200
PRODUCTION_ZERO_OFFSET = 100_000
SAMPLES_PER_REALIZATION = 1024
BOOTSTRAP_REPLICATES = 1000
AGGREGATION_BOOTSTRAP_SEED = 2_026_082_101
PROPAGATION_BOOTSTRAP_SEED = 2_026_082_102
INNER_CHAIN_BATCHES = 8
PROPAGATION_STRIDE = 2

REPORT_NAME = "V404_LOCAL_PRODUCTION_REPORT.json"
PUBLIC_MANIFEST_NAME = "SHA256SUMS_v404_local_production.txt"

METALLICITY_AUDIT_OUTPUT_NAMES = (
    "metallicity_tams_differential_sensitivity.json",
    "native_solar_tams_nodes.csv",
    "NUMERICAL_RUNTIME_POLICY.json",
    "PROVENANCE_METALLICITY_DIFFERENTIAL.md",
    "SHA256SUMS_all.txt",
)
HOST_TAMS_AUDIT_OUTPUT_NAMES = (
    "host_tams_audit.json",
    "host_selector_sensitivity.csv",
    "SHA256SUMS_host_tams_audit.txt",
)
DR25_SUPPORT_OUTPUT_NAMES = (
    "dr25_support_audit.json",
    "dr25_target_counts_by_trial.csv",
    "SHA256SUMS_dr25_support_public.txt",
)
DR25_PRIVATE_OUTPUT_NAMES = (
    "dr25_perturbed_candidate_frequency.csv",
    "dr25_nominal_near_support.csv",
)
SENSITIVITY_ARTIFACT_OUTPUT_NAMES = (
    "bryson_model_form_sensitivity.json",
    "hz_sensitivity_results.json",
    "tams_all_branch_results.json",
    "RUN_PROVENANCE.json",
    "SHA256SUMS_sensitivity_artifacts.txt",
)


class OrchestrationError(RuntimeError):
    """Raised when any execution or provenance condition fails closed."""


def fail(message: str) -> None:
    raise OrchestrationError(message)


def _has_reparse_point(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int]
    data: bytes | None = None


def snapshot_file(
    path: Path,
    description: str,
    *,
    collect: bool = False,
    maximum_bytes: int | None = None,
) -> FileSnapshot:
    """Hash one regular file through one descriptor and reject path swaps."""

    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if (
        stat.S_ISLNK(before.st_mode)
        or _has_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        fail(f"{description} must be a regular non-link file: {candidate}")
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        fail(f"{description} exceeds its byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if collect else None
    descriptor = -1
    size = 0
    try:
        descriptor = os.open(candidate, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            fail(f"opened {description} is not a regular file")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if maximum_bytes is not None and size > maximum_bytes:
                fail(f"{description} exceeds its byte limit")
            if chunks is not None:
                chunks.append(block)
        opened_after = os.fstat(descriptor)
    except OSError as exc:
        fail(f"cannot read {description}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    observed_identity = _identity(opened_before)
    if (
        observed_identity != _identity(opened_after)
        or observed_identity != _identity(before)
        or observed_identity != _identity(after)
        or stat.S_ISLNK(after.st_mode)
        or _has_reparse_point(after)
        or size != opened_before.st_size
    ):
        fail(f"{description} changed during its stable snapshot")
    return FileSnapshot(
        path=candidate,
        sha256=digest.hexdigest(),
        size_bytes=size,
        identity=observed_identity,
        data=b"".join(chunks) if chunks is not None else None,
    )


def recheck_snapshot(snapshot: FileSnapshot, description: str) -> None:
    current = snapshot_file(snapshot.path, description)
    if (
        current.sha256 != snapshot.sha256
        or current.size_bytes != snapshot.size_bytes
        or current.identity != snapshot.identity
    ):
        fail(f"{description} changed after pre-flight")


def snapshot_directory_identity(path: Path, description: str) -> tuple[Path, tuple[int, int, int, int, int]]:
    """Bind one real directory path to its identity without following redirects."""

    candidate = Path(path)
    try:
        status = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if (
        stat.S_ISLNK(status.st_mode)
        or _has_reparse_point(status)
        or not stat.S_ISDIR(status.st_mode)
    ):
        fail(f"{description} must be a real non-link directory")
    resolved = candidate.resolve(strict=True)
    try:
        resolved_status = resolved.lstat()
    except OSError as exc:
        fail(f"cannot resolve {description}: {exc}")
    if _identity(status) != _identity(resolved_status):
        fail(f"{description} changed while its identity was captured")
    return resolved, _identity(status)


def snapshot_exact_aggregate(root: Path, branch: str) -> ExactAggregateRoot:
    """Capture the exact eight-file accepted aggregate as one stable object."""

    resolved, root_identity = snapshot_directory_identity(
        root, f"{branch} accepted aggregate root"
    )
    names = aggregate_output_names(branch)
    ensure_exact_files(resolved, names, f"{branch} accepted aggregate")
    snapshots = tuple(
        snapshot_file(resolved / name, f"{branch} accepted aggregate file {name}")
        for name in names
    )
    ensure_exact_files(resolved, names, f"{branch} accepted aggregate")
    current_root, current_identity = snapshot_directory_identity(
        resolved, f"{branch} accepted aggregate root"
    )
    if current_root != resolved or current_identity != root_identity:
        fail(f"{branch} accepted aggregate root changed during its snapshot")
    return ExactAggregateRoot(
        root=resolved,
        branch=branch,
        root_identity=root_identity,
        snapshots=snapshots,
    )


def recheck_exact_aggregate(aggregate: ExactAggregateRoot, description: str) -> None:
    """Fail if an accepted aggregate root, member set, or member identity changed."""

    root, identity = snapshot_directory_identity(aggregate.root, description)
    if root != aggregate.root or identity != aggregate.root_identity:
        fail(f"{description} directory identity changed after acceptance")
    names = aggregate_output_names(aggregate.branch)
    ensure_exact_files(root, names, description)
    if tuple(snapshot.path.name for snapshot in aggregate.snapshots) != names:
        fail(f"{description} captured file order differs from its exact contract")
    for snapshot in aggregate.snapshots:
        recheck_snapshot(snapshot, f"{description} file {snapshot.path.name}")
    ensure_exact_files(root, names, description)


def recheck_host_contract_binding(binding: HostContractBinding, description: str) -> None:
    """Recheck external contract B, pending contract A, and its signed report."""

    recheck_snapshot(binding.pending_contract, f"{description} pending host contract A")
    recheck_snapshot(binding.accepted_contract, f"{description} accepted host contract B")
    recheck_snapshot(binding.qualification_report, f"{description} host qualification report")


def sha256(path: Path) -> str:
    return snapshot_file(path, f"file {path}").sha256


def _reject_constant(value: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key is forbidden: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: Any, location: str = "JSON") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        fail(f"non-finite number is forbidden at {location}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_nonfinite(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_nonfinite(item, f"{location}.{key}")


def load_strict_json_bytes(data: bytes, description: str) -> Any:
    """Parse strict JSON from bytes already captured by a stable snapshot."""

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"{description} is not strict UTF-8: {exc}")
    if text.startswith("\ufeff"):
        fail(f"{description} must not contain a UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except OrchestrationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        fail(f"cannot parse {description}: {exc}")
    _reject_nonfinite(value)
    return value


def load_strict_json(path: Path, description: str) -> Any:
    snapshot = snapshot_file(path, description, collect=True, maximum_bytes=16_000_000)
    if snapshot.data is None:
        fail(f"JSON snapshot was not collected: {description}")
    return load_strict_json_bytes(snapshot.data, description)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _portable_archive_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        fail(f"unsafe source-archive member: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        fail(f"unsafe source-archive member: {name!r}")
    normalized = pure.as_posix()
    if normalized != name.rstrip("/"):
        fail(f"non-canonical source-archive member: {name!r}")
    return normalized


@dataclass(frozen=True)
class SourceArchiveEvidence:
    snapshot: FileSnapshot
    files: Mapping[str, tuple[str, int]]
    directories: frozenset[str]


def inspect_source_archive(
    archive: Path, expected_sha256: str
) -> SourceArchiveEvidence:
    expected = expected_sha256.strip().lower()
    if not SHA256_RE.fullmatch(expected):
        fail("expected source-archive SHA-256 must contain exactly 64 hexadecimal characters")
    snap = snapshot_file(
        archive,
        "source archive",
        collect=True,
        maximum_bytes=SOURCE_ARCHIVE_MAX_BYTES,
    )
    if snap.sha256 != expected:
        fail(f"source archive SHA-256 mismatch: {snap.sha256} != {expected}")
    if snap.data is None:
        fail("source archive snapshot was not collected")
    files: dict[str, tuple[str, int]] = {}
    declared_directories: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(snap.data), mode="r:*") as archive_file:
            for member in archive_file.getmembers():
                name = _portable_archive_name(member.name)
                if name in files or name in declared_directories:
                    fail(f"duplicate source-archive member: {name}")
                if member.isdir():
                    declared_directories.add(name)
                    continue
                if not member.isfile():
                    fail(f"source archive contains a non-regular member: {name}")
                handle = archive_file.extractfile(member)
                if handle is None:
                    fail(f"cannot read source-archive member: {name}")
                digest = hashlib.sha256()
                size = 0
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                if size != member.size:
                    fail(f"truncated source-archive member: {name}")
                files[name] = (digest.hexdigest(), size)
    except (tarfile.TarError, OSError) as exc:
        fail(f"cannot inspect source archive: {exc}")
    portable_names = [*files, *declared_directories]
    folded_names = [name.casefold() for name in portable_names]
    if len(folded_names) != len(set(folded_names)):
        fail("source archive contains portable case-colliding members")
    required = "scripts/run_v404_local_production.py"
    if required not in files:
        fail(f"source archive lacks its production controller: {required}")
    if not files:
        fail("source archive contains no regular files")
    directories: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while parent.as_posix() != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    if not declared_directories.issubset(directories):
        unexpected = sorted(declared_directories - directories)
        fail(f"source archive contains empty or unexpected directories: {unexpected}")
    return SourceArchiveEvidence(snap, files, frozenset(directories))


def verify_source_tree(root: Path, evidence: SourceArchiveEvidence) -> None:
    source = Path(root)
    try:
        root_status = source.lstat()
    except OSError as exc:
        fail(f"cannot inspect source root: {exc}")
    if (
        stat.S_ISLNK(root_status.st_mode)
        or _has_reparse_point(root_status)
        or not stat.S_ISDIR(root_status.st_mode)
    ):
        fail("source root must be a real directory")
    actual_files: dict[str, tuple[str, int]] = {}
    actual_directories: set[str] = set()
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(source).as_posix()
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or _has_reparse_point(status):
            fail(f"source tree contains a link or reparse point: {relative}")
        if stat.S_ISDIR(status.st_mode):
            actual_directories.add(relative)
        elif stat.S_ISREG(status.st_mode):
            snap = snapshot_file(path, f"source-tree file {relative}")
            actual_files[relative] = (snap.sha256, snap.size_bytes)
        else:
            fail(f"source tree contains a special file: {relative}")
    if actual_files != dict(evidence.files):
        missing = sorted(set(evidence.files) - set(actual_files))
        extra = sorted(set(actual_files) - set(evidence.files))
        changed = sorted(
            name
            for name in set(actual_files).intersection(evidence.files)
            if actual_files[name] != evidence.files[name]
        )
        fail(
            "source tree differs from the locked archive: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    if actual_directories != set(evidence.directories):
        fail(
            "source directory set differs from the locked archive: "
            f"missing={sorted(set(evidence.directories) - actual_directories)}, "
            f"extra={sorted(actual_directories - set(evidence.directories))}"
        )


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if value.startswith(('"', "'")) and value.endswith(value[:1]):
            value = value[1:-1]
        values[key] = value
    return values


def validate_ubuntu_2204_wsl(
    *,
    platform_name: str | None = None,
    kernel_release: str | None = None,
    os_release_text: str | None = None,
) -> None:
    platform_value = sys.platform if platform_name is None else platform_name
    if platform_value != "linux":
        fail("production execution is restricted to Ubuntu 22.04 under WSL")
    if kernel_release is None:
        try:
            kernel_release = Path("/proc/sys/kernel/osrelease").read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            fail(f"cannot inspect WSL kernel release: {exc}")
    if "microsoft" not in kernel_release.lower():
        fail("Linux runtime is not identified as WSL")
    if os_release_text is None:
        try:
            os_release_text = Path("/etc/os-release").read_text(encoding="utf-8")
        except OSError as exc:
            fail(f"cannot inspect Ubuntu release: {exc}")
    release = parse_os_release(os_release_text)
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "22.04":
        fail(
            "production execution requires Ubuntu 22.04; observed "
            f"ID={release.get('ID')!r}, VERSION_ID={release.get('VERSION_ID')!r}"
        )


def _resolved(path: Path) -> Path:
    return Path(path).resolve(strict=False)


def same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(_resolved(left))) == os.path.normcase(str(_resolved(right)))


def is_within(path: Path, root: Path) -> bool:
    candidate = _resolved(path)
    base = _resolved(root)
    return candidate == base or base in candidate.parents


def paths_overlap(left: Path, right: Path) -> bool:
    return is_within(left, right) or is_within(right, left)


def require_absolute(path: Path, description: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        fail(f"{description} must be an absolute path")
    return candidate


def validate_mutable_roots(
    roots: Mapping[str, Path], protected_paths: Mapping[str, Path]
) -> dict[str, Path]:
    normalized = {
        name: _resolved(require_absolute(path, name)) for name, path in roots.items()
    }
    items = list(normalized.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if paths_overlap(left, right):
                fail(f"mutable roots overlap: {left_name}={left}, {right_name}={right}")
    for root_name, root in items:
        for protected_name, protected in protected_paths.items():
            candidate = _resolved(protected)
            if is_within(candidate, root):
                fail(f"{protected_name} is inside mutable root {root_name}")
            if candidate.is_dir() and is_within(root, candidate):
                fail(f"mutable root {root_name} is inside protected {protected_name}")
        if root.exists():
            status = root.lstat()
            if (
                stat.S_ISLNK(status.st_mode)
                or _has_reparse_point(status)
                or not stat.S_ISDIR(status.st_mode)
            ):
                fail(f"{root_name} must be absent or an empty real directory")
            if any(root.iterdir()):
                fail(f"{root_name} must be empty")
        else:
            root.mkdir(parents=True, exist_ok=False)
    return normalized


def make_empty_directory(path: Path, description: str) -> Path:
    candidate = Path(path)
    if candidate.exists() or candidate.is_symlink():
        fail(f"{description} already exists: {candidate}")
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def ensure_exact_files(root: Path, expected: Iterable[str], description: str) -> None:
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        fail(f"{description} is not a safe directory: {base}")
    expected_set = set(expected)
    observed: set[str] = set()
    for path in base.rglob("*"):
        relative = path.relative_to(base).as_posix()
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or _has_reparse_point(status):
            fail(f"{description} contains a link or reparse point: {relative}")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode):
            fail(f"{description} contains a special file: {relative}")
        observed.add(relative)
    if observed != expected_set:
        fail(
            f"{description} file-set mismatch: "
            f"missing={sorted(expected_set - observed)}, "
            f"extra={sorted(observed - expected_set)}"
        )


def snapshot_plain_directory_chain(
    path: Path, description: str
) -> tuple[Path, tuple[int, int, int, int, int]]:
    """Reject links/reparse points in an existing absolute directory chain."""

    candidate = require_absolute(Path(path), description)
    components = [candidate, *candidate.parents]
    for component in reversed(components):
        try:
            observed = component.lstat()
        except OSError as exc:
            fail(f"cannot inspect {description} path component {component}: {exc}")
        if (
            stat.S_ISLNK(observed.st_mode)
            or _has_reparse_point(observed)
            or not stat.S_ISDIR(observed.st_mode)
        ):
            fail(f"{description} path chain contains a non-plain directory: {component}")
    resolved = candidate.resolve(strict=True)
    if os.path.normcase(str(resolved)) != os.path.normcase(str(candidate)):
        fail(f"{description} path changes under real-path resolution")
    status = candidate.lstat()
    return resolved, _identity(status)


def enumerate_plain_tree(
    root: Path, description: str
) -> tuple[set[str], set[str]]:
    """Enumerate an exact non-link tree and reject portable case collisions."""

    base, _identity_value = snapshot_plain_directory_chain(root, description)
    files: set[str] = set()
    directories: set[str] = {"."}

    def visit(directory: Path, relative: PurePosixPath) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            fail(f"cannot enumerate {description}: {exc}")
        local_folded: set[str] = set()
        for entry in entries:
            folded = entry.name.casefold()
            if folded in local_folded:
                fail(f"{description} contains case-colliding entries")
            local_folded.add(folded)
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", entry.name) is None:
                fail(f"{description} contains a non-portable entry name: {entry.name!r}")
            try:
                observed = Path(entry.path).lstat()
            except OSError as exc:
                fail(f"cannot inspect {description} entry {entry.name}: {exc}")
            if entry.is_symlink() or _has_reparse_point(observed):
                fail(f"{description} contains a link/reparse entry: {entry.name}")
            name = str(relative / entry.name) if str(relative) != "." else entry.name
            if stat.S_ISDIR(observed.st_mode):
                directories.add(name)
                visit(Path(entry.path), PurePosixPath(name))
            elif stat.S_ISREG(observed.st_mode):
                if observed.st_nlink != 1:
                    fail(f"{description} contains a multiply-linked file: {name}")
                files.add(name)
            else:
                fail(f"{description} contains a special filesystem entry: {name}")

    visit(base, PurePosixPath("."))
    folded_paths = [name.casefold() for name in (*files, *directories) if name != "."]
    if len(folded_paths) != len(set(folded_paths)):
        fail(f"{description} contains case-colliding paths")
    return files, directories


def ensure_exact_tree(
    root: Path,
    *,
    expected_files: Iterable[str],
    expected_directories: Iterable[str] = (".",),
    description: str,
) -> None:
    files, directories = enumerate_plain_tree(root, description)
    expected_file_set = set(expected_files)
    expected_directory_set = set(expected_directories)
    if files != expected_file_set or directories != expected_directory_set:
        fail(
            f"{description} exact tree mismatch: "
            f"missing_files={sorted(expected_file_set - files)}, "
            f"extra_files={sorted(files - expected_file_set)}, "
            f"missing_directories={sorted(expected_directory_set - directories)}, "
            f"extra_directories={sorted(directories - expected_directory_set)}"
        )
    final_files, final_directories = enumerate_plain_tree(
        root, f"{description} final recheck"
    )
    if final_files != files or final_directories != directories:
        fail(f"{description} changed during exact-tree validation")


def validate_sha256_manifest_root(
    root: Path,
    *,
    manifest_name: str,
    target_names: Sequence[str],
    description: str,
) -> dict[str, FileSnapshot]:
    """Verify one exact flat artifact root and its complete SHA-256 manifest."""

    if len(set(target_names)) != len(target_names) or manifest_name in target_names:
        fail(f"{description} manifest contract is malformed")
    expected = set(target_names) | {manifest_name}
    ensure_exact_files(root, expected, description)
    manifest = snapshot_file(
        Path(root) / manifest_name,
        f"{description} manifest",
        collect=True,
        maximum_bytes=1_000_000,
    )
    if manifest.data is None:
        fail(f"{description} manifest snapshot was not collected")
    try:
        lines = manifest.data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        fail(f"{description} manifest is not UTF-8: {exc}")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None:
            fail(f"{description} manifest line {line_number} is malformed")
        digest, name = match.groups()
        if name in entries:
            fail(f"{description} manifest repeats target {name}")
        entries[name] = digest
    if set(entries) != set(target_names):
        fail(f"{description} manifest target set differs from its file contract")
    snapshots: dict[str, FileSnapshot] = {}
    for name in target_names:
        snapshot = snapshot_file(Path(root) / name, f"{description} file {name}")
        if snapshot.sha256 != entries[name]:
            fail(f"{description} manifest digest mismatch for {name}")
        snapshots[name] = snapshot
    recheck_snapshot(manifest, f"{description} manifest")
    ensure_exact_files(root, expected, description)
    return snapshots


def runner_output_names(branch: str, label: str) -> tuple[str, ...]:
    return (
        f"joint_posterior_{branch}_{label}.csv",
        f"perturbed_planets_{branch}_{label}.csv",
        f"perturbation_audit_{branch}_{label}.csv",
        f"trial_diagnostics_{branch}_{label}.json",
        f"posterior_summary_{branch}_{label}.json",
        f"SHA256SUMS_{branch}_{label}.txt",
    )


def raw_output_names(branch: str, label: str) -> tuple[str, ...]:
    binaries = tuple(
        f"raw_production_chain_{branch}_{label}_trial-{trial:03d}.bin"
        for trial in range(TRIALS_PER_SHARD)
    )
    return binaries + (
        f"raw_chain_index_{branch}_{label}.json",
        f"SHA256SUMS_raw_chain_{branch}_{label}.txt",
    )


def aggregate_output_names(branch: str) -> tuple[str, ...]:
    return (
        f"joint_posterior_{branch}_full.csv.gz",
        f"joint_posterior_{branch}_for_galactic_propagation.csv.gz",
        f"joint_posterior_{branch}_correlation.csv",
        f"trial_diagnostics_{branch}_full.jsonl",
        f"joint_posterior_{branch}_aggregate_summary.json",
        f"perturbation_audit_{branch}_full.csv.gz",
        f"raw_unthinned_chain_audit_{branch}.json",
        f"SHA256SUMS_{branch}_aggregate.txt",
    )


def propagation_output_names(branch: str) -> tuple[str, ...]:
    return (
        "collapsed_host_temperature_measure.csv",
        f"galactic_posterior_draws_{branch}.csv.gz",
        f"galactic_posterior_summary_{branch}.json",
        f"SHA256SUMS_galactic_{branch}.txt",
    )


def portable_leaf_from_path(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{description} is not a non-empty path string")
    leaf = re.split(r"[\\/]", value)[-1]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", leaf) is None:
        fail(f"{description} does not end in a portable filename")
    return leaf


def make_propagation_summary_release_safe(output: Path, branch: str) -> None:
    """Remove machine-local input locations and rebind the exact manifest."""

    summary_name = f"galactic_posterior_summary_{branch}.json"
    summary_path = Path(output) / summary_name
    summary = load_strict_json(summary_path, f"{branch} propagation summary")
    if not isinstance(summary, dict):
        fail(f"{branch} propagation summary is not a JSON object")
    for key in ("source_posterior_samples", "host_rows"):
        record = summary.get(key)
        if not isinstance(record, dict) or "path" not in record:
            fail(f"{branch} propagation summary lacks {key}.path")
        record["path"] = portable_leaf_from_path(
            record["path"], f"{branch} propagation {key}.path"
        )
    summary_path.write_bytes(canonical_json_bytes(summary))
    targets = (
        "collapsed_host_temperature_measure.csv",
        f"galactic_posterior_draws_{branch}.csv.gz",
        summary_name,
    )
    manifest_name = f"SHA256SUMS_galactic_{branch}.txt"
    manifest_path = Path(output) / manifest_name
    manifest_path.write_text(
        "".join(f"{sha256(Path(output) / name)}  {name}\n" for name in targets),
        encoding="utf-8",
        newline="\n",
    )
    validate_sha256_manifest_root(
        output,
        manifest_name=manifest_name,
        target_names=targets,
        description=f"release-safe {branch} propagation",
    )


def seed_stability_output_names(branch: str) -> tuple[str, ...]:
    names: list[str] = []
    for family in (1, 2):
        label = f"corrected-pilot-seed-{family}"
        names.extend(
            (
                f"joint_posterior_{branch}_{label}.csv",
                f"perturbed_planets_{branch}_{label}.csv",
                f"perturbation_audit_{branch}_{label}.csv",
                f"trial_diagnostics_{branch}_{label}.json",
            )
        )
    names.extend(
        (
            f"mcmc_seed_stability_{branch}.json",
            f"SHA256SUMS_mcmc_seed_stability_{branch}.txt",
        )
    )
    return tuple(names)


def likelihood_grid_output_names() -> tuple[str, ...]:
    return (
        "selected_joint_parameter_points.csv",
        "LIKELIHOOD_GRID_CONVERGENCE.json",
        "SHA256SUMS_likelihood_grid_convergence.txt",
    )


PUBLIC_AGGREGATES = {
    "aggregates/corrected-constant": "constant",
    "aggregates/corrected-zero": "zero",
    "aggregates/legacy-measurement-constant": "constant",
}
PUBLIC_PROPAGATIONS = {
    "propagations/corrected-constant/canonical": "constant",
    "propagations/corrected-constant/legacy": "constant",
    "propagations/corrected-zero/canonical": "zero",
    "propagations/corrected-zero/legacy": "zero",
    "propagations/legacy-measurement-constant/canonical": "constant",
}
PUBLIC_SEED_STABILITY = {
    "qualification/seed-stability/constant": "constant",
    "qualification/seed-stability/zero": "zero",
}
PUBLIC_LIKELIHOOD_GRID = {
    "qualification/likelihood-grid/constant": "constant",
    "qualification/likelihood-grid/zero": "zero",
}
PUBLIC_AUDITS = {
    "audits/metallicity-tams": METALLICITY_AUDIT_OUTPUT_NAMES,
    "audits/host-tams": HOST_TAMS_AUDIT_OUTPUT_NAMES,
    "audits/dr25-support": DR25_SUPPORT_OUTPUT_NAMES,
    "audits/sensitivity-artifacts": SENSITIVITY_ARTIFACT_OUTPUT_NAMES,
}


def expected_public_files(*, final: bool = True) -> tuple[str, ...]:
    paths: list[str] = []
    for directory, branch in PUBLIC_AGGREGATES.items():
        paths.extend(f"{directory}/{name}" for name in aggregate_output_names(branch))
    for directory, branch in PUBLIC_PROPAGATIONS.items():
        paths.extend(
            f"{directory}/{name}" for name in propagation_output_names(branch)
        )
    for directory, branch in PUBLIC_SEED_STABILITY.items():
        paths.extend(
            f"{directory}/{name}" for name in seed_stability_output_names(branch)
        )
    for directory in PUBLIC_LIKELIHOOD_GRID:
        paths.extend(
            f"{directory}/{name}" for name in likelihood_grid_output_names()
        )
    for directory, names in PUBLIC_AUDITS.items():
        paths.extend(f"{directory}/{name}" for name in names)
    if final:
        paths.extend((REPORT_NAME, PUBLIC_MANIFEST_NAME))
    return tuple(sorted(paths))


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str, ...]
    log_path: Path


@dataclass(frozen=True)
class CommandResult:
    command_id: str
    returncode: int
    runtime_seconds: float


def production_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
        environment.pop(name, None)
    environment.update(NUMERICAL_ENVIRONMENT)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "MPLBACKEND": "Agg",
        }
    )
    return environment


def run_command(
    spec: CommandSpec, *, cwd: Path, environment: Mapping[str, str]
) -> CommandResult:
    if not SAFE_COMMAND_ID.fullmatch(spec.command_id):
        fail(f"invalid command identifier: {spec.command_id!r}")
    if not spec.argv or any(not isinstance(value, str) or not value for value in spec.argv):
        fail(f"command {spec.command_id} has an invalid argv")
    if spec.log_path.exists() or spec.log_path.is_symlink():
        fail(f"command log already exists: {spec.log_path}")
    spec.log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with spec.log_path.open("xb") as log:
        completed = subprocess.run(
            list(spec.argv),
            cwd=str(cwd),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            shell=False,
            check=False,
        )
    elapsed = time.monotonic() - started
    result = CommandResult(spec.command_id, int(completed.returncode), float(elapsed))
    if completed.returncode != 0:
        fail(
            f"command {spec.command_id} failed with exit code "
            f"{completed.returncode}; private log: {spec.log_path}"
        )
    return result


def run_bounded(
    specs: Sequence[CommandSpec],
    *,
    maximum_parallel: int,
    runner: Callable[[CommandSpec], CommandResult],
) -> list[CommandResult]:
    if not 1 <= maximum_parallel <= MAXIMUM_PARALLEL_SHARDS:
        fail(f"maximum parallel process count must be between 1 and {MAXIMUM_PARALLEL_SHARDS}")
    if len({spec.command_id for spec in specs}) != len(specs):
        fail("parallel command identifiers are not unique")
    results: list[CommandResult] = []
    with ThreadPoolExecutor(max_workers=maximum_parallel) as pool:
        futures: dict[Future[CommandResult], CommandSpec] = {
            pool.submit(runner, spec): spec for spec in specs
        }
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except BaseException:
            for pending in futures:
                pending.cancel()
            raise
    return sorted(results, key=lambda item: item.command_id)


def capture_command(
    argv: Sequence[str], *, cwd: Path, environment: Mapping[str, str], description: str
) -> bytes:
    completed = subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"{description} failed with exit code {completed.returncode}")
    return bytes(completed.stdout)


def validate_pip_freeze(data: bytes) -> list[str]:
    try:
        lines = [line.strip() for line in data.decode("utf-8", errors="strict").splitlines()]
    except UnicodeDecodeError as exc:
        fail(f"pip freeze output is not UTF-8: {exc}")
    pins: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, version = line.split("==", 1)
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in pins:
            fail(f"pip freeze contains duplicate package {normalized!r}")
        pins[normalized] = version
    mismatches = {
        name: (expected, pins.get(name))
        for name, expected in REQUIRED_RUNTIME_PINS.items()
        if pins.get(name) != expected
    }
    if mismatches:
        fail(f"installed numerical package versions differ from policy: {mismatches}")
    return sorted(line for line in lines if line)


@dataclass(frozen=True)
class Configuration:
    source_root: Path
    source_archive: Path
    expected_source_archive_sha256: str
    python_executable: Path
    rate_model_source: Path
    stellar_catalog: Path
    pc_catalog: Path
    constant_completeness: Path
    zero_completeness: Path
    host_artifact_root: Path
    host_contract: Path
    expected_host_contract_sha256: str
    parent_hosts: Path
    canonical_hosts: Path
    legacy_hosts: Path
    metallicity_audit_root: Path
    production_checkout: Path
    release_checkout: Path
    command_plan: Path
    git_executable: Path
    private_work_root: Path
    private_raw_root: Path
    public_output_root: Path
    expected_bryson_source_sha256: str
    maximum_parallel_shards: int
    recovery_contract: Path | None = None
    expected_recovery_contract_sha256: str | None = None
    expected_recovery_contract_size_bytes: int | None = None
    donor_work_shard_root: Path | None = None
    donor_raw_root: Path | None = None
    donor_evidence_root: Path | None = None
    donor_attestation_contract: Path | None = None
    donor_command_plan: Path | None = None
    donor_numerical_runtime_manifest: Path | None = None
    donor_source_archive: Path | None = None
    source_transition_evidence: Path | None = None
    recovery_qualification_report: Path | None = None
    ssh_keygen_executable: Path | None = None


@dataclass(frozen=True)
class Variant:
    name: str
    branch: str
    measurement_mode: str
    acceptance_profile: str
    maximum_steps: int
    seed_offset: int


@dataclass(frozen=True)
class GitCheckoutEvidence:
    head_sha: str
    tree_sha: str
    tree_sha256: str
    source_archive_sha256: str
    source_archive_size_bytes: int = 0


@dataclass(frozen=True)
class ExactAggregateRoot:
    root: Path
    branch: str
    root_identity: tuple[int, int, int, int, int]
    snapshots: tuple[FileSnapshot, ...]


@dataclass(frozen=True)
class HostContractBinding:
    pending_contract: FileSnapshot
    accepted_contract: FileSnapshot
    qualification_report: FileSnapshot
    source_lock: Mapping[str, Any]
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class RecoveryContractBinding:
    contract: Mapping[str, Any]
    snapshot: FileSnapshot
    evidence_root: Path
    evidence_root_identity: tuple[int, int, int, int, int]
    evidence_snapshots: tuple[FileSnapshot, ...]
    donor_attestation_contract: FileSnapshot
    donor_plan: FileSnapshot
    donor_runtime: FileSnapshot
    donor_source_archive: SourceArchiveEvidence
    source_transition: FileSnapshot
    qualification_report: FileSnapshot
    source_transition_value: Mapping[str, Any]
    qualification_report_value: Mapping[str, Any]
    donor_work_root: Path
    donor_work_root_identity: tuple[int, int, int, int, int]
    donor_raw_root: Path
    donor_raw_root_identity: tuple[int, int, int, int, int]
    manifest_snapshots: tuple[FileSnapshot, ...]
    trusted_ssh_keygen: FileSnapshot
    mcmc_policy_sha256: str


@dataclass(frozen=True)
class RecoveryImportEvidence:
    snapshots: tuple[FileSnapshot, ...]
    work_root: Path
    work_root_identity: tuple[int, int, int, int, int]
    work_file_count: int
    work_size_bytes: int
    work_tree_sha256: str
    raw_root: Path
    raw_root_identity: tuple[int, int, int, int, int]
    raw_file_count: int
    raw_size_bytes: int
    raw_tree_sha256: str


VARIANTS = (
    Variant(
        "corrected-constant",
        "constant",
        CORRECTED_MODE,
        "v4.0.4-production",
        20_000,
        0,
    ),
    Variant(
        "corrected-zero",
        "zero",
        CORRECTED_MODE,
        "v4.0.4-zero-extended",
        30_000,
        PRODUCTION_ZERO_OFFSET,
    ),
    Variant(
        "legacy-measurement-constant",
        "constant",
        LEGACY_MODE,
        "v4.0.4-legacy-measurement-sensitivity",
        20_000,
        0,
    ),
)


def _recovery_mcmc_policy_snapshot(source: bytes, description: str) -> dict[str, Any]:
    """Return a location-independent AST lock for all reused-MCMC semantics."""

    try:
        tree = ast.parse(source, filename=description, mode="exec")
    except (SyntaxError, ValueError, TypeError) as exc:
        fail(f"cannot parse {description} for its MCMC policy: {exc}")
    assignments: dict[str, str] = {}
    functions: dict[str, str] = {}
    variant_class: str | None = None
    wanted_assignments = set(RECOVERY_MCMC_POLICY_ASSIGNMENTS)
    wanted_functions = set(RECOVERY_MCMC_POLICY_FUNCTIONS)
    for node in tree.body:
        assignment_name: str | None = None
        assignment_value: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                assignment_name = target.id
                assignment_value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assignment_name = node.target.id
            assignment_value = node.value
        if assignment_name in wanted_assignments and assignment_value is not None:
            if assignment_name in assignments:
                fail(f"{description} repeats MCMC policy assignment {assignment_name}")
            assignments[assignment_name] = ast.dump(
                assignment_value, annotate_fields=True, include_attributes=False
            )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted_functions:
            if node.name in functions:
                fail(f"{description} repeats MCMC policy function {node.name}")
            functions[node.name] = ast.dump(
                node, annotate_fields=True, include_attributes=False
            )
        if isinstance(node, ast.ClassDef) and node.name == "Variant":
            if variant_class is not None:
                fail(f"{description} repeats the Variant policy class")
            variant_class = ast.dump(node, annotate_fields=True, include_attributes=False)
    missing_assignments = wanted_assignments - set(assignments)
    missing_functions = wanted_functions - set(functions)
    if missing_assignments or missing_functions or variant_class is None:
        fail(
            f"{description} lacks the exact MCMC policy surface: "
            f"assignments={sorted(missing_assignments)}, "
            f"functions={sorted(missing_functions)}, variant_class={variant_class is not None}"
        )
    return {
        "assignments": {name: assignments[name] for name in sorted(assignments)},
        "functions": {name: functions[name] for name in sorted(functions)},
        "variant_class": variant_class,
    }


def _recovery_controller_invariant_snapshot(
    source: bytes, description: str
) -> dict[str, str]:
    """Lock every unchanged controller node outside the explicit recovery surface."""

    try:
        tree = ast.parse(source, filename=description, mode="exec")
    except (SyntaxError, ValueError, TypeError) as exc:
        fail(f"cannot parse {description} for its invariant surface: {exc}")
    allowed_classes = set(RECOVERY_CONTROLLER_ALLOWED_CLASSES)
    allowed_functions = set(RECOVERY_CONTROLLER_ALLOWED_FUNCTIONS)
    result: dict[str, str] = {}
    for node in tree.body:
        normalized: ast.AST | None = node
        key: str
        if isinstance(node, ast.Import):
            names = [alias for alias in node.names if alias.name not in {"ast", "tempfile"}]
            if not names:
                continue
            normalized = ast.Import(names=names)
            key = "import:" + ",".join(
                f"{alias.name}:{alias.asname or ''}" for alias in names
            )
        elif isinstance(node, ast.ImportFrom):
            key = "import-from:" + ast.dump(
                node, annotate_fields=True, include_attributes=False
            )
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(
            node.targets[0], ast.Name
        ):
            name = node.targets[0].id
            if name.startswith(("RECOVERY_", "DONOR_")):
                continue
            key = f"assignment:{name}"
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if name.startswith(("RECOVERY_", "DONOR_")):
                continue
            key = f"annotated-assignment:{name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in allowed_functions:
                continue
            key = f"function:{node.name}"
        elif isinstance(node, ast.ClassDef):
            if node.name in allowed_classes:
                continue
            key = f"class:{node.name}"
        elif isinstance(node, ast.If):
            simple_main_guard = (
                isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"
            )
            if simple_main_guard:
                continue
            key = "if:" + ast.dump(
                node.test, annotate_fields=True, include_attributes=False
            )
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        ):
            key = "module-docstring"
        else:
            key = "node:" + ast.dump(
                node, annotate_fields=True, include_attributes=False
            )
        if normalized is None:
            continue
        if key in result:
            fail(f"{description} repeats invariant controller node {key}")
        result[key] = ast.dump(
            normalized, annotate_fields=True, include_attributes=False
        )
    return {key: result[key] for key in sorted(result)}


def _exact_object(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = set(value) if isinstance(value, dict) else set()
        fail(
            f"{description} keys differ from the exact contract: "
            f"missing={sorted(keys - observed)}, extra={sorted(observed - keys)}"
        )
    return value


def _validate_recovery_evidence(
    value: Any, description: str, *, allow_empty: bool = False
) -> dict[str, Any]:
    item = _exact_object(value, {"sha256", "size_bytes"}, description)
    if not isinstance(item["sha256"], str) or SHA256_RE.fullmatch(item["sha256"]) is None:
        fail(f"{description} SHA-256 is malformed")
    if (
        isinstance(item["size_bytes"], bool)
        or not isinstance(item["size_bytes"], int)
        or item["size_bytes"] < (0 if allow_empty else 1)
    ):
        fail(f"{description} size is invalid")
    if (
        item["size_bytes"] == 0
        and item["sha256"] != hashlib.sha256(b"").hexdigest()
    ):
        fail(f"{description} empty-file SHA-256 is invalid")
    return item


def recovery_enabled(config: Configuration) -> bool:
    values = (
        config.recovery_contract,
        config.expected_recovery_contract_sha256,
        config.expected_recovery_contract_size_bytes,
        config.donor_work_shard_root,
        config.donor_raw_root,
        config.donor_evidence_root,
        config.donor_attestation_contract,
        config.donor_command_plan,
        config.donor_numerical_runtime_manifest,
        config.donor_source_archive,
        config.source_transition_evidence,
        config.recovery_qualification_report,
        config.ssh_keygen_executable,
    )
    populated = [value is not None for value in values]
    if any(populated) and not all(populated):
        fail("MCMC recovery configuration is only partially populated")
    return all(populated)


def _matches_recovery_evidence(
    snapshot: FileSnapshot,
    value: Any,
    description: str,
    *,
    allow_empty: bool = False,
) -> None:
    expected = _validate_recovery_evidence(
        value, description, allow_empty=allow_empty
    )
    if {
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
    } != expected:
        fail(f"{description} differs from the external recovery contract")


def _validate_recovery_self_id(
    value: Mapping[str, Any], field: str, description: str
) -> None:
    identifier = value.get(field)
    if not isinstance(identifier, str) or SHA256_RE.fullmatch(identifier) is None:
        fail(f"{description} {field} is malformed")
    body = dict(value)
    body.pop(field, None)
    if hashlib.sha256(canonical_json_bytes(body)).hexdigest() != identifier:
        fail(f"{description} {field} does not match its canonical body")


def _source_archive_member_bytes(
    evidence: SourceArchiveEvidence, name: str, description: str
) -> bytes:
    if evidence.snapshot.data is None or name not in evidence.files:
        fail(f"{description} is absent from the donor source archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(evidence.snapshot.data), mode="r:*") as bundle:
            matches = [member for member in bundle.getmembers() if member.name == name]
            if len(matches) != 1 or not matches[0].isfile():
                fail(f"{description} is not one regular archive member")
            handle = bundle.extractfile(matches[0])
            if handle is None:
                fail(f"cannot extract {description}")
            data = handle.read()
    except (tarfile.TarError, OSError) as exc:
        fail(f"cannot read {description}: {exc}")
    expected_sha256, expected_size = evidence.files[name]
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha256:
        fail(f"{description} differs from the donor archive inventory")
    return data


def _write_exclusive_captured_bytes(
    path: Path,
    data: bytes,
    description: str,
    *,
    executable: bool = False,
) -> FileSnapshot:
    """Materialize already captured bytes into one new private temporary file."""

    destination = Path(path)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(destination, flags, 0o500 if executable else 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                fail(f"cannot write {description}")
            offset += written
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != len(data):
            fail(f"{description} temporary materialization is invalid")
    except OSError as exc:
        fail(f"cannot materialize {description}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    snapshot = snapshot_file(destination, description)
    if (
        snapshot.size_bytes != len(data)
        or snapshot.sha256 != hashlib.sha256(data).hexdigest()
    ):
        fail(f"{description} temporary materialization differs from captured bytes")
    return snapshot


def _validate_source_transition(
    value: Any,
    *,
    donor_source: SourceArchiveEvidence,
    current_source: SourceArchiveEvidence,
    donor_commit: str,
    donor_tree: str,
    current_git: GitCheckoutEvidence,
) -> dict[str, Any]:
    report = _exact_object(
        value,
        {
            "schema_version",
            "report_id",
            "transition_id",
            "status",
            "from_source",
            "to_source",
            "protected_paths",
        },
        "MCMC source-transition report",
    )
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["transition_id"] != "a7-to-a8-mcmc-source-equivalence-v4.0.4"
        or report["status"] != "PASS"
    ):
        fail("MCMC source-transition report is not the exact schema-1 PASS report")
    _validate_recovery_self_id(report, "report_id", "MCMC source-transition report")
    expected_from = {
        "commit": donor_commit,
        "tree": donor_tree,
        "archive_sha256": donor_source.snapshot.sha256,
        "archive_size_bytes": donor_source.snapshot.size_bytes,
    }
    expected_to = {
        "commit": current_git.head_sha,
        "tree": current_git.tree_sha,
        "archive_sha256": current_source.snapshot.sha256,
        "archive_size_bytes": current_source.snapshot.size_bytes,
    }
    if report["from_source"] != expected_from or report["to_source"] != expected_to:
        fail("MCMC source-transition endpoints differ from the verified A7/A8 archives")
    donor_prefix = {
        name for name in donor_source.files if name.startswith(RECOVERY_MCMC_SOURCE_PREFIX)
    }
    current_prefix = {
        name for name in current_source.files if name.startswith(RECOVERY_MCMC_SOURCE_PREFIX)
    }
    if donor_prefix != current_prefix or not donor_prefix:
        fail("tracked Bryson/MCMC source file-set changed across A7 to A8")
    expected_paths = tuple(sorted(donor_prefix | set(RECOVERY_MCMC_SOURCE_FIXED_PATHS)))
    if any(
        name not in donor_source.files or name not in current_source.files
        for name in expected_paths
    ):
        fail("MCMC source-transition archive lacks a protected dependency")
    entries = report["protected_paths"]
    if not isinstance(entries, list) or len(entries) != len(expected_paths):
        fail("MCMC source-transition protected path count differs from policy")
    for name, raw in zip(expected_paths, entries):
        item = _exact_object(
            raw,
            {
                "path",
                "from_sha256",
                "from_size_bytes",
                "to_sha256",
                "to_size_bytes",
                "bit_identical",
            },
            f"MCMC source transition {name}",
        )
        from_sha256, from_size = donor_source.files[name]
        to_sha256, to_size = current_source.files[name]
        expected = {
            "path": name,
            "from_sha256": from_sha256,
            "from_size_bytes": from_size,
            "to_sha256": to_sha256,
            "to_size_bytes": to_size,
            "bit_identical": True,
        }
        if item != expected or (from_sha256, from_size) != (to_sha256, to_size):
            fail(f"MCMC source/dependency bytes changed across A7 to A8: {name}")
    return report


def _validate_recovery_qualification(
    value: Any,
    *,
    donor_run_id: str,
    source_transition: FileSnapshot,
) -> dict[str, Any]:
    report = _exact_object(
        value,
        {
            "schema_version",
            "report_id",
            "status",
            "decision",
            "donor_run_id",
            "recovery_contract_id",
            "source_transition_sha256",
            "completion_attestation_present",
            "work_manifest_count",
            "raw_manifest_count",
            "mcmc_realizations",
            "total_file_count",
            "total_size_bytes",
        },
        "MCMC recovery qualification report",
    )
    expected = {
        "schema_version": 1,
        "status": "PASS",
        "decision": "REUSE_MCMC_RECOMPUTE_ALL_DOWNSTREAM",
        "donor_run_id": donor_run_id,
        "recovery_contract_id": RECOVERY_CONTRACT_ID,
        "source_transition_sha256": source_transition.sha256,
        "completion_attestation_present": False,
        "work_manifest_count": len(VARIANTS) * SHARDS,
        "raw_manifest_count": len(VARIANTS) * SHARDS,
        "mcmc_realizations": len(VARIANTS) * SHARDS * TRIALS_PER_SHARD,
        "total_file_count": RECOVERY_TOTAL_FILE_COUNT,
        "total_size_bytes": RECOVERY_TOTAL_SIZE_BYTES,
    }
    if {key: report.get(key) for key in expected} != expected:
        fail("MCMC recovery qualification report differs from the narrow recovery decision")
    _validate_recovery_self_id(report, "report_id", "MCMC recovery qualification report")
    return report


def _parse_recovery_manifest(
    snapshot: FileSnapshot,
    *,
    expected_targets: Sequence[str],
    description: str,
) -> dict[str, str]:
    if snapshot.data is None:
        fail(f"{description} bytes were not captured")
    try:
        lines = snapshot.data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        fail(f"{description} is not strict UTF-8: {exc}")
    entries: dict[str, str] = {}
    folded: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None:
            fail(f"{description} line {line_number} is malformed")
        digest, name = match.groups()
        if name in entries or name.casefold() in folded:
            fail(f"{description} repeats or case-collides target {name}")
        entries[name] = digest
        folded.add(name.casefold())
    expected = tuple(expected_targets)
    if len(expected) != len(set(expected)) or set(entries) != set(expected):
        fail(f"{description} target set differs from the exact shard contract")
    return entries


def _recovery_tree_paths(*, raw: bool) -> tuple[tuple[str, ...], tuple[str, ...]]:
    files: list[str] = []
    directories = ["."]
    for variant in VARIANTS:
        directories.append(variant.name)
        for shard in range(SHARDS):
            shard_directory = f"{variant.name}/shard-{shard:02d}"
            directories.append(shard_directory)
            label = f"production-shard-{shard}"
            names = (
                raw_output_names(variant.branch, label)
                if raw
                else (*runner_output_names(variant.branch, label), "numerical_environment.txt", "SHA256SUMS_complete.txt")
            )
            files.extend(f"{shard_directory}/{name}" for name in names)
    return tuple(sorted(files)), tuple(sorted(directories))


def _validate_recovery_donor_trees(
    config: Configuration,
    contract: Mapping[str, Any],
) -> tuple[
    Path,
    tuple[int, int, int, int, int],
    Path,
    tuple[int, int, int, int, int],
    tuple[FileSnapshot, ...],
]:
    if config.donor_work_shard_root is None or config.donor_raw_root is None:
        fail("recovery donor work/raw roots are missing")
    work_root, work_identity = snapshot_plain_directory_chain(
        config.donor_work_shard_root, "donor MCMC work-shard root"
    )
    raw_root, raw_identity = snapshot_plain_directory_chain(
        config.donor_raw_root, "donor MCMC raw-chain root"
    )
    if paths_overlap(work_root, raw_root):
        fail("donor MCMC work and raw roots overlap")
    work_files, work_directories = _recovery_tree_paths(raw=False)
    raw_files, raw_directories = _recovery_tree_paths(raw=True)
    ensure_exact_tree(
        work_root,
        expected_files=work_files,
        expected_directories=work_directories,
        description="donor MCMC work-shard tree",
    )
    ensure_exact_tree(
        raw_root,
        expected_files=raw_files,
        expected_directories=raw_directories,
        description="donor MCMC raw-chain tree",
    )
    manifest_snapshots: list[FileSnapshot] = []
    total_size = 0
    total_count = 0
    contract_variants = contract["variants"]
    for variant, contract_variant in zip(VARIANTS, contract_variants):
        for shard, shard_contract in enumerate(contract_variant["shards"]):
            label = f"production-shard-{shard}"
            work_directory = work_root / variant.name / f"shard-{shard:02d}"
            raw_directory = raw_root / variant.name / f"shard-{shard:02d}"
            work_manifest = snapshot_file(
                work_directory / "SHA256SUMS_complete.txt",
                f"donor {variant.name} shard {shard} work manifest",
                collect=True,
                maximum_bytes=1_000_000,
            )
            raw_manifest_name = f"SHA256SUMS_raw_chain_{variant.branch}_{label}.txt"
            raw_manifest = snapshot_file(
                raw_directory / raw_manifest_name,
                f"donor {variant.name} shard {shard} raw manifest",
                collect=True,
                maximum_bytes=1_000_000,
            )
            _matches_recovery_evidence(
                work_manifest,
                shard_contract["work_manifest"],
                f"recovery {variant.name} shard {shard} work manifest",
            )
            _matches_recovery_evidence(
                raw_manifest,
                shard_contract["raw_manifest"],
                f"recovery {variant.name} shard {shard} raw manifest",
            )
            work_entries = _parse_recovery_manifest(
                work_manifest,
                expected_targets=(*runner_output_names(variant.branch, label), "numerical_environment.txt"),
                description=f"donor {variant.name} shard {shard} work manifest",
            )
            raw_entries = _parse_recovery_manifest(
                raw_manifest,
                expected_targets=tuple(
                    name
                    for name in raw_output_names(variant.branch, label)
                    if name != raw_manifest_name
                ),
                description=f"donor {variant.name} shard {shard} raw manifest",
            )
            manifest_snapshots.extend((work_manifest, raw_manifest))
            total_count += 2
            total_size += work_manifest.size_bytes + raw_manifest.size_bytes
            for directory, entries, tree_name in (
                (work_directory, work_entries, "work"),
                (raw_directory, raw_entries, "raw"),
            ):
                for name, expected_sha256 in sorted(entries.items()):
                    target = snapshot_file(
                        directory / name,
                        f"donor {variant.name} shard {shard} {tree_name} file {name}",
                    )
                    if target.sha256 != expected_sha256:
                        fail(
                            f"donor {variant.name} shard {shard} {tree_name} file "
                            f"{name} differs from its manifest"
                        )
                    total_count += 1
                    total_size += target.size_bytes
    if total_count != RECOVERY_TOTAL_FILE_COUNT or total_size != RECOVERY_TOTAL_SIZE_BYTES:
        fail(
            "donor MCMC file count/size differs from the qualified recovery set: "
            f"count={total_count}, size={total_size}"
        )
    ensure_exact_tree(
        work_root,
        expected_files=work_files,
        expected_directories=work_directories,
        description="donor MCMC work-shard tree",
    )
    ensure_exact_tree(
        raw_root,
        expected_files=raw_files,
        expected_directories=raw_directories,
        description="donor MCMC raw-chain tree",
    )
    final_work_root, final_work_identity = snapshot_plain_directory_chain(
        work_root, "donor MCMC work-shard root after validation"
    )
    final_raw_root, final_raw_identity = snapshot_plain_directory_chain(
        raw_root, "donor MCMC raw-chain root after validation"
    )
    if (
        final_work_root != work_root
        or final_work_identity != work_identity
        or final_raw_root != raw_root
        or final_raw_identity != raw_identity
    ):
        fail("donor MCMC root identity changed during validation")
    return (
        work_root,
        work_identity,
        raw_root,
        raw_identity,
        tuple(manifest_snapshots),
    )


def _validate_recovery_policy(value: Any) -> dict[str, Any]:
    """Require the one exact, qualified MCMC-recovery policy."""

    policy = _exact_object(
        value,
        {
            "copy_policy",
            "mcmc_reused",
            "aggregates_and_downstream_recomputed",
            "shards_per_variant",
            "trials_per_shard",
            "total_realizations",
            "work_file_count",
            "raw_file_count",
            "total_file_count",
            "work_size_bytes",
            "raw_size_bytes",
            "total_size_bytes",
            "work_tree_sha256",
            "raw_tree_sha256",
            "mcmc_policy_sha256",
        },
        "MCMC recovery policy",
    )
    expected_policy = {
        "copy_policy": RECOVERY_COPY_POLICY,
        "mcmc_reused": True,
        "aggregates_and_downstream_recomputed": True,
        "shards_per_variant": SHARDS,
        "trials_per_shard": TRIALS_PER_SHARD,
        "total_realizations": len(VARIANTS) * SHARDS * TRIALS_PER_SHARD,
        "work_file_count": RECOVERY_WORK_FILE_COUNT,
        "raw_file_count": RECOVERY_RAW_FILE_COUNT,
        "total_file_count": RECOVERY_TOTAL_FILE_COUNT,
        "work_size_bytes": RECOVERY_WORK_SIZE_BYTES,
        "raw_size_bytes": RECOVERY_RAW_SIZE_BYTES,
        "total_size_bytes": RECOVERY_TOTAL_SIZE_BYTES,
        "work_tree_sha256": RECOVERY_WORK_TREE_SHA256,
        "raw_tree_sha256": RECOVERY_RAW_TREE_SHA256,
        "mcmc_policy_sha256": RECOVERY_MCMC_POLICY_SHA256,
    }
    if policy != expected_policy:
        fail("MCMC recovery policy differs from the exact v4.0.4 recovery policy")
    return policy


def validate_recovery_contract(
    config: Configuration,
    *,
    current_source: SourceArchiveEvidence,
    current_git: GitCheckoutEvidence,
) -> RecoveryContractBinding:
    """Validate the signed-start donor and exact external A7 MCMC artifact contract."""

    if not recovery_enabled(config):
        fail("recover-mcmc requires one complete external recovery contract binding")
    required_paths = (
        config.recovery_contract,
        config.donor_evidence_root,
        config.donor_attestation_contract,
        config.donor_command_plan,
        config.donor_numerical_runtime_manifest,
        config.donor_source_archive,
        config.source_transition_evidence,
        config.recovery_qualification_report,
        config.ssh_keygen_executable,
    )
    if any(path is None for path in required_paths):
        fail("internal recovery binding state is incomplete")
    if (
        config.expected_recovery_contract_sha256 is None
        or config.expected_recovery_contract_size_bytes is None
    ):
        fail("internal recovery contract lock is incomplete")
    contract_snapshot = snapshot_file(
        config.recovery_contract,
        "external MCMC recovery contract",
        collect=True,
        maximum_bytes=4_000_000,
    )
    if (
        contract_snapshot.sha256 != config.expected_recovery_contract_sha256
        or contract_snapshot.size_bytes != config.expected_recovery_contract_size_bytes
    ):
        fail("external MCMC recovery contract differs from the signed plan lock")
    if contract_snapshot.data is None:
        fail("external MCMC recovery contract bytes were not captured")
    contract = _exact_object(
        load_strict_json_bytes(
            contract_snapshot.data, "external MCMC recovery contract"
        ),
        {
            "schema_version",
            "contract_id",
            "status",
            "donor",
            "policy",
            "variants",
            "source_transition",
            "qualification_report",
        },
        "external MCMC recovery contract",
    )
    if (
        type(contract["schema_version"]) is not int
        or contract["schema_version"] != RECOVERY_CONTRACT_SCHEMA_VERSION
        or contract["contract_id"] != RECOVERY_CONTRACT_ID
        or contract["status"] != "ACCEPTED"
    ):
        fail("external MCMC recovery contract is not the exact schema-2 ACCEPTED contract")
    donor = _exact_object(
        contract["donor"],
        {
            "run_id",
            "source_commit",
            "source_tree",
            "source_file_set_sha256",
            "source_file_count",
            "execution_environment",
            "attestation_contract",
            "source_archive",
            "command_plan",
            "numerical_runtime_manifest",
            "start_challenge",
            "start_signature",
            "command_stdout",
            "command_stderr",
            "completion_attestation_present",
        },
        "recovery donor",
    )
    if not isinstance(donor["run_id"], str) or SHA256_RE.fullmatch(donor["run_id"]) is None:
        fail("recovery donor run id is malformed")
    for key in ("source_commit", "source_tree"):
        if not isinstance(donor[key], str) or re.fullmatch(r"[0-9a-f]{40}", donor[key]) is None:
            fail(f"recovery donor {key} is malformed")
    if (
        not isinstance(donor["source_file_set_sha256"], str)
        or SHA256_RE.fullmatch(donor["source_file_set_sha256"]) is None
        or type(donor["source_file_count"]) is not int
        or donor["source_file_count"] <= 0
        or not isinstance(donor["execution_environment"], str)
        or SAFE_COMMAND_ID.fullmatch(donor["execution_environment"]) is None
        or donor["completion_attestation_present"] is not False
    ):
        fail("recovery donor source or signed-start/no-completion state is invalid")
    for key in (
        "attestation_contract",
        "source_archive",
        "command_plan",
        "numerical_runtime_manifest",
        "start_challenge",
        "start_signature",
        "command_stdout",
        "command_stderr",
    ):
        _validate_recovery_evidence(
            donor[key],
            f"recovery donor {key}",
            allow_empty=key == "command_stdout",
        )
    policy = _validate_recovery_policy(contract["policy"])
    raw_variants = contract["variants"]
    if not isinstance(raw_variants, list) or len(raw_variants) != len(VARIANTS):
        fail("MCMC recovery contract does not contain exactly three variants")
    for expected_variant, raw_variant in zip(VARIANTS, raw_variants):
        item = _exact_object(
            raw_variant,
            {"name", "branch", "measurement_error_mode", "maximum_steps", "shards"},
            f"MCMC recovery variant {expected_variant.name}",
        )
        if (
            item["name"] != expected_variant.name
            or item["branch"] != expected_variant.branch
            or item["measurement_error_mode"] != expected_variant.measurement_mode
            or type(item["maximum_steps"]) is not int
            or item["maximum_steps"] != expected_variant.maximum_steps
        ):
            fail(f"MCMC recovery variant policy mismatch: {expected_variant.name}")
        shards = item["shards"]
        if not isinstance(shards, list) or len(shards) != SHARDS:
            fail(f"MCMC recovery shard count mismatch: {expected_variant.name}")
        for shard, raw_shard in enumerate(shards):
            shard_item = _exact_object(
                raw_shard,
                {"shard", "work_manifest", "raw_manifest"},
                f"MCMC recovery {expected_variant.name} shard {shard}",
            )
            if type(shard_item["shard"]) is not int or shard_item["shard"] != shard:
                fail(f"MCMC recovery shard order mismatch: {expected_variant.name}")
            _validate_recovery_evidence(
                shard_item["work_manifest"],
                f"MCMC recovery {expected_variant.name} shard {shard} work manifest",
            )
            _validate_recovery_evidence(
                shard_item["raw_manifest"],
                f"MCMC recovery {expected_variant.name} shard {shard} raw manifest",
            )
    transition_lock = _validate_recovery_evidence(
        contract["source_transition"], "MCMC source-transition report"
    )
    qualification_lock = _exact_object(
        contract["qualification_report"],
        {"report_id", "sha256", "size_bytes"},
        "MCMC recovery qualification report lock",
    )
    _validate_recovery_evidence(
        {"sha256": qualification_lock["sha256"], "size_bytes": qualification_lock["size_bytes"]},
        "MCMC recovery qualification report",
    )

    evidence_root, evidence_identity = snapshot_plain_directory_chain(
        config.donor_evidence_root, "donor failed-run evidence root"
    )
    ensure_exact_tree(
        evidence_root,
        expected_files=DONOR_EVIDENCE_FILES,
        description="donor failed-run evidence",
    )
    evidence_snapshots_by_name = {
        name: snapshot_file(
            evidence_root / name,
            f"donor failed-run evidence {name}",
            collect=name in {DONOR_START_NAME, DONOR_START_SIGNATURE_NAME},
            maximum_bytes=(
                4_000_000
                if name == DONOR_START_NAME
                else 1_000_000
                if name == DONOR_START_SIGNATURE_NAME
                else None
            ),
        )
        for name in DONOR_EVIDENCE_FILES
    }
    for name, key in (
        (DONOR_START_NAME, "start_challenge"),
        (DONOR_START_SIGNATURE_NAME, "start_signature"),
        (DONOR_STDOUT_NAME, "command_stdout"),
        (DONOR_STDERR_NAME, "command_stderr"),
    ):
        _matches_recovery_evidence(
            evidence_snapshots_by_name[name],
            donor[key],
            f"recovery donor {key}",
            allow_empty=key == "command_stdout",
        )
    ensure_exact_tree(
        evidence_root,
        expected_files=DONOR_EVIDENCE_FILES,
        description="donor failed-run evidence",
    )

    donor_contract_snapshot = snapshot_file(
        config.donor_attestation_contract,
        "donor A7 attestation contract",
        collect=True,
        maximum_bytes=4_000_000,
    )
    donor_plan_snapshot = snapshot_file(
        config.donor_command_plan,
        "donor A7 command plan",
        collect=True,
        maximum_bytes=4_000_000,
    )
    donor_runtime_snapshot = snapshot_file(
        config.donor_numerical_runtime_manifest,
        "donor A7 numerical runtime",
        collect=True,
        maximum_bytes=4_000_000,
    )
    trusted_ssh_keygen = snapshot_file(
        config.ssh_keygen_executable,
        "trusted ssh-keygen executable",
        collect=True,
        maximum_bytes=4_000_000,
    )
    _matches_recovery_evidence(
        donor_contract_snapshot, donor["attestation_contract"], "recovery donor attestation_contract"
    )
    _matches_recovery_evidence(donor_plan_snapshot, donor["command_plan"], "recovery donor command_plan")
    _matches_recovery_evidence(
        donor_runtime_snapshot,
        donor["numerical_runtime_manifest"],
        "recovery donor numerical_runtime_manifest",
    )
    donor_source = inspect_source_archive(
        config.donor_source_archive, donor["source_archive"]["sha256"]
    )
    if donor_source.snapshot.size_bytes != donor["source_archive"]["size_bytes"]:
        fail("donor A7 source archive size differs from the recovery contract")
    donor_controller_source = _source_archive_member_bytes(
        donor_source,
        TRACKED_CONTROLLER_PATH,
        "donor A7 production controller",
    )
    current_controller_source = _source_archive_member_bytes(
        current_source,
        TRACKED_CONTROLLER_PATH,
        "current A8 production controller",
    )
    donor_mcmc_policy = _recovery_mcmc_policy_snapshot(
        donor_controller_source, "donor A7 production controller"
    )
    current_mcmc_policy = _recovery_mcmc_policy_snapshot(
        current_controller_source, "current A8 production controller"
    )
    if current_mcmc_policy != donor_mcmc_policy:
        fail("A7 to A8 changed the protected MCMC or downstream scientific policy")
    donor_controller_invariants = _recovery_controller_invariant_snapshot(
        donor_controller_source, "donor A7 production controller"
    )
    current_controller_invariants = _recovery_controller_invariant_snapshot(
        current_controller_source, "current A8 production controller"
    )
    if current_controller_invariants != donor_controller_invariants:
        fail("A7 to A8 changed the protected non-recovery controller surface")
    mcmc_policy_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "scientific_policy": current_mcmc_policy,
                "unchanged_controller_surface": current_controller_invariants,
            }
        )
    ).hexdigest()
    if mcmc_policy_sha256 != policy["mcmc_policy_sha256"]:
        fail("recomputed MCMC AST policy differs from the exact recovery policy lock")
    transition_snapshot = snapshot_file(
        config.source_transition_evidence,
        "MCMC source-transition report",
        collect=True,
        maximum_bytes=4_000_000,
    )
    _matches_recovery_evidence(
        transition_snapshot, transition_lock, "MCMC source-transition report"
    )
    if transition_snapshot.data is None:
        fail("MCMC source-transition report bytes were not captured")
    transition_value = _validate_source_transition(
        load_strict_json_bytes(transition_snapshot.data, "MCMC source-transition report"),
        donor_source=donor_source,
        current_source=current_source,
        donor_commit=donor["source_commit"],
        donor_tree=donor["source_tree"],
        current_git=current_git,
    )
    qualification_snapshot = snapshot_file(
        config.recovery_qualification_report,
        "MCMC recovery qualification report",
        collect=True,
        maximum_bytes=4_000_000,
    )
    _matches_recovery_evidence(
        qualification_snapshot,
        {"sha256": qualification_lock["sha256"], "size_bytes": qualification_lock["size_bytes"]},
        "MCMC recovery qualification report",
    )
    if qualification_snapshot.data is None:
        fail("MCMC recovery qualification report bytes were not captured")
    qualification_value = _validate_recovery_qualification(
        load_strict_json_bytes(
            qualification_snapshot.data, "MCMC recovery qualification report"
        ),
        donor_run_id=donor["run_id"],
        source_transition=transition_snapshot,
    )
    if qualification_value["report_id"] != qualification_lock["report_id"]:
        fail("MCMC recovery qualification report id differs from the contract lock")

    verifier_source = _source_archive_member_bytes(
        donor_source,
        "scripts/verify_local_run_attestation.py",
        "donor A7 local-run attestation verifier",
    )
    captured_inputs = {
        "contract": donor_contract_snapshot,
        "plan": donor_plan_snapshot,
        "runtime": donor_runtime_snapshot,
        "start": evidence_snapshots_by_name[DONOR_START_NAME],
        "signature": evidence_snapshots_by_name[DONOR_START_SIGNATURE_NAME],
        "ssh_keygen": trusted_ssh_keygen,
    }
    if any(snapshot.data is None for snapshot in captured_inputs.values()):
        fail("donor signed-start inputs were not captured before verification")
    with tempfile.TemporaryDirectory(prefix="exoearth-donor-attestation-") as temporary:
        temporary_root = Path(temporary)
        verifier_path = temporary_root / "verify_local_run_attestation.py"
        contract_path = temporary_root / "donor-contract.json"
        plan_path = temporary_root / "donor-plan.json"
        runtime_path = temporary_root / "donor-runtime.json"
        start_path = temporary_root / DONOR_START_NAME
        signature_path = temporary_root / DONOR_START_SIGNATURE_NAME
        ssh_keygen_path = temporary_root / "ssh-keygen"
        _write_exclusive_captured_bytes(
            verifier_path, verifier_source, "captured donor A7 attestation verifier"
        )
        for path, key, description in (
            (contract_path, "contract", "captured donor A7 attestation contract"),
            (plan_path, "plan", "captured donor A7 command plan"),
            (runtime_path, "runtime", "captured donor A7 numerical runtime"),
            (start_path, "start", "captured donor A7 start challenge"),
            (signature_path, "signature", "captured donor A7 start signature"),
        ):
            data = captured_inputs[key].data
            if data is None:
                fail(f"{description} bytes are absent")
            _write_exclusive_captured_bytes(path, data, description)
        ssh_keygen_bytes = captured_inputs["ssh_keygen"].data
        if ssh_keygen_bytes is None:
            fail("captured trusted ssh-keygen bytes are absent")
        _write_exclusive_captured_bytes(
            ssh_keygen_path,
            ssh_keygen_bytes,
            "captured trusted ssh-keygen executable",
            executable=True,
        )
        verifier, _verifier_snapshot = _load_module_from_snapshot(
            verifier_path,
            module_name="_exoearth_v404_donor_attestation_validator",
            description="donor A7 local-run attestation verifier",
        )
        try:
            donor_attestation, candidate, verified_contract_snapshot = verifier.select_contract(
                contract_path, DONOR_CANDIDATE_ID
            )
            if verifier.snapshot_evidence(verified_contract_snapshot) != {
                "sha256": donor_contract_snapshot.sha256,
                "size_bytes": donor_contract_snapshot.size_bytes,
            }:
                fail("donor verifier did not use the captured attestation contract")
            if donor_attestation["contract_id"] != DONOR_ATTESTATION_CONTRACT_ID:
                fail("donor attestation contract id differs from v4.0.4")
            verified_tool_snapshot = verifier.validate_tool(
                ssh_keygen_path,
                candidate["source_lock"]["ssh_keygen_executable"],
                "donor trusted ssh-keygen executable",
            )
            if verifier.snapshot_evidence(verified_tool_snapshot) != {
                "sha256": trusted_ssh_keygen.sha256,
                "size_bytes": trusted_ssh_keygen.size_bytes,
            }:
                fail("donor verifier did not use the captured ssh-keygen executable")
            runtime_value, runtime_snapshot = verifier.load_json_snapshot(
                runtime_path, "donor numerical runtime"
            )
            runtime = verifier.validate_numerical_runtime(runtime_value)
            plan_value, plan_snapshot = verifier.load_json_snapshot(
                plan_path, "donor command plan"
            )
            verifier.validate_plan(plan_value, runtime)
            if candidate["command_plan"] != verifier.snapshot_evidence(plan_snapshot):
                fail("donor candidate does not bind the supplied command plan")
            if candidate["numerical_runtime_manifest"] != verifier.snapshot_evidence(runtime_snapshot):
                fail("donor candidate does not bind the supplied numerical runtime")
            source_state = {
                key: candidate["source_lock"][key]
                for key in (
                    "public_repository",
                    "private_repository",
                    "commit",
                    "tree",
                    "archive_sha256",
                    "archive_size_bytes",
                )
            }
            if source_state != {
                "public_repository": EXPECTED_RELEASE_REPOSITORY,
                "private_repository": EXPECTED_PRODUCTION_REPOSITORY,
                "commit": donor["source_commit"],
                "tree": donor["source_tree"],
                "archive_sha256": donor_source.snapshot.sha256,
                "archive_size_bytes": donor_source.snapshot.size_bytes,
            }:
                fail("donor A7 candidate source lock differs from the recovery contract")
            files, _directories = verifier.archive_members(donor_source.snapshot.data)
            source_manifest = verifier.source_manifest(files)
            if (
                source_manifest["file_set_sha256"] != donor["source_file_set_sha256"]
                or source_manifest["file_count"] != donor["source_file_count"]
            ):
                fail("donor source archive inventory differs from the recovery contract")
            challenge_value, start_snapshot = verifier.load_json_snapshot(
                start_path, "donor start challenge"
            )
            challenge = verifier.validate_challenge(
                challenge_value,
                donor_attestation,
                candidate,
                source_state,
                source_manifest,
                plan_snapshot,
                runtime_snapshot,
                donor["execution_environment"],
            )
            if challenge["run_id"] != donor["run_id"]:
                fail("donor signed start run id differs from the recovery contract")
            start_signature = verifier.read_snapshot(
                signature_path,
                "donor start challenge signature",
                maximum_bytes=verifier.MAX_SIGNATURE_BYTES,
            )
            for verified_snapshot, captured_snapshot, description in (
                (plan_snapshot, donor_plan_snapshot, "donor command plan"),
                (runtime_snapshot, donor_runtime_snapshot, "donor numerical runtime"),
                (
                    start_snapshot,
                    evidence_snapshots_by_name[DONOR_START_NAME],
                    "donor start challenge",
                ),
                (
                    start_signature,
                    evidence_snapshots_by_name[DONOR_START_SIGNATURE_NAME],
                    "donor start signature",
                ),
            ):
                if verifier.snapshot_evidence(verified_snapshot) != {
                    "sha256": captured_snapshot.sha256,
                    "size_bytes": captured_snapshot.size_bytes,
                }:
                    fail(f"donor verifier did not use the captured {description}")
            signer = verifier.signer_by_id(
                donor_attestation, challenge["start_signer_id"]
            )
            if signer != {
                "signer_id": DONOR_START_SIGNER_ID,
                "public_key": DONOR_START_PUBLIC_KEY,
            }:
                fail("donor signed start does not use the pinned signer A")
            verifier.verify_signature(
                ssh_keygen_path,
                start_snapshot,
                start_signature,
                signer,
                DONOR_START_NAMESPACE,
                "donor start challenge",
            )
        except OrchestrationError:
            raise
        except Exception as exc:
            fail(f"donor A7 signed-start verification failed: {exc}")

    (
        donor_work_root,
        donor_work_identity,
        donor_raw_root,
        donor_raw_identity,
        manifest_snapshots,
    ) = _validate_recovery_donor_trees(config, contract)
    for snapshot, description in (
        (contract_snapshot, "external MCMC recovery contract"),
        (donor_contract_snapshot, "donor A7 attestation contract"),
        (donor_plan_snapshot, "donor A7 command plan"),
        (donor_runtime_snapshot, "donor A7 numerical runtime"),
        (donor_source.snapshot, "donor A7 source archive"),
        (transition_snapshot, "MCMC source-transition report"),
        (qualification_snapshot, "MCMC recovery qualification report"),
        *(
            (snapshot, f"donor failed-run evidence {snapshot.path.name}")
            for snapshot in evidence_snapshots_by_name.values()
        ),
    ):
        recheck_snapshot(snapshot, description)
    ensure_exact_tree(
        evidence_root,
        expected_files=DONOR_EVIDENCE_FILES,
        description="donor failed-run evidence",
    )
    return RecoveryContractBinding(
        contract=dict(contract),
        snapshot=contract_snapshot,
        evidence_root=evidence_root,
        evidence_root_identity=evidence_identity,
        evidence_snapshots=tuple(evidence_snapshots_by_name.values()),
        donor_attestation_contract=donor_contract_snapshot,
        donor_plan=donor_plan_snapshot,
        donor_runtime=donor_runtime_snapshot,
        donor_source_archive=donor_source,
        source_transition=transition_snapshot,
        qualification_report=qualification_snapshot,
        source_transition_value=dict(transition_value),
        qualification_report_value=dict(qualification_value),
        donor_work_root=donor_work_root,
        donor_work_root_identity=donor_work_identity,
        donor_raw_root=donor_raw_root,
        donor_raw_root_identity=donor_raw_identity,
        manifest_snapshots=manifest_snapshots,
        trusted_ssh_keygen=trusted_ssh_keygen,
        mcmc_policy_sha256=mcmc_policy_sha256,
    )


def validate_recovery_lineage(
    git_executable: Path,
    checkout: Path,
    *,
    expected_head: str,
    donor_commit: str,
    environment: Mapping[str, str],
    description: str,
) -> None:
    """Require one exact HEAD with exactly donor A7 as its sole parent."""

    result = subprocess.run(
        [
            str(git_executable),
            "-C",
            str(checkout),
            "rev-list",
            "--parents",
            "-n",
            "1",
            "HEAD",
        ],
        cwd=str(checkout),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    lineage = result.stdout.decode("ascii", errors="replace").strip().split()
    if result.returncode != 0 or lineage != [expected_head, donor_commit]:
        fail(
            f"{description} A8 source is not the single-parent direct Git child "
            "of donor A7"
        )


def script_path(config: Configuration, relative: str) -> str:
    return str(config.source_root / PurePosixPath(relative))


def runner_argv(
    config: Configuration,
    *,
    bryson_root: Path,
    completeness: Path,
    branch: str,
    output: Path,
    seed: int,
    mcmc_seed_offset: int,
    trials: int,
    maximum_steps: int,
    measurement_mode: str,
    label: str,
    run_status: str,
    private_raw: Path | None = None,
) -> tuple[str, ...]:
    argv = [
        str(config.python_executable),
        script_path(
            config, "research/bryson-joint-posterior/run_hab2_joint_posterior.py"
        ),
        "--bryson-root",
        str(bryson_root),
        "--stellar-catalog",
        str(config.stellar_catalog),
        "--pc-catalog",
        str(config.pc_catalog),
        "--completeness",
        str(completeness),
        "--branch",
        branch,
        "--out",
        str(output),
        "--seed",
        str(seed),
        "--mcmc-seed-offset",
        str(mcmc_seed_offset),
        "--trials",
        str(trials),
        "--walkers",
        str(WALKERS),
        "--burnin",
        str(BURNIN),
        "--steps",
        str(MINIMUM_STEPS),
        "--adaptive-production",
        "--max-steps",
        str(maximum_steps),
        "--check-interval",
        str(CHECK_INTERVAL),
        "--tau-multiple",
        f"{TAU_MULTIPLE:g}",
        "--tau-relative-tolerance",
        str(TAU_RELATIVE_TOLERANCE),
        "--tau-stability-checks",
        str(TAU_STABILITY_CHECKS),
        "--thin",
        str(RUNNER_THIN),
        "--measurement-error-mode",
        measurement_mode,
        "--run-status",
        run_status,
        "--run-label",
        label,
        "--verified-bryson-source-sha256",
        config.expected_bryson_source_sha256,
    ]
    if private_raw is not None:
        insertion = argv.index("--seed")
        argv[insertion:insertion] = ["--private-raw-chain-dir", str(private_raw)]
    return tuple(argv)


def aggregate_argv(
    config: Configuration,
    variant: Variant,
    *,
    shard_root: Path,
    raw_root: Path,
    output: Path,
) -> tuple[str, ...]:
    return (
        str(config.python_executable),
        script_path(
            config, "research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py"
        ),
        "--root",
        str(shard_root),
        "--branch",
        variant.branch,
        "--out",
        str(output),
        "--private-raw-chain-root",
        str(raw_root),
        "--expected-shards",
        str(SHARDS),
        "--trials-per-shard",
        str(TRIALS_PER_SHARD),
        "--walkers",
        str(WALKERS),
        "--steps",
        str(MINIMUM_STEPS),
        "--runner-thin",
        str(RUNNER_THIN),
        "--samples-per-realization",
        str(SAMPLES_PER_REALIZATION),
        "--require-all-converged",
        "--acceptance-profile",
        variant.acceptance_profile,
        "--minimum-ess-per-realization",
        "1000",
        "--cluster-bootstrap-replicates",
        str(BOOTSTRAP_REPLICATES),
        "--bootstrap-seed",
        str(AGGREGATION_BOOTSTRAP_SEED),
        "--inner-chain-batches",
        str(INNER_CHAIN_BATCHES),
        "--maximum-outer-q50-mcse-fraction",
        "0.10",
        "--maximum-inner-q50-mcse-fraction",
        "0.05",
        "--propagation-stride",
        str(PROPAGATION_STRIDE),
        "--expected-measurement-error-mode",
        variant.measurement_mode,
        "--expected-bryson-source-sha256",
        config.expected_bryson_source_sha256,
    )


def accepted_verifier_argv(
    config: Configuration, variant: Variant, aggregate_root: Path
) -> tuple[str, ...]:
    return (
        str(config.python_executable),
        script_path(config, "scripts/verify_accepted_aggregate.py"),
        "--artifact-root",
        str(aggregate_root),
        "--branch",
        variant.branch,
        "--pc-catalog",
        str(config.pc_catalog),
        "--stellar-catalog",
        str(config.stellar_catalog),
        "--expected-bryson-source-sha256",
        config.expected_bryson_source_sha256,
    )


def propagation_argv(
    config: Configuration,
    *,
    branch: str,
    hosts: Path,
    samples: Path,
    output: Path,
    selector: str,
) -> tuple[str, ...]:
    if selector not in {"canonical", "legacy"}:
        fail(f"unknown host selector: {selector}")
    if selector == "canonical":
        count = "263061992.36674237"
        temperatures = "539"
        label = "canonical PARSEC-TAMS selector"
        alternative: tuple[str, ...] = ()
    else:
        count = "196679892.57673854"
        temperatures = "536"
        label = "legacy 4.3 < logg < 7 selector"
        alternative = ("--skip-canonical-plugin-validation",)
    return (
        str(config.python_executable),
        script_path(
            config, "research/bryson-joint-posterior/propagate_hab2_joint_posterior.py"
        ),
        "--hosts",
        str(hosts),
        "--samples",
        str(samples),
        "--branch",
        branch,
        "--out",
        str(output),
        "--chunk-size",
        "2000",
        "--cluster-bootstrap-replicates",
        str(BOOTSTRAP_REPLICATES),
        "--bootstrap-seed",
        str(PROPAGATION_BOOTSTRAP_SEED),
        "--inner-chain-batches",
        str(INNER_CHAIN_BATCHES),
        "--expected-distinct-host-temperatures",
        temperatures,
        "--expected-host-count",
        count,
        "--host-selection-label",
        label,
        *alternative,
    )


def write_complete_shard_manifest(directory: Path, branch: str, label: str) -> None:
    expected_before = set(runner_output_names(branch, label)) | {
        "numerical_environment.txt"
    }
    ensure_exact_files(directory, expected_before, f"{branch} {label} shard output")
    manifest = directory / "SHA256SUMS_complete.txt"
    lines = [
        f"{sha256(directory / name)}  {name}\n" for name in sorted(expected_before)
    ]
    manifest.write_text("".join(lines), encoding="utf-8", newline="\n")
    ensure_exact_files(
        directory,
        expected_before | {manifest.name},
        f"{branch} {label} complete shard output",
    )


def validate_pilot_output(root: Path, branch: str, label: str) -> None:
    ensure_exact_files(root, runner_output_names(branch, label), f"pilot {branch}:{label}")
    summary = load_strict_json(
        root / f"posterior_summary_{branch}_{label}.json", "pilot summary"
    )
    diagnostics = load_strict_json(
        root / f"trial_diagnostics_{branch}_{label}.json", "pilot diagnostics"
    )
    if not isinstance(summary, dict) or summary.get("status") != "pilot_only":
        fail(f"pilot {branch}:{label} is not classified pilot_only")
    if not isinstance(diagnostics, list) or len(diagnostics) != PILOT_TRIALS:
        fail(f"pilot {branch}:{label} diagnostic count mismatch")
    if any(
        not isinstance(entry, dict)
        or entry.get("optimizer_success") is not True
        or entry.get("converged") is not True
        for entry in diagnostics
    ):
        fail(f"pilot {branch}:{label} contains a failed optimizer or convergence gate")


def validate_seed_stability_output(root: Path, branch: str) -> None:
    expected = set(seed_stability_output_names(branch))
    ensure_exact_files(root, expected, f"{branch} seed-stability output")
    report = load_strict_json(
        root / f"mcmc_seed_stability_{branch}.json", "seed-stability report"
    )
    if (
        not isinstance(report, dict)
        or report.get("status") != "pass"
        or report.get("branch") != branch
        or report.get("outer_realizations_identical_across_families") is not True
        or report.get("independent_mcmc_seed_families") is not True
        or report.get("all_trials_converged") is not True
        or report.get("gate_failures") != []
    ):
        fail(f"{branch} MCMC seed-stability gate did not pass")


def _summary_mode(summary: Mapping[str, Any]) -> str | None:
    measurement = summary.get("measurement_error")
    return measurement.get("mode") if isinstance(measurement, dict) else None


def write_legacy_pair_report(
    corrected_root: Path, legacy_root: Path, output_root: Path
) -> None:
    corrected_label = "corrected-pilot-seed-1"
    legacy_label = "legacy-pilot-paired"
    corrected = load_strict_json(
        corrected_root / f"posterior_summary_constant_{corrected_label}.json",
        "paired corrected pilot summary",
    )
    legacy = load_strict_json(
        legacy_root / f"posterior_summary_constant_{legacy_label}.json",
        "paired legacy pilot summary",
    )
    if not isinstance(corrected, dict) or not isinstance(legacy, dict):
        fail("paired pilot summaries must be JSON objects")
    fixed_keys = (
        "branch",
        "base_seed",
        "mcmc_seed_offset",
        "trials",
        "walkers",
        "burnin_steps",
        "production_steps_requested_minimum",
        "production_steps_requested_maximum",
        "thin",
    )
    mismatches = {
        key: (corrected.get(key), legacy.get(key))
        for key in fixed_keys
        if corrected.get(key) != legacy.get(key)
    }
    if mismatches:
        fail(f"corrected/legacy paired-pilot policy mismatch: {mismatches}")
    if (
        corrected.get("base_seed") != CONSTANT_PILOT_SEED
        or corrected.get("mcmc_seed_offset") != MCMC_SEED_OFFSET_A
        or corrected.get("trials") != PILOT_TRIALS
    ):
        fail("paired pilots do not use the release seed schedule")
    if _summary_mode(corrected) != CORRECTED_MODE or _summary_mode(legacy) != LEGACY_MODE:
        fail("paired pilots do not use the corrected/legacy measurement modes")
    for name, summary in (("corrected", corrected), ("legacy", legacy)):
        adaptive = summary.get("adaptive_production")
        if (
            not isinstance(adaptive, dict)
            or adaptive.get("enabled") is not True
            or adaptive.get("converged_realizations") != PILOT_TRIALS
        ):
            fail(f"{name} paired pilot did not converge in every realization")
    corrected_inputs = corrected.get("input_files")
    legacy_inputs = legacy.get("input_files")
    if not isinstance(corrected_inputs, dict) or not isinstance(legacy_inputs, dict):
        fail("paired pilot summaries lack input provenance")
    corrected_hashes = {
        key: value.get("sha256") if isinstance(value, dict) else None
        for key, value in corrected_inputs.items()
    }
    legacy_hashes = {
        key: value.get("sha256") if isinstance(value, dict) else None
        for key, value in legacy_inputs.items()
    }
    if corrected_hashes != legacy_hashes:
        fail("paired pilots used different locked input bytes")
    report = {
        "schema_version": 1,
        "status": "PASS",
        "branch": "constant",
        "corrected_mode": CORRECTED_MODE,
        "legacy_mode": LEGACY_MODE,
        "outer_seed_schedule_identical": True,
        "mcmc_seed_schedule_identical": True,
        "all_realizations_converged": True,
        "trials_per_mode": PILOT_TRIALS,
        "base_seed": CONSTANT_PILOT_SEED,
        "mcmc_seed_offset": MCMC_SEED_OFFSET_A,
        "locked_input_sha256": corrected_hashes,
    }
    make_empty_directory(output_root, "legacy paired-pilot gate output")
    report_path = output_root / "legacy_measurement_pilot_pair_constant.json"
    report_path.write_bytes(canonical_json_bytes(report))
    manifest_path = output_root / "SHA256SUMS_legacy_measurement_pilot_pair.txt"
    manifest_path.write_text(
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    ensure_exact_files(
        output_root,
        {report_path.name, manifest_path.name},
        "legacy paired-pilot gate output",
    )


def public_output_inventory(
    root: Path,
    *,
    expected: Iterable[str],
    protected_snapshots: Iterable[FileSnapshot],
) -> list[dict[str, Any]]:
    ensure_exact_files(root, expected, "public production output")
    protected = {
        (snapshot.sha256, snapshot.size_bytes) for snapshot in protected_snapshots
    }
    records: list[dict[str, Any]] = []
    for relative in sorted(expected):
        lower = relative.lower()
        name = PurePosixPath(relative).name
        if (
            lower.endswith(".bin")
            or name.startswith("raw_chain_index_")
            or name.startswith("SHA256SUMS_raw_chain_")
            or name
            in {
                CANONICAL_HOST_NAME,
                LEGACY_HOST_NAME,
                "PCs_dr25_hab2.csv",
                "dr25_stellar_berger2020_clean_hab2.txt",
                "rateModels3D.py",
                "out_sc0_hab2_insol_teff_extrap_const.fits.gz",
                "out_sc0_hab2_insol_teff.fits.gz",
            }
        ):
            fail(f"forbidden private or third-party file in public output: {relative}")
        snap = snapshot_file(root / PurePosixPath(relative), f"public output {relative}")
        if (snap.sha256, snap.size_bytes) in protected:
            fail(f"public output duplicates protected input bytes: {relative}")
        records.append(
            {
                "path": relative,
                "sha256": snap.sha256,
                "size_bytes": snap.size_bytes,
            }
        )
    return records


def canonical_github_repository_slug(url: str) -> str:
    if not isinstance(url, str) or url != url.strip() or any(
        character in url for character in ("\x00", "\r", "\n", "\\")
    ):
        fail("Git origin is not one canonical github.com URL")
    if re.fullmatch(
        r"git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url
    ):
        path = url.split(":", 1)[1]
    else:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            fail(f"Git origin contains an invalid port: {exc}")
        if parsed.scheme == "https":
            if (
                parsed.netloc != "github.com"
                or parsed.username is not None
                or parsed.password is not None
                or port is not None
                or parsed.query
                or parsed.fragment
            ):
                fail("HTTPS Git origin is not canonical github.com")
        elif parsed.scheme == "ssh":
            if (
                parsed.netloc != "git@github.com"
                or parsed.username != "git"
                or parsed.password is not None
                or port is not None
                or parsed.query
                or parsed.fragment
            ):
                fail("SSH Git origin is not canonical git@github.com")
        else:
            fail("Git origin must use canonical github.com HTTPS or SSH")
        path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path) is None:
        fail("Git origin does not contain one canonical owner/repository slug")
    return path


def git_checkout_evidence(
    git_executable: Path,
    checkout: Path,
    *,
    label: str,
    expected_repository: str,
    environment: Mapping[str, str],
) -> GitCheckoutEvidence:
    """Bind one clean Git checkout to its commit, tree, and archive bytes."""

    root_arg = Path(checkout)
    try:
        root_status = root_arg.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label} checkout: {exc}")
    if (
        stat.S_ISLNK(root_status.st_mode)
        or _has_reparse_point(root_status)
        or not stat.S_ISDIR(root_status.st_mode)
    ):
        fail(f"{label} checkout must be a real non-link directory")
    root = root_arg.resolve(strict=True)

    def git(*arguments: str) -> bytes:
        completed = subprocess.run(
            [str(git_executable), "-C", str(root), *arguments],
            cwd=str(root),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            fail(f"cannot inspect {label} checkout: {message}")
        return bytes(completed.stdout)

    if git("status", "--porcelain=v1", "--untracked-files=all"):
        fail(f"{label} checkout is not clean")
    try:
        remote = git("remote", "get-url", "origin").decode(
            "utf-8", errors="strict"
        ).strip()
        head_sha = git("rev-parse", "HEAD").decode("ascii", errors="strict").strip()
        tree_sha = (
            git("rev-parse", "HEAD^{tree}").decode("ascii", errors="strict").strip()
        )
    except UnicodeDecodeError as exc:
        fail(f"{label} Git object identifiers are not ASCII: {exc}")
    normalized_remote = canonical_github_repository_slug(remote)
    if normalized_remote != expected_repository:
        fail(f"{label} origin differs from its exact repository role")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha) or not re.fullmatch(
        r"[0-9a-f]{40}", tree_sha
    ):
        fail(f"{label} checkout does not use 40-hex Git object identifiers")
    tree_listing = git("ls-tree", "-r", "-z", "--full-tree", tree_sha)
    archive = git("archive", "--format=tar", "HEAD")
    if not tree_listing or not archive:
        fail(f"{label} Git tree or source archive is empty")
    return GitCheckoutEvidence(
        head_sha=head_sha,
        tree_sha=tree_sha,
        tree_sha256=hashlib.sha256(tree_listing).hexdigest(),
        source_archive_sha256=hashlib.sha256(archive).hexdigest(),
        source_archive_size_bytes=len(archive),
    )


def recheck_git_checkout_evidence(
    config: Configuration,
    *,
    production_expected: GitCheckoutEvidence,
    release_expected: GitCheckoutEvidence,
    environment: Mapping[str, str],
) -> None:
    production_current = git_checkout_evidence(
        config.git_executable,
        config.production_checkout,
        label="private production",
        expected_repository=EXPECTED_PRODUCTION_REPOSITORY,
        environment=environment,
    )
    release_current = git_checkout_evidence(
        config.git_executable,
        config.release_checkout,
        label="public release",
        expected_repository=EXPECTED_RELEASE_REPOSITORY,
        environment=environment,
    )
    if production_current != production_expected or release_current != release_expected:
        fail("production or release Git checkout changed after pre-flight")


@contextmanager
def _isolated_snapshot_import_path(source_path: Path) -> Iterable[None]:
    """Exclude the computational checkout/CWD during snapshot execution."""

    original = list(sys.path)
    repository_root = source_path.resolve(strict=True).parents[1]
    runtime_prefix = Path(sys.prefix).resolve(strict=False)

    def within(candidate: Path, boundary: Path) -> bool:
        try:
            return os.path.commonpath((str(candidate), str(boundary))) == str(boundary)
        except ValueError:
            return False

    safe: list[str] = []
    for entry in original:
        if not entry:
            continue
        try:
            candidate = Path(entry).resolve(strict=False)
        except OSError:
            continue
        if within(candidate, repository_root) and not within(candidate, runtime_prefix):
            continue
        safe.append(entry)
    sys.path[:] = safe
    try:
        yield
    finally:
        sys.path[:] = original


def _load_module_from_snapshot(path: Path, *, module_name: str, description: str) -> tuple[Any, FileSnapshot]:
    """Execute one exact captured Python source file without import-path trust."""

    snapshot = snapshot_file(
        path,
        description,
        collect=True,
        maximum_bytes=16_000_000,
    )
    if snapshot.data is None:
        fail(f"{description} source bytes were not captured")
    module = types.ModuleType(module_name)
    module.__file__ = str(snapshot.path)
    module.__package__ = ""
    module.__cached__ = None
    module.__loader__ = None
    module.__spec__ = None
    module.__dict__["__source_only_sha256__"] = snapshot.sha256
    missing = object()
    previous = sys.modules.get(module_name, missing)
    sys.modules[module_name] = module
    try:
        code = compile(snapshot.data, str(snapshot.path), "exec")
        with _isolated_snapshot_import_path(snapshot.path):
            exec(code, module.__dict__)
        recheck_snapshot(snapshot, description)
        if (
            module.__dict__.get("__source_only_sha256__") != snapshot.sha256
            or module.__dict__.get("__cached__") is not None
        ):
            fail(f"{description} changed its source-only loader evidence")
    except Exception as exc:
        if isinstance(exc, OrchestrationError):
            raise
        fail(f"cannot load {description} from captured bytes: {exc}")
    finally:
        if previous is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    return module, snapshot


def validate_external_host_contract(
    config: Configuration,
    *,
    source_evidence: SourceArchiveEvidence,
    production_git: GitCheckoutEvidence,
    release_git: GitCheckoutEvidence,
) -> HostContractBinding:
    """Bind external accepted contract B and report to immutable source A."""

    pending_path = config.source_root / "provenance" / HOST_CONTRACT_NAME
    pending_snapshot = snapshot_file(
        pending_path, "pending host artifact contract A"
    )
    accepted_snapshot = snapshot_file(
        config.host_contract, "external accepted host artifact contract B"
    )
    if accepted_snapshot.sha256 != config.expected_host_contract_sha256:
        fail("external accepted host contract B differs from the signed plan lock")
    if same_path(pending_snapshot.path, accepted_snapshot.path):
        fail("external accepted host contract B aliases pending contract A")
    verifier, verifier_snapshot = _load_module_from_snapshot(
        config.source_root / "scripts" / "verify_host_artifact_contract.py",
        module_name="_exoearth_v404_external_host_contract_verifier",
        description="host artifact contract verifier from computational source A",
    )
    expected_public_source = {
        "repository": EXPECTED_RELEASE_REPOSITORY,
        "commit_sha": release_git.head_sha,
        "git_tree_sha": release_git.tree_sha,
        "source_archive_sha256": source_evidence.snapshot.sha256,
        "source_archive_size_bytes": source_evidence.snapshot.size_bytes,
    }
    expected_private_source = {
        "repository": EXPECTED_PRODUCTION_REPOSITORY,
        "commit_sha": production_git.head_sha,
        "git_tree_sha": production_git.tree_sha,
        "source_archive_sha256": source_evidence.snapshot.sha256,
        "source_archive_size_bytes": source_evidence.snapshot.size_bytes,
    }
    try:
        evidence = verifier.validate_external_contract_promotion(
            pending_path,
            config.host_contract,
            config.expected_host_contract_sha256,
            expected_public_source,
            expected_private_source,
        )
        verified = verifier.verify_artifact(
            config.host_contract, config.host_artifact_root
        )
    except Exception as exc:
        fail(f"external accepted host contract B failed closed: {exc}")
    if not isinstance(evidence, dict) or not isinstance(verified, dict):
        fail("external host contract verifier returned malformed evidence")
    report_path_value = evidence.get("qualification_report_path")
    if not isinstance(report_path_value, str) or not report_path_value:
        fail("external host contract B lacks one qualification-report path")
    report_snapshot = snapshot_file(
        Path(report_path_value), "external host qualification report"
    )
    if (
        evidence.get("accepted_contract_sha256") != accepted_snapshot.sha256
        or evidence.get("accepted_contract_size_bytes") != accepted_snapshot.size_bytes
        or evidence.get("qualification_report_sha256") != report_snapshot.sha256
        or evidence.get("qualification_report_size_bytes") != report_snapshot.size_bytes
    ):
        fail("external host contract evidence differs from its stable snapshots")
    expected_source_lock = {
        "public_source": expected_public_source,
        "private_source": expected_private_source,
    }
    if evidence.get("source_lock") != expected_source_lock:
        fail("external host qualification report is not bound to computational source A")
    artifact_set = verified.get("artifact_set")
    if not isinstance(artifact_set, dict) or artifact_set.get("production_accepted") is not True:
        fail("external host contract B did not select one production-accepted tuple")
    for snapshot, description in (
        (pending_snapshot, "pending host artifact contract A"),
        (accepted_snapshot, "external accepted host artifact contract B"),
        (report_snapshot, "external host qualification report"),
        (verifier_snapshot, "host artifact contract verifier from computational source A"),
    ):
        recheck_snapshot(snapshot, description)
    return HostContractBinding(
        pending_contract=pending_snapshot,
        accepted_contract=accepted_snapshot,
        qualification_report=report_snapshot,
        source_lock=expected_source_lock,
        evidence=dict(evidence),
    )


def validate_configuration(
    config: Configuration,
    *,
    environment: Mapping[str, str],
) -> tuple[
    SourceArchiveEvidence,
    list[FileSnapshot],
    GitCheckoutEvidence,
    GitCheckoutEvidence,
    HostContractBinding,
    RecoveryContractBinding | None,
]:
    validate_ubuntu_2204_wsl()
    if not 1 <= config.maximum_parallel_shards <= MAXIMUM_PARALLEL_SHARDS:
        fail("maximum parallel shard processes must be between 1 and 4")
    if config.expected_bryson_source_sha256 != EXPECTED_BRYSON_SOURCE_SHA256:
        fail("Bryson source SHA-256 differs from the v4.0.4 lock")
    if SHA256_RE.fullmatch(config.expected_host_contract_sha256) is None:
        fail("expected external host-contract SHA-256 is malformed")
    is_recovery = recovery_enabled(config)
    if is_recovery and (
        config.expected_recovery_contract_sha256 is None
        or SHA256_RE.fullmatch(config.expected_recovery_contract_sha256) is None
        or type(config.expected_recovery_contract_size_bytes) is not int
        or config.expected_recovery_contract_size_bytes <= 0
    ):
        fail("expected external recovery-contract hash/size is malformed")
    for description, path in (
        ("source root", config.source_root),
        ("source archive", config.source_archive),
        ("Python executable", config.python_executable),
        ("rate-model source", config.rate_model_source),
        ("stellar catalog", config.stellar_catalog),
        ("planet-candidate catalog", config.pc_catalog),
        ("constant completeness contour", config.constant_completeness),
        ("zero completeness contour", config.zero_completeness),
        ("host artifact root", config.host_artifact_root),
        ("host contract", config.host_contract),
        ("parent host table", config.parent_hosts),
        ("canonical hosts", config.canonical_hosts),
        ("legacy hosts", config.legacy_hosts),
        ("metallicity audit root", config.metallicity_audit_root),
        ("production checkout", config.production_checkout),
        ("release checkout", config.release_checkout),
        ("signed local command plan", config.command_plan),
        ("Git executable", config.git_executable),
        ("private work root", config.private_work_root),
        ("private raw root", config.private_raw_root),
        ("public output root", config.public_output_root),
    ):
        require_absolute(path, description)
    if is_recovery:
        recovery_paths = (
            ("external MCMC recovery contract", config.recovery_contract),
            ("donor MCMC work-shard root", config.donor_work_shard_root),
            ("donor MCMC raw-chain root", config.donor_raw_root),
            ("donor failed-run evidence root", config.donor_evidence_root),
            ("donor A7 attestation contract", config.donor_attestation_contract),
            ("donor A7 command plan", config.donor_command_plan),
            ("donor A7 numerical runtime", config.donor_numerical_runtime_manifest),
            ("donor A7 source archive", config.donor_source_archive),
            ("MCMC source-transition report", config.source_transition_evidence),
            ("MCMC recovery qualification report", config.recovery_qualification_report),
            ("trusted ssh-keygen executable", config.ssh_keygen_executable),
        )
        for description, path in recovery_paths:
            if path is None:
                fail(f"{description} is missing")
            require_absolute(path, description)
    expected_controller = config.source_root / "scripts" / Path(__file__).name
    if not same_path(Path(__file__), expected_controller):
        fail("controller is not executing from the supplied source root")
    pending_contract = config.source_root / "provenance" / HOST_CONTRACT_NAME
    if same_path(config.host_contract, pending_contract):
        fail("accepted host contract must be external to computational source A")
    for description, source_checkout in (
        ("execution source A", config.source_root),
        ("private production checkout", config.production_checkout),
        ("public release checkout", config.release_checkout),
    ):
        if is_within(config.host_contract, source_checkout):
            fail(f"accepted host contract B must be outside the {description}")
    if not same_path(config.canonical_hosts, config.host_artifact_root / CANONICAL_HOST_NAME):
        fail("canonical host path is not the canonical file in host-artifact-root")
    if not same_path(config.legacy_hosts, config.host_artifact_root / LEGACY_HOST_NAME):
        fail("legacy host path is not the legacy file in host-artifact-root")
    if not same_path(config.parent_hosts, config.host_artifact_root / PARENT_HOST_NAME):
        fail("parent host path is not the parent file in host-artifact-root")
    if not config.python_executable.exists() or not os.access(config.python_executable, os.X_OK):
        fail("Python executable is missing or not executable")
    if not config.git_executable.exists() or not os.access(config.git_executable, os.X_OK):
        fail("Git executable is missing or not executable")
    evidence = inspect_source_archive(
        config.source_archive, config.expected_source_archive_sha256
    )
    verify_source_tree(config.source_root, evidence)
    protected_paths = {
        "source_root": config.source_root,
        "source_archive": config.source_archive,
        "rate_model_source": config.rate_model_source,
        "stellar_catalog": config.stellar_catalog,
        "pc_catalog": config.pc_catalog,
        "constant_completeness": config.constant_completeness,
        "zero_completeness": config.zero_completeness,
        "host_artifact_root": config.host_artifact_root,
        "host_contract": config.host_contract,
        "parent_hosts": config.parent_hosts,
        "canonical_hosts": config.canonical_hosts,
        "legacy_hosts": config.legacy_hosts,
        "metallicity_audit_root": config.metallicity_audit_root,
        "production_checkout": config.production_checkout,
        "release_checkout": config.release_checkout,
        "command_plan": config.command_plan,
        "git_executable": config.git_executable,
    }
    if is_recovery:
        protected_paths.update(
            {
                "recovery_contract": config.recovery_contract,
                "donor_work_shard_root": config.donor_work_shard_root,
                "donor_raw_root": config.donor_raw_root,
                "donor_evidence_root": config.donor_evidence_root,
                "donor_attestation_contract": config.donor_attestation_contract,
                "donor_command_plan": config.donor_command_plan,
                "donor_numerical_runtime_manifest": config.donor_numerical_runtime_manifest,
                "donor_source_archive": config.donor_source_archive,
                "source_transition_evidence": config.source_transition_evidence,
                "recovery_qualification_report": config.recovery_qualification_report,
                "ssh_keygen_executable": config.ssh_keygen_executable,
            }
        )
    protected_snapshots = [
        snapshot_file(config.command_plan, "signed local command plan"),
        snapshot_file(config.rate_model_source, "locked rate-model source"),
        snapshot_file(config.stellar_catalog, "locked stellar catalog"),
        snapshot_file(config.pc_catalog, "locked planet-candidate catalog"),
        snapshot_file(config.constant_completeness, "locked constant completeness"),
        snapshot_file(config.zero_completeness, "locked zero completeness"),
        snapshot_file(config.parent_hosts, "parent host rows"),
        snapshot_file(config.canonical_hosts, "canonical host rows"),
        snapshot_file(config.legacy_hosts, "legacy host rows"),
        snapshot_file(config.git_executable, "attestation-bound Git executable"),
    ]
    production_git = git_checkout_evidence(
        config.git_executable,
        config.production_checkout,
        label="private production",
        expected_repository=EXPECTED_PRODUCTION_REPOSITORY,
        environment=environment,
    )
    release_git = git_checkout_evidence(
        config.git_executable,
        config.release_checkout,
        label="public release",
        expected_repository=EXPECTED_RELEASE_REPOSITORY,
        environment=environment,
    )
    if (
        production_git.head_sha != release_git.head_sha
        or production_git.tree_sha != release_git.tree_sha
        or production_git.source_archive_sha256
        != release_git.source_archive_sha256
        or production_git.source_archive_size_bytes
        != release_git.source_archive_size_bytes
        or production_git.source_archive_size_bytes
        != evidence.snapshot.size_bytes
        or release_git.source_archive_size_bytes != evidence.snapshot.size_bytes
        or production_git.source_archive_sha256 != evidence.snapshot.sha256
        or release_git.source_archive_sha256 != evidence.snapshot.sha256
        or production_git.tree_sha256 != release_git.tree_sha256
    ):
        fail("private production and public release computational source A differs")
    if (
        production_git.tree_sha != release_git.tree_sha
        or production_git.tree_sha256 != release_git.tree_sha256
    ):
        fail("private production and public release Git trees are not content-identical")
    if production_git.source_archive_sha256 != evidence.snapshot.sha256:
        fail("supplied source archive is not exact private-production git archive HEAD")
    host_binding = validate_external_host_contract(
        config,
        source_evidence=evidence,
        production_git=production_git,
        release_git=release_git,
    )
    protected_snapshots.extend(
        (
            host_binding.pending_contract,
            host_binding.accepted_contract,
            host_binding.qualification_report,
        )
    )
    recovery_binding: RecoveryContractBinding | None = None
    if is_recovery:
        if config.ssh_keygen_executable is None:
            fail("trusted ssh-keygen executable is missing")
        if (
            not config.ssh_keygen_executable.exists()
            or not os.access(config.ssh_keygen_executable, os.X_OK)
        ):
            fail("trusted ssh-keygen executable is missing or not executable")
        donor_roots = {
            "donor MCMC work-shard root": config.donor_work_shard_root,
            "donor MCMC raw-chain root": config.donor_raw_root,
            "donor failed-run evidence root": config.donor_evidence_root,
        }
        protected_roots = {
            "execution source A": config.source_root,
            "private production checkout": config.production_checkout,
            "public release checkout": config.release_checkout,
            "host artifact root": config.host_artifact_root,
            "metallicity audit root": config.metallicity_audit_root,
        }
        for donor_name, donor_root in donor_roots.items():
            if donor_root is None:
                fail(f"{donor_name} is missing")
            for protected_name, protected_root in protected_roots.items():
                if paths_overlap(donor_root, protected_root):
                    fail(f"{donor_name} overlaps {protected_name}")
        donor_items = list(donor_roots.items())
        for index, (left_name, left) in enumerate(donor_items):
            for right_name, right in donor_items[index + 1 :]:
                if paths_overlap(left, right):
                    fail(f"{left_name} overlaps {right_name}")
        recovery_binding = validate_recovery_contract(
            config,
            current_source=evidence,
            current_git=production_git,
        )
        donor_commit = recovery_binding.contract["donor"]["source_commit"]
        for checkout_name, checkout, expected_head in (
            ("private production", config.production_checkout, production_git.head_sha),
            ("public release", config.release_checkout, release_git.head_sha),
        ):
            validate_recovery_lineage(
                config.git_executable,
                checkout,
                expected_head=expected_head,
                donor_commit=donor_commit,
                environment=environment,
                description=checkout_name,
            )
        protected_snapshots.extend(
            (
                recovery_binding.snapshot,
                *recovery_binding.evidence_snapshots,
                recovery_binding.donor_attestation_contract,
                recovery_binding.donor_plan,
                recovery_binding.donor_runtime,
                recovery_binding.donor_source_archive.snapshot,
                recovery_binding.source_transition,
                recovery_binding.qualification_report,
                *recovery_binding.manifest_snapshots,
                recovery_binding.trusted_ssh_keygen,
            )
        )
    normalized_roots = validate_mutable_roots(
        {
            "private_work_root": config.private_work_root,
            "private_raw_root": config.private_raw_root,
            "public_output_root": config.public_output_root,
        },
        protected_paths,
    )
    for name, normalized in normalized_roots.items():
        configured = getattr(config, name)
        if not same_path(configured, normalized):
            fail(f"cannot normalize mutable root {name}")
    return (
        evidence,
        protected_snapshots,
        production_git,
        release_git,
        host_binding,
        recovery_binding,
    )


def create_numerical_environment(
    config: Configuration,
    *,
    environment: Mapping[str, str],
    log_root: Path,
) -> tuple[Path, Path, list[CommandResult]]:
    preflight = make_empty_directory(config.private_work_root / "preflight", "preflight root")
    runtime_path = preflight / "numerical_runtime.json"
    specs = (
        CommandSpec(
            "verify-dependency-lock",
            (
                str(config.python_executable),
                script_path(config, "scripts/verify_dependency_lock.py"),
            ),
            log_root / "verify-dependency-lock.log",
        ),
        CommandSpec(
            "pip-check",
            (str(config.python_executable), "-m", "pip", "check"),
            log_root / "pip-check.log",
        ),
        CommandSpec(
            "verify-numerical-runtime",
            (
                str(config.python_executable),
                script_path(config, "scripts/verify_numerical_runtime.py"),
                "--output",
                str(runtime_path),
            ),
            log_root / "verify-numerical-runtime.log",
        ),
    )
    results = [
        run_command(spec, cwd=config.source_root, environment=environment)
        for spec in specs
    ]
    ensure_exact_files(preflight, {runtime_path.name}, "numerical runtime preflight")
    runtime = load_strict_json(runtime_path, "numerical runtime report")
    if not isinstance(runtime, dict) or runtime.get("status") != "PASS":
        fail("numerical runtime policy did not pass")
    python_version = str(runtime.get("python", ""))
    if not python_version.startswith("3.10."):
        fail(f"production Python is not 3.10: {python_version!r}")
    version_output = capture_command(
        (str(config.python_executable), "--version"),
        cwd=config.source_root,
        environment=environment,
        description="python --version",
    )
    pip_version_output = capture_command(
        (str(config.python_executable), "-m", "pip", "--version"),
        cwd=config.source_root,
        environment=environment,
        description="pip --version",
    )
    freeze_output = capture_command(
        (str(config.python_executable), "-m", "pip", "freeze", "--all"),
        cwd=config.source_root,
        environment=environment,
        description="pip freeze --all",
    )
    frozen_lines = validate_pip_freeze(freeze_output)
    numerical_environment = config.private_work_root / "numerical_environment.txt"
    rendered = bytearray(snapshot_file(runtime_path, "runtime report", collect=True).data or b"")
    for data in (version_output, pip_version_output):
        rendered.extend(data)
        if data and not data.endswith(b"\n"):
            rendered.extend(b"\n")
    rendered.extend(("\n".join(frozen_lines) + "\n").encode("utf-8"))
    numerical_environment.write_bytes(bytes(rendered))
    return numerical_environment, runtime_path, results


def preflight_locked_inputs_and_hosts(
    config: Configuration,
    *,
    host_binding: HostContractBinding,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    input_checks = (
        f"bryson_rate_models_3d={config.rate_model_source}",
        f"bryson_pc_catalog={config.pc_catalog}",
        f"bryson_stellar_catalog_extracted={config.stellar_catalog}",
        f"completeness_constant={config.constant_completeness}",
        f"completeness_zero={config.zero_completeness}",
    )
    argv: list[str] = [
        str(config.python_executable),
        script_path(config, "scripts/verify_locked_inputs.py"),
    ]
    for check in input_checks:
        argv.extend(("--check", check))
    locked_spec = CommandSpec(
        "verify-locked-inputs",
        tuple(argv),
        log_root / "verify-locked-inputs.log",
    )
    host_spec = CommandSpec(
        "verify-host-artifact",
        (
            str(config.python_executable),
            script_path(config, "scripts/verify_host_artifact_contract.py"),
            "--mode",
            "verify",
            "--contract",
            str(config.host_contract),
            "--artifact-root",
            str(config.host_artifact_root),
        ),
        log_root / "verify-host-artifact.log",
    )
    results = [
        run_command(locked_spec, cwd=config.source_root, environment=environment)
    ]
    recheck_host_contract_binding(host_binding, "host preflight before verification")
    results.append(
        run_command(host_spec, cwd=config.source_root, environment=environment)
    )
    recheck_host_contract_binding(host_binding, "host preflight after verification")
    return results


def create_bryson_projection(config: Configuration) -> Path:
    root = make_empty_directory(
        config.private_work_root / "bryson-source-projection",
        "private Bryson source projection",
    )
    insolation = root / "insolation"
    insolation.mkdir()
    destination = insolation / "rateModels3D.py"
    shutil.copyfile(config.rate_model_source, destination)
    if sha256(destination) != config.expected_bryson_source_sha256:
        fail("private Bryson source projection differs from the locked input")
    return root


def run_pilots(
    config: Configuration,
    *,
    bryson_root: Path,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    pilot_root = make_empty_directory(config.private_work_root / "pilots", "pilot root")
    corrected_root = pilot_root / "corrected"
    corrected_root.mkdir()
    specs: list[CommandSpec] = []
    for branch, completeness, base_seed in (
        ("constant", config.constant_completeness, CONSTANT_PILOT_SEED),
        ("zero", config.zero_completeness, ZERO_PILOT_SEED),
    ):
        branch_root = corrected_root / branch
        branch_root.mkdir()
        for family, offset in ((1, MCMC_SEED_OFFSET_A), (2, MCMC_SEED_OFFSET_B)):
            label = f"corrected-pilot-seed-{family}"
            output = make_empty_directory(
                branch_root / f"family-{family}", f"{branch} pilot family {family}"
            )
            specs.append(
                CommandSpec(
                    f"pilot-{branch}-family-{family}",
                    runner_argv(
                        config,
                        bryson_root=bryson_root,
                        completeness=completeness,
                        branch=branch,
                        output=output,
                        seed=base_seed,
                        mcmc_seed_offset=offset,
                        trials=PILOT_TRIALS,
                        maximum_steps=20_000,
                        measurement_mode=CORRECTED_MODE,
                        label=label,
                        run_status="pilot_only",
                    ),
                    log_root / f"pilot-{branch}-family-{family}.log",
                )
            )
    runner = lambda spec: run_command(  # noqa: E731
        spec, cwd=config.source_root, environment=environment
    )
    results = run_bounded(
        specs,
        maximum_parallel=min(config.maximum_parallel_shards, len(specs)),
        runner=runner,
    )
    for branch in ("constant", "zero"):
        for family in (1, 2):
            validate_pilot_output(
                corrected_root / branch / f"family-{family}",
                branch,
                f"corrected-pilot-seed-{family}",
            )
        stability = make_empty_directory(
            config.public_output_root / "qualification" / "seed-stability" / branch,
            f"{branch} seed-stability output",
        )
        spec = CommandSpec(
            f"seed-stability-{branch}",
            (
                str(config.python_executable),
                script_path(
                    config,
                    "research/bryson-joint-posterior/compare_mcmc_seed_families.py",
                ),
                "--root",
                str(corrected_root / branch),
                "--branch",
                branch,
                "--out",
                str(stability),
                "--expected-families",
                "2",
                "--max-quantile-width-fraction",
                "0.15",
            ),
            log_root / f"seed-stability-{branch}.log",
        )
        results.append(
            run_command(spec, cwd=config.source_root, environment=environment)
        )
        validate_seed_stability_output(stability, branch)
    legacy_root = make_empty_directory(
        pilot_root / "legacy-measurement-constant", "legacy paired pilot"
    )
    legacy_spec = CommandSpec(
        "pilot-legacy-measurement-constant",
        runner_argv(
            config,
            bryson_root=bryson_root,
            completeness=config.constant_completeness,
            branch="constant",
            output=legacy_root,
            seed=CONSTANT_PILOT_SEED,
            mcmc_seed_offset=MCMC_SEED_OFFSET_A,
            trials=PILOT_TRIALS,
            maximum_steps=20_000,
            measurement_mode=LEGACY_MODE,
            label="legacy-pilot-paired",
            run_status="pilot_only",
        ),
        log_root / "pilot-legacy-measurement-constant.log",
    )
    results.append(
        run_command(legacy_spec, cwd=config.source_root, environment=environment)
    )
    validate_pilot_output(legacy_root, "constant", "legacy-pilot-paired")
    write_legacy_pair_report(
        corrected_root / "constant" / "family-1",
        legacy_root,
        pilot_root / "legacy-pair-gate",
    )
    return results


def _stable_copy_recovery_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int | None,
    description: str,
) -> FileSnapshot:
    """Byte-copy one immutable donor file into a fresh O_EXCL destination."""

    if SHA256_RE.fullmatch(expected_sha256) is None:
        fail(f"{description} expected SHA-256 is malformed")
    if expected_size_bytes is not None and (
        type(expected_size_bytes) is not int or expected_size_bytes <= 0
    ):
        fail(f"{description} expected size is malformed")
    snapshot_plain_directory_chain(source.parent, f"{description} source parent")
    snapshot_plain_directory_chain(destination.parent, f"{description} destination parent")
    if destination.exists() or destination.is_symlink():
        fail(f"{description} destination already exists")
    try:
        named_before = source.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description} source: {exc}")
    if (
        stat.S_ISLNK(named_before.st_mode)
        or _has_reparse_point(named_before)
        or not stat.S_ISREG(named_before.st_mode)
        or named_before.st_nlink != 1
    ):
        fail(f"{description} source is not one plain singly-linked regular file")
    source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor = -1
    destination_descriptor = -1
    created = False
    digest = hashlib.sha256()
    size = 0
    try:
        source_descriptor = os.open(source, source_flags)
        source_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source_before.st_nlink != 1
            or _identity(source_before) != _identity(named_before)
        ):
            fail(f"{description} source changed before copy")
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        created = True
        destination_before = os.fstat(destination_descriptor)
        if not stat.S_ISREG(destination_before.st_mode) or destination_before.st_nlink != 1:
            fail(f"{description} destination is not one new regular file")
        if (source_before.st_dev, source_before.st_ino) == (
            destination_before.st_dev,
            destination_before.st_ino,
        ):
            fail(f"{description} destination aliases donor storage")
        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    fail(f"{description} destination write made no progress")
                view = view[written:]
        os.fsync(destination_descriptor)
        source_after = os.fstat(source_descriptor)
        destination_after = os.fstat(destination_descriptor)
    except OrchestrationError:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
            destination_descriptor = -1
        if source_descriptor >= 0:
            os.close(source_descriptor)
            source_descriptor = -1
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    except OSError as exc:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
            destination_descriptor = -1
        if source_descriptor >= 0:
            os.close(source_descriptor)
            source_descriptor = -1
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        fail(f"cannot copy {description}: {exc}")
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
    try:
        source_named_after = source.lstat()
        destination_named_after = destination.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description} after copy: {exc}")
    if (
        _identity(source_before) != _identity(source_after)
        or _identity(source_after) != _identity(source_named_after)
        or _identity(destination_after) != _identity(destination_named_after)
        or not stat.S_ISREG(destination_named_after.st_mode)
        or destination_named_after.st_nlink != 1
        or size != source_before.st_size
        or size != destination_after.st_size
        or digest.hexdigest() != expected_sha256
        or (expected_size_bytes is not None and size != expected_size_bytes)
    ):
        try:
            destination.unlink()
        except OSError:
            pass
        fail(f"{description} failed stable byte-copy verification")
    snapshot_plain_directory_chain(source.parent, f"{description} source parent after copy")
    snapshot_plain_directory_chain(
        destination.parent, f"{description} destination parent after copy"
    )
    destination_snapshot = snapshot_file(destination, f"{description} copied destination")
    if (
        destination_snapshot.sha256 != expected_sha256
        or destination_snapshot.size_bytes != size
        or destination_snapshot.identity[:2] == _identity(source_after)[:2]
    ):
        fail(f"{description} copied destination failed independent verification")
    return destination_snapshot


def import_recovery_shards(
    config: Configuration,
    binding: RecoveryContractBinding,
    *,
    numerical_environment: Path,
) -> tuple[dict[str, tuple[Path, Path]], RecoveryImportEvidence]:
    """Copy and independently rehash the exact 48+48 qualified donor shards."""

    numerical_snapshot = snapshot_file(
        numerical_environment, "fresh recovery numerical environment"
    )
    work_parent = make_empty_directory(
        config.private_work_root / "shards", "recovery work-shard root"
    )
    raw_parent = config.private_raw_root
    if any(raw_parent.iterdir()):
        fail("fresh private raw root is not empty before MCMC recovery import")
    roots: dict[str, tuple[Path, Path]] = {}
    copied: list[FileSnapshot] = []
    work_records: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
    contract_variants = binding.contract["variants"]
    for variant, contract_variant in zip(VARIANTS, contract_variants):
        destination_work_variant = make_empty_directory(
            work_parent / variant.name, f"recovery {variant.name} work root"
        )
        destination_raw_variant = make_empty_directory(
            raw_parent / variant.name, f"recovery {variant.name} raw root"
        )
        roots[variant.name] = (destination_work_variant, destination_raw_variant)
        for shard, shard_contract in enumerate(contract_variant["shards"]):
            label = f"production-shard-{shard}"
            source_work = binding.donor_work_root / variant.name / f"shard-{shard:02d}"
            source_raw = binding.donor_raw_root / variant.name / f"shard-{shard:02d}"
            destination_work = make_empty_directory(
                destination_work_variant / f"shard-{shard:02d}",
                f"recovery {variant.name} work shard {shard}",
            )
            destination_raw = make_empty_directory(
                destination_raw_variant / f"shard-{shard:02d}",
                f"recovery {variant.name} raw shard {shard}",
            )
            work_manifest = snapshot_file(
                source_work / "SHA256SUMS_complete.txt",
                f"recovery {variant.name} shard {shard} work manifest",
                collect=True,
                maximum_bytes=1_000_000,
            )
            _matches_recovery_evidence(
                work_manifest,
                shard_contract["work_manifest"],
                f"recovery {variant.name} shard {shard} work manifest",
            )
            work_targets = (*runner_output_names(variant.branch, label), "numerical_environment.txt")
            work_entries = _parse_recovery_manifest(
                work_manifest,
                expected_targets=work_targets,
                description=f"recovery {variant.name} shard {shard} work manifest",
            )
            if work_entries["numerical_environment.txt"] != numerical_snapshot.sha256:
                fail(
                    f"recovery {variant.name} shard {shard} numerical environment "
                    "differs from the fresh runtime"
                )
            for name in sorted(work_targets):
                snapshot = _stable_copy_recovery_file(
                    source_work / name,
                    destination_work / name,
                    expected_sha256=work_entries[name],
                    expected_size_bytes=None,
                    description=f"recovery {variant.name} shard {shard} work file {name}",
                )
                copied.append(snapshot)
                work_records.append(
                    {
                        "path": f"{variant.name}/shard-{shard:02d}/{name}",
                        "sha256": snapshot.sha256,
                        "size_bytes": snapshot.size_bytes,
                    }
                )
            copied_work_manifest = _stable_copy_recovery_file(
                work_manifest.path,
                destination_work / work_manifest.path.name,
                expected_sha256=work_manifest.sha256,
                expected_size_bytes=work_manifest.size_bytes,
                description=f"recovery {variant.name} shard {shard} work manifest",
            )
            copied.append(copied_work_manifest)
            work_records.append(
                {
                    "path": f"{variant.name}/shard-{shard:02d}/{work_manifest.path.name}",
                    "sha256": copied_work_manifest.sha256,
                    "size_bytes": copied_work_manifest.size_bytes,
                }
            )
            validate_sha256_manifest_root(
                destination_work,
                manifest_name="SHA256SUMS_complete.txt",
                target_names=work_targets,
                description=f"imported {variant.name} work shard {shard}",
            )

            raw_manifest_name = f"SHA256SUMS_raw_chain_{variant.branch}_{label}.txt"
            raw_manifest = snapshot_file(
                source_raw / raw_manifest_name,
                f"recovery {variant.name} shard {shard} raw manifest",
                collect=True,
                maximum_bytes=1_000_000,
            )
            _matches_recovery_evidence(
                raw_manifest,
                shard_contract["raw_manifest"],
                f"recovery {variant.name} shard {shard} raw manifest",
            )
            raw_targets = tuple(
                name
                for name in raw_output_names(variant.branch, label)
                if name != raw_manifest_name
            )
            raw_entries = _parse_recovery_manifest(
                raw_manifest,
                expected_targets=raw_targets,
                description=f"recovery {variant.name} shard {shard} raw manifest",
            )
            for name in sorted(raw_targets):
                snapshot = _stable_copy_recovery_file(
                    source_raw / name,
                    destination_raw / name,
                    expected_sha256=raw_entries[name],
                    expected_size_bytes=None,
                    description=f"recovery {variant.name} shard {shard} raw file {name}",
                )
                copied.append(snapshot)
                raw_records.append(
                    {
                        "path": f"{variant.name}/shard-{shard:02d}/{name}",
                        "sha256": snapshot.sha256,
                        "size_bytes": snapshot.size_bytes,
                    }
                )
            copied_raw_manifest = _stable_copy_recovery_file(
                raw_manifest.path,
                destination_raw / raw_manifest.path.name,
                expected_sha256=raw_manifest.sha256,
                expected_size_bytes=raw_manifest.size_bytes,
                description=f"recovery {variant.name} shard {shard} raw manifest",
            )
            copied.append(copied_raw_manifest)
            raw_records.append(
                {
                    "path": f"{variant.name}/shard-{shard:02d}/{raw_manifest.path.name}",
                    "sha256": copied_raw_manifest.sha256,
                    "size_bytes": copied_raw_manifest.size_bytes,
                }
            )
            validate_sha256_manifest_root(
                destination_raw,
                manifest_name=raw_manifest_name,
                target_names=raw_targets,
                description=f"imported {variant.name} raw shard {shard}",
            )
            recheck_snapshot(work_manifest, f"donor {variant.name} shard {shard} work manifest")
            recheck_snapshot(raw_manifest, f"donor {variant.name} shard {shard} raw manifest")

    work_files, work_directories = _recovery_tree_paths(raw=False)
    raw_files, raw_directories = _recovery_tree_paths(raw=True)
    ensure_exact_tree(
        work_parent,
        expected_files=work_files,
        expected_directories=work_directories,
        description="imported MCMC work-shard tree",
    )
    ensure_exact_tree(
        raw_parent,
        expected_files=raw_files,
        expected_directories=raw_directories,
        description="imported MCMC raw-chain tree",
    )
    _validate_recovery_donor_trees(config, binding.contract)
    if len(work_records) != RECOVERY_WORK_FILE_COUNT or len(raw_records) != RECOVERY_RAW_FILE_COUNT:
        fail("imported MCMC file count differs from the exact recovery policy")
    work_size = sum(item["size_bytes"] for item in work_records)
    raw_size = sum(item["size_bytes"] for item in raw_records)
    if work_size + raw_size != RECOVERY_TOTAL_SIZE_BYTES:
        fail("imported MCMC bytes differ from the exact qualified donor size")
    imported_work_root, imported_work_identity = snapshot_plain_directory_chain(
        work_parent, "imported MCMC work-shard root"
    )
    imported_raw_root, imported_raw_identity = snapshot_plain_directory_chain(
        raw_parent, "imported MCMC raw-chain root"
    )
    evidence = RecoveryImportEvidence(
        snapshots=tuple(copied),
        work_root=imported_work_root,
        work_root_identity=imported_work_identity,
        work_file_count=len(work_records),
        work_size_bytes=work_size,
        work_tree_sha256=hashlib.sha256(
            canonical_json_bytes(sorted(work_records, key=lambda item: item["path"]))
        ).hexdigest(),
        raw_root=imported_raw_root,
        raw_root_identity=imported_raw_identity,
        raw_file_count=len(raw_records),
        raw_size_bytes=raw_size,
        raw_tree_sha256=hashlib.sha256(
            canonical_json_bytes(sorted(raw_records, key=lambda item: item["path"]))
        ).hexdigest(),
    )
    return roots, evidence


def _validate_recovery_import_policy(
    evidence: RecoveryImportEvidence,
    policy: Mapping[str, Any],
) -> None:
    """Bind the freshly copied split inventories to the qualified policy."""

    expected = (
        policy["work_file_count"],
        policy["work_size_bytes"],
        policy["work_tree_sha256"],
        policy["raw_file_count"],
        policy["raw_size_bytes"],
        policy["raw_tree_sha256"],
        policy["total_file_count"],
        policy["total_size_bytes"],
    )
    observed = (
        evidence.work_file_count,
        evidence.work_size_bytes,
        evidence.work_tree_sha256,
        evidence.raw_file_count,
        evidence.raw_size_bytes,
        evidence.raw_tree_sha256,
        evidence.work_file_count + evidence.raw_file_count,
        evidence.work_size_bytes + evidence.raw_size_bytes,
    )
    if observed != expected:
        fail("imported MCMC split inventories differ from the exact recovery policy")


def recheck_recovery_import(
    evidence: RecoveryImportEvidence,
    description: str,
    *,
    rehash_files: bool,
) -> None:
    """Reassert imported-root identity, exact set, and optionally every byte hash."""

    work_files, work_directories = _recovery_tree_paths(raw=False)
    raw_files, raw_directories = _recovery_tree_paths(raw=True)
    for name, root, identity, files, directories in (
        (
            "work",
            evidence.work_root,
            evidence.work_root_identity,
            work_files,
            work_directories,
        ),
        (
            "raw",
            evidence.raw_root,
            evidence.raw_root_identity,
            raw_files,
            raw_directories,
        ),
    ):
        current_root, current_identity = snapshot_plain_directory_chain(
            root, f"{description} {name} root"
        )
        if current_root != root or current_identity != identity:
            fail(f"{description} {name} root identity changed")
        ensure_exact_tree(
            root,
            expected_files=files,
            expected_directories=directories,
            description=f"{description} {name} tree",
        )
    if rehash_files:
        for index, snapshot in enumerate(evidence.snapshots):
            recheck_snapshot(snapshot, f"{description} artifact {index}")
    for name, root, identity, files, directories in (
        (
            "work",
            evidence.work_root,
            evidence.work_root_identity,
            work_files,
            work_directories,
        ),
        (
            "raw",
            evidence.raw_root,
            evidence.raw_root_identity,
            raw_files,
            raw_directories,
        ),
    ):
        ensure_exact_tree(
            root,
            expected_files=files,
            expected_directories=directories,
            description=f"{description} {name} tree after rehash",
        )
        final_root, final_identity = snapshot_plain_directory_chain(
            root, f"{description} {name} root after recheck"
        )
        if final_root != root or final_identity != identity:
            fail(f"{description} {name} root changed during recheck")


def run_production_shards(
    config: Configuration,
    variant: Variant,
    *,
    bryson_root: Path,
    numerical_environment: Path,
    environment: Mapping[str, str],
    log_root: Path,
) -> tuple[Path, Path, list[CommandResult]]:
    shards_parent = config.private_work_root / "shards"
    shards_parent.mkdir(exist_ok=True)
    shard_root = make_empty_directory(
        shards_parent / variant.name, f"{variant.name} shard root"
    )
    raw_root = make_empty_directory(
        config.private_raw_root / variant.name, f"{variant.name} private raw root"
    )
    completeness = (
        config.constant_completeness
        if variant.branch == "constant"
        else config.zero_completeness
    )
    specs: list[CommandSpec] = []
    for shard in range(SHARDS):
        label = f"production-shard-{shard}"
        output = make_empty_directory(
            shard_root / f"shard-{shard:02d}", f"{variant.name} shard {shard}"
        )
        shutil.copyfile(numerical_environment, output / "numerical_environment.txt")
        raw_output = raw_root / f"shard-{shard:02d}"
        seed = PRODUCTION_BASE_SEED + variant.seed_offset + shard * 1000
        specs.append(
            CommandSpec(
                f"shard-{variant.name}-{shard:02d}",
                runner_argv(
                    config,
                    bryson_root=bryson_root,
                    completeness=completeness,
                    branch=variant.branch,
                    output=output,
                    private_raw=raw_output,
                    seed=seed,
                    mcmc_seed_offset=MCMC_SEED_OFFSET_A,
                    trials=TRIALS_PER_SHARD,
                    maximum_steps=variant.maximum_steps,
                    measurement_mode=variant.measurement_mode,
                    label=label,
                    run_status="production_candidate",
                ),
                log_root / f"shard-{variant.name}-{shard:02d}.log",
            )
        )
    runner = lambda spec: run_command(  # noqa: E731
        spec, cwd=config.source_root, environment=environment
    )
    results = run_bounded(
        specs,
        maximum_parallel=config.maximum_parallel_shards,
        runner=runner,
    )
    for shard in range(SHARDS):
        label = f"production-shard-{shard}"
        output = shard_root / f"shard-{shard:02d}"
        write_complete_shard_manifest(output, variant.branch, label)
        ensure_exact_files(
            raw_root / f"shard-{shard:02d}",
            raw_output_names(variant.branch, label),
            f"{variant.name} raw-chain shard {shard}",
        )
    return shard_root, raw_root, results


def aggregate_and_verify(
    config: Configuration,
    variant: Variant,
    *,
    shard_root: Path,
    raw_root: Path,
    environment: Mapping[str, str],
    log_root: Path,
) -> tuple[ExactAggregateRoot, list[CommandResult]]:
    output = make_empty_directory(
        config.public_output_root / "aggregates" / variant.name,
        f"{variant.name} public aggregate",
    )
    aggregate_spec = CommandSpec(
        f"aggregate-{variant.name}",
        aggregate_argv(
            config,
            variant,
            shard_root=shard_root,
            raw_root=raw_root,
            output=output,
        ),
        log_root / f"aggregate-{variant.name}.log",
    )
    results = [
        run_command(aggregate_spec, cwd=config.source_root, environment=environment)
    ]
    ensure_exact_files(
        output, aggregate_output_names(variant.branch), f"{variant.name} aggregate"
    )
    accepted_aggregate = snapshot_exact_aggregate(output, variant.branch)
    verifier_spec = CommandSpec(
        f"verify-accepted-{variant.name}",
        accepted_verifier_argv(config, variant, output),
        log_root / f"verify-accepted-{variant.name}.log",
    )
    results.append(
        run_command(verifier_spec, cwd=config.source_root, environment=environment)
    )
    recheck_exact_aggregate(
        accepted_aggregate,
        f"{variant.name} aggregate after independent acceptance verification",
    )
    return accepted_aggregate, results


def reverify_accepted_aggregates(
    config: Configuration,
    aggregates: Mapping[str, ExactAggregateRoot],
    *,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    """Run the independent accepted verifier again immediately before final PASS."""

    results: list[CommandResult] = []
    for variant in VARIANTS:
        try:
            aggregate = aggregates[variant.name]
        except KeyError:
            fail(f"missing aggregate for final reverification: {variant.name}")
        recheck_exact_aggregate(
            aggregate, f"{variant.name} aggregate before final reverification"
        )
        spec = CommandSpec(
            f"final-verify-accepted-{variant.name}",
            accepted_verifier_argv(config, variant, aggregate.root),
            log_root / f"final-verify-accepted-{variant.name}.log",
        )
        results.append(
            run_command(spec, cwd=config.source_root, environment=environment)
        )
        recheck_exact_aggregate(
            aggregate, f"{variant.name} aggregate after final reverification"
        )
    return results


def propagate_variant(
    config: Configuration,
    variant: Variant,
    *,
    aggregate_root: ExactAggregateRoot,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    selectors = ("canonical",) if variant.measurement_mode == LEGACY_MODE else (
        "canonical",
        "legacy",
    )
    recheck_exact_aggregate(
        aggregate_root, f"{variant.name} aggregate before propagation"
    )
    samples = aggregate_root.root / (
        f"joint_posterior_{variant.branch}_for_galactic_propagation.csv.gz"
    )
    results: list[CommandResult] = []
    for selector in selectors:
        recheck_exact_aggregate(
            aggregate_root,
            f"{variant.name} aggregate before {selector} propagation",
        )
        hosts = config.canonical_hosts if selector == "canonical" else config.legacy_hosts
        output = make_empty_directory(
            config.public_output_root / "propagations" / variant.name / selector,
            f"{variant.name} {selector} propagation",
        )
        spec = CommandSpec(
            f"propagate-{variant.name}-{selector}",
            propagation_argv(
                config,
                branch=variant.branch,
                hosts=hosts,
                samples=samples,
                output=output,
                selector=selector,
            ),
            log_root / f"propagate-{variant.name}-{selector}.log",
        )
        results.append(
            run_command(spec, cwd=config.source_root, environment=environment)
        )
        recheck_exact_aggregate(
            aggregate_root,
            f"{variant.name} aggregate after {selector} propagation",
        )
        ensure_exact_files(
            output,
            propagation_output_names(variant.branch),
            f"{variant.name} {selector} propagation",
        )
        make_propagation_summary_release_safe(output, variant.branch)
    return results


def run_likelihood_grid_audits(
    config: Configuration,
    *,
    aggregate_roots: Mapping[str, ExactAggregateRoot],
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    """Run the locked 31/61/121 grid audit for both corrected branches."""

    results: list[CommandResult] = []
    for branch, variant_name, completeness in (
        ("constant", "corrected-constant", config.constant_completeness),
        ("zero", "corrected-zero", config.zero_completeness),
    ):
        try:
            aggregate_root = aggregate_roots[variant_name]
        except KeyError as exc:
            fail(f"missing accepted corrected aggregate for {branch} grid audit")
        output = make_empty_directory(
            config.public_output_root / "qualification" / "likelihood-grid" / branch,
            f"{branch} likelihood-grid output",
        )
        spec = CommandSpec(
            f"likelihood-grid-{branch}",
            (
                str(config.python_executable),
                script_path(
                    config,
                    "research/bryson-joint-posterior/likelihood_grid_convergence.py",
                ),
                "--branch",
                branch,
                "--rate-model-source",
                str(config.rate_model_source),
                "--completeness",
                str(completeness),
                "--posterior",
                str(aggregate_root.root / f"joint_posterior_{branch}_full.csv.gz"),
                "--aggregate-manifest",
                str(aggregate_root.root / f"SHA256SUMS_{branch}_aggregate.txt"),
                "--out",
                str(output),
            ),
            log_root / f"likelihood-grid-{branch}.log",
        )
        recheck_exact_aggregate(
            aggregate_root, f"{branch} aggregate before likelihood-grid audit"
        )
        results.append(
            run_command(spec, cwd=config.source_root, environment=environment)
        )
        recheck_exact_aggregate(
            aggregate_root, f"{branch} aggregate after likelihood-grid audit"
        )
        ensure_exact_files(
            output,
            likelihood_grid_output_names(),
            f"{branch} likelihood-grid output",
        )
        report = load_strict_json(
            output / "LIKELIHOOD_GRID_CONVERGENCE.json",
            f"{branch} likelihood-grid report",
        )
        if (
            not isinstance(report, dict)
            or report.get("status") != "PASS"
            or report.get("branch") != branch
            or not isinstance(report.get("results"), dict)
            or report["results"].get("accepted") is not True
        ):
            fail(f"{branch} 31/61/121 likelihood-grid audit did not pass")
    return results


def _copy_snapshots_to_exact_root(
    snapshots: Mapping[str, FileSnapshot],
    destination: Path,
    *,
    description: str,
) -> Path:
    """Copy a previously stable, exact derived artifact without path leakage."""

    output = make_empty_directory(destination, description)
    expected = set(snapshots)
    for name, snapshot in snapshots.items():
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None:
            fail(f"{description} contains an unsafe output name: {name!r}")
        if snapshot.data is None:
            fail(f"{description} snapshot was not collected: {name}")
        target = output / name
        target.write_bytes(snapshot.data)
        copied = snapshot_file(target, f"copied {description} file {name}")
        if copied.sha256 != snapshot.sha256 or copied.size_bytes != snapshot.size_bytes:
            fail(f"{description} copy changed bytes: {name}")
    ensure_exact_files(output, expected, description)
    return output


def stage_metallicity_audit(
    config: Configuration,
    *,
    environment: Mapping[str, str],
    log_root: Path,
) -> tuple[Path, list[CommandResult]]:
    """Verify and stage the five-file negative metallicity validation."""

    ensure_exact_files(
        config.metallicity_audit_root,
        METALLICITY_AUDIT_OUTPUT_NAMES,
        "input metallicity-TAMS audit",
    )
    snapshots = {
        name: snapshot_file(
            config.metallicity_audit_root / name,
            f"input metallicity-TAMS audit file {name}",
            collect=True,
            maximum_bytes=16_000_000,
        )
        for name in METALLICITY_AUDIT_OUTPUT_NAMES
    }
    spec = CommandSpec(
        "verify-metallicity-tams-audit",
        (
            str(config.python_executable),
            script_path(config, "scripts/verify_metallicity_tams_audit.py"),
            "--artifact-root",
            str(config.metallicity_audit_root),
            "--data-locks",
            script_path(config, "provenance/DATA_LOCKS.json"),
        ),
        log_root / "verify-metallicity-tams-audit.log",
    )
    result = run_command(spec, cwd=config.source_root, environment=environment)
    validate_sha256_manifest_root(
        config.metallicity_audit_root,
        manifest_name="SHA256SUMS_all.txt",
        target_names=tuple(
            name
            for name in METALLICITY_AUDIT_OUTPUT_NAMES
            if name != "SHA256SUMS_all.txt"
        ),
        description="input metallicity-TAMS audit",
    )
    for name, snapshot in snapshots.items():
        recheck_snapshot(snapshot, f"verified metallicity-TAMS audit file {name}")
    output = _copy_snapshots_to_exact_root(
        snapshots,
        config.public_output_root / "audits" / "metallicity-tams",
        description="public metallicity-TAMS audit",
    )
    return output, [result]


def run_dr25_support_audit(
    config: Configuration,
    *,
    aggregate_roots: Mapping[str, ExactAggregateRoot],
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    """Derive public support counts while retaining row-level evidence privately."""

    try:
        constant = aggregate_roots["corrected-constant"]
        zero = aggregate_roots["corrected-zero"]
    except KeyError:
        fail("DR25 support audit requires both corrected accepted aggregates")
    private_output = make_empty_directory(
        config.private_work_root / "audits" / "dr25-support",
        "private DR25 support audit output",
    )
    spec = CommandSpec(
        "audit-dr25-support",
        (
            str(config.python_executable),
            script_path(config, "research/v4-validation/dr25_support_audit.py"),
            "--pc-catalog",
            str(config.pc_catalog),
            "--stellar-catalog",
            str(config.stellar_catalog),
            "--constant-audit",
            str(constant.root / "perturbation_audit_constant_full.csv.gz"),
            "--zero-audit",
            str(zero.root / "perturbation_audit_zero_full.csv.gz"),
            "--out",
            str(private_output),
        ),
        log_root / "audit-dr25-support.log",
    )
    recheck_exact_aggregate(constant, "constant aggregate before DR25 support audit")
    recheck_exact_aggregate(zero, "zero aggregate before DR25 support audit")
    result = run_command(spec, cwd=config.source_root, environment=environment)
    recheck_exact_aggregate(constant, "constant aggregate after DR25 support audit")
    recheck_exact_aggregate(zero, "zero aggregate after DR25 support audit")
    ensure_exact_files(
        private_output,
        tuple(f"public/{name}" for name in DR25_SUPPORT_OUTPUT_NAMES)
        + tuple(f"private/{name}" for name in DR25_PRIVATE_OUTPUT_NAMES),
        "private DR25 support audit output",
    )
    public_source = private_output / "public"
    validate_sha256_manifest_root(
        public_source,
        manifest_name="SHA256SUMS_dr25_support_public.txt",
        target_names=("dr25_support_audit.json", "dr25_target_counts_by_trial.csv"),
        description="generated public DR25 support audit",
    )
    snapshots = {
        name: snapshot_file(
            public_source / name,
            f"public DR25 support source {name}",
            collect=True,
            maximum_bytes=16_000_000,
        )
        for name in DR25_SUPPORT_OUTPUT_NAMES
    }
    report = load_strict_json(
        public_source / "dr25_support_audit.json", "DR25 support audit report"
    )
    if (
        not isinstance(report, dict)
        or report.get("status") != "FAIL_LOCAL_EMPIRICAL_SUPPORT"
        or report.get("engineering_validation") != "PASS"
    ):
        fail("DR25 support audit did not produce the expected categorical result")
    _copy_snapshots_to_exact_root(
        snapshots,
        config.public_output_root / "audits" / "dr25-support",
        description="public DR25 support audit",
    )
    return [result]


def run_host_tams_audit(
    config: Configuration,
    *,
    aggregate_roots: Mapping[str, ExactAggregateRoot],
    metallicity_root: Path,
    host_binding: HostContractBinding,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    """Cross-check both host selectors against all four corrected propagations."""

    try:
        constant = aggregate_roots["corrected-constant"]
        zero = aggregate_roots["corrected-zero"]
    except KeyError:
        fail("host/TAMS audit requires both corrected accepted aggregates")
    output = make_empty_directory(
        config.public_output_root / "audits" / "host-tams",
        "public host-TAMS audit",
    )
    propagation = config.public_output_root / "propagations"
    spec = CommandSpec(
        "audit-host-tams",
        (
            str(config.python_executable),
            script_path(config, "research/v4-validation/host_tams_audit.py"),
            "--parent",
            str(config.parent_hosts),
            "--host-artifact-contract",
            str(config.host_contract),
            "--expected-host-artifact-contract-sha256",
            host_binding.accepted_contract.sha256,
            "--expected-host-artifact-contract-size-bytes",
            str(host_binding.accepted_contract.size_bytes),
            "--expected-host-qualification-report-sha256",
            host_binding.qualification_report.sha256,
            "--expected-host-qualification-report-size-bytes",
            str(host_binding.qualification_report.size_bytes),
            "--expected-computational-source-commit",
            str(host_binding.evidence["source_lock"]["public_source"]["commit_sha"]),
            "--expected-computational-source-tree",
            str(host_binding.evidence["source_lock"]["public_source"]["git_tree_sha"]),
            "--expected-computational-source-archive-sha256",
            str(host_binding.evidence["source_lock"]["public_source"]["source_archive_sha256"]),
            "--expected-computational-source-archive-size-bytes",
            str(host_binding.evidence["source_lock"]["public_source"]["source_archive_size_bytes"]),
            "--host-artifact-root",
            str(config.host_artifact_root),
            "--native-solar-tams-points",
            str(metallicity_root / "native_solar_tams_nodes.csv"),
            "--metallicity-audit-root",
            str(metallicity_root),
            "--kepler-stars",
            str(config.stellar_catalog),
            "--canonical-hosts",
            str(config.canonical_hosts),
            "--legacy-hosts",
            str(config.legacy_hosts),
            "--canonical-constant-artifact-root",
            str(propagation / "corrected-constant" / "canonical"),
            "--canonical-zero-artifact-root",
            str(propagation / "corrected-zero" / "canonical"),
            "--legacy-constant-artifact-root",
            str(propagation / "corrected-constant" / "legacy"),
            "--legacy-zero-artifact-root",
            str(propagation / "corrected-zero" / "legacy"),
            "--constant-posterior-samples",
            str(constant.root / "joint_posterior_constant_for_galactic_propagation.csv.gz"),
            "--zero-posterior-samples",
            str(zero.root / "joint_posterior_zero_for_galactic_propagation.csv.gz"),
            "--out",
            str(output),
        ),
        log_root / "audit-host-tams.log",
    )
    recheck_host_contract_binding(host_binding, "host/TAMS audit before consumption")
    recheck_exact_aggregate(constant, "constant aggregate before host/TAMS audit")
    recheck_exact_aggregate(zero, "zero aggregate before host/TAMS audit")
    result = run_command(spec, cwd=config.source_root, environment=environment)
    recheck_exact_aggregate(constant, "constant aggregate after host/TAMS audit")
    recheck_exact_aggregate(zero, "zero aggregate after host/TAMS audit")
    recheck_host_contract_binding(host_binding, "host/TAMS audit after consumption")
    validate_sha256_manifest_root(
        output,
        manifest_name="SHA256SUMS_host_tams_audit.txt",
        target_names=("host_tams_audit.json", "host_selector_sensitivity.csv"),
        description="public host-TAMS audit",
    )
    report = load_strict_json(output / "host_tams_audit.json", "host-TAMS audit")
    if (
        not isinstance(report, dict)
        or report.get("status")
        != "PASS_WITH_METALLICITY_CORRECTION_NOT_PUBLISHABLE"
    ):
        fail("host-TAMS audit did not pass its predeclared selector gate")
    return [result]


def run_sensitivity_artifacts(
    config: Configuration,
    *,
    numerical_runtime: Path,
    source_evidence: SourceArchiveEvidence,
    production_git: GitCheckoutEvidence,
    release_git: GitCheckoutEvidence,
    environment: Mapping[str, str],
    log_root: Path,
) -> list[CommandResult]:
    """Recompute the three scientific sensitivity JSONs and local provenance."""

    jobs_root = make_empty_directory(
        config.private_work_root / "audits" / "sensitivity-jobs",
        "private sensitivity jobs root",
    )
    jobs = (
        (
            "sensitivity-model-form",
            "research/jj-host-export/bryson_model_form_sensitivity.py",
            config.canonical_hosts,
            "bryson-model-form",
            (
                "bryson_model_form_sensitivity.json",
                "bryson_model_form_sensitivity.csv",
            ),
        ),
        (
            "sensitivity-hz",
            "research/jj-host-export/hz_boundary_sensitivity.py",
            config.canonical_hosts,
            "hz",
            (
                "hz_sensitivity_results.json",
                "hz_inner_boundary_perturbations.csv",
                "hz_planet_mass_sensitivity.csv",
            ),
        ),
        (
            "sensitivity-tams-branches",
            "research/jj-host-export/recalc_all_branches_tams.py",
            config.parent_hosts,
            "tams-branches",
            (
                "tams_all_branch_results.json",
                "tams_branches_lineweaver_7_9.csv",
                "tams_ghz_sensitivity_chz_constant.csv",
                "tams_branch_mask_matrix.csv",
            ),
        ),
    )
    specs: list[CommandSpec] = []
    output_roots: dict[str, tuple[Path, tuple[str, ...]]] = {}
    for command_id, producer, input_path, output_label, output_names in jobs:
        output = make_empty_directory(
            jobs_root / output_label, f"private {output_label} sensitivity output"
        )
        output_roots[command_id] = (output, output_names)
        specs.append(
            CommandSpec(
                command_id,
                (
                    str(config.python_executable),
                    script_path(config, producer),
                    "--input",
                    str(input_path),
                    "--out",
                    str(output),
                ),
                log_root / f"{command_id}.log",
            )
        )
    results = [
        run_command(spec, cwd=config.source_root, environment=environment)
        for spec in specs
    ]
    for command_id, (output, names) in output_roots.items():
        ensure_exact_files(output, names, f"{command_id} output")

    json_sources = {
        "bryson_model_form_sensitivity.json": output_roots[
            "sensitivity-model-form"
        ][0]
        / "bryson_model_form_sensitivity.json",
        "hz_sensitivity_results.json": output_roots["sensitivity-hz"][0]
        / "hz_sensitivity_results.json",
        "tams_all_branch_results.json": output_roots[
            "sensitivity-tams-branches"
        ][0]
        / "tams_all_branch_results.json",
    }
    snapshots: dict[str, FileSnapshot] = {}
    for name, path in json_sources.items():
        value = load_strict_json(path, f"generated sensitivity artifact {name}")
        if not isinstance(value, dict) or not value:
            fail(f"generated sensitivity artifact is empty: {name}")
        snapshots[name] = snapshot_file(
            path,
            f"generated sensitivity artifact {name}",
            collect=True,
            maximum_bytes=16_000_000,
        )

    runtime_snapshot = snapshot_file(
        numerical_runtime,
        "numerical runtime manifest for sensitivity provenance",
    )
    plan_snapshot = snapshot_file(
        config.command_plan,
        "signed local command plan for sensitivity provenance",
    )
    recheck_snapshot(source_evidence.snapshot, "source archive for sensitivity provenance")
    recheck_git_checkout_evidence(
        config,
        production_expected=production_git,
        release_expected=release_git,
        environment=environment,
    )
    provenance = build_sensitivity_run_provenance(
        source_archive_sha256=source_evidence.snapshot.sha256,
        numerical_runtime_sha256=runtime_snapshot.sha256,
        command_plan_sha256=plan_snapshot.sha256,
        production_git=production_git,
        release_git=release_git,
    )
    output = make_empty_directory(
        config.public_output_root / "audits" / "sensitivity-artifacts",
        "public sensitivity artifact root",
    )
    for name, snapshot in snapshots.items():
        if snapshot.data is None:
            fail(f"generated sensitivity snapshot was not collected: {name}")
        (output / name).write_bytes(snapshot.data)
    provenance_path = output / "RUN_PROVENANCE.json"
    provenance_path.write_bytes(canonical_json_bytes(provenance))
    manifest_targets = (
        "bryson_model_form_sensitivity.json",
        "hz_sensitivity_results.json",
        "tams_all_branch_results.json",
        "RUN_PROVENANCE.json",
    )
    manifest_path = output / "SHA256SUMS_sensitivity_artifacts.txt"
    manifest_path.write_text(
        "".join(f"{sha256(output / name)}  {name}\n" for name in manifest_targets),
        encoding="utf-8",
        newline="\n",
    )
    validate_sha256_manifest_root(
        output,
        manifest_name="SHA256SUMS_sensitivity_artifacts.txt",
        target_names=manifest_targets,
        description="public sensitivity artifact root",
    )
    return results


def build_sensitivity_run_provenance(
    *,
    source_archive_sha256: str,
    numerical_runtime_sha256: str,
    command_plan_sha256: str,
    production_git: GitCheckoutEvidence,
    release_git: GitCheckoutEvidence,
) -> dict[str, Any]:
    """Build schema-v4 local provenance from values fixed before final signing."""

    for name, digest in (
        ("source archive", source_archive_sha256),
        ("numerical runtime", numerical_runtime_sha256),
        ("command plan", command_plan_sha256),
    ):
        if not SHA256_RE.fullmatch(digest):
            fail(f"{name} SHA-256 is malformed")
    if (
        production_git.tree_sha != release_git.tree_sha
        or production_git.tree_sha256 != release_git.tree_sha256
    ):
        fail("cannot build sensitivity provenance from unequal Git trees")
    if production_git.source_archive_sha256 != source_archive_sha256:
        fail("sensitivity provenance source archive differs from production Git HEAD")
    return {
        "schema_version": 4,
        "execution_mode": "local_ubuntu_22_04_wsl2",
        "production": {
            "repository": EXPECTED_PRODUCTION_REPOSITORY,
            "repository_id": EXPECTED_PRODUCTION_REPOSITORY_ID,
            "private_commit": production_git.head_sha,
            "tree_sha": production_git.tree_sha,
            "tree_sha256": production_git.tree_sha256,
            "source_archive_sha256": source_archive_sha256,
            "os_runtime_manifest_sha256": numerical_runtime_sha256,
            "command_plan_sha256": command_plan_sha256,
            "artifact_name": EXPECTED_SENSITIVITY_ARTIFACT_NAME,
        },
        "release": {
            "repository": EXPECTED_RELEASE_REPOSITORY,
            "repository_id": EXPECTED_RELEASE_REPOSITORY_ID,
            "head_sha": release_git.head_sha,
            "tree_sha": release_git.tree_sha,
            "tree_sha256": release_git.tree_sha256,
        },
        "conclusion": "success",
        "maximum_mcmc_steps": None,
    }


def finalize_public_output(
    config: Configuration,
    *,
    source_evidence: SourceArchiveEvidence,
    protected_snapshots: Sequence[FileSnapshot],
    aggregate_roots: Mapping[str, ExactAggregateRoot],
    host_binding: HostContractBinding,
    command_results: Sequence[CommandResult],
    started: float,
    recovery_binding: RecoveryContractBinding | None = None,
    recovery_import: RecoveryImportEvidence | None = None,
) -> None:
    if (recovery_binding is None) != (recovery_import is None):
        fail("final recovery evidence is only partially populated")
    for name, aggregate in aggregate_roots.items():
        recheck_exact_aggregate(aggregate, f"{name} aggregate before finalization")
    recheck_host_contract_binding(host_binding, "host inputs before finalization")
    result_files = expected_public_files(final=False)
    records = public_output_inventory(
        config.public_output_root,
        expected=result_files,
        protected_snapshots=protected_snapshots,
    )
    stage_runtime: dict[str, float] = {}
    for result in command_results:
        stage = result.command_id.split("-", 1)[0]
        stage_runtime[stage] = stage_runtime.get(stage, 0.0) + result.runtime_seconds
    recovery_report: dict[str, Any]
    if recovery_binding is None or recovery_import is None:
        recovery_report = {
            "mcmc_reused": False,
            "aggregates_and_downstream_recomputed": True,
        }
    else:
        donor = recovery_binding.contract["donor"]
        recovery_report = {
            "mcmc_reused": True,
            "fresh_preflight_runtime_and_pilots_recomputed": True,
            "aggregates_and_downstream_recomputed": True,
            "donor_completion_attestation_present_in_qualified_evidence_set": False,
            "donor_run_id": donor["run_id"],
            "donor_source_commit": donor["source_commit"],
            "donor_source_tree": donor["source_tree"],
            "donor_source_archive_sha256": donor["source_archive"]["sha256"],
            "donor_source_archive_size_bytes": donor["source_archive"]["size_bytes"],
            "donor_source_file_set_sha256": donor["source_file_set_sha256"],
            "donor_source_file_count": donor["source_file_count"],
            "donor_attestation_contract_sha256": recovery_binding.donor_attestation_contract.sha256,
            "donor_attestation_contract_size_bytes": recovery_binding.donor_attestation_contract.size_bytes,
            "donor_command_plan_sha256": recovery_binding.donor_plan.sha256,
            "donor_numerical_runtime_sha256": recovery_binding.donor_runtime.sha256,
            "donor_start_challenge_sha256": donor["start_challenge"]["sha256"],
            "donor_start_signature_sha256": donor["start_signature"]["sha256"],
            "recovery_contract_sha256": recovery_binding.snapshot.sha256,
            "recovery_contract_size_bytes": recovery_binding.snapshot.size_bytes,
            "mcmc_policy_sha256": recovery_binding.mcmc_policy_sha256,
            "recovery_source_commit": recovery_binding.source_transition_value["to_source"]["commit"],
            "recovery_source_tree": recovery_binding.source_transition_value["to_source"]["tree"],
            "source_transition_report_id": recovery_binding.source_transition_value["report_id"],
            "source_transition_report_sha256": recovery_binding.source_transition.sha256,
            "qualification_report_id": recovery_binding.qualification_report_value["report_id"],
            "qualification_report_sha256": recovery_binding.qualification_report.sha256,
            "reused_realizations": len(VARIANTS) * SHARDS * TRIALS_PER_SHARD,
            "imported_work_file_count": recovery_import.work_file_count,
            "imported_work_size_bytes": recovery_import.work_size_bytes,
            "imported_work_tree_sha256": recovery_import.work_tree_sha256,
            "imported_raw_file_count": recovery_import.raw_file_count,
            "imported_raw_size_bytes": recovery_import.raw_size_bytes,
            "imported_raw_tree_sha256": recovery_import.raw_tree_sha256,
        }
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS",
        "release_candidate": "v4.0.4",
        "execution_environment": "Ubuntu 22.04 under WSL",
        "source_archive": {
            "sha256": source_evidence.snapshot.sha256,
            "size_bytes": source_evidence.snapshot.size_bytes,
            "regular_files_verified": len(source_evidence.files),
            "execution_tree_byte_identical": True,
        },
        "production_design": {
            "corrected_pilot_branches": ["constant", "zero"],
            "corrected_pilot_seed_families_per_branch": 2,
            "legacy_constant_paired_pilot": True,
            "production_variants": [variant.name for variant in VARIANTS],
            "shards_per_variant": SHARDS,
            "trials_per_shard": TRIALS_PER_SHARD,
            "outer_realizations_per_variant": SHARDS * TRIALS_PER_SHARD,
            "maximum_parallel_shard_processes": config.maximum_parallel_shards,
            "accepted_aggregate_profiles": {
                variant.name: variant.acceptance_profile for variant in VARIANTS
            },
            "mcmc_recovery": recovery_report,
        },
        "acceptance": {
            "corrected_seed_stability_passed": ["constant", "zero"],
            "legacy_paired_pilot_passed": True,
            "likelihood_grid_31_61_121_passed": ["constant", "zero"],
            "accepted_aggregates": [variant.name for variant in VARIANTS],
            "catalog_replays_per_aggregate": SHARDS * TRIALS_PER_SHARD,
            "private_raw_chain_audits_per_aggregate": SHARDS * TRIALS_PER_SHARD,
            "propagations": sorted(PUBLIC_PROPAGATIONS),
            "release_safe_audits": sorted(PUBLIC_AUDITS),
            "dr25_local_support_status": "FAIL_LOCAL_EMPIRICAL_SUPPORT",
            "metallicity_correction_applied": False,
        },
        "public_boundary": {
            "third_party_input_files_copied": False,
            "row_level_host_files_copied": False,
            "private_raw_chain_files_copied": False,
            "private_logs_copied": False,
        },
        "public_files": records,
        "command_count": len(command_results),
        "runtime_seconds_by_stage": {
            key: stage_runtime[key] for key in sorted(stage_runtime)
        },
        "total_runtime_seconds": float(time.monotonic() - started),
        "completed_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    report_path = config.public_output_root / REPORT_NAME
    report_path.write_bytes(canonical_json_bytes(report))
    manifest_targets = list(result_files) + [REPORT_NAME]
    manifest_path = config.public_output_root / PUBLIC_MANIFEST_NAME
    manifest_path.write_text(
        "".join(
            f"{sha256(config.public_output_root / PurePosixPath(relative))}  {relative}\n"
            for relative in sorted(manifest_targets)
        ),
        encoding="utf-8",
        newline="\n",
    )
    ensure_exact_files(
        config.public_output_root,
        expected_public_files(final=True),
        "final public production output",
    )
    for name, aggregate in aggregate_roots.items():
        recheck_exact_aggregate(aggregate, f"{name} aggregate after finalization")
    recheck_host_contract_binding(host_binding, "host inputs after finalization")
    if recovery_binding is not None and recovery_import is not None:
        recheck_recovery_import(
            recovery_import,
            "imported MCMC evidence after finalization",
            rehash_files=True,
        )
        evidence_root, evidence_identity = snapshot_plain_directory_chain(
            recovery_binding.evidence_root,
            "donor failed-run evidence root after finalization",
        )
        if (
            evidence_root != recovery_binding.evidence_root
            or evidence_identity != recovery_binding.evidence_root_identity
        ):
            fail("donor failed-run evidence root identity changed during recovery")
        ensure_exact_tree(
            evidence_root,
            expected_files=DONOR_EVIDENCE_FILES,
            description="donor failed-run evidence after finalization",
        )
        work_root, work_identity = snapshot_plain_directory_chain(
            recovery_binding.donor_work_root, "donor MCMC work root after finalization"
        )
        raw_root, raw_identity = snapshot_plain_directory_chain(
            recovery_binding.donor_raw_root, "donor MCMC raw root after finalization"
        )
        if (
            work_root != recovery_binding.donor_work_root
            or work_identity != recovery_binding.donor_work_root_identity
            or raw_root != recovery_binding.donor_raw_root
            or raw_identity != recovery_binding.donor_raw_root_identity
        ):
            fail("donor MCMC root identity changed during recovery")
        _validate_recovery_donor_trees(config, recovery_binding.contract)
        final_evidence_root, final_evidence_identity = snapshot_plain_directory_chain(
            recovery_binding.evidence_root,
            "donor failed-run evidence root after donor revalidation",
        )
        if (
            final_evidence_root != recovery_binding.evidence_root
            or final_evidence_identity != recovery_binding.evidence_root_identity
        ):
            fail("donor failed-run evidence root changed during final recovery checks")
        ensure_exact_tree(
            final_evidence_root,
            expected_files=DONOR_EVIDENCE_FILES,
            description="donor failed-run evidence after donor revalidation",
        )
    recheck_snapshot(source_evidence.snapshot, "source archive after finalization")
    for index, snapshot in enumerate(protected_snapshots):
        recheck_snapshot(snapshot, f"protected final input {index}")
    final_public_snapshots = {
        relative: snapshot_file(
            config.public_output_root / PurePosixPath(relative),
            f"final public output {relative}",
        )
        for relative in manifest_targets
    }
    final_manifest = snapshot_file(
        manifest_path,
        "final public production manifest",
        collect=True,
        maximum_bytes=1_000_000,
    )
    expected_manifest_bytes = "".join(
        f"{final_public_snapshots[relative].sha256}  {relative}\n"
        for relative in sorted(manifest_targets)
    ).encode("utf-8")
    if final_manifest.data != expected_manifest_bytes:
        fail("final public production manifest differs from the rehashed output")
    for relative, snapshot in final_public_snapshots.items():
        recheck_snapshot(snapshot, f"final public output {relative} after manifest check")
    recheck_snapshot(final_manifest, "final public production manifest")
    ensure_exact_files(
        config.public_output_root,
        expected_public_files(final=True),
        "final public production output after all recovery checks",
    )


def execute(config: Configuration) -> None:
    started = time.monotonic()
    environment = production_environment()
    validated_configuration = validate_configuration(config, environment=environment)
    if len(validated_configuration) == 5:  # compatibility for isolated stage-test mocks
        (
            source_evidence,
            protected_snapshots,
            production_git,
            release_git,
            host_binding,
        ) = validated_configuration
        recovery_binding = None
    else:
        (
            source_evidence,
            protected_snapshots,
            production_git,
            release_git,
            host_binding,
            recovery_binding,
        ) = validated_configuration
    logs = make_empty_directory(config.private_work_root / "logs", "private log root")
    command_results: list[CommandResult] = []
    command_results.extend(
        preflight_locked_inputs_and_hosts(
            config,
            host_binding=host_binding,
            environment=environment,
            log_root=logs,
        )
    )
    (
        numerical_environment,
        numerical_runtime,
        numerical_results,
    ) = create_numerical_environment(
        config, environment=environment, log_root=logs
    )
    command_results.extend(numerical_results)
    metallicity_root, metallicity_results = stage_metallicity_audit(
        config, environment=environment, log_root=logs
    )
    command_results.extend(metallicity_results)
    bryson_root = create_bryson_projection(config)
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        run_pilots(
            config,
            bryson_root=bryson_root,
            environment=environment,
            log_root=logs,
        )
    )
    verify_source_tree(config.source_root, source_evidence)
    aggregate_roots: dict[str, ExactAggregateRoot] = {}
    recovery_import: RecoveryImportEvidence | None = None
    recovery_roots: dict[str, tuple[Path, Path]] = {}
    if recovery_binding is not None:
        recovery_roots, recovery_import = import_recovery_shards(
            config,
            recovery_binding,
            numerical_environment=numerical_environment,
        )
        _validate_recovery_import_policy(
            recovery_import,
            recovery_binding.contract["policy"],
        )
        recheck_recovery_import(
            recovery_import,
            "imported MCMC evidence before aggregation",
            rehash_files=False,
        )
        verify_source_tree(config.source_root, source_evidence)
    for variant in VARIANTS:
        if recovery_binding is None:
            shard_root, raw_root, shard_results = run_production_shards(
                config,
                variant,
                bryson_root=bryson_root,
                numerical_environment=numerical_environment,
                environment=environment,
                log_root=logs,
            )
        else:
            shard_root, raw_root = recovery_roots[variant.name]
            shard_results = []
        command_results.extend(shard_results)
        verify_source_tree(config.source_root, source_evidence)
        aggregate_root, aggregate_results = aggregate_and_verify(
            config,
            variant,
            shard_root=shard_root,
            raw_root=raw_root,
            environment=environment,
            log_root=logs,
        )
        command_results.extend(aggregate_results)
        aggregate_roots[variant.name] = aggregate_root
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        run_likelihood_grid_audits(
            config,
            aggregate_roots=aggregate_roots,
            environment=environment,
            log_root=logs,
        )
    )
    verify_source_tree(config.source_root, source_evidence)
    for variant in VARIANTS:
        command_results.extend(
            propagate_variant(
                config,
                variant,
                aggregate_root=aggregate_roots[variant.name],
                environment=environment,
                log_root=logs,
            )
        )
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        run_host_tams_audit(
            config,
            aggregate_roots=aggregate_roots,
            metallicity_root=metallicity_root,
            host_binding=host_binding,
            environment=environment,
            log_root=logs,
        )
    )
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        run_dr25_support_audit(
            config,
            aggregate_roots=aggregate_roots,
            environment=environment,
            log_root=logs,
        )
    )
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        run_sensitivity_artifacts(
            config,
            numerical_runtime=numerical_runtime,
            source_evidence=source_evidence,
            production_git=production_git,
            release_git=release_git,
            environment=environment,
            log_root=logs,
        )
    )
    verify_source_tree(config.source_root, source_evidence)
    command_results.extend(
        reverify_accepted_aggregates(
            config,
            aggregate_roots,
            environment=environment,
            log_root=logs,
        )
    )
    for name, aggregate in aggregate_roots.items():
        recheck_exact_aggregate(aggregate, f"{name} aggregate before final PASS")
    recheck_host_contract_binding(host_binding, "host inputs before final PASS")
    recheck_snapshot(source_evidence.snapshot, "source archive")
    for index, snapshot in enumerate(protected_snapshots):
        recheck_snapshot(snapshot, f"protected pre-flight input {index}")
    recheck_git_checkout_evidence(
        config,
        production_expected=production_git,
        release_expected=release_git,
        environment=environment,
    )
    finalize_public_output(
        config,
        source_evidence=source_evidence,
        protected_snapshots=protected_snapshots,
        aggregate_roots=aggregate_roots,
        host_binding=host_binding,
        command_results=command_results,
        started=started,
        recovery_binding=recovery_binding,
        recovery_import=recovery_import,
    )
    print(
        "PASS local v4.0.4 production orchestration "
        f"({len(command_results)} shell-free commands; "
        f"{len(expected_public_files())} public files)",
        flush=True,
    )


def _load_attestation_validator() -> tuple[Any, FileSnapshot]:
    """Load the tracked sibling validator without relying on ``PYTHONPATH``."""

    validator_path = Path(__file__).with_name(ATTESTATION_VALIDATOR_NAME)
    module_name = "_exoearth_v404_local_run_attestation_validator"
    module, validator_snapshot = _load_module_from_snapshot(
        validator_path,
        module_name=module_name,
        description="tracked local-run attestation validator",
    )
    setattr(module, "_ORCHESTRATOR_SOURCE_SHA256", validator_snapshot.sha256)
    return module, validator_snapshot


def _canonical_absolute_path(path: Path, description: str) -> Path:
    candidate = require_absolute(path, description)
    lexical = Path(os.path.abspath(candidate))
    if os.path.normcase(str(candidate)) != os.path.normcase(str(lexical)):
        fail(f"{description} uses non-canonical lexical path rebasing")
    resolved = candidate.resolve(strict=False)
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        fail(f"{description} uses a symlinked ancestor")
    return resolved


def _lexical_absolute_path(path: Path, description: str) -> Path:
    candidate = require_absolute(path, description)
    lexical = Path(os.path.abspath(candidate))
    if os.path.normcase(str(candidate)) != os.path.normcase(str(lexical)):
        fail(f"{description} uses non-canonical lexical path rebasing")
    return lexical


def _require_absent_root(path: Path, description: str) -> Path:
    candidate = _canonical_absolute_path(path, description)
    if candidate.exists() or candidate.is_symlink():
        fail(f"{description} must not pre-exist while building the plan")
    return candidate


def _validate_plan_output_path(path: Path) -> Path:
    output = _canonical_absolute_path(path, "command-plan output")
    if output.exists() or output.is_symlink():
        fail("command-plan output already exists")
    try:
        parent_status = output.parent.lstat()
    except OSError as exc:
        fail(f"cannot inspect command-plan output parent: {exc}")
    if (
        stat.S_ISLNK(parent_status.st_mode)
        or _has_reparse_point(parent_status)
        or not stat.S_ISDIR(parent_status.st_mode)
    ):
        fail("command-plan output parent must be an existing real directory")
    return output


def local_production_run_argv(
    config: Configuration, *, execution_root: Path, plan_output: Path
) -> tuple[str, ...]:
    """Return the one exact tracked command stored in the signed plan."""

    python = _lexical_absolute_path(config.python_executable, "Python executable")
    def path(value: Path) -> str:
        return str(_canonical_absolute_path(Path(value), "run path argument"))

    base = (
        str(python),
        TRACKED_CONTROLLER_PATH,
        "recover-mcmc" if recovery_enabled(config) else "run",
        "--source-root",
        str(execution_root),
        "--source-archive",
        path(config.source_archive),
        "--expected-source-archive-sha256",
        config.expected_source_archive_sha256,
        "--python-executable",
        str(python),
        "--rate-model-source",
        path(config.rate_model_source),
        "--stellar-catalog",
        path(config.stellar_catalog),
        "--pc-catalog",
        path(config.pc_catalog),
        "--constant-completeness",
        path(config.constant_completeness),
        "--zero-completeness",
        path(config.zero_completeness),
        "--host-artifact-root",
        path(config.host_artifact_root),
        "--host-contract",
        path(config.host_contract),
        "--expected-host-contract-sha256",
        config.expected_host_contract_sha256,
        "--parent-hosts",
        path(config.parent_hosts),
        "--canonical-hosts",
        path(config.canonical_hosts),
        "--legacy-hosts",
        path(config.legacy_hosts),
        "--metallicity-audit-root",
        path(config.metallicity_audit_root),
        "--production-checkout",
        path(config.production_checkout),
        "--release-checkout",
        path(config.release_checkout),
        "--local-command-plan",
        str(plan_output),
        "--git-executable",
        path(config.git_executable),
        "--private-work-root",
        path(config.private_work_root),
        "--private-raw-root",
        path(config.private_raw_root),
        "--public-output-root",
        path(config.public_output_root),
        "--expected-bryson-source-sha256",
        config.expected_bryson_source_sha256,
        "--maximum-parallel-shards",
        str(config.maximum_parallel_shards),
    )
    if not recovery_enabled(config):
        return base
    if (
        config.recovery_contract is None
        or config.expected_recovery_contract_sha256 is None
        or config.expected_recovery_contract_size_bytes is None
        or config.donor_work_shard_root is None
        or config.donor_raw_root is None
        or config.donor_evidence_root is None
        or config.donor_attestation_contract is None
        or config.donor_command_plan is None
        or config.donor_numerical_runtime_manifest is None
        or config.donor_source_archive is None
        or config.source_transition_evidence is None
        or config.recovery_qualification_report is None
        or config.ssh_keygen_executable is None
    ):
        fail("internal recovery argv binding is incomplete")
    return base + (
        "--recovery-contract",
        path(config.recovery_contract),
        "--expected-recovery-contract-sha256",
        config.expected_recovery_contract_sha256,
        "--expected-recovery-contract-size-bytes",
        str(config.expected_recovery_contract_size_bytes),
        "--donor-work-shard-root",
        path(config.donor_work_shard_root),
        "--donor-raw-root",
        path(config.donor_raw_root),
        "--donor-evidence-root",
        path(config.donor_evidence_root),
        "--donor-attestation-contract",
        path(config.donor_attestation_contract),
        "--donor-command-plan",
        path(config.donor_command_plan),
        "--donor-numerical-runtime-manifest",
        path(config.donor_numerical_runtime_manifest),
        "--donor-source-archive",
        path(config.donor_source_archive),
        "--source-transition-evidence",
        path(config.source_transition_evidence),
        "--recovery-qualification-report",
        path(config.recovery_qualification_report),
        "--ssh-keygen-executable",
        path(config.ssh_keygen_executable),
    )


def build_plan_document(
    config: Configuration,
    *,
    execution_root: Path,
    runtime_manifest: Path,
    output: Path,
) -> tuple[dict[str, Any], bytes]:
    """Build and pre-validate one deterministic local attestation plan."""

    execution = _require_absent_root(execution_root, "execution root")
    source = _require_absent_root(config.source_root, "run source root")
    if source != execution:
        fail("run source root must be the exact future execution root")
    public = _require_absent_root(config.public_output_root, "public output root")
    private_work = _require_absent_root(config.private_work_root, "private work root")
    private_raw = _require_absent_root(config.private_raw_root, "private raw root")
    future_roots = {
        "execution root": execution,
        "public output root": public,
        "private work root": private_work,
        "private raw root": private_raw,
    }
    future_items = list(future_roots.items())
    for index, (left_name, left) in enumerate(future_items):
        for right_name, right in future_items[index + 1 :]:
            if paths_overlap(left, right):
                fail(f"future roots overlap: {left_name} and {right_name}")

    plan_output = _validate_plan_output_path(output)
    configured_plan = _canonical_absolute_path(
        config.command_plan, "run local-command-plan"
    )
    if configured_plan != plan_output:
        fail("run local-command-plan must equal the build-plan output path")
    runtime_path = _canonical_absolute_path(runtime_manifest, "runtime manifest")
    for description, protected in (
        ("command-plan output", plan_output),
        ("runtime manifest", runtime_path),
    ):
        for root_name, root in future_roots.items():
            if is_within(protected, root):
                fail(f"{description} must be outside the future {root_name}")
    for checkout_name, checkout_value in (
        ("private production checkout", config.production_checkout),
        ("public release checkout", config.release_checkout),
    ):
        checkout = Path(checkout_value).resolve(strict=False)
        for root_name, root in future_roots.items():
            if paths_overlap(checkout, root):
                fail(f"{root_name} overlaps the {checkout_name}")
        if is_within(plan_output, checkout):
            fail(f"command-plan output must be outside the {checkout_name}")

    pending_host_contract = execution / "provenance" / HOST_CONTRACT_NAME
    accepted_host_contract = Path(config.host_contract).resolve(strict=False)
    if accepted_host_contract == pending_host_contract:
        fail("accepted host contract must be external to computational source A")
    for checkout_name, checkout_value in (
        ("private production checkout", config.production_checkout),
        ("public release checkout", config.release_checkout),
    ):
        if is_within(accepted_host_contract, checkout_value):
            fail(f"accepted host contract B must be outside the {checkout_name}")
    for root_name, root in future_roots.items():
        if paths_overlap(accepted_host_contract, root):
            fail(f"accepted host contract overlaps the future {root_name}")
    if Path(config.parent_hosts).resolve(strict=False) != Path(
        config.host_artifact_root
    ).resolve(strict=False) / PARENT_HOST_NAME:
        fail("parent host path is not rooted in host-artifact-root")
    if Path(config.canonical_hosts).resolve(strict=False) != Path(
        config.host_artifact_root
    ).resolve(strict=False) / CANONICAL_HOST_NAME:
        fail("canonical host path is not rooted in host-artifact-root")
    if Path(config.legacy_hosts).resolve(strict=False) != Path(
        config.host_artifact_root
    ).resolve(strict=False) / LEGACY_HOST_NAME:
        fail("legacy host path is not rooted in host-artifact-root")
    if SHA256_RE.fullmatch(config.expected_source_archive_sha256) is None:
        fail("expected source archive SHA-256 is not lowercase 64-hex")
    if SHA256_RE.fullmatch(config.expected_host_contract_sha256) is None:
        fail("expected host-contract SHA-256 is not lowercase 64-hex")
    if config.expected_bryson_source_sha256 != EXPECTED_BRYSON_SOURCE_SHA256:
        fail("Bryson source SHA-256 differs from the v4.0.4 lock")
    if not 1 <= config.maximum_parallel_shards <= MAXIMUM_PARALLEL_SHARDS:
        fail("maximum parallel shard processes must be between 1 and 4")
    if recovery_enabled(config):
        if (
            config.expected_recovery_contract_sha256 is None
            or SHA256_RE.fullmatch(config.expected_recovery_contract_sha256) is None
            or type(config.expected_recovery_contract_size_bytes) is not int
            or config.expected_recovery_contract_size_bytes <= 0
        ):
            fail("expected recovery-contract hash/size is malformed")
        recovery_protected = {
            "recovery contract": config.recovery_contract,
            "donor work-shard root": config.donor_work_shard_root,
            "donor raw-chain root": config.donor_raw_root,
            "donor failed-run evidence root": config.donor_evidence_root,
            "donor attestation contract": config.donor_attestation_contract,
            "donor command plan": config.donor_command_plan,
            "donor numerical runtime": config.donor_numerical_runtime_manifest,
            "donor source archive": config.donor_source_archive,
            "source-transition report": config.source_transition_evidence,
            "recovery qualification report": config.recovery_qualification_report,
            "ssh-keygen executable": config.ssh_keygen_executable,
        }
        canonical_recovery: dict[str, Path] = {}
        for description, raw_path in recovery_protected.items():
            if raw_path is None:
                fail(f"{description} is missing")
            path_value = _canonical_absolute_path(raw_path, description)
            canonical_recovery[description] = path_value
            for root_name, root in future_roots.items():
                if paths_overlap(path_value, root):
                    fail(f"{description} overlaps the future {root_name}")
            for checkout_name, checkout_value in (
                ("private production checkout", config.production_checkout),
                ("public release checkout", config.release_checkout),
            ):
                if paths_overlap(path_value, checkout_value):
                    fail(f"{description} overlaps the {checkout_name}")
        donor_root_names = (
            "donor work-shard root",
            "donor raw-chain root",
            "donor failed-run evidence root",
        )
        for index, left_name in enumerate(donor_root_names):
            for right_name in donor_root_names[index + 1 :]:
                if paths_overlap(
                    canonical_recovery[left_name], canonical_recovery[right_name]
                ):
                    fail(f"{left_name} overlaps {right_name}")

    validator, validator_snapshot = _load_attestation_validator()
    try:
        runtime_value, runtime_snapshot = validator.load_json_snapshot(
            runtime_path, "numerical runtime manifest"
        )
        runtime = validator.validate_numerical_runtime(runtime_value)
        if validator.REQUIRED_RUNTIME_ENV != NUMERICAL_ENVIRONMENT:
            fail("orchestrator and attestation numerical environments differ")
        python = _lexical_absolute_path(config.python_executable, "Python executable")
        if str(python) != runtime["python_executable"]:
            fail("runtime manifest Python path differs from --python-executable")
        executable_snapshot, executable_chain_sha256 = validator.executable_chain(
            python
        )
        environment = dict(NUMERICAL_ENVIRONMENT)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "EXOEARTH_SOURCE_ROOT": str(execution),
                "EXOEARTH_OUTPUT_ROOT": str(public),
                "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST": str(runtime_path),
            }
        )
        plan = {
            "schema_version": 1,
            "plan_label": RECOVERY_PLAN_LABEL if recovery_enabled(config) else PLAN_LABEL,
            "commands": [
                {
                    "command_id": (
                        RECOVERY_PLAN_COMMAND_ID
                        if recovery_enabled(config)
                        else PLAN_COMMAND_ID
                    ),
                    "argv": list(
                        local_production_run_argv(
                            config,
                            execution_root=execution,
                            plan_output=plan_output,
                        )
                    ),
                    "cwd": ".",
                    "env": environment,
                    "executable_sha256": executable_snapshot.sha256,
                    "executable_size_bytes": executable_snapshot.size_bytes,
                    "executable_chain_sha256": executable_chain_sha256,
                }
            ],
            "expected_output_files": list(expected_public_files(final=True)),
        }
        validated = validator.validate_plan(plan, runtime)
        validator.validate_plan_bindings(
            validated,
            runtime,
            execution,
            public,
            runtime_path,
            plan_output,
            config.git_executable,
            config.production_checkout,
            config.release_checkout,
            require_extracted_programs=False,
            trusted_ssh_keygen_executable=config.ssh_keygen_executable,
        )
        encoded = validator.canonical_json_bytes(validated)
        validator.recheck_snapshot(runtime_snapshot, "numerical runtime manifest")
    except validator.AttestationError as exc:
        fail(f"attestation plan validation failed: {exc}")
    recheck_snapshot(validator_snapshot, "tracked local-run attestation validator")
    return validated, encoded


def _write_exclusive_plan(path: Path, data: bytes) -> None:
    validator, validator_snapshot = _load_attestation_validator()
    try:
        validator.atomic_write_new(
            path, data, "local v4.0.4 command-plan output"
        )
    except validator.AttestationError as exc:
        fail(f"cannot create command-plan output exclusively: {exc}")
    recheck_snapshot(validator_snapshot, "tracked local-run attestation validator")


def write_local_command_plan(
    config: Configuration,
    *,
    execution_root: Path,
    runtime_manifest: Path,
    output: Path,
) -> FileSnapshot:
    plan, encoded = build_plan_document(
        config,
        execution_root=execution_root,
        runtime_manifest=runtime_manifest,
        output=output,
    )
    plan_output = Path(output).resolve(strict=False)
    _write_exclusive_plan(plan_output, encoded)
    snapshot = snapshot_file(
        plan_output, "generated local command plan", collect=True, maximum_bytes=4_000_000
    )
    if snapshot.data != encoded:
        fail("generated command-plan bytes changed immediately after creation")

    validator, validator_snapshot = _load_attestation_validator()
    runtime_path = Path(runtime_manifest).resolve(strict=True)
    execution = Path(execution_root).resolve(strict=False)
    public = Path(config.public_output_root).resolve(strict=False)
    try:
        runtime_value, runtime_snapshot = validator.load_json_snapshot(
            runtime_path, "numerical runtime manifest"
        )
        runtime = validator.validate_numerical_runtime(runtime_value)
        roundtrip, plan_snapshot = validator.load_json_snapshot(
            plan_output, "generated local command plan"
        )
        validated = validator.validate_plan(roundtrip, runtime)
        if validated != plan or validator.canonical_json_bytes(validated) != encoded:
            fail("generated command plan failed its canonical byte roundtrip")
        if validated["expected_output_files"] != list(
            expected_public_files(final=True)
        ):
            fail("generated command plan does not contain the exact final output set")
        validator.validate_plan_bindings(
            validated,
            runtime,
            execution,
            public,
            runtime_path,
            plan_output,
            config.git_executable,
            config.production_checkout,
            config.release_checkout,
            require_extracted_programs=False,
            trusted_ssh_keygen_executable=config.ssh_keygen_executable,
        )
        validator.recheck_snapshot(runtime_snapshot, "numerical runtime manifest")
        validator.recheck_snapshot(plan_snapshot, "generated local command plan")
    except validator.AttestationError as exc:
        fail(f"generated command-plan roundtrip failed: {exc}")
    recheck_snapshot(validator_snapshot, "tracked local-run attestation validator")
    recheck_snapshot(snapshot, "generated local command plan")
    return snapshot


def _add_run_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--source-root", required=True, type=Path)
    command.add_argument("--source-archive", required=True, type=Path)
    command.add_argument("--expected-source-archive-sha256", required=True)
    command.add_argument("--python-executable", required=True, type=Path)
    command.add_argument("--rate-model-source", required=True, type=Path)
    command.add_argument("--stellar-catalog", required=True, type=Path)
    command.add_argument("--pc-catalog", required=True, type=Path)
    command.add_argument("--constant-completeness", required=True, type=Path)
    command.add_argument("--zero-completeness", required=True, type=Path)
    command.add_argument("--host-artifact-root", required=True, type=Path)
    command.add_argument("--host-contract", required=True, type=Path)
    command.add_argument("--expected-host-contract-sha256", required=True)
    command.add_argument("--parent-hosts", required=True, type=Path)
    command.add_argument("--canonical-hosts", required=True, type=Path)
    command.add_argument("--legacy-hosts", required=True, type=Path)
    command.add_argument("--metallicity-audit-root", required=True, type=Path)
    command.add_argument("--production-checkout", required=True, type=Path)
    command.add_argument("--release-checkout", required=True, type=Path)
    command.add_argument("--local-command-plan", required=True, type=Path)
    command.add_argument("--git-executable", required=True, type=Path)
    command.add_argument("--private-work-root", required=True, type=Path)
    command.add_argument("--private-raw-root", required=True, type=Path)
    command.add_argument("--public-output-root", required=True, type=Path)
    command.add_argument("--expected-bryson-source-sha256", required=True)
    command.add_argument(
        "--maximum-parallel-shards",
        type=int,
        default=MAXIMUM_PARALLEL_SHARDS,
        choices=range(1, MAXIMUM_PARALLEL_SHARDS + 1),
    )


def _add_recovery_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--recovery-contract", required=True, type=Path)
    command.add_argument("--expected-recovery-contract-sha256", required=True)
    command.add_argument(
        "--expected-recovery-contract-size-bytes", required=True, type=int
    )
    command.add_argument("--donor-work-shard-root", required=True, type=Path)
    command.add_argument("--donor-raw-root", required=True, type=Path)
    command.add_argument("--donor-evidence-root", required=True, type=Path)
    command.add_argument("--donor-attestation-contract", required=True, type=Path)
    command.add_argument("--donor-command-plan", required=True, type=Path)
    command.add_argument(
        "--donor-numerical-runtime-manifest", required=True, type=Path
    )
    command.add_argument("--donor-source-archive", required=True, type=Path)
    command.add_argument("--source-transition-evidence", required=True, type=Path)
    command.add_argument(
        "--recovery-qualification-report", required=True, type=Path
    )
    command.add_argument("--ssh-keygen-executable", required=True, type=Path)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="mode", required=True)
    subparsers.add_parser(
        "expected-output-set",
        help="print the exact relative public output file set without executing",
    )
    build = subparsers.add_parser(
        "build-plan",
        help="exclusively create and roundtrip-validate the exact attestation plan",
    )
    _add_run_arguments(build)
    build.add_argument("--execution-root", required=True, type=Path)
    build.add_argument("--runtime-manifest", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    recovery_build = subparsers.add_parser(
        "build-recovery-plan",
        help="exclusively create the exact signed-start MCMC recovery plan",
    )
    _add_run_arguments(recovery_build)
    _add_recovery_arguments(recovery_build)
    recovery_build.add_argument("--execution-root", required=True, type=Path)
    recovery_build.add_argument("--runtime-manifest", required=True, type=Path)
    recovery_build.add_argument("--output", required=True, type=Path)
    run = subparsers.add_parser("run", help="execute the complete local production plan")
    _add_run_arguments(run)
    recovery_run = subparsers.add_parser(
        "recover-mcmc",
        help="reuse only the qualified MCMC shards and recompute every downstream stage",
    )
    _add_run_arguments(recovery_run)
    _add_recovery_arguments(recovery_run)
    return root


def configuration_from_args(args: argparse.Namespace) -> Configuration:
    return Configuration(
        source_root=args.source_root,
        source_archive=args.source_archive,
        expected_source_archive_sha256=args.expected_source_archive_sha256.strip().lower(),
        python_executable=args.python_executable,
        rate_model_source=args.rate_model_source,
        stellar_catalog=args.stellar_catalog,
        pc_catalog=args.pc_catalog,
        constant_completeness=args.constant_completeness,
        zero_completeness=args.zero_completeness,
        host_artifact_root=args.host_artifact_root,
        host_contract=args.host_contract,
        expected_host_contract_sha256=args.expected_host_contract_sha256.strip().lower(),
        parent_hosts=args.parent_hosts,
        canonical_hosts=args.canonical_hosts,
        legacy_hosts=args.legacy_hosts,
        metallicity_audit_root=args.metallicity_audit_root,
        production_checkout=args.production_checkout,
        release_checkout=args.release_checkout,
        command_plan=args.local_command_plan,
        git_executable=args.git_executable,
        private_work_root=args.private_work_root,
        private_raw_root=args.private_raw_root,
        public_output_root=args.public_output_root,
        expected_bryson_source_sha256=args.expected_bryson_source_sha256.strip().lower(),
        maximum_parallel_shards=args.maximum_parallel_shards,
        recovery_contract=getattr(args, "recovery_contract", None),
        expected_recovery_contract_sha256=(
            getattr(args, "expected_recovery_contract_sha256", None).strip().lower()
            if getattr(args, "expected_recovery_contract_sha256", None) is not None
            else None
        ),
        expected_recovery_contract_size_bytes=getattr(
            args, "expected_recovery_contract_size_bytes", None
        ),
        donor_work_shard_root=getattr(args, "donor_work_shard_root", None),
        donor_raw_root=getattr(args, "donor_raw_root", None),
        donor_evidence_root=getattr(args, "donor_evidence_root", None),
        donor_attestation_contract=getattr(
            args, "donor_attestation_contract", None
        ),
        donor_command_plan=getattr(args, "donor_command_plan", None),
        donor_numerical_runtime_manifest=getattr(
            args, "donor_numerical_runtime_manifest", None
        ),
        donor_source_archive=getattr(args, "donor_source_archive", None),
        source_transition_evidence=getattr(
            args, "source_transition_evidence", None
        ),
        recovery_qualification_report=getattr(
            args, "recovery_qualification_report", None
        ),
        ssh_keygen_executable=getattr(args, "ssh_keygen_executable", None),
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.mode == "expected-output-set":
        print(json.dumps(list(expected_public_files()), indent=2))
        return
    try:
        if args.mode in {"build-plan", "build-recovery-plan"}:
            snapshot = write_local_command_plan(
                configuration_from_args(args),
                execution_root=args.execution_root,
                runtime_manifest=args.runtime_manifest,
                output=args.output,
            )
            print(
                "PASS local v4.0.4 command plan "
                f"({snapshot.sha256}; {len(expected_public_files(final=True))} outputs)"
            )
            return
        execute(configuration_from_args(args))
    except OrchestrationError as exc:
        raise SystemExit(f"LOCAL PRODUCTION FAIL: {exc}") from exc


if __name__ == "__main__":
    main()
