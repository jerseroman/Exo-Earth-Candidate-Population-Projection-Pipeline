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
TRACKED_CONTROLLER_PATH = "scripts/run_v404_local_production.py"
ATTESTATION_VALIDATOR_NAME = "verify_local_run_attestation.py"
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


def load_strict_json(path: Path, description: str) -> Any:
    snapshot = snapshot_file(path, description, collect=True, maximum_bytes=16_000_000)
    if snapshot.data is None:
        fail(f"JSON snapshot was not collected: {description}")
    try:
        text = snapshot.data.decode("utf-8", errors="strict")
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
    sys.modules[module_name] = module
    try:
        code = compile(snapshot.data, str(snapshot.path), "exec")
        with _isolated_snapshot_import_path(snapshot.path):
            exec(code, module.__dict__)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        fail(f"cannot load {description} from captured bytes: {exc}")
    recheck_snapshot(snapshot, description)
    if (
        module.__dict__.get("__source_only_sha256__") != snapshot.sha256
        or module.__dict__.get("__cached__") is not None
    ):
        fail(f"{description} changed its source-only loader evidence")
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
]:
    validate_ubuntu_2204_wsl()
    if not 1 <= config.maximum_parallel_shards <= MAXIMUM_PARALLEL_SHARDS:
        fail("maximum parallel shard processes must be between 1 and 4")
    if config.expected_bryson_source_sha256 != EXPECTED_BRYSON_SOURCE_SHA256:
        fail("Bryson source SHA-256 differs from the v4.0.4 lock")
    if SHA256_RE.fullmatch(config.expected_host_contract_sha256) is None:
        fail("expected external host-contract SHA-256 is malformed")
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
    return evidence, protected_snapshots, production_git, release_git, host_binding


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
) -> None:
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


def execute(config: Configuration) -> None:
    started = time.monotonic()
    environment = production_environment()
    (
        source_evidence,
        protected_snapshots,
        production_git,
        release_git,
        host_binding,
    ) = validate_configuration(config, environment=environment)
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
    for variant in VARIANTS:
        shard_root, raw_root, shard_results = run_production_shards(
            config,
            variant,
            bryson_root=bryson_root,
            numerical_environment=numerical_environment,
            environment=environment,
            log_root=logs,
        )
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

    return (
        str(python),
        TRACKED_CONTROLLER_PATH,
        "run",
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
            "plan_label": PLAN_LABEL,
            "commands": [
                {
                    "command_id": PLAN_COMMAND_ID,
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
    run = subparsers.add_parser("run", help="execute the complete local production plan")
    _add_run_arguments(run)
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
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.mode == "expected-output-set":
        print(json.dumps(list(expected_public_files()), indent=2))
        return
    try:
        if args.mode == "build-plan":
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
