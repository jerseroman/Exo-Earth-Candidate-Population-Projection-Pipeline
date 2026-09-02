#!/usr/bin/env python3
"""Execute and verify a two-signer local production run.

The controller deliberately separates three things that are often conflated:

* a signed, source- and plan-bound challenge created before execution;
* a second-signer completion attestation over exit codes and exact output bytes;
* a small public qualification report that contains hashes, status, counts, and
  timings, but no command arguments, filesystem paths, logs, or result bytes.

An unaccepted candidate may be executed only in explicit qualification mode.
The production gate remains closed until the resulting public report is
reviewed and hash-locked in the contract.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _bootstrap_os
    import sys as _bootstrap_sys

    if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.dont_write_bytecode:
        _optimisation = (
            "-" + "O" * _bootstrap_sys.flags.optimize
            if _bootstrap_sys.flags.optimize
            else None
        )
        _argv = [_bootstrap_sys.executable]
        if _optimisation is not None:
            _argv.append(_optimisation)
        _script_path = _bootstrap_os.path.abspath(__file__)
        _argv.extend(
            (
                "-I",
                "-B",
                _script_path,
                *_bootstrap_sys.argv[1:],
            )
        )
        if _bootstrap_os.name == "nt":
            def _quote_windows_argument(value: str) -> str:
                if value and not any(character in " \t\"" for character in value):
                    return value
                rendered = '"'
                backslashes = 0
                for character in value:
                    if character == "\\":
                        backslashes += 1
                    elif character == '"':
                        rendered += "\\" * (2 * backslashes + 1) + '"'
                        backslashes = 0
                    else:
                        rendered += "\\" * backslashes + character
                        backslashes = 0
                return rendered + "\\" * (2 * backslashes) + '"'

            _argv = [_quote_windows_argument(value) for value in _argv]
        _bootstrap_os.execv(_bootstrap_sys.executable, _argv)

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
CONTRACT_ID = "local-production-run-v4.0.4"
START_NAMESPACE = "exoearth-local-production-start-v4.0.4"
COMPLETION_NAMESPACE = "exoearth-local-production-completion-v4.0.4"
PUBLIC_REPOSITORY = "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
PRIVATE_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production"
)
PINNED_SIGNERS = (
    {
        "signer_id": "v404-local-attestor-a",
        "public_key": (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF6o39g15REJBdvRMh21U9DUs+spMaeeIVw7seFaqWwi "
            "v4.0.4-local-attestor-a"
        ),
    },
    {
        "signer_id": "v404-local-attestor-b",
        "public_key": (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA3LslBc9zXOtiUoZedp9hzUO67FiV3ny8VJBOHXHouP "
            "v4.0.4-local-attestor-b"
        ),
    },
)

START_NAME = "LOCAL_RUN_START_CHALLENGE.json"
START_SIGNATURE_NAME = f"{START_NAME}.sig"
OUTPUT_MANIFEST_NAME = "LOCAL_RUN_OUTPUT_SHA256.json"
COMPLETION_NAME = "LOCAL_RUN_COMPLETION_ATTESTATION.json"
COMPLETION_SIGNATURE_NAME = f"{COMPLETION_NAME}.sig"
REPORT_NAME = "LOCAL_RUN_PUBLIC_REPORT.json"

MAX_JSON_BYTES = 4_000_000
MAX_SIGNATURE_BYTES = 100_000
MAX_LOG_BYTES_IN_REPORT = 2**63 - 1
MAX_ARCHIVE_BYTES = 256_000_000
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
HEX40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_RUNTIME_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
REQUIRED_ENABLED_CPU = ("AVX2", "FMA3")
REQUIRED_DISABLED_CPU = (
    "AVX512F",
    "AVX512CD",
    "AVX512_KNL",
    "AVX512_KNM",
    "AVX512_SKX",
    "AVX512_CLX",
    "AVX512_CNL",
    "AVX512_ICL",
)

V404_PLAN_LABEL = "v4.0.4-local-production"
V404_COMMAND_ID = "run-v404-local-production"
V404_RECOVERY_PLAN_LABEL = "v4.0.4-local-production-recover-mcmc"
V404_RECOVERY_COMMAND_ID = "run-v404-local-production-recover-mcmc"
V404_PROGRAM = "scripts/run_v404_local_production.py"
V404_BRYSON_SOURCE_SHA256 = (
    "0bb479b0c94c4f793b95e4fa1e853973805c54d3de7e2a2acc2e51c05b70a586"
)
V404_RUN_FLAGS = (
    "--source-root",
    "--source-archive",
    "--expected-source-archive-sha256",
    "--python-executable",
    "--rate-model-source",
    "--stellar-catalog",
    "--pc-catalog",
    "--constant-completeness",
    "--zero-completeness",
    "--host-artifact-root",
    "--host-contract",
    "--expected-host-contract-sha256",
    "--parent-hosts",
    "--canonical-hosts",
    "--legacy-hosts",
    "--metallicity-audit-root",
    "--production-checkout",
    "--release-checkout",
    "--local-command-plan",
    "--git-executable",
    "--private-work-root",
    "--private-raw-root",
    "--public-output-root",
    "--expected-bryson-source-sha256",
    "--maximum-parallel-shards",
)
V404_RECOVERY_FLAGS = (
    "--recovery-contract",
    "--expected-recovery-contract-sha256",
    "--expected-recovery-contract-size-bytes",
    "--donor-work-shard-root",
    "--donor-raw-root",
    "--donor-evidence-root",
    "--donor-attestation-contract",
    "--donor-command-plan",
    "--donor-numerical-runtime-manifest",
    "--donor-source-archive",
    "--source-transition-evidence",
    "--recovery-qualification-report",
    "--ssh-keygen-executable",
)
V404_RECOVERY_RUN_FLAGS = V404_RUN_FLAGS + V404_RECOVERY_FLAGS
V404_PATH_FLAGS = frozenset(
    flag
    for flag in V404_RUN_FLAGS
    if flag
    not in {
        "--expected-source-archive-sha256",
        "--expected-host-contract-sha256",
        "--expected-bryson-source-sha256",
        "--maximum-parallel-shards",
    }
)
V404_RECOVERY_PATH_FLAGS = frozenset(
    {
        *V404_PATH_FLAGS,
        *(
            flag
            for flag in V404_RECOVERY_FLAGS
            if flag
            not in {
                "--expected-recovery-contract-sha256",
                "--expected-recovery-contract-size-bytes",
            }
        ),
    }
)
V404_ENV_KEYS = frozenset(
    {
        *REQUIRED_RUNTIME_ENV,
        "PYTHONDONTWRITEBYTECODE",
        "EXOEARTH_SOURCE_ROOT",
        "EXOEARTH_OUTPUT_ROOT",
        "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST",
    }
)


def _v404_expected_output_files() -> tuple[str, ...]:
    aggregate_names = lambda branch: (
        f"joint_posterior_{branch}_full.csv.gz",
        f"joint_posterior_{branch}_for_galactic_propagation.csv.gz",
        f"joint_posterior_{branch}_correlation.csv",
        f"trial_diagnostics_{branch}_full.jsonl",
        f"joint_posterior_{branch}_aggregate_summary.json",
        f"perturbation_audit_{branch}_full.csv.gz",
        f"raw_unthinned_chain_audit_{branch}.json",
        f"SHA256SUMS_{branch}_aggregate.txt",
    )
    propagation_names = lambda branch: (
        "collapsed_host_temperature_measure.csv",
        f"galactic_posterior_draws_{branch}.csv.gz",
        f"galactic_posterior_summary_{branch}.json",
        f"SHA256SUMS_galactic_{branch}.txt",
    )

    def seed_names(branch: str) -> tuple[str, ...]:
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

    paths: list[str] = []
    for directory, branch in (
        ("aggregates/corrected-constant", "constant"),
        ("aggregates/corrected-zero", "zero"),
        ("aggregates/legacy-measurement-constant", "constant"),
    ):
        paths.extend(f"{directory}/{name}" for name in aggregate_names(branch))
    for directory, branch in (
        ("propagations/corrected-constant/canonical", "constant"),
        ("propagations/corrected-constant/legacy", "constant"),
        ("propagations/corrected-zero/canonical", "zero"),
        ("propagations/corrected-zero/legacy", "zero"),
        ("propagations/legacy-measurement-constant/canonical", "constant"),
    ):
        paths.extend(f"{directory}/{name}" for name in propagation_names(branch))
    for directory, branch in (
        ("qualification/seed-stability/constant", "constant"),
        ("qualification/seed-stability/zero", "zero"),
    ):
        paths.extend(f"{directory}/{name}" for name in seed_names(branch))
    grid_names = (
        "selected_joint_parameter_points.csv",
        "LIKELIHOOD_GRID_CONVERGENCE.json",
        "SHA256SUMS_likelihood_grid_convergence.txt",
    )
    for directory in (
        "qualification/likelihood-grid/constant",
        "qualification/likelihood-grid/zero",
    ):
        paths.extend(f"{directory}/{name}" for name in grid_names)
    for directory, names in (
        (
            "audits/metallicity-tams",
            (
                "metallicity_tams_differential_sensitivity.json",
                "native_solar_tams_nodes.csv",
                "NUMERICAL_RUNTIME_POLICY.json",
                "PROVENANCE_METALLICITY_DIFFERENTIAL.md",
                "SHA256SUMS_all.txt",
            ),
        ),
        (
            "audits/host-tams",
            (
                "host_tams_audit.json",
                "host_selector_sensitivity.csv",
                "SHA256SUMS_host_tams_audit.txt",
            ),
        ),
        (
            "audits/dr25-support",
            (
                "dr25_support_audit.json",
                "dr25_target_counts_by_trial.csv",
                "SHA256SUMS_dr25_support_public.txt",
            ),
        ),
        (
            "audits/sensitivity-artifacts",
            (
                "bryson_model_form_sensitivity.json",
                "hz_sensitivity_results.json",
                "tams_all_branch_results.json",
                "RUN_PROVENANCE.json",
                "SHA256SUMS_sensitivity_artifacts.txt",
            ),
        ),
    ):
        paths.extend(f"{directory}/{name}" for name in names)
    paths.extend(("V404_LOCAL_PRODUCTION_REPORT.json", "SHA256SUMS_v404_local_production.txt"))
    return tuple(sorted(paths))


V404_EXPECTED_OUTPUT_FILES = _v404_expected_output_files()
if len(V404_EXPECTED_OUTPUT_FILES) != 88 or len(set(V404_EXPECTED_OUTPUT_FILES)) != 88:
    raise RuntimeError("internal v4.0.4 output contract is not exactly 88 unique files")


class AttestationError(RuntimeError):
    """Raised when any provenance or execution condition fails closed."""


def fail(message: str) -> None:
    raise AttestationError(message)


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


def _component_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    """Identify a path component without volatile directory timestamps."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(getattr(value, "st_file_attributes", 0)),
    )


@dataclass(frozen=True)
class DirectoryComponentSnapshot:
    path: Path
    identity: tuple[int, int, int, int]


@dataclass
class BoundDirectory:
    path: Path
    components: tuple[DirectoryComponentSnapshot, ...]
    descriptor: int | None = None
    windows_handle: int | None = None


def _plain_directory_components(
    path: Path, description: str
) -> tuple[DirectoryComponentSnapshot, ...]:
    directory = Path(os.path.abspath(path))
    components = tuple(reversed((directory, *directory.parents)))
    snapshots: list[DirectoryComponentSnapshot] = []
    for component in components:
        try:
            observed = component.lstat()
        except OSError as exc:
            fail(f"cannot inspect {description} ancestor {component}: {exc}")
        if (
            stat.S_ISLNK(observed.st_mode)
            or _has_reparse_point(observed)
            or not stat.S_ISDIR(observed.st_mode)
        ):
            fail(
                f"{description} contains a symlink/reparse/junction ancestor: "
                f"{component}"
            )
        snapshots.append(
            DirectoryComponentSnapshot(component, _component_identity(observed))
        )
    return tuple(snapshots)


def _recheck_plain_directory_components(
    snapshots: tuple[DirectoryComponentSnapshot, ...], description: str
) -> None:
    for snapshot in snapshots:
        try:
            observed = snapshot.path.lstat()
        except OSError as exc:
            fail(f"cannot re-inspect {description} ancestor {snapshot.path}: {exc}")
        if (
            stat.S_ISLNK(observed.st_mode)
            or _has_reparse_point(observed)
            or not stat.S_ISDIR(observed.st_mode)
            or _component_identity(observed) != snapshot.identity
        ):
            fail(
                f"{description} ancestor was replaced or redirected: {snapshot.path}"
            )


def _open_windows_directory_handle(path: Path, description: str) -> int:
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x0080,  # FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002,  # share read/write, deliberately not delete
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        error = ctypes.get_last_error()
        fail(f"cannot bind {description} directory handle (Windows error {error})")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    close_handle(wintypes.HANDLE(handle))


@contextmanager
def bind_plain_directory(path: Path, description: str) -> Iterable[BoundDirectory]:
    """Hold a parent and recheck its complete plain ancestor identity chain."""

    directory = Path(os.path.abspath(path))
    components = _plain_directory_components(directory, description)
    binding = BoundDirectory(path=directory, components=components)
    try:
        if os.name == "nt":
            binding.windows_handle = _open_windows_directory_handle(
                directory, description
            )
        else:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                binding.descriptor = os.open(directory, flags)
            except OSError as exc:
                fail(f"cannot bind {description} directory descriptor: {exc}")
            opened = os.fstat(binding.descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _component_identity(opened) != components[-1].identity
            ):
                fail(f"{description} directory changed while it was opened")
        _recheck_plain_directory_components(components, description)
        yield binding
        _recheck_plain_directory_components(components, description)
        if binding.descriptor is not None:
            opened_after = os.fstat(binding.descriptor)
            if _component_identity(opened_after) != components[-1].identity:
                fail(f"{description} bound directory identity changed")
    finally:
        if binding.descriptor is not None:
            os.close(binding.descriptor)
        if binding.windows_handle is not None:
            _close_windows_handle(binding.windows_handle)


def _open_exclusive_child(
    binding: BoundDirectory, name: str, flags: int, mode: int
) -> int:
    if not name or name in (".", "..") or Path(name).name != name:
        fail("exclusive output name must be one plain leaf component")
    if binding.descriptor is not None:
        return os.open(name, flags, mode, dir_fd=binding.descriptor)
    return os.open(binding.path / name, flags, mode)


def _unlink_bound_child(binding: BoundDirectory, name: str) -> None:
    try:
        if binding.descriptor is not None:
            os.unlink(name, dir_fd=binding.descriptor)
        else:
            (binding.path / name).unlink()
    except OSError:
        pass


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int]
    data: bytes | None = None


def read_snapshot(
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
        fail(f"{description} exceeds the byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if collect else None
    size = 0
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            fail(f"opened {description} is not a regular file")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            if maximum_bytes is not None and size > maximum_bytes:
                fail(f"{description} exceeds the byte limit")
            digest.update(block)
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
    try:
        current = snapshot.path.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    if (
        stat.S_ISLNK(current.st_mode)
        or _has_reparse_point(current)
        or _identity(current) != snapshot.identity
    ):
        fail(f"{description} was replaced after its stable snapshot")


def reject_constant(value: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
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


def load_json_bytes(data: bytes, description: str) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"{description} is not strict UTF-8: {exc}")
    if text.startswith("\ufeff"):
        fail(f"{description} must not contain a UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except AttestationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        fail(f"cannot parse {description}: {exc}")
    _reject_nonfinite(value)
    return value


def load_json_snapshot(path: Path, description: str) -> tuple[Any, FileSnapshot]:
    snapshot = read_snapshot(
        path, description, collect=True, maximum_bytes=MAX_JSON_BYTES
    )
    if snapshot.data is None:
        fail(f"internal error: {description} bytes were not collected")
    return load_json_bytes(snapshot.data, description), snapshot


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        fail(f"cannot serialize canonical JSON: {exc}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_keys(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    actual = set(value)
    if actual != expected:
        fail(
            f"{description} keys differ; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    return value


def safe_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        fail(f"{description} is not a safe identifier")
    return value


def require_hash(value: Any, description: str, *, git: bool = False) -> str:
    pattern = HEX40_OR_64 if git else HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{description} is not a lowercase hexadecimal hash")
    return value


def require_size(value: Any, description: str) -> int:
    if type(value) is not int or value < 0:
        fail(f"{description} must be a non-negative integer")
    return value


def require_exact_integer(value: Any, expected: int, description: str) -> None:
    if type(value) is not int or value != expected:
        fail(f"{description} must be integer {expected}")


def safe_relative(value: Any, description: str, *, allow_dot: bool = False) -> str:
    if value == "." and allow_dot:
        return "."
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail(f"{description} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(
        part in ("", ".", "..") for part in path.parts
    ):
        fail(f"{description} contains absolute, traversal, or non-canonical syntax")
    for part in path.parts:
        if (
            len(part) > 128
            or SAFE_ID.fullmatch(part) is None
            or ":" in part
        ):
            fail(f"{description} contains an unsafe path component")
    return value


def safe_archive_relative(
    value: Any, description: str, *, is_directory: bool
) -> str:
    """Validate one canonical, portable Git-archive member name.

    Git repositories legitimately contain leading-dot names such as
    ``.gitattributes``, ``.gitignore``, and ``.github``.  Production plan
    paths intentionally use the narrower :func:`safe_relative` grammar; source
    archives need this separate grammar so those tracked names remain valid
    without admitting traversal, alternate-data-stream, or separator tricks.
    """

    if not isinstance(value, str) or not value:
        fail(f"{description} must be a non-empty POSIX relative path")
    if any(character in value for character in ("\\", "\x00", "\r", "\n", ":")):
        fail(f"{description} contains an unsafe character")
    if value.endswith("/"):
        if not is_directory:
            fail(f"{description} regular-file name must not end with a slash")
        value = value[:-1]
    if not value or value.startswith("/"):
        fail(f"{description} must be a non-empty POSIX relative path")
    components = value.split("/")
    if any(component in ("", ".", "..") for component in components):
        fail(f"{description} contains empty, dot, or traversal components")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        fail(f"{description} contains absolute or non-canonical syntax")
    return value


def parse_utc(value: Any, description: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{description} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        fail(f"cannot parse {description}: {exc}")
    if parsed.tzinfo != timezone.utc:
        fail(f"{description} is not UTC")
    return parsed


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def atomic_write_new(path: Path, data: bytes, description: str) -> None:
    candidate = Path(os.path.abspath(path))
    candidate.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    with bind_plain_directory(candidate.parent, f"{description} parent") as binding:
        descriptor = -1
        created = False
        try:
            _recheck_plain_directory_components(
                binding.components, f"{description} parent before create"
            )
            descriptor = _open_exclusive_child(
                binding, candidate.name, flags, 0o600
            )
            created = True
            opened_before = os.fstat(descriptor)
            if not stat.S_ISREG(opened_before.st_mode) or opened_before.st_nlink != 1:
                fail(f"opened {description} is not one new regular file")
            _recheck_plain_directory_components(
                binding.components, f"{description} parent after create"
            )
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    fail(f"zero-byte write while creating {description}")
                view = view[written:]
            os.fsync(descriptor)
            opened_after = os.fstat(descriptor)
            try:
                named_after = candidate.lstat()
            except OSError as exc:
                fail(f"cannot re-inspect newly created {description}: {exc}")
            if (
                _identity(opened_before)[:2] != _identity(opened_after)[:2]
                or _identity(opened_after) != _identity(named_after)
                or stat.S_ISLNK(named_after.st_mode)
                or _has_reparse_point(named_after)
                or opened_after.st_nlink != 1
                or opened_after.st_size != len(data)
            ):
                fail(f"{description} was redirected or replaced during creation")
            _recheck_plain_directory_components(
                binding.components, f"{description} parent after write"
            )
        except AttestationError:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            if created:
                _unlink_bound_child(binding, candidate.name)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            if created:
                _unlink_bound_child(binding, candidate.name)
            fail(f"cannot create {description}: {exc}")
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def ensure_new_empty_directory(path: Path, description: str) -> Path:
    candidate = Path(path).resolve(strict=False)
    if candidate.exists() or candidate.is_symlink():
        fail(f"{description} must not pre-exist: {candidate}")
    try:
        candidate.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        fail(f"cannot create {description}: {exc}")
    observed = candidate.lstat()
    if not stat.S_ISDIR(observed.st_mode) or _has_reparse_point(observed):
        fail(f"{description} is not a plain directory")
    return candidate


def validate_plain_root(path: Path, description: str) -> Path:
    candidate = Path(path).resolve(strict=False)
    try:
        observed = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _has_reparse_point(observed)
    ):
        fail(f"{description} must be a plain non-link directory")
    return candidate


def paths_overlap(first: Path, second: Path) -> bool:
    left = Path(first).resolve(strict=False)
    right = Path(second).resolve(strict=False)
    return left == right or left in right.parents or right in left.parents


def validate_root_separation(
    public_source_repo: Path,
    source_repo: Path,
    evidence_dir: Path,
    output_root: Path,
    execution_root: Path,
    report_path: Path | None,
) -> None:
    """Keep private outputs/evidence away from source and one another."""

    public_source = Path(public_source_repo).resolve(strict=False)
    source = Path(source_repo).resolve(strict=False)
    roots = {
        "private run-evidence root": Path(evidence_dir).resolve(strict=False),
        "production output root": Path(output_root).resolve(strict=False),
        "archive execution root": Path(execution_root).resolve(strict=False),
    }
    for description, root in roots.items():
        if paths_overlap(source, root):
            fail(f"{description} must be outside the private source repository")
        if paths_overlap(public_source, root):
            fail(f"{description} must be outside the public source repository")
    items = list(roots.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if paths_overlap(left, right):
                fail(f"{left_name} and {right_name} must not overlap")
    if report_path is not None:
        report = Path(report_path).resolve(strict=False)
        if report == source or source in report.parents:
            fail("public report must not be written into the private source repository")
        for description, root in roots.items():
            if report == root or root in report.parents:
                fail(f"public report must be outside the {description}")


def validate_evidence(value: Any, description: str) -> dict[str, Any]:
    item = exact_keys(value, {"sha256", "size_bytes"}, description)
    require_hash(item["sha256"], f"{description} sha256")
    require_size(item["size_bytes"], f"{description} size")
    return item


def executable_chain(path: Path) -> tuple[FileSnapshot, str]:
    """Pin a venv-style executable symlink chain and its regular target.

    Production Python virtual environments normally expose ``bin/python`` as
    a symlink. Output, evidence, source, plan, runtime, key, and tool files
    still reject links outright; this narrowly scoped routine permits only an
    exact, loop-free executable chain whose link text and final bytes are
    hash-locked in the command plan.
    """

    current = Path(path)
    if not current.is_absolute():
        fail("runtime executable path must be absolute")
    lexical = Path(os.path.abspath(current))
    if os.path.normcase(str(current)) != os.path.normcase(str(lexical)):
        fail("runtime executable path must use canonical lexical syntax")
    current = lexical
    seen: set[str] = set()
    entries: list[dict[str, Any]] = []
    ancestor_by_path: dict[str, DirectoryComponentSnapshot] = {}
    link_snapshots: list[
        tuple[Path, tuple[int, int, int, int], str]
    ] = []
    for _index in range(16):
        for component in _plain_directory_components(
            current.parent, "runtime executable"
        ):
            key = os.path.normcase(str(component.path))
            previous = ancestor_by_path.get(key)
            if previous is not None and previous.identity != component.identity:
                fail("runtime executable ancestor identity changed during traversal")
            ancestor_by_path[key] = component
        normalized = os.path.normcase(str(current.absolute()))
        if normalized in seen:
            fail("runtime executable symlink chain contains a loop")
        seen.add(normalized)
        try:
            observed = current.lstat()
        except OSError as exc:
            fail(f"cannot inspect runtime executable chain: {exc}")
        if stat.S_ISLNK(observed.st_mode):
            try:
                target = os.readlink(current)
            except OSError as exc:
                fail(f"cannot read runtime executable symlink: {exc}")
            try:
                observed_after = current.lstat()
                target_after = os.readlink(current)
            except OSError as exc:
                fail(f"cannot re-inspect runtime executable symlink: {exc}")
            link_identity = _component_identity(observed)
            if (
                not stat.S_ISLNK(observed_after.st_mode)
                or _component_identity(observed_after) != link_identity
                or target_after != target
            ):
                fail("runtime executable symlink changed during traversal")
            link_snapshots.append((current, link_identity, target))
            entries.append(
                {
                    "kind": "symlink",
                    "path": str(current.absolute()),
                    "target": target,
                    "identity": list(link_identity),
                }
            )
            target_path = Path(target)
            current = (
                target_path
                if target_path.is_absolute()
                else current.parent / target_path
            )
            current = Path(os.path.abspath(current))
            continue
        if _has_reparse_point(observed):
            fail("runtime executable chain contains a non-symlink reparse point")
        if not stat.S_ISREG(observed.st_mode):
            fail("runtime executable chain does not end in a regular file")
        snapshot = read_snapshot(current, "runtime executable target")
        entries.append(
            {
                "kind": "regular",
                "path": str(current.absolute()),
                "sha256": snapshot.sha256,
                "size_bytes": snapshot.size_bytes,
                "identity": list(_component_identity(current.lstat())),
            }
        )
        ancestor_snapshots = tuple(ancestor_by_path.values())
        _recheck_plain_directory_components(
            ancestor_snapshots, "runtime executable"
        )
        for link_path, link_identity, target in link_snapshots:
            try:
                link_now = link_path.lstat()
                target_now = os.readlink(link_path)
            except OSError as exc:
                fail(f"cannot recheck runtime executable symlink chain: {exc}")
            if (
                not stat.S_ISLNK(link_now.st_mode)
                or _component_identity(link_now) != link_identity
                or target_now != target
            ):
                fail("runtime executable symlink chain changed after traversal")
        recheck_snapshot(snapshot, "runtime executable target")
        chain_document = {
            "ancestors": [
                {
                    "path": str(item.path),
                    "identity": list(item.identity),
                }
                for item in ancestor_snapshots
            ],
            "chain": entries,
        }
        return snapshot, sha256_bytes(canonical_json_bytes(chain_document))
    fail("runtime executable symlink chain is too deep")


def snapshot_evidence(snapshot: FileSnapshot) -> dict[str, Any]:
    return {"sha256": snapshot.sha256, "size_bytes": snapshot.size_bytes}


def validate_signers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != 2:
        fail("contract must lock exactly two attestation signers")
    result: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = exact_keys(raw, {"signer_id", "public_key"}, f"signer {index}")
        identifier = safe_id(item["signer_id"], f"signer {index} id")
        public_key = item["public_key"]
        if (
            not isinstance(public_key, str)
            or "\n" in public_key
            or "\r" in public_key
            or len(public_key.split()) not in (2, 3)
            or public_key.split()[0] != "ssh-ed25519"
        ):
            fail("signer public key must be one OpenSSH Ed25519 line")
        result.append({"signer_id": identifier, "public_key": public_key})
    if (
        len({item["signer_id"] for item in result}) != 2
        or len({" ".join(item["public_key"].split()[:2]) for item in result}) != 2
    ):
        fail("attestation signer ids and key material must be distinct")
    return result


def validate_source_lock(value: Any, *, complete: bool) -> dict[str, Any]:
    item = exact_keys(
        value,
        {
            "public_repository",
            "private_repository",
            "commit",
            "tree",
            "archive_sha256",
            "archive_size_bytes",
            "git_executable",
            "ssh_keygen_executable",
        },
        "candidate source lock",
    )
    if item["public_repository"] != PUBLIC_REPOSITORY:
        fail("candidate public repository slug is not the release repository")
    if item["private_repository"] != PRIVATE_REPOSITORY:
        fail("candidate private repository slug is not the production repository")
    nullable = (
        "commit",
        "tree",
        "archive_sha256",
        "archive_size_bytes",
        "git_executable",
        "ssh_keygen_executable",
    )
    if not complete and all(item[name] is None for name in nullable):
        return item
    if any(item[name] is None for name in nullable):
        fail("candidate source/tool lock is only partially populated")
    require_hash(item["commit"], "source commit", git=True)
    require_hash(item["tree"], "source tree", git=True)
    require_hash(item["archive_sha256"], "source archive sha256")
    require_size(item["archive_size_bytes"], "source archive size")
    validate_evidence(item["git_executable"], "git executable lock")
    validate_evidence(item["ssh_keygen_executable"], "ssh-keygen executable lock")
    return item


def validate_candidate(value: Any) -> dict[str, Any]:
    item = exact_keys(
        value,
        {
            "id",
            "role",
            "qualification_eligible",
            "production_accepted",
            "source_lock",
            "command_plan",
            "numerical_runtime_manifest",
            "accepted_report",
            "note",
        },
        "local-run candidate",
    )
    safe_id(item["id"], "candidate id")
    safe_id(item["role"], "candidate role")
    if item["qualification_eligible"] is not True:
        fail("local-run candidate is not qualification-eligible")
    if type(item["production_accepted"]) is not bool:
        fail("candidate production_accepted must be Boolean")
    complete = item["production_accepted"] is True or any(
        part is not None
        for part in (
            item["command_plan"],
            item["numerical_runtime_manifest"],
            item["accepted_report"],
        )
    )
    validate_source_lock(item["source_lock"], complete=complete)
    for field in ("command_plan", "numerical_runtime_manifest"):
        if item[field] is None:
            if complete:
                fail(f"candidate {field} lock is missing")
        else:
            validate_evidence(item[field], f"candidate {field}")
    if item["accepted_report"] is None:
        if item["production_accepted"]:
            fail("production-accepted candidate lacks an accepted report lock")
    else:
        report = exact_keys(
            item["accepted_report"],
            {"report_id", "sha256", "size_bytes"},
            "accepted public report lock",
        )
        require_hash(report["report_id"], "accepted report id")
        require_hash(report["sha256"], "accepted report sha256")
        require_size(report["size_bytes"], "accepted report size")
        if not item["production_accepted"]:
            fail("unaccepted candidate must not pre-lock an accepted report")
    if not isinstance(item["note"], str):
        fail("candidate note must be text")
    return item


def validate_contract(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = exact_keys(
        value,
        {
            "schema_version",
            "contract_id",
            "policy",
            "attestation_signers",
            "candidates",
        },
        "local-run contract",
    )
    require_exact_integer(
        contract["schema_version"], SCHEMA_VERSION, "local-run contract schema_version"
    )
    safe_id(contract["contract_id"], "contract id")
    policy = exact_keys(
        contract["policy"],
        {
            "start_signature_namespace",
            "completion_signature_namespace",
            "nonce_bytes",
            "required_distinct_signers",
            "execution_controller",
            "command_execution",
            "require_clean_exact_private_source",
            "require_archive_extracted_execution_tree",
            "require_exact_output_file_set",
            "require_shell_false",
            "public_report_disclosure",
            "controller_sha256",
            "allowed_execution_environments",
        },
        "local-run policy",
    )
    expected_policy = {
        "start_signature_namespace": START_NAMESPACE,
        "completion_signature_namespace": COMPLETION_NAMESPACE,
        "nonce_bytes": 32,
        "required_distinct_signers": 2,
        "execution_controller": "verify_local_run_attestation.execute_plan",
        "command_execution": "subprocess_run_exact_argv_env_cwd_shell_false",
        "require_clean_exact_private_source": True,
        "require_archive_extracted_execution_tree": True,
        "require_exact_output_file_set": True,
        "require_shell_false": True,
        "public_report_disclosure": "hashes_status_counts_and_timings_only",
    }
    for key, expected in expected_policy.items():
        if type(expected) is bool:
            matches = type(policy[key]) is bool and policy[key] is expected
        elif type(expected) is int:
            matches = type(policy[key]) is int and policy[key] == expected
        else:
            matches = policy[key] == expected
        if not matches:
            fail(f"local-run policy {key} is not the required value")
    require_hash(policy["controller_sha256"], "controller sha256")
    environments = policy["allowed_execution_environments"]
    if (
        not isinstance(environments, list)
        or not environments
        or len(environments) != len(set(environments))
    ):
        fail("allowed execution environments must be a non-empty unique list")
    for entry in environments:
        safe_id(entry, "allowed execution environment")
    signers = validate_signers(contract["attestation_signers"])
    if contract["contract_id"] == CONTRACT_ID and tuple(signers) != PINNED_SIGNERS:
        fail("release contract signer keys differ from the pinned v4.0.4 keys")
    candidates = contract["candidates"]
    if not isinstance(candidates, list) or not candidates:
        fail("local-run contract must contain at least one candidate")
    validated = [validate_candidate(item) for item in candidates]
    if len({item["id"] for item in validated}) != len(validated):
        fail("candidate ids must be unique")
    return contract, {item["id"]: item for item in validated}


def select_contract(
    contract_path: Path, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any], FileSnapshot]:
    value, snapshot = load_json_snapshot(contract_path, "local-run contract")
    contract, candidates = validate_contract(value)
    if candidate_id not in candidates:
        fail(f"unknown local-run candidate: {candidate_id!r}")
    candidate = candidates[candidate_id]
    validate_source_lock(candidate["source_lock"], complete=True)
    if candidate["command_plan"] is None or candidate["numerical_runtime_manifest"] is None:
        fail("candidate plan/runtime locks are not populated")
    controller = read_snapshot(Path(__file__), "local-run controller")
    if controller.sha256 != contract["policy"]["controller_sha256"]:
        fail("running controller bytes differ from the contract lock")
    return contract, candidate, snapshot


def signer_by_id(contract: Mapping[str, Any], signer_id: str) -> dict[str, str]:
    matches = [
        item for item in contract["attestation_signers"] if item["signer_id"] == signer_id
    ]
    if len(matches) != 1:
        fail(f"unknown or duplicate signer id: {signer_id!r}")
    return matches[0]


def validate_tool(path: Path, lock: Mapping[str, Any], description: str) -> FileSnapshot:
    candidate = Path(path)
    if not candidate.is_absolute():
        fail(f"{description} path must be absolute")
    snapshot = read_snapshot(candidate, description)
    if snapshot_evidence(snapshot) != lock:
        fail(f"{description} bytes differ from the candidate lock")
    return snapshot


def run_checked(argv: list[str], description: str, **kwargs: Any) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, shell=False, **kwargs)
    except (OSError, ValueError) as exc:
        fail(f"cannot execute {description}: {exc}")
    return result


def git_text(git: Path, repo: Path, args: list[str], description: str) -> str:
    result = run_checked(
        [str(git), "-C", str(repo), *args],
        description,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"{description} failed with exit code {result.returncode}")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        fail(f"{description} output is not strict UTF-8: {exc}")


def normalize_repository_slug(url: str) -> str:
    """Accept only canonical github.com HTTPS or Git-over-SSH origins."""

    if not isinstance(url, str) or url != url.strip() or any(
        character in url for character in ("\x00", "\r", "\n", "\\")
    ):
        fail("Git origin is not one canonical github.com URL")
    path = ""
    if re.fullmatch(r"git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url):
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


def git_archive(git: Path, repo: Path) -> bytes:
    result = run_checked(
        [str(git), "-C", str(repo), "archive", "--format=tar", "HEAD"],
        "git archive",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"git archive failed with exit code {result.returncode}")
    if len(result.stdout) > MAX_ARCHIVE_BYTES:
        fail("git archive exceeds the controller byte limit")
    return result.stdout


def inspect_source(
    source_repo: Path,
    git: Path,
    source_lock: Mapping[str, Any],
    *,
    repository_field: str = "private_repository",
) -> tuple[dict[str, Any], bytes]:
    if repository_field not in ("public_repository", "private_repository"):
        fail("internal error: invalid source repository role")
    role = "public" if repository_field == "public_repository" else "private"
    repo = validate_plain_root(source_repo, f"{role} source repository")
    if git_text(git, repo, ["rev-parse", "--is-inside-work-tree"], "git worktree check") != "true":
        fail(f"{role} source is not a Git worktree")
    status = git_text(
        git,
        repo,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"],
        "git clean-state check",
    )
    if status:
        fail(f"{role} source contains tracked, untracked, or ignored shadow changes")
    staged = git_text(git, repo, ["ls-files", "--stage"], "git tracked-file mode check")
    for line in staged.splitlines():
        mode = line.split(" ", 1)[0]
        if mode not in ("100644", "100755"):
            fail(f"{role} source contains a non-regular tracked entry mode: {mode}")
    observed_repository = normalize_repository_slug(
        git_text(git, repo, ["remote", "get-url", "origin"], "git origin lookup")
    )
    if observed_repository != source_lock[repository_field]:
        fail(f"{role} source origin differs from the candidate repository lock")
    actual = {
        "public_repository": source_lock["public_repository"],
        "private_repository": source_lock["private_repository"],
        "commit": git_text(git, repo, ["rev-parse", "HEAD"], "git commit lookup"),
        "tree": git_text(git, repo, ["rev-parse", "HEAD^{tree}"], "git tree lookup"),
    }
    archive = git_archive(git, repo)
    actual["archive_sha256"] = sha256_bytes(archive)
    actual["archive_size_bytes"] = len(archive)
    expected = {
        key: source_lock[key]
        for key in (
            "public_repository",
            "private_repository",
            "commit",
            "tree",
            "archive_sha256",
            "archive_size_bytes",
        )
    }
    if actual != expected:
        fail(f"{role} source Git/tree/archive identity differs from the public candidate lock")
    return actual, archive


def archive_members(archive: bytes) -> tuple[dict[str, bytes], set[str]]:
    files: dict[str, bytes] = {}
    directories = {"."}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for member in bundle.getmembers():
                relative = safe_archive_relative(
                    member.name,
                    "source archive member",
                    is_directory=member.isdir(),
                )
                if member.isdir():
                    directories.add(relative)
                    continue
                if not member.isfile():
                    fail("source archive contains a link or special member")
                extracted = bundle.extractfile(member)
                if extracted is None:
                    fail("cannot read a regular source archive member")
                data = extracted.read()
                if relative in files:
                    fail("source archive contains a duplicate member")
                files[relative] = data
                parent = PurePosixPath(relative).parent
                while str(parent) != ".":
                    directories.add(str(parent))
                    parent = parent.parent
    except (tarfile.TarError, OSError) as exc:
        fail(f"cannot inspect source archive: {exc}")
    folded = [name.casefold() for name in [*files, *directories] if name != "."]
    if len(folded) != len(set(folded)):
        fail("source archive has case-colliding paths")
    return files, directories


def source_manifest(files: Mapping[str, bytes]) -> dict[str, Any]:
    entries = [
        {"path": name, "sha256": sha256_bytes(data), "size_bytes": len(data)}
        for name, data in sorted(files.items())
    ]
    return {
        "file_count": len(entries),
        "total_size_bytes": sum(item["size_bytes"] for item in entries),
        "file_set_sha256": sha256_bytes(canonical_json_bytes(entries)),
    }


def extract_archive_exact(archive: bytes, destination: Path) -> dict[str, Any]:
    files, directories = archive_members(archive)
    root = ensure_new_empty_directory(destination, "archive execution root")
    for name in sorted(directories, key=lambda item: (item.count("/"), item)):
        if name == ".":
            continue
        (root / Path(*PurePosixPath(name).parts)).mkdir(exist_ok=False)
    for name, data in sorted(files.items()):
        target = root / Path(*PurePosixPath(name).parts)
        atomic_write_new(target, data, f"source member {name}")
    verify_exact_tree(root, files, directories, "archive execution tree")
    return source_manifest(files)


def enumerate_plain_tree(
    root: Path, description: str, *, allow_git_archive_paths: bool = False
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = {"."}

    def visit(directory: Path, relative: PurePosixPath) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            fail(f"cannot enumerate {description}: {exc}")
        for entry in entries:
            try:
                observed = entry.stat(follow_symlinks=False)
            except OSError as exc:
                fail(f"cannot inspect {description} entry: {exc}")
            if entry.is_symlink() or _has_reparse_point(observed):
                fail(f"{description} contains a link/reparse entry: {entry.name}")
            name = str(relative / entry.name) if str(relative) != "." else entry.name
            if stat.S_ISDIR(observed.st_mode):
                if allow_git_archive_paths:
                    safe_archive_relative(
                        name, f"{description} path", is_directory=True
                    )
                else:
                    safe_relative(name, f"{description} path")
                directories.add(name)
                visit(Path(entry.path), PurePosixPath(name))
            elif stat.S_ISREG(observed.st_mode):
                if allow_git_archive_paths:
                    safe_archive_relative(
                        name, f"{description} path", is_directory=False
                    )
                else:
                    safe_relative(name, f"{description} path")
                files.add(name)
            else:
                fail(f"{description} contains a special filesystem entry")

    visit(root, PurePosixPath("."))
    return files, directories


def verify_exact_tree(
    root: Path,
    expected_files: Mapping[str, bytes],
    expected_directories: set[str],
    description: str,
) -> None:
    plain = validate_plain_root(root, description)
    files, directories = enumerate_plain_tree(
        plain, description, allow_git_archive_paths=True
    )
    if files != set(expected_files) or directories != expected_directories:
        fail(f"{description} exact file/directory set differs from the source archive")
    snapshots: list[FileSnapshot] = []
    for name, expected in sorted(expected_files.items()):
        snapshot = read_snapshot(
            plain / Path(*PurePosixPath(name).parts), f"{description} member {name}"
        )
        if snapshot.sha256 != sha256_bytes(expected) or snapshot.size_bytes != len(expected):
            fail(f"{description} member bytes differ: {name}")
        snapshots.append(snapshot)
    for snapshot in snapshots:
        recheck_snapshot(snapshot, f"{description} member")
    final_files, final_directories = enumerate_plain_tree(
        plain, description, allow_git_archive_paths=True
    )
    if final_files != files or final_directories != directories:
        fail(f"{description} file set changed during verification")


def validate_numerical_runtime(value: Any) -> dict[str, Any]:
    runtime = exact_keys(
        value,
        {
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
        },
        "numerical runtime manifest",
    )
    if type(runtime["schema_version"]) is not int or runtime["schema_version"] != 1 or runtime["status"] != "PASS":
        fail("numerical runtime manifest is not schema-1 PASS")
    if runtime["numpy_version"] != "1.23.5":
        fail("numerical runtime manifest does not pin NumPy 1.23.5")
    if runtime["environment"] != REQUIRED_RUNTIME_ENV:
        fail("numerical runtime environment differs from the release policy")
    features = runtime["selected_cpu_features"]
    if not isinstance(features, dict):
        fail("numerical runtime CPU feature selection must be an object")
    for name in REQUIRED_ENABLED_CPU:
        if features.get(name) is not True:
            fail(f"numerical runtime required feature is not enabled: {name}")
    for name in REQUIRED_DISABLED_CPU:
        if features.get(name) is not False:
            fail(f"numerical runtime forbidden feature is not disabled: {name}")
    executable = runtime["python_executable"]
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        fail("numerical runtime Python executable must be an absolute path")
    for field in ("python", "platform", "machine"):
        if not isinstance(runtime[field], str) or not runtime[field]:
            fail(f"numerical runtime {field} must be non-empty text")
    for field in ("numpy_cpu_baseline", "numpy_cpu_dispatch_build"):
        if not isinstance(runtime[field], list) or not all(
            isinstance(item, str) for item in runtime[field]
        ):
            fail(f"numerical runtime {field} must be a string list")
    return runtime


def validate_plan(value: Any, runtime: Mapping[str, Any]) -> dict[str, Any]:
    plan = exact_keys(
        value,
        {"schema_version", "plan_label", "commands", "expected_output_files"},
        "local production command plan",
    )
    require_exact_integer(plan["schema_version"], 1, "command plan schema_version")
    plan_specs = {
        V404_PLAN_LABEL: (
            V404_COMMAND_ID,
            "run",
            V404_RUN_FLAGS,
            V404_PATH_FLAGS,
        ),
        V404_RECOVERY_PLAN_LABEL: (
            V404_RECOVERY_COMMAND_ID,
            "recover-mcmc",
            V404_RECOVERY_RUN_FLAGS,
            V404_RECOVERY_PATH_FLAGS,
        ),
    }
    try:
        expected_command_id, expected_mode, expected_flags, expected_path_flags = (
            plan_specs[plan["plan_label"]]
        )
    except (KeyError, TypeError):
        fail(
            "command plan label must be exactly one of the recognized "
            "v4.0.4 plan labels"
        )
    outputs = plan["expected_output_files"]
    if not isinstance(outputs, list):
        fail("command plan expected outputs must be an array")
    validated_outputs = [
        safe_relative(item, f"expected output {index}")
        for index, item in enumerate(outputs)
    ]
    if validated_outputs != sorted(validated_outputs):
        fail("expected output paths must be sorted")
    if len({item.casefold() for item in validated_outputs}) != len(validated_outputs):
        fail("expected output paths must be unique without case collisions")
    if tuple(validated_outputs) != V404_EXPECTED_OUTPUT_FILES:
        fail("command plan must lock the exact 88-file v4.0.4 public output set")
    commands = plan["commands"]
    if not isinstance(commands, list) or len(commands) != 1:
        fail("command plan must contain exactly one v4.0.4 production command")
    identifiers: list[str] = []
    for index, raw in enumerate(commands):
        command = exact_keys(
            raw,
            {
                "command_id",
                "argv",
                "cwd",
                "env",
                "executable_sha256",
                "executable_size_bytes",
                "executable_chain_sha256",
            },
            f"command {index}",
        )
        identifiers.append(safe_id(command["command_id"], f"command {index} id"))
        if command["command_id"] != expected_command_id:
            fail(f"command id must be exactly {expected_command_id!r}")
        if command["cwd"] != ".":
            fail("every production command cwd must be the exact extracted source root")
        argv = command["argv"]
        if not isinstance(argv, list) or len(argv) != 3 + 2 * len(expected_flags) or not all(
            isinstance(item, str)
            and item
            and "\x00" not in item
            and "\r" not in item
            and "\n" not in item
            for item in argv
        ):
            fail("every command argv must be a non-empty string array")
        executable = Path(argv[0])
        if not executable.is_absolute() or argv[0] != runtime["python_executable"]:
            fail("every command must use the exact runtime Python executable")
        if argv[1] != V404_PROGRAM or argv[2] != expected_mode:
            fail("command must invoke the exact tracked v4.0.4 production program")
        observed_flags = tuple(argv[position] for position in range(3, len(argv), 2))
        if observed_flags != expected_flags:
            fail("command argv flags/order differ from the canonical v4.0.4 run schema")
        argv_values = {
            argv[position]: argv[position + 1]
            for position in range(3, len(argv), 2)
        }
        for flag in expected_path_flags:
            raw_path = argv_values[flag]
            path_value = Path(raw_path)
            if not path_value.is_absolute():
                fail(f"command path argument must be absolute: {flag}")
            lexical = Path(os.path.abspath(path_value))
            if os.path.normcase(raw_path) != os.path.normcase(str(lexical)):
                fail(f"command path argument is not lexically canonical: {flag}")
        require_hash(
            argv_values["--expected-source-archive-sha256"],
            "expected source archive hash argument",
        )
        require_hash(
            argv_values["--expected-host-contract-sha256"],
            "expected external host contract hash argument",
        )
        if (
            argv_values["--expected-bryson-source-sha256"]
            != V404_BRYSON_SOURCE_SHA256
        ):
            fail("Bryson source hash argument differs from the v4.0.4 lock")
        if argv_values["--maximum-parallel-shards"] not in {"1", "2", "3", "4"}:
            fail("maximum parallel shards argument must be canonical integer 1..4")
        if expected_mode == "recover-mcmc":
            require_hash(
                argv_values["--expected-recovery-contract-sha256"],
                "expected recovery-contract hash argument",
            )
            size_value = argv_values["--expected-recovery-contract-size-bytes"]
            if (
                not size_value.isascii()
                or not size_value.isdecimal()
                or size_value.startswith("0")
                or int(size_value) <= 0
            ):
                fail("expected recovery-contract size argument is not a canonical positive integer")
        if argv_values["--python-executable"] != argv[0]:
            fail("command Python argument differs from argv[0]")
        require_hash(command["executable_sha256"], f"command {index} executable hash")
        require_size(command["executable_size_bytes"], f"command {index} executable size")
        require_hash(
            command["executable_chain_sha256"],
            f"command {index} executable chain hash",
        )
        env = command["env"]
        if not isinstance(env, dict) or set(env) != V404_ENV_KEYS:
            fail("command environment keys differ from the exact v4.0.4 schema")
        for key, item in env.items():
            if (
                not isinstance(key, str)
                or not key
                or "=" in key
                or "\x00" in key
                or not isinstance(item, str)
                or "\x00" in item
            ):
                fail("command env contains an invalid name or value")
        for key, expected in REQUIRED_RUNTIME_ENV.items():
            if env.get(key) != expected:
                fail(f"command environment differs from runtime policy: {key}")
        if env.get("PYTHONDONTWRITEBYTECODE") != "1":
            fail("command environment must disable Python bytecode writes")
        for required in (
            "EXOEARTH_SOURCE_ROOT",
            "EXOEARTH_OUTPUT_ROOT",
            "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST",
        ):
            if not isinstance(env.get(required), str) or not env[required]:
                fail(f"command environment lacks {required}")
    if len(identifiers) != len(set(identifiers)):
        fail("command ids must be unique")
    return plan


def validate_plan_bindings(
    plan: Mapping[str, Any],
    runtime: Mapping[str, Any],
    execution_root: Path,
    output_root: Path,
    runtime_path: Path,
    plan_path: Path,
    trusted_git_executable: Path,
    private_production_checkout: Path,
    public_release_checkout: Path,
    *,
    require_extracted_programs: bool,
    trusted_ssh_keygen_executable: Path | None = None,
) -> None:
    expected_bindings = {
        "EXOEARTH_SOURCE_ROOT": str(execution_root),
        "EXOEARTH_OUTPUT_ROOT": str(output_root),
        "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST": str(runtime_path.resolve()),
    }
    executable_snapshot: FileSnapshot | None = None
    for index, command in enumerate(plan["commands"]):
        for key, expected in expected_bindings.items():
            if command["env"].get(key) != expected:
                fail(f"command {index} {key} does not bind the controller path")
        argv_values = {
            command["argv"][position]: command["argv"][position + 1]
            for position in range(3, len(command["argv"]), 2)
        }
        expected_argv_bindings = {
            "--source-root": str(execution_root),
            "--public-output-root": str(output_root),
            "--python-executable": runtime["python_executable"],
            "--local-command-plan": str(Path(plan_path).resolve()),
            "--git-executable": str(Path(trusted_git_executable).resolve()),
            "--production-checkout": str(
                Path(private_production_checkout).resolve()
            ),
            "--release-checkout": str(Path(public_release_checkout).resolve()),
        }
        for flag, expected in expected_argv_bindings.items():
            if argv_values.get(flag) != expected:
                fail(f"command {index} {flag} does not bind the canonical run path")
        host_root = Path(argv_values["--host-artifact-root"])
        for flag, leaf in (
            ("--parent-hosts", "jj_g_hosts_parent_prelogg_padova.csv"),
            ("--canonical-hosts", "jj_g_hosts_raw_eligible_padova.csv"),
            ("--legacy-hosts", "jj_g_hosts_raw_eligible_padova_legacy_logg43.csv"),
        ):
            if Path(argv_values[flag]) != host_root / leaf:
                fail(f"command {index} {flag} differs from its host-root binding")
        mutable_roots = {
            "source": Path(argv_values["--source-root"]),
            "public": Path(argv_values["--public-output-root"]),
            "private work": Path(argv_values["--private-work-root"]),
            "private raw": Path(argv_values["--private-raw-root"]),
        }
        accepted_host_contract = Path(argv_values["--host-contract"])
        pending_host_contract = (
            execution_root / "provenance" / "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
        )
        if accepted_host_contract == pending_host_contract:
            fail("accepted host contract must be external to computational source A")
        for checkout_name, checkout in (
            ("private production checkout", private_production_checkout),
            ("public release checkout", public_release_checkout),
        ):
            if paths_overlap(accepted_host_contract, Path(checkout)):
                fail(f"accepted host contract must be outside the {checkout_name}")
        for root_name, root in mutable_roots.items():
            if paths_overlap(accepted_host_contract, root):
                fail(f"external host contract overlaps mutable {root_name} root")
        root_items = list(mutable_roots.items())
        for root_index, (left_name, left) in enumerate(root_items):
            for right_name, right in root_items[root_index + 1 :]:
                if paths_overlap(left, right):
                    fail(
                        f"command {index} mutable roots overlap: "
                        f"{left_name} and {right_name}"
                    )
        if command["argv"][2] == "recover-mcmc":
            if trusted_ssh_keygen_executable is None:
                fail("recovery plan validation requires a trusted ssh-keygen executable")
            trusted_ssh = str(Path(trusted_ssh_keygen_executable).resolve())
            if argv_values.get("--ssh-keygen-executable") != trusted_ssh:
                fail("recovery ssh-keygen does not bind the trusted attestation tool")
            donor_roots = {
                "donor work": Path(argv_values["--donor-work-shard-root"]),
                "donor raw": Path(argv_values["--donor-raw-root"]),
                "donor evidence": Path(argv_values["--donor-evidence-root"]),
            }
            protected_recovery_paths = {
                **donor_roots,
                "recovery contract": Path(argv_values["--recovery-contract"]),
                "donor attestation contract": Path(
                    argv_values["--donor-attestation-contract"]
                ),
                "donor command plan": Path(argv_values["--donor-command-plan"]),
                "donor numerical runtime manifest": Path(
                    argv_values["--donor-numerical-runtime-manifest"]
                ),
                "donor source archive": Path(argv_values["--donor-source-archive"]),
                "source transition evidence": Path(
                    argv_values["--source-transition-evidence"]
                ),
                "recovery qualification report": Path(
                    argv_values["--recovery-qualification-report"]
                ),
                "recovery ssh-keygen": Path(argv_values["--ssh-keygen-executable"]),
            }
            donor_items = list(donor_roots.items())
            for donor_index, (left_name, left) in enumerate(donor_items):
                for right_name, right in donor_items[donor_index + 1 :]:
                    if paths_overlap(left, right):
                        fail(
                            f"command {index} recovery roots overlap: "
                            f"{left_name} and {right_name}"
                        )
            for protected_name, protected in protected_recovery_paths.items():
                for root_name, root in mutable_roots.items():
                    if paths_overlap(protected, root):
                        fail(
                            f"recovery {protected_name} overlaps mutable "
                            f"{root_name} root"
                        )
        if require_extracted_programs:
            script = execution_root / Path(*PurePosixPath(command["argv"][1]).parts)
            script_snapshot = read_snapshot(script, f"command {index} tracked program")
            del script_snapshot
        current_executable, chain_hash = executable_chain(Path(command["argv"][0]))
        expected_executable = {
            "sha256": command["executable_sha256"],
            "size_bytes": command["executable_size_bytes"],
        }
        if snapshot_evidence(current_executable) != expected_executable:
            fail("runtime Python executable differs from command plan lock")
        if chain_hash != command["executable_chain_sha256"]:
            fail("runtime Python executable symlink chain differs from command plan lock")
        if executable_snapshot is None:
            executable_snapshot = current_executable
        elif snapshot_evidence(current_executable) != snapshot_evidence(executable_snapshot):
            fail("commands do not share one exact Python executable")
    if str(Path(runtime["python_executable"])) != plan["commands"][0]["argv"][0]:
        fail("runtime manifest and command plan Python paths differ")


def verify_signing_key(
    ssh_keygen: Path, key_path: Path, signer: Mapping[str, str], description: str
) -> None:
    key = Path(key_path)
    snapshot = read_snapshot(key, description, maximum_bytes=100_000)
    del snapshot
    result = run_checked(
        [str(ssh_keygen), "-y", "-f", str(key)],
        f"{description} public-key derivation",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"cannot derive public key from {description}")
    try:
        derived = result.stdout.decode("ascii", errors="strict").strip().split()
    except UnicodeDecodeError:
        fail(f"derived {description} public key is not ASCII")
    pinned = signer["public_key"].split()
    if derived[:2] != pinned[:2] or derived[0] != "ssh-ed25519":
        fail(f"{description} does not match the pinned Ed25519 signer")


def sign_document(
    ssh_keygen: Path,
    document: Path,
    key: Path,
    namespace: str,
    description: str,
) -> FileSnapshot:
    signature = document.with_name(document.name + ".sig")
    if signature.exists() or signature.is_symlink():
        fail(f"unexpected pre-existing {description} signature")
    result = run_checked(
        [str(ssh_keygen), "-Y", "sign", "-f", str(key), "-n", namespace, str(document)],
        f"{description} signing",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"OpenSSH could not sign {description}")
    return read_snapshot(
        signature, f"{description} signature", maximum_bytes=MAX_SIGNATURE_BYTES
    )


def verify_signature(
    ssh_keygen: Path,
    document: FileSnapshot,
    signature: FileSnapshot,
    signer: Mapping[str, str],
    namespace: str,
    description: str,
) -> None:
    if document.data is None:
        fail(f"internal error: {description} bytes were not collected")
    with tempfile.TemporaryDirectory(prefix="exoearth-allowed-signer-") as temporary:
        allowed = Path(temporary) / "allowed_signers"
        atomic_write_new(
            allowed,
            f"{signer['signer_id']} {signer['public_key']}\n".encode("ascii"),
            "temporary allowed-signers file",
        )
        result = run_checked(
            [
                str(ssh_keygen),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                signer["signer_id"],
                "-n",
                namespace,
                "-s",
                str(signature.path),
            ],
            f"{description} signature verification",
            input=document.data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        fail(f"{description} OpenSSH/Ed25519 signature is invalid")


def document_with_id(body: Mapping[str, Any], id_name: str) -> dict[str, Any]:
    identifier = sha256_bytes(canonical_json_bytes(body))
    result = dict(body)
    result[id_name] = identifier
    return result


def validate_self_id(value: Mapping[str, Any], id_name: str, description: str) -> None:
    identifier = require_hash(value[id_name], f"{description} {id_name}")
    body = dict(value)
    body.pop(id_name)
    if identifier != sha256_bytes(canonical_json_bytes(body)):
        fail(f"{description} self-identifier mismatch")


def create_start_challenge(
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    signer: Mapping[str, str],
    source: Mapping[str, Any],
    plan_snapshot: FileSnapshot,
    runtime_snapshot: FileSnapshot,
    source_manifest_value: Mapping[str, Any],
    execution_environment: str,
) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_id": candidate["id"],
        "run_id": secrets.token_hex(32),
        "nonce_hex": secrets.token_hex(32),
        "issued_utc": utc_now(),
        "start_signer_id": signer["signer_id"],
        "execution_environment": execution_environment,
        "source_state": dict(source),
        "source_file_set_sha256": source_manifest_value["file_set_sha256"],
        "source_file_count": source_manifest_value["file_count"],
        "command_plan": snapshot_evidence(plan_snapshot),
        "numerical_runtime_manifest": snapshot_evidence(runtime_snapshot),
    }
    return document_with_id(body, "challenge_id")


def expected_output_directories(paths: Iterable[str]) -> set[str]:
    directories = {"."}
    for name in paths:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return directories


def snapshot_exact_outputs(
    output_root: Path, expected_paths: Iterable[str]
) -> tuple[dict[str, Any], list[FileSnapshot]]:
    root = validate_plain_root(output_root, "production output root")
    names = list(expected_paths)
    actual_files, actual_directories = enumerate_plain_tree(root, "production output tree")
    if actual_files != set(names):
        fail("production output exact file set differs from the locked command plan")
    if actual_directories != expected_output_directories(names):
        fail("production output directory set contains an unexpected shadow directory")
    snapshots: list[FileSnapshot] = []
    entries: list[dict[str, Any]] = []
    for name in names:
        snapshot = read_snapshot(
            root / Path(*PurePosixPath(name).parts), f"production output {name}"
        )
        snapshots.append(snapshot)
        entries.append(
            {"path": name, "sha256": snapshot.sha256, "size_bytes": snapshot.size_bytes}
        )
    for snapshot in snapshots:
        recheck_snapshot(snapshot, "production output")
    final_files, final_directories = enumerate_plain_tree(root, "production output tree")
    if final_files != actual_files or final_directories != actual_directories:
        fail("production output file set changed during stable snapshots")
    manifest = {
        "schema_version": 1,
        "algorithm": "sha256",
        "files": entries,
    }
    return manifest, snapshots


def validate_output_manifest(
    value: Any, expected_paths: Iterable[str]
) -> list[dict[str, Any]]:
    manifest = exact_keys(
        value, {"schema_version", "algorithm", "files"}, "output manifest"
    )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["algorithm"] != "sha256":
        fail("output manifest schema/algorithm differs from the required values")
    files = manifest["files"]
    if not isinstance(files, list):
        fail("output manifest files must be a list")
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(files):
        item = exact_keys(raw, {"path", "sha256", "size_bytes"}, f"output entry {index}")
        safe_relative(item["path"], f"output entry {index} path")
        require_hash(item["sha256"], f"output entry {index} sha256")
        require_size(item["size_bytes"], f"output entry {index} size")
        entries.append(item)
    expected = list(expected_paths)
    if [item["path"] for item in entries] != expected:
        fail("output manifest file set/order differs from the locked command plan")
    return entries


def command_log_names(plan: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for index, command in enumerate(plan["commands"]):
        prefix = f"COMMAND_{index:03d}_{command['command_id']}"
        names.extend((f"{prefix}.stdout.bin", f"{prefix}.stderr.bin"))
    return names


def expected_evidence_files(plan: Mapping[str, Any]) -> set[str]:
    return {
        START_NAME,
        START_SIGNATURE_NAME,
        OUTPUT_MANIFEST_NAME,
        COMPLETION_NAME,
        COMPLETION_SIGNATURE_NAME,
        *command_log_names(plan),
    }


def validate_exact_evidence_tree(evidence_dir: Path, plan: Mapping[str, Any]) -> None:
    root = validate_plain_root(evidence_dir, "private run-evidence root")
    files, directories = enumerate_plain_tree(root, "private run-evidence tree")
    if files != expected_evidence_files(plan) or directories != {"."}:
        fail("private run-evidence tree contains missing or shadow files/directories")


def execute_commands(
    plan: Mapping[str, Any], execution_root: Path, evidence_dir: Path
) -> tuple[list[dict[str, Any]], bool]:
    results: list[dict[str, Any]] = []
    all_passed = True
    for index, command in enumerate(plan["commands"]):
        if not all_passed:
            break
        executable, chain_hash = executable_chain(Path(command["argv"][0]))
        if snapshot_evidence(executable) != {
            "sha256": command["executable_sha256"],
            "size_bytes": command["executable_size_bytes"],
        } or chain_hash != command["executable_chain_sha256"]:
            fail("runtime executable changed immediately before command launch")
        prefix = f"COMMAND_{index:03d}_{command['command_id']}"
        stdout_path = evidence_dir / f"{prefix}.stdout.bin"
        stderr_path = evidence_dir / f"{prefix}.stderr.bin"
        started = utc_now()
        stdout_handle = open(stdout_path, "xb")
        stderr_handle = open(stderr_path, "xb")
        try:
            try:
                completed = subprocess.run(
                    list(command["argv"]),
                    cwd=execution_root,
                    env=dict(command["env"]),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    check=False,
                )
                exit_code = int(completed.returncode)
            except (OSError, ValueError) as exc:
                stderr_handle.write(f"controller launch failure: {exc}\n".encode("utf-8"))
                exit_code = 255
        finally:
            stdout_handle.flush()
            stderr_handle.flush()
            os.fsync(stdout_handle.fileno())
            os.fsync(stderr_handle.fileno())
            stdout_handle.close()
            stderr_handle.close()
        ended = utc_now()
        executable_after, chain_after = executable_chain(Path(command["argv"][0]))
        if snapshot_evidence(executable_after) != snapshot_evidence(executable) or chain_after != chain_hash:
            fail("runtime executable changed during command execution")
        stdout_snapshot = read_snapshot(stdout_path, f"command {index} stdout")
        stderr_snapshot = read_snapshot(stderr_path, f"command {index} stderr")
        results.append(
            {
                "command_index": index,
                "command_id": command["command_id"],
                "exit_code": exit_code,
                "started_utc": started,
                "ended_utc": ended,
                "stdout": snapshot_evidence(stdout_snapshot),
                "stderr": snapshot_evidence(stderr_snapshot),
            }
        )
        all_passed = exit_code == 0
    return results, all_passed and len(results) == len(plan["commands"])


def completion_body(
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    challenge: Mapping[str, Any],
    start_snapshot: FileSnapshot,
    start_signature: FileSnapshot,
    completion_signer: Mapping[str, str],
    source_before: Mapping[str, Any],
    source_after: Mapping[str, Any],
    source_manifest_value: Mapping[str, Any],
    plan_snapshot: FileSnapshot,
    runtime_snapshot: FileSnapshot,
    output_manifest_snapshot: FileSnapshot,
    command_results: list[dict[str, Any]],
    started_utc: str,
    ended_utc: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "PASS",
        "contract_id": contract["contract_id"],
        "candidate_id": candidate["id"],
        "run_id": challenge["run_id"],
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce_hex": challenge["nonce_hex"],
        "completion_nonce_hex": secrets.token_hex(32),
        "start_signer_id": challenge["start_signer_id"],
        "completion_signer_id": completion_signer["signer_id"],
        "execution_environment": challenge["execution_environment"],
        "execution_started_utc": started_utc,
        "execution_ended_utc": ended_utc,
        "source_state_before": dict(source_before),
        "source_state_after": dict(source_after),
        "source_file_set_sha256": source_manifest_value["file_set_sha256"],
        "source_file_count": source_manifest_value["file_count"],
        "command_plan": snapshot_evidence(plan_snapshot),
        "numerical_runtime_manifest": snapshot_evidence(runtime_snapshot),
        "start_challenge": snapshot_evidence(start_snapshot),
        "start_challenge_signature": snapshot_evidence(start_signature),
        "output_manifest": snapshot_evidence(output_manifest_snapshot),
        "command_results": command_results,
    }


def validate_challenge(
    value: Any,
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    source: Mapping[str, Any],
    source_manifest_value: Mapping[str, Any],
    plan_snapshot: FileSnapshot,
    runtime_snapshot: FileSnapshot,
    execution_environment: str,
) -> dict[str, Any]:
    challenge = exact_keys(
        value,
        {
            "schema_version",
            "challenge_id",
            "contract_id",
            "candidate_id",
            "run_id",
            "nonce_hex",
            "issued_utc",
            "start_signer_id",
            "execution_environment",
            "source_state",
            "source_file_set_sha256",
            "source_file_count",
            "command_plan",
            "numerical_runtime_manifest",
        },
        "start challenge",
    )
    require_exact_integer(challenge["schema_version"], 1, "start challenge schema_version")
    validate_self_id(challenge, "challenge_id", "start challenge")
    if (
        challenge["contract_id"] != contract["contract_id"]
        or challenge["candidate_id"] != candidate["id"]
        or challenge["execution_environment"] != execution_environment
        or challenge["source_state"] != source
        or challenge["source_file_set_sha256"] != source_manifest_value["file_set_sha256"]
        or challenge["source_file_count"] != source_manifest_value["file_count"]
        or challenge["command_plan"] != snapshot_evidence(plan_snapshot)
        or challenge["numerical_runtime_manifest"] != snapshot_evidence(runtime_snapshot)
    ):
        fail("start challenge does not bind the current source, plan, and runtime")
    require_hash(challenge["run_id"], "start challenge run id")
    if not isinstance(challenge["nonce_hex"], str) or NONCE.fullmatch(challenge["nonce_hex"]) is None:
        fail("start challenge nonce must be 32 lowercase-hex bytes")
    parse_utc(challenge["issued_utc"], "start challenge issue time")
    signer_by_id(contract, challenge["start_signer_id"])
    return challenge


def validate_command_results(
    value: Any, plan: Mapping[str, Any], evidence_dir: Path
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(plan["commands"]):
        fail("completion does not contain one result for every planned command")
    results: list[dict[str, Any]] = []
    previous_end: datetime | None = None
    for index, raw in enumerate(value):
        item = exact_keys(
            raw,
            {
                "command_index",
                "command_id",
                "exit_code",
                "started_utc",
                "ended_utc",
                "stdout",
                "stderr",
            },
            f"command result {index}",
        )
        if (
            type(item["command_index"]) is not int
            or item["command_index"] != index
            or item["command_id"] != plan["commands"][index]["command_id"]
            or type(item["exit_code"]) is not int
            or item["exit_code"] != 0
        ):
            fail("command result identity or exit code is invalid")
        started = parse_utc(item["started_utc"], f"command {index} start")
        ended = parse_utc(item["ended_utc"], f"command {index} end")
        if ended < started or (previous_end is not None and started < previous_end):
            fail("command result timings are not ordered")
        previous_end = ended
        prefix = f"COMMAND_{index:03d}_{item['command_id']}"
        for stream in ("stdout", "stderr"):
            expected = validate_evidence(item[stream], f"command {index} {stream}")
            snapshot = read_snapshot(
                evidence_dir / f"{prefix}.{stream}.bin", f"command {index} {stream}"
            )
            if snapshot_evidence(snapshot) != expected:
                fail(f"command {index} {stream} bytes differ from completion")
        results.append(item)
    return results


def validate_completion(
    value: Any,
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    challenge: Mapping[str, Any],
    start_snapshot: FileSnapshot,
    start_signature: FileSnapshot,
    source: Mapping[str, Any],
    source_manifest_value: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_snapshot: FileSnapshot,
    runtime_snapshot: FileSnapshot,
    output_manifest_snapshot: FileSnapshot,
    evidence_dir: Path,
) -> dict[str, Any]:
    completion = exact_keys(
        value,
        {
            "schema_version",
            "completion_id",
            "status",
            "contract_id",
            "candidate_id",
            "run_id",
            "challenge_id",
            "challenge_nonce_hex",
            "completion_nonce_hex",
            "start_signer_id",
            "completion_signer_id",
            "execution_environment",
            "execution_started_utc",
            "execution_ended_utc",
            "source_state_before",
            "source_state_after",
            "source_file_set_sha256",
            "source_file_count",
            "command_plan",
            "numerical_runtime_manifest",
            "start_challenge",
            "start_challenge_signature",
            "output_manifest",
            "command_results",
        },
        "completion attestation",
    )
    if type(completion["schema_version"]) is not int or completion["schema_version"] != 1 or completion["status"] != "PASS":
        fail("completion attestation is not schema-1 PASS")
    validate_self_id(completion, "completion_id", "completion attestation")
    expected_scalars = {
        "contract_id": contract["contract_id"],
        "candidate_id": candidate["id"],
        "run_id": challenge["run_id"],
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce_hex": challenge["nonce_hex"],
        "start_signer_id": challenge["start_signer_id"],
        "execution_environment": challenge["execution_environment"],
        "source_state_before": source,
        "source_state_after": source,
        "source_file_set_sha256": source_manifest_value["file_set_sha256"],
        "source_file_count": source_manifest_value["file_count"],
        "command_plan": snapshot_evidence(plan_snapshot),
        "numerical_runtime_manifest": snapshot_evidence(runtime_snapshot),
        "start_challenge": snapshot_evidence(start_snapshot),
        "start_challenge_signature": snapshot_evidence(start_signature),
        "output_manifest": snapshot_evidence(output_manifest_snapshot),
    }
    for key, expected in expected_scalars.items():
        if completion[key] != expected:
            fail(f"completion attestation binding differs for {key}")
    completion_nonce = completion["completion_nonce_hex"]
    if not isinstance(completion_nonce, str) or NONCE.fullmatch(completion_nonce) is None:
        fail("completion nonce must be 32 lowercase-hex bytes")
    if completion_nonce == challenge["nonce_hex"]:
        fail("start and completion nonces must be distinct")
    if completion["completion_signer_id"] == completion["start_signer_id"]:
        fail("start and completion signers must be distinct")
    signer_by_id(contract, completion["completion_signer_id"])
    issued = parse_utc(challenge["issued_utc"], "challenge issue time")
    started = parse_utc(completion["execution_started_utc"], "execution start")
    ended = parse_utc(completion["execution_ended_utc"], "execution end")
    if not issued <= started <= ended:
        fail("challenge/execution timings are not ordered")
    results = validate_command_results(completion["command_results"], plan, evidence_dir)
    if results:
        if parse_utc(results[0]["started_utc"], "first command start") < started:
            fail("first command predates execution start")
        if parse_utc(results[-1]["ended_utc"], "last command end") > ended:
            fail("last command ends after execution completion")
    return completion


def build_public_report(
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    challenge: Mapping[str, Any],
    completion: Mapping[str, Any],
    start_snapshot: FileSnapshot,
    start_signature: FileSnapshot,
    completion_snapshot: FileSnapshot,
    completion_signature: FileSnapshot,
    output_manifest_snapshot: FileSnapshot,
    output_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    command_evidence = []
    for result in completion["command_results"]:
        command_evidence.append(
            {
                "command_index": result["command_index"],
                "exit_code": result["exit_code"],
                "started_utc": result["started_utc"],
                "ended_utc": result["ended_utc"],
                "stdout_sha256": result["stdout"]["sha256"],
                "stdout_size_bytes": result["stdout"]["size_bytes"],
                "stderr_sha256": result["stderr"]["sha256"],
                "stderr_size_bytes": result["stderr"]["size_bytes"],
            }
        )
    body = {
        "schema_version": 1,
        "qualification_status": "PASS",
        "contract_id": contract["contract_id"],
        "candidate_id": candidate["id"],
        "source_commit": completion["source_state_after"]["commit"],
        "source_tree": completion["source_state_after"]["tree"],
        "source_archive_sha256": completion["source_state_after"]["archive_sha256"],
        "source_archive_size_bytes": completion["source_state_after"][
            "archive_size_bytes"
        ],
        "source_file_set_sha256": completion["source_file_set_sha256"],
        "command_plan_sha256": completion["command_plan"]["sha256"],
        "numerical_runtime_manifest_sha256": completion[
            "numerical_runtime_manifest"
        ]["sha256"],
        "run_id_sha256": sha256_bytes(challenge["run_id"].encode("ascii")),
        "challenge_id": challenge["challenge_id"],
        "start_signer_id": challenge["start_signer_id"],
        "start_challenge_sha256": start_snapshot.sha256,
        "start_signature_sha256": start_signature.sha256,
        "completion_id": completion["completion_id"],
        "completion_signer_id": completion["completion_signer_id"],
        "completion_attestation_sha256": completion_snapshot.sha256,
        "completion_signature_sha256": completion_signature.sha256,
        "execution_started_utc": completion["execution_started_utc"],
        "execution_ended_utc": completion["execution_ended_utc"],
        "command_results": command_evidence,
        "output_manifest_sha256": output_manifest_snapshot.sha256,
        "output_file_count": len(output_entries),
        "output_total_size_bytes": sum(item["size_bytes"] for item in output_entries),
        "output_file_set_sha256": sha256_bytes(canonical_json_bytes(output_entries)),
    }
    return document_with_id(body, "report_id")


def validate_report_disclosure(report: Mapping[str, Any]) -> None:
    forbidden_fragments = ("path", "argv", "cwd", "env", "stdout_bytes", "stderr_bytes")

    def visit(value: Any, location: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = key.casefold()
                if any(fragment in lowered for fragment in forbidden_fragments):
                    fail(f"public report exposes a forbidden field at {location}.{key}")
                visit(item, f"{location}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{location}[{index}]")

    visit(report, "report")


def _load_and_lock_inputs(
    contract_path: Path,
    candidate_id: str,
    plan_path: Path,
    runtime_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    FileSnapshot,
    dict[str, Any],
    FileSnapshot,
    dict[str, Any],
    FileSnapshot,
]:
    contract, candidate, contract_snapshot = select_contract(contract_path, candidate_id)
    runtime_value, runtime_snapshot = load_json_snapshot(
        runtime_path, "numerical runtime manifest"
    )
    runtime = validate_numerical_runtime(runtime_value)
    plan_value, plan_snapshot = load_json_snapshot(plan_path, "command plan")
    plan = validate_plan(plan_value, runtime)
    if snapshot_evidence(plan_snapshot) != candidate["command_plan"]:
        fail("command plan bytes differ from the candidate lock")
    if snapshot_evidence(runtime_snapshot) != candidate["numerical_runtime_manifest"]:
        fail("numerical runtime manifest bytes differ from the candidate lock")
    return (
        contract,
        candidate,
        contract_snapshot,
        plan,
        plan_snapshot,
        runtime,
        runtime_snapshot,
    )


def execute_plan(
    *,
    contract_path: Path,
    candidate_id: str,
    public_source_repo: Path,
    source_repo: Path,
    plan_path: Path,
    runtime_path: Path,
    output_root: Path,
    evidence_dir: Path,
    execution_root: Path,
    start_signer_id: str,
    start_signing_key: Path,
    completion_signer_id: str,
    completion_signing_key: Path,
    execution_environment: str,
    git_executable: Path,
    ssh_keygen_executable: Path,
    report_path: Path,
) -> dict[str, Any]:
    (
        contract,
        candidate,
        contract_snapshot,
        plan,
        plan_snapshot,
        runtime,
        runtime_snapshot,
    ) = _load_and_lock_inputs(contract_path, candidate_id, plan_path, runtime_path)
    if execution_environment not in contract["policy"]["allowed_execution_environments"]:
        fail("execution environment is not permitted by the contract")
    start_signer = signer_by_id(contract, start_signer_id)
    completion_signer = signer_by_id(contract, completion_signer_id)
    if start_signer_id == completion_signer_id:
        fail("start and completion signer ids must be distinct")
    source_lock = candidate["source_lock"]
    validate_tool(git_executable, source_lock["git_executable"], "git executable")
    validate_tool(
        ssh_keygen_executable,
        source_lock["ssh_keygen_executable"],
        "ssh-keygen executable",
    )
    verify_signing_key(
        ssh_keygen_executable, start_signing_key, start_signer, "start signing key"
    )
    verify_signing_key(
        ssh_keygen_executable,
        completion_signing_key,
        completion_signer,
        "completion signing key",
    )
    public_source_before, public_archive = inspect_source(
        public_source_repo,
        git_executable,
        source_lock,
        repository_field="public_repository",
    )
    source_before, archive = inspect_source(
        source_repo,
        git_executable,
        source_lock,
        repository_field="private_repository",
    )
    if public_source_before != source_before or public_archive != archive:
        fail("public candidate and private production source archives are not exact matches")
    files, _directories = archive_members(archive)
    source_manifest_value = source_manifest(files)

    evidence = Path(evidence_dir).resolve(strict=False)
    output = Path(output_root).resolve(strict=False)
    execution = Path(execution_root).resolve(strict=False)
    validate_root_separation(
        public_source_repo,
        source_repo,
        evidence,
        output,
        execution,
        report_path,
    )
    evidence = ensure_new_empty_directory(evidence, "private run-evidence root")
    if output.exists() or output.is_symlink() or execution.exists() or execution.is_symlink():
        fail("output and execution roots must not pre-exist")

    validate_plan_bindings(
        plan,
        runtime,
        execution,
        output,
        runtime_path,
        plan_path,
        git_executable,
        source_repo,
        public_source_repo,
        require_extracted_programs=False,
        trusted_ssh_keygen_executable=ssh_keygen_executable,
    )
    challenge = create_start_challenge(
        contract,
        candidate,
        start_signer,
        source_before,
        plan_snapshot,
        runtime_snapshot,
        source_manifest_value,
        execution_environment,
    )
    start_path = evidence / START_NAME
    atomic_write_new(start_path, canonical_json_bytes(challenge), "start challenge")
    start_snapshot = read_snapshot(
        start_path, "start challenge", collect=True, maximum_bytes=MAX_JSON_BYTES
    )
    start_signature = sign_document(
        ssh_keygen_executable,
        start_path,
        start_signing_key,
        START_NAMESPACE,
        "start challenge",
    )
    verify_signature(
        ssh_keygen_executable,
        start_snapshot,
        start_signature,
        start_signer,
        START_NAMESPACE,
        "start challenge",
    )

    execution_started = utc_now()
    extracted_manifest = extract_archive_exact(archive, execution)
    if extracted_manifest != source_manifest_value:
        fail("extracted execution source manifest differs from the signed challenge")
    validate_plan_bindings(
        plan,
        runtime,
        execution,
        output,
        runtime_path,
        plan_path,
        git_executable,
        source_repo,
        public_source_repo,
        require_extracted_programs=True,
        trusted_ssh_keygen_executable=ssh_keygen_executable,
    )
    ensure_new_empty_directory(output, "production output root")
    command_results, commands_passed = execute_commands(plan, execution, evidence)
    execution_ended = utc_now()
    if not commands_passed:
        fail("one or more exact production commands failed; completion is not signed")
    verify_exact_tree(execution, files, archive_members(archive)[1], "archive execution tree")
    public_source_after, public_archive_after = inspect_source(
        public_source_repo,
        git_executable,
        source_lock,
        repository_field="public_repository",
    )
    source_after, archive_after = inspect_source(
        source_repo,
        git_executable,
        source_lock,
        repository_field="private_repository",
    )
    if source_after != source_before or archive_after != archive:
        fail("private source state changed during execution")
    if public_source_after != public_source_before or public_archive_after != public_archive:
        fail("public source state changed during execution")

    output_manifest, output_snapshots = snapshot_exact_outputs(
        output, plan["expected_output_files"]
    )
    output_manifest_path = evidence / OUTPUT_MANIFEST_NAME
    atomic_write_new(
        output_manifest_path,
        canonical_json_bytes(output_manifest),
        "strict output manifest",
    )
    output_manifest_snapshot = read_snapshot(
        output_manifest_path,
        "strict output manifest",
        collect=True,
        maximum_bytes=MAX_JSON_BYTES,
    )
    completion = document_with_id(
        completion_body(
            contract,
            candidate,
            challenge,
            start_snapshot,
            start_signature,
            completion_signer,
            source_before,
            source_after,
            source_manifest_value,
            plan_snapshot,
            runtime_snapshot,
            output_manifest_snapshot,
            command_results,
            execution_started,
            execution_ended,
        ),
        "completion_id",
    )
    completion_path = evidence / COMPLETION_NAME
    atomic_write_new(
        completion_path,
        canonical_json_bytes(completion),
        "completion attestation",
    )
    completion_snapshot = read_snapshot(
        completion_path,
        "completion attestation",
        collect=True,
        maximum_bytes=MAX_JSON_BYTES,
    )
    completion_signature = sign_document(
        ssh_keygen_executable,
        completion_path,
        completion_signing_key,
        COMPLETION_NAMESPACE,
        "completion attestation",
    )
    verify_signature(
        ssh_keygen_executable,
        completion_snapshot,
        completion_signature,
        completion_signer,
        COMPLETION_NAMESPACE,
        "completion attestation",
    )
    for snapshot in output_snapshots:
        recheck_snapshot(snapshot, "production output")
    recheck_snapshot(contract_snapshot, "local-run contract")
    recheck_snapshot(plan_snapshot, "command plan")
    recheck_snapshot(runtime_snapshot, "numerical runtime manifest")
    return verify_run(
        contract_path=contract_path,
        candidate_id=candidate_id,
        public_source_repo=public_source_repo,
        source_repo=source_repo,
        plan_path=plan_path,
        runtime_path=runtime_path,
        output_root=output,
        evidence_dir=evidence,
        execution_root=execution,
        execution_environment=execution_environment,
        git_executable=git_executable,
        ssh_keygen_executable=ssh_keygen_executable,
        report_path=report_path,
        qualification_mode=True,
    )


def verify_run(
    *,
    contract_path: Path,
    candidate_id: str,
    public_source_repo: Path,
    source_repo: Path,
    plan_path: Path,
    runtime_path: Path,
    output_root: Path,
    evidence_dir: Path,
    execution_root: Path,
    execution_environment: str,
    git_executable: Path,
    ssh_keygen_executable: Path,
    report_path: Path | None,
    qualification_mode: bool,
) -> dict[str, Any]:
    (
        contract,
        candidate,
        contract_snapshot,
        plan,
        plan_snapshot,
        runtime,
        runtime_snapshot,
    ) = _load_and_lock_inputs(contract_path, candidate_id, plan_path, runtime_path)
    if execution_environment not in contract["policy"]["allowed_execution_environments"]:
        fail("execution environment is not permitted by the contract")
    source_lock = candidate["source_lock"]
    validate_tool(git_executable, source_lock["git_executable"], "git executable")
    validate_tool(
        ssh_keygen_executable,
        source_lock["ssh_keygen_executable"],
        "ssh-keygen executable",
    )
    public_source, public_archive = inspect_source(
        public_source_repo,
        git_executable,
        source_lock,
        repository_field="public_repository",
    )
    source, archive = inspect_source(
        source_repo,
        git_executable,
        source_lock,
        repository_field="private_repository",
    )
    if public_source != source or public_archive != archive:
        fail("public candidate and private production source archives are not exact matches")
    files, directories = archive_members(archive)
    source_manifest_value = source_manifest(files)
    execution = validate_plain_root(execution_root, "archive execution root")
    output = validate_plain_root(output_root, "production output root")
    evidence = validate_plain_root(evidence_dir, "private run-evidence root")
    validate_root_separation(
        public_source_repo,
        source_repo,
        evidence,
        output,
        execution,
        report_path,
    )
    validate_plan_bindings(
        plan,
        runtime,
        execution,
        output,
        runtime_path,
        plan_path,
        git_executable,
        source_repo,
        public_source_repo,
        require_extracted_programs=True,
        trusted_ssh_keygen_executable=ssh_keygen_executable,
    )
    verify_exact_tree(execution, files, directories, "archive execution tree")
    validate_exact_evidence_tree(evidence, plan)

    challenge_value, start_snapshot = load_json_snapshot(
        evidence / START_NAME, "start challenge"
    )
    challenge = validate_challenge(
        challenge_value,
        contract,
        candidate,
        source,
        source_manifest_value,
        plan_snapshot,
        runtime_snapshot,
        execution_environment,
    )
    start_signature = read_snapshot(
        evidence / START_SIGNATURE_NAME,
        "start challenge signature",
        maximum_bytes=MAX_SIGNATURE_BYTES,
    )
    start_signer = signer_by_id(contract, challenge["start_signer_id"])
    verify_signature(
        ssh_keygen_executable,
        start_snapshot,
        start_signature,
        start_signer,
        START_NAMESPACE,
        "start challenge",
    )

    output_manifest_value, output_manifest_snapshot = load_json_snapshot(
        evidence / OUTPUT_MANIFEST_NAME, "strict output manifest"
    )
    output_entries = validate_output_manifest(
        output_manifest_value, plan["expected_output_files"]
    )
    current_manifest, output_snapshots = snapshot_exact_outputs(
        output, plan["expected_output_files"]
    )
    if current_manifest != output_manifest_value:
        fail("production output bytes differ from the strict signed manifest")

    completion_value, completion_snapshot = load_json_snapshot(
        evidence / COMPLETION_NAME, "completion attestation"
    )
    completion = validate_completion(
        completion_value,
        contract,
        candidate,
        challenge,
        start_snapshot,
        start_signature,
        source,
        source_manifest_value,
        plan,
        plan_snapshot,
        runtime_snapshot,
        output_manifest_snapshot,
        evidence,
    )
    completion_signature = read_snapshot(
        evidence / COMPLETION_SIGNATURE_NAME,
        "completion attestation signature",
        maximum_bytes=MAX_SIGNATURE_BYTES,
    )
    completion_signer = signer_by_id(contract, completion["completion_signer_id"])
    verify_signature(
        ssh_keygen_executable,
        completion_snapshot,
        completion_signature,
        completion_signer,
        COMPLETION_NAMESPACE,
        "completion attestation",
    )
    for snapshot in output_snapshots:
        recheck_snapshot(snapshot, "production output")
    validate_exact_evidence_tree(evidence, plan)
    verify_exact_tree(execution, files, directories, "archive execution tree")
    final_public_source, final_public_archive = inspect_source(
        public_source_repo,
        git_executable,
        source_lock,
        repository_field="public_repository",
    )
    final_private_source, final_private_archive = inspect_source(
        source_repo,
        git_executable,
        source_lock,
        repository_field="private_repository",
    )
    if (
        final_public_source != public_source
        or final_private_source != source
        or final_public_archive != public_archive
        or final_private_archive != archive
    ):
        fail("public/private source state changed during run verification")
    for snapshot, description in (
        (contract_snapshot, "local-run contract"),
        (plan_snapshot, "command plan"),
        (runtime_snapshot, "numerical runtime manifest"),
        (start_snapshot, "start challenge"),
        (start_signature, "start challenge signature"),
        (output_manifest_snapshot, "strict output manifest"),
        (completion_snapshot, "completion attestation"),
        (completion_signature, "completion attestation signature"),
    ):
        recheck_snapshot(snapshot, description)
    report = build_public_report(
        contract,
        candidate,
        challenge,
        completion,
        start_snapshot,
        start_signature,
        completion_snapshot,
        completion_signature,
        output_manifest_snapshot,
        output_entries,
    )
    validate_report_disclosure(report)
    report_bytes = canonical_json_bytes(report)
    report_evidence = {
        "report_id": report["report_id"],
        "sha256": sha256_bytes(report_bytes),
        "size_bytes": len(report_bytes),
    }
    if candidate["production_accepted"]:
        if report_evidence != candidate["accepted_report"]:
            fail("current public report differs from the production-accepted report lock")
    elif not qualification_mode:
        fail("qualification passed but production gate remains closed in the contract")
    if report_path is not None:
        atomic_write_new(Path(report_path), report_bytes, "public local-run report")
    return report


def verify_existing_public_report(
    expected_report: Mapping[str, Any], report_path: Path
) -> FileSnapshot:
    """Verify an existing public report without overwriting or rebasing it."""

    value, snapshot = load_json_snapshot(report_path, "existing public local-run report")
    validate_report_disclosure(value)
    canonical = canonical_json_bytes(value)
    if snapshot.data != canonical:
        fail("existing public local-run report is not canonical JSON bytes")
    if value != expected_report:
        fail("existing public local-run report differs from reverified evidence")
    recheck_snapshot(snapshot, "existing public local-run report")
    return snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--contract", type=Path, required=True)
        command.add_argument("--candidate", required=True)
        command.add_argument("--public-source-repo", type=Path, required=True)
        command.add_argument("--source-repo", type=Path, required=True)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--runtime-manifest", type=Path, required=True)
        command.add_argument("--output-root", type=Path, required=True)
        command.add_argument("--evidence-dir", type=Path, required=True)
        command.add_argument("--execution-root", type=Path, required=True)
        command.add_argument("--execution-environment", required=True)
        command.add_argument("--git-executable", type=Path, required=True)
        command.add_argument("--ssh-keygen-executable", type=Path, required=True)

    execute = subparsers.add_parser("execute", help="challenge, execute, attest, verify")
    common(execute)
    execute.add_argument("--report", type=Path, required=True)
    execute.add_argument("--start-signer-id", required=True)
    execute.add_argument("--start-signing-key", type=Path, required=True)
    execute.add_argument("--completion-signer-id", required=True)
    execute.add_argument("--completion-signing-key", type=Path, required=True)
    execute.add_argument(
        "--confirm-execution",
        choices=("execute-exact-locked-local-production-plan",),
        required=True,
    )

    verify = subparsers.add_parser("verify", help="revalidate all private evidence")
    common(verify)
    verify.add_argument("--accepted-report", type=Path, required=True)
    verify.add_argument(
        "--report",
        type=Path,
        help="optional new copy of the independently regenerated report",
    )
    verify.add_argument(
        "--qualification-mode",
        action="store_true",
        help="permit a PASS report while production_accepted is still false",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "execute":
            report = execute_plan(
                contract_path=args.contract,
                candidate_id=args.candidate,
                public_source_repo=args.public_source_repo,
                source_repo=args.source_repo,
                plan_path=args.plan,
                runtime_path=args.runtime_manifest,
                output_root=args.output_root,
                evidence_dir=args.evidence_dir,
                execution_root=args.execution_root,
                start_signer_id=args.start_signer_id,
                start_signing_key=args.start_signing_key,
                completion_signer_id=args.completion_signer_id,
                completion_signing_key=args.completion_signing_key,
                execution_environment=args.execution_environment,
                git_executable=args.git_executable,
                ssh_keygen_executable=args.ssh_keygen_executable,
                report_path=args.report,
            )
            print(f"QUALIFICATION PASS {report['report_id']}")
            print("PRODUCTION BLOCKED until the report is reviewed and hash-locked")
            return 0
        report = verify_run(
            contract_path=args.contract,
            candidate_id=args.candidate,
            public_source_repo=args.public_source_repo,
            source_repo=args.source_repo,
            plan_path=args.plan,
            runtime_path=args.runtime_manifest,
            output_root=args.output_root,
            evidence_dir=args.evidence_dir,
            execution_root=args.execution_root,
            execution_environment=args.execution_environment,
            git_executable=args.git_executable,
            ssh_keygen_executable=args.ssh_keygen_executable,
            report_path=args.report,
            qualification_mode=args.qualification_mode,
        )
        verify_existing_public_report(report, args.accepted_report)
        print(f"LOCAL RUN PASS {report['report_id']}")
        return 0
    except AttestationError as exc:
        print(f"LOCAL RUN FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
