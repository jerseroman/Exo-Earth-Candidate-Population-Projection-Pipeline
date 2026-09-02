#!/usr/bin/env python3
"""Build, qualify, and verify the v4.0.4 pre-age-cut JJ SSP contract.

The contract is the trust root missing from an ordinary checksum manifest.  A
production-accepted member tuple must be reproduced bit for bit by two distinct
runs, recorded in a self-identifying qualification report, and then explicitly
locked in the repository contract.  Until that review step occurs, verification
fails even when an artifact's self-generated checksums are internally valid.
"""

from __future__ import annotations

# A direct CLI invocation must shed the script directory, user site, and all
# bytecode import paths before even json/argparse are imported.  Preserve the
# caller's optimisation level because the acceptance suite exercises both
# normal and ``-O`` execution.
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
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable
import uuid
import zipfile


JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
PADOVA_SHA256 = "97c8e09ea2669abe4147333f0fa141642e2c56d97b6f44de4e4518974ab7c7e8"
PADOVA_SIZE_BYTES = 327078533
PADOVA_FILENAME = "multiband_padova.zip"
PADOVA_LOCK_ID = "jj_padova_multiband_archive"

SSP_MANIFEST_NAME = "JJ_SSP_INPUT_SHA256SUMS.txt"
REPETITION_MANIFEST_NAME = "SHA256SUMS_age_cut_ssp_repetition.txt"
PARAMETERS_NAME = "parameters"
SFR_NAME = "sfrd_peaks_parameters"
RUNTIME_NAME = "NUMERICAL_RUNTIME_POLICY.json"
PROVENANCE_NAME = "AGE_CUT_RUN_PROVENANCE.json"
START_CHALLENGE_NAME = "RUN_START_CHALLENGE.json"
START_CHALLENGE_SIGNATURE_NAME = "RUN_START_CHALLENGE.sig"
EXECUTION_RECORD_NAME = "RUN_EXECUTION_RECORD.json"
ATTESTATION_NAME = "RUN_ATTESTATION.json"
ATTESTATION_SIGNATURE_NAME = "RUN_ATTESTATION.sig"
ATTESTATION_NAMESPACE = "exoearth-age-cut-ssp-v4.0.4"
START_CHALLENGE_NAMESPACE = ATTESTATION_NAMESPACE + ".start"
SSP_MEMBERS = tuple(
    f"SSP_R{4.0 + 0.5 * index:.1f}_{component}_Padova.csv"
    for index in range(21)
    for component in ("d", "t")
)
REPETITION_MANIFEST_MEMBERS = (
    PARAMETERS_NAME,
    SFR_NAME,
    RUNTIME_NAME,
    PROVENANCE_NAME,
    START_CHALLENGE_NAME,
    START_CHALLENGE_SIGNATURE_NAME,
    EXECUTION_RECORD_NAME,
    SSP_MANIFEST_NAME,
    *SSP_MEMBERS,
)
REPETITION_FILES = {
    *REPETITION_MANIFEST_MEMBERS,
    REPETITION_MANIFEST_NAME,
    ATTESTATION_NAME,
    ATTESTATION_SIGNATURE_NAME,
}

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
MAX_CONTRACT_BYTES = 1_000_000
MAX_REPORT_BYTES = 5_000_000
MAX_MANIFEST_BYTES = 20_000
MAX_PROVENANCE_BYTES = 1_000_000
MAX_RUNTIME_BYTES = 1_000_000
MAX_EXECUTION_RECORD_BYTES = 1_000_000
GENERATION_PROGRAM = "research/jj-host-export/run_jj_export.py"
ALLOWED_ENVIRONMENTS = (
    "local_ubuntu_22_04_wsl2",
    "github_actions_ubuntu_22_04",
)
EXPECTED_NUMERICAL_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,"
        "AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
EXPECTED_CPU_FEATURES = {
    "AVX2": True,
    "FMA3": True,
    "AVX512F": False,
    "AVX512CD": False,
    "AVX512_KNL": False,
    "AVX512_KNM": False,
    "AVX512_SKX": False,
    "AVX512_CLX": False,
    "AVX512_CNL": False,
    "AVX512_ICL": False,
}


class SSPContractError(RuntimeError):
    """Raised when SSP qualification or verification fails closed."""


def fail(message: str) -> None:
    raise SSPContractError(message)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class ExtractedArchiveTree:
    files: dict[str, tuple[str, int]]
    directories: frozenset[str]


def read_snapshot(
    path: Path, description: str, *, maximum_bytes: int | None = None
) -> FileSnapshot:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{description} must be a regular, non-symlink file: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened_before = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_before.st_mode):
                fail(f"{description} opened object is not a regular file")
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
    except OSError as exc:
        fail(f"cannot read {description}: {exc}")
    try:
        after = candidate.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1 or len(data) != opened_after.st_size:
        fail(f"{description} changed while it was read: {candidate}")
    if maximum_bytes is not None and len(data) > maximum_bytes:
        fail(f"{description} exceeds {maximum_bytes} bytes")
    return FileSnapshot(
        path=candidate.resolve(),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def recheck_snapshot(snapshot: FileSnapshot, description: str) -> None:
    """Prove that a path still exposes the exact bytes captured earlier."""

    current = read_snapshot(snapshot.path, description)
    if (
        current.data != snapshot.data
        or current.sha256 != snapshot.sha256
        or current.size_bytes != snapshot.size_bytes
    ):
        fail(f"{description} changed after its stable snapshot")


def _has_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _safe_archive_relative(name: str, description: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        fail(f"{description} has an unsafe member path")
    relative = PurePosixPath(name.rstrip("/"))
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        fail(f"{description} contains path traversal or an empty member")
    return relative.as_posix()


def _archive_parent_directories(relative: str) -> set[str]:
    parts = PurePosixPath(relative).parts
    return {
        PurePosixPath(*parts[:index]).as_posix()
        for index in range(1, len(parts))
    }


def _plain_tree_inventory(
    root: Path, description: str, *, allow_git_metadata: bool
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for current_text, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        current = Path(current_text)
        relative_current = current.relative_to(root)
        retained_directories: list[str] = []
        for name in directory_names:
            child = current / name
            try:
                metadata = child.lstat()
            except OSError as exc:
                fail(f"cannot inspect {description} directory {child}: {exc}")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or _has_reparse_point(metadata)
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                fail(f"{description} contains a linked or non-directory object")
            relative = (relative_current / name).as_posix()
            if allow_git_metadata and relative == ".git":
                continue
            directories.add(relative)
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in file_names:
            child = current / name
            try:
                metadata = child.lstat()
            except OSError as exc:
                fail(f"cannot inspect {description} file {child}: {exc}")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or _has_reparse_point(metadata)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                fail(f"{description} contains a linked or non-regular file")
            files.add((relative_current / name).as_posix())
    return files, directories


def extract_git_archive_snapshot(
    archive: FileSnapshot,
    destination: Path,
    description: str,
    *,
    allow_existing_git_metadata: bool = False,
) -> ExtractedArchiveTree:
    """Safely materialise only regular source bytes from a captured Git TAR."""

    root = Path(destination)
    if allow_existing_git_metadata:
        if root.is_symlink() or not root.is_dir():
            fail(f"{description} destination must be a plain existing directory")
        existing_files, existing_directories = _plain_tree_inventory(
            root, description, allow_git_metadata=True
        )
        if existing_files or existing_directories:
            fail(f"{description} destination contains source bytes before extraction")
    else:
        if root.exists() or root.is_symlink():
            fail(f"fresh {description} destination already exists")
        root.mkdir()

    file_records: dict[str, tuple[str, int]] = {}
    directories: set[str] = set()
    casefolded: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive.data), mode="r:") as bundle:
            for member in bundle.getmembers():
                relative = _safe_archive_relative(member.name, description)
                folded = relative.casefold()
                if folded in casefolded:
                    fail(f"{description} contains duplicate or case-colliding paths")
                casefolded.add(folded)
                if member.isdir():
                    directories.add(relative)
                    directories.update(_archive_parent_directories(relative))
                    root.joinpath(*PurePosixPath(relative).parts).mkdir(
                        parents=True, exist_ok=True
                    )
                    continue
                if not member.isreg():
                    fail(f"{description} contains a link or special member")
                extracted = bundle.extractfile(member)
                if extracted is None:
                    fail(f"cannot read regular {description} member {relative}")
                data = extracted.read()
                if len(data) != member.size:
                    fail(f"short read for {description} member {relative}")
                target = root.joinpath(*PurePosixPath(relative).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                write_bytes_exclusive(target, data)
                file_records[relative] = (hashlib.sha256(data).hexdigest(), len(data))
                directories.update(_archive_parent_directories(relative))
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot safely extract {description}: {exc}")
    if not file_records:
        fail(f"{description} contains no regular source files")
    tree = ExtractedArchiveTree(file_records, frozenset(directories))
    verify_extracted_archive_tree(
        root,
        tree,
        description,
        allow_git_metadata=allow_existing_git_metadata,
    )
    return tree


def verify_extracted_archive_tree(
    root: Path,
    expected: ExtractedArchiveTree,
    description: str,
    *,
    allow_git_metadata: bool = False,
    allowed_overlay_files: set[str] | None = None,
    allowed_overlay_directories: set[str] | None = None,
) -> None:
    overlay = set() if allowed_overlay_files is None else set(allowed_overlay_files)
    overlay_directories = (
        set()
        if allowed_overlay_directories is None
        else set(allowed_overlay_directories)
    )
    for relative in overlay:
        _safe_archive_relative(relative, f"{description} overlay")
        overlay_directories.update(_archive_parent_directories(relative))
    observed_files, observed_directories = _plain_tree_inventory(
        root, description, allow_git_metadata=allow_git_metadata
    )
    if observed_files != set(expected.files) | overlay:
        fail(f"{description} exact source file inventory changed")
    if observed_directories != set(expected.directories) | overlay_directories:
        fail(f"{description} exact source directory inventory changed")
    for relative, (digest, size_bytes) in expected.files.items():
        snapshot = read_snapshot(
            root.joinpath(*PurePosixPath(relative).parts),
            f"{description} member {relative}",
        )
        if snapshot.sha256 != digest or snapshot.size_bytes != size_bytes:
            fail(f"{description} member bytes changed: {relative}")


def extract_padova_overlay_snapshot(
    padova_archive: FileSnapshot, jj_root: Path
) -> tuple[set[str], dict[str, Any], set[str]]:
    destination_relative = PurePosixPath("jjmodel/input/isochrones/Padova")
    destination = Path(jj_root).joinpath(*destination_relative.parts)
    if destination.exists() or destination.is_symlink():
        fail("fresh JJ source already contains a Padova overlay")
    destination.mkdir(parents=True)
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(padova_archive.data)) as archive:
            for info in archive.infolist():
                relative = _safe_archive_relative(info.filename, "Padova archive")
                folded = relative.casefold()
                if folded in seen:
                    fail("Padova archive contains duplicate or case-colliding paths")
                seen.add(folded)
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    fail("Padova archive contains a symbolic-link member")
                target = destination.joinpath(*PurePosixPath(relative).parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as handle:
                    data = handle.read()
                if len(data) != info.file_size:
                    fail(f"short read for Padova archive member {relative}")
                write_bytes_exclusive(target, data)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        fail(f"cannot safely materialise locked Padova overlay: {exc}")
    files, record = exact_padova_extraction(jj_root, padova_archive)
    _, relative_directories = _plain_tree_inventory(
        destination, "fresh Padova overlay", allow_git_metadata=False
    )
    overlay_directories = {
        destination_relative.as_posix(),
        *_archive_parent_directories(destination_relative.as_posix()),
        *{
            (destination_relative / PurePosixPath(relative)).as_posix()
            for relative in relative_directories
        },
    }
    return files, record, overlay_directories


def require_directory(path: Path, description: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_dir():
        fail(f"{description} must be an existing non-symlink directory: {candidate}")
    return candidate.resolve()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_constant(token: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {token}")


def finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def load_json_bytes(data: bytes, description: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse strict UTF-8 JSON {description}: {exc}")


def exact_keys(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    observed = set(value)
    if observed != expected:
        fail(
            f"{description} keys differ: missing={sorted(expected - observed)!r}, "
            f"extra={sorted(observed - expected)!r}"
        )
    return value


def require_sha(value: Any, length: int, description: str) -> str:
    pattern = HEX40 if length == 40 else HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{description} must be lowercase {length}-hex")
    return value


def require_safe_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        fail(f"{description} is not a safe identifier")
    return value


def require_positive_int(value: Any, description: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{description} must be a positive JSON integer")
    return value


def require_nonnegative_int(value: Any, description: str) -> int:
    if type(value) is not int or value < 0:
        fail(f"{description} must be a nonnegative JSON integer")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_base64(value: Any, description: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or len(value) > (4 * maximum_bytes // 3 + 8):
        fail(f"{description} base64 value is missing or too large")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        fail(f"cannot decode strict base64 {description}: {exc}")
    if len(decoded) > maximum_bytes or encode_base64(decoded) != value:
        fail(f"{description} is oversized or non-canonical base64")
    return decoded


def synthetic_snapshot(
    name: str, data: bytes, *, sha256_value: str | None = None, size_bytes: int | None = None
) -> FileSnapshot:
    digest = hashlib.sha256(data).hexdigest() if sha256_value is None else sha256_value
    size = len(data) if size_bytes is None else size_bytes
    return FileSnapshot(Path(name), data, digest, size)


def evidence(snapshot: FileSnapshot) -> dict[str, Any]:
    return {
        "filename": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
    }


def validate_evidence(
    value: Any, expected_name: str, description: str
) -> dict[str, Any]:
    item = exact_keys(value, {"filename", "sha256", "size_bytes"}, description)
    if item["filename"] != expected_name:
        fail(f"{description} filename mismatch")
    require_sha(item["sha256"], 64, f"{description} SHA-256")
    require_positive_int(item["size_bytes"], f"{description} size")
    return item


def parse_manifest(
    data: bytes, expected_names: tuple[str, ...], description: str
) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    if len(lines) != len(expected_names):
        fail(f"{description} entry count differs")
    result: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            fail(f"malformed or unsafe {description} line: {line!r}")
        digest, name = match.groups()
        if name in result:
            fail(f"duplicate {description} member: {name}")
        result[name] = digest
        order.append(name)
    if tuple(order) != expected_names:
        fail(f"{description} member order/set changed")
    return result


def validate_runtime_manifest(document: Any) -> dict[str, Any]:
    runtime = exact_keys(
        document,
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
        "numerical-runtime manifest",
    )
    if type(runtime["schema_version"]) is not int or runtime["schema_version"] != 1:
        fail("numerical-runtime manifest schema_version must be integer 1")
    if runtime["status"] != "PASS" or runtime["numpy_version"] != "1.23.5":
        fail("numerical-runtime manifest is not the pinned NumPy-1.23.5 PASS")
    for key in ("python", "python_executable", "platform", "machine"):
        if not isinstance(runtime[key], str) or not runtime[key]:
            fail(f"numerical-runtime field {key} is empty or invalid")
    for key in ("numpy_cpu_baseline", "numpy_cpu_dispatch_build"):
        if not isinstance(runtime[key], list) or not all(
            isinstance(item, str) and item for item in runtime[key]
        ):
            fail(f"numerical-runtime field {key} is invalid")
    if runtime["environment"] != EXPECTED_NUMERICAL_ENV:
        fail("numerical-runtime environment differs from the release policy")
    if runtime["selected_cpu_features"] != EXPECTED_CPU_FEATURES:
        fail("numerical-runtime CPU-feature policy differs")
    return runtime


def validate_contract(document: Any) -> dict[str, Any]:
    contract = exact_keys(
        document,
        {
            "schema_version",
            "contract_id",
            "ssp_manifest_name",
            "repetition_manifest_name",
            "runtime_parameters_name",
            "sfr_peaks_parameters_name",
            "numerical_runtime_manifest_name",
            "provenance_name",
            "ssp_members",
            "locked_inputs",
            "qualification_policy",
            "artifact_sets",
        },
        "age-cut SSP contract",
    )
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        fail("unsupported SSP contract schema")
    if contract["contract_id"] != "jj-padova-pre-age-ssp-v4.0.4":
        fail("unexpected SSP contract id")
    expected_names = {
        "ssp_manifest_name": SSP_MANIFEST_NAME,
        "repetition_manifest_name": REPETITION_MANIFEST_NAME,
        "runtime_parameters_name": PARAMETERS_NAME,
        "sfr_peaks_parameters_name": SFR_NAME,
        "numerical_runtime_manifest_name": RUNTIME_NAME,
        "provenance_name": PROVENANCE_NAME,
    }
    for key, expected in expected_names.items():
        if contract[key] != expected:
            fail(f"SSP contract {key} changed")
    if contract["ssp_members"] != list(SSP_MEMBERS):
        fail("SSP contract member order/set changed")
    locked = exact_keys(
        contract["locked_inputs"],
        {
            "jj_repository",
            "jj_commit",
            "jj_version_expected",
            "isochrone_label",
            "isochrone_family",
            "padova_archive",
        },
        "SSP contract locked inputs",
    )
    if locked != {
        "jj_repository": "askenja/jjmodel",
        "jj_commit": JJ_SHA,
        "jj_version_expected": "1.0.1",
        "isochrone_label": "Padova",
        "isochrone_family": "Padova/PARSEC",
        "padova_archive": {
            "data_lock_id": PADOVA_LOCK_ID,
            "filename": PADOVA_FILENAME,
            "sha256": PADOVA_SHA256,
            "size_bytes": PADOVA_SIZE_BYTES,
        },
    }:
        fail("SSP contract locked inputs differ from the release locks")
    policy = exact_keys(
        contract["qualification_policy"],
        {
            "required_distinct_fresh_repetitions",
            "attestation_namespace",
            "required_distinct_signers",
            "nonce_bytes",
            "fresh_execution_controller",
            "generation_program",
            "generation_argv_mode",
            "require_signed_pre_run_challenge",
            "require_controller_created_empty_run_directory",
            "require_exact_padova_extraction_from_locked_archive",
            "require_bit_identical_ssp_members",
            "require_bit_identical_runtime_inputs",
            "require_identical_source_state",
            "required_source_roles",
            "allowed_execution_environments",
            "exact_repeat_files",
        },
        "SSP qualification policy",
    )
    if (
        type(policy["required_distinct_fresh_repetitions"]) is not int
        or policy["required_distinct_fresh_repetitions"] != 2
        or policy["attestation_namespace"] != ATTESTATION_NAMESPACE
        or type(policy["required_distinct_signers"]) is not int
        or policy["required_distinct_signers"] != 2
        or type(policy["nonce_bytes"]) is not int
        or policy["nonce_bytes"] != 32
        or policy["fresh_execution_controller"]
        != "verify_age_cut_ssp_contract.execute_fresh_repetition"
        or policy["generation_program"] != GENERATION_PROGRAM
        or policy["generation_argv_mode"] != "subprocess_no_shell_exact_pinned"
        or policy["require_signed_pre_run_challenge"] is not True
        or policy["require_controller_created_empty_run_directory"] is not True
        or policy["require_exact_padova_extraction_from_locked_archive"] is not True
        or policy["require_bit_identical_ssp_members"] is not True
        or policy["require_bit_identical_runtime_inputs"] is not True
        or policy["require_identical_source_state"] is not True
        or policy["required_source_roles"] != ["public_release", "private_production"]
        or policy["allowed_execution_environments"] != list(ALLOWED_ENVIRONMENTS)
        or policy["exact_repeat_files"]
        != [SSP_MANIFEST_NAME, PARAMETERS_NAME, SFR_NAME, RUNTIME_NAME]
    ):
        fail("SSP qualification policy changed")
    sets = contract["artifact_sets"]
    if not isinstance(sets, list) or not sets:
        fail("SSP contract artifact_sets must be a non-empty list")
    seen: set[str] = set()
    accepted = 0
    for index, value in enumerate(sets):
        item = exact_keys(
            value,
            {
                "id",
                "role",
                "production_accepted",
                "qualification_eligible",
                "ssp_manifest_sha256",
                "ssp_member_sha256",
                "runtime_parameters_sha256",
                "sfr_peaks_parameters_sha256",
                "numerical_runtime_manifest_sha256",
                "attestation_signers",
                "qualification_report",
                "note",
            },
            f"SSP artifact set {index}",
        )
        identifier = require_safe_id(item["id"], f"SSP artifact set {index} id")
        if identifier in seen:
            fail(f"duplicate SSP artifact-set id: {identifier}")
        seen.add(identifier)
        if item["role"] not in {"qualification_candidate", "qualified_candidate"}:
            fail(f"invalid SSP artifact-set role: {item['role']!r}")
        if type(item["production_accepted"]) is not bool or type(
            item["qualification_eligible"]
        ) is not bool:
            fail("SSP artifact-set policy flags must be booleans")
        if not isinstance(item["note"], str) or not item["note"]:
            fail("SSP artifact-set note must be non-empty")
        hash_fields = (
            "ssp_manifest_sha256",
            "runtime_parameters_sha256",
            "sfr_peaks_parameters_sha256",
            "numerical_runtime_manifest_sha256",
        )
        populated = [item[field] is not None for field in hash_fields]
        populated.append(item["ssp_member_sha256"] is not None)
        populated.append(item["qualification_report"] is not None)
        if any(populated) and not all(populated):
            fail("SSP artifact-set qualification fields must be all null or all populated")
        if all(populated):
            for field in hash_fields:
                require_sha(item[field], 64, f"SSP artifact set {identifier} {field}")
            member_hashes = item["ssp_member_sha256"]
            if not isinstance(member_hashes, dict) or set(member_hashes) != set(SSP_MEMBERS):
                fail("SSP artifact-set member hash set changed")
            for name in SSP_MEMBERS:
                require_sha(
                    member_hashes[name], 64, f"SSP artifact set {identifier} {name}"
                )
        signers = item["attestation_signers"]
        if signers is not None:
            if not isinstance(signers, list) or len(signers) != 2:
                fail("qualified SSP candidate must lock exactly two attestation signers")
            signer_ids: set[str] = set()
            public_keys: set[str] = set()
            for signer_index, signer_value in enumerate(signers):
                signer = exact_keys(
                    signer_value,
                    {"signer_id", "public_key"},
                    f"SSP attestation signer {signer_index}",
                )
                signer_id = require_safe_id(
                    signer["signer_id"], f"SSP attestation signer {signer_index} id"
                )
                public_key = signer["public_key"]
                if (
                    not isinstance(public_key, str)
                    or not public_key.startswith("ssh-ed25519 ")
                    or "\n" in public_key
                    or "\r" in public_key
                    or len(public_key) > 1000
                ):
                    fail("SSP attestation public key must be one OpenSSH Ed25519 line")
                signer_ids.add(signer_id)
                public_keys.add(public_key)
            if len(signer_ids) != 2 or len(public_keys) != 2:
                fail("SSP attestation signer ids and public keys must be distinct")
        if all(populated):
            report = exact_keys(
                item["qualification_report"],
                {"path", "sha256"},
                f"SSP artifact set {identifier} qualification report",
            )
            if (
                not isinstance(report["path"], str)
                or Path(report["path"]).name != report["path"]
                or "/" in report["path"]
                or "\\" in report["path"]
            ):
                fail("SSP qualification report path must be one safe basename")
            require_sha(report["sha256"], 64, "SSP qualification report hash")
        if item["production_accepted"]:
            accepted += 1
            if (
                item["role"] != "qualified_candidate"
                or item["qualification_eligible"] is not True
                or not all(populated)
                or item["attestation_signers"] is None
            ):
                fail("production-accepted SSP set is not fully qualified")
    if accepted > 1:
        fail("SSP contract cannot have more than one production-accepted set")
    return contract


def load_contract(path: Path) -> tuple[dict[str, Any], FileSnapshot]:
    contract_snapshot = read_snapshot(
        path, "age-cut SSP contract", maximum_bytes=MAX_CONTRACT_BYTES
    )
    return validate_contract(
        load_json_bytes(contract_snapshot.data, "age-cut SSP contract")
    ), contract_snapshot


def repository_slug_from_remote(value: str, description: str) -> str:
    remote = value.strip()
    patterns = (
        r"https://github\.com/([^/\s]+/[^/\s]+?)(?:\.git)?/?$",
        r"ssh://git@github\.com/([^/\s]+/[^/\s]+?)(?:\.git)?/?$",
        r"git@github\.com:([^/\s]+/[^/\s]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote)
        if match is not None:
            slug = match.group(1)
            if SAFE_REPOSITORY.fullmatch(slug) is not None:
                return slug
    fail(f"{description} origin is not a canonical GitHub repository URL")


def git_state(
    root_path: Path,
    description: str,
    *,
    expected_repository: str,
    allowed_untracked_paths: set[str] | None = None,
) -> dict[str, str]:
    root = require_directory(root_path, description)
    if SAFE_REPOSITORY.fullmatch(expected_repository) is None:
        fail(f"invalid expected repository slug for {description}")
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=root,
        )
        ignored = subprocess.check_output(
            [
                "git",
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
            cwd=root,
        )
        remote = subprocess.check_output(
            ["git", "remote", "get-url", "origin"], cwd=root, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot inspect {description} git state: {exc}")
    require_sha(commit, 40, f"{description} commit")
    require_sha(tree, 40, f"{description} Git tree")
    permitted = set() if allowed_untracked_paths is None else allowed_untracked_paths
    observed_untracked: set[str] = set()
    for raw in status.split(b"\0"):
        if not raw:
            continue
        if not raw.startswith(b"?? "):
            fail(f"{description} contains tracked modifications")
        try:
            relative = raw[3:].decode("utf-8")
        except UnicodeError as exc:
            fail(f"cannot decode untracked path in {description}: {exc}")
        if relative in observed_untracked:
            fail(f"duplicate untracked path reported in {description}")
        observed_untracked.add(relative)
    observed_ignored: set[str] = set()
    for raw in ignored.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeError as exc:
            fail(f"cannot decode ignored path in {description}: {exc}")
        if relative in observed_ignored:
            fail(f"duplicate ignored path reported in {description}")
        observed_ignored.add(relative)
    if observed_untracked & observed_ignored:
        fail(f"{description} reports a path as both ignored and untracked")
    if observed_untracked | observed_ignored != permitted:
        fail(
            f"{description} ignored/untracked paths differ from the exact allowed overlay"
        )
    if repository_slug_from_remote(remote, description) != expected_repository:
        fail(f"{description} origin repository differs from {expected_repository}")
    return {"commit_sha": commit, "git_tree_sha": tree}


def validate_padova_extraction_record(value: Any) -> dict[str, Any]:
    record = exact_keys(
        value,
        {"root_relative_path", "member_count", "tree_sha256"},
        "Padova extraction record",
    )
    if record["root_relative_path"] != "jjmodel/input/isochrones/Padova":
        fail("Padova extraction root differs from the JJ runtime location")
    require_positive_int(record["member_count"], "Padova extraction member count")
    require_sha(record["tree_sha256"], 64, "Padova extraction tree SHA-256")
    return record


def exact_padova_extraction(
    jj_root_path: Path, padova_archive: FileSnapshot
) -> tuple[set[str], dict[str, Any]]:
    jj_root = require_directory(jj_root_path, "JJ source root")
    destination_relative = PurePosixPath("jjmodel/input/isochrones/Padova")
    destination = jj_root.joinpath(*destination_relative.parts)
    if destination.is_symlink() or not destination.is_dir():
        fail("locked Padova extraction root is missing or is a symlink")
    members: list[dict[str, Any]] = []
    expected_relative: set[str] = set()
    try:
        # Inspect the already captured bytes.  A path replacement after the
        # snapshot therefore cannot influence either comparison or execution.
        with zipfile.ZipFile(io.BytesIO(padova_archive.data)) as archive:
            seen: set[str] = set()
            for info in archive.infolist():
                name = info.filename
                if "\\" in name or "\x00" in name:
                    fail("Padova archive contains an unsafe member path")
                relative = PurePosixPath(name)
                if relative.is_absolute() or not relative.parts or any(
                    part in {"", ".", ".."} for part in relative.parts
                ):
                    fail("Padova archive contains path traversal or an empty member")
                normalized = relative.as_posix()
                if normalized in seen:
                    fail("Padova archive contains duplicate member paths")
                seen.add(normalized)
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    fail("Padova archive contains a symbolic-link member")
                if info.is_dir():
                    continue
                extracted = read_snapshot(
                    destination.joinpath(*relative.parts),
                    f"extracted Padova member {normalized}",
                )
                with archive.open(info, "r") as handle:
                    archived_bytes = handle.read()
                if extracted.data != archived_bytes or extracted.size_bytes != info.file_size:
                    fail(f"extracted Padova bytes differ from archive member {normalized}")
                git_relative = (destination_relative / relative).as_posix()
                expected_relative.add(git_relative)
                members.append(
                    {
                        "path": git_relative,
                        "sha256": extracted.sha256,
                        "size_bytes": extracted.size_bytes,
                    }
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        fail(f"cannot validate locked Padova extraction: {exc}")
    actual_relative: set[str] = set()
    for path in destination.rglob("*"):
        if path.is_symlink():
            fail("Padova extraction contains a symbolic link")
        if path.is_file():
            actual_relative.add(path.relative_to(jj_root).as_posix())
        elif not path.is_dir():
            fail("Padova extraction contains a non-regular filesystem object")
    if not expected_relative or actual_relative != expected_relative:
        fail("Padova extraction file set differs from the locked archive")
    members.sort(key=lambda item: item["path"])
    record = {
        "root_relative_path": destination_relative.as_posix(),
        "member_count": len(members),
        "tree_sha256": hashlib.sha256(canonical_json_bytes(members)).hexdigest(),
    }
    return expected_relative, validate_padova_extraction_record(record)


def exact_git_archive(
    root_path: Path, archive_path: Path, description: str
) -> FileSnapshot:
    root = require_directory(root_path, description)
    supplied = read_snapshot(archive_path, f"{description} source archive")
    try:
        result = subprocess.run(
            ["git", "archive", "--format=tar", "HEAD"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot generate exact git archive for {description}: {exc}")
    if result.returncode != 0:
        fail(f"cannot generate exact git archive for {description}")
    if result.stdout != supplied.data:
        fail(f"supplied {description} archive is not exact git archive --format=tar HEAD")
    recheck_snapshot(supplied, f"{description} source archive")
    return supplied


def parse_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{description} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        fail(f"invalid {description}: {exc}")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail(f"{description} is not UTC")
    return parsed


def validate_source_record(value: Any, role: str) -> dict[str, Any]:
    record = exact_keys(
        value,
        {"role", "repository", "commit_sha", "git_tree_sha", "source_archive"},
        f"{role} source provenance",
    )
    if record["role"] != role:
        fail(f"source provenance role mismatch for {role}")
    if not isinstance(record["repository"], str) or SAFE_REPOSITORY.fullmatch(
        record["repository"]
    ) is None:
        fail(f"invalid repository slug for {role}")
    require_sha(record["commit_sha"], 40, f"{role} commit")
    require_sha(record["git_tree_sha"], 40, f"{role} Git tree")
    archive = validate_evidence(
        record["source_archive"],
        record["source_archive"].get("filename")
        if isinstance(record["source_archive"], dict)
        else "",
        f"{role} source archive",
    )
    if (
        Path(archive["filename"]).name != archive["filename"]
        or "/" in archive["filename"]
        or "\\" in archive["filename"]
    ):
        fail(f"unsafe source archive filename for {role}")
    return record


def validate_provenance(
    document: Any,
    snapshots: dict[str, FileSnapshot],
    contract: dict[str, Any],
) -> dict[str, Any]:
    provenance = exact_keys(
        document,
        {
            "schema_version",
            "repeat_label",
            "execution_id",
            "execution_environment",
            "run_started_utc",
            "run_completed_utc",
            "generation_program",
            "jj_source",
            "padova_archive",
            "padova_extraction",
            "public_source",
            "private_source",
            "runtime_parameters",
            "sfr_peaks_parameters",
            "numerical_runtime_manifest",
            "ssp_manifest",
            "start_challenge",
            "start_challenge_signature",
            "execution_record",
        },
        "age-cut repetition provenance",
    )
    if type(provenance["schema_version"]) is not int or provenance["schema_version"] != 1:
        fail("age-cut repetition provenance schema_version must be integer 1")
    require_safe_id(provenance["repeat_label"], "repetition label")
    try:
        execution_id = str(uuid.UUID(provenance["execution_id"]))
    except (TypeError, ValueError, AttributeError) as exc:
        fail(f"invalid repetition execution UUID: {exc}")
    if execution_id != provenance["execution_id"]:
        fail("repetition execution UUID is not canonical lowercase form")
    if provenance["execution_environment"] not in ALLOWED_ENVIRONMENTS:
        fail("repetition execution environment is not allowed")
    started = parse_timestamp(provenance["run_started_utc"], "run_started_utc")
    completed = parse_timestamp(provenance["run_completed_utc"], "run_completed_utc")
    if completed <= started:
        fail("repetition completion time must be later than start time")
    validate_evidence(
        provenance["generation_program"],
        Path(GENERATION_PROGRAM).name,
        "repetition generation program",
    )
    jj = validate_source_record(provenance["jj_source"], "jj_generator")
    if (
        jj["repository"] != "askenja/jjmodel"
        or jj["commit_sha"] != JJ_SHA
    ):
        fail("repetition JJ provenance differs from the locked source")
    if provenance["padova_archive"] != {
        "data_lock_id": PADOVA_LOCK_ID,
        "filename": PADOVA_FILENAME,
        "sha256": PADOVA_SHA256,
        "size_bytes": PADOVA_SIZE_BYTES,
    }:
        fail("repetition Padova archive provenance differs from the lock")
    validate_padova_extraction_record(provenance["padova_extraction"])
    public = validate_source_record(provenance["public_source"], "public_release")
    private = validate_source_record(provenance["private_source"], "private_production")
    if public["repository"] == private["repository"]:
        fail("public and private source repositories must be distinct")
    if public["git_tree_sha"] != private["git_tree_sha"]:
        fail("public and private source Git trees must be identical")
    bindings = (
        ("runtime_parameters", PARAMETERS_NAME),
        ("sfr_peaks_parameters", SFR_NAME),
        ("numerical_runtime_manifest", RUNTIME_NAME),
        ("ssp_manifest", SSP_MANIFEST_NAME),
        ("start_challenge", START_CHALLENGE_NAME),
        ("start_challenge_signature", START_CHALLENGE_SIGNATURE_NAME),
        ("execution_record", EXECUTION_RECORD_NAME),
    )
    for field, name in bindings:
        observed = validate_evidence(provenance[field], name, f"provenance {field}")
        expected = evidence(snapshots[name])
        if observed != expected:
            fail(f"repetition provenance binding mismatch for {field}")
    return provenance


def candidate_signer(candidate: dict[str, Any], signer_id: str) -> dict[str, str]:
    signers = candidate.get("attestation_signers")
    if not isinstance(signers, list) or len(signers) != 2:
        fail("SSP candidate does not yet lock two attestation signers")
    matches = [item for item in signers if item.get("signer_id") == signer_id]
    if len(matches) != 1:
        fail(f"unknown or duplicate SSP attestation signer: {signer_id!r}")
    return matches[0]


def provenance_source_state(provenance: dict[str, Any]) -> dict[str, Any]:
    return {
        "jj_source": provenance["jj_source"],
        "public_source": provenance["public_source"],
        "private_source": provenance["private_source"],
        "padova_archive": provenance["padova_archive"],
        "padova_extraction": provenance["padova_extraction"],
    }


def validate_source_state_document(
    value: Any, contract: dict[str, Any], description: str
) -> dict[str, Any]:
    state = exact_keys(
        value,
        {
            "jj_source",
            "public_source",
            "private_source",
            "padova_archive",
            "padova_extraction",
        },
        description,
    )
    jj = validate_source_record(state["jj_source"], "jj_generator")
    public = validate_source_record(state["public_source"], "public_release")
    private = validate_source_record(state["private_source"], "private_production")
    if jj["repository"] != "askenja/jjmodel" or jj["commit_sha"] != JJ_SHA:
        fail(f"{description} JJ source differs from the locked source")
    if public["repository"] == private["repository"]:
        fail(f"{description} public/private repositories are not distinct")
    if public["git_tree_sha"] != private["git_tree_sha"]:
        fail(f"{description} public/private Git trees differ")
    if state["padova_archive"] != contract["locked_inputs"]["padova_archive"]:
        fail(f"{description} Padova archive differs from the contract")
    validate_padova_extraction_record(state["padova_extraction"])
    return state


def start_challenge_body(
    contract: dict[str, Any],
    candidate: dict[str, Any],
    *,
    signer_id: str,
    repeat_label: str,
    execution_id: str,
    nonce_hex: str,
    issued_utc: str,
    generation_program: FileSnapshot,
    source_state_value: dict[str, Any],
    runtime_parameters: FileSnapshot,
    sfr_peaks_parameters: FileSnapshot,
    numerical_runtime_manifest: FileSnapshot,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate["id"],
        "signer_id": signer_id,
        "repeat_label": repeat_label,
        "execution_id": execution_id,
        "nonce_hex": nonce_hex,
        "issued_utc": issued_utc,
        "generation_program": evidence(generation_program),
        "source_state": source_state_value,
        "runtime_parameters": evidence(runtime_parameters),
        "sfr_peaks_parameters": evidence(sfr_peaks_parameters),
        "numerical_runtime_manifest": evidence(numerical_runtime_manifest),
        "fresh_execution_policy": {
            "controller": "verify_age_cut_ssp_contract.execute_fresh_repetition",
            "program_relative_path": GENERATION_PROGRAM,
            "python_flags": ["-I", "-B"],
            "shell": False,
            "run_directory_must_not_exist": True,
            "host_output_directory_must_not_exist": True,
        },
    }


def validate_start_challenge(
    document: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
) -> dict[str, Any]:
    challenge = exact_keys(
        document,
        {
            "challenge_id",
            "schema_version",
            "contract_id",
            "candidate_artifact_set_id",
            "signer_id",
            "repeat_label",
            "execution_id",
            "nonce_hex",
            "issued_utc",
            "generation_program",
            "source_state",
            "runtime_parameters",
            "sfr_peaks_parameters",
            "numerical_runtime_manifest",
            "fresh_execution_policy",
        },
        "SSP fresh-execution start challenge",
    )
    body = dict(challenge)
    challenge_id = body.pop("challenge_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if challenge_id != expected_id:
        fail("SSP start challenge self-identifier mismatch")
    if type(challenge["schema_version"]) is not int or challenge["schema_version"] != 1:
        fail("SSP start challenge schema_version must be integer 1")
    signer_id = require_safe_id(challenge["signer_id"], "start challenge signer")
    candidate_signer(candidate, signer_id)
    if (
        challenge["contract_id"] != contract["contract_id"]
        or challenge["candidate_artifact_set_id"] != candidate["id"]
        or challenge["repeat_label"] != provenance["repeat_label"]
        or challenge["execution_id"] != provenance["execution_id"]
    ):
        fail("SSP start challenge identity differs from repetition provenance")
    nonce = challenge["nonce_hex"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        fail("SSP start challenge nonce must be 32 lowercase-hex bytes")
    issued = parse_timestamp(challenge["issued_utc"], "start challenge issue time")
    if issued >= parse_timestamp(provenance["run_started_utc"], "run_started_utc"):
        fail("SSP start challenge was not issued before execution started")
    program = validate_evidence(
        challenge["generation_program"],
        Path(GENERATION_PROGRAM).name,
        "start challenge generation program",
    )
    if program["sha256"] != provenance["generation_program"]["sha256"]:
        fail("start challenge generation program differs from provenance")
    state = validate_source_state_document(
        challenge["source_state"], contract, "start challenge source state"
    )
    if state != provenance_source_state(provenance):
        fail("start challenge source state differs from repetition provenance")
    for field, name in (
        ("runtime_parameters", PARAMETERS_NAME),
        ("sfr_peaks_parameters", SFR_NAME),
        ("numerical_runtime_manifest", RUNTIME_NAME),
    ):
        observed = validate_evidence(
            challenge[field], name, f"start challenge {field}"
        )
        if observed != evidence(snapshots[name]):
            fail(f"start challenge input binding mismatch for {field}")
    if challenge["fresh_execution_policy"] != {
        "controller": "verify_age_cut_ssp_contract.execute_fresh_repetition",
        "program_relative_path": GENERATION_PROGRAM,
        "python_flags": ["-I", "-B"],
        "shell": False,
        "run_directory_must_not_exist": True,
        "host_output_directory_must_not_exist": True,
    }:
        fail("SSP start challenge does not require the exact fresh-execution policy")
    return challenge


def validate_execution_record(
    document: Any,
    challenge: dict[str, Any],
    provenance: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    runtime_document: dict[str, Any],
) -> dict[str, Any]:
    record = exact_keys(
        document,
        {
            "execution_record_id",
            "schema_version",
            "controller",
            "challenge_id",
            "execution_id",
            "nonce_hex",
            "argv",
            "cwd",
            "shell",
            "run_directory_created_empty",
            "host_output_directory_created_empty",
            "run_started_utc",
            "run_completed_utc",
            "return_code",
            "stdout",
            "stderr",
            "ssp_member_sha256",
        },
        "SSP fresh-execution record",
    )
    body = dict(record)
    record_id = body.pop("execution_record_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if record_id != expected_id:
        fail("SSP execution-record self-identifier mismatch")
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or record["controller"]
        != "verify_age_cut_ssp_contract.execute_fresh_repetition"
        or record["challenge_id"] != challenge["challenge_id"]
        or record["execution_id"] != provenance["execution_id"]
        or record["nonce_hex"] != challenge["nonce_hex"]
        or record["shell"] is not False
        or record["run_directory_created_empty"] is not True
        or record["host_output_directory_created_empty"] is not True
        or type(record["return_code"]) is not int
        or record["return_code"] != 0
        or record["run_started_utc"] != provenance["run_started_utc"]
        or record["run_completed_utc"] != provenance["run_completed_utc"]
    ):
        fail("SSP execution record does not prove the exact successful fresh-run gate")
    if not isinstance(record["cwd"], str) or not record["cwd"]:
        fail("SSP execution record cwd must be a non-empty string")
    argv = record["argv"]
    if not isinstance(argv, list) or len(argv) != 14 or not all(
        isinstance(item, str) and item and "\x00" not in item for item in argv
    ):
        fail("SSP execution record argv is invalid")
    if (
        argv[0] != runtime_document["python_executable"]
        or argv[1:3] != ["-I", "-B"]
        or Path(argv[3]).name != Path(GENERATION_PROGRAM).name
        or argv[4] != "--jj-root"
        or argv[6] != "--run-dir"
        or argv[8] != "--out"
        or argv[10:]
        != ["--iso", "Padova", "--expected-radial-step-kpc", "0.5"]
    ):
        fail("SSP execution record argv is not the exact pinned generator command")
    for stream_name in ("stdout", "stderr"):
        stream = exact_keys(
            record[stream_name], {"sha256", "size_bytes"}, f"execution {stream_name}"
        )
        require_sha(stream["sha256"], 64, f"execution {stream_name} SHA-256")
        require_nonnegative_int(stream["size_bytes"], f"execution {stream_name} size")
    hashes = record["ssp_member_sha256"]
    if not isinstance(hashes, dict) or set(hashes) != set(SSP_MEMBERS):
        fail("SSP execution-record output tuple differs from the exact member set")
    for name in SSP_MEMBERS:
        require_sha(hashes[name], 64, f"execution-record SSP hash {name}")
        if hashes[name] != snapshots[name].sha256:
            fail(f"execution-record SSP output binding mismatch for {name}")
    return record


def attestation_body(
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    signer_id: str,
    nonce_hex: str,
) -> dict[str, Any]:
    state = provenance_source_state(provenance)
    return {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate["id"],
        "signer_id": signer_id,
        "repeat_label": provenance["repeat_label"],
        "execution_id": provenance["execution_id"],
        "nonce_hex": nonce_hex,
        "run_started_utc": provenance["run_started_utc"],
        "run_completed_utc": provenance["run_completed_utc"],
        "repetition_manifest_sha256": snapshots[REPETITION_MANIFEST_NAME].sha256,
        "ssp_manifest_sha256": snapshots[SSP_MANIFEST_NAME].sha256,
        "runtime_parameters_sha256": snapshots[PARAMETERS_NAME].sha256,
        "sfr_peaks_parameters_sha256": snapshots[SFR_NAME].sha256,
        "numerical_runtime_manifest_sha256": snapshots[RUNTIME_NAME].sha256,
        "provenance_sha256": snapshots[PROVENANCE_NAME].sha256,
        "start_challenge_sha256": snapshots[START_CHALLENGE_NAME].sha256,
        "start_challenge_signature_sha256": snapshots[
            START_CHALLENGE_SIGNATURE_NAME
        ].sha256,
        "execution_record_sha256": snapshots[EXECUTION_RECORD_NAME].sha256,
        "source_state_sha256": hashlib.sha256(canonical_json_bytes(state)).hexdigest(),
    }


def validate_attestation(
    document: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
) -> dict[str, Any]:
    attestation = exact_keys(
        document,
        {
            "attestation_id",
            "schema_version",
            "contract_id",
            "candidate_artifact_set_id",
            "signer_id",
            "repeat_label",
            "execution_id",
            "nonce_hex",
            "run_started_utc",
            "run_completed_utc",
            "repetition_manifest_sha256",
            "ssp_manifest_sha256",
            "runtime_parameters_sha256",
            "sfr_peaks_parameters_sha256",
            "numerical_runtime_manifest_sha256",
            "provenance_sha256",
            "start_challenge_sha256",
            "start_challenge_signature_sha256",
            "execution_record_sha256",
            "source_state_sha256",
        },
        "SSP run attestation",
    )
    if type(attestation["schema_version"]) is not int or attestation["schema_version"] != 1:
        fail("SSP run attestation schema_version must be integer 1")
    signer_id = require_safe_id(attestation["signer_id"], "SSP attestation signer id")
    candidate_signer(candidate, signer_id)
    nonce = attestation["nonce_hex"]
    if (
        not isinstance(nonce, str)
        or len(nonce) != 64
        or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
    ):
        fail("SSP run attestation nonce must be 32 lowercase-hex bytes")
    expected_body = attestation_body(
        contract, candidate, provenance, snapshots, signer_id, nonce
    )
    body = dict(attestation)
    attestation_id = body.pop("attestation_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if attestation_id != expected_id:
        fail("SSP run attestation self-identifier mismatch")
    if body != expected_body:
        fail("SSP run attestation does not bind the current repetition bytes/provenance")
    return attestation


def verify_signature(
    attestation: FileSnapshot,
    signature: FileSnapshot,
    signer: dict[str, str],
    *,
    namespace: str,
) -> None:
    temporary = Path(tempfile.mkdtemp(prefix="age-ssp-signature-"))
    try:
        allowed = temporary / "allowed_signers"
        signature_copy = temporary / ATTESTATION_SIGNATURE_NAME
        allowed.write_text(
            f"{signer['signer_id']} {signer['public_key']}\n",
            encoding="utf-8",
            newline="\n",
        )
        signature_copy.write_bytes(signature.data)
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    signer["signer_id"],
                    "-n",
                    namespace,
                    "-s",
                    str(signature_copy),
                ],
                input=attestation.data,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        except OSError as exc:
            fail(f"cannot execute OpenSSH attestation verification: {exc}")
        if result.returncode != 0:
            fail("SSP run attestation OpenSSH/Ed25519 signature is invalid")
    finally:
        shutil.rmtree(temporary)


def signing_public_key(signing_key: Path) -> str:
    key = Path(signing_key)
    try:
        info = key.lstat()
    except OSError as exc:
        fail(f"cannot inspect SSP attestation signing key: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("SSP attestation signing key must be a regular non-symlink file")
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot derive SSP attestation public key: {exc}")
    if result.returncode != 0:
        fail("cannot derive public key from SSP attestation signing key")
    public_key = result.stdout.strip()
    if not public_key.startswith("ssh-ed25519 "):
        fail("SSP attestation signing key is not Ed25519")
    return public_key


def sign_document(
    path: Path, signing_key: Path, *, namespace: str, destination_name: str
) -> Path:
    generated = Path(str(path) + ".sig")
    if generated.exists() or generated.is_symlink():
        fail("unexpected pre-existing generated attestation signature")
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(signing_key),
                "-n",
                namespace,
                str(path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute OpenSSH attestation signing: {exc}")
    if result.returncode != 0 or not generated.is_file() or generated.is_symlink():
        fail("OpenSSH could not sign the SSP run attestation")
    destination = path.parent / destination_name
    os.replace(generated, destination)
    return destination


def sign_attestation(path: Path, signing_key: Path) -> Path:
    return sign_document(
        path,
        signing_key,
        namespace=ATTESTATION_NAMESPACE,
        destination_name=ATTESTATION_SIGNATURE_NAME,
    )


def inspect_repetition_root(
    root_path: Path, contract: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    root = require_directory(root_path, "SSP repetition root")
    entries = {path.name for path in root.iterdir()}
    if entries != REPETITION_FILES:
        fail(
            "SSP repetition root does not have the exact file set: "
            f"missing={sorted(REPETITION_FILES - entries)!r}, "
            f"extra={sorted(entries - REPETITION_FILES)!r}"
        )
    snapshots = {
        name: read_snapshot(
            root / name,
            f"SSP repetition file {name}",
            maximum_bytes=(
                MAX_MANIFEST_BYTES
                if name in {SSP_MANIFEST_NAME, REPETITION_MANIFEST_NAME}
                else MAX_RUNTIME_BYTES
                if name == RUNTIME_NAME
                else MAX_PROVENANCE_BYTES
                if name == PROVENANCE_NAME
                else MAX_PROVENANCE_BYTES
                if name
                in {
                    ATTESTATION_NAME,
                    ATTESTATION_SIGNATURE_NAME,
                    START_CHALLENGE_NAME,
                    START_CHALLENGE_SIGNATURE_NAME,
                }
                else MAX_EXECUTION_RECORD_BYTES
                if name == EXECUTION_RECORD_NAME
                else None
            ),
        )
        for name in REPETITION_FILES
    }
    if {path.name for path in root.iterdir()} != REPETITION_FILES:
        fail("SSP repetition root changed during snapshot")
    ssp_manifest = parse_manifest(
        snapshots[SSP_MANIFEST_NAME].data, SSP_MEMBERS, "SSP input manifest"
    )
    for name in SSP_MEMBERS:
        if snapshots[name].sha256 != ssp_manifest[name]:
            fail(f"SSP input manifest hash mismatch for {name}")
    repetition_manifest = parse_manifest(
        snapshots[REPETITION_MANIFEST_NAME].data,
        REPETITION_MANIFEST_MEMBERS,
        "SSP repetition manifest",
    )
    for name in REPETITION_MANIFEST_MEMBERS:
        if snapshots[name].sha256 != repetition_manifest[name]:
            fail(f"SSP repetition manifest hash mismatch for {name}")
    runtime_document = validate_runtime_manifest(
        load_json_bytes(snapshots[RUNTIME_NAME].data, "numerical-runtime manifest")
    )
    provenance = validate_provenance(
        load_json_bytes(snapshots[PROVENANCE_NAME].data, "repetition provenance"),
        snapshots,
        contract,
    )
    challenge = validate_start_challenge(
        load_json_bytes(
            snapshots[START_CHALLENGE_NAME].data, "SSP start challenge"
        ),
        contract,
        candidate,
        provenance,
        snapshots,
    )
    start_signer = candidate_signer(candidate, challenge["signer_id"])
    verify_signature(
        snapshots[START_CHALLENGE_NAME],
        snapshots[START_CHALLENGE_SIGNATURE_NAME],
        start_signer,
        namespace=START_CHALLENGE_NAMESPACE,
    )
    execution_record = validate_execution_record(
        load_json_bytes(
            snapshots[EXECUTION_RECORD_NAME].data, "SSP execution record"
        ),
        challenge,
        provenance,
        snapshots,
        runtime_document,
    )
    attestation = validate_attestation(
        load_json_bytes(snapshots[ATTESTATION_NAME].data, "SSP run attestation"),
        contract,
        candidate,
        provenance,
        snapshots,
    )
    signer = candidate_signer(candidate, attestation["signer_id"])
    if signer["signer_id"] != start_signer["signer_id"]:
        fail("start and completion attestations use different signers")
    verify_signature(
        snapshots[ATTESTATION_NAME],
        snapshots[ATTESTATION_SIGNATURE_NAME],
        signer,
        namespace=ATTESTATION_NAMESPACE,
    )
    return {
        "root": root,
        "snapshots": snapshots,
        "label": provenance["repeat_label"],
        "execution_id": provenance["execution_id"],
        "execution_environment": provenance["execution_environment"],
        "signer_id": attestation["signer_id"],
        "nonce_hex": attestation["nonce_hex"],
        "attestation_id": attestation["attestation_id"],
        "attestation_sha256": snapshots[ATTESTATION_NAME].sha256,
        "attestation_signature_sha256": snapshots[
            ATTESTATION_SIGNATURE_NAME
        ].sha256,
        "attestation_bytes": snapshots[ATTESTATION_NAME].data,
        "attestation_signature_bytes": snapshots[ATTESTATION_SIGNATURE_NAME].data,
        "start_challenge_id": challenge["challenge_id"],
        "start_challenge_sha256": snapshots[START_CHALLENGE_NAME].sha256,
        "start_challenge_signature_sha256": snapshots[
            START_CHALLENGE_SIGNATURE_NAME
        ].sha256,
        "start_challenge_bytes": snapshots[START_CHALLENGE_NAME].data,
        "start_challenge_signature_bytes": snapshots[
            START_CHALLENGE_SIGNATURE_NAME
        ].data,
        "execution_record_id": execution_record["execution_record_id"],
        "execution_record_sha256": snapshots[EXECUTION_RECORD_NAME].sha256,
        "execution_record_bytes": snapshots[EXECUTION_RECORD_NAME].data,
        "run_started_utc": provenance["run_started_utc"],
        "run_completed_utc": provenance["run_completed_utc"],
        "ssp_manifest_sha256": snapshots[SSP_MANIFEST_NAME].sha256,
        "ssp_member_sha256": {name: snapshots[name].sha256 for name in SSP_MEMBERS},
        "runtime_parameters_sha256": snapshots[PARAMETERS_NAME].sha256,
        "sfr_peaks_parameters_sha256": snapshots[SFR_NAME].sha256,
        "numerical_runtime_manifest_sha256": snapshots[RUNTIME_NAME].sha256,
        "numerical_runtime_manifest_bytes": snapshots[RUNTIME_NAME].data,
        "provenance_sha256": snapshots[PROVENANCE_NAME].sha256,
        "repetition_manifest_sha256": snapshots[REPETITION_MANIFEST_NAME].sha256,
        "jj_source": provenance["jj_source"],
        "public_source": provenance["public_source"],
        "private_source": provenance["private_source"],
        "padova_archive": provenance["padova_archive"],
        "padova_extraction": provenance["padova_extraction"],
    }


def artifact_set(contract: dict[str, Any], identifier: str) -> dict[str, Any]:
    matches = [item for item in contract["artifact_sets"] if item["id"] == identifier]
    if len(matches) != 1:
        fail(f"unknown or duplicate SSP artifact-set id: {identifier!r}")
    return matches[0]


def source_state(inspection: dict[str, Any]) -> dict[str, Any]:
    return {
        "jj_source": inspection["jj_source"],
        "public_source": inspection["public_source"],
        "private_source": inspection["private_source"],
        "padova_archive": inspection["padova_archive"],
        "padova_extraction": inspection["padova_extraction"],
    }


def qualification_report_body(
    contract: dict[str, Any], candidate_id: str, repetitions: list[dict[str, Any]]
) -> dict[str, Any]:
    first = repetitions[0]
    return {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate_id,
        "status": "PASS",
        "fresh_repetitions": [
            {
                "label": item["label"],
                "execution_id": item["execution_id"],
                "execution_environment": item["execution_environment"],
                "signer_id": item["signer_id"],
                "nonce_hex": item["nonce_hex"],
                "attestation_id": item["attestation_id"],
                "attestation_sha256": item["attestation_sha256"],
                "attestation_signature_sha256": item[
                    "attestation_signature_sha256"
                ],
                "attestation_bytes_base64": encode_base64(
                    item["attestation_bytes"]
                ),
                "attestation_signature_base64": encode_base64(
                    item["attestation_signature_bytes"]
                ),
                "start_challenge_id": item["start_challenge_id"],
                "start_challenge_sha256": item["start_challenge_sha256"],
                "start_challenge_signature_sha256": item[
                    "start_challenge_signature_sha256"
                ],
                "start_challenge_bytes_base64": encode_base64(
                    item["start_challenge_bytes"]
                ),
                "start_challenge_signature_base64": encode_base64(
                    item["start_challenge_signature_bytes"]
                ),
                "execution_record_id": item["execution_record_id"],
                "execution_record_sha256": item["execution_record_sha256"],
                "execution_record_bytes_base64": encode_base64(
                    item["execution_record_bytes"]
                ),
                "run_started_utc": item["run_started_utc"],
                "run_completed_utc": item["run_completed_utc"],
                "ssp_manifest_sha256": item["ssp_manifest_sha256"],
                "ssp_member_sha256": item["ssp_member_sha256"],
                "runtime_parameters_sha256": item["runtime_parameters_sha256"],
                "sfr_peaks_parameters_sha256": item["sfr_peaks_parameters_sha256"],
                "numerical_runtime_manifest_sha256": item[
                    "numerical_runtime_manifest_sha256"
                ],
                "numerical_runtime_manifest_bytes_base64": encode_base64(
                    item["numerical_runtime_manifest_bytes"]
                ),
                "provenance_sha256": item["provenance_sha256"],
                "repetition_manifest_sha256": item["repetition_manifest_sha256"],
                "source_state": source_state(item),
            }
            for item in repetitions
        ],
        "exact_repeat_sha256": {
            "ssp_manifest_sha256": first["ssp_manifest_sha256"],
            "ssp_member_sha256": first["ssp_member_sha256"],
            "runtime_parameters_sha256": first["runtime_parameters_sha256"],
            "sfr_peaks_parameters_sha256": first["sfr_peaks_parameters_sha256"],
            "numerical_runtime_manifest_sha256": first[
                "numerical_runtime_manifest_sha256"
            ],
        },
        "source_state": source_state(first),
        "policy": {
            "controller_created_fresh_runs": True,
            "signed_pre_run_challenges": True,
            "distinct_roots": True,
            "distinct_labels": True,
            "distinct_execution_ids": True,
            "distinct_signers": True,
            "distinct_nonces": True,
            "valid_ed25519_attestations": True,
            "bit_identical_ssp_members": True,
            "bit_identical_runtime_inputs": True,
            "identical_source_state": True,
        },
    }


def qualify_repetitions(
    contract_path: Path,
    repeat_a_root: Path,
    repeat_b_root: Path,
    candidate_set_id: str,
    report_path: Path,
) -> dict[str, Any]:
    contract, _ = load_contract(contract_path)
    candidate = artifact_set(contract, require_safe_id(candidate_set_id, "candidate id"))
    if not candidate["qualification_eligible"]:
        fail("requested SSP candidate is not qualification eligible")
    if candidate["attestation_signers"] is None:
        fail("requested SSP candidate does not lock two attestation public keys")
    roots = [Path(repeat_a_root).resolve(), Path(repeat_b_root).resolve()]
    if len(set(roots)) != 2:
        fail("SSP qualification requires two distinct repetition roots")
    repetitions = [
        inspect_repetition_root(repeat_a_root, contract, candidate),
        inspect_repetition_root(repeat_b_root, contract, candidate),
    ]
    if len({item["label"] for item in repetitions}) != 2:
        fail("SSP qualification repetition labels are not distinct")
    if len({item["execution_id"] for item in repetitions}) != 2:
        fail("SSP qualification execution ids are not distinct")
    if len({item["signer_id"] for item in repetitions}) != 2:
        fail("SSP qualification requires two distinct attestation signers")
    if len({item["nonce_hex"] for item in repetitions}) != 2:
        fail("SSP qualification attestation nonces are not distinct")
    exact_fields = (
        "ssp_manifest_sha256",
        "ssp_member_sha256",
        "runtime_parameters_sha256",
        "sfr_peaks_parameters_sha256",
        "numerical_runtime_manifest_sha256",
    )
    for field in exact_fields:
        if repetitions[0][field] != repetitions[1][field]:
            fail(f"fresh SSP repetitions differ for {field}")
    if source_state(repetitions[0]) != source_state(repetitions[1]):
        fail("fresh SSP repetitions use different source state")
    body = qualification_report_body(contract, candidate_set_id, repetitions)
    report = {
        "qualification_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
        **body,
    }
    destination = Path(report_path)
    if destination.is_symlink() or destination.exists():
        fail(f"qualification report destination already exists: {destination}")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        fail("qualification report parent must be an existing non-symlink directory")
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
    except OSError as exc:
        fail(f"cannot write SSP qualification report: {exc}")
    return report


def verify_embedded_repetition_attestations(
    item: dict[str, Any],
    contract: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    attestation_bytes = decode_base64(
        item["attestation_bytes_base64"],
        "embedded completion attestation",
        MAX_PROVENANCE_BYTES,
    )
    attestation_signature = decode_base64(
        item["attestation_signature_base64"],
        "embedded completion signature",
        MAX_PROVENANCE_BYTES,
    )
    challenge_bytes = decode_base64(
        item["start_challenge_bytes_base64"],
        "embedded start challenge",
        MAX_PROVENANCE_BYTES,
    )
    challenge_signature = decode_base64(
        item["start_challenge_signature_base64"],
        "embedded start signature",
        MAX_PROVENANCE_BYTES,
    )
    execution_bytes = decode_base64(
        item["execution_record_bytes_base64"],
        "embedded execution record",
        MAX_EXECUTION_RECORD_BYTES,
    )
    runtime_bytes = decode_base64(
        item["numerical_runtime_manifest_bytes_base64"],
        "embedded numerical-runtime manifest",
        MAX_RUNTIME_BYTES,
    )
    if hashlib.sha256(runtime_bytes).hexdigest() != item[
        "numerical_runtime_manifest_sha256"
    ]:
        fail("embedded numerical-runtime manifest hash mismatch")
    runtime_document = validate_runtime_manifest(
        load_json_bytes(runtime_bytes, "embedded numerical-runtime manifest")
    )
    byte_bindings = (
        (attestation_bytes, item["attestation_sha256"], "completion attestation"),
        (
            attestation_signature,
            item["attestation_signature_sha256"],
            "completion signature",
        ),
        (challenge_bytes, item["start_challenge_sha256"], "start challenge"),
        (
            challenge_signature,
            item["start_challenge_signature_sha256"],
            "start signature",
        ),
        (execution_bytes, item["execution_record_sha256"], "execution record"),
    )
    for data, expected, description in byte_bindings:
        if hashlib.sha256(data).hexdigest() != expected:
            fail(f"embedded {description} hash mismatch")
    challenge_document = load_json_bytes(challenge_bytes, "embedded start challenge")
    execution_document = load_json_bytes(execution_bytes, "embedded execution record")
    attestation_document = load_json_bytes(
        attestation_bytes, "embedded completion attestation"
    )
    if not isinstance(challenge_document, dict):
        fail("embedded start challenge must be an object")
    challenge_inputs = {
        field: validate_evidence(
            challenge_document.get(field), name, f"embedded challenge {field}"
        )
        for field, name in (
            ("runtime_parameters", PARAMETERS_NAME),
            ("sfr_peaks_parameters", SFR_NAME),
            ("numerical_runtime_manifest", RUNTIME_NAME),
        )
    }
    source = validate_source_state_document(
        item["source_state"], contract, "embedded repetition source state"
    )
    provenance = {
        "repeat_label": item["label"],
        "execution_id": item["execution_id"],
        "run_started_utc": item["run_started_utc"],
        "run_completed_utc": item["run_completed_utc"],
        "generation_program": challenge_document.get("generation_program"),
        **source,
    }
    snapshots: dict[str, FileSnapshot] = {
        PARAMETERS_NAME: synthetic_snapshot(
            PARAMETERS_NAME,
            b"",
            sha256_value=challenge_inputs["runtime_parameters"]["sha256"],
            size_bytes=challenge_inputs["runtime_parameters"]["size_bytes"],
        ),
        SFR_NAME: synthetic_snapshot(
            SFR_NAME,
            b"",
            sha256_value=challenge_inputs["sfr_peaks_parameters"]["sha256"],
            size_bytes=challenge_inputs["sfr_peaks_parameters"]["size_bytes"],
        ),
        RUNTIME_NAME: synthetic_snapshot(
            RUNTIME_NAME,
            b"",
            sha256_value=challenge_inputs["numerical_runtime_manifest"]["sha256"],
            size_bytes=challenge_inputs["numerical_runtime_manifest"]["size_bytes"],
        ),
        SSP_MANIFEST_NAME: synthetic_snapshot(
            SSP_MANIFEST_NAME, b"", sha256_value=item["ssp_manifest_sha256"]
        ),
        PROVENANCE_NAME: synthetic_snapshot(
            PROVENANCE_NAME, b"", sha256_value=item["provenance_sha256"]
        ),
        REPETITION_MANIFEST_NAME: synthetic_snapshot(
            REPETITION_MANIFEST_NAME,
            b"",
            sha256_value=item["repetition_manifest_sha256"],
        ),
        START_CHALLENGE_NAME: synthetic_snapshot(
            START_CHALLENGE_NAME, challenge_bytes
        ),
        START_CHALLENGE_SIGNATURE_NAME: synthetic_snapshot(
            START_CHALLENGE_SIGNATURE_NAME, challenge_signature
        ),
        EXECUTION_RECORD_NAME: synthetic_snapshot(
            EXECUTION_RECORD_NAME, execution_bytes
        ),
    }
    for name, digest in item["ssp_member_sha256"].items():
        snapshots[name] = synthetic_snapshot(name, b"", sha256_value=digest)
    challenge = validate_start_challenge(
        challenge_document, contract, candidate, provenance, snapshots
    )
    if challenge["challenge_id"] != item["start_challenge_id"]:
        fail("embedded start challenge id differs from qualification report")
    signer = candidate_signer(candidate, item["signer_id"])
    if challenge["signer_id"] != signer["signer_id"]:
        fail("embedded start challenge signer differs from report")
    verify_signature(
        snapshots[START_CHALLENGE_NAME],
        snapshots[START_CHALLENGE_SIGNATURE_NAME],
        signer,
        namespace=START_CHALLENGE_NAMESPACE,
    )
    execution = validate_execution_record(
        execution_document, challenge, provenance, snapshots, runtime_document
    )
    if execution["execution_record_id"] != item["execution_record_id"]:
        fail("embedded execution-record id differs from qualification report")
    attestation = validate_attestation(
        attestation_document, contract, candidate, provenance, snapshots
    )
    if (
        attestation["attestation_id"] != item["attestation_id"]
        or attestation["signer_id"] != signer["signer_id"]
        or attestation["nonce_hex"] != item["nonce_hex"]
    ):
        fail("embedded completion attestation differs from qualification report")
    verify_signature(
        synthetic_snapshot(ATTESTATION_NAME, attestation_bytes),
        synthetic_snapshot(ATTESTATION_SIGNATURE_NAME, attestation_signature),
        signer,
        namespace=ATTESTATION_NAMESPACE,
    )


def validate_report_document(
    report: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    document = exact_keys(
        report,
        {
            "qualification_id",
            "schema_version",
            "contract_id",
            "candidate_artifact_set_id",
            "status",
            "fresh_repetitions",
            "exact_repeat_sha256",
            "source_state",
            "policy",
        },
        "SSP qualification report",
    )
    body = dict(document)
    qualification_id = body.pop("qualification_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if qualification_id != expected_id:
        fail("SSP qualification report self-identifier mismatch")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["contract_id"] != contract["contract_id"]
        or document["candidate_artifact_set_id"] != candidate["id"]
        or document["status"] != "PASS"
    ):
        fail("SSP qualification report identity/status mismatch")
    repetitions = document["fresh_repetitions"]
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        fail("SSP qualification report must contain exactly two repetitions")
    expected_repeat_keys = {
        "label",
        "execution_id",
        "execution_environment",
        "signer_id",
        "nonce_hex",
        "attestation_id",
        "attestation_sha256",
        "attestation_signature_sha256",
        "attestation_bytes_base64",
        "attestation_signature_base64",
        "start_challenge_id",
        "start_challenge_sha256",
        "start_challenge_signature_sha256",
        "start_challenge_bytes_base64",
        "start_challenge_signature_base64",
        "execution_record_id",
        "execution_record_sha256",
        "execution_record_bytes_base64",
        "run_started_utc",
        "run_completed_utc",
        "ssp_manifest_sha256",
        "ssp_member_sha256",
        "runtime_parameters_sha256",
        "sfr_peaks_parameters_sha256",
        "numerical_runtime_manifest_sha256",
        "numerical_runtime_manifest_bytes_base64",
        "provenance_sha256",
        "repetition_manifest_sha256",
        "source_state",
    }
    labels: set[str] = set()
    execution_ids: set[str] = set()
    signer_ids: set[str] = set()
    nonces: set[str] = set()
    for index, raw in enumerate(repetitions):
        item = exact_keys(raw, expected_repeat_keys, f"qualification repetition {index}")
        labels.add(require_safe_id(item["label"], f"qualification repetition {index} label"))
        try:
            execution_ids.add(str(uuid.UUID(item["execution_id"])))
        except (TypeError, ValueError, AttributeError) as exc:
            fail(f"invalid qualification execution id: {exc}")
        if item["execution_environment"] not in ALLOWED_ENVIRONMENTS:
            fail("qualification repetition execution environment is invalid")
        signer_id = require_safe_id(
            item["signer_id"], f"qualification repetition {index} signer"
        )
        candidate_signer(candidate, signer_id)
        signer_ids.add(signer_id)
        nonce = item["nonce_hex"]
        if (
            not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        ):
            fail("qualification repetition nonce is invalid")
        nonces.add(nonce)
        if (
            not isinstance(item["attestation_id"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", item["attestation_id"])
            is None
        ):
            fail("qualification repetition attestation id is invalid")
        for identity_field in ("start_challenge_id", "execution_record_id"):
            if (
                not isinstance(item[identity_field], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", item[identity_field])
                is None
            ):
                fail(f"qualification repetition {identity_field} is invalid")
        if parse_timestamp(item["run_completed_utc"], "qualification completion") <= parse_timestamp(
            item["run_started_utc"], "qualification start"
        ):
            fail("qualification repetition time interval is invalid")
        for field in (
            "ssp_manifest_sha256",
            "runtime_parameters_sha256",
            "sfr_peaks_parameters_sha256",
            "numerical_runtime_manifest_sha256",
            "provenance_sha256",
            "repetition_manifest_sha256",
            "attestation_sha256",
            "attestation_signature_sha256",
            "start_challenge_sha256",
            "start_challenge_signature_sha256",
            "execution_record_sha256",
        ):
            require_sha(item[field], 64, f"qualification repetition {field}")
        hashes = item["ssp_member_sha256"]
        if not isinstance(hashes, dict) or set(hashes) != set(SSP_MEMBERS):
            fail("qualification repetition SSP member tuple changed")
        for digest in hashes.values():
            require_sha(digest, 64, "qualification repetition SSP member hash")
        validate_source_state_document(
            item["source_state"], contract, "qualification source state"
        )
        verify_embedded_repetition_attestations(item, contract, candidate)
    if (
        len(labels) != 2
        or len(execution_ids) != 2
        or len(signer_ids) != 2
        or len(nonces) != 2
    ):
        fail("qualification report repetitions are not distinctly identified")
    exact = exact_keys(
        document["exact_repeat_sha256"],
        {
            "ssp_manifest_sha256",
            "ssp_member_sha256",
            "runtime_parameters_sha256",
            "sfr_peaks_parameters_sha256",
            "numerical_runtime_manifest_sha256",
        },
        "qualification exact repeat tuple",
    )
    first = repetitions[0]
    for field in exact:
        if exact[field] != first[field] or exact[field] != repetitions[1][field]:
            fail(f"qualification repetitions are not exact for {field}")
    if document["source_state"] != repetitions[0]["source_state"] or document[
        "source_state"
    ] != repetitions[1]["source_state"]:
        fail("qualification source states are not identical")
    if document["policy"] != {
        "controller_created_fresh_runs": True,
        "signed_pre_run_challenges": True,
        "distinct_roots": True,
        "distinct_labels": True,
        "distinct_execution_ids": True,
        "distinct_signers": True,
        "distinct_nonces": True,
        "valid_ed25519_attestations": True,
        "bit_identical_ssp_members": True,
        "bit_identical_runtime_inputs": True,
        "identical_source_state": True,
    }:
        fail("qualification report policy is not an exact PASS")
    candidate_expectations = {
        "ssp_manifest_sha256": exact["ssp_manifest_sha256"],
        "ssp_member_sha256": exact["ssp_member_sha256"],
        "runtime_parameters_sha256": exact["runtime_parameters_sha256"],
        "sfr_peaks_parameters_sha256": exact["sfr_peaks_parameters_sha256"],
        "numerical_runtime_manifest_sha256": exact[
            "numerical_runtime_manifest_sha256"
        ],
    }
    for field, expected in candidate_expectations.items():
        if candidate[field] != expected:
            fail(f"accepted SSP contract tuple differs from report at {field}")
    return document


def accepted_candidate(contract: dict[str, Any]) -> dict[str, Any]:
    accepted = [item for item in contract["artifact_sets"] if item["production_accepted"]]
    if len(accepted) != 1:
        fail("SSP contract does not contain exactly one production-accepted set")
    return accepted[0]


def verify_accepted_repetition(
    contract_path: Path,
    qualification_report_path: Path,
    repetition_root: Path,
) -> dict[str, Any]:
    contract, contract_snapshot = load_contract(contract_path)
    candidate = accepted_candidate(contract)
    reference = candidate["qualification_report"]
    expected_path = (Path(contract_path).resolve().parent / reference["path"]).resolve()
    supplied = Path(qualification_report_path)
    if supplied.is_symlink() or supplied.resolve() != expected_path:
        fail("supplied SSP qualification report is not the contract-locked path")
    report_snapshot = read_snapshot(
        supplied, "SSP qualification report", maximum_bytes=MAX_REPORT_BYTES
    )
    if report_snapshot.sha256 != reference["sha256"]:
        fail("SSP qualification report hash differs from the contract")
    report = validate_report_document(
        load_json_bytes(report_snapshot.data, "SSP qualification report"),
        contract,
        candidate,
    )
    inspection = inspect_repetition_root(repetition_root, contract, candidate)
    expected = {
        "ssp_manifest_sha256": candidate["ssp_manifest_sha256"],
        "ssp_member_sha256": candidate["ssp_member_sha256"],
        "runtime_parameters_sha256": candidate["runtime_parameters_sha256"],
        "sfr_peaks_parameters_sha256": candidate["sfr_peaks_parameters_sha256"],
        "numerical_runtime_manifest_sha256": candidate[
            "numerical_runtime_manifest_sha256"
        ],
    }
    for field, value in expected.items():
        if inspection[field] != value:
            fail(f"active SSP repetition differs from accepted tuple at {field}")
    matches = [
        item
        for item in report["fresh_repetitions"]
        if item["label"] == inspection["label"]
        and item["execution_id"] == inspection["execution_id"]
        and item["provenance_sha256"] == inspection["provenance_sha256"]
        and item["repetition_manifest_sha256"]
        == inspection["repetition_manifest_sha256"]
        and item["attestation_sha256"] == inspection["attestation_sha256"]
        and item["attestation_signature_sha256"]
        == inspection["attestation_signature_sha256"]
        and item["start_challenge_sha256"]
        == inspection["start_challenge_sha256"]
        and item["start_challenge_signature_sha256"]
        == inspection["start_challenge_signature_sha256"]
        and item["execution_record_sha256"]
        == inspection["execution_record_sha256"]
    ]
    if len(matches) != 1:
        fail("active SSP root is not one exact qualified repetition")
    return {
        "contract_id": contract["contract_id"],
        "contract_sha256": contract_snapshot.sha256,
        "artifact_set_id": candidate["id"],
        "qualification_id": report["qualification_id"],
        "qualification_report_sha256": report_snapshot.sha256,
        "active_repetition_label": inspection["label"],
        "active_execution_id": inspection["execution_id"],
        "active_signer_id": inspection["signer_id"],
        "active_attestation_id": inspection["attestation_id"],
        "ssp_manifest_sha256": inspection["ssp_manifest_sha256"],
        "ssp_member_sha256": inspection["ssp_member_sha256"],
        "runtime_parameters_sha256": inspection["runtime_parameters_sha256"],
        "sfr_peaks_parameters_sha256": inspection["sfr_peaks_parameters_sha256"],
        "numerical_runtime_manifest_sha256": inspection[
            "numerical_runtime_manifest_sha256"
        ],
    }


def write_bytes_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except OSError as exc:
        fail(f"cannot write repetition file {path.name}: {exc}")


def write_manifest(path: Path, names: tuple[str, ...], root: Path) -> None:
    lines = []
    for name in names:
        member = read_snapshot(root / name, f"generated repetition file {name}")
        lines.append(f"{member.sha256}  {name}\n")
    write_bytes_exclusive(path, "".join(lines).encode("utf-8"))


def find_ssp_sources(run_dir_path: Path) -> dict[str, FileSnapshot]:
    root = require_directory(run_dir_path, "source JJ run directory")
    result: dict[str, FileSnapshot] = {}
    for name in SSP_MEMBERS:
        matches = [path for path in root.rglob(name) if path.is_file() or path.is_symlink()]
        if len(matches) != 1:
            fail(f"expected exactly one source SSP file {name}, found {len(matches)}")
        result[name] = read_snapshot(matches[0], f"source SSP file {name}")
    parents = {item.path.parent for item in result.values()}
    if len(parents) != 1:
        fail("source SSP files do not share one output directory")
    observed = {
        path.name
        for path in next(iter(parents)).iterdir()
        if path.is_file()
        and re.fullmatch(r"SSP_R[^/\\]+_[dt]_Padova\.csv", path.name)
    }
    if observed != set(SSP_MEMBERS):
        fail("source output directory does not contain exactly 42 disk SSP files")
    return result


def source_record(
    role: str,
    repository: str,
    git_root: Path,
    archive_path: Path,
    *,
    allowed_untracked_paths: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(repository, str) or SAFE_REPOSITORY.fullmatch(repository) is None:
        fail(f"invalid {role} repository slug")
    state = git_state(
        git_root,
        f"{role} source root",
        expected_repository=repository,
        allowed_untracked_paths=allowed_untracked_paths,
    )
    archive = exact_git_archive(git_root, archive_path, f"{role} source root")
    return {
        "role": role,
        "repository": repository,
        **state,
        "source_archive": evidence(archive),
    }


def _disabled_legacy_packager(
    contract_path: Path,
    *,
    jj_root: Path,
    run_dir: Path,
    numerical_runtime_manifest: Path,
    padova_archive: Path,
    public_source_root: Path,
    public_repository: str,
    public_source_archive: Path,
    private_source_root: Path,
    private_repository: str,
    private_source_archive: Path,
    candidate_set_id: str,
    signer_id: str,
    signing_key: Path,
    nonce_hex: str,
    repeat_label: str,
    execution_id: str,
    execution_environment: str,
    run_started_utc: str,
    run_completed_utc: str,
    output_root: Path,
) -> dict[str, Any]:
    fail(
        "direct packaging of a pre-existing run is disabled; use "
        "execute_fresh_repetition"
    )
    contract, _ = load_contract(contract_path)
    candidate = artifact_set(
        contract, require_safe_id(candidate_set_id, "candidate artifact-set id")
    )
    signer = candidate_signer(
        candidate, require_safe_id(signer_id, "attestation signer id")
    )
    if signing_public_key(signing_key) != signer["public_key"]:
        fail("attestation private key does not match the contract-locked signer")
    if (
        not isinstance(nonce_hex, str)
        or re.fullmatch(r"[0-9a-f]{64}", nonce_hex) is None
    ):
        fail("attestation nonce must be 32 lowercase-hex bytes")
    label = require_safe_id(repeat_label, "repetition label")
    try:
        canonical_execution_id = str(uuid.UUID(execution_id))
    except (TypeError, ValueError, AttributeError) as exc:
        fail(f"invalid execution UUID: {exc}")
    if canonical_execution_id != execution_id:
        fail("execution UUID must use canonical lowercase form")
    if execution_environment not in ALLOWED_ENVIRONMENTS:
        fail("execution environment is not allowed")
    started = parse_timestamp(run_started_utc, "run_started_utc")
    completed = parse_timestamp(run_completed_utc, "run_completed_utc")
    if completed <= started:
        fail("run completion must be later than run start")
    jj_state = git_state(jj_root, "JJ source root")
    if jj_state["commit_sha"] != JJ_SHA:
        fail("JJ source root is not at the locked commit")
    padova = read_snapshot(padova_archive, "locked Padova archive")
    if (
        padova.path.name != PADOVA_FILENAME
        or padova.sha256 != PADOVA_SHA256
        or padova.size_bytes != PADOVA_SIZE_BYTES
    ):
        fail("Padova archive does not match the release data lock")
    runtime = read_snapshot(
        numerical_runtime_manifest,
        "numerical-runtime manifest",
        maximum_bytes=MAX_RUNTIME_BYTES,
    )
    validate_runtime_manifest(
        load_json_bytes(runtime.data, "numerical-runtime manifest")
    )
    run = require_directory(run_dir, "source JJ run directory")
    parameters = read_snapshot(run / PARAMETERS_NAME, "runtime JJ parameters")
    sfr = read_snapshot(run / SFR_NAME, "runtime JJ SFR peaks")
    ssp = find_ssp_sources(run)
    public = source_record(
        "public_release", public_repository, public_source_root, public_source_archive
    )
    private = source_record(
        "private_production",
        private_repository,
        private_source_root,
        private_source_archive,
    )
    if public["repository"] == private["repository"]:
        fail("public and private repositories must be distinct")
    if public["git_tree_sha"] != private["git_tree_sha"]:
        fail("public/private production source trees are not identical")
    output = Path(output_root)
    if output.is_symlink() or output.exists():
        fail("repetition output root must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".age-ssp-repeat-", dir=output.parent))
    try:
        write_bytes_exclusive(temporary / PARAMETERS_NAME, parameters.data)
        write_bytes_exclusive(temporary / SFR_NAME, sfr.data)
        write_bytes_exclusive(temporary / RUNTIME_NAME, runtime.data)
        for name in SSP_MEMBERS:
            write_bytes_exclusive(temporary / name, ssp[name].data)
        write_manifest(temporary / SSP_MANIFEST_NAME, SSP_MEMBERS, temporary)
        provenance = {
            "schema_version": 1,
            "repeat_label": label,
            "execution_id": execution_id,
            "execution_environment": execution_environment,
            "run_started_utc": run_started_utc,
            "run_completed_utc": run_completed_utc,
            "jj_source": {"repository": "askenja/jjmodel", "commit_sha": JJ_SHA},
            "padova_archive": contract["locked_inputs"]["padova_archive"],
            "public_source": public,
            "private_source": private,
            "runtime_parameters": evidence(
                read_snapshot(temporary / PARAMETERS_NAME, "packaged runtime parameters")
            ),
            "sfr_peaks_parameters": evidence(
                read_snapshot(temporary / SFR_NAME, "packaged SFR peaks")
            ),
            "numerical_runtime_manifest": evidence(
                read_snapshot(temporary / RUNTIME_NAME, "packaged runtime manifest")
            ),
            "ssp_manifest": evidence(
                read_snapshot(temporary / SSP_MANIFEST_NAME, "packaged SSP manifest")
            ),
        }
        write_bytes_exclusive(
            temporary / PROVENANCE_NAME,
            (json.dumps(provenance, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
                "utf-8"
            ),
        )
        write_manifest(
            temporary / REPETITION_MANIFEST_NAME,
            REPETITION_MANIFEST_MEMBERS,
            temporary,
        )
        attestation_snapshots = {
            name: read_snapshot(
                temporary / name, f"pre-attestation repetition file {name}"
            )
            for name in (*REPETITION_MANIFEST_MEMBERS, REPETITION_MANIFEST_NAME)
        }
        attestation_payload = attestation_body(
            contract,
            candidate,
            provenance,
            attestation_snapshots,
            signer["signer_id"],
            nonce_hex,
        )
        attestation = {
            "attestation_id": "sha256:"
            + hashlib.sha256(canonical_json_bytes(attestation_payload)).hexdigest(),
            **attestation_payload,
        }
        write_bytes_exclusive(
            temporary / ATTESTATION_NAME,
            (json.dumps(attestation, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
                "utf-8"
            ),
        )
        sign_attestation(temporary / ATTESTATION_NAME, signing_key)
        if {path.name for path in temporary.iterdir()} != REPETITION_FILES:
            fail("generated SSP repetition root has an unexpected file set")
        os.replace(temporary, output)
        return inspect_repetition_root(output, contract, candidate)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def detect_execution_environment() -> str:
    if sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true":
        return "github_actions_ubuntu_22_04"
    if sys.platform == "linux":
        try:
            kernel = Path("/proc/sys/kernel/osrelease").read_text(
                encoding="utf-8"
            )
        except OSError:
            kernel = ""
        if os.environ.get("WSL_DISTRO_NAME") or "microsoft" in kernel.lower():
            return "local_ubuntu_22_04_wsl2"
    fail("fresh SSP production execution is restricted to the locked WSL2/GitHub environment")


def write_json_exclusive(path: Path, value: Any) -> None:
    write_bytes_exclusive(
        path,
        (
            json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8"),
    )


def tracked_program_snapshot(root: Path) -> FileSnapshot:
    program = read_snapshot(
        root / Path(GENERATION_PROGRAM), "pinned JJ generation program"
    )
    try:
        committed = subprocess.check_output(
            ["git", "show", f"HEAD:{GENERATION_PROGRAM}"], cwd=root
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot read the committed JJ generation program: {exc}")
    if committed != program.data:
        fail("working JJ generation program differs from the committed source")
    return program


def archive_snapshot_for_record(
    archive_path: Path, source: dict[str, Any], description: str
) -> FileSnapshot:
    snapshot = read_snapshot(archive_path, description)
    if evidence(snapshot) != source["source_archive"]:
        fail(f"{description} bytes differ from the source-state evidence")
    recheck_snapshot(snapshot, description)
    return snapshot


def materialize_jj_archive_checkout(
    source_root: Path,
    archive: FileSnapshot,
    destination: Path,
    expected_commit: str,
) -> ExtractedArchiveTree:
    """Create Git metadata separately, then populate only captured TAR bytes."""

    root = Path(destination)
    if root.exists() or root.is_symlink():
        fail("fresh JJ archive execution root already exists")
    try:
        cloned = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-local",
                "--no-checkout",
                "--",
                str(require_directory(source_root, "JJ source root")),
                str(root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError as exc:
        fail(f"cannot create fresh JJ Git metadata: {exc}")
    if cloned.returncode != 0:
        fail("cannot create fresh JJ Git metadata")
    try:
        reset = subprocess.run(
            ["git", "-C", str(root), "reset", "--quiet", "--mixed", expected_commit],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
        remote = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "remote",
                "set-url",
                "origin",
                "https://github.com/askenja/jjmodel.git",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
        line_endings = subprocess.run(
            ["git", "-C", str(root), "config", "core.autocrlf", "false"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError as exc:
        fail(f"cannot bind fresh JJ Git metadata: {exc}")
    if (
        reset.returncode != 0
        or remote.returncode != 0
        or line_endings.returncode != 0
    ):
        fail("cannot bind fresh JJ Git metadata to the locked commit and origin")
    tree = extract_git_archive_snapshot(
        archive,
        root,
        "captured JJ Git archive",
        allow_existing_git_metadata=True,
    )
    state = git_state(
        root,
        "fresh JJ archive execution root",
        expected_repository="askenja/jjmodel",
    )
    if state["commit_sha"] != expected_commit:
        fail("fresh JJ archive execution root is not at the locked commit")
    return tree


def execute_fresh_repetition(
    contract_path: Path,
    *,
    jj_root: Path,
    jj_source_archive: Path,
    runtime_parameters: Path,
    sfr_peaks_parameters: Path,
    numerical_runtime_manifest: Path,
    padova_archive: Path,
    public_source_root: Path,
    public_repository: str,
    public_source_archive: Path,
    private_source_root: Path,
    private_repository: str,
    private_source_archive: Path,
    candidate_set_id: str,
    signer_id: str,
    signing_key: Path,
    repeat_label: str,
    execution_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Run the pinned generator once in a controller-created fresh workspace."""

    contract, _ = load_contract(contract_path)
    candidate = artifact_set(
        contract, require_safe_id(candidate_set_id, "candidate artifact-set id")
    )
    if candidate["qualification_eligible"] is not True:
        fail("requested SSP candidate is not qualification eligible")
    signer = candidate_signer(
        candidate, require_safe_id(signer_id, "attestation signer id")
    )
    if signing_public_key(signing_key) != signer["public_key"]:
        fail("attestation private key does not match the contract-locked signer")
    label = require_safe_id(repeat_label, "repetition label")
    execution_environment = detect_execution_environment()

    padova = read_snapshot(padova_archive, "locked Padova archive")
    if (
        padova.path.name != PADOVA_FILENAME
        or padova.sha256 != PADOVA_SHA256
        or padova.size_bytes != PADOVA_SIZE_BYTES
    ):
        fail("Padova archive does not match the release data lock")
    padova_untracked, padova_extraction = exact_padova_extraction(jj_root, padova)
    jj_source = source_record(
        "jj_generator",
        "askenja/jjmodel",
        jj_root,
        jj_source_archive,
        allowed_untracked_paths=padova_untracked,
    )
    if jj_source["commit_sha"] != JJ_SHA:
        fail("JJ source root is not at the locked commit")
    public = source_record(
        "public_release", public_repository, public_source_root, public_source_archive
    )
    private = source_record(
        "private_production",
        private_repository,
        private_source_root,
        private_source_archive,
    )
    if public["repository"] == private["repository"]:
        fail("public and private repositories must be distinct")
    if public["git_tree_sha"] != private["git_tree_sha"]:
        fail("public/private production source trees are not identical")
    private_root = require_directory(private_source_root, "private production source")
    working_generation_program = tracked_program_snapshot(private_root)
    jj_archive = archive_snapshot_for_record(
        jj_source_archive, jj_source, "captured JJ source archive"
    )
    public_archive = archive_snapshot_for_record(
        public_source_archive, public, "captured public source archive"
    )
    private_archive = archive_snapshot_for_record(
        private_source_archive, private, "captured private source archive"
    )

    runtime = read_snapshot(
        numerical_runtime_manifest,
        "numerical-runtime manifest",
        maximum_bytes=MAX_RUNTIME_BYTES,
    )
    runtime_document = validate_runtime_manifest(
        load_json_bytes(runtime.data, "numerical-runtime manifest")
    )
    parameters = read_snapshot(runtime_parameters, "runtime JJ parameters")
    sfr = read_snapshot(sfr_peaks_parameters, "runtime JJ SFR peaks")
    try:
        committed_sfr = subprocess.check_output(
            [
                "git",
                "show",
                "HEAD:jjmodel/tutorials/tutorial2/sfrd_peaks_parameters",
            ],
            cwd=Path(jj_root),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot read locked JJ SFR-peak parameters: {exc}")
    if committed_sfr != sfr.data:
        fail("runtime JJ SFR-peak parameters differ from the locked tutorial2 source")

    execution = Path(execution_root)
    repetition = Path(output_root)
    execution_resolved = execution.resolve()
    repetition_resolved = repetition.resolve()
    if (
        execution_resolved == repetition_resolved
        or execution_resolved in repetition_resolved.parents
        or repetition_resolved in execution_resolved.parents
    ):
        fail("execution and repetition roots must be distinct and non-nested")
    for path, description in (
        (execution, "execution root"),
        (repetition, "repetition output root"),
    ):
        if path.exists() or path.is_symlink():
            fail(f"fresh {description} must not already exist: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            fail(f"fresh {description} parent must be a non-symlink directory")
    execution.mkdir()
    source_execution = execution / "captured-sources"
    source_execution.mkdir()
    private_execution_root = source_execution / "private-production"
    private_execution_tree = extract_git_archive_snapshot(
        private_archive,
        private_execution_root,
        "captured private production Git archive",
    )
    generation_program = read_snapshot(
        private_execution_root / Path(GENERATION_PROGRAM),
        "captured private JJ generation program",
    )
    # `git archive` may apply a repository-declared checkout conversion on
    # some platforms.  The executable trust root is therefore the exact TAR
    # member, while `tracked_program_snapshot` independently proves that the
    # supplied checkout still equals its committed blob.
    del working_generation_program
    jj_execution_root = source_execution / "jjmodel"
    jj_execution_tree = materialize_jj_archive_checkout(
        jj_root, jj_archive, jj_execution_root, JJ_SHA
    )
    archived_sfr = read_snapshot(
        jj_execution_root
        / "jjmodel"
        / "tutorials"
        / "tutorial2"
        / "sfrd_peaks_parameters",
        "captured JJ tutorial2 SFR-peak parameters",
    )
    if archived_sfr.data != sfr.data:
        fail("runtime JJ SFR-peak parameters differ from captured JJ archive bytes")
    (
        execution_padova_paths,
        execution_padova_extraction,
        execution_padova_directories,
    ) = (
        extract_padova_overlay_snapshot(padova, jj_execution_root)
    )
    if (
        execution_padova_paths != padova_untracked
        or execution_padova_extraction != padova_extraction
    ):
        fail("fresh JJ Padova overlay differs from the locked source overlay")
    if source_record(
        "jj_generator",
        "askenja/jjmodel",
        jj_execution_root,
        jj_source_archive,
        allowed_untracked_paths=execution_padova_paths,
    ) != jj_source:
        fail("fresh JJ archive execution root differs from locked source state")
    run_dir = execution / "jj-run"
    host_output = execution / "host-export"
    run_dir.mkdir()
    host_output.mkdir()
    write_bytes_exclusive(run_dir / PARAMETERS_NAME, parameters.data)
    write_bytes_exclusive(run_dir / SFR_NAME, sfr.data)

    execution_id = str(uuid.uuid4())
    nonce_hex = secrets.token_hex(32)
    source_state_value = {
        "jj_source": jj_source,
        "public_source": public,
        "private_source": private,
        "padova_archive": contract["locked_inputs"]["padova_archive"],
        "padova_extraction": padova_extraction,
    }
    issued_utc = utc_now()
    challenge_payload = start_challenge_body(
        contract,
        candidate,
        signer_id=signer["signer_id"],
        repeat_label=label,
        execution_id=execution_id,
        nonce_hex=nonce_hex,
        issued_utc=issued_utc,
        generation_program=generation_program,
        source_state_value=source_state_value,
        runtime_parameters=parameters,
        sfr_peaks_parameters=sfr,
        numerical_runtime_manifest=runtime,
    )
    challenge = {
        "challenge_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(challenge_payload)).hexdigest(),
        **challenge_payload,
    }
    challenge_path = execution / START_CHALLENGE_NAME
    write_json_exclusive(challenge_path, challenge)
    sign_document(
        challenge_path,
        signing_key,
        namespace=START_CHALLENGE_NAMESPACE,
        destination_name=START_CHALLENGE_SIGNATURE_NAME,
    )
    challenge_snapshot = read_snapshot(challenge_path, "issued start challenge")
    challenge_signature_snapshot = read_snapshot(
        execution / START_CHALLENGE_SIGNATURE_NAME, "issued start signature"
    )

    python_executable = runtime_document["python_executable"]
    if not Path(python_executable).is_absolute() or not Path(python_executable).is_file():
        fail("numerical-runtime python_executable must be an existing absolute file")
    argv = [
        python_executable,
        "-I",
        "-B",
        str(generation_program.path),
        "--jj-root",
        str(jj_execution_root.resolve()),
        "--run-dir",
        str(run_dir.resolve()),
        "--out",
        str(host_output.resolve()),
        "--iso",
        "Padova",
        "--expected-radial-step-kpc",
        "0.5",
    ]
    child_environment = os.environ.copy()
    child_environment.update(EXPECTED_NUMERICAL_ENV)
    child_environment["PYTHONNOUSERSITE"] = "1"
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    child_environment.pop("PYTHONPATH", None)
    run_started_utc = utc_now()
    try:
        result = subprocess.run(
            argv,
            cwd=private_execution_root,
            env=child_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError as exc:
        fail(f"cannot execute pinned JJ generator: {exc}")
    run_completed_utc = utc_now()
    if result.returncode != 0:
        fail(
            "pinned JJ generator failed closed with return code "
            f"{result.returncode}; execution root retained at {execution}"
        )
    post_padova_paths, post_padova_extraction = exact_padova_extraction(
        jj_execution_root, padova
    )
    if (
        post_padova_paths != execution_padova_paths
        or post_padova_extraction != padova_extraction
    ):
        fail("Padova extraction changed during the controlled execution")
    if source_record(
        "jj_generator",
        "askenja/jjmodel",
        jj_root,
        jj_source_archive,
        allowed_untracked_paths=padova_untracked,
    ) != jj_source:
        fail("JJ source state changed during the controlled execution")
    if source_record(
        "public_release", public_repository, public_source_root, public_source_archive
    ) != public:
        fail("public source state changed during the controlled execution")
    if source_record(
        "private_production",
        private_repository,
        private_source_root,
        private_source_archive,
    ) != private:
        fail("private source state changed during the controlled execution")
    for snapshot, description in (
        (jj_archive, "captured JJ source archive"),
        (public_archive, "captured public source archive"),
        (private_archive, "captured private source archive"),
        (padova, "locked Padova archive"),
        (runtime, "numerical-runtime manifest"),
        (parameters, "runtime JJ parameters"),
        (sfr, "runtime JJ SFR peaks"),
    ):
        recheck_snapshot(snapshot, description)
    verify_extracted_archive_tree(
        private_execution_root,
        private_execution_tree,
        "captured private production Git archive",
    )
    verify_extracted_archive_tree(
        jj_execution_root,
        jj_execution_tree,
        "captured JJ Git archive",
        allow_git_metadata=True,
        allowed_overlay_files=execution_padova_paths,
        allowed_overlay_directories=execution_padova_directories,
    )
    if source_record(
        "jj_generator",
        "askenja/jjmodel",
        jj_execution_root,
        jj_source_archive,
        allowed_untracked_paths=execution_padova_paths,
    ) != jj_source:
        fail("fresh JJ archive source state changed during controlled execution")
    ssp = find_ssp_sources(run_dir)
    execution_payload = {
        "schema_version": 1,
        "controller": "verify_age_cut_ssp_contract.execute_fresh_repetition",
        "challenge_id": challenge["challenge_id"],
        "execution_id": execution_id,
        "nonce_hex": nonce_hex,
        "argv": argv,
        "cwd": str(private_execution_root),
        "shell": False,
        "run_directory_created_empty": True,
        "host_output_directory_created_empty": True,
        "run_started_utc": run_started_utc,
        "run_completed_utc": run_completed_utc,
        "return_code": result.returncode,
        "stdout": {
            "sha256": hashlib.sha256(result.stdout).hexdigest(),
            "size_bytes": len(result.stdout),
        },
        "stderr": {
            "sha256": hashlib.sha256(result.stderr).hexdigest(),
            "size_bytes": len(result.stderr),
        },
        "ssp_member_sha256": {name: ssp[name].sha256 for name in SSP_MEMBERS},
    }
    execution_record = {
        "execution_record_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(execution_payload)).hexdigest(),
        **execution_payload,
    }
    execution_record_path = execution / EXECUTION_RECORD_NAME
    write_json_exclusive(execution_record_path, execution_record)
    execution_record_snapshot = read_snapshot(
        execution_record_path, "fresh execution record"
    )

    temporary = Path(
        tempfile.mkdtemp(prefix=".age-ssp-repeat-", dir=repetition.parent)
    )
    try:
        write_bytes_exclusive(temporary / PARAMETERS_NAME, parameters.data)
        write_bytes_exclusive(temporary / SFR_NAME, sfr.data)
        write_bytes_exclusive(temporary / RUNTIME_NAME, runtime.data)
        write_bytes_exclusive(
            temporary / START_CHALLENGE_NAME, challenge_snapshot.data
        )
        write_bytes_exclusive(
            temporary / START_CHALLENGE_SIGNATURE_NAME,
            challenge_signature_snapshot.data,
        )
        write_bytes_exclusive(
            temporary / EXECUTION_RECORD_NAME, execution_record_snapshot.data
        )
        for name in SSP_MEMBERS:
            write_bytes_exclusive(temporary / name, ssp[name].data)
        write_manifest(temporary / SSP_MANIFEST_NAME, SSP_MEMBERS, temporary)
        provenance = {
            "schema_version": 1,
            "repeat_label": label,
            "execution_id": execution_id,
            "execution_environment": execution_environment,
            "run_started_utc": run_started_utc,
            "run_completed_utc": run_completed_utc,
            "generation_program": evidence(generation_program),
            "jj_source": jj_source,
            "padova_archive": contract["locked_inputs"]["padova_archive"],
            "padova_extraction": padova_extraction,
            "public_source": public,
            "private_source": private,
            "runtime_parameters": evidence(
                read_snapshot(temporary / PARAMETERS_NAME, "packaged parameters")
            ),
            "sfr_peaks_parameters": evidence(
                read_snapshot(temporary / SFR_NAME, "packaged SFR peaks")
            ),
            "numerical_runtime_manifest": evidence(
                read_snapshot(temporary / RUNTIME_NAME, "packaged runtime manifest")
            ),
            "ssp_manifest": evidence(
                read_snapshot(temporary / SSP_MANIFEST_NAME, "packaged SSP manifest")
            ),
            "start_challenge": evidence(
                read_snapshot(temporary / START_CHALLENGE_NAME, "packaged challenge")
            ),
            "start_challenge_signature": evidence(
                read_snapshot(
                    temporary / START_CHALLENGE_SIGNATURE_NAME,
                    "packaged start signature",
                )
            ),
            "execution_record": evidence(
                read_snapshot(
                    temporary / EXECUTION_RECORD_NAME, "packaged execution record"
                )
            ),
        }
        write_json_exclusive(temporary / PROVENANCE_NAME, provenance)
        write_manifest(
            temporary / REPETITION_MANIFEST_NAME,
            REPETITION_MANIFEST_MEMBERS,
            temporary,
        )
        attestation_snapshots = {
            name: read_snapshot(
                temporary / name, f"pre-attestation repetition file {name}"
            )
            for name in (*REPETITION_MANIFEST_MEMBERS, REPETITION_MANIFEST_NAME)
        }
        attestation_payload = attestation_body(
            contract,
            candidate,
            provenance,
            attestation_snapshots,
            signer["signer_id"],
            nonce_hex,
        )
        attestation = {
            "attestation_id": "sha256:"
            + hashlib.sha256(canonical_json_bytes(attestation_payload)).hexdigest(),
            **attestation_payload,
        }
        write_json_exclusive(temporary / ATTESTATION_NAME, attestation)
        sign_attestation(temporary / ATTESTATION_NAME, signing_key)
        if {path.name for path in temporary.iterdir()} != REPETITION_FILES:
            fail("generated SSP repetition root has an unexpected file set")
        os.replace(temporary, repetition)
        return inspect_repetition_root(repetition, contract, candidate)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        "--mode", required=True, choices=("verify", "qualify", "execute")
    )
    argument_parser.add_argument("--contract", required=True, type=Path)
    argument_parser.add_argument("--repetition-root", type=Path)
    argument_parser.add_argument("--qualification-report", type=Path)
    argument_parser.add_argument("--repeat-a-root", type=Path)
    argument_parser.add_argument("--repeat-b-root", type=Path)
    argument_parser.add_argument("--candidate-set-id")
    argument_parser.add_argument("--report-out", type=Path)
    argument_parser.add_argument("--jj-root", type=Path)
    argument_parser.add_argument("--jj-source-archive", type=Path)
    argument_parser.add_argument("--runtime-parameters", type=Path)
    argument_parser.add_argument("--sfr-peaks-parameters", type=Path)
    argument_parser.add_argument("--numerical-runtime-manifest", type=Path)
    argument_parser.add_argument("--padova-archive", type=Path)
    argument_parser.add_argument("--public-source-root", type=Path)
    argument_parser.add_argument("--public-repository")
    argument_parser.add_argument("--public-source-archive", type=Path)
    argument_parser.add_argument("--private-source-root", type=Path)
    argument_parser.add_argument("--private-repository")
    argument_parser.add_argument("--private-source-archive", type=Path)
    argument_parser.add_argument("--signer-id")
    argument_parser.add_argument("--signing-key", type=Path)
    argument_parser.add_argument("--repeat-label")
    argument_parser.add_argument("--execution-root", type=Path)
    argument_parser.add_argument("--out", type=Path)
    return argument_parser


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        if args.mode == "verify":
            if (
                args.repetition_root is None
                or args.qualification_report is None
            ):
                fail("verify mode requires --repetition-root and --qualification-report")
            result = verify_accepted_repetition(
                args.contract, args.qualification_report, args.repetition_root
            )
            print(
                "PASS age-cut SSP contract "
                f"({result['artifact_set_id']}; {len(result['ssp_member_sha256'])} files)"
            )
            return
        if args.mode == "qualify":
            required = {
                "repeat_a_root": args.repeat_a_root,
                "repeat_b_root": args.repeat_b_root,
                "candidate_set_id": args.candidate_set_id,
                "report_out": args.report_out,
            }
            missing = sorted(key for key, value in required.items() if value is None)
            if missing:
                fail(f"qualify mode lacks options: {missing}")
            report = qualify_repetitions(
                args.contract,
                args.repeat_a_root,
                args.repeat_b_root,
                args.candidate_set_id,
                args.report_out,
            )
            print(f"PASS age-cut SSP qualification ({report['qualification_id']})")
            return
        required = {
            "jj_root": args.jj_root,
            "jj_source_archive": args.jj_source_archive,
            "runtime_parameters": args.runtime_parameters,
            "sfr_peaks_parameters": args.sfr_peaks_parameters,
            "numerical_runtime_manifest": args.numerical_runtime_manifest,
            "padova_archive": args.padova_archive,
            "public_source_root": args.public_source_root,
            "public_repository": args.public_repository,
            "public_source_archive": args.public_source_archive,
            "private_source_root": args.private_source_root,
            "private_repository": args.private_repository,
            "private_source_archive": args.private_source_archive,
            "candidate_set_id": args.candidate_set_id,
            "signer_id": args.signer_id,
            "signing_key": args.signing_key,
            "repeat_label": args.repeat_label,
            "execution_root": args.execution_root,
            "out": args.out,
        }
        missing = sorted(key for key, value in required.items() if value is None)
        if missing:
            fail(f"execute mode lacks options: {missing}")
        result = execute_fresh_repetition(
            args.contract,
            jj_root=args.jj_root,
            jj_source_archive=args.jj_source_archive,
            runtime_parameters=args.runtime_parameters,
            sfr_peaks_parameters=args.sfr_peaks_parameters,
            numerical_runtime_manifest=args.numerical_runtime_manifest,
            padova_archive=args.padova_archive,
            public_source_root=args.public_source_root,
            public_repository=args.public_repository,
            public_source_archive=args.public_source_archive,
            private_source_root=args.private_source_root,
            private_repository=args.private_repository,
            private_source_archive=args.private_source_archive,
            candidate_set_id=args.candidate_set_id,
            signer_id=args.signer_id,
            signing_key=args.signing_key,
            repeat_label=args.repeat_label,
            execution_root=args.execution_root,
            output_root=args.out,
        )
        print(
            "PASS age-cut SSP controlled fresh repetition "
            f"({result['label']}; {len(result['ssp_member_sha256'])} files)"
        )
    except SSPContractError as exc:
        raise SystemExit(f"AGE CUT SSP CONTRACT FAIL: {exc}") from exc


if __name__ == "__main__":
    main()
