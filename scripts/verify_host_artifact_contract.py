#!/usr/bin/env python3
"""Verify or qualify the exact v4.0.4 JJ host-artifact contract.

Production verification is exact: an artifact is usable only when its full
parent table, canonical and legacy projections, summaries, auxiliary outputs,
runtime inputs, and exact manifests equal one production-accepted tuple.
Qualification requires two independently signed, controller-created fresh
executions from the same locked source archives and bit-identical outputs.
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
import base64
import copy
import csv
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable, Mapping
import types
import uuid
import zipfile


HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EXPECTED_CANONICAL_FILES = (
    "jj_g_hosts_radial_padova.csv",
    "jj_g_hosts_R_T_padova.csv",
    "jj_g_hosts_R_T_age_padova.csv",
    "jj_g_hosts_raw_eligible_padova.csv",
    "jj_g_hosts_summary_padova.json",
)
EXPECTED_MANIFEST = "SHA256SUMS_padova.txt"
EXPECTED_LEGACY_FILES = tuple(
    f"{Path(name).stem}_legacy_logg43{Path(name).suffix}"
    for name in EXPECTED_CANONICAL_FILES
)
EXPECTED_LEGACY_MANIFEST = "SHA256SUMS_padova_legacy_logg43.txt"
EXPECTED_PARENT_FILE = "jj_g_hosts_parent_prelogg_padova.csv"
EXPECTED_AUXILIARY_FILES = ("tams_ab_radial.csv", "tams_ab_results.json")
EXPECTED_PARENT_COLUMNS = (
    "R_kpc",
    "component",
    "age_Gyr",
    "FeH",
    "Mini",
    "Mf",
    "logL",
    "logT",
    "Teff_K",
    "logg",
    "N_surface_pc-2",
    "Rstar_g_Rsun",
    "Rstar_L_Rsun",
    "R_TAMS_Rsun",
    "A_logg",
    "B_TAMS_MS",
    "f_HZ",
    "f_earth10",
)
EXPECTED_SELECTOR_COLUMNS = {"canonical": "B_TAMS_MS", "legacy": "A_logg"}
FULL_RUNTIME_FILES = (
    "JJ_tutorial2_parameters_original.txt",
    "JJ_tutorial2_parameters_runtime.txt",
    "JJ_tutorial2_sfr_peaks_parameters.txt",
    "NUMERICAL_RUNTIME_POLICY.json",
)
HOST_REPETITION_MANIFEST = "SHA256SUMS_host_qualification_repetition.txt"
HOST_PROVENANCE_NAME = "HOST_RUN_PROVENANCE.json"
HOST_START_CHALLENGE_NAME = "HOST_RUN_START_CHALLENGE.json"
HOST_START_SIGNATURE_NAME = "HOST_RUN_START_CHALLENGE.sig"
HOST_EXECUTION_RECORD_NAME = "HOST_EXECUTION_RECORD.json"
HOST_ATTESTATION_NAME = "HOST_RUN_ATTESTATION.json"
HOST_ATTESTATION_SIGNATURE_NAME = "HOST_RUN_ATTESTATION.sig"
HOST_ATTESTATION_NAMESPACE = "exoearth-host-artifact-v4.0.4"
HOST_START_NAMESPACE = "exoearth-host-artifact-start-v4.0.4"
PADOVA_SHA256 = "97c8e09ea2669abe4147333f0fa141642e2c56d97b6f44de4e4518974ab7c7e8"
PADOVA_SIZE_BYTES = 327_078_533
PADOVA_FILENAME = "multiband_padova.zip"
JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
PARAMETERS_ORIGINAL_SHA256 = "e5919225b94e9ce8d8a7ad31553f0932bd437e2ae14f117dc39a37934e78a1c6"
PARAMETERS_RUNTIME_SHA256 = "0510dde5fb87a2a67c67c73200f07462b61cf024c0d16e0e41452a91f4ce5ad5"
SFR_SHA256 = "56d25b9ea61f454630a222ce6a6414bd1eaeb13bd165c25e9559ebe5c6b5039b"
PUBLIC_REPOSITORY = "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
PRIVATE_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production"
)
GENERATION_PROGRAMS = (
    "research/jj-host-export/run_jj_export.py",
    "research/jj-host-export/export_raw_eligible.py",
    "research/jj-host-export/tams_ab_test.py",
    "research/jj-host-export/promote_tams_provider.py",
    "research/jj-host-export/assert_canonical_tams.py",
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
EXPECTED_RAW_COLUMNS = (
    "R_kpc",
    "component",
    "Teff_K",
    "age_Gyr",
    "logg",
    "N_surface_pc-2",
)
IDENTITY_ALGORITHM = "utf8-json-string-arrays-v1"
SUMMARY_ALGORITHM = "utf8-json-sorted-top-level-exclusions-v1"
MAX_JSON_BYTES = 1_000_000
MAX_MANIFEST_BYTES = 10_000
MAX_CONTRACT_BYTES = 2_000_000
MAX_ARCHIVE_BYTES = 1_000_000_000
JJ_PARAMETERS_PATH = "jjmodel/tutorials/tutorial2/parameters"
JJ_SFR_PATH = "jjmodel/tutorials/tutorial2/sfrd_peaks_parameters"
EXPECTED_NUMERICAL_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}


class ContractError(RuntimeError):
    """Raised when an artifact or contract fails closed."""


def fail(message: str) -> None:
    raise ContractError(message)


@dataclass(frozen=True)
class FileSnapshot:
    """Stable bytes and identity captured by one regular-file read."""

    path: Path
    data: bytes
    sha256: str
    size_bytes: int


def read_file_snapshot(
    path: Path,
    description: str,
    *,
    maximum_bytes: int | None = None,
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
                fail(f"{description} opened object is not a regular file: {candidate}")
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
    except OSError as exc:
        fail(f"cannot read {description}: {exc}")
    try:
        after = candidate.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode):
        fail(f"{description} changed type while being read: {candidate}")
    identities = {
        (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
        )
        for observed in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1 or len(data) != opened_after.st_size:
        fail(f"{description} changed while it was being read: {candidate}")
    if maximum_bytes is not None and len(data) > maximum_bytes:
        fail(f"{description} exceeds {maximum_bytes} bytes: {candidate}")
    return FileSnapshot(
        path=candidate.resolve(),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def sha256_file(path: Path) -> str:
    return read_file_snapshot(path, "SHA-256 input").sha256


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_constant(token: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {token}")


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} must be a regular, non-symlink file: {path}")


def _require_directory(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_dir():
        fail(f"{description} must be a directory, not a symlink: {path}")


def load_json_bytes(data: bytes, description: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse strict UTF-8 JSON {description}: {exc}")


def load_json_snapshot(
    path: Path, *, maximum_bytes: int = MAX_JSON_BYTES
) -> tuple[Any, FileSnapshot]:
    snapshot = read_file_snapshot(
        path, "JSON file", maximum_bytes=maximum_bytes
    )
    return load_json_bytes(snapshot.data, str(snapshot.path)), snapshot


def load_json(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> Any:
    value, _ = load_json_snapshot(path, maximum_bytes=maximum_bytes)
    return value


def _controller_helper() -> tuple[types.ModuleType, FileSnapshot]:
    """Load hardened source/archive/signature primitives from one snapshot."""

    helper_path = Path(__file__).with_name("verify_age_cut_ssp_contract.py")
    snapshot = read_file_snapshot(
        helper_path,
        "host controller security helper",
        maximum_bytes=2_000_000,
    )
    module_name = f"_host_controller_helper_{snapshot.sha256}"
    module = types.ModuleType(module_name)
    module.__file__ = str(snapshot.path)
    module.__package__ = ""
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        exec(
            compile(snapshot.data, str(snapshot.path), "exec"),
            module.__dict__,
        )
    except BaseException as exc:
        fail(f"cannot load host controller security helper: {exc}")
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    return module, snapshot


def _helper_call(
    module: types.ModuleType, function: str, *args: Any, **kwargs: Any
) -> Any:
    try:
        return getattr(module, function)(*args, **kwargs)
    except Exception as exc:
        fail(f"host controller security check failed in {function}: {exc}")


def _safe_archive_parts(value: str, description: str) -> tuple[str, ...]:
    if "\\" in value or "\x00" in value:
        fail(f"{description} contains an unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"{description} contains traversal or an empty path")
    return path.parts


def _extract_git_tar(
    snapshot: FileSnapshot, destination: Path, description: str
) -> None:
    """Extract a Git tar snapshot while rejecting links and special members."""

    if destination.exists() or destination.is_symlink():
        fail(f"fresh {description} extraction root already exists")
    destination.mkdir(parents=True)
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(snapshot.data), mode="r:") as archive:
            for member in archive.getmembers():
                parts = _safe_archive_parts(member.name, description)
                normalized = PurePosixPath(*parts).as_posix()
                if normalized in seen:
                    fail(f"{description} archive contains duplicate members")
                seen.add(normalized)
                target = destination.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    fail(f"{description} archive contains a link or special member")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read {description} archive member")
                data = source.read()
                if len(data) != member.size:
                    fail(f"truncated {description} archive member")
                if target.exists() or target.is_symlink():
                    fail(f"duplicate extracted {description} path")
                with target.open("xb") as handle:
                    handle.write(data)
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot extract {description} archive: {exc}")


def _extract_padova_zip(
    snapshot: FileSnapshot, jj_root: Path
) -> dict[str, Any]:
    destination_relative = PurePosixPath("jjmodel/input/isochrones/Padova")
    destination = jj_root.joinpath(*destination_relative.parts)
    if destination.exists() or destination.is_symlink():
        fail("clean JJ archive unexpectedly already contains Padova output")
    destination.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(snapshot.data)) as archive:
            for member in archive.infolist():
                parts = _safe_archive_parts(member.filename, "Padova ZIP")
                normalized = PurePosixPath(*parts).as_posix()
                if normalized in seen:
                    fail("Padova ZIP contains duplicate member paths")
                seen.add(normalized)
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    fail("Padova ZIP contains a symbolic link")
                target = destination.joinpath(*parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    fail("duplicate extracted Padova path")
                data = archive.read(member)
                if len(data) != member.file_size:
                    fail("truncated Padova ZIP member")
                with target.open("xb") as handle:
                    handle.write(data)
                records.append(
                    {
                        "path": (destination_relative / normalized).as_posix(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                    }
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        fail(f"cannot extract locked Padova ZIP: {exc}")
    if not records:
        fail("locked Padova ZIP contains no regular files")
    records.sort(key=lambda item: item["path"])
    return {
        "root_relative_path": destination_relative.as_posix(),
        "member_count": len(records),
        "tree_sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
    }


def _derive_runtime_parameters(original: bytes) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeError as exc:
        fail(f"cannot decode locked JJ tutorial parameters: {exc}")
    substitutions = (
        (r"^(Rmin[\t ]+)4([\t ])", r"\g<1>4.0\g<2>"),
        (r"^(Rmax[\t ]+)14([\t ])", r"\g<1>14.0\g<2>"),
        (r"^(dR[\t ]+)1([\t ])", r"\g<1>0.5\g<2>"),
        (r"^(nprocess[\t ]+)4([\t ])", r"\g<1>2\g<2>"),
    )
    for pattern, replacement in substitutions:
        text, count = re.subn(
            pattern, replacement, text, count=1, flags=re.MULTILINE
        )
        if count != 1:
            fail(f"locked JJ parameter transformation did not match {pattern!r}")
    derived = text.encode("utf-8")
    if hashlib.sha256(derived).hexdigest() != PARAMETERS_RUNTIME_SHA256:
        fail("derived JJ runtime parameter bytes differ from the release lock")
    return derived


def _runtime_executable_chain(path_value: str) -> dict[str, Any]:
    requested = Path(path_value)
    if not requested.is_absolute():
        fail("numerical-runtime Python executable path must be absolute")
    current = requested
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    for _ in range(16):
        canonical = os.path.normcase(str(current.absolute()))
        if canonical in seen:
            fail("numerical-runtime Python executable symlink chain contains a cycle")
        seen.add(canonical)
        try:
            before = current.lstat()
        except OSError as exc:
            fail(f"cannot inspect numerical-runtime Python executable: {exc}")
        if stat.S_ISLNK(before.st_mode):
            try:
                first_target = os.readlink(current)
                after = current.lstat()
                second_target = os.readlink(current)
            except OSError as exc:
                fail(f"cannot read numerical-runtime Python symlink: {exc}")
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if before_identity != after_identity or first_target != second_target:
                fail("numerical-runtime Python symlink changed during inspection")
            links.append({"path": str(current.absolute()), "target": first_target})
            target = Path(first_target)
            current = target if target.is_absolute() else current.parent / target
            current = Path(os.path.normpath(current))
            continue
        final = read_file_snapshot(
            current, "numerical-runtime Python executable target"
        )
        return {
            "requested_path": str(requested),
            "links": links,
            "final_path": str(final.path),
            "final_file": _evidence(final),
        }
    fail("numerical-runtime Python executable symlink chain is too deep")


def _validate_runtime_executable_record(value: Any) -> dict[str, Any]:
    record = _require_exact_keys(
        value,
        {"requested_path", "links", "final_path", "final_file"},
        "host runtime executable record",
    )
    for key in ("requested_path", "final_path"):
        if not isinstance(record[key], str) or not record[key] or "\x00" in record[key]:
            fail(f"host runtime executable {key} is invalid")
    links = record["links"]
    if not isinstance(links, list) or len(links) > 16:
        fail("host runtime executable link chain is invalid")
    for item in links:
        item = _require_exact_keys(
            item, {"path", "target"}, "host runtime executable symlink"
        )
        if not all(
            isinstance(item[key], str) and item[key] and "\x00" not in item[key]
            for key in ("path", "target")
        ):
            fail("host runtime executable symlink record is invalid")
    final_name = Path(record["final_path"]).name
    _validate_evidence_record(
        record["final_file"], final_name, "host runtime executable final file"
    )
    return record


def _require_exact_keys(
    value: Any, expected: set[str], description: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    observed = set(value)
    if observed != expected:
        fail(
            f"{description} keys differ: missing={sorted(expected - observed)}, "
            f"extra={sorted(observed - expected)}"
        )
    return value


def _require_hex(value: Any, description: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{description} must be lowercase 64-hex SHA-256")
    return value


def _require_safe_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        fail(f"{description} is not a safe identifier")
    return value


def _is_portable_safe_leaf(value: Any) -> bool:
    """Return true only for one path leaf under both POSIX and Windows rules."""

    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "\x00" not in value
        and "/" not in value
        and "\\" not in value
        and ":" not in value
        and PurePosixPath(value).name == value
        and PureWindowsPath(value).name == value
    )


def _host_exact_repeat_files() -> list[str]:
    return [
        EXPECTED_PARENT_FILE,
        EXPECTED_MANIFEST,
        *EXPECTED_CANONICAL_FILES,
        EXPECTED_LEGACY_MANIFEST,
        *EXPECTED_LEGACY_FILES,
        *EXPECTED_AUXILIARY_FILES,
        *FULL_RUNTIME_FILES,
    ]


def _validate_signers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != 2:
        fail("host qualification must pin exactly two attestation signers")
    signers: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        signer = _require_exact_keys(
            raw, {"signer_id", "public_key"}, f"attestation_signers[{index}]"
        )
        identifier = _require_safe_id(
            signer["signer_id"], f"attestation_signers[{index}].signer_id"
        )
        public_key = signer["public_key"]
        if (
            not isinstance(public_key, str)
            or not public_key.startswith("ssh-ed25519 ")
            or "\n" in public_key
            or "\r" in public_key
        ):
            fail("host attestation public key must be one Ed25519 public-key line")
        signers.append({"signer_id": identifier, "public_key": public_key})
    if len({item["signer_id"] for item in signers}) != 2 or len(
        {item["public_key"] for item in signers}
    ) != 2:
        fail("host attestation signer ids and public keys must be distinct")
    return signers


def _validate_full_artifact_contract(value: Any) -> dict[str, Any]:
    full = _require_exact_keys(
        value,
        {
            "schema_version",
            "parent_file",
            "parent_columns",
            "projection_columns",
            "selector_columns",
            "canonical_manifest_name",
            "canonical_files",
            "legacy_manifest_name",
            "legacy_files",
            "auxiliary_files",
            "runtime_files",
            "repetition_manifest_name",
            "provenance_files",
            "locked_inputs",
            "attestation_signers",
            "qualification_policy",
            "accepted_tuple",
        },
        "full_artifact_contract",
    )
    if type(full["schema_version"]) is not int or full["schema_version"] != 1:
        fail("unsupported full host-artifact contract schema")
    expected_scalars = {
        "parent_file": EXPECTED_PARENT_FILE,
        "canonical_manifest_name": EXPECTED_MANIFEST,
        "legacy_manifest_name": EXPECTED_LEGACY_MANIFEST,
        "repetition_manifest_name": HOST_REPETITION_MANIFEST,
    }
    for key, expected in expected_scalars.items():
        if full[key] != expected:
            fail(f"full_artifact_contract.{key} changed")
    expected_lists = {
        "parent_columns": list(EXPECTED_PARENT_COLUMNS),
        "projection_columns": list(EXPECTED_RAW_COLUMNS),
        "canonical_files": list(EXPECTED_CANONICAL_FILES),
        "legacy_files": list(EXPECTED_LEGACY_FILES),
        "auxiliary_files": list(EXPECTED_AUXILIARY_FILES),
        "runtime_files": list(FULL_RUNTIME_FILES),
        "provenance_files": [
            HOST_PROVENANCE_NAME,
            HOST_START_CHALLENGE_NAME,
            HOST_START_SIGNATURE_NAME,
            HOST_EXECUTION_RECORD_NAME,
            HOST_ATTESTATION_NAME,
            HOST_ATTESTATION_SIGNATURE_NAME,
        ],
    }
    for key, expected in expected_lists.items():
        if full[key] != expected:
            fail(f"full_artifact_contract.{key} order or set changed")
    if full["selector_columns"] != EXPECTED_SELECTOR_COLUMNS:
        fail("full host parent-selector mapping changed")
    locked = _require_exact_keys(
        full["locked_inputs"],
        {
            "jj_repository",
            "jj_commit",
            "public_repository",
            "private_repository",
            "padova_archive",
            "parameters_original_sha256",
            "parameters_runtime_sha256",
            "sfr_peaks_parameters_sha256",
            "generation_programs",
        },
        "full host locked_inputs",
    )
    if (
        locked["jj_repository"] != "askenja/jjmodel"
        or locked["jj_commit"] != JJ_SHA
        or locked["public_repository"] != PUBLIC_REPOSITORY
        or locked["private_repository"] != PRIVATE_REPOSITORY
        or locked["parameters_original_sha256"] != PARAMETERS_ORIGINAL_SHA256
        or locked["parameters_runtime_sha256"] != PARAMETERS_RUNTIME_SHA256
        or locked["sfr_peaks_parameters_sha256"] != SFR_SHA256
        or locked["generation_programs"] != list(GENERATION_PROGRAMS)
    ):
        fail("full host locked source/input tuple changed")
    if locked["padova_archive"] != {
        "data_lock_id": "jj_padova_multiband_archive",
        "filename": PADOVA_FILENAME,
        "sha256": PADOVA_SHA256,
        "size_bytes": PADOVA_SIZE_BYTES,
    }:
        fail("full host Padova archive lock changed")
    signers = _validate_signers(full["attestation_signers"])
    if signers != list(PINNED_SIGNERS):
        fail("full host attestation signer tuple differs from the pinned keys")
    policy = _require_exact_keys(
        full["qualification_policy"],
        {
            "required_distinct_fresh_repetitions",
            "required_distinct_signers",
            "nonce_bytes",
            "attestation_namespace",
            "start_challenge_namespace",
            "fresh_execution_controller",
            "generation_argv_mode",
            "require_controller_created_empty_roots",
            "require_signed_pre_run_challenge",
            "require_signed_completion_attestation",
            "require_exact_clean_source_archives",
            "require_exact_padova_extraction",
            "require_runtime_executable_chain",
            "require_identical_source_state",
            "require_bit_identical_host_tuple",
            "public_report_contains_row_level_hosts",
            "allowed_execution_environments",
            "exact_repeat_files",
        },
        "full host qualification policy",
    )
    expected_policy = {
        "required_distinct_fresh_repetitions": 2,
        "required_distinct_signers": 2,
        "nonce_bytes": 32,
        "attestation_namespace": HOST_ATTESTATION_NAMESPACE,
        "start_challenge_namespace": HOST_START_NAMESPACE,
        "fresh_execution_controller": (
            "verify_host_artifact_contract.execute_fresh_repetition"
        ),
        "generation_argv_mode": "subprocess_no_shell_exact_pinned",
        "require_controller_created_empty_roots": True,
        "require_signed_pre_run_challenge": True,
        "require_signed_completion_attestation": True,
        "require_exact_clean_source_archives": True,
        "require_exact_padova_extraction": True,
        "require_runtime_executable_chain": True,
        "require_identical_source_state": True,
        "require_bit_identical_host_tuple": True,
        "public_report_contains_row_level_hosts": False,
        "allowed_execution_environments": [
            "local_ubuntu_22_04_wsl2",
            "github_actions_ubuntu_22_04",
        ],
        "exact_repeat_files": _host_exact_repeat_files(),
    }
    if policy != expected_policy:
        fail("full host qualification policy changed")
    accepted = full["accepted_tuple"]
    if accepted is not None:
        accepted = _validate_accepted_tuple(accepted)
        if {item["signer_id"] for item in accepted["attestation_signers"]} != {
            item["signer_id"] for item in signers
        }:
            fail("accepted full-host tuple signer set differs from the contract")
    return full


def _nested_value(document: dict[str, Any], dotted_path: str) -> tuple[bool, Any]:
    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _same_json_scalar(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    return left == right


def artifact_set_by_id(
    contract: dict[str, Any], identifier: str
) -> dict[str, Any]:
    matches = [
        item for item in contract["artifact_sets"] if item["id"] == identifier
    ]
    if len(matches) != 1:
        fail(f"artifact-set id is not unique and known: {identifier!r}")
    return matches[0]


def validate_contract(document: Any) -> dict[str, Any]:
    contract = _require_exact_keys(
        document,
        {
            "schema_version",
            "contract_id",
            "manifest_name",
            "canonical_files",
            "raw_file",
            "summary_file",
            "raw_schema",
            "identity_projection",
            "summary_projection",
            "summary_required_values",
            "forbidden_summary_paths",
            "artifact_sets",
            "qualification_policy",
            "full_artifact_contract",
        },
        "contract",
    )
    if contract["schema_version"] != 1:
        fail("unsupported contract schema_version")
    _require_safe_id(contract["contract_id"], "contract_id")
    if contract["manifest_name"] != EXPECTED_MANIFEST:
        fail("unexpected manifest_name")
    if contract["canonical_files"] != list(EXPECTED_CANONICAL_FILES):
        fail("canonical file order or set changed")
    if contract["raw_file"] != EXPECTED_CANONICAL_FILES[3]:
        fail("unexpected raw_file")
    if contract["summary_file"] != EXPECTED_CANONICAL_FILES[4]:
        fail("unexpected summary_file")

    raw_schema = _require_exact_keys(
        contract["raw_schema"],
        {"columns", "row_count", "weight_column"},
        "raw_schema",
    )
    if raw_schema["columns"] != list(EXPECTED_RAW_COLUMNS):
        fail("raw CSV schema changed")
    if (
        not isinstance(raw_schema["row_count"], int)
        or raw_schema["row_count"] <= 0
    ):
        fail("raw_schema.row_count must be a positive integer")
    if raw_schema["weight_column"] != EXPECTED_RAW_COLUMNS[-1]:
        fail("unexpected weight column")

    identity = _require_exact_keys(
        contract["identity_projection"],
        {
            "algorithm",
            "columns",
            "encoding",
            "csv_dialect",
            "row_serialization",
            "numeric_text_rule",
            "record_terminator",
            "sha256",
        },
        "identity_projection",
    )
    if identity["algorithm"] != IDENTITY_ALGORITHM:
        fail("unsupported identity projection algorithm")
    if identity["columns"] != list(EXPECTED_RAW_COLUMNS[:-1]):
        fail("identity projection columns changed")
    if identity["encoding"] != "UTF-8":
        fail("identity projection encoding changed")
    if (
        identity["csv_dialect"]
        != "Python csv.excel with newline='' and UTF-8 decoding"
    ):
        fail("identity CSV dialect changed")
    if (
        identity["row_serialization"]
        != "compact JSON array of original CSV field strings"
    ):
        fail("identity row serialization description changed")
    if (
        identity["numeric_text_rule"]
        != "preserve decoded CSV field strings exactly; no numeric parsing "
        "or reformatting"
    ):
        fail("identity numeric-text rule changed")
    if identity["record_terminator"] != "LF after every row":
        fail("identity record terminator changed")
    _require_hex(identity["sha256"], "identity_projection.sha256")

    summary = _require_exact_keys(
        contract["summary_projection"],
        {
            "algorithm",
            "encoding",
            "input_rule",
            "number_rule",
            "excluded_top_level_keys",
            "serialization",
            "sha256",
        },
        "summary_projection",
    )
    if summary["algorithm"] != SUMMARY_ALGORITHM:
        fail("unsupported summary projection algorithm")
    if summary["encoding"] != "UTF-8":
        fail("summary projection encoding changed")
    if (
        summary["input_rule"]
        != "strict JSON; duplicate keys and non-finite constants rejected"
    ):
        fail("summary input rule changed")
    if (
        summary["number_rule"]
        != "Python 3.10 json numeric parse and json.dumps emission; "
        "no numeric coercion"
    ):
        fail("summary numeric rule changed")
    if summary["excluded_top_level_keys"] != [
        "python",
        "tams_transfer_assumption",
    ]:
        fail("summary projection exclusions changed")
    if (
        summary["serialization"]
        != "JSON sort_keys=true, ensure_ascii=false, separators=(',',':'), "
        "allow_nan=false"
    ):
        fail("summary serialization description changed")
    _require_hex(summary["sha256"], "summary_projection.sha256")

    required_values = contract["summary_required_values"]
    if not isinstance(required_values, dict) or not required_values:
        fail("summary_required_values must be a non-empty object")
    forbidden = contract["forbidden_summary_paths"]
    if not isinstance(forbidden, list) or not all(
        isinstance(item, str) and item for item in forbidden
    ):
        fail("forbidden_summary_paths must contain non-empty strings")
    full_contract = _validate_full_artifact_contract(
        contract["full_artifact_contract"]
    )

    artifact_sets = contract["artifact_sets"]
    if not isinstance(artifact_sets, list) or not artifact_sets:
        fail("artifact_sets must be a non-empty array")
    identifiers: set[str] = set()
    baseline_count = 0
    for index, value in enumerate(artifact_sets):
        artifact_set = _require_exact_keys(
            value,
            {
                "id",
                "role",
                "production_accepted",
                "qualification_eligible",
                "manifest_sha256",
                "file_sha256",
                "summary_sha256_without_python",
                "qualification_report",
                "note",
            },
            f"artifact_sets[{index}]",
        )
        identifier = _require_safe_id(
            artifact_set["id"], f"artifact_sets[{index}].id"
        )
        if identifier in identifiers:
            fail(f"duplicate artifact-set id: {identifier}")
        identifiers.add(identifier)
        if artifact_set["role"] not in {
            "historical_baseline",
            "diagnostic_candidate",
            "qualified_candidate",
        }:
            fail(f"invalid artifact-set role: {artifact_set['role']!r}")
        if artifact_set["role"] == "historical_baseline":
            baseline_count += 1
        if type(artifact_set["production_accepted"]) is not bool:
            fail("production_accepted must be Boolean")
        if type(artifact_set["qualification_eligible"]) is not bool:
            fail("qualification_eligible must be Boolean")
        _require_hex(
            artifact_set["manifest_sha256"], f"{identifier}.manifest_sha256"
        )
        file_hashes = artifact_set["file_sha256"]
        if (
            not isinstance(file_hashes, dict)
            or list(file_hashes) != list(EXPECTED_CANONICAL_FILES)
        ):
            fail(
                f"{identifier}.file_sha256 must use the exact canonical "
                "order and set"
            )
        for filename, digest in file_hashes.items():
            _require_hex(digest, f"{identifier}.file_sha256[{filename!r}]")
        _require_hex(
            artifact_set["summary_sha256_without_python"],
            f"{identifier}.summary_sha256_without_python",
        )
        if not isinstance(artifact_set["note"], str) or not artifact_set["note"]:
            fail(f"{identifier}.note must be non-empty")
        evidence = artifact_set["qualification_report"]
        if artifact_set["role"] == "historical_baseline":
            if artifact_set["qualification_eligible"]:
                fail("historical baseline cannot be a fresh candidate")
            if evidence is not None:
                fail("historical baseline must not claim a qualification report")
        elif artifact_set["production_accepted"]:
            if (
                artifact_set["role"] != "qualified_candidate"
                or not artifact_set["qualification_eligible"]
            ):
                fail(
                    "an accepted non-baseline set must be an eligible, "
                    "qualified candidate"
                )
            evidence = _require_exact_keys(
                evidence,
                {"path", "sha256"},
                f"{identifier}.qualification_report",
            )
            if not _is_portable_safe_leaf(evidence["path"]):
                fail("qualification-report path must be one safe basename")
            _require_hex(
                evidence["sha256"],
                f"{identifier}.qualification_report.sha256",
            )
        elif evidence is not None:
            fail("non-accepted candidate must not claim qualification evidence")
    if baseline_count != 1:
        fail("contract must contain exactly one historical baseline")
    accepted_sets = [
        item for item in artifact_sets if item["production_accepted"] is True
    ]
    if accepted_sets and full_contract["accepted_tuple"] is None:
        fail("a production-accepted host set requires an accepted full-host tuple")
    if len(accepted_sets) > 1:
        fail("at most one host artifact set may be production accepted")
    if accepted_sets:
        accepted_set = accepted_sets[0]
        accepted_tuple = full_contract["accepted_tuple"]
        if (
            accepted_tuple["canonical_manifest"]["sha256"]
            != accepted_set["manifest_sha256"]
            or {
                name: accepted_tuple["canonical_files"][name]["sha256"]
                for name in EXPECTED_CANONICAL_FILES
            }
            != accepted_set["file_sha256"]
        ):
            fail("accepted full-host tuple differs from the accepted canonical set")

    policy = _require_exact_keys(
        contract["qualification_policy"],
        {
            "baseline_artifact_set_id",
            "required_distinct_fresh_repetitions",
            "exact_repeat_files",
            "require_exact_identity_projection",
            "require_exact_summary_projection",
            "numeric_weight_comparison",
        },
        "qualification_policy",
    )
    if policy["baseline_artifact_set_id"] not in identifiers:
        fail("qualification baseline id is unknown")
    baseline = artifact_set_by_id(
        contract, policy["baseline_artifact_set_id"]
    )
    if baseline["role"] != "historical_baseline":
        fail("qualification baseline must be the historical baseline")
    if policy["required_distinct_fresh_repetitions"] != 2:
        fail("qualification must require exactly two fresh repetitions")
    if policy["exact_repeat_files"] != [
        EXPECTED_MANIFEST,
        *EXPECTED_CANONICAL_FILES,
    ]:
        fail("qualification exact-repeat set changed")
    if policy["require_exact_identity_projection"] is not True:
        fail("qualification must require exact row identity and order")
    if policy["require_exact_summary_projection"] is not True:
        fail("qualification must require the exact science-summary projection")
    numeric = _require_exact_keys(
        policy["numeric_weight_comparison"],
        {"column", "relative_tolerance", "absolute_tolerance"},
        "numeric_weight_comparison",
    )
    if numeric["column"] != EXPECTED_RAW_COLUMNS[-1]:
        fail("qualification may compare only the weight column numerically")
    for key in ("relative_tolerance", "absolute_tolerance"):
        value = numeric[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            fail(f"{key} must be numeric")
        if not math.isfinite(float(value)) or value < 0:
            fail(f"{key} must be finite and non-negative")
    if (
        numeric["relative_tolerance"] > 1e-12
        or numeric["absolute_tolerance"] > 0
    ):
        fail("qualification tolerance is broader than the audited limit")
    return contract


def load_contract(path: Path) -> dict[str, Any]:
    document, _ = load_json_snapshot(path)
    contract = validate_contract(document)
    for artifact_set in contract["artifact_sets"]:
        if (
            artifact_set["production_accepted"]
            and artifact_set["role"] != "historical_baseline"
        ):
            _validate_qualification_report(path, contract, artifact_set)
    return contract


def read_manifest(
    root: Path, contract: dict[str, Any]
) -> tuple[dict[str, str], FileSnapshot, dict[str, FileSnapshot]]:
    manifest = root / contract["manifest_name"]
    manifest_snapshot = read_file_snapshot(
        manifest, "host manifest", maximum_bytes=MAX_MANIFEST_BYTES
    )
    try:
        lines = manifest_snapshot.data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot read host manifest: {exc}")
    if len(lines) != len(EXPECTED_CANONICAL_FILES):
        fail("host manifest does not contain exactly five canonical entries")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line
        )
        if match is None:
            fail(f"invalid host-manifest line {line_number}: {line!r}")
        digest, filename = match.groups()
        if not _is_portable_safe_leaf(filename):
            fail(f"unsafe host-manifest filename: {filename!r}")
        if filename in entries:
            fail(f"duplicate host-manifest filename: {filename}")
        entries[filename] = digest
    if list(entries) != list(EXPECTED_CANONICAL_FILES):
        fail("host manifest order or canonical file set changed")
    snapshots: dict[str, FileSnapshot] = {}
    for filename, expected in entries.items():
        path = root / filename
        snapshot = read_file_snapshot(path, f"manifest target {filename}")
        if snapshot.sha256 != expected:
            fail(
                f"manifest target hash mismatch for {filename}: "
                f"{snapshot.sha256} != {expected}"
            )
        snapshots[filename] = snapshot
    return entries, manifest_snapshot, snapshots


def identity_projection_snapshot(
    snapshot: FileSnapshot, contract: dict[str, Any]
) -> tuple[str, int, list[float]]:
    columns = contract["identity_projection"]["columns"]
    weight_column = contract["raw_schema"]["weight_column"]
    digest = hashlib.sha256()
    weights: list[float] = []
    try:
        with io.StringIO(snapshot.data.decode("utf-8"), newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != list(EXPECTED_RAW_COLUMNS):
                fail(f"raw CSV columns differ: {reader.fieldnames!r}")
            for row_number, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    fail(f"malformed raw CSV row {row_number}")
                record = (
                    canonical_json_bytes([row[column] for column in columns])
                    + b"\n"
                )
                digest.update(record)
                try:
                    weight = float(row[weight_column])
                except ValueError:
                    fail(f"non-numeric host weight at row {row_number}")
                if not math.isfinite(weight) or weight < 0:
                    fail(
                        f"invalid host weight at row {row_number}: {weight!r}"
                    )
                weights.append(weight)
    except (UnicodeError, csv.Error) as exc:
        fail(f"cannot parse raw host CSV: {exc}")
    return digest.hexdigest(), len(weights), weights


def identity_projection(
    path: Path, contract: dict[str, Any]
) -> tuple[str, int, list[float]]:
    return identity_projection_snapshot(
        read_file_snapshot(path, "raw host table"), contract
    )


def summary_projection_snapshot(
    snapshot: FileSnapshot, contract: dict[str, Any]
) -> tuple[str, str]:
    summary = load_json_bytes(snapshot.data, str(snapshot.path))
    if not isinstance(summary, dict):
        fail("host summary must be a JSON object")
    for dotted_path, expected in contract["summary_required_values"].items():
        present, observed = _nested_value(summary, dotted_path)
        if not present or not _same_json_scalar(observed, expected):
            fail(
                f"host summary invariant mismatch at {dotted_path}: "
                f"{observed!r} != {expected!r}"
            )
    for dotted_path in contract["forbidden_summary_paths"]:
        present, _ = _nested_value(summary, dotted_path)
        if present:
            fail(f"forbidden host-summary path is present: {dotted_path}")
    semantic = dict(summary)
    semantic.pop("python", None)
    semantic_sha256 = hashlib.sha256(
        canonical_json_bytes(semantic)
    ).hexdigest()
    projected = dict(summary)
    for key in contract["summary_projection"]["excluded_top_level_keys"]:
        projected.pop(key, None)
    science_sha256 = hashlib.sha256(
        canonical_json_bytes(projected)
    ).hexdigest()
    return science_sha256, semantic_sha256


def summary_projection(
    path: Path, contract: dict[str, Any]
) -> tuple[str, str]:
    return summary_projection_snapshot(
        read_file_snapshot(path, "host summary", maximum_bytes=MAX_JSON_BYTES),
        contract,
    )


def _evidence(snapshot: FileSnapshot) -> dict[str, Any]:
    return {
        "filename": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
    }


def _validate_evidence_record(
    value: Any, expected_name: str, description: str
) -> dict[str, Any]:
    record = _require_exact_keys(
        value, {"filename", "sha256", "size_bytes"}, description
    )
    if record["filename"] != expected_name:
        fail(f"{description} filename changed")
    _require_hex(record["sha256"], f"{description} SHA-256")
    if type(record["size_bytes"]) is not int or record["size_bytes"] <= 0:
        fail(f"{description} size must be a positive integer")
    return record


def _read_exact_manifest(
    root: Path, manifest_name: str, filenames: tuple[str, ...], description: str
) -> tuple[FileSnapshot, dict[str, FileSnapshot]]:
    manifest = read_file_snapshot(
        root / manifest_name, f"{description} manifest", maximum_bytes=MAX_MANIFEST_BYTES
    )
    try:
        lines = manifest.data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode {description} manifest: {exc}")
    if len(lines) != len(filenames):
        fail(f"{description} manifest file count changed")
    entries: list[tuple[str, str]] = []
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None:
            fail(f"malformed {description} manifest line {line_number}")
        digest, filename = match.groups()
        if not _is_portable_safe_leaf(filename):
            fail(f"unsafe {description} manifest filename")
        entries.append((filename, digest))
    if [name for name, _ in entries] != list(filenames):
        fail(f"{description} manifest order or exact file set changed")
    snapshots: dict[str, FileSnapshot] = {}
    for filename, digest in entries:
        snapshot = read_file_snapshot(root / filename, f"{description} target {filename}")
        if snapshot.sha256 != digest:
            fail(f"{description} manifest target hash mismatch for {filename}")
        snapshots[filename] = snapshot
    return manifest, snapshots


def _read_csv_rows(
    snapshot: FileSnapshot, expected_columns: tuple[str, ...], description: str
) -> list[dict[str, str]]:
    try:
        text = snapshot.data.decode("utf-8")
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != expected_columns:
            fail(f"{description} column order or schema changed")
        rows = list(reader)
    except csv.Error as exc:
        fail(f"cannot parse {description}: {exc}")
    if not rows:
        fail(f"{description} is empty")
    for index, row in enumerate(rows):
        if set(row) != set(expected_columns) or None in row or any(
            value is None for value in row.values()
        ):
            fail(f"malformed {description} row {index}")
    return rows


def _finite_csv_number(value: str, description: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        fail(f"invalid numeric {description}: {exc}")
    if not math.isfinite(number):
        fail(f"non-finite numeric {description}")
    return number


def _projection_digest(rows: list[list[Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(canonical_json_bytes(row))
        digest.update(b"\n")
    return digest.hexdigest()


def _validate_parent_and_projection(
    parent_snapshot: FileSnapshot,
    raw_snapshots: dict[str, FileSnapshot],
) -> tuple[dict[str, Any], dict[str, Any]]:
    parent_rows = _read_csv_rows(
        parent_snapshot, EXPECTED_PARENT_COLUMNS, "full parent host table"
    )
    numeric_parent = [name for name in EXPECTED_PARENT_COLUMNS if name != "component"]
    parsed_parent: list[dict[str, Any]] = []
    for index, row in enumerate(parent_rows):
        if row["component"] not in {"thin", "thick"}:
            fail(f"invalid parent component at row {index}")
        parsed = {
            name: _finite_csv_number(row[name], f"parent {name} row {index}")
            for name in numeric_parent
        }
        parsed["component"] = row["component"]
        for selector in ("A_logg", "B_TAMS_MS"):
            if parsed[selector] not in {0.0, 1.0}:
                fail(f"parent selector {selector} is not exactly binary at row {index}")
        expected_legacy = 4.3 < parsed["logg"] < 7.0
        expected_canonical = (
            parsed["Rstar_g_Rsun"] <= parsed["R_TAMS_Rsun"]
            and parsed["logg"] < 7.0
        )
        if bool(parsed["A_logg"]) != expected_legacy:
            fail(f"parent legacy selector identity failed at row {index}")
        if bool(parsed["B_TAMS_MS"]) != expected_canonical:
            fail(f"parent canonical selector identity failed at row {index}")
        parsed_parent.append(parsed)

    projection_evidence: dict[str, Any] = {}
    raw_evidence: dict[str, Any] = {}
    for selector in ("canonical", "legacy"):
        selector_column = EXPECTED_SELECTOR_COLUMNS[selector]
        expected = [row for row in parsed_parent if row[selector_column] == 1.0]
        observed_text = _read_csv_rows(
            raw_snapshots[selector], EXPECTED_RAW_COLUMNS, f"{selector} raw hosts"
        )
        if len(expected) != len(observed_text):
            fail(f"{selector} raw rows are not the exact parent projection")
        projected_rows: list[list[Any]] = []
        identity_rows: list[list[Any]] = []
        weights: list[float] = []
        for index, (parent_row, raw_row) in enumerate(zip(expected, observed_text)):
            if raw_row["component"] != parent_row["component"]:
                fail(f"{selector} raw component differs from parent at row {index}")
            values: list[Any] = []
            identities: list[Any] = []
            for column in EXPECTED_RAW_COLUMNS:
                if column == "component":
                    value: Any = raw_row[column]
                else:
                    value = _finite_csv_number(
                        raw_row[column], f"{selector} raw {column} row {index}"
                    )
                    if value != parent_row[column]:
                        fail(
                            f"{selector} raw numerical value differs from parent at "
                            f"row {index}, column {column}"
                        )
                values.append(value)
                if column != "N_surface_pc-2":
                    identities.append(value)
            projected_rows.append(values)
            identity_rows.append(identities)
            weights.append(float(values[-1]))
        projection_evidence[selector] = {
            "selector_column": selector_column,
            "row_count": len(projected_rows),
            "identity_sha256": _projection_digest(identity_rows),
            "value_sha256": _projection_digest(projected_rows),
            "weight_sum": math.fsum(weights),
        }
        raw_evidence[selector] = {
            **_evidence(raw_snapshots[selector]),
            "row_count": len(projected_rows),
        }
    parent_evidence = {
        **_evidence(parent_snapshot),
        "row_count": len(parent_rows),
    }
    return parent_evidence, {"raw": raw_evidence, "projections": projection_evidence}


def _validate_projection_record(value: Any, selector: str) -> dict[str, Any]:
    record = _require_exact_keys(
        value,
        {"selector_column", "row_count", "identity_sha256", "value_sha256", "weight_sum"},
        f"accepted {selector} projection",
    )
    if record["selector_column"] != EXPECTED_SELECTOR_COLUMNS[selector]:
        fail(f"accepted {selector} selector column changed")
    if type(record["row_count"]) is not int or record["row_count"] <= 0:
        fail(f"accepted {selector} projection row count is invalid")
    _require_hex(record["identity_sha256"], f"accepted {selector} identity")
    _require_hex(record["value_sha256"], f"accepted {selector} values")
    weight = record["weight_sum"]
    if (
        isinstance(weight, bool)
        or not isinstance(weight, (int, float))
        or not math.isfinite(float(weight))
        or weight < 0
    ):
        fail(f"accepted {selector} projection weight sum is invalid")
    return record


def _validate_accepted_tuple(value: Any) -> dict[str, Any]:
    accepted = _require_exact_keys(
        value,
        {
            "schema_version",
            "parent",
            "canonical_manifest",
            "canonical_files",
            "legacy_manifest",
            "legacy_files",
            "auxiliary_files",
            "runtime_files",
            "projections",
            "attestation_signers",
        },
        "accepted full-host tuple",
    )
    if type(accepted["schema_version"]) is not int or accepted["schema_version"] != 1:
        fail("accepted full-host tuple schema changed")
    parent = _require_exact_keys(
        accepted["parent"],
        {"filename", "sha256", "size_bytes", "row_count"},
        "accepted full parent",
    )
    _validate_evidence_record(
        {key: parent[key] for key in ("filename", "sha256", "size_bytes")},
        EXPECTED_PARENT_FILE,
        "accepted full parent",
    )
    if type(parent["row_count"]) is not int or parent["row_count"] <= 0:
        fail("accepted full parent row count is invalid")
    _validate_evidence_record(
        accepted["canonical_manifest"], EXPECTED_MANIFEST, "accepted canonical manifest"
    )
    _validate_evidence_record(
        accepted["legacy_manifest"], EXPECTED_LEGACY_MANIFEST, "accepted legacy manifest"
    )
    for key, names in (
        ("canonical_files", EXPECTED_CANONICAL_FILES),
        ("legacy_files", EXPECTED_LEGACY_FILES),
        ("auxiliary_files", EXPECTED_AUXILIARY_FILES),
        ("runtime_files", FULL_RUNTIME_FILES),
    ):
        records = _require_exact_keys(accepted[key], set(names), f"accepted {key}")
        for name in names:
            _validate_evidence_record(records[name], name, f"accepted {key} {name}")
    projections = _require_exact_keys(
        accepted["projections"], {"canonical", "legacy"}, "accepted projections"
    )
    for selector in ("canonical", "legacy"):
        _validate_projection_record(projections[selector], selector)
    _validate_signers(accepted["attestation_signers"])
    return accepted


def inspect_full_artifact(
    artifact_root: Path, contract: dict[str, Any]
) -> dict[str, Any]:
    root = Path(artifact_root)
    _require_directory(root, "full host artifact root")
    full = contract["full_artifact_contract"]
    canonical_manifest, canonical = _read_exact_manifest(
        root, EXPECTED_MANIFEST, EXPECTED_CANONICAL_FILES, "canonical host"
    )
    legacy_manifest, legacy = _read_exact_manifest(
        root, EXPECTED_LEGACY_MANIFEST, EXPECTED_LEGACY_FILES, "legacy host"
    )
    parent = read_file_snapshot(root / EXPECTED_PARENT_FILE, "full parent host table")
    auxiliary = {
        name: read_file_snapshot(root / name, f"host auxiliary {name}")
        for name in EXPECTED_AUXILIARY_FILES
    }
    runtime = {
        name: read_file_snapshot(root / name, f"host runtime input {name}")
        for name in FULL_RUNTIME_FILES
    }
    if runtime[FULL_RUNTIME_FILES[0]].sha256 != PARAMETERS_ORIGINAL_SHA256:
        fail("host original JJ tutorial parameters differ from the lock")
    if runtime[FULL_RUNTIME_FILES[1]].sha256 != PARAMETERS_RUNTIME_SHA256:
        fail("host runtime JJ tutorial parameters differ from the lock")
    if runtime[FULL_RUNTIME_FILES[2]].sha256 != SFR_SHA256:
        fail("host JJ SFR parameters differ from the lock")
    strict_documents: dict[str, Any] = {}
    for name, source in (
        (EXPECTED_CANONICAL_FILES[-1], canonical[EXPECTED_CANONICAL_FILES[-1]]),
        (EXPECTED_LEGACY_FILES[-1], legacy[EXPECTED_LEGACY_FILES[-1]]),
        (EXPECTED_AUXILIARY_FILES[-1], auxiliary[EXPECTED_AUXILIARY_FILES[-1]]),
        (FULL_RUNTIME_FILES[-1], runtime[FULL_RUNTIME_FILES[-1]]),
    ):
        strict_documents[name] = load_json_bytes(
            source.data, f"strict host JSON {name}"
        )
    helper, _ = _controller_helper()
    _helper_call(
        helper,
        "validate_runtime_manifest",
        strict_documents[FULL_RUNTIME_FILES[-1]],
    )
    parent_record, projection = _validate_parent_and_projection(
        parent,
        {
            "canonical": canonical[EXPECTED_CANONICAL_FILES[3]],
            "legacy": legacy[EXPECTED_LEGACY_FILES[3]],
        },
    )
    observed = {
        "schema_version": 1,
        "parent": parent_record,
        "canonical_manifest": _evidence(canonical_manifest),
        "canonical_files": {
            name: _evidence(canonical[name]) for name in EXPECTED_CANONICAL_FILES
        },
        "legacy_manifest": _evidence(legacy_manifest),
        "legacy_files": {
            name: _evidence(legacy[name]) for name in EXPECTED_LEGACY_FILES
        },
        "auxiliary_files": {
            name: _evidence(auxiliary[name]) for name in EXPECTED_AUXILIARY_FILES
        },
        "runtime_files": {
            name: _evidence(runtime[name]) for name in FULL_RUNTIME_FILES
        },
        "projections": projection["projections"],
        "attestation_signers": list(full["attestation_signers"]),
    }
    _validate_accepted_tuple(observed)
    return observed


def inspect_artifact(
    root: Path, contract: dict[str, Any]
) -> dict[str, Any]:
    _require_directory(root, "artifact root")
    entries, manifest_snapshot, snapshots = read_manifest(root, contract)
    manifest_sha = manifest_snapshot.sha256
    observed_identity, rows, weights = identity_projection_snapshot(
        snapshots[contract["raw_file"]], contract
    )
    expected_identity = contract["identity_projection"]["sha256"]
    if observed_identity != expected_identity:
        fail(
            f"row identity/order hash mismatch: "
            f"{observed_identity} != {expected_identity}"
        )
    if rows != contract["raw_schema"]["row_count"]:
        fail(f"raw host row count mismatch: {rows}")
    observed_science, observed_semantic = summary_projection_snapshot(
        snapshots[contract["summary_file"]], contract
    )
    expected_science = contract["summary_projection"]["sha256"]
    if observed_science != expected_science:
        fail(
            f"science-summary projection mismatch: "
            f"{observed_science} != {expected_science}"
        )
    exact_matches = [
        item
        for item in contract["artifact_sets"]
        if item["manifest_sha256"] == manifest_sha
        and item["file_sha256"] == entries
    ]
    portable_matches = [
        item
        for item in contract["artifact_sets"]
        if item["role"] == "qualified_candidate"
        and item["production_accepted"] is True
        and all(
            entries[name] == item["file_sha256"][name]
            for name in EXPECTED_CANONICAL_FILES
            if name != contract["summary_file"]
        )
        and observed_semantic == item["summary_sha256_without_python"]
    ]
    matches_by_id = {
        item["id"]: item for item in [*exact_matches, *portable_matches]
    }
    if len(matches_by_id) != 1:
        fail(
            "artifact is neither one exact contract tuple nor one qualified "
            "runtime-only summary representation"
        )
    artifact_set = next(iter(matches_by_id.values()))
    expected_semantic = artifact_set["summary_sha256_without_python"]
    if observed_semantic != expected_semantic:
        fail(
            f"artifact-set summary semantic hash mismatch: "
            f"{observed_semantic} != {expected_semantic}"
        )
    representation_match = (
        "exact_tuple"
        if artifact_set in exact_matches
        else "qualified_runtime_only_summary"
    )
    return {
        "artifact_set": artifact_set,
        "representation_match": representation_match,
        "manifest_sha256": manifest_sha,
        "file_sha256": entries,
        "identity_projection_sha256": observed_identity,
        "summary_projection_sha256": observed_science,
        "summary_sha256_without_python": observed_semantic,
        "row_count": rows,
        "weights": weights,
    }


def _host_repetition_manifest_members() -> tuple[str, ...]:
    return (
        *_host_exact_repeat_files(),
        HOST_PROVENANCE_NAME,
        HOST_START_CHALLENGE_NAME,
        HOST_START_SIGNATURE_NAME,
        HOST_EXECUTION_RECORD_NAME,
    )


def _host_repetition_files() -> set[str]:
    return {
        *_host_repetition_manifest_members(),
        HOST_REPETITION_MANIFEST,
        HOST_ATTESTATION_NAME,
        HOST_ATTESTATION_SIGNATURE_NAME,
    }


def _write_bytes_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except OSError as exc:
        fail(f"cannot write host repetition file {path.name}: {exc}")


def _write_json_exclusive(path: Path, value: Any) -> None:
    _write_bytes_exclusive(
        path,
        (
            json.dumps(
                value,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8"),
    )


def _write_manifest(path: Path, names: tuple[str, ...], root: Path) -> None:
    lines: list[str] = []
    for name in names:
        snapshot = read_file_snapshot(root / name, f"host repetition member {name}")
        lines.append(f"{snapshot.sha256}  {name}\n")
    _write_bytes_exclusive(path, "".join(lines).encode("utf-8"))


def _validate_digest_size(value: Any, description: str) -> dict[str, Any]:
    record = _require_exact_keys(value, {"sha256", "size_bytes"}, description)
    _require_hex(record["sha256"], f"{description} SHA-256")
    if type(record["size_bytes"]) is not int or record["size_bytes"] < 0:
        fail(f"{description} size must be a non-negative integer")
    return record


def _validate_program_records(value: Any) -> dict[str, Any]:
    records = _require_exact_keys(
        value, set(GENERATION_PROGRAMS), "host generation-program records"
    )
    for relative in GENERATION_PROGRAMS:
        record = _require_exact_keys(
            records[relative],
            {"relative_path", "sha256", "size_bytes"},
            f"host generation program {relative}",
        )
        if record["relative_path"] != relative:
            fail("host generation-program relative path changed")
        _require_hex(record["sha256"], f"host generation program {relative}")
        if type(record["size_bytes"]) is not int or record["size_bytes"] <= 0:
            fail("host generation-program size must be positive")
    return records


def _validate_padova_extraction_record(value: Any) -> dict[str, Any]:
    record = _require_exact_keys(
        value,
        {"root_relative_path", "member_count", "tree_sha256"},
        "host Padova extraction record",
    )
    if record["root_relative_path"] != "jjmodel/input/isochrones/Padova":
        fail("host Padova extraction root changed")
    if type(record["member_count"]) is not int or record["member_count"] <= 0:
        fail("host Padova extraction member count is invalid")
    _require_hex(record["tree_sha256"], "host Padova extraction tree")
    return record


def _validate_source_state(
    value: Any, contract: dict[str, Any], helper: types.ModuleType
) -> dict[str, Any]:
    state = _require_exact_keys(
        value,
        {
            "jj_source",
            "public_source",
            "private_source",
            "padova_archive",
            "padova_extraction",
            "runtime_executable",
            "controller_program",
            "controller_helper",
        },
        "host source state",
    )
    roles = (
        ("jj_source", "jj_generator", "jj_repository"),
        ("public_source", "public_release", "public_repository"),
        ("private_source", "private_production", "private_repository"),
    )
    locked = contract["full_artifact_contract"]["locked_inputs"]
    for key, role, repository_key in roles:
        _helper_call(helper, "validate_source_record", state[key], role)
        if state[key]["repository"] != locked[repository_key]:
            fail(f"host source repository mismatch for {role}")
    if state["jj_source"]["commit_sha"] != locked["jj_commit"]:
        fail("host JJ source commit differs from the lock")
    if state["public_source"]["repository"] == state["private_source"]["repository"]:
        fail("host public/private repositories are not distinct")
    if state["public_source"]["git_tree_sha"] != state["private_source"]["git_tree_sha"]:
        fail("host public/private Git trees differ")
    if state["padova_archive"] != locked["padova_archive"]:
        fail("host Padova source-state lock changed")
    _validate_padova_extraction_record(state["padova_extraction"])
    _validate_runtime_executable_record(state["runtime_executable"])
    _validate_evidence_record(
        state["controller_program"],
        "verify_host_artifact_contract.py",
        "host controller program",
    )
    _validate_evidence_record(
        state["controller_helper"],
        "verify_age_cut_ssp_contract.py",
        "host controller helper",
    )
    return state


def _validate_runtime_evidence(value: Any) -> dict[str, Any]:
    records = _require_exact_keys(
        value, set(FULL_RUNTIME_FILES), "host runtime evidence"
    )
    for name in FULL_RUNTIME_FILES:
        _validate_evidence_record(records[name], name, f"host runtime evidence {name}")
    return records


def _validate_nonce(value: Any, description: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{description} must be exactly 32 lowercase-hex bytes")
    return value


def _validate_execution_id(value: Any, description: str) -> str:
    try:
        canonical = str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        fail(f"invalid {description}: {exc}")
    if canonical != value:
        fail(f"{description} must use canonical lowercase UUID form")
    return canonical


def _validate_timestamp(
    helper: types.ModuleType, value: Any, description: str
) -> datetime:
    return _helper_call(helper, "parse_timestamp", value, description)


def _candidate_signer(
    contract: dict[str, Any], signer_id: str
) -> dict[str, str]:
    matches = [
        item
        for item in contract["full_artifact_contract"]["attestation_signers"]
        if item["signer_id"] == signer_id
    ]
    if len(matches) != 1:
        fail(f"unknown host attestation signer: {signer_id!r}")
    return matches[0]


def _validate_planned_commands(
    value: Any, runtime_document: dict[str, Any]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(GENERATION_PROGRAMS):
        fail("host challenge must contain the exact five planned commands")
    validated: list[dict[str, Any]] = []
    common_jj: str | None = None
    common_run: str | None = None
    common_out: str | None = None
    for index, (raw, relative) in enumerate(zip(value, GENERATION_PROGRAMS)):
        command = _require_exact_keys(
            raw, {"program", "argv", "cwd", "shell"}, "host planned command"
        )
        if command["program"] != relative or command["shell"] is not False:
            fail("host planned command program/shell policy changed")
        argv = command["argv"]
        if not isinstance(argv, list) or not all(
            isinstance(item, str) and item and "\x00" not in item for item in argv
        ):
            fail("host planned command argv is invalid")
        if not isinstance(command["cwd"], str) or not command["cwd"]:
            fail("host planned command cwd is invalid")
        if argv[0] != runtime_document["python_executable"]:
            fail("host planned command does not use the locked runtime Python")
        normalized_program = argv[1].replace("\\", "/")
        if not normalized_program.endswith("/" + relative):
            fail("host planned command does not execute the locked program path")
        if index < 3:
            suffix = ["--jj-root", None, "--run-dir", None, "--out", None, "--iso", "Padova"]
            if index == 0:
                suffix += ["--expected-radial-step-kpc", "0.5"]
            if len(argv) != 2 + len(suffix):
                fail("host planned JJ command argv length changed")
            for offset, expected in enumerate(suffix, start=2):
                if expected is not None and argv[offset] != expected:
                    fail("host planned JJ command argv changed")
            jj_root = argv[3]
            run_root = argv[5]
            out_root = argv[7]
            if index == 0:
                common_jj, common_run, common_out = jj_root, run_root, out_root
            elif (jj_root, run_root, out_root) != (common_jj, common_run, common_out):
                fail("host planned JJ commands do not share exact fresh roots")
        else:
            if argv != [argv[0], argv[1], "--out", common_out]:
                fail("host planned post-processing command argv changed")
        validated.append(command)
    return validated


def _validate_start_challenge(
    document: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    runtime_document: dict[str, Any],
    helper: types.ModuleType,
) -> dict[str, Any]:
    challenge = _require_exact_keys(
        document,
        {
            "schema_version",
            "challenge_id",
            "namespace",
            "contract_id",
            "candidate_artifact_set_id",
            "signer_id",
            "repeat_label",
            "execution_id",
            "nonce_hex",
            "issued_utc",
            "controller",
            "source_state",
            "source_state_sha256",
            "locked_inputs",
            "runtime_inputs",
            "generation_programs",
            "planned_commands",
            "execution_root_created_empty",
        },
        "host start challenge",
    )
    if type(challenge["schema_version"]) is not int or challenge["schema_version"] != 1:
        fail("host start challenge schema changed")
    if (
        challenge["namespace"] != HOST_START_NAMESPACE
        or challenge["contract_id"] != contract["contract_id"]
        or challenge["candidate_artifact_set_id"] != candidate["id"]
        or challenge["controller"]
        != "verify_host_artifact_contract.execute_fresh_repetition"
        or challenge["execution_root_created_empty"] is not True
    ):
        fail("host start challenge policy/identity changed")
    _candidate_signer(
        contract, _require_safe_id(challenge["signer_id"], "host signer id")
    )
    _require_safe_id(challenge["repeat_label"], "host repetition label")
    _validate_execution_id(challenge["execution_id"], "host execution id")
    _validate_nonce(challenge["nonce_hex"], "host challenge nonce")
    _validate_timestamp(helper, challenge["issued_utc"], "host challenge issued_utc")
    source_state = _validate_source_state(challenge["source_state"], contract, helper)
    if source_state["runtime_executable"]["requested_path"] != runtime_document[
        "python_executable"
    ]:
        fail("host challenge runtime executable differs from the runtime manifest")
    expected_source_hash = hashlib.sha256(canonical_json_bytes(source_state)).hexdigest()
    if challenge["source_state_sha256"] != expected_source_hash:
        fail("host challenge source-state hash mismatch")
    if challenge["locked_inputs"] != contract["full_artifact_contract"]["locked_inputs"]:
        fail("host challenge locked-input tuple changed")
    _validate_runtime_evidence(challenge["runtime_inputs"])
    _validate_program_records(challenge["generation_programs"])
    _validate_planned_commands(challenge["planned_commands"], runtime_document)
    body = dict(challenge)
    identifier = body.pop("challenge_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if identifier != expected_id:
        fail("host start challenge self-identifier mismatch")
    return challenge


def _validate_execution_record(
    document: Any,
    challenge: dict[str, Any],
    full_tuple: dict[str, Any],
    helper: types.ModuleType,
) -> dict[str, Any]:
    record = _require_exact_keys(
        document,
        {
            "schema_version",
            "execution_record_id",
            "controller",
            "challenge_id",
            "execution_id",
            "nonce_hex",
            "commands",
            "run_directory_created_empty",
            "host_output_directory_created_empty",
            "run_started_utc",
            "run_completed_utc",
            "source_state_sha256",
            "full_artifact_tuple",
        },
        "host execution record",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or record["controller"]
        != "verify_host_artifact_contract.execute_fresh_repetition"
        or record["challenge_id"] != challenge["challenge_id"]
        or record["execution_id"] != challenge["execution_id"]
        or record["nonce_hex"] != challenge["nonce_hex"]
        or record["run_directory_created_empty"] is not True
        or record["host_output_directory_created_empty"] is not True
        or record["source_state_sha256"] != challenge["source_state_sha256"]
        or record["full_artifact_tuple"] != full_tuple
    ):
        fail("host execution record does not bind the challenge/full tuple")
    started = _validate_timestamp(helper, record["run_started_utc"], "host run start")
    completed = _validate_timestamp(helper, record["run_completed_utc"], "host run completion")
    if completed <= started:
        fail("host run completion is not later than run start")
    commands = record["commands"]
    planned = challenge["planned_commands"]
    if not isinstance(commands, list) or len(commands) != len(planned):
        fail("host execution record command count changed")
    for observed, expected in zip(commands, planned):
        command = _require_exact_keys(
            observed,
            {"program", "argv", "cwd", "shell", "return_code", "stdout", "stderr"},
            "executed host command",
        )
        if {key: command[key] for key in ("program", "argv", "cwd", "shell")} != expected:
            fail("executed host command differs from signed pre-run argv")
        if type(command["return_code"]) is not int or command["return_code"] != 0:
            fail("host execution command did not return success")
        _validate_digest_size(command["stdout"], "host command stdout")
        _validate_digest_size(command["stderr"], "host command stderr")
    body = dict(record)
    identifier = body.pop("execution_record_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if identifier != expected_id:
        fail("host execution-record self-identifier mismatch")
    return record


def _validate_provenance(
    document: Any,
    contract: dict[str, Any],
    challenge: dict[str, Any],
    execution: dict[str, Any],
    full_tuple: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    helper: types.ModuleType,
) -> dict[str, Any]:
    provenance = _require_exact_keys(
        document,
        {
            "schema_version",
            "repeat_label",
            "execution_id",
            "execution_environment",
            "run_started_utc",
            "run_completed_utc",
            "signer_id",
            "controller",
            "source_state",
            "generation_programs",
            "runtime_files",
            "full_artifact_tuple",
            "start_challenge",
            "start_challenge_signature",
            "execution_record",
        },
        "host run provenance",
    )
    policy = contract["full_artifact_contract"]["qualification_policy"]
    if (
        type(provenance["schema_version"]) is not int
        or provenance["schema_version"] != 1
        or provenance["repeat_label"] != challenge["repeat_label"]
        or provenance["execution_id"] != challenge["execution_id"]
        or provenance["signer_id"] != challenge["signer_id"]
        or provenance["controller"] != policy["fresh_execution_controller"]
        or provenance["execution_environment"]
        not in policy["allowed_execution_environments"]
        or provenance["run_started_utc"] != execution["run_started_utc"]
        or provenance["run_completed_utc"] != execution["run_completed_utc"]
        or provenance["source_state"] != challenge["source_state"]
        or provenance["generation_programs"] != challenge["generation_programs"]
        or provenance["runtime_files"] != challenge["runtime_inputs"]
        or provenance["full_artifact_tuple"] != full_tuple
    ):
        fail("host provenance does not bind the signed execution/full tuple")
    for field, name in (
        ("start_challenge", HOST_START_CHALLENGE_NAME),
        ("start_challenge_signature", HOST_START_SIGNATURE_NAME),
        ("execution_record", HOST_EXECUTION_RECORD_NAME),
    ):
        if provenance[field] != _evidence(snapshots[name]):
            fail(f"host provenance evidence mismatch for {field}")
    _validate_source_state(provenance["source_state"], contract, helper)
    _validate_program_records(provenance["generation_programs"])
    _validate_runtime_evidence(provenance["runtime_files"])
    return provenance


def _attestation_body(
    contract: dict[str, Any],
    candidate: dict[str, Any],
    challenge: dict[str, Any],
    full_tuple: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
) -> dict[str, Any]:
    exact_hashes = {
        name: snapshots[name].sha256 for name in _host_exact_repeat_files()
    }
    return {
        "schema_version": 1,
        "namespace": HOST_ATTESTATION_NAMESPACE,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate["id"],
        "signer_id": challenge["signer_id"],
        "repeat_label": challenge["repeat_label"],
        "execution_id": challenge["execution_id"],
        "nonce_hex": challenge["nonce_hex"],
        "source_state_sha256": challenge["source_state_sha256"],
        "start_challenge_sha256": snapshots[HOST_START_CHALLENGE_NAME].sha256,
        "start_challenge_signature_sha256": snapshots[HOST_START_SIGNATURE_NAME].sha256,
        "execution_record_sha256": snapshots[HOST_EXECUTION_RECORD_NAME].sha256,
        "provenance_sha256": snapshots[HOST_PROVENANCE_NAME].sha256,
        "repetition_manifest_sha256": snapshots[HOST_REPETITION_MANIFEST].sha256,
        "exact_repeat_sha256": exact_hashes,
        "full_artifact_tuple": full_tuple,
    }


def _validate_attestation(
    document: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    challenge: dict[str, Any],
    full_tuple: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
) -> dict[str, Any]:
    expected_body = _attestation_body(
        contract, candidate, challenge, full_tuple, snapshots
    )
    attestation = _require_exact_keys(
        document, {"attestation_id", *expected_body}, "host run attestation"
    )
    body = dict(attestation)
    identifier = body.pop("attestation_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if identifier != expected_id or body != expected_body:
        fail("host run attestation does not bind the exact repetition bytes")
    return attestation


def inspect_signed_repetition(
    root_path: Path, contract: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    root = Path(root_path)
    _require_directory(root, "signed host repetition root")
    entries = {path.name for path in root.iterdir()}
    if entries != _host_repetition_files():
        fail("signed host repetition root does not have the exact file set")
    manifest, listed = _read_exact_manifest(
        root,
        HOST_REPETITION_MANIFEST,
        _host_repetition_manifest_members(),
        "signed host repetition",
    )
    snapshots = {**listed, HOST_REPETITION_MANIFEST: manifest}
    canonical = inspect_artifact(root, contract)
    if canonical["artifact_set"]["id"] != candidate["id"]:
        fail("signed host repetition does not match the candidate artifact set")
    full_tuple = inspect_full_artifact(root, contract)
    runtime_document = load_json_bytes(
        snapshots[FULL_RUNTIME_FILES[-1]].data, "host runtime manifest"
    )
    helper, _ = _controller_helper()
    _helper_call(helper, "validate_runtime_manifest", runtime_document)
    challenge = _validate_start_challenge(
        load_json_bytes(
            snapshots[HOST_START_CHALLENGE_NAME].data, "host start challenge"
        ),
        contract,
        candidate,
        runtime_document,
        helper,
    )
    if challenge["runtime_inputs"] != full_tuple["runtime_files"]:
        fail("signed host challenge runtime inputs differ from the full tuple")
    signer = _candidate_signer(contract, challenge["signer_id"])
    _helper_call(
        helper,
        "verify_signature",
        snapshots[HOST_START_CHALLENGE_NAME],
        snapshots[HOST_START_SIGNATURE_NAME],
        signer,
        namespace=HOST_START_NAMESPACE,
    )
    execution = _validate_execution_record(
        load_json_bytes(
            snapshots[HOST_EXECUTION_RECORD_NAME].data, "host execution record"
        ),
        challenge,
        full_tuple,
        helper,
    )
    provenance = _validate_provenance(
        load_json_bytes(snapshots[HOST_PROVENANCE_NAME].data, "host provenance"),
        contract,
        challenge,
        execution,
        full_tuple,
        snapshots,
        helper,
    )
    attestation_snapshot = read_file_snapshot(
        root / HOST_ATTESTATION_NAME,
        "host run attestation",
        maximum_bytes=MAX_JSON_BYTES,
    )
    signature_snapshot = read_file_snapshot(
        root / HOST_ATTESTATION_SIGNATURE_NAME,
        "host run attestation signature",
        maximum_bytes=MAX_JSON_BYTES,
    )
    snapshots[HOST_ATTESTATION_NAME] = attestation_snapshot
    snapshots[HOST_ATTESTATION_SIGNATURE_NAME] = signature_snapshot
    attestation = _validate_attestation(
        load_json_bytes(attestation_snapshot.data, "host run attestation"),
        contract,
        candidate,
        challenge,
        full_tuple,
        snapshots,
    )
    _helper_call(
        helper,
        "verify_signature",
        attestation_snapshot,
        signature_snapshot,
        signer,
        namespace=HOST_ATTESTATION_NAMESPACE,
    )
    embedded_names = (
        FULL_RUNTIME_FILES[-1],
        HOST_PROVENANCE_NAME,
        HOST_START_CHALLENGE_NAME,
        HOST_START_SIGNATURE_NAME,
        HOST_EXECUTION_RECORD_NAME,
        HOST_REPETITION_MANIFEST,
        HOST_ATTESTATION_NAME,
        HOST_ATTESTATION_SIGNATURE_NAME,
    )
    return {
        "label": challenge["repeat_label"],
        "execution_id": challenge["execution_id"],
        "nonce_hex": challenge["nonce_hex"],
        "signer_id": signer["signer_id"],
        "source_state": challenge["source_state"],
        "source_state_sha256": challenge["source_state_sha256"],
        "full_artifact_tuple": full_tuple,
        "exact_repeat_sha256": {
            name: snapshots[name].sha256 for name in _host_exact_repeat_files()
        },
        "attestation_id": attestation["attestation_id"],
        "repetition_manifest_sha256": manifest.sha256,
        "embedded_signed_evidence": {
            name: base64.b64encode(snapshots[name].data).decode("ascii")
            for name in embedded_names
        },
        "provenance": provenance,
    }


def _validate_legacy_qualification_report(
    contract_path: Path,
    contract: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    reference = candidate["qualification_report"]
    if reference is None:
        fail(
            f"accepted candidate {candidate['id']} lacks "
            "qualification evidence"
        )
    report_path = contract_path.parent / reference["path"]
    report_document, report_snapshot = load_json_snapshot(report_path)
    if report_snapshot.sha256 != reference["sha256"]:
        fail("qualification report hash mismatch")
    report = _require_exact_keys(
        report_document,
        {
            "schema_version",
            "qualification_id",
            "baseline_artifact_set_id",
            "candidate_artifact_set_id",
            "fresh_repetitions",
            "exact_repeat_sha256",
            "invariant_sha256",
            "numeric_weight_comparison",
        },
        "qualification report",
    )
    qualification_id = report["qualification_id"]
    body = dict(report)
    del body["qualification_id"]
    expected_id = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    )
    if qualification_id != expected_id:
        fail("qualification report self-identifier mismatch")
    policy = contract["qualification_policy"]
    if report["schema_version"] != 1:
        fail("unsupported qualification report schema")
    if (
        report["baseline_artifact_set_id"]
        != policy["baseline_artifact_set_id"]
    ):
        fail("qualification report baseline mismatch")
    if report["candidate_artifact_set_id"] != candidate["id"]:
        fail("qualification report candidate mismatch")
    repetitions = report["fresh_repetitions"]
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        fail("qualification report must record two repetitions")
    labels = []
    for item in repetitions:
        item = _require_exact_keys(
            item,
            {"label", "manifest_sha256", "file_sha256"},
            "fresh repetition",
        )
        labels.append(
            _require_safe_id(item["label"], "fresh repetition label")
        )
        if item["manifest_sha256"] != candidate["manifest_sha256"]:
            fail("qualification repetition manifest mismatch")
        if item["file_sha256"] != candidate["file_sha256"]:
            fail("qualification repetition file tuple mismatch")
    if len(set(labels)) != 2:
        fail("qualification repetition labels must be distinct")
    expected_repeat = {
        EXPECTED_MANIFEST: candidate["manifest_sha256"],
        **candidate["file_sha256"],
    }
    if report["exact_repeat_sha256"] != expected_repeat:
        fail("qualification exact-repeat hashes mismatch")
    invariants = report["invariant_sha256"]
    if invariants != {
        "identity_projection": contract["identity_projection"]["sha256"],
        "summary_projection": contract["summary_projection"]["sha256"],
        "candidate_summary_without_python": candidate[
            "summary_sha256_without_python"
        ],
    }:
        fail("qualification invariant hashes mismatch")
    numeric = report["numeric_weight_comparison"]
    numeric = _require_exact_keys(
        numeric,
        {
            "column",
            "relative_tolerance",
            "absolute_tolerance",
            "all_within_tolerance",
            "repeat_metrics",
        },
        "qualification numeric comparison",
    )
    if numeric["all_within_tolerance"] is not True:
        fail(
            "qualification report does not pass the one-time "
            "numeric comparison"
        )
    configured = policy["numeric_weight_comparison"]
    for key in ("column", "relative_tolerance", "absolute_tolerance"):
        if numeric.get(key) != configured[key]:
            fail(f"qualification numeric policy mismatch at {key}")
    metrics = numeric["repeat_metrics"]
    if not isinstance(metrics, list) or len(metrics) != 2:
        fail("qualification report must contain two numeric comparisons")
    metric_keys = {
        "row_count",
        "outside_tolerance_count",
        "max_absolute_difference",
        "max_relative_difference",
        "reference_weight_sum",
        "candidate_weight_sum",
        "all_within_tolerance",
    }
    for metric in metrics:
        metric = _require_exact_keys(
            metric, metric_keys, "qualification weight metric"
        )
        if (
            metric["row_count"] != contract["raw_schema"]["row_count"]
            or metric["outside_tolerance_count"] != 0
            or metric["all_within_tolerance"] is not True
        ):
            fail("qualification weight metric does not pass")
        for key in (
            "max_absolute_difference",
            "max_relative_difference",
            "reference_weight_sum",
            "candidate_weight_sum",
        ):
            value = metric[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
            ):
                fail(f"invalid qualification weight metric: {key}")


def _tuple_file_evidence(full_tuple: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {
        full_tuple["parent"]["filename"]: {
            key: full_tuple["parent"][key]
            for key in ("filename", "sha256", "size_bytes")
        },
        full_tuple["canonical_manifest"]["filename"]: full_tuple[
            "canonical_manifest"
        ],
        full_tuple["legacy_manifest"]["filename"]: full_tuple["legacy_manifest"],
    }
    for group in (
        "canonical_files",
        "legacy_files",
        "auxiliary_files",
        "runtime_files",
    ):
        records.update(full_tuple[group])
    return records


def _decode_embedded_evidence(value: Any) -> dict[str, FileSnapshot]:
    expected = {
        FULL_RUNTIME_FILES[-1],
        HOST_PROVENANCE_NAME,
        HOST_START_CHALLENGE_NAME,
        HOST_START_SIGNATURE_NAME,
        HOST_EXECUTION_RECORD_NAME,
        HOST_REPETITION_MANIFEST,
        HOST_ATTESTATION_NAME,
        HOST_ATTESTATION_SIGNATURE_NAME,
    }
    encoded = _require_exact_keys(value, expected, "embedded host signed evidence")
    snapshots: dict[str, FileSnapshot] = {}
    for name in expected:
        text = encoded[name]
        if not isinstance(text, str) or not text:
            fail(f"embedded host signed evidence {name} is invalid")
        try:
            data = base64.b64decode(text, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            fail(f"cannot decode embedded host signed evidence {name}: {exc}")
        if base64.b64encode(data).decode("ascii") != text:
            fail(f"embedded host signed evidence {name} is not canonical base64")
        if len(data) > MAX_JSON_BYTES:
            fail(f"embedded host signed evidence {name} is too large")
        snapshots[name] = FileSnapshot(
            path=Path(name),
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
    return snapshots


def _parse_exact_manifest_snapshot(
    snapshot: FileSnapshot, expected_names: tuple[str, ...], description: str
) -> dict[str, str]:
    try:
        lines = snapshot.data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    if len(lines) != len(expected_names):
        fail(f"{description} entry count changed")
    result: dict[str, str] = {}
    for line, expected_name in zip(lines, expected_names):
        parts = line.split("  ", 1)
        if len(parts) != 2:
            fail(f"malformed {description} line")
        digest_value, name = parts
        _require_hex(digest_value, f"{description} digest")
        if not _is_portable_safe_leaf(name) or name != expected_name:
            fail(f"{description} member order/set changed")
        if name in result:
            fail(f"duplicate {description} member")
        result[name] = digest_value
    return result


def _validate_embedded_repetition(
    item: Any,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    accepted_tuple: dict[str, Any],
    exact_repeat_sha256: dict[str, str],
) -> dict[str, Any]:
    repetition = _require_exact_keys(
        item,
        {
            "label",
            "execution_id",
            "nonce_hex",
            "signer_id",
            "source_state_sha256",
            "attestation_id",
            "repetition_manifest_sha256",
            "public_evidence",
            "embedded_signed_evidence",
        },
        "qualified host repetition",
    )
    snapshots = _decode_embedded_evidence(repetition["embedded_signed_evidence"])
    if snapshots[HOST_REPETITION_MANIFEST].sha256 != repetition[
        "repetition_manifest_sha256"
    ]:
        fail("embedded host repetition-manifest hash mismatch")
    manifest_entries = _parse_exact_manifest_snapshot(
        snapshots[HOST_REPETITION_MANIFEST],
        _host_repetition_manifest_members(),
        "embedded host repetition manifest",
    )
    expected_manifest_entries = {
        **exact_repeat_sha256,
        HOST_PROVENANCE_NAME: snapshots[HOST_PROVENANCE_NAME].sha256,
        HOST_START_CHALLENGE_NAME: snapshots[HOST_START_CHALLENGE_NAME].sha256,
        HOST_START_SIGNATURE_NAME: snapshots[HOST_START_SIGNATURE_NAME].sha256,
        HOST_EXECUTION_RECORD_NAME: snapshots[HOST_EXECUTION_RECORD_NAME].sha256,
    }
    if manifest_entries != expected_manifest_entries:
        fail("embedded host repetition manifest does not bind the exact evidence")
    runtime_document = load_json_bytes(
        snapshots[FULL_RUNTIME_FILES[-1]].data,
        "embedded host numerical-runtime manifest",
    )
    helper, _ = _controller_helper()
    _helper_call(helper, "validate_runtime_manifest", runtime_document)
    challenge = _validate_start_challenge(
        load_json_bytes(
            snapshots[HOST_START_CHALLENGE_NAME].data,
            "embedded host start challenge",
        ),
        contract,
        candidate,
        runtime_document,
        helper,
    )
    if challenge["runtime_inputs"] != accepted_tuple["runtime_files"]:
        fail("embedded host runtime inputs differ from the accepted full tuple")
    if snapshots[FULL_RUNTIME_FILES[-1]].sha256 != exact_repeat_sha256[
        FULL_RUNTIME_FILES[-1]
    ]:
        fail("embedded numerical-runtime bytes differ from the accepted tuple")
    signer = _candidate_signer(contract, challenge["signer_id"])
    _helper_call(
        helper,
        "verify_signature",
        snapshots[HOST_START_CHALLENGE_NAME],
        snapshots[HOST_START_SIGNATURE_NAME],
        signer,
        namespace=HOST_START_NAMESPACE,
    )
    execution = _validate_execution_record(
        load_json_bytes(
            snapshots[HOST_EXECUTION_RECORD_NAME].data,
            "embedded host execution record",
        ),
        challenge,
        accepted_tuple,
        helper,
    )
    _validate_provenance(
        load_json_bytes(
            snapshots[HOST_PROVENANCE_NAME].data, "embedded host provenance"
        ),
        contract,
        challenge,
        execution,
        accepted_tuple,
        snapshots,
        helper,
    )
    tuple_files = _tuple_file_evidence(accepted_tuple)
    for name in _host_exact_repeat_files():
        if exact_repeat_sha256.get(name) != tuple_files[name]["sha256"]:
            fail(f"qualified host exact-repeat hash mismatch for {name}")
        evidence = tuple_files[name]
        snapshots[name] = FileSnapshot(
            path=Path(name),
            data=b"",
            sha256=evidence["sha256"],
            size_bytes=evidence["size_bytes"],
        )
    attestation = _validate_attestation(
        load_json_bytes(
            snapshots[HOST_ATTESTATION_NAME].data,
            "embedded host attestation",
        ),
        contract,
        candidate,
        challenge,
        accepted_tuple,
        snapshots,
    )
    _helper_call(
        helper,
        "verify_signature",
        snapshots[HOST_ATTESTATION_NAME],
        snapshots[HOST_ATTESTATION_SIGNATURE_NAME],
        signer,
        namespace=HOST_ATTESTATION_NAMESPACE,
    )
    expected_public = {
        "parent": accepted_tuple["parent"],
        "canonical_manifest": accepted_tuple["canonical_manifest"],
        "legacy_manifest": accepted_tuple["legacy_manifest"],
        "projections": accepted_tuple["projections"],
        "canonical_files": accepted_tuple["canonical_files"],
        "legacy_files": accepted_tuple["legacy_files"],
        "auxiliary_files": accepted_tuple["auxiliary_files"],
        "runtime_files": accepted_tuple["runtime_files"],
    }
    if repetition["public_evidence"] != expected_public:
        fail("qualified host public evidence differs from the accepted tuple")
    expected_scalars = {
        "label": challenge["repeat_label"],
        "execution_id": challenge["execution_id"],
        "nonce_hex": challenge["nonce_hex"],
        "signer_id": challenge["signer_id"],
        "source_state_sha256": challenge["source_state_sha256"],
        "attestation_id": attestation["attestation_id"],
    }
    for key, expected in expected_scalars.items():
        if repetition[key] != expected:
            fail(f"qualified host repetition metadata mismatch for {key}")
    return {
        **repetition,
        "source_state": challenge["source_state"],
    }


def _validate_qualification_report(
    contract_path: Path,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    *,
    include_source_state: bool = False,
) -> dict[str, Any]:
    reference = candidate["qualification_report"]
    if reference is None:
        fail(f"accepted candidate {candidate['id']} lacks qualification evidence")
    report_path = contract_path.parent / reference["path"]
    document, snapshot = load_json_snapshot(
        report_path, maximum_bytes=MAX_CONTRACT_BYTES
    )
    if snapshot.sha256 != reference["sha256"]:
        fail("host qualification-report hash mismatch")
    report = _require_exact_keys(
        document,
        {
            "schema_version",
            "qualification_id",
            "contract_id",
            "candidate_artifact_set_id",
            "accepted_full_artifact_tuple",
            "exact_repeat_sha256",
            "identical_source_state_sha256",
            "qualified_source",
            "fresh_repetitions",
        },
        "signed host qualification report",
    )
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 3
        or report["contract_id"] != contract["contract_id"]
        or report["candidate_artifact_set_id"] != candidate["id"]
    ):
        fail("signed host qualification-report identity/schema changed")
    accepted = contract["full_artifact_contract"]["accepted_tuple"]
    if accepted is None or report["accepted_full_artifact_tuple"] != accepted:
        fail("host qualification report differs from the accepted full tuple")
    exact = _require_exact_keys(
        report["exact_repeat_sha256"],
        set(_host_exact_repeat_files()),
        "host qualification exact-repeat hashes",
    )
    for name, digest in exact.items():
        _require_hex(digest, f"qualified exact-repeat hash {name}")
    _require_hex(
        report["identical_source_state_sha256"],
        "qualified identical source-state hash",
    )
    repetitions = report["fresh_repetitions"]
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        fail("signed host qualification requires exactly two repetitions")
    inspected = [
        _validate_embedded_repetition(item, contract, candidate, accepted, exact)
        for item in repetitions
    ]
    for key in ("label", "execution_id", "nonce_hex", "signer_id"):
        if len({item[key] for item in inspected}) != 2:
            fail(f"qualified host repetitions do not have distinct {key}")
    if {item["signer_id"] for item in inspected} != {
        item["signer_id"]
        for item in contract["full_artifact_contract"]["attestation_signers"]
    }:
        fail("qualified host repetitions do not use both pinned signers")
    if any(
        item["source_state_sha256"] != report["identical_source_state_sha256"]
        for item in inspected
    ) or inspected[0]["source_state"] != inspected[1]["source_state"]:
        fail("qualified host repetitions do not bind identical source state")
    qualified_source = _require_exact_keys(
        report["qualified_source"],
        {"public_source", "private_source"},
        "qualified host source lock",
    )
    expected_qualified_source = {
        "public_source": inspected[0]["source_state"]["public_source"],
        "private_source": inspected[0]["source_state"]["private_source"],
    }
    if qualified_source != expected_qualified_source:
        fail("qualified host source lock differs from signed repetition evidence")
    body = dict(report)
    identifier = body.pop("qualification_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if identifier != expected_id:
        fail("signed host qualification-report self-identifier mismatch")
    if include_source_state:
        return {"report": report, "source_state": inspected[0]["source_state"]}
    return report


def validate_contract_promotion(
    pending_document: Any, accepted_document: Any
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Allow only the evidence-backed pending-to-accepted lifecycle transition."""

    pending = validate_contract(copy.deepcopy(pending_document))
    accepted = validate_contract(copy.deepcopy(accepted_document))
    pending_sets = {item["id"]: item for item in pending["artifact_sets"]}
    accepted_sets = {item["id"]: item for item in accepted["artifact_sets"]}
    if list(pending_sets) != list(accepted_sets):
        fail("host contract promotion changed artifact-set ids or order")
    promoted_ids: list[str] = []
    for identifier, pending_set in pending_sets.items():
        accepted_set = accepted_sets[identifier]
        if pending_set == accepted_set:
            continue
        for field in pending_set:
            if field not in {"role", "production_accepted", "qualification_report"}:
                if pending_set[field] != accepted_set[field]:
                    fail(f"host promotion changed locked candidate field: {identifier}.{field}")
        if not (
            pending_set["role"] == "diagnostic_candidate"
            and pending_set["production_accepted"] is False
            and pending_set["qualification_eligible"] is True
            and pending_set["qualification_report"] is None
            and accepted_set["role"] == "qualified_candidate"
            and accepted_set["production_accepted"] is True
            and accepted_set["qualification_eligible"] is True
            and isinstance(accepted_set["qualification_report"], dict)
        ):
            fail("host candidate transition is not the exact pending-to-accepted promotion")
        promoted_ids.append(identifier)
    if len(promoted_ids) != 1:
        fail("host contract promotion must accept exactly one pending candidate")
    pending_full = pending["full_artifact_contract"]
    accepted_full = accepted["full_artifact_contract"]
    if pending_full["accepted_tuple"] is not None or accepted_full["accepted_tuple"] is None:
        fail("host contract promotion must populate one previously pending full tuple")
    for field in pending_full:
        if field != "accepted_tuple" and pending_full[field] != accepted_full[field]:
            fail(f"host promotion changed full-contract locked field: {field}")
    normalized = copy.deepcopy(accepted)
    normalized["artifact_sets"] = copy.deepcopy(pending["artifact_sets"])
    normalized["full_artifact_contract"]["accepted_tuple"] = None
    if normalized != pending:
        fail("host contract promotion changed policy, signers, inputs, or science locks")
    promoted = artifact_set_by_id(accepted, promoted_ids[0])
    return pending, accepted, promoted


def validate_external_contract_promotion(
    pending_contract_path: Path,
    accepted_contract_path: Path,
    expected_accepted_sha256: str,
    expected_public_source: Mapping[str, Any],
    expected_private_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate external accepted contract B and bind its signed report to source A."""

    _require_hex(expected_accepted_sha256, "expected accepted host contract SHA-256")
    pending_document, pending_snapshot = load_json_snapshot(
        pending_contract_path, maximum_bytes=MAX_CONTRACT_BYTES
    )
    accepted_document, accepted_snapshot = load_json_snapshot(
        accepted_contract_path, maximum_bytes=MAX_CONTRACT_BYTES
    )
    if accepted_snapshot.sha256 != expected_accepted_sha256:
        fail("external accepted host contract SHA-256 differs from the signed plan")
    _pending, accepted, promoted = validate_contract_promotion(
        pending_document, accepted_document
    )
    validated = _validate_qualification_report(
        Path(accepted_contract_path),
        accepted,
        promoted,
        include_source_state=True,
    )
    source_state = validated["source_state"]

    def compact_source(record: Mapping[str, Any]) -> dict[str, Any]:
        archive = record["source_archive"]
        return {
            "repository": record["repository"],
            "commit_sha": record["commit_sha"],
            "git_tree_sha": record["git_tree_sha"],
            "source_archive_sha256": archive["sha256"],
            "source_archive_size_bytes": archive["size_bytes"],
        }

    source_lock = {
        "public_source": compact_source(source_state["public_source"]),
        "private_source": compact_source(source_state["private_source"]),
    }
    if source_lock["public_source"] != dict(expected_public_source):
        fail("host qualification public source does not match computational source A")
    if source_lock["private_source"] != dict(expected_private_source):
        fail("host qualification private source does not match computational source A")
    reference = promoted["qualification_report"]
    report_path = Path(accepted_contract_path).parent / reference["path"]
    report_snapshot = read_file_snapshot(
        report_path, "external host qualification report", maximum_bytes=MAX_CONTRACT_BYTES
    )
    if report_snapshot.sha256 != reference["sha256"]:
        fail("external host qualification report differs from contract B")
    return {
        "candidate_artifact_set_id": promoted["id"],
        "qualification_id": validated["report"]["qualification_id"],
        "pending_contract_sha256": pending_snapshot.sha256,
        "accepted_contract_sha256": accepted_snapshot.sha256,
        "accepted_contract_size_bytes": accepted_snapshot.size_bytes,
        "qualification_report_path": str(report_path.resolve()),
        "qualification_report_sha256": report_snapshot.sha256,
        "qualification_report_size_bytes": report_snapshot.size_bytes,
        "source_lock": source_lock,
    }


def verify_artifact(
    contract_path: Path, artifact_root: Path
) -> dict[str, Any]:
    contract = load_contract(contract_path)
    inspection = inspect_artifact(artifact_root, contract)
    artifact_set = inspection["artifact_set"]
    if not artifact_set["production_accepted"]:
        fail(
            f"artifact set {artifact_set['id']!r} is known only for "
            "diagnostics; it is not production accepted"
        )
    if artifact_set["role"] == "historical_baseline":
        fail("historical host tuples are not production accepted under the signed v4.0.4 contract")
    full_inspection = inspect_full_artifact(artifact_root, contract)
    accepted_tuple = contract["full_artifact_contract"]["accepted_tuple"]
    if accepted_tuple is None or full_inspection != accepted_tuple:
        fail("full parent/canonical/legacy host tuple differs from the accepted contract")
    _validate_qualification_report(contract_path, contract, artifact_set)
    inspection["full_artifact_tuple"] = full_inspection
    return inspection


def _weight_metrics(
    reference: list[float],
    candidate: list[float],
    rtol: float,
    atol: float,
) -> dict[str, Any]:
    if len(reference) != len(candidate):
        fail("weight-vector lengths differ")
    outside = 0
    maximum_absolute = 0.0
    maximum_relative = 0.0
    for left, right in zip(reference, candidate):
        delta = abs(left - right)
        scale = max(abs(left), abs(right))
        relative = delta / scale if scale else (
            0.0 if delta == 0 else math.inf
        )
        maximum_absolute = max(maximum_absolute, delta)
        maximum_relative = max(maximum_relative, relative)
        if delta > atol + rtol * scale:
            outside += 1
    return {
        "row_count": len(reference),
        "outside_tolerance_count": outside,
        "max_absolute_difference": maximum_absolute,
        "max_relative_difference": maximum_relative,
        "reference_weight_sum": math.fsum(reference),
        "candidate_weight_sum": math.fsum(candidate),
        "all_within_tolerance": outside == 0,
    }


def _legacy_qualify_artifacts(
    contract_path: Path,
    historical_root: Path,
    repeat_a_root: Path,
    repeat_b_root: Path,
    candidate_set_id: str,
    repeat_a_label: str,
    repeat_b_label: str,
    report_path: Path,
) -> dict[str, Any]:
    contract = load_contract(contract_path)
    _require_safe_id(candidate_set_id, "candidate-set id")
    labels = [
        _require_safe_id(repeat_a_label, "repeat-a label"),
        _require_safe_id(repeat_b_label, "repeat-b label"),
    ]
    if len(set(labels)) != 2:
        fail("fresh repetition labels must be distinct")
    roots = [
        historical_root.resolve(),
        repeat_a_root.resolve(),
        repeat_b_root.resolve(),
    ]
    if len(set(roots)) != 3:
        fail(
            "historical and fresh repetition roots must be three "
            "distinct directories"
        )
    baseline = inspect_artifact(historical_root, contract)
    expected_baseline_id = contract["qualification_policy"][
        "baseline_artifact_set_id"
    ]
    if baseline["artifact_set"]["id"] != expected_baseline_id:
        fail("historical root is not the contract baseline")
    candidate = artifact_set_by_id(contract, candidate_set_id)
    if candidate["role"] == "historical_baseline":
        fail("fresh repetitions must target a non-baseline candidate set")
    if not candidate["qualification_eligible"]:
        fail("requested candidate set is diagnostic-only and not qualifiable")
    fresh = [
        inspect_artifact(repeat_a_root, contract),
        inspect_artifact(repeat_b_root, contract),
    ]
    if any(
        item["artifact_set"]["id"] != candidate_set_id for item in fresh
    ):
        fail("fresh repetition does not match the requested candidate set")

    fresh_hashes = [
        {
            contract["manifest_name"]: item["manifest_sha256"],
            **item["file_sha256"],
        }
        for item in fresh
    ]
    for filename in contract["qualification_policy"]["exact_repeat_files"]:
        if fresh_hashes[0][filename] != fresh_hashes[1][filename]:
            fail(
                f"fresh repetitions are not bit-identical for {filename}"
            )

    numeric_policy = contract["qualification_policy"][
        "numeric_weight_comparison"
    ]
    rtol = float(numeric_policy["relative_tolerance"])
    atol = float(numeric_policy["absolute_tolerance"])
    comparisons = [
        _weight_metrics(baseline["weights"], item["weights"], rtol, atol)
        for item in fresh
    ]
    if not all(item["all_within_tolerance"] for item in comparisons):
        fail(
            "fresh representation exceeds the one-time historical "
            "weight tolerance"
        )

    report_body = {
        "schema_version": 1,
        "baseline_artifact_set_id": expected_baseline_id,
        "candidate_artifact_set_id": candidate_set_id,
        "fresh_repetitions": [
            {
                "label": label,
                "manifest_sha256": item["manifest_sha256"],
                "file_sha256": item["file_sha256"],
            }
            for label, item in zip(labels, fresh)
        ],
        "exact_repeat_sha256": {
            EXPECTED_MANIFEST: candidate["manifest_sha256"],
            **candidate["file_sha256"],
        },
        "invariant_sha256": {
            "identity_projection": contract["identity_projection"]["sha256"],
            "summary_projection": contract["summary_projection"]["sha256"],
            "candidate_summary_without_python": candidate[
                "summary_sha256_without_python"
            ],
        },
        "numeric_weight_comparison": {
            "column": numeric_policy["column"],
            "relative_tolerance": numeric_policy["relative_tolerance"],
            "absolute_tolerance": numeric_policy["absolute_tolerance"],
            "all_within_tolerance": True,
            "repeat_metrics": comparisons,
        },
    }
    report = {
        "qualification_id": (
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(report_body)).hexdigest()
        ),
        **report_body,
    }
    if report_path.is_symlink() or report_path.exists():
        fail(
            f"qualification report destination already exists: {report_path}"
        )
    if report_path.parent.is_symlink() or not report_path.parent.is_dir():
        fail(
            "qualification report parent must be an existing "
            "non-symlink directory"
        )
    try:
        with report_path.open(
            "x", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(
                json.dumps(
                    report, ensure_ascii=False, indent=2, sort_keys=True
                )
                + "\n"
            )
    except OSError as exc:
        fail(f"cannot write qualification report: {exc}")
    return report


def qualify_artifacts(
    contract_path: Path,
    repeat_a_root: Path,
    repeat_b_root: Path,
    candidate_set_id: str,
    report_path: Path,
) -> dict[str, Any]:
    """Qualify exactly two independently signed controlled host executions."""

    contract = load_contract(contract_path)
    candidate = artifact_set_by_id(
        contract, _require_safe_id(candidate_set_id, "candidate-set id")
    )
    if (
        candidate["role"] == "historical_baseline"
        or candidate["qualification_eligible"] is not True
    ):
        fail("requested host candidate is not eligible for fresh qualification")
    roots = [Path(repeat_a_root).resolve(), Path(repeat_b_root).resolve()]
    if len(set(roots)) != 2:
        fail("host qualification requires two distinct repetition roots")
    inspections = [
        inspect_signed_repetition(root, contract, candidate) for root in roots
    ]
    for key in ("label", "execution_id", "nonce_hex", "signer_id"):
        if len({item[key] for item in inspections}) != 2:
            fail(f"fresh host repetitions do not have distinct {key}")
    expected_signers = {
        item["signer_id"]
        for item in contract["full_artifact_contract"]["attestation_signers"]
    }
    if {item["signer_id"] for item in inspections} != expected_signers:
        fail("fresh host repetitions do not use both pinned signers")
    first, second = inspections
    if first["source_state"] != second["source_state"]:
        fail("fresh host repetitions do not use identical exact source state")
    if first["full_artifact_tuple"] != second["full_artifact_tuple"]:
        fail("fresh host repetitions do not reproduce the full host tuple")
    if first["exact_repeat_sha256"] != second["exact_repeat_sha256"]:
        fail("fresh host repetitions are not bit-identical for all host artifacts")
    accepted_tuple = first["full_artifact_tuple"]
    public_evidence = {
        "parent": accepted_tuple["parent"],
        "canonical_manifest": accepted_tuple["canonical_manifest"],
        "legacy_manifest": accepted_tuple["legacy_manifest"],
        "projections": accepted_tuple["projections"],
        "canonical_files": accepted_tuple["canonical_files"],
        "legacy_files": accepted_tuple["legacy_files"],
        "auxiliary_files": accepted_tuple["auxiliary_files"],
        "runtime_files": accepted_tuple["runtime_files"],
    }
    body = {
        "schema_version": 3,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate["id"],
        "accepted_full_artifact_tuple": accepted_tuple,
        "exact_repeat_sha256": first["exact_repeat_sha256"],
        "identical_source_state_sha256": first["source_state_sha256"],
        "qualified_source": {
            "public_source": first["source_state"]["public_source"],
            "private_source": first["source_state"]["private_source"],
        },
        "fresh_repetitions": [
            {
                "label": item["label"],
                "execution_id": item["execution_id"],
                "nonce_hex": item["nonce_hex"],
                "signer_id": item["signer_id"],
                "source_state_sha256": item["source_state_sha256"],
                "attestation_id": item["attestation_id"],
                "repetition_manifest_sha256": item[
                    "repetition_manifest_sha256"
                ],
                "public_evidence": public_evidence,
                "embedded_signed_evidence": item["embedded_signed_evidence"],
            }
            for item in inspections
        ],
    }
    report = {
        "qualification_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
        **body,
    }
    destination = Path(report_path)
    if destination.exists() or destination.is_symlink():
        fail("host qualification-report destination already exists")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        fail("host qualification-report parent must be an existing directory")
    _write_json_exclusive(destination, report)
    return report


def _source_record(
    helper: types.ModuleType,
    role: str,
    repository: str,
    source_root: Path,
    archive_path: Path,
    *,
    allowed_untracked_paths: set[str] | None = None,
) -> dict[str, Any]:
    return _helper_call(
        helper,
        "source_record",
        role,
        repository,
        source_root,
        archive_path,
        allowed_untracked_paths=allowed_untracked_paths,
    )


def _archive_snapshot_for_record(
    path: Path, record: dict[str, Any], description: str
) -> FileSnapshot:
    snapshot = read_file_snapshot(
        path, description, maximum_bytes=MAX_ARCHIVE_BYTES
    )
    if _evidence(snapshot) != record["source_archive"]:
        fail(f"{description} changed after exact Git-archive verification")
    return snapshot


def _generation_program_records(
    private_root: Path,
    public_root: Path,
) -> tuple[dict[str, Any], dict[str, FileSnapshot]]:
    records: dict[str, Any] = {}
    snapshots: dict[str, FileSnapshot] = {}
    for relative in GENERATION_PROGRAMS:
        private = read_file_snapshot(
            private_root / Path(relative), f"private generation program {relative}"
        )
        public = read_file_snapshot(
            public_root / Path(relative), f"public generation program {relative}"
        )
        if private.data != public.data:
            fail(f"public/private generation program bytes differ: {relative}")
        snapshots[relative] = private
        records[relative] = {
            "relative_path": relative,
            "sha256": private.sha256,
            "size_bytes": private.size_bytes,
        }
    _validate_program_records(records)
    return records, snapshots


def _planned_host_commands(
    python_executable: str,
    private_root: Path,
    jj_root: Path,
    run_root: Path,
    host_output: Path,
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for index, relative in enumerate(GENERATION_PROGRAMS):
        argv = [python_executable, str((private_root / Path(relative)).resolve())]
        if index < 3:
            argv.extend(
                [
                    "--jj-root",
                    str(jj_root.resolve()),
                    "--run-dir",
                    str(run_root.resolve()),
                    "--out",
                    str(host_output.resolve()),
                    "--iso",
                    "Padova",
                ]
            )
            if index == 0:
                argv.extend(["--expected-radial-step-kpc", "0.5"])
        else:
            argv.extend(["--out", str(host_output.resolve())])
        commands.append(
            {
                "program": relative,
                "argv": argv,
                "cwd": str(private_root.resolve()),
                "shell": False,
            }
        )
    return commands


def execute_fresh_repetition(
    contract_path: Path,
    *,
    jj_root: Path,
    jj_source_archive: Path,
    padova_archive: Path,
    public_source_root: Path,
    public_source_archive: Path,
    private_source_root: Path,
    private_source_archive: Path,
    numerical_runtime_manifest: Path,
    candidate_set_id: str,
    signer_id: str,
    signing_key: Path,
    repeat_label: str,
    execution_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Execute the five pinned host producers in a fresh archive-built root."""

    contract = load_contract(contract_path)
    candidate = artifact_set_by_id(
        contract, _require_safe_id(candidate_set_id, "candidate-set id")
    )
    if candidate["qualification_eligible"] is not True:
        fail("requested host candidate is not qualification eligible")
    signer = _candidate_signer(
        contract, _require_safe_id(signer_id, "host signer id")
    )
    label = _require_safe_id(repeat_label, "host repetition label")
    helper, helper_snapshot = _controller_helper()
    if _helper_call(helper, "signing_public_key", Path(signing_key)) != signer[
        "public_key"
    ]:
        fail("host signing key does not match the contract-pinned signer")
    execution_environment = _helper_call(helper, "detect_execution_environment")
    policy = contract["full_artifact_contract"]["qualification_policy"]
    if execution_environment not in policy["allowed_execution_environments"]:
        fail("host execution environment is not contract allowed")

    roots = [
        Path(jj_root).resolve(),
        Path(public_source_root).resolve(),
        Path(private_source_root).resolve(),
    ]
    if len(set(roots)) != 3:
        fail("JJ/public/private source roots must be three distinct directories")
    locked = contract["full_artifact_contract"]["locked_inputs"]
    jj_source = _source_record(
        helper,
        "jj_generator",
        locked["jj_repository"],
        jj_root,
        jj_source_archive,
    )
    public_source = _source_record(
        helper,
        "public_release",
        locked["public_repository"],
        public_source_root,
        public_source_archive,
    )
    private_source = _source_record(
        helper,
        "private_production",
        locked["private_repository"],
        private_source_root,
        private_source_archive,
    )
    if jj_source["commit_sha"] != locked["jj_commit"]:
        fail("JJ source is not at the locked commit")
    if public_source["git_tree_sha"] != private_source["git_tree_sha"]:
        fail("public/private source Git trees are not identical")
    jj_archive = _archive_snapshot_for_record(
        jj_source_archive, jj_source, "exact JJ source archive"
    )
    public_archive = _archive_snapshot_for_record(
        public_source_archive, public_source, "exact public source archive"
    )
    private_archive = _archive_snapshot_for_record(
        private_source_archive, private_source, "exact private source archive"
    )
    padova = read_file_snapshot(
        padova_archive, "locked Padova archive", maximum_bytes=MAX_ARCHIVE_BYTES
    )
    if _evidence(padova) != {
        "filename": locked["padova_archive"]["filename"],
        "sha256": locked["padova_archive"]["sha256"],
        "size_bytes": locked["padova_archive"]["size_bytes"],
    }:
        fail("Padova archive differs from the release data lock")
    runtime_manifest = read_file_snapshot(
        numerical_runtime_manifest,
        "host numerical-runtime manifest",
        maximum_bytes=MAX_JSON_BYTES,
    )
    runtime_document = load_json_bytes(
        runtime_manifest.data, "host numerical-runtime manifest"
    )
    _helper_call(helper, "validate_runtime_manifest", runtime_document)
    python_path = Path(runtime_document["python_executable"])
    python_executable_record = _runtime_executable_chain(str(python_path))

    execution = Path(execution_root)
    repetition = Path(output_root)
    execution_resolved = execution.resolve()
    repetition_resolved = repetition.resolve()
    if (
        execution_resolved == repetition_resolved
        or execution_resolved in repetition_resolved.parents
        or repetition_resolved in execution_resolved.parents
    ):
        fail("host execution/repetition roots must be distinct and non-nested")
    for path, description in (
        (execution, "host execution root"),
        (repetition, "host repetition root"),
    ):
        if path.exists() or path.is_symlink():
            fail(f"fresh {description} must not already exist")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            fail(f"fresh {description} parent is not a regular directory")
    execution.mkdir()
    jj_execution = execution / "source-jj"
    public_execution = execution / "source-public"
    private_execution = execution / "source-private"
    execution_jj_tree = _helper_call(
        helper,
        "materialize_jj_archive_checkout",
        Path(jj_root),
        jj_archive,
        jj_execution,
        locked["jj_commit"],
    )
    _extract_git_tar(public_archive, public_execution, "public source")
    _extract_git_tar(private_archive, private_execution, "private source")
    (
        execution_padova_paths,
        padova_extraction,
        execution_padova_directories,
    ) = _helper_call(
        helper, "extract_padova_overlay_snapshot", padova, jj_execution
    )
    execution_jj_source = _source_record(
        helper,
        "jj_generator",
        locked["jj_repository"],
        jj_execution,
        jj_source_archive,
        allowed_untracked_paths=execution_padova_paths,
    )
    if execution_jj_source != jj_source:
        fail("fresh JJ execution checkout differs from the locked source state")

    controller_snapshot = read_file_snapshot(
        Path(__file__), "host execution controller", maximum_bytes=2_000_000
    )
    for source_root, description in (
        (public_execution, "public archive"),
        (private_execution, "private archive"),
    ):
        archived_controller = read_file_snapshot(
            source_root / "scripts" / "verify_host_artifact_contract.py",
            f"{description} host execution controller",
            maximum_bytes=2_000_000,
        )
        archived_helper = read_file_snapshot(
            source_root / "scripts" / "verify_age_cut_ssp_contract.py",
            f"{description} controller helper",
            maximum_bytes=2_000_000,
        )
        if archived_controller.data != controller_snapshot.data:
            fail(f"running host controller differs from {description}")
        if archived_helper.data != helper_snapshot.data:
            fail(f"running host security helper differs from {description}")
    program_records, _ = _generation_program_records(
        private_execution, public_execution
    )

    original = read_file_snapshot(
        jj_execution / Path(JJ_PARAMETERS_PATH), "locked JJ original parameters"
    )
    sfr = read_file_snapshot(
        jj_execution / Path(JJ_SFR_PATH), "locked JJ SFR parameters"
    )
    if original.sha256 != PARAMETERS_ORIGINAL_SHA256 or sfr.sha256 != SFR_SHA256:
        fail("JJ runtime-source parameters differ from the release locks")
    runtime_parameters = _derive_runtime_parameters(original.data)
    runtime_bundle = execution / "runtime-inputs"
    run_root = execution / "jj-run"
    host_output = execution / "host-output"
    runtime_bundle.mkdir()
    run_root.mkdir()
    host_output.mkdir()
    runtime_values = {
        FULL_RUNTIME_FILES[0]: original.data,
        FULL_RUNTIME_FILES[1]: runtime_parameters,
        FULL_RUNTIME_FILES[2]: sfr.data,
        FULL_RUNTIME_FILES[3]: runtime_manifest.data,
    }
    for name, data in runtime_values.items():
        _write_bytes_exclusive(runtime_bundle / name, data)
    _write_bytes_exclusive(run_root / "parameters", runtime_parameters)
    _write_bytes_exclusive(run_root / "sfrd_peaks_parameters", sfr.data)
    runtime_evidence = {
        name: _evidence(
            read_file_snapshot(runtime_bundle / name, f"host runtime input {name}")
        )
        for name in FULL_RUNTIME_FILES
    }
    commands = _planned_host_commands(
        runtime_document["python_executable"],
        private_execution,
        jj_execution,
        run_root,
        host_output,
    )
    _validate_planned_commands(commands, runtime_document)
    source_state = {
        "jj_source": jj_source,
        "public_source": public_source,
        "private_source": private_source,
        "padova_archive": locked["padova_archive"],
        "padova_extraction": padova_extraction,
        "runtime_executable": python_executable_record,
        "controller_program": _evidence(controller_snapshot),
        "controller_helper": _evidence(helper_snapshot),
    }
    _validate_source_state(source_state, contract, helper)
    source_state_sha256 = hashlib.sha256(
        canonical_json_bytes(source_state)
    ).hexdigest()
    execution_id = str(uuid.uuid4())
    nonce_hex = secrets.token_hex(32)
    issued_utc = _helper_call(helper, "utc_now")
    challenge_body = {
        "schema_version": 1,
        "namespace": HOST_START_NAMESPACE,
        "contract_id": contract["contract_id"],
        "candidate_artifact_set_id": candidate["id"],
        "signer_id": signer["signer_id"],
        "repeat_label": label,
        "execution_id": execution_id,
        "nonce_hex": nonce_hex,
        "issued_utc": issued_utc,
        "controller": policy["fresh_execution_controller"],
        "source_state": source_state,
        "source_state_sha256": source_state_sha256,
        "locked_inputs": locked,
        "runtime_inputs": runtime_evidence,
        "generation_programs": program_records,
        "planned_commands": commands,
        "execution_root_created_empty": True,
    }
    challenge = {
        "challenge_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(challenge_body)).hexdigest(),
        **challenge_body,
    }
    challenge_path = execution / HOST_START_CHALLENGE_NAME
    _write_json_exclusive(challenge_path, challenge)
    _helper_call(
        helper,
        "sign_document",
        challenge_path,
        signing_key,
        namespace=HOST_START_NAMESPACE,
        destination_name=HOST_START_SIGNATURE_NAME,
    )
    challenge_snapshot = read_file_snapshot(
        challenge_path, "signed host start challenge"
    )
    challenge_signature = read_file_snapshot(
        execution / HOST_START_SIGNATURE_NAME, "host start-challenge signature"
    )
    _helper_call(
        helper,
        "verify_signature",
        challenge_snapshot,
        challenge_signature,
        signer,
        namespace=HOST_START_NAMESPACE,
    )

    child_environment = os.environ.copy()
    child_environment.update(EXPECTED_NUMERICAL_ENV)
    child_environment["PYTHONNOUSERSITE"] = "1"
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    child_environment.pop("PYTHONPATH", None)
    command_records: list[dict[str, Any]] = []
    run_started_utc = _helper_call(helper, "utc_now")
    for command in commands:
        try:
            result = subprocess.run(
                command["argv"],
                cwd=command["cwd"],
                env=child_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
            )
        except OSError as exc:
            fail(f"cannot execute pinned host command {command['program']}: {exc}")
        command_records.append(
            {
                **command,
                "return_code": result.returncode,
                "stdout": {
                    "sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "size_bytes": len(result.stdout),
                },
                "stderr": {
                    "sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "size_bytes": len(result.stderr),
                },
            }
        )
        if result.returncode != 0:
            fail(
                f"pinned host command {command['program']} failed with "
                f"return code {result.returncode}; execution retained at {execution}"
            )
    run_completed_utc = _helper_call(helper, "utc_now")
    for name in FULL_RUNTIME_FILES:
        _write_bytes_exclusive(host_output / name, runtime_values[name])
    canonical = inspect_artifact(host_output, contract)
    if canonical["artifact_set"]["id"] != candidate["id"]:
        fail("fresh host output does not match the requested candidate")
    full_tuple = inspect_full_artifact(host_output, contract)

    if _runtime_executable_chain(str(python_path)) != python_executable_record:
        fail("numerical-runtime Python executable changed during the host run")
    _helper_call(
        helper,
        "verify_extracted_archive_tree",
        jj_execution,
        execution_jj_tree,
        "captured JJ Git archive",
        allow_git_metadata=True,
        allowed_overlay_files=execution_padova_paths,
        allowed_overlay_directories=execution_padova_directories,
    )
    if (
        _source_record(
            helper,
            "jj_generator",
            locked["jj_repository"],
            jj_execution,
            jj_source_archive,
            allowed_untracked_paths=execution_padova_paths,
        )
        != execution_jj_source
    ):
        fail("fresh JJ execution source changed during the host run")
    post_sources = (
        _source_record(
            helper,
            "jj_generator",
            locked["jj_repository"],
            jj_root,
            jj_source_archive,
        ),
        _source_record(
            helper,
            "public_release",
            locked["public_repository"],
            public_source_root,
            public_source_archive,
        ),
        _source_record(
            helper,
            "private_production",
            locked["private_repository"],
            private_source_root,
            private_source_archive,
        ),
    )
    if post_sources != (jj_source, public_source, private_source):
        fail("host source state changed during the controlled execution")
    if read_file_snapshot(Path(__file__), "post-run host controller") != controller_snapshot:
        fail("host controller changed during the controlled execution")
    post_helper, post_helper_snapshot = _controller_helper()
    del post_helper
    if post_helper_snapshot != helper_snapshot:
        fail("host controller helper changed during the controlled execution")

    execution_body = {
        "schema_version": 1,
        "controller": policy["fresh_execution_controller"],
        "challenge_id": challenge["challenge_id"],
        "execution_id": execution_id,
        "nonce_hex": nonce_hex,
        "commands": command_records,
        "run_directory_created_empty": True,
        "host_output_directory_created_empty": True,
        "run_started_utc": run_started_utc,
        "run_completed_utc": run_completed_utc,
        "source_state_sha256": source_state_sha256,
        "full_artifact_tuple": full_tuple,
    }
    execution_record = {
        "execution_record_id": "sha256:"
        + hashlib.sha256(canonical_json_bytes(execution_body)).hexdigest(),
        **execution_body,
    }
    execution_record_path = execution / HOST_EXECUTION_RECORD_NAME
    _write_json_exclusive(execution_record_path, execution_record)
    execution_record_snapshot = read_file_snapshot(
        execution_record_path, "host execution record"
    )

    temporary = Path(
        tempfile.mkdtemp(prefix=".host-repeat-", dir=repetition.parent)
    )
    try:
        for name in _host_exact_repeat_files():
            source = read_file_snapshot(host_output / name, f"fresh host output {name}")
            _write_bytes_exclusive(temporary / name, source.data)
        _write_bytes_exclusive(
            temporary / HOST_START_CHALLENGE_NAME, challenge_snapshot.data
        )
        _write_bytes_exclusive(
            temporary / HOST_START_SIGNATURE_NAME, challenge_signature.data
        )
        _write_bytes_exclusive(
            temporary / HOST_EXECUTION_RECORD_NAME, execution_record_snapshot.data
        )
        provenance = {
            "schema_version": 1,
            "repeat_label": label,
            "execution_id": execution_id,
            "execution_environment": execution_environment,
            "run_started_utc": run_started_utc,
            "run_completed_utc": run_completed_utc,
            "signer_id": signer["signer_id"],
            "controller": policy["fresh_execution_controller"],
            "source_state": source_state,
            "generation_programs": program_records,
            "runtime_files": runtime_evidence,
            "full_artifact_tuple": full_tuple,
            "start_challenge": _evidence(
                read_file_snapshot(
                    temporary / HOST_START_CHALLENGE_NAME,
                    "packaged host start challenge",
                )
            ),
            "start_challenge_signature": _evidence(
                read_file_snapshot(
                    temporary / HOST_START_SIGNATURE_NAME,
                    "packaged host start signature",
                )
            ),
            "execution_record": _evidence(
                read_file_snapshot(
                    temporary / HOST_EXECUTION_RECORD_NAME,
                    "packaged host execution record",
                )
            ),
        }
        _write_json_exclusive(temporary / HOST_PROVENANCE_NAME, provenance)
        _write_manifest(
            temporary / HOST_REPETITION_MANIFEST,
            _host_repetition_manifest_members(),
            temporary,
        )
        snapshots = {
            name: read_file_snapshot(
                temporary / name, f"pre-attestation host repetition {name}"
            )
            for name in (
                *_host_repetition_manifest_members(),
                HOST_REPETITION_MANIFEST,
            )
        }
        attestation_body = _attestation_body(
            contract, candidate, challenge, full_tuple, snapshots
        )
        attestation = {
            "attestation_id": "sha256:"
            + hashlib.sha256(canonical_json_bytes(attestation_body)).hexdigest(),
            **attestation_body,
        }
        attestation_path = temporary / HOST_ATTESTATION_NAME
        _write_json_exclusive(attestation_path, attestation)
        _helper_call(
            helper,
            "sign_document",
            attestation_path,
            signing_key,
            namespace=HOST_ATTESTATION_NAMESPACE,
            destination_name=HOST_ATTESTATION_SIGNATURE_NAME,
        )
        if {path.name for path in temporary.iterdir()} != _host_repetition_files():
            fail("generated signed host repetition has an unexpected file set")
        os.replace(temporary, repetition)
        return inspect_signed_repetition(repetition, contract, candidate)
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
    argument_parser.add_argument("--artifact-root", type=Path)
    argument_parser.add_argument("--repeat-a-root", type=Path)
    argument_parser.add_argument("--repeat-b-root", type=Path)
    argument_parser.add_argument("--candidate-set-id")
    argument_parser.add_argument("--report", type=Path)
    argument_parser.add_argument("--jj-root", type=Path)
    argument_parser.add_argument("--jj-source-archive", type=Path)
    argument_parser.add_argument("--padova-archive", type=Path)
    argument_parser.add_argument("--public-source-root", type=Path)
    argument_parser.add_argument("--public-source-archive", type=Path)
    argument_parser.add_argument("--private-source-root", type=Path)
    argument_parser.add_argument("--private-source-archive", type=Path)
    argument_parser.add_argument("--numerical-runtime-manifest", type=Path)
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
            if args.artifact_root is None:
                fail("verify mode requires --artifact-root")
            forbidden = (
                args.repeat_a_root,
                args.repeat_b_root,
                args.candidate_set_id,
                args.report,
                args.jj_root,
                args.jj_source_archive,
                args.padova_archive,
                args.public_source_root,
                args.public_source_archive,
                args.private_source_root,
                args.private_source_archive,
                args.numerical_runtime_manifest,
                args.signer_id,
                args.signing_key,
                args.repeat_label,
                args.execution_root,
                args.out,
            )
            if any(value is not None for value in forbidden):
                fail("verify mode received qualification-only options")
            inspection = verify_artifact(
                args.contract, args.artifact_root
            )
            print(
                "PASS host artifact contract "
                f"({inspection['artifact_set']['id']}; "
                f"{inspection['row_count']} rows)"
            )
            return
        if args.mode == "qualify":
            if args.artifact_root is not None:
                fail("qualify mode does not accept --artifact-root")
            required = {
                "repeat_a_root": args.repeat_a_root,
                "repeat_b_root": args.repeat_b_root,
                "candidate_set_id": args.candidate_set_id,
                "report": args.report,
            }
            missing = sorted(
                name for name, value in required.items() if value is None
            )
            if missing:
                fail(f"qualify mode lacks options: {missing}")
            report = qualify_artifacts(
                args.contract,
                args.repeat_a_root,
                args.repeat_b_root,
                args.candidate_set_id,
                args.report,
            )
            print(
                "PASS host artifact qualification "
                f"({report['qualification_id']})"
            )
            return
        required = {
            "jj_root": args.jj_root,
            "jj_source_archive": args.jj_source_archive,
            "padova_archive": args.padova_archive,
            "public_source_root": args.public_source_root,
            "public_source_archive": args.public_source_archive,
            "private_source_root": args.private_source_root,
            "private_source_archive": args.private_source_archive,
            "numerical_runtime_manifest": args.numerical_runtime_manifest,
            "candidate_set_id": args.candidate_set_id,
            "signer_id": args.signer_id,
            "signing_key": args.signing_key,
            "repeat_label": args.repeat_label,
            "execution_root": args.execution_root,
            "out": args.out,
        }
        missing = sorted(name for name, value in required.items() if value is None)
        if missing:
            fail(f"execute mode lacks options: {missing}")
        result = execute_fresh_repetition(
            args.contract,
            jj_root=args.jj_root,
            jj_source_archive=args.jj_source_archive,
            padova_archive=args.padova_archive,
            public_source_root=args.public_source_root,
            public_source_archive=args.public_source_archive,
            private_source_root=args.private_source_root,
            private_source_archive=args.private_source_archive,
            numerical_runtime_manifest=args.numerical_runtime_manifest,
            candidate_set_id=args.candidate_set_id,
            signer_id=args.signer_id,
            signing_key=args.signing_key,
            repeat_label=args.repeat_label,
            execution_root=args.execution_root,
            output_root=args.out,
        )
        print(
            "PASS controlled fresh host repetition "
            f"({result['label']}; signer {result['signer_id']})"
        )
    except ContractError as exc:
        raise SystemExit(
            f"HOST ARTIFACT CONTRACT FAIL: {exc}"
        ) from exc


if __name__ == "__main__":
    main()
