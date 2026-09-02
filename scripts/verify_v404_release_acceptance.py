#!/usr/bin/env python3
"""Fail-closed public acceptance gate for the v4.0.4 release package.

The component contracts remain the authority for their signed evidence.  This
gate adds the release-level invariant that one accepted candidate from every
contract, both frozen result sets, and the headline posterior artifacts all
refer to the same production source and the same accepted local run.
"""

from __future__ import annotations

import os as _bootstrap_os
import sys as _bootstrap_sys


def _reexec_isolated_if_main() -> None:
    """Remove the repository and working directory from Python import search."""

    if __name__ != "__main__" or _bootstrap_sys.flags.isolated:
        return
    flags = ["-I", "-B"]
    if _bootstrap_sys.flags.optimize:
        flags.append("-" + "O" * _bootstrap_sys.flags.optimize)
    _bootstrap_os.execv(
        _bootstrap_sys.executable,
        [
            _bootstrap_sys.executable,
            *flags,
            _bootstrap_os.path.abspath(__file__),
            *_bootstrap_sys.argv[1:],
        ],
    )


_reexec_isolated_if_main()

import argparse
import base64
import csv
from contextlib import contextmanager
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
from types import ModuleType, SimpleNamespace
from typing import Any, BinaryIO, Callable, Iterator, Mapping
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_PATH = "provenance/V4_0_4_RELEASE_ACCEPTANCE.json"
RELEASE_VERSION = "4.0.4"
RESULTS_ARCHIVE_NAME = (
    "Exo-Earth-Candidate-Population-Projection-Pipeline-v4.0.4-results.zip"
)
RESULTS_CHECKSUM_NAME = RESULTS_ARCHIVE_NAME + ".sha256"
RESULTS_ARCHIVE_PREFIX = RESULTS_ARCHIVE_NAME[:-4]
PUBLIC_RESULTS_MANIFEST_NAME = "SHA256SUMS_v404_local_production.txt"
PUBLIC_RESULTS_REPORT_NAME = "V404_LOCAL_PRODUCTION_REPORT.json"
SOURCE_ARCHIVE_NAME = (
    "exo-earth-candidate-population-projection-pipeline-4.0.4-source.zip"
)
SOURCE_CHECKSUM_NAME = "PUBLIC_SHA256SUMS"
TRUSTED_SOURCE_ARCHIVE_ENV = "V404_TRUSTED_SOURCE_ARCHIVE"
TRUSTED_SOURCE_CHECKSUM_ENV = "V404_TRUSTED_SOURCE_CHECKSUM"
SOURCE_ZIP_TIME = (2026, 8, 30, 0, 0, 0)
HEADLINE_SUMMARY_PATHS = {
    "constant": (
        "propagations/corrected-constant/canonical/"
        "galactic_posterior_summary_constant.json"
    ),
    "zero": (
        "propagations/corrected-zero/canonical/"
        "galactic_posterior_summary_zero.json"
    ),
}
HEADLINE_DRAW_PATHS = {
    "constant": (
        "propagations/corrected-constant/canonical/"
        "galactic_posterior_draws_constant.csv.gz"
    ),
    "zero": (
        "propagations/corrected-zero/canonical/"
        "galactic_posterior_draws_zero.csv.gz"
    ),
}
FINALIZATION_PATHS = (ACCEPTANCE_PATH, "MANIFEST.sha256")
POST_COMPUTATION_POLICY = "computational-ancestor-exact-evidence-diff-v1"
POST_COMPUTATION_STATIC_PATHS = frozenset(
    {
        ACCEPTANCE_PATH,
        "MANIFEST.sha256",
        ".zenodo.json",
        "CITATION.cff",
        "CHANGELOG.md",
        "LICENSE",
        "AUTHORSHIP_AND_LICENSING_DECLARATION.md",
        "LICENSE_POLICY.md",
        "NOTICE",
        "README.md",
        "REPRODUCIBILITY.md",
        "THIRD_PARTY_NOTICES.md",
        "provenance/LICENSE_MATRIX.csv",
        "provenance/PUBLIC_EXCLUSIONS.csv",
        "provenance/RELEASE_4_0_4_CHANGE_RECORD.json",
        "provenance/ROMAN_MIT_PATHS.txt",
    }
)
MANIFEST_SKIP_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "local-artifacts",
    "outputs",
    "results",
    "dist",
}
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_FREEZE_FILE_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
REPORT_ID = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
SAFE_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
REPARSE_POINT = 0x400

CONTRACT_PATHS = {
    "host": "provenance/HOST_ARTIFACT_CONTRACT_v4_0_4.json",
    "age": "provenance/AGE_CUT_SSP_CONTRACT_v4_0_4.json",
    "radial": "provenance/RADIAL_SSP_CONTRACT_v4_0_4.json",
    "local": "provenance/LOCAL_RUN_ATTESTATION_CONTRACT_v4_0_4.json",
}

FREEZE_SPECS = {
    "numerical": {
        "root": "research/bryson-joint-posterior/frozen-v4",
        "manifest": "SHA256SUMS_v4_numerical_freeze.txt",
        "targets": (
            "V4_NUMERICAL_FREEZE.json",
            "v4_parameter_quantiles.csv",
            "v4_galactic_quantiles.csv",
            "V4_NUMERICAL_FREEZE.md",
        ),
        "json": "V4_NUMERICAL_FREEZE.json",
    },
    "sensitivity": {
        "root": "research/v4-validation/frozen-sensitivities",
        "manifest": "SHA256SUMS_v4_sensitivity_freeze.txt",
        "targets": (
            "V4_SENSITIVITY_FREEZE.json",
            "v4_sensitivity_register.csv",
        ),
        "json": "V4_SENSITIVITY_FREEZE.json",
    },
}

POSTERIOR_KEYS = {
    "corrected_constant_full",
    "corrected_constant_propagation",
    "corrected_zero_full",
    "corrected_zero_propagation",
    "legacy_constant_full",
    "legacy_constant_propagation",
}

LOCAL_REPORT_KEYS = {
    "schema_version",
    "qualification_status",
    "contract_id",
    "candidate_id",
    "source_commit",
    "source_tree",
    "source_archive_sha256",
    "source_archive_size_bytes",
    "source_file_set_sha256",
    "command_plan_sha256",
    "numerical_runtime_manifest_sha256",
    "run_id_sha256",
    "challenge_id",
    "start_signer_id",
    "start_challenge_sha256",
    "start_signature_sha256",
    "completion_id",
    "completion_signer_id",
    "completion_attestation_sha256",
    "completion_signature_sha256",
    "execution_started_utc",
    "execution_ended_utc",
    "command_results",
    "output_manifest_sha256",
    "output_file_count",
    "output_total_size_bytes",
    "output_file_set_sha256",
    "report_id",
}

LOCAL_HASH_FIELDS = {
    "source_archive_sha256",
    "source_file_set_sha256",
    "command_plan_sha256",
    "numerical_runtime_manifest_sha256",
    "run_id_sha256",
    "start_challenge_sha256",
    "start_signature_sha256",
    "completion_attestation_sha256",
    "completion_signature_sha256",
    "output_manifest_sha256",
    "output_file_set_sha256",
}

LOCAL_BINDING_FIELDS = {
    "report_id",
    "contract_sha256",
    "public_report_sha256",
    "candidate_id",
    "source_archive_sha256",
    "source_archive_size_bytes",
    "command_plan_sha256",
    "numerical_runtime_manifest_sha256",
    "output_manifest_sha256",
    "output_file_set_sha256",
    "output_file_count",
    "output_total_size_bytes",
}


class ReleaseAcceptanceError(RuntimeError):
    """A public release invariant was not proved."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class LargeFileEvidence:
    path: Path
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int]


def fail(message: str) -> None:
    raise ReleaseAcceptanceError(message)


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
    except (TypeError, ValueError) as error:
        fail(f"cannot serialize canonical JSON: {error}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key is forbidden: {key!r}")
        result[key] = value
    return result


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        fail("non-finite or overflowing JSON number is forbidden")
    return value


def load_json_bytes(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"{label} is not strict UTF-8: {error}")
    if text.startswith("\ufeff"):
        fail(f"{label} contains a UTF-8 BOM")
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: fail(
                f"non-finite JSON constant is forbidden: {value}"
            ),
            parse_float=_finite_float,
        )
    except ReleaseAcceptanceError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        fail(f"cannot parse {label}: {error}")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT
    )


def _safe_relative(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or "\r" in value
        or "\n" in value
        or ":" in value
    ):
        fail(f"{label} is not a canonical POSIX relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail(f"{label} contains absolute, dot, or traversal syntax")
    return value


def _safe_leaf(value: Any, label: str) -> str:
    if not isinstance(value, str) or SAFE_LEAF.fullmatch(value) is None:
        fail(f"{label} is not a portable leaf filename")
    if value in {".", ".."}:
        fail(f"{label} is not a portable leaf filename")
    return value


def _plain_path(root: Path, relative: str, *, directory: bool) -> Path:
    _safe_relative(relative, "repository path")
    try:
        current = root.resolve(strict=True)
    except OSError as error:
        fail(f"repository root cannot be resolved: {error}")
    try:
        root_metadata = current.lstat()
    except OSError as error:
        fail(f"repository root cannot be inspected: {error}")
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        fail("repository root must be a plain directory")
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"missing release path {relative}: {error}")
        if _is_link_or_reparse(metadata):
            fail(f"release path contains a link or reparse point: {relative}")
        last = index == len(parts) - 1
        if not last and not stat.S_ISDIR(metadata.st_mode):
            fail(f"release path has a non-directory parent: {relative}")
        if last:
            required = stat.S_ISDIR if directory else stat.S_ISREG
            if not required(metadata.st_mode):
                kind = "directory" if directory else "regular file"
                fail(f"release path is not a {kind}: {relative}")
    return current


def read_snapshot(
    root: Path,
    relative: str,
    label: str,
    *,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> Snapshot:
    path = _plain_path(root, relative, directory=False)
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if _identity(opened) != _identity(before):
                fail(f"{label} changed while it was opened")
            data = handle.read(maximum_bytes + 1)
            after = os.fstat(handle.fileno())
    except ReleaseAcceptanceError:
        raise
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if len(data) > maximum_bytes:
        fail(f"{label} exceeds the byte limit")
    if _identity(after) != _identity(opened) or len(data) != opened.st_size:
        fail(f"{label} changed while it was read")
    return Snapshot(
        path=path,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        identity=_identity(opened),
    )


def recheck_snapshot(snapshot: Snapshot, label: str) -> None:
    try:
        current = snapshot.path.lstat()
    except OSError as error:
        fail(f"cannot recheck {label}: {error}")
    if _is_link_or_reparse(current) or _identity(current) != snapshot.identity:
        fail(f"{label} changed after its stable snapshot")


@contextmanager
def open_stable_file(path: Path, label: str) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one ordinary file once and retain its identity through consumption."""

    candidate = Path(os.path.abspath(path))
    try:
        before = candidate.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular non-link file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    ancestor_descriptors: list[int] = []
    try:
        if os.name == "posix" and getattr(os, "O_DIRECTORY", 0):
            directory_flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            parent_descriptor = os.open(candidate.anchor, directory_flags)
            ancestor_descriptors.append(parent_descriptor)
            parts = candidate.parts[1:]
            for part in parts[:-1]:
                parent_descriptor = os.open(
                    part, directory_flags, dir_fd=parent_descriptor
                )
                ancestor_descriptors.append(parent_descriptor)
            descriptor = os.open(parts[-1], flags, dir_fd=parent_descriptor)
        else:
            descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            fail(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            yield handle, opened
            after_fd = os.fstat(handle.fileno())
            if _identity(after_fd) != _identity(opened):
                fail(f"{label} changed while it was consumed")
    except ReleaseAcceptanceError:
        raise
    except OSError as error:
        fail(f"cannot consume {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for ancestor in reversed(ancestor_descriptors):
            os.close(ancestor)
    try:
        after = candidate.lstat()
    except OSError as error:
        fail(f"cannot re-inspect {label}: {error}")
    if _is_link_or_reparse(after) or _identity(after) != _identity(before):
        fail(f"{label} changed during its stable consumption")


def read_external_snapshot(
    path: Path, label: str, *, maximum_bytes: int = MAX_JSON_BYTES
) -> Snapshot:
    with open_stable_file(path, label) as (handle, opened):
        data = handle.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            fail(f"{label} exceeds the byte limit")
        if len(data) != opened.st_size:
            fail(f"{label} changed while it was read")
    return Snapshot(
        path=Path(path),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        identity=_identity(opened),
    )


def _path_within(path: Path, root: Path) -> bool:
    try:
        candidate = Path(path).resolve(strict=False)
        boundary = Path(root).resolve(strict=True)
        return os.path.commonpath((str(candidate), str(boundary))) == str(boundary)
    except (OSError, ValueError):
        return False


@contextmanager
def isolated_repository_import_path(repository_root: Path) -> Iterator[None]:
    """Temporarily remove the repository/CWD from normal import resolution."""

    original = list(sys.path)
    safe: list[str] = []
    try:
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
    except OSError:
        runtime_prefix = Path(sys.prefix).resolve(strict=False)
    for entry in original:
        if not entry:
            continue
        try:
            candidate = Path(entry).resolve(strict=False)
        except OSError:
            continue
        if _path_within(candidate, repository_root) and not (
            runtime_prefix != Path(repository_root).resolve(strict=True)
            and _path_within(candidate, runtime_prefix)
        ):
            continue
        safe.append(entry)
    sys.path[:] = safe
    try:
        yield
    finally:
        sys.path[:] = original


def load_source_only_module(
    repository_root: Path,
    relative: str,
    module_name: str,
    label: str,
) -> ModuleType:
    """Compile one stable ``.py`` snapshot without consulting bytecode caches.

    Release verifiers are part of the trust boundary.  A normal import may read
    an untracked ``__pycache__`` entry even when Python is invoked with ``-B``.
    This loader accepts only an explicit repository ``.py`` path, snapshots its
    bytes through the same no-link release path boundary, compiles those exact
    bytes, and never asks importlib for a cached-code candidate.
    """

    _safe_relative(relative, f"{label} source path")
    if PurePosixPath(relative).suffix != ".py":
        fail(f"{label} source-only loader rejects bytecode/non-source paths")
    if not isinstance(module_name, str) or re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
        module_name,
    ) is None:
        fail(f"{label} module name is unsafe")
    snapshot = read_snapshot(
        Path(repository_root),
        relative,
        f"{label} source",
        maximum_bytes=8 * 1024 * 1024,
    )
    try:
        code = compile(
            snapshot.data,
            str(snapshot.path),
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=-1,
        )
    except (SyntaxError, ValueError, TypeError) as error:
        fail(f"cannot compile {label} source snapshot: {error}")

    module = ModuleType(module_name)
    module.__file__ = str(snapshot.path)
    module.__package__ = module_name.rpartition(".")[0]
    module.__cached__ = None
    module.__loader__ = None
    module.__spec__ = None
    module.__dict__["__source_only_sha256__"] = snapshot.sha256
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        with isolated_repository_import_path(repository_root):
            exec(code, module.__dict__)
    except BaseException as error:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        fail(f"cannot execute {label} source snapshot: {error}")
    recheck_snapshot(snapshot, f"{label} source")
    if (
        module.__dict__.get("__source_only_sha256__") != snapshot.sha256
        or module.__dict__.get("__cached__") is not None
    ):
        fail(f"{label} changed its source-only loader evidence")
    return module


def recheck_large_file(evidence: LargeFileEvidence, label: str) -> None:
    try:
        current = evidence.path.lstat()
    except OSError as error:
        fail(f"cannot recheck {label}: {error}")
    if _is_link_or_reparse(current) or _identity(current) != evidence.identity:
        fail(f"{label} changed after its stable verification")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    item = _mapping(value, label)
    if set(item) != expected:
        fail(
            f"{label} keys changed: expected={sorted(expected)!r}, "
            f"actual={sorted(item)!r}"
        )
    return item


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        fail(f"{label} is not a lowercase 40-character Git hash")
    return value


def _positive_size(value: Any, label: str, *, allow_zero: bool = False) -> int:
    lower = 0 if allow_zero else 1
    if type(value) is not int or value < lower:
        fail(f"{label} is not a valid byte count")
    return value


def _report_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or REPORT_ID.fullmatch(value) is None:
        fail(f"{label} is not a valid report identifier")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} is not an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"cannot parse {label}: {error}")
    if parsed.tzinfo != timezone.utc:
        fail(f"{label} is not UTC")
    return parsed


def _file_evidence(
    value: Any,
    label: str,
    *,
    expected_path: str | None = None,
) -> dict[str, Any]:
    expected = {"path", "sha256", "size_bytes"} if expected_path else {
        "sha256",
        "size_bytes",
    }
    item = _exact_keys(value, expected, label)
    if expected_path is not None and item["path"] != expected_path:
        fail(f"{label} path differs from the canonical release path")
    _sha(item["sha256"], f"{label} sha256")
    _positive_size(item["size_bytes"], f"{label} size_bytes")
    return item


def _matches_snapshot(evidence: Mapping[str, Any], snapshot: Snapshot, label: str) -> None:
    if (
        evidence["sha256"] != snapshot.sha256
        or evidence["size_bytes"] != snapshot.size_bytes
    ):
        fail(f"{label} differs from its release-acceptance lock")


def _nested(value: Any, path: tuple[str, ...], label: str) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            fail(f"{label} lacks {'.'.join(path)}")
        current = current[key]
    return current


def _call_verifier(label: str, function: Callable[..., Any], *args: Any) -> Any:
    try:
        return function(*args)
    except ReleaseAcceptanceError:
        raise
    except SystemExit as error:
        fail(f"{label} rejected the public evidence: {error}")
    except Exception as error:
        fail(f"{label} could not verify the public evidence: {error}")


def _default_verifiers() -> SimpleNamespace:
    age = load_source_only_module(
        ROOT,
        "scripts/verify_age_cut_ssp_contract.py",
        "verify_age_cut_ssp_contract",
        "age-cut component verifier",
    )
    host = load_source_only_module(
        ROOT,
        "scripts/verify_host_artifact_contract.py",
        "verify_host_artifact_contract",
        "host component verifier",
    )
    local = load_source_only_module(
        ROOT,
        "scripts/verify_local_run_attestation.py",
        "verify_local_run_attestation",
        "local-run component verifier",
    )
    # The radial verifier imports two repository modules transitively.  Load
    # the whole chain from explicit source bytes before executing its source,
    # so none of those imports can fall back to untracked cached bytecode.
    load_source_only_module(
        ROOT,
        "scripts/verify_age_cut_sensitivity.py",
        "verify_age_cut_sensitivity",
        "age-cut sensitivity verifier",
    )
    load_source_only_module(
        ROOT,
        "research/jj-tams-convergence/radial_ssp_rederive.py",
        "radial_ssp_rederive",
        "radial SSP independent rederivation",
    )
    radial = load_source_only_module(
        ROOT,
        "scripts/verify_radial_ssp_contract.py",
        "verify_radial_ssp_contract",
        "radial component verifier",
    )
    return SimpleNamespace(host=host, age=age, radial=radial, local=local)


def _validate_source_lock(value: Any) -> dict[str, Any]:
    source = _exact_keys(
        value,
        {"commit", "tree", "archive_sha256", "archive_size_bytes"},
        "release source lock",
    )
    _git_sha(source["commit"], "release source commit")
    _git_sha(source["tree"], "release source tree")
    _sha(source["archive_sha256"], "release source archive")
    _positive_size(source["archive_size_bytes"], "release source archive size")
    return source


def _validate_release_source(value: Any) -> dict[str, Any]:
    release = _exact_keys(
        value,
        {
            "lineage_commit",
            "lineage_tree",
            "lineage_relationship",
            "manifest_path",
            "payload_manifest_sha256",
            "public_payload_manifest_sha256",
            "computational_projection_manifest_sha256",
            "public_computational_projection_manifest_sha256",
            "post_computation_policy",
            "acceptance_verifier_sha256",
            "allowed_finalization_paths",
            "final_binding",
        },
        "release source lineage",
    )
    _git_sha(release["lineage_commit"], "release lineage commit")
    _git_sha(release["lineage_tree"], "release lineage tree")
    if release["lineage_relationship"] != "direct_parent_of_final_release":
        fail("release lineage relationship policy changed")
    if release["manifest_path"] != "MANIFEST.sha256":
        fail("release source must bind through top-level MANIFEST.sha256")
    _sha(
        release["payload_manifest_sha256"],
        "release payload-manifest sha256",
    )
    _sha(
        release["public_payload_manifest_sha256"],
        "release public payload-manifest sha256",
    )
    _sha(
        release["computational_projection_manifest_sha256"],
        "release computational-projection manifest sha256",
    )
    _sha(
        release["public_computational_projection_manifest_sha256"],
        "release public computational-projection manifest sha256",
    )
    if release["post_computation_policy"] != POST_COMPUTATION_POLICY:
        fail("release post-computation path policy changed")
    _sha(
        release["acceptance_verifier_sha256"],
        "release acceptance-verifier sha256",
    )
    if release["allowed_finalization_paths"] != list(FINALIZATION_PATHS):
        fail("release finalization path allowlist changed")
    if release["final_binding"] != "direct-parent-exact-diff-and-payload-manifest":
        fail("release final-binding policy changed")
    return release


def _validate_results_archive(value: Any) -> dict[str, Any]:
    archive = _exact_keys(
        value,
        {
            "filename",
            "sha256_sidecar_filename",
            "sha256",
            "size_bytes",
            "source_manifest_sha256",
        },
        "results archive lock",
    )
    if archive["filename"] != RESULTS_ARCHIVE_NAME:
        fail("results archive filename differs from the canonical v4.0.4 name")
    if archive["sha256_sidecar_filename"] != RESULTS_CHECKSUM_NAME:
        fail("results checksum filename differs from the canonical v4.0.4 name")
    _sha(archive["sha256"], "results archive sha256")
    _positive_size(archive["size_bytes"], "results archive size")
    _sha(archive["source_manifest_sha256"], "results source-manifest sha256")
    return archive


def post_computation_allowed_paths(
    acceptance: Mapping[str, Any],
) -> frozenset[str]:
    """Return the exact release-evidence files permitted to differ after A."""

    allowed = set(POST_COMPUTATION_STATIC_PATHS)
    contracts = _mapping(acceptance.get("contracts"), "release contracts")
    if set(contracts) != set(CONTRACT_PATHS):
        fail("release contract role set changed")
    for role in CONTRACT_PATHS:
        entry = _contract_acceptance_entry(contracts[role], role)
        allowed.add(entry["contract_path"])
        allowed.add(entry["report_path"])
    freezes = _mapping(acceptance.get("freezes"), "release freezes")
    if set(freezes) != set(FREEZE_SPECS):
        fail("release freeze role set changed")
    for role, spec in FREEZE_SPECS.items():
        _mapping(freezes[role], f"{role} release freeze")
        allowed.add(f"{spec['root']}/{spec['manifest']}")
        allowed.update(f"{spec['root']}/{name}" for name in spec["targets"])
    return frozenset(allowed)


def is_post_computation_allowed_path(
    relative: str, allowed: frozenset[str]
) -> bool:
    if relative in allowed:
        return True
    path = PurePosixPath(relative)
    # Documentation and license texts are non-executable release explanation;
    # scripts, workflows, model inputs, lock files, and configuration remain in
    # the computational projection even when they live beside documentation.
    if path.parts and path.parts[0] == "LICENSES":
        return path.suffix.casefold() in {".md", ".txt"}
    if path.parts and path.parts[0] in {"docs", "documentation"}:
        return path.suffix.casefold() in {".md", ".rst", ".txt"}
    return False


def computational_projection_manifest_bytes(
    entries: Mapping[str, str], acceptance: Mapping[str, Any]
) -> bytes:
    allowed = post_computation_allowed_paths(acceptance)
    return "".join(
        f"{entries[relative]}  {relative}\n"
        for relative in sorted(entries)
        if not is_post_computation_allowed_path(relative, allowed)
    ).encode("utf-8")


def compute_computational_projection_sha256(
    entries: Mapping[str, str], acceptance: Mapping[str, Any]
) -> str:
    return hashlib.sha256(
        computational_projection_manifest_bytes(entries, acceptance)
    ).hexdigest()


def _verify_git_lineage_if_available(
    root: Path, acceptance: Mapping[str, Any]
) -> None:
    release = _mapping(acceptance.get("release_source"), "release source lineage")
    source = _mapping(acceptance.get("computational_source"), "computational source")
    marker = root / ".git"
    if not marker.exists() and not marker.is_symlink():
        return
    try:
        marker_metadata = marker.lstat()
    except OSError as error:
        fail(f"cannot inspect Git metadata marker: {error}")
    if _is_link_or_reparse(marker_metadata):
        fail("Git metadata marker is a link or reparse point")
    if not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        fail("Git metadata marker is not a directory or worktree pointer")
    executable = shutil.which("git")
    if executable is None:
        fail("Git is required to verify release lineage in a Git checkout")

    def run(arguments: list[str], label: str) -> str:
        try:
            result = subprocess.run(
                [executable, "-C", str(root), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
            )
        except OSError as error:
            fail(f"cannot execute Git for {label}: {error}")
        if result.returncode != 0:
            fail(f"Git could not verify {label}")
        try:
            return result.stdout.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            fail(f"Git returned non-ASCII {label}: {error}")

    if run(["status", "--porcelain", "--untracked-files=no"], "release worktree status"):
        fail("release worktree has tracked modifications outside the committed tree")
    if source["commit"] == release["lineage_commit"]:
        fail("computational source must precede the pre-final release lineage")
    observed_source_tree = run(
        ["rev-parse", f"{source['commit']}^{{tree}}"],
        "computational source tree",
    )
    if observed_source_tree != source["tree"]:
        fail("computational source commit does not resolve to the locked tree")
    try:
        ancestry = subprocess.run(
            [
                executable,
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                source["commit"],
                release["lineage_commit"],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute Git for computational ancestry: {error}")
    if ancestry.returncode != 0:
        fail("computational source is not an ancestor of the pre-final release")
    allowed = post_computation_allowed_paths(acceptance)
    computational_diff = run(
        [
            "diff",
            "--name-status",
            "--no-renames",
            source["commit"],
            release["lineage_commit"],
            "--",
        ],
        "post-computation release diff",
    )
    if computational_diff:
        for line in computational_diff.splitlines():
            fields = line.split("\t")
            if len(fields) != 2:
                fail("post-computation release diff has an unparseable path record")
            status_code, relative = fields
            _safe_relative(relative, "post-computation changed path")
            if status_code not in {"A", "M"}:
                fail("post-computation release diff deletes, renames, or type-changes a path")
            if not is_post_computation_allowed_path(relative, allowed):
                fail(
                    "post-computation release diff changes computational code or locked input: "
                    f"{relative}"
                )
    observed_tree = run(
        ["rev-parse", f"{release['lineage_commit']}^{{tree}}"],
        "release lineage tree",
    )
    if observed_tree != release["lineage_tree"]:
        fail("release lineage commit does not resolve to the locked tree")
    parents = run(["rev-list", "--parents", "-n", "1", "HEAD"], "final release parents").split()
    if len(parents) != 2 or parents[1] != release["lineage_commit"]:
        fail("release lineage commit is not the sole direct parent of HEAD")
    raw_diff = run(
        [
            "diff",
            "--name-status",
            "--no-renames",
            release["lineage_commit"],
            "HEAD",
            "--",
        ],
        "final release diff",
    )
    changes: dict[str, str] = {}
    if raw_diff:
        for line in raw_diff.splitlines():
            fields = line.split("\t")
            if len(fields) != 2:
                fail("final release diff has an unparseable path record")
            status_code, relative = fields
            _safe_relative(relative, "final release changed path")
            if status_code not in {"A", "M"} or relative in changes:
                fail("final release diff contains a deletion, rename, type change, or duplicate")
            changes[relative] = status_code
    if set(changes) != set(FINALIZATION_PATHS):
        fail("final release diff is not exactly the two self-binding files")


IMPORT_SCAN_SKIP_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "dist",
        "local-artifacts",
        "outputs",
        "results",
    }
)


def _tracked_python_paths(root: Path) -> set[str] | None:
    marker = root / ".git"
    if not marker.exists() and not marker.is_symlink():
        return None
    executable = shutil.which("git")
    if executable is None:
        fail("Git is required to reject untracked Python import shadows")
    try:
        completed = subprocess.run(
            [executable, "-C", str(root), "ls-files", "-z", "--", "*.py"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
    except OSError as error:
        fail(f"cannot enumerate tracked Python sources: {error}")
    if completed.returncode != 0:
        fail("Git could not enumerate tracked Python sources")
    try:
        names = completed.stdout.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as error:
        fail(f"Git returned non-UTF-8 Python paths: {error}")
    result: set[str] = set()
    for relative in filter(None, names):
        _safe_relative(relative, "tracked Python source path")
        result.add(relative)
    return result


def reject_repository_import_shadows(root: Path) -> None:
    """Reject caches/bytecode and Git-untracked source before any repo import."""

    boundary = Path(root).resolve(strict=True)
    tracked = _tracked_python_paths(boundary)
    pending = [boundary]
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            fail(f"cannot scan release import boundary: {error}")
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(boundary).as_posix()
            parts = PurePosixPath(relative).parts
            if set(parts).intersection(IMPORT_SCAN_SKIP_PARTS):
                continue
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                fail(f"cannot inspect release import-boundary member: {error}")
            if _is_link_or_reparse(metadata):
                fail(f"release import boundary contains a link/reparse point: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                if child.name.casefold() == "__pycache__":
                    fail(f"release import boundary contains __pycache__: {relative}")
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"release import boundary contains a special file: {relative}")
            suffix = path.suffix.casefold()
            if suffix in {".pyc", ".pyo"}:
                fail(f"release import boundary contains bytecode: {relative}")
            if suffix == ".py" and tracked is not None and relative not in tracked:
                fail(f"release import boundary contains untracked Python source: {relative}")


def _manifest_scope_path(relative: str) -> bool:
    return not MANIFEST_SKIP_PARTS.intersection(PurePosixPath(relative).parts)


def _verify_manifest_inventory(root: Path, entries: Mapping[str, str]) -> None:
    """Bind the manifest to the exact tracked tree, or the exact no-Git archive."""

    expected = set(entries) | {"MANIFEST.sha256"}
    marker = root / ".git"
    if marker.exists() or marker.is_symlink():
        executable = shutil.which("git")
        if executable is None:
            fail("Git is required to verify the release manifest inventory")
        try:
            completed = subprocess.run(
                [executable, "-C", str(root), "ls-files", "-z"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
            )
        except OSError as error:
            fail(f"cannot execute Git for release inventory: {error}")
        if completed.returncode != 0:
            fail("Git could not enumerate the final release tree")
        try:
            names = completed.stdout.decode("utf-8", errors="strict").split("\0")
        except UnicodeDecodeError as error:
            fail(f"Git returned a non-UTF-8 release inventory: {error}")
        observed = set()
        for relative in filter(None, names):
            _safe_relative(relative, "tracked release path")
            if _manifest_scope_path(relative):
                observed.add(relative)
        if observed != expected:
            fail("repository manifest does not describe the exact tracked release tree")
        return

    observed: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            fail(f"cannot enumerate no-Git release tree: {error}")
        for child in children:
            path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                fail(f"cannot inspect no-Git release member: {error}")
            relative = path.relative_to(root).as_posix()
            if not _manifest_scope_path(relative):
                continue
            if _is_link_or_reparse(metadata):
                fail(f"no-Git release tree contains a link or reparse point: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                observed.add(relative)
            else:
                fail(f"no-Git release tree contains a special file: {relative}")
    if observed != expected:
        fail("repository manifest does not describe the exact no-Git release tree")


def _verify_manifest_file_hashes(root: Path, entries: Mapping[str, str]) -> None:
    """Hash every manifest member from one stable descriptor, not only gate files."""

    for relative in sorted(entries):
        path = _plain_path(root, relative, directory=False)
        digest = hashlib.sha256()
        size = 0
        with open_stable_file(path, f"repository manifest member {relative}") as (
            handle,
            metadata,
        ):
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
            if size != metadata.st_size:
                fail(f"repository manifest member changed while read: {relative}")
        if digest.hexdigest() != entries[relative]:
            fail(f"repository manifest hash differs for {relative}")


def _parse_repository_manifest(snapshot: Snapshot) -> dict[str, str]:
    try:
        lines = snapshot.data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"repository manifest is not strict UTF-8: {error}")
    if not lines:
        fail("repository manifest is empty")
    entries: dict[str, str] = {}
    ordered: list[str] = []
    folded: set[str] = set()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            fail(f"repository manifest line {number} is malformed")
        digest, relative = match.groups()
        _safe_relative(relative, f"repository manifest line {number} path")
        if relative == "MANIFEST.sha256":
            fail("repository manifest cannot contain a self entry")
        if relative.casefold() in folded:
            fail(f"repository manifest repeats or case-collides at {relative}")
        entries[relative] = digest
        ordered.append(relative)
        folded.add(relative.casefold())
    if ordered != sorted(ordered):
        fail("repository manifest paths are not in canonical sorted order")
    return entries


def _plain_external_file(path: Path, label: str) -> Path:
    candidate = Path(os.path.abspath(path))
    chain = [candidate]
    while chain[-1] != chain[-1].parent:
        chain.append(chain[-1].parent)
    for current in reversed(chain):
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if _is_link_or_reparse(metadata):
            fail(f"{label} path contains a link or reparse point")
        if current == candidate:
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"{label} is not a regular file")
        elif not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} has a non-directory ancestor")
    return candidate


def _trusted_source_paths(
    root: Path,
    archive: Path | None,
    checksum: Path | None,
) -> tuple[Path, Path]:
    archive_value = archive
    checksum_value = checksum
    if archive_value is None:
        raw = os.environ.get(TRUSTED_SOURCE_ARCHIVE_ENV)
        archive_value = Path(raw) if raw else None
    if checksum_value is None:
        raw = os.environ.get(TRUSTED_SOURCE_CHECKSUM_ENV)
        checksum_value = Path(raw) if raw else None
    if archive_value is None or checksum_value is None:
        fail(
            "no-Git verification requires an external trusted source ZIP and "
            "checksum anchor"
        )
    archive_path = _plain_external_file(archive_value, "trusted source ZIP")
    checksum_path = _plain_external_file(checksum_value, "trusted source checksum")
    if archive_path.name != SOURCE_ARCHIVE_NAME or checksum_path.name != SOURCE_CHECKSUM_NAME:
        fail("trusted source anchor filenames are not canonical")
    if _path_within(archive_path, root) or _path_within(checksum_path, root):
        fail("trusted source anchor must be outside the no-Git release tree")
    return archive_path, checksum_path


def verify_no_git_trusted_source_anchor(
    root: Path,
    entries: Mapping[str, str],
    manifest_snapshot: Snapshot,
    archive: Path | None,
    checksum: Path | None,
) -> dict[str, Any]:
    """Bind an extracted no-Git tree to separately supplied published assets."""

    archive_path, checksum_path = _trusted_source_paths(root, archive, checksum)
    checksum_snapshot = read_external_snapshot(
        checksum_path, "trusted source checksum", maximum_bytes=1024
    )
    expected_members = sorted((*entries, "MANIFEST.sha256"))
    digest = hashlib.sha256()
    size = 0
    archive_identity: tuple[int, int, int, int, int] | None = None
    try:
        with open_stable_file(archive_path, "trusted source ZIP") as (handle, metadata):
            archive_identity = _identity(metadata)
            if metadata.st_size > 512 * 1024 * 1024:
                fail("trusted source ZIP exceeds the byte limit")
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
            if size != metadata.st_size:
                fail("trusted source ZIP changed while hashed")
            handle.seek(0)
            with zipfile.ZipFile(handle, mode="r") as source_zip:
                if source_zip.comment:
                    fail("trusted source ZIP has an unexpected comment")
                infos = source_zip.infolist()
                if [info.filename for info in infos] != expected_members:
                    fail("trusted source ZIP inventory differs from the no-Git tree")
                for info in infos:
                    relative = _safe_relative(info.filename, "trusted source ZIP member")
                    mode = info.external_attr >> 16
                    if (
                        info.is_dir()
                        or info.compress_type != zipfile.ZIP_STORED
                        or info.date_time != SOURCE_ZIP_TIME
                        or info.create_system != 3
                        or not stat.S_ISREG(mode)
                        or stat.S_IMODE(mode) != 0o644
                        or info.comment
                        or info.extra
                        or info.compress_size != info.file_size
                    ):
                        fail(f"trusted source ZIP member metadata is not canonical: {relative}")
                    snapshot = (
                        manifest_snapshot
                        if relative == "MANIFEST.sha256"
                        else read_snapshot(
                            root,
                            relative,
                            f"no-Git source member {relative}",
                            maximum_bytes=MAX_FREEZE_FILE_BYTES,
                        )
                    )
                    if info.file_size != snapshot.size_bytes:
                        fail(f"trusted source ZIP size differs for {relative}")
                    member_digest = hashlib.sha256()
                    member_size = 0
                    with source_zip.open(info, mode="r") as member:
                        while True:
                            block = member.read(1024 * 1024)
                            if not block:
                                break
                            member_digest.update(block)
                            member_size += len(block)
                    if (
                        member_size != snapshot.size_bytes
                        or member_digest.hexdigest() != snapshot.sha256
                    ):
                        fail(f"trusted source ZIP bytes differ for {relative}")
                    recheck_snapshot(snapshot, f"no-Git source member {relative}")
    except ReleaseAcceptanceError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        fail(f"cannot verify trusted source ZIP: {error}")
    if archive_identity is None:
        fail("trusted source ZIP was not opened")
    observed_digest = digest.hexdigest()
    expected_sidecar = f"{observed_digest}  {SOURCE_ARCHIVE_NAME}\n".encode("ascii")
    if checksum_snapshot.data != expected_sidecar:
        fail("external trusted source checksum does not bind the source ZIP")
    recheck_snapshot(checksum_snapshot, "trusted source checksum")
    recheck_large_file(
        LargeFileEvidence(archive_path, observed_digest, size, archive_identity),
        "trusted source ZIP",
    )
    return {
        "archive_sha256": observed_digest,
        "archive_size_bytes": size,
        "checksum_sha256": checksum_snapshot.sha256,
    }


def _payload_manifest_bytes(entries: Mapping[str, str]) -> bytes:
    return "".join(
        f"{entries[relative]}  {relative}\n"
        for relative in sorted(entries)
        if relative != ACCEPTANCE_PATH
    ).encode("utf-8")


def compute_payload_manifest_sha256(repository_root: Path) -> str:
    """Measure the pre-final payload lock while excluding only acceptance itself."""

    root = Path(repository_root)
    manifest = read_snapshot(
        root,
        "MANIFEST.sha256",
        "repository payload manifest",
        maximum_bytes=16 * 1024 * 1024,
    )
    entries = _parse_repository_manifest(manifest)
    _verify_manifest_inventory(root, entries)
    _verify_manifest_file_hashes(root, entries)
    recheck_snapshot(manifest, "repository payload manifest")
    return hashlib.sha256(_payload_manifest_bytes(entries)).hexdigest()


def _early_release_tree_preflight(
    root: Path,
    acceptance: Mapping[str, Any],
    *,
    trusted_source_archive: Path | None,
    trusted_source_checksum: Path | None,
) -> dict[str, Any] | None:
    """Close import-shadow and no-Git trust gaps before repository imports."""

    release = _mapping(acceptance.get("release_source"), "release source lineage")
    manifest = read_snapshot(
        root,
        release["manifest_path"],
        "early release manifest preflight",
        maximum_bytes=16 * 1024 * 1024,
    )
    entries = _parse_repository_manifest(manifest)
    reject_repository_import_shadows(root)
    _verify_manifest_inventory(root, entries)
    _verify_manifest_file_hashes(root, entries)
    marker = root / ".git"
    anchor: dict[str, Any] | None = None
    if not marker.exists() and not marker.is_symlink():
        anchor = verify_no_git_trusted_source_anchor(
            root,
            entries,
            manifest,
            trusted_source_archive,
            trusted_source_checksum,
        )
    recheck_snapshot(manifest, "early release manifest preflight")
    return anchor


def _verify_release_manifest_binding(
    root: Path,
    acceptance: Mapping[str, Any],
    acceptance_snapshot: Snapshot,
    component_snapshots: Mapping[str, tuple[Snapshot, Snapshot]],
    freeze_snapshots: Mapping[str, Mapping[str, Snapshot]],
) -> Snapshot:
    release = _mapping(acceptance.get("release_source"), "release source lineage")
    manifest = read_snapshot(
        root,
        release["manifest_path"],
        "repository release manifest",
        maximum_bytes=16 * 1024 * 1024,
    )
    entries = _parse_repository_manifest(manifest)
    _verify_manifest_inventory(root, entries)
    _verify_manifest_file_hashes(root, entries)
    git_checkout = (root / ".git").exists() or (root / ".git").is_symlink()
    payload_digest = hashlib.sha256(_payload_manifest_bytes(entries)).hexdigest()
    expected_payload = (
        release["payload_manifest_sha256"]
        if git_checkout
        else release["public_payload_manifest_sha256"]
    )
    if payload_digest != expected_payload:
        boundary = "repository" if git_checkout else "public no-Git"
        fail(f"release {boundary} payload manifest differs from its lock")
    projection_digest = compute_computational_projection_sha256(entries, acceptance)
    expected_projection = (
        release["computational_projection_manifest_sha256"]
        if git_checkout
        else release["public_computational_projection_manifest_sha256"]
    )
    if projection_digest != expected_projection:
        boundary = "repository" if git_checkout else "public no-Git"
        fail(
            f"release {boundary} computational projection differs from the "
            "accepted computational-source payload"
        )
    required: dict[str, str] = {
        ACCEPTANCE_PATH: acceptance_snapshot.sha256,
        "scripts/verify_v404_release_acceptance.py": release[
            "acceptance_verifier_sha256"
        ],
    }
    for role, (contract_snapshot, report_snapshot) in component_snapshots.items():
        required[CONTRACT_PATHS[role]] = contract_snapshot.sha256
        required[f"provenance/{report_snapshot.path.name}"] = report_snapshot.sha256
    for role, snapshots in freeze_snapshots.items():
        root_path = FREEZE_SPECS[role]["root"]
        for name, snapshot in snapshots.items():
            required[f"{root_path}/{name}"] = snapshot.sha256
    for relative, digest in required.items():
        if entries.get(relative) != digest:
            fail(f"repository manifest does not bind release file {relative}")
    verifier = read_snapshot(
        root,
        "scripts/verify_v404_release_acceptance.py",
        "release acceptance verifier",
        maximum_bytes=4 * 1024 * 1024,
    )
    if verifier.sha256 != release["acceptance_verifier_sha256"]:
        fail("running release acceptance verifier differs from the release-source lock")
    recheck_snapshot(verifier, "release acceptance verifier")
    return manifest


def _expected_results_paths() -> tuple[str, ...]:
    controller = load_source_only_module(
        ROOT,
        "scripts/run_v404_local_production.py",
        "run_v404_local_production",
        "local production controller",
    )
    paths = tuple(controller.expected_public_files(final=True))
    if (
        not paths
        or list(paths) != sorted(paths)
        or len(paths) != len({item.casefold() for item in paths})
        or PUBLIC_RESULTS_MANIFEST_NAME not in paths
        or PUBLIC_RESULTS_REPORT_NAME not in paths
    ):
        fail("local production output contract is not canonical")
    for index, relative in enumerate(paths):
        _safe_relative(relative, f"local production output path {index}")
        lowered = relative.casefold()
        leaf = PurePosixPath(relative).name.casefold()
        if (
            lowered.endswith(".bin")
            or "raw_chain" in lowered
            or any(part in {"private", "logs", "inputs"} for part in PurePosixPath(lowered).parts)
            or leaf
            in {
                "pcs_dr25_hab2.csv",
                "dr25_stellar_berger2020_clean_hab2.txt",
                "ratemodels3d.py",
                "out_sc0_hab2_insol_teff_extrap_const.fits.gz",
                "out_sc0_hab2_insol_teff.fits.gz",
            }
        ):
            fail(f"local production output contract exposes a forbidden path: {relative}")
    return paths


def _validate_output_entries(
    value: Any, local_report: Mapping[str, Any], label: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail(f"{label} must be a JSON list")
    expected_paths = list(_expected_results_paths())
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item = _exact_keys(raw, {"path", "sha256", "size_bytes"}, f"{label} entry {index}")
        _safe_relative(item["path"], f"{label} entry {index} path")
        _sha(item["sha256"], f"{label} entry {index} sha256")
        _positive_size(item["size_bytes"], f"{label} entry {index} size", allow_zero=True)
        entries.append(dict(item))
    if [item["path"] for item in entries] != expected_paths:
        fail(f"{label} differs from the exact public production output set/order")
    if local_report.get("output_file_count") != len(entries):
        fail(f"{label} count differs from the signed local public report")
    if local_report.get("output_total_size_bytes") != sum(
        item["size_bytes"] for item in entries
    ):
        fail(f"{label} byte total differs from the signed local public report")
    file_set_sha = hashlib.sha256(canonical_json_bytes(entries)).hexdigest()
    if local_report.get("output_file_set_sha256") != file_set_sha:
        fail(f"{label} file-set hash differs from the signed local public report")
    return entries


def validate_local_output_manifest_bytes(
    data: bytes, local_report: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Validate the private strict output manifest bound by the public attestation."""

    if hashlib.sha256(data).hexdigest() != local_report.get("output_manifest_sha256"):
        fail("strict local output manifest differs from the signed public report")
    value = _exact_keys(
        load_json_bytes(data, "strict local output manifest"),
        {"schema_version", "algorithm", "files"},
        "strict local output manifest",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        fail("strict local output manifest schema changed")
    if value["algorithm"] != "sha256":
        fail("strict local output manifest algorithm changed")
    if data != canonical_json_bytes(value):
        fail("strict local output manifest is not canonical JSON bytes")
    return _validate_output_entries(value["files"], local_report, "strict local output manifest")


def _parse_public_results_manifest(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"embedded results manifest is not strict UTF-8: {error}")
    entries: dict[str, str] = {}
    ordered: list[str] = []
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)", line)
        if match is None:
            fail(f"embedded results manifest line {number} is malformed")
        digest, relative = match.groups()
        _safe_relative(relative, f"embedded results manifest line {number} path")
        if relative == PUBLIC_RESULTS_MANIFEST_NAME or relative.casefold() in {
            item.casefold() for item in ordered
        }:
            fail("embedded results manifest has a self entry or case collision")
        entries[relative] = digest
        ordered.append(relative)
    if not ordered or ordered != sorted(ordered):
        fail("embedded results manifest paths are empty or not sorted")
    return entries


def _validate_public_results_report(
    data: bytes,
    observed: Mapping[str, tuple[str, int]],
    source: Mapping[str, Any],
) -> dict[str, Any]:
    report = _exact_keys(
        load_json_bytes(data, "embedded local production report"),
        {
            "schema_version",
            "status",
            "release_candidate",
            "execution_environment",
            "source_archive",
            "production_design",
            "acceptance",
            "public_boundary",
            "public_files",
            "command_count",
            "runtime_seconds_by_stage",
            "total_runtime_seconds",
            "completed_utc",
        },
        "embedded local production report",
    )
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["status"] != "PASS"
        or report["release_candidate"] != "v4.0.4"
    ):
        fail("embedded local production report identity/status changed")
    archive = _exact_keys(
        report["source_archive"],
        {"sha256", "size_bytes", "regular_files_verified", "execution_tree_byte_identical"},
        "embedded local production source archive",
    )
    if (
        archive["sha256"] != source["archive_sha256"]
        or archive["size_bytes"] != source["archive_size_bytes"]
        or archive["execution_tree_byte_identical"] is not True
    ):
        fail("embedded local production report does not bind the computational source")
    if (
        type(archive["regular_files_verified"]) is not int
        or archive["regular_files_verified"] <= 0
    ):
        fail("embedded local production source-file count is invalid")
    if report["public_boundary"] != {
        "third_party_input_files_copied": False,
        "row_level_host_files_copied": False,
        "private_raw_chain_files_copied": False,
        "private_logs_copied": False,
    }:
        fail("embedded local production report violates the public boundary")
    expected_inventory = []
    for relative in _expected_results_paths():
        if relative in {PUBLIC_RESULTS_REPORT_NAME, PUBLIC_RESULTS_MANIFEST_NAME}:
            continue
        digest, size = observed[relative]
        expected_inventory.append({"path": relative, "sha256": digest, "size_bytes": size})
    if report["public_files"] != expected_inventory:
        fail("embedded local production report inventory differs from the archive")
    if type(report["command_count"]) is not int or report["command_count"] <= 0:
        fail("embedded local production report command count is invalid")
    _utc(report["completed_utc"], "embedded local production completion time")
    for label in ("production_design", "acceptance", "runtime_seconds_by_stage"):
        if not isinstance(report[label], dict) or not report[label]:
            fail(f"embedded local production report {label} is empty")
    recovery = _mapping(
        report["production_design"].get("mcmc_recovery"),
        "embedded local production MCMC recovery disclosure",
    )
    if recovery.get("mcmc_reused") is False:
        if recovery != {
            "mcmc_reused": False,
            "aggregates_and_downstream_recomputed": True,
        }:
            fail("embedded full-run MCMC disclosure differs from the exact schema")
    elif recovery.get("mcmc_reused") is True:
        recovery = _exact_keys(
            recovery,
            {
                "mcmc_reused",
                "fresh_preflight_runtime_and_pilots_recomputed",
                "aggregates_and_downstream_recomputed",
                "donor_completion_attestation_present_in_qualified_evidence_set",
                "donor_run_id",
                "donor_source_commit",
                "donor_source_tree",
                "donor_source_archive_sha256",
                "donor_source_archive_size_bytes",
                "donor_source_file_set_sha256",
                "donor_source_file_count",
                "donor_attestation_contract_sha256",
                "donor_attestation_contract_size_bytes",
                "donor_command_plan_sha256",
                "donor_numerical_runtime_sha256",
                "donor_start_challenge_sha256",
                "donor_start_signature_sha256",
                "recovery_contract_sha256",
                "recovery_contract_size_bytes",
                "mcmc_policy_sha256",
                "recovery_source_commit",
                "recovery_source_tree",
                "source_transition_report_id",
                "source_transition_report_sha256",
                "qualification_report_id",
                "qualification_report_sha256",
                "reused_realizations",
                "imported_work_file_count",
                "imported_work_size_bytes",
                "imported_work_tree_sha256",
                "imported_raw_file_count",
                "imported_raw_size_bytes",
                "imported_raw_tree_sha256",
            },
            "embedded recovery MCMC disclosure",
        )
        for field in (
            "fresh_preflight_runtime_and_pilots_recomputed",
            "aggregates_and_downstream_recomputed",
        ):
            if recovery[field] is not True:
                fail(f"embedded recovery disclosure does not confirm {field}")
        if (
            recovery[
                "donor_completion_attestation_present_in_qualified_evidence_set"
            ]
            is not False
        ):
            fail("embedded recovery disclosure misstates qualified donor completion evidence")
        _sha(recovery["donor_run_id"], "embedded recovery donor run id")
        _git_sha(recovery["donor_source_commit"], "embedded recovery donor commit")
        _git_sha(recovery["donor_source_tree"], "embedded recovery donor tree")
        _git_sha(recovery["recovery_source_commit"], "embedded recovery source commit")
        _git_sha(recovery["recovery_source_tree"], "embedded recovery source tree")
        if (
            recovery["recovery_source_commit"] != source["commit"]
            or recovery["recovery_source_tree"] != source["tree"]
        ):
            fail("embedded recovery disclosure does not bind the release source")
        for field in (
            "donor_source_archive_sha256",
            "donor_source_file_set_sha256",
            "donor_attestation_contract_sha256",
            "donor_command_plan_sha256",
            "donor_numerical_runtime_sha256",
            "donor_start_challenge_sha256",
            "donor_start_signature_sha256",
            "recovery_contract_sha256",
            "mcmc_policy_sha256",
            "source_transition_report_sha256",
            "qualification_report_sha256",
            "imported_work_tree_sha256",
            "imported_raw_tree_sha256",
        ):
            _sha(recovery[field], f"embedded recovery {field}")
        _report_id(
            recovery["source_transition_report_id"],
            "embedded recovery source-transition report id",
        )
        _report_id(
            recovery["qualification_report_id"],
            "embedded recovery qualification report id",
        )
        _positive_size(
            recovery["recovery_contract_size_bytes"],
            "embedded recovery contract size",
        )
        _positive_size(
            recovery["donor_source_archive_size_bytes"],
            "embedded recovery donor source archive size",
        )
        _positive_size(
            recovery["donor_attestation_contract_size_bytes"],
            "embedded recovery donor attestation contract size",
        )
        _positive_size(
            recovery["donor_source_file_count"],
            "embedded recovery donor source-file count",
        )
        exact_counts = {
            "reused_realizations": 1_200,
            "imported_work_file_count": 384,
            "imported_raw_file_count": 1_296,
        }
        for field, expected in exact_counts.items():
            if type(recovery[field]) is not int or recovery[field] != expected:
                fail(f"embedded recovery {field} differs from v4.0.4 policy")
        work_size = _positive_size(
            recovery["imported_work_size_bytes"],
            "embedded recovery work-tree size",
        )
        raw_size = _positive_size(
            recovery["imported_raw_size_bytes"],
            "embedded recovery raw-tree size",
        )
        if work_size + raw_size != 13_501_074_979:
            fail("embedded recovery imported byte total differs from the qualified donor")
    else:
        fail("embedded local production report lacks an exact MCMC provenance decision")
    for field in ("total_runtime_seconds",):
        value = report[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value <= 0:
            fail(f"embedded local production report {field} is invalid")
    return report


def _rederive_headline_q50_from_draws(
    data: bytes, branch: str
) -> tuple[float, int]:
    """Strictly decode the accepted deterministic gzip/CSV and recompute q50."""

    if (
        len(data) < 18
        or data[:3] != b"\x1f\x8b\x08"
        or data[3] != 0
        or data[4:8] != b"\x00\x00\x00\x00"
        or data[8] != 2
        or data[9] != 255
    ):
        fail(f"signed {branch} headline draws lack the deterministic gzip header")
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        raw = decoder.decompress(data, 512 * 1024 * 1024 + 1)
        raw += decoder.flush()
    except zlib.error as error:
        fail(f"cannot decode signed {branch} headline draws gzip: {error}")
    if (
        len(raw) > 512 * 1024 * 1024
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
    ):
        fail(f"signed {branch} headline draws gzip boundary is not exact")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"signed {branch} headline draws CSV is not UTF-8: {error}")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail(f"signed {branch} headline draws CSV newline/text policy changed")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    fields = reader.fieldnames
    if (
        fields is None
        or len(fields) != len(set(fields))
        or "Lambda_EE" not in fields
        or "global_trial" not in fields
    ):
        fail(f"signed {branch} headline draws CSV schema changed")
    values: list[float] = []
    trials: set[str] = set()
    for index, row in enumerate(reader, 1):
        if None in row or set(row) != set(fields) or any(value is None for value in row.values()):
            fail(f"signed {branch} headline draws CSV row {index} is malformed")
        try:
            value = float(row["Lambda_EE"])
        except (TypeError, ValueError) as error:
            fail(f"signed {branch} headline draws CSV q50 input is invalid: {error}")
        if not math.isfinite(value) or value < 0.0:
            fail(f"signed {branch} headline draws CSV contains invalid Lambda_EE")
        trial = row["global_trial"]
        if not trial:
            fail(f"signed {branch} headline draws CSV lacks global_trial")
        trials.add(trial)
        values.append(value)
    if len(values) < 2 or len(trials) < 2:
        fail(f"signed {branch} headline draws CSV is too small for a posterior median")
    values.sort()
    midpoint = len(values) // 2
    if len(values) % 2:
        median = values[midpoint]
    else:
        # NumPy's declared default q=0.5 linear rule is the midpoint between
        # the two central order statistics for an even sample count.
        median = values[midpoint - 1] + 0.5 * (
            values[midpoint] - values[midpoint - 1]
        )
    return median, len(values)


def _signed_headline_q50(
    embedded: Mapping[str, bytes],
    posterior: Mapping[str, Any],
) -> dict[str, float]:
    """Read headline medians from the production-attested propagation bytes."""

    result: dict[str, float] = {}
    for branch, relative in HEADLINE_SUMMARY_PATHS.items():
        data = embedded.get(relative)
        if data is None:
            fail(f"results ZIP lacks signed {branch} headline propagation summary")
        summary = _mapping(
            load_json_bytes(data, f"signed {branch} propagation summary"),
            f"signed {branch} propagation summary",
        )
        if data != canonical_json_bytes(summary):
            fail(f"signed {branch} propagation summary is not canonical JSON bytes")
        if summary.get("branch") != branch:
            fail(f"signed {branch} propagation summary branch changed")
        source_samples = _mapping(
            summary.get("source_posterior_samples"),
            f"signed {branch} propagation source posterior",
        )
        expected_posterior = posterior[f"corrected_{branch}_propagation"]
        if source_samples.get("sha256") != expected_posterior:
            fail(
                f"signed {branch} propagation summary does not bind the accepted "
                "posterior bytes"
            )
        row_count = source_samples.get("row_count")
        if type(row_count) is not int or row_count < 2:
            fail(f"signed {branch} propagation posterior row count is invalid")
        q50 = _nested(
            summary,
            ("posterior_quantiles", "Lambda_EE", "q50"),
            f"signed {branch} propagation summary",
        )
        if (
            isinstance(q50, bool)
            or not isinstance(q50, (int, float))
            or not math.isfinite(float(q50))
        ):
            fail(f"signed {branch} propagation headline q50 is not finite")
        derived_q50, derived_count = _rederive_headline_q50_from_draws(
            embedded[HEADLINE_DRAW_PATHS[branch]], branch
        )
        if derived_count != row_count:
            fail(f"signed {branch} headline draw count differs from its summary")
        if not math.isclose(
            float(q50), derived_q50, rel_tol=5.0e-15, abs_tol=1.0e-12
        ):
            fail(
                f"signed {branch} propagation headline q50 differs from the "
                "rederived accepted draws"
            )
        result[branch] = float(q50)
    return result


def _verify_results_archive(
    archive_lock: Mapping[str, Any],
    local_report: Mapping[str, Any],
    source: Mapping[str, Any],
    posterior: Mapping[str, Any],
    archive_path: Path,
    checksum_path: Path,
) -> tuple[LargeFileEvidence, Snapshot, dict[str, Any], dict[str, float]]:
    checksum = read_external_snapshot(
        checksum_path, "results SHA-256 sidecar", maximum_bytes=1024
    )
    expected_sidecar = (
        f"{archive_lock['sha256']}  {archive_lock['filename']}\n"
    ).encode("ascii")
    if checksum.data != expected_sidecar:
        fail("results SHA-256 sidecar differs from the release-acceptance lock")

    expected_paths = list(_expected_results_paths())
    expected_members = [f"{RESULTS_ARCHIVE_PREFIX}/{name}" for name in expected_paths]
    observed: dict[str, tuple[str, int]] = {}
    embedded: dict[str, bytes] = {}
    digest = hashlib.sha256()
    archive_size = 0
    archive_identity: tuple[int, int, int, int, int] | None = None
    try:
        with open_stable_file(archive_path, "results ZIP archive") as (handle, metadata):
            archive_identity = _identity(metadata)
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                archive_size += len(block)
            if archive_size != metadata.st_size:
                fail("results ZIP archive size changed during hashing")
            handle.seek(0)
            with zipfile.ZipFile(handle, mode="r") as archive:
                if archive.comment:
                    fail("results ZIP archive has an unexpected archive comment")
                infos = archive.infolist()
                names = [info.filename for info in infos]
                if names != expected_members or len(names) != len(set(names)):
                    fail("results ZIP member set/order differs from signed production output")
                for info, relative in zip(infos, expected_paths):
                    mode = info.external_attr >> 16
                    if (
                        info.filename != f"{RESULTS_ARCHIVE_PREFIX}/{relative}"
                        or info.is_dir()
                        or info.compress_type != zipfile.ZIP_STORED
                        or info.date_time != (1980, 1, 1, 0, 0, 0)
                        or info.create_system != 3
                        or not stat.S_ISREG(mode)
                        or stat.S_IMODE(mode) != 0o644
                        or info.comment
                        or info.extra
                        or info.flag_bits not in {0, 0x800}
                        or info.compress_size != info.file_size
                    ):
                        fail(f"results ZIP member metadata is not canonical: {relative}")
                    member_digest = hashlib.sha256()
                    size = 0
                    with archive.open(info, mode="r") as stream:
                        while True:
                            block = stream.read(1024 * 1024)
                            if not block:
                                break
                            member_digest.update(block)
                            size += len(block)
                            if size > local_report["output_total_size_bytes"]:
                                fail("results ZIP member exceeds the signed output byte total")
                    if size != info.file_size:
                        fail(f"results ZIP member size changed while read: {relative}")
                    observed[relative] = (member_digest.hexdigest(), size)
                    if relative in {
                        PUBLIC_RESULTS_MANIFEST_NAME,
                        PUBLIC_RESULTS_REPORT_NAME,
                        *HEADLINE_SUMMARY_PATHS.values(),
                        *HEADLINE_DRAW_PATHS.values(),
                    }:
                        maximum_embedded = (
                            256 * 1024 * 1024
                            if relative in HEADLINE_DRAW_PATHS.values()
                            else 8 * 1024 * 1024
                        )
                        if size > maximum_embedded:
                            fail(f"embedded release control file is too large: {relative}")
                        with archive.open(info, mode="r") as stream:
                            embedded[relative] = stream.read()
    except ReleaseAcceptanceError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        fail(f"cannot strictly verify results ZIP archive: {error}")
    if archive_identity is None:
        fail("results ZIP archive was not opened")
    archive_sha = digest.hexdigest()
    if archive_sha != archive_lock["sha256"] or archive_size != archive_lock["size_bytes"]:
        fail("results ZIP hash/size differs from the release-acceptance lock")

    reconstructed = [
        {"path": relative, "sha256": observed[relative][0], "size_bytes": observed[relative][1]}
        for relative in expected_paths
    ]
    _validate_output_entries(reconstructed, local_report, "results ZIP output inventory")
    manifest_data = embedded[PUBLIC_RESULTS_MANIFEST_NAME]
    if hashlib.sha256(manifest_data).hexdigest() != archive_lock["source_manifest_sha256"]:
        fail("embedded results manifest differs from the release-acceptance lock")
    public_manifest = _parse_public_results_manifest(manifest_data)
    expected_manifest_paths = set(expected_paths) - {PUBLIC_RESULTS_MANIFEST_NAME}
    if set(public_manifest) != expected_manifest_paths:
        fail("embedded results manifest does not name the exact non-self output set")
    for relative, expected_digest in public_manifest.items():
        if observed[relative][0] != expected_digest:
            fail(f"embedded results manifest hash differs for {relative}")
    report = _validate_public_results_report(
        embedded[PUBLIC_RESULTS_REPORT_NAME], observed, source
    )
    headline_q50 = _signed_headline_q50(embedded, posterior)
    evidence = LargeFileEvidence(
        path=Path(archive_path),
        sha256=archive_sha,
        size_bytes=archive_size,
        identity=archive_identity,
    )
    recheck_large_file(evidence, "results ZIP archive")
    recheck_snapshot(checksum, "results SHA-256 sidecar")
    return evidence, checksum, report, headline_q50


def _source_record_matches(
    value: Any,
    source: Mapping[str, Any],
    label: str,
) -> None:
    record = _mapping(value, label)
    archive = _mapping(record.get("source_archive"), f"{label} source_archive")
    observed = {
        "commit": record.get("commit_sha"),
        "tree": record.get("git_tree_sha"),
        "archive_sha256": archive.get("sha256"),
        "archive_size_bytes": archive.get("size_bytes"),
    }
    if observed != dict(source):
        fail(f"{label} does not bind the release source lock")


def _source_state_matches(
    value: Any,
    source: Mapping[str, Any],
    label: str,
) -> None:
    state = _mapping(value, label)
    _source_record_matches(state.get("public_source"), source, f"{label} public source")
    _source_record_matches(state.get("private_source"), source, f"{label} private source")


def _contract_acceptance_entry(value: Any, role: str) -> dict[str, Any]:
    canonical = CONTRACT_PATHS[role]
    item = _exact_keys(
        value,
        {
            "contract_path",
            "contract_sha256",
            "contract_size_bytes",
            "accepted_id",
            "report_path",
            "report_sha256",
            "report_size_bytes",
            "report_id",
        },
        f"{role} acceptance entry",
    )
    if item["contract_path"] != canonical:
        fail(f"{role} contract path differs from the canonical release path")
    _sha(item["contract_sha256"], f"{role} contract sha256")
    _positive_size(item["contract_size_bytes"], f"{role} contract size")
    if not isinstance(item["accepted_id"], str) or not item["accepted_id"]:
        fail(f"{role} accepted id is missing")
    report_path = _safe_relative(item["report_path"], f"{role} report path")
    parts = PurePosixPath(report_path).parts
    if len(parts) != 2 or parts[0] != "provenance":
        fail(f"{role} report must be one top-level provenance file")
    _safe_leaf(parts[1], f"{role} report filename")
    _sha(item["report_sha256"], f"{role} report sha256")
    _positive_size(item["report_size_bytes"], f"{role} report size")
    _report_id(item["report_id"], f"{role} report id")
    return item


def _load_component_files(
    root: Path,
    entry: Mapping[str, Any],
    role: str,
) -> tuple[Snapshot, Snapshot, Any, Any]:
    contract_snapshot = read_snapshot(
        root, entry["contract_path"], f"{role} release contract"
    )
    report_snapshot = read_snapshot(
        root, entry["report_path"], f"{role} accepted public report"
    )
    _matches_snapshot(
        {
            "sha256": entry["contract_sha256"],
            "size_bytes": entry["contract_size_bytes"],
        },
        contract_snapshot,
        f"{role} contract",
    )
    _matches_snapshot(
        {
            "sha256": entry["report_sha256"],
            "size_bytes": entry["report_size_bytes"],
        },
        report_snapshot,
        f"{role} report",
    )
    return (
        contract_snapshot,
        report_snapshot,
        load_json_bytes(contract_snapshot.data, f"{role} contract"),
        load_json_bytes(report_snapshot.data, f"{role} report"),
    )


def _accepted(items: Any, role: str) -> dict[str, Any]:
    if not isinstance(items, list):
        fail(f"{role} contract candidate collection is not an array")
    matches = [
        item
        for item in items
        if isinstance(item, dict) and item.get("production_accepted") is True
    ]
    if len(matches) != 1:
        fail(f"{role} contract must contain exactly one production-accepted candidate")
    return matches[0]


def _internal_report_path(contract_path: str, leaf: Any, role: str) -> str:
    name = _safe_leaf(leaf, f"{role} contract report lock")
    parent = PurePosixPath(contract_path).parent
    return (parent / name).as_posix()


def _host_source_state(report: Mapping[str, Any], host: Any) -> dict[str, Any]:
    repetitions = report.get("fresh_repetitions")
    if not isinstance(repetitions, list) or len(repetitions) != 2:
        fail("host report does not contain exactly two fresh repetitions")
    embedded = _mapping(
        repetitions[0].get("embedded_signed_evidence"),
        "host embedded signed evidence",
    )
    challenge_name = getattr(host, "HOST_START_CHALLENGE_NAME", None)
    if not isinstance(challenge_name, str) or challenge_name not in embedded:
        fail("host report lacks its embedded signed start challenge")
    encoded = embedded[challenge_name]
    if not isinstance(encoded, str) or not encoded:
        fail("host embedded start challenge is not base64 text")
    try:
        challenge_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        fail(f"host embedded start challenge is not canonical base64: {error}")
    if base64.b64encode(challenge_bytes).decode("ascii") != encoded:
        fail("host embedded start challenge is not canonical base64")
    challenge = _mapping(
        load_json_bytes(challenge_bytes, "host embedded start challenge"),
        "host embedded start challenge",
    )
    return _mapping(challenge.get("source_state"), "host signed source state")


def _verify_host(
    root: Path,
    entry: Mapping[str, Any],
    source: Mapping[str, Any],
    host: Any,
) -> dict[str, Any]:
    contract_snapshot, report_snapshot, _raw_contract, report = _load_component_files(
        root, entry, "host"
    )
    contract = _call_verifier("host contract verifier", host.load_contract, contract_snapshot.path)
    candidate = _accepted(contract.get("artifact_sets"), "host")
    if candidate.get("id") != entry["accepted_id"]:
        fail("host accepted candidate differs from the release lock")
    lock = _mapping(candidate.get("qualification_report"), "host report lock")
    if (
        _internal_report_path(entry["contract_path"], lock.get("path"), "host")
        != entry["report_path"]
        or lock.get("sha256") != report_snapshot.sha256
    ):
        fail("host report differs from its contract lock")
    if report.get("qualification_id") != entry["report_id"]:
        fail("host report id differs from the release lock")
    _source_state_matches(_host_source_state(report, host), source, "host qualification")
    return {
        "contract_sha256": contract_snapshot.sha256,
        "report_sha256": report_snapshot.sha256,
        "report_name": report_snapshot.path.name,
        "accepted_id": candidate["id"],
        "report_id": report["qualification_id"],
        "_snapshots": (contract_snapshot, report_snapshot),
    }


def _verify_age(
    root: Path,
    entry: Mapping[str, Any],
    source: Mapping[str, Any],
    age: Any,
) -> dict[str, Any]:
    contract_snapshot, report_snapshot, _raw_contract, report = _load_component_files(
        root, entry, "age"
    )
    loaded = _call_verifier("age contract verifier", age.load_contract, contract_snapshot.path)
    contract = loaded[0] if isinstance(loaded, tuple) else loaded
    candidate = _call_verifier("age accepted-candidate verifier", age.accepted_candidate, contract)
    if candidate.get("id") != entry["accepted_id"]:
        fail("age accepted candidate differs from the release lock")
    lock = _mapping(candidate.get("qualification_report"), "age report lock")
    if (
        _internal_report_path(entry["contract_path"], lock.get("path"), "age")
        != entry["report_path"]
        or lock.get("sha256") != report_snapshot.sha256
    ):
        fail("age report differs from its contract lock")
    validated = _call_verifier(
        "age public-report verifier",
        age.validate_report_document,
        report,
        contract,
        candidate,
    )
    if validated.get("qualification_id") != entry["report_id"]:
        fail("age report id differs from the release lock")
    _source_state_matches(validated.get("source_state"), source, "age qualification")
    return {
        "contract_sha256": contract_snapshot.sha256,
        "report_sha256": report_snapshot.sha256,
        "report_name": report_snapshot.path.name,
        "accepted_id": candidate["id"],
        "report_id": validated["qualification_id"],
        "_snapshots": (contract_snapshot, report_snapshot),
    }


def _verify_radial(
    root: Path,
    entry: Mapping[str, Any],
    source: Mapping[str, Any],
    radial: Any,
) -> dict[str, Any]:
    contract_snapshot, report_snapshot, _raw_contract, report = _load_component_files(
        root, entry, "radial"
    )
    loaded = _call_verifier(
        "radial contract verifier", radial.load_contract, contract_snapshot.path
    )
    contract = loaded[0] if isinstance(loaded, tuple) else loaded
    candidate = _call_verifier(
        "radial accepted-candidate verifier", radial.accepted_candidate, contract
    )
    if candidate.get("id") != entry["accepted_id"]:
        fail("radial accepted candidate differs from the release lock")
    lock = _mapping(candidate.get("qualification_report"), "radial report lock")
    if (
        _internal_report_path(entry["contract_path"], lock.get("path"), "radial")
        != entry["report_path"]
        or lock.get("sha256") != report_snapshot.sha256
    ):
        fail("radial report differs from its contract lock")
    verified = _call_verifier(
        "radial public-report verifier",
        radial.verify_public_qualification,
        contract_snapshot.path,
        report_snapshot.path,
    )
    if report.get("qualification_id") != entry["report_id"]:
        fail("radial report id differs from the release lock")
    if verified.get("artifact_set_id") != candidate["id"]:
        fail("radial verifier returned a different accepted candidate")
    triplets = report.get("triplets")
    if not isinstance(triplets, list) or len(triplets) != 2:
        fail("radial report does not contain exactly two signed triplets")
    _source_state_matches(
        _mapping(triplets[0], "radial triplet").get("source_provenance"),
        source,
        "radial qualification",
    )
    return {
        "contract_sha256": contract_snapshot.sha256,
        "report_sha256": report_snapshot.sha256,
        "report_name": report_snapshot.path.name,
        "accepted_id": candidate["id"],
        "report_id": report["qualification_id"],
        "_snapshots": (contract_snapshot, report_snapshot),
    }


def _validate_local_report(
    report: Any,
    contract: Mapping[str, Any],
    candidate: Mapping[str, Any],
    local: Any,
) -> dict[str, Any]:
    item = _exact_keys(report, LOCAL_REPORT_KEYS, "local public report")
    if (
        item["schema_version"] != 1
        or type(item["schema_version"]) is not int
        or item["qualification_status"] != "PASS"
        or item["contract_id"] != contract.get("contract_id")
        or item["candidate_id"] != candidate.get("id")
    ):
        fail("local public report identity/status changed")
    _git_sha(item["source_commit"], "local report source commit")
    _git_sha(item["source_tree"], "local report source tree")
    for field in LOCAL_HASH_FIELDS:
        _sha(item[field], f"local report {field}")
    _sha(item["report_id"], "local report id")
    _sha(item["challenge_id"], "local report challenge id")
    _sha(item["completion_id"], "local report completion id")
    started = _utc(item["execution_started_utc"], "local execution start")
    ended = _utc(item["execution_ended_utc"], "local execution end")
    if ended <= started:
        fail("local production execution interval is not positive")
    for field in (
        "source_archive_size_bytes",
        "output_file_count",
        "output_total_size_bytes",
    ):
        _positive_size(item[field], f"local report {field}")
    results = item["command_results"]
    if not isinstance(results, list) or not results:
        fail("local public report command results are empty")
    for index, result in enumerate(results):
        command = _exact_keys(
            result,
            {
                "command_index",
                "exit_code",
                "started_utc",
                "ended_utc",
                "stdout_sha256",
                "stdout_size_bytes",
                "stderr_sha256",
                "stderr_size_bytes",
            },
            f"local command result {index}",
        )
        if type(command["command_index"]) is not int or command["command_index"] != index:
            fail("local command-result indices are not exact and contiguous")
        if type(command["exit_code"]) is not int or command["exit_code"] != 0:
            fail("local production command did not exit successfully")
        command_started = _utc(
            command["started_utc"], f"local command {index} start"
        )
        command_ended = _utc(command["ended_utc"], f"local command {index} end")
        if command_ended <= command_started:
            fail("local command execution interval is not positive")
        if command_started < started or command_ended > ended:
            fail("local command interval lies outside the production run")
        for stream in ("stdout", "stderr"):
            _sha(command[f"{stream}_sha256"], f"local command {stream} hash")
            _positive_size(
                command[f"{stream}_size_bytes"],
                f"local command {stream} size",
                allow_zero=True,
            )
    _call_verifier("local disclosure verifier", local.validate_report_disclosure, item)
    canonical = _call_verifier("local canonical serializer", local.canonical_json_bytes, item)
    if not isinstance(canonical, bytes):
        fail("local verifier did not return canonical report bytes")
    body = dict(item)
    identifier = body.pop("report_id")
    expected_identifier = hashlib.sha256(
        _call_verifier("local canonical serializer", local.canonical_json_bytes, body)
    ).hexdigest()
    if identifier != expected_identifier:
        fail("local public report self-identifier mismatch")
    return item


def _verify_local(
    root: Path,
    entry: Mapping[str, Any],
    source: Mapping[str, Any],
    local: Any,
) -> dict[str, Any]:
    contract_snapshot, report_snapshot, raw_contract, report = _load_component_files(
        root, entry, "local"
    )
    validated = _call_verifier("local contract verifier", local.validate_contract, raw_contract)
    contract = validated[0] if isinstance(validated, tuple) else validated
    candidates = validated[1] if isinstance(validated, tuple) else {
        item["id"]: item for item in contract.get("candidates", [])
    }
    candidate = _accepted(list(candidates.values()), "local")
    if candidate.get("id") != entry["accepted_id"]:
        fail("local accepted candidate differs from the release lock")
    report = _validate_local_report(report, contract, candidate, local)
    if report_snapshot.data != _call_verifier(
        "local canonical serializer", local.canonical_json_bytes, report
    ):
        fail("accepted local public report is not canonical JSON bytes")
    lock = _mapping(candidate.get("accepted_report"), "local accepted report lock")
    expected_lock = {
        "report_id": report["report_id"],
        "sha256": report_snapshot.sha256,
        "size_bytes": report_snapshot.size_bytes,
    }
    if lock != expected_lock:
        fail("local public report differs from its contract lock")
    if report["report_id"] != entry["report_id"]:
        fail("local report id differs from the release lock")
    if (
        report["source_commit"] != source["commit"]
        or report["source_tree"] != source["tree"]
        or report["source_archive_sha256"] != source["archive_sha256"]
        or report["source_archive_size_bytes"] != source["archive_size_bytes"]
    ):
        fail("local public report does not bind the release source")
    source_lock = _mapping(candidate.get("source_lock"), "local candidate source lock")
    for field in ("commit", "tree", "archive_sha256", "archive_size_bytes"):
        if source_lock.get(field) != source[field]:
            fail("local candidate source lock differs from the release source")
    signers = contract.get("attestation_signers")
    if not isinstance(signers, list) or len(signers) != 2:
        fail("local contract does not contain exactly two attestation signers")
    signer_ids = {item.get("signer_id") for item in signers if isinstance(item, dict)}
    if {
        report["start_signer_id"],
        report["completion_signer_id"],
    } != signer_ids or report["start_signer_id"] == report["completion_signer_id"]:
        fail("local report does not bind both distinct contract signers")
    return {
        "contract_sha256": contract_snapshot.sha256,
        "report_sha256": report_snapshot.sha256,
        "report_name": report_snapshot.path.name,
        "accepted_id": candidate["id"],
        "report_id": report["report_id"],
        "report": report,
        "_snapshots": (contract_snapshot, report_snapshot),
    }


def verify_local_report_contract_binding(
    repository_root: Path,
    report_path: Path,
    *,
    local_verifier: Any | None = None,
) -> dict[str, Any]:
    """Verify the accepted local contract/report before release-lock measurement."""

    root = Path(repository_root)
    local = local_verifier
    if local is None:
        local = load_source_only_module(
            ROOT,
            "scripts/verify_local_run_attestation.py",
            "verify_local_run_attestation",
            "local-run component verifier",
        )
    contract_snapshot = read_snapshot(
        root,
        CONTRACT_PATHS["local"],
        "local production attestation contract",
    )
    raw_contract = load_json_bytes(
        contract_snapshot.data, "local production attestation contract"
    )
    validated = _call_verifier(
        "local contract verifier", local.validate_contract, raw_contract
    )
    contract = validated[0] if isinstance(validated, tuple) else validated
    candidates = validated[1] if isinstance(validated, tuple) else {
        item["id"]: item for item in contract.get("candidates", [])
    }
    candidate = _accepted(list(candidates.values()), "local")
    report_snapshot = read_external_snapshot(
        report_path, "accepted local public report", maximum_bytes=MAX_JSON_BYTES
    )
    report = _validate_local_report(
        load_json_bytes(report_snapshot.data, "accepted local public report"),
        contract,
        candidate,
        local,
    )
    if report_snapshot.data != _call_verifier(
        "local canonical serializer", local.canonical_json_bytes, report
    ):
        fail("accepted local public report is not canonical JSON bytes")
    expected_report = {
        "report_id": report["report_id"],
        "sha256": report_snapshot.sha256,
        "size_bytes": report_snapshot.size_bytes,
    }
    if candidate.get("accepted_report") != expected_report:
        fail("accepted local public report differs from its production contract lock")
    source_lock = _mapping(candidate.get("source_lock"), "local candidate source lock")
    source = {
        field: source_lock.get(field)
        for field in ("commit", "tree", "archive_sha256", "archive_size_bytes")
    }
    _validate_source_lock(source)
    if (
        report["source_commit"] != source["commit"]
        or report["source_tree"] != source["tree"]
        or report["source_archive_sha256"] != source["archive_sha256"]
        or report["source_archive_size_bytes"] != source["archive_size_bytes"]
    ):
        fail("accepted local public report differs from its source lock")
    recheck_snapshot(contract_snapshot, "local production attestation contract")
    recheck_snapshot(report_snapshot, "accepted local public report")
    return {
        "report": report,
        "source": source,
        "candidate_id": candidate["id"],
        "contract_sha256": contract_snapshot.sha256,
        "report_sha256": report_snapshot.sha256,
    }


def _verify_freeze(
    root: Path,
    role: str,
    value: Any,
) -> tuple[dict[str, Any], dict[str, Snapshot]]:
    spec = FREEZE_SPECS[role]
    item = _exact_keys(value, {"root", "manifest", "files"}, f"{role} freeze lock")
    if item["root"] != spec["root"]:
        fail(f"{role} freeze root differs from the canonical release root")
    directory = _plain_path(root, item["root"], directory=True)
    expected_names = {*spec["targets"], spec["manifest"]}
    try:
        entries = list(os.scandir(directory))
    except OSError as error:
        fail(f"cannot enumerate {role} freeze root: {error}")
    observed: set[str] = set()
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            fail(f"cannot inspect {role} freeze member: {error}")
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            fail(f"{role} freeze root contains a non-regular member: {entry.name}")
        observed.add(entry.name)
    if observed != expected_names:
        fail(
            f"{role} freeze file set changed: expected={sorted(expected_names)!r}, "
            f"actual={sorted(observed)!r}"
        )
    files = _mapping(item["files"], f"{role} freeze files")
    if set(files) != set(spec["targets"]):
        fail(f"{role} freeze target lock set changed")
    snapshots: dict[str, Snapshot] = {}
    for name in spec["targets"]:
        evidence = _file_evidence(files[name], f"{role} freeze file {name}")
        relative = f"{item['root']}/{name}"
        snapshot = read_snapshot(
            root,
            relative,
            f"{role} freeze file {name}",
            maximum_bytes=MAX_FREEZE_FILE_BYTES,
        )
        _matches_snapshot(evidence, snapshot, f"{role} freeze file {name}")
        snapshots[name] = snapshot
    manifest_path = f"{item['root']}/{spec['manifest']}"
    manifest_evidence = _file_evidence(
        item["manifest"],
        f"{role} freeze manifest",
        expected_path=manifest_path,
    )
    manifest = read_snapshot(
        root, manifest_path, f"{role} freeze manifest", maximum_bytes=1_000_000
    )
    _matches_snapshot(manifest_evidence, manifest, f"{role} freeze manifest")
    try:
        lines = manifest.data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{role} freeze manifest is not strict UTF-8: {error}")
    expected_lines = [
        f"{snapshots[name].sha256}  {name}" for name in spec["targets"]
    ]
    if lines != expected_lines:
        fail(f"{role} freeze manifest order, set, or hashes changed")
    snapshots[spec["manifest"]] = manifest
    document = _mapping(
        load_json_bytes(snapshots[spec["json"]].data, f"{role} freeze JSON"),
        f"{role} freeze JSON",
    )
    return document, snapshots


def _expect(value: Any, expected: Any, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        fail(f"{label} differs from the release cross-binding")


def _verify_freeze_cross_bindings(
    numerical: Mapping[str, Any],
    sensitivity: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    posterior: Mapping[str, str],
) -> dict[str, float]:
    if numerical.get("status") != "PASS":
        fail("numerical freeze status is not PASS")
    if (
        sensitivity.get("status") != "SENSITIVITY_REGISTER_FROZEN"
        or sensitivity.get("scientific_readiness")
        != "CONDITIONAL_MODEL_PROJECTION_ONLY"
    ):
        fail("sensitivity freeze status/readiness changed")

    for label, freeze in (("numerical", numerical), ("sensitivity", sensitivity)):
        host = _mapping(
            _nested(freeze, ("artifact_roots", "host_artifact_contract"), label),
            f"{label} host binding",
        )
        _expect(host.get("production_accepted"), True, f"{label} host acceptance")
        _expect(
            host.get("contract_sha256"),
            components["host"]["contract_sha256"],
            f"{label} host contract hash",
        )
        _expect(
            host.get("artifact_set_id"),
            components["host"]["accepted_id"],
            f"{label} host candidate",
        )
        qualification_reports = host.get("qualification_reports")
        expected_reports = {
            components["host"]["report_name"]: components["host"]["report_sha256"]
        }
        _expect(
            qualification_reports,
            expected_reports,
            f"{label} host qualification report",
        )

        radial = _mapping(
            _nested(freeze, ("artifact_roots", "radial_ssp_qualification"), label),
            f"{label} radial binding",
        )
        _expect(radial.get("status"), "PASS", f"{label} radial status")
        _expect(
            radial.get("contract_sha256"),
            components["radial"]["contract_sha256"],
            f"{label} radial contract hash",
        )
        _expect(
            radial.get("qualification_report_sha256"),
            components["radial"]["report_sha256"],
            f"{label} radial report hash",
        )
        _expect(
            radial.get("artifact_set_id"),
            components["radial"]["accepted_id"],
            f"{label} radial candidate",
        )

        local = _mapping(
            _nested(freeze, ("artifact_roots", "signed_local_production_run"), label),
            f"{label} local-run binding",
        )
        _expect(local.get("status"), "PASS", f"{label} local-run status")
        report = components["local"]["report"]
        expected_local = {
            "report_id": report["report_id"],
            "contract_sha256": components["local"]["contract_sha256"],
            "public_report_sha256": components["local"]["report_sha256"],
            "candidate_id": components["local"]["accepted_id"],
            "source_archive_sha256": report["source_archive_sha256"],
            "source_archive_size_bytes": report["source_archive_size_bytes"],
            "command_plan_sha256": report["command_plan_sha256"],
            "numerical_runtime_manifest_sha256": report[
                "numerical_runtime_manifest_sha256"
            ],
            "output_manifest_sha256": report["output_manifest_sha256"],
            "output_file_set_sha256": report["output_file_set_sha256"],
            "output_file_count": report["output_file_count"],
            "output_total_size_bytes": report["output_total_size_bytes"],
        }
        for field in LOCAL_BINDING_FIELDS:
            _expect(
                local.get(field), expected_local[field], f"{label} local-run {field}"
            )

    age = _mapping(
        _nested(
            sensitivity,
            ("artifact_roots", "age_cut_sensitivity"),
            "sensitivity",
        ),
        "sensitivity age binding",
    )
    _expect(age.get("status"), "PASS", "sensitivity age status")
    _expect(
        age.get("age_ssp_contract_sha256"),
        components["age"]["contract_sha256"],
        "sensitivity age contract hash",
    )
    _expect(
        age.get("ssp_qualification_report_sha256"),
        components["age"]["report_sha256"],
        "sensitivity age report hash",
    )
    _expect(
        age.get("accepted_ssp_repetition_rederived"),
        True,
        "sensitivity accepted SSP rederivation",
    )

    numerical_inputs = _mapping(numerical.get("inputs"), "numerical freeze inputs")
    sensitivity_inputs = _mapping(sensitivity.get("inputs"), "sensitivity freeze inputs")
    posterior_locations = {
        "corrected_constant_full": (
            numerical_inputs,
            "constant_full_posterior_samples",
        ),
        "corrected_constant_propagation": (
            numerical_inputs,
            "constant_posterior_samples",
        ),
        "corrected_zero_full": (numerical_inputs, "zero_full_posterior_samples"),
        "corrected_zero_propagation": (numerical_inputs, "zero_posterior_samples"),
        "legacy_constant_propagation": (
            sensitivity_inputs,
            "legacy_measurement_posterior_samples",
        ),
    }
    for key, (collection, member) in posterior_locations.items():
        record = _mapping(collection.get(member), f"posterior input {member}")
        _expect(record.get("sha256"), posterior[key], f"posterior hash {key}")
    legacy_root = _mapping(
        _nested(
            sensitivity,
            (
                "artifact_roots",
                "legacy_measurement_accepted_aggregate",
                "accepted_root",
            ),
            "sensitivity",
        ),
        "legacy accepted aggregate",
    )
    _expect(
        legacy_root.get("full_samples_sha256"),
        posterior["legacy_constant_full"],
        "legacy full posterior hash",
    )
    _expect(
        legacy_root.get("propagation_samples_sha256"),
        posterior["legacy_constant_propagation"],
        "legacy propagation posterior hash",
    )

    headline_q50: dict[str, float] = {}
    for branch in ("constant", "zero"):
        numerical_record = _mapping(
            numerical_inputs.get(f"{branch}_posterior_samples"),
            f"numerical {branch} posterior input",
        )
        sensitivity_record = _mapping(
            sensitivity_inputs.get(f"{branch}_posterior_samples"),
            f"sensitivity {branch} posterior input",
        )
        _expect(
            sensitivity_record.get("sha256"),
            numerical_record.get("sha256"),
            f"cross-freeze {branch} posterior hash",
        )
        numerical_q50 = _nested(
            numerical,
            ("galactic_results", "canonical", branch, "Lambda_EE", "q50"),
            "numerical",
        )
        sensitivity_q50 = _nested(
            sensitivity,
            ("canonical_posterior_q50", f"{branch}_Lambda_EE"),
            "sensitivity",
        )
        if (
            isinstance(numerical_q50, bool)
            or not isinstance(numerical_q50, (int, float))
            or not math.isfinite(float(numerical_q50))
        ):
            fail(f"numerical {branch} headline q50 is not finite")
        _expect(
            sensitivity_q50,
            numerical_q50,
            f"cross-freeze {branch} Lambda_EE q50",
        )
        headline_q50[branch] = float(numerical_q50)
    return headline_q50


def validate_acceptance_document(value: Any) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "schema_version",
            "release_version",
            "production_accepted",
            "acceptance_id",
            "computational_source",
            "release_source",
            "results_archive",
            "contracts",
            "freezes",
            "posterior_artifacts",
        },
        "v4.0.4 release acceptance",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 2:
        fail("release acceptance schema_version must be integer 2")
    if document["release_version"] != RELEASE_VERSION:
        fail("release acceptance version is not 4.0.4")
    if document["production_accepted"] is not True:
        fail("release acceptance production_accepted is not true")
    _report_id(document["acceptance_id"], "release acceptance id")
    body = dict(document)
    identifier = body.pop("acceptance_id")
    expected_id = "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if identifier != expected_id:
        fail("release acceptance self-identifier mismatch")
    _validate_source_lock(document["computational_source"])
    _validate_release_source(document["release_source"])
    _validate_results_archive(document["results_archive"])
    contracts = _mapping(document["contracts"], "release contracts")
    if set(contracts) != set(CONTRACT_PATHS):
        fail("release contract role set changed")
    report_paths: set[str] = set()
    for role in CONTRACT_PATHS:
        entry = _contract_acceptance_entry(contracts[role], role)
        if entry["report_path"] in report_paths:
            fail("release contracts reuse one public report path")
        report_paths.add(entry["report_path"])
    freezes = _mapping(document["freezes"], "release freezes")
    if set(freezes) != set(FREEZE_SPECS):
        fail("release freeze role set changed")
    posterior = _mapping(document["posterior_artifacts"], "posterior artifact locks")
    if set(posterior) != POSTERIOR_KEYS:
        fail("headline posterior lock set changed")
    for key, digest in posterior.items():
        _sha(digest, f"headline posterior {key}")
    return document


def _verify_release_foundation(
    repository_root: Path = ROOT,
    *,
    verifiers: SimpleNamespace | None = None,
    trusted_source_archive: Path | None = None,
    trusted_source_checksum: Path | None = None,
) -> dict[str, Any]:
    root = Path(repository_root)
    acceptance_snapshot = read_snapshot(
        root, ACCEPTANCE_PATH, "v4.0.4 release acceptance"
    )
    acceptance = validate_acceptance_document(
        load_json_bytes(acceptance_snapshot.data, "v4.0.4 release acceptance")
    )
    source = acceptance["computational_source"]
    release_source = acceptance["release_source"]
    _verify_git_lineage_if_available(root, acceptance)
    trusted_anchor = _early_release_tree_preflight(
        root,
        acceptance,
        trusted_source_archive=trusted_source_archive,
        trusted_source_checksum=trusted_source_checksum,
    )
    modules = verifiers if verifiers is not None else _default_verifiers()
    entries = acceptance["contracts"]
    components = {
        "host": _verify_host(root, entries["host"], source, modules.host),
        "age": _verify_age(root, entries["age"], source, modules.age),
        "radial": _verify_radial(root, entries["radial"], source, modules.radial),
        "local": _verify_local(root, entries["local"], source, modules.local),
    }
    numerical, numerical_snapshots = _verify_freeze(
        root, "numerical", acceptance["freezes"]["numerical"]
    )
    sensitivity, sensitivity_snapshots = _verify_freeze(
        root, "sensitivity", acceptance["freezes"]["sensitivity"]
    )
    headline_q50 = _verify_freeze_cross_bindings(
        numerical,
        sensitivity,
        components,
        acceptance["posterior_artifacts"],
    )
    component_snapshots = {
        role: component["_snapshots"] for role, component in components.items()
    }
    manifest_snapshot = _verify_release_manifest_binding(
        root,
        acceptance,
        acceptance_snapshot,
        component_snapshots,
        {
            "numerical": numerical_snapshots,
            "sensitivity": sensitivity_snapshots,
        },
    )
    for snapshot, label in (
        (acceptance_snapshot, "release acceptance"),
        (manifest_snapshot, "repository release manifest"),
        *(
            (snapshot, f"{role} release evidence")
            for role, pair in component_snapshots.items()
            for snapshot in pair
        ),
        *(
            (item, f"numerical freeze {name}")
            for name, item in numerical_snapshots.items()
        ),
        *(
            (item, f"sensitivity freeze {name}")
            for name, item in sensitivity_snapshots.items()
        ),
    ):
        recheck_snapshot(snapshot, label)
    return {
        "status": "PASS",
        "release_version": RELEASE_VERSION,
        "acceptance_id": acceptance["acceptance_id"],
        "acceptance_sha256": acceptance_snapshot.sha256,
        "computational_source": dict(source),
        "release_source": dict(release_source),
        "results_archive": dict(acceptance["results_archive"]),
        "contracts": {
            role: {
                key: value
                for key, value in component.items()
                if key not in {"report", "_snapshots"}
            }
            for role, component in components.items()
        },
        "freeze_manifests": {
            role: acceptance["freezes"][role]["manifest"]["sha256"]
            for role in FREEZE_SPECS
        },
        "posterior_artifacts": dict(acceptance["posterior_artifacts"]),
        "trusted_source_anchor": trusted_anchor,
        "_headline_q50": headline_q50,
        "_local_report": dict(components["local"]["report"]),
    }


def verify_release_acceptance(
    repository_root: Path = ROOT,
    *,
    verifiers: SimpleNamespace | None = None,
    results_archive: Path | None = None,
    results_checksum: Path | None = None,
    trusted_source_archive: Path | None = None,
    trusted_source_checksum: Path | None = None,
) -> dict[str, Any]:
    """Verify release evidence plus the actual byte-locked results assets."""

    root = Path(repository_root)
    evidence = _verify_release_foundation(
        root,
        verifiers=verifiers,
        trusted_source_archive=trusted_source_archive,
        trusted_source_checksum=trusted_source_checksum,
    )
    archive_path = (
        Path(results_archive)
        if results_archive is not None
        else root / "dist" / RESULTS_ARCHIVE_NAME
    )
    checksum_path = (
        Path(results_checksum)
        if results_checksum is not None
        else root / "dist" / RESULTS_CHECKSUM_NAME
    )
    archive_evidence, checksum_snapshot, public_report, signed_headline_q50 = (
        _verify_results_archive(
        evidence["results_archive"],
        evidence["_local_report"],
        evidence["computational_source"],
        evidence["posterior_artifacts"],
        archive_path,
        checksum_path,
        )
    )
    for branch in ("constant", "zero"):
        _expect(
            evidence["_headline_q50"][branch],
            signed_headline_q50[branch],
            f"{branch} headline q50 versus signed local production output",
        )
    evidence["results_archive"] = {
        **evidence["results_archive"],
        "verified_path": str(archive_evidence.path),
        "verified_sidecar_path": str(checksum_snapshot.path),
        "embedded_report_status": public_report["status"],
    }
    evidence.pop("_local_report", None)
    evidence.pop("_headline_q50", None)
    evidence["headline_q50"] = signed_headline_q50
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--results-archive", type=Path)
    parser.add_argument("--results-checksum", type=Path)
    parser.add_argument("--trusted-source-archive", type=Path)
    parser.add_argument("--trusted-source-checksum", type=Path)
    args = parser.parse_args()
    try:
        evidence = verify_release_acceptance(
            args.repository_root,
            results_archive=args.results_archive,
            results_checksum=args.results_checksum,
            trusted_source_archive=args.trusted_source_archive,
            trusted_source_checksum=args.trusted_source_checksum,
        )
    except ReleaseAcceptanceError as error:
        raise SystemExit(f"V4.0.4 RELEASE ACCEPTANCE FAIL: {error}") from error
    print(
        "PASS v4.0.4 release acceptance: "
        f"{evidence['acceptance_id']} "
        f"computational_source={evidence['computational_source']['commit']}"
    )


if __name__ == "__main__":
    main()
