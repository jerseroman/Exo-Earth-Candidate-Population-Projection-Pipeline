#!/usr/bin/env python3
"""Build and verify a deterministic archive of signed v4.0.4 results."""

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
import copy
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import tempfile
from types import ModuleType
from typing import Any, BinaryIO
import zipfile


MANIFEST_NAME = "SHA256SUMS_v404_local_production.txt"
REPORT_NAME = "V404_LOCAL_PRODUCTION_REPORT.json"
ARCHIVE_PREFIX = "Exo-Earth-Candidate-Population-Projection-Pipeline-v4.0.4-results"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$")
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class PackageError(RuntimeError):
    """Raised when the public result boundary is not exact and release-safe."""


def fail(message: str) -> None:
    raise PackageError(message)


def has_reparse_point(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def plain_root(path: Path, label: str) -> Path:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or has_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        fail(f"{label} must be a plain directory")
    return candidate.resolve(strict=True)


def enumerate_plain_files(root: Path, label: str) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = {""}
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            fail(f"cannot enumerate {label}: {error}")
        for entry in entries:
            relative = (
                f"{relative_directory}/{entry.name}"
                if relative_directory
                else entry.name
            )
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                fail(f"cannot inspect {label} member {relative}: {error}")
            if stat.S_ISLNK(metadata.st_mode) or has_reparse_point(metadata):
                fail(f"{label} contains a link or reparse point: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
            else:
                fail(f"{label} contains a non-regular member: {relative}")
    return files, directories


def read_stable(path: Path, label: str, *, maximum_bytes: int | None = None) -> bytes:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or has_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        fail(f"{label} must be a regular non-link file")
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        fail(f"{label} exceeds the byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened_before = os.fstat(descriptor)
        data = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            data.extend(block)
            if maximum_bytes is not None and len(data) > maximum_bytes:
                fail(f"{label} exceeds the byte limit")
        opened_after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as error:
        fail(f"cannot re-inspect {label}: {error}")
    observed = identity(opened_before)
    if (
        observed != identity(opened_after)
        or observed != identity(before)
        or observed != identity(after)
        or stat.S_ISLNK(after.st_mode)
        or has_reparse_point(after)
        or len(data) != opened_after.st_size
    ):
        fail(f"{label} changed during its stable read")
    return bytes(data)


def _load_release_gate_source_only() -> ModuleType:
    """Load the release gate from stable source bytes, never ``.pyc``."""

    source = Path(os.path.abspath(__file__)).with_name(
        "verify_v404_release_acceptance.py"
    )
    data = read_stable(
        source, "release acceptance verifier source", maximum_bytes=8 * 1024 * 1024
    )
    try:
        code = compile(
            data,
            str(source),
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=-1,
        )
    except (SyntaxError, TypeError, ValueError) as error:
        fail(f"cannot compile release acceptance verifier source: {error}")
    name = "verify_v404_release_acceptance"
    module = ModuleType(name)
    module.__file__ = str(source)
    module.__package__ = ""
    module.__cached__ = None
    module.__loader__ = None
    module.__spec__ = None
    module.__dict__["__source_only_sha256__"] = hashlib.sha256(data).hexdigest()
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    if read_stable(
        source,
        "release acceptance verifier source final recheck",
        maximum_bytes=8 * 1024 * 1024,
    ) != data:
        fail("release acceptance verifier source changed while it was loaded")
    if module.__dict__.get("__cached__") is not None:
        fail("release acceptance verifier enabled a bytecode-cache binding")
    return module


verify_v404_release_acceptance = _load_release_gate_source_only()


def validate_relative_path(value: str) -> str:
    if "\\" in value or ":" in value or "\x00" in value or "\r" in value or "\n" in value:
        fail("production manifest contains an unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail("production manifest contains an unsafe path")
    return value


def load_manifest(root: Path) -> tuple[dict[str, str], bytes]:
    data = read_stable(root / MANIFEST_NAME, "public production manifest", maximum_bytes=2_000_000)
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"public production manifest is not UTF-8: {error}")
    if not lines:
        fail("public production manifest is empty")
    entries: dict[str, str] = {}
    ordered: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        match = MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            fail(f"malformed public production manifest line {line_number}")
        digest, relative = match.groups()
        validate_relative_path(relative)
        if relative == MANIFEST_NAME or relative.casefold() in {
            item.casefold() for item in ordered
        }:
            fail("public production manifest has a self entry or case collision")
        entries[relative] = digest
        ordered.append(relative)
    if ordered != sorted(ordered):
        fail("public production manifest paths are not sorted")
    if REPORT_NAME not in entries:
        fail("public production manifest does not include its public report")
    return entries, data


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    # Result tables are already compressed where material.  Stored members
    # avoid zlib-version drift and make the container byte-reproducible.
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits |= 0x800
    return info


def add_verified_file(
    archive: zipfile.ZipFile,
    source: Path,
    member: str,
    expected_sha256: str,
) -> tuple[str, int]:
    try:
        before = source.lstat()
    except OSError as error:
        fail(f"cannot inspect result file {source}: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or has_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        fail(f"result file is not a regular non-link file: {source}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        with archive.open(zip_info(member), mode="w") as target:
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                target.write(block)
                digest.update(block)
                size += len(block)
        opened_after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot archive result file {source}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = source.lstat()
    except OSError as error:
        fail(f"cannot re-inspect result file {source}: {error}")
    observed = identity(opened_before)
    actual = digest.hexdigest()
    if (
        observed != identity(opened_after)
        or observed != identity(before)
        or observed != identity(after)
        or stat.S_ISLNK(after.st_mode)
        or has_reparse_point(after)
        or size != opened_after.st_size
        or actual != expected_sha256
    ):
        fail(f"result file differs from its signed manifest: {source}")
    return actual, size


def sha256_file(path: Path) -> tuple[str, int]:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        fail(f"cannot inspect file for stable SHA-256: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or has_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        fail("stable SHA-256 input must be a regular non-link file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        after_fd = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot hash file stably: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as error:
        fail(f"cannot re-inspect stable SHA-256 input: {error}")
    if (
        identity(before) != identity(opened)
        or identity(opened) != identity(after_fd)
        or identity(opened) != identity(after)
        or stat.S_ISLNK(after.st_mode)
        or has_reparse_point(after)
        or size != opened.st_size
    ):
        fail("file changed during its stable SHA-256 measurement")
    return digest.hexdigest(), size


def paths_overlap(first: Path, second: Path) -> bool:
    a = Path(first).resolve(strict=False)
    b = Path(second).resolve(strict=False)
    try:
        a.relative_to(b)
        return True
    except ValueError:
        pass
    try:
        b.relative_to(a)
        return True
    except ValueError:
        return False


def expected_directories(paths: list[str]) -> set[str]:
    directories = {""}
    for relative in paths:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


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
        fail(f"cannot serialize canonical public-results JSON: {error}")


def canonical_entry_digest(entries: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def parse_scoped_manifest(
    data: bytes,
    manifest_path: str,
) -> dict[str, str]:
    """Parse one directory-scoped manifest into full logical paths."""

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"scoped manifest is not strict UTF-8: {manifest_path}: {error}")
    if not text.endswith("\n") or "\r" in text:
        fail(f"scoped manifest is not canonical LF text: {manifest_path}")
    lines = text.splitlines()
    if not lines:
        fail(f"scoped manifest is empty: {manifest_path}")
    parent = PurePosixPath(manifest_path).parent
    entries: dict[str, str] = {}
    leaves: list[str] = []
    casefolded: set[str] = set()
    for number, line in enumerate(lines, start=1):
        match = MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            fail(f"scoped manifest line is malformed: {manifest_path}:{number}")
        digest, leaf = match.groups()
        validate_relative_path(leaf)
        if "/" in leaf or PurePosixPath(leaf).name != leaf:
            fail(f"scoped manifest target is not a same-directory leaf: {manifest_path}")
        folded = leaf.casefold()
        if folded in casefolded:
            fail(f"scoped manifest has a case collision: {manifest_path}")
        casefolded.add(folded)
        leaves.append(leaf)
        entries[(parent / leaf).as_posix()] = digest
    if leaves != sorted(leaves):
        fail(f"scoped manifest targets are not sorted: {manifest_path}")
    return entries


def render_scoped_manifest(
    manifest_path: str,
    targets: tuple[str, ...],
    records: dict[str, dict[str, Any]],
) -> bytes:
    parent = PurePosixPath(manifest_path).parent
    lines: list[str] = []
    for target in targets:
        path = PurePosixPath(target)
        if path.parent != parent or target not in records:
            fail(f"public scoped manifest target escaped its signed directory: {target}")
        lines.append(f"{records[target]['sha256']}  {path.name}\n")
    if [line.rsplit("  ", 1)[1][:-1] for line in lines] != sorted(
        line.rsplit("  ", 1)[1][:-1] for line in lines
    ):
        fail(f"public scoped manifest target order is not canonical: {manifest_path}")
    return "".join(lines).encode("utf-8")


def load_signed_output_manifest(
    path: Path, local_report: dict[str, Any]
) -> tuple[list[dict[str, Any]], bytes]:
    snapshot = verify_v404_release_acceptance.read_external_snapshot(
        path, "signed strict local output manifest", maximum_bytes=16 * 1024 * 1024
    )
    entries = verify_v404_release_acceptance.validate_local_output_manifest_bytes(
        snapshot.data, local_report
    )
    verify_v404_release_acceptance.recheck_snapshot(
        snapshot, "signed strict local output manifest"
    )
    return entries, snapshot.data


@dataclass(frozen=True)
class PreparedResults:
    root: Path
    signed_by_path: dict[str, dict[str, Any]]
    signed_manifest_data: bytes
    private_manifest_entries: dict[str, str]
    private_manifest_data: bytes
    public_paths: tuple[str, ...]
    projected_members: dict[str, bytes]
    projected_records: dict[str, tuple[str, int]]
    policy_sha256: str
    files: set[str]
    directories: set[str]


@dataclass(frozen=True)
class DirectorySnapshot:
    path: Path
    chain: tuple[tuple[Path, tuple[int, int]], ...]


@dataclass(frozen=True)
class FileCommitEvidence:
    path: Path
    device_inode: tuple[int, int]
    sha256: str
    size_bytes: int


def snapshot_output_directory(path: Path, label: str) -> DirectorySnapshot:
    candidate = Path(os.path.abspath(path))
    paths = [candidate]
    while paths[-1] != paths[-1].parent:
        paths.append(paths[-1].parent)
    chain: list[tuple[Path, tuple[int, int]]] = []
    for current in reversed(paths):
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"cannot inspect {label} ancestor {current}: {error}")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or has_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            fail(f"{label} ancestor is not a plain directory: {current}")
        chain.append((current, (int(metadata.st_dev), int(metadata.st_ino))))
    return DirectorySnapshot(candidate, tuple(chain))


def recheck_output_directory(snapshot: DirectorySnapshot, label: str) -> None:
    for path, expected in snapshot.chain:
        try:
            metadata = path.lstat()
        except OSError as error:
            fail(f"cannot recheck {label} ancestor {path}: {error}")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or has_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
            or (int(metadata.st_dev), int(metadata.st_ino)) != expected
        ):
            fail(f"{label} ancestor identity changed: {path}")


def create_bound_temporary_file(
    directory: DirectorySnapshot, label: str
) -> tuple[Path, BinaryIO, tuple[int, int]]:
    """Create an unpredictable O_EXCL temp through the bound output parent."""

    recheck_output_directory(directory, f"{label} directory")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = -1
    for _attempt in range(128):
        leaf = f".{label.replace(' ', '-')}.{secrets.token_hex(16)}.tmp"
        path = directory.path / leaf
        descriptor = -1
        try:
            if os.name != "nt":
                directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                directory_flags |= getattr(os, "O_NOFOLLOW", 0)
                directory_descriptor = os.open(directory.path, directory_flags)
                opened_directory = os.fstat(directory_descriptor)
                if (
                    int(opened_directory.st_dev), int(opened_directory.st_ino)
                ) != directory.chain[-1][1]:
                    fail(f"{label} directory changed while opened")
                descriptor = os.open(
                    leaf, flags, 0o600, dir_fd=directory_descriptor
                )
            else:
                descriptor = os.open(path, flags, 0o600)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                fail(f"{label} temporary output is not a regular file")
            metadata = path.lstat()
            device_inode = (int(opened.st_dev), int(opened.st_ino))
            if (
                stat.S_ISLNK(metadata.st_mode)
                or has_reparse_point(metadata)
                or (int(metadata.st_dev), int(metadata.st_ino)) != device_inode
            ):
                fail(f"{label} temporary output path is not descriptor-bound")
            recheck_output_directory(directory, f"{label} directory")
            return path, os.fdopen(descriptor, "w+b", closefd=True), device_inode
        except FileExistsError:
            if descriptor >= 0:
                os.close(descriptor)
            continue
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
                directory_descriptor = -1
    fail(f"cannot allocate a unique {label} temporary output")


def snapshot_committable_file(
    path: Path,
    device_inode: tuple[int, int],
    expected_sha256: str,
    expected_size: int,
    directory: DirectorySnapshot,
    label: str,
) -> FileCommitEvidence:
    recheck_output_directory(directory, f"{label} directory")
    digest, size = sha256_file(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or has_reparse_point(metadata)
        or (int(metadata.st_dev), int(metadata.st_ino)) != device_inode
        or digest != expected_sha256
        or size != expected_size
    ):
        fail(f"{label} temporary output differs from verified bytes")
    return FileCommitEvidence(path, device_inode, digest, size)


def promote_verified_file(
    evidence: FileCommitEvidence,
    destination: Path,
    directory: DirectorySnapshot,
    label: str,
) -> None:
    """Hard-link one verified inode to a refuse-existing final name."""

    if Path(os.path.abspath(destination.parent)) != directory.path:
        fail(f"{label} destination parent differs from its bound directory")
    if evidence.path.parent != directory.path:
        fail(f"{label} temporary file is outside its bound directory")
    recheck_output_directory(directory, f"{label} directory")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        fail(f"cannot inspect final {label}: {error}")
    else:
        fail(f"refusing to replace existing final {label}")
    snapshot_committable_file(
        evidence.path,
        evidence.device_inode,
        evidence.sha256,
        evidence.size_bytes,
        directory,
        label,
    )
    directory_descriptor = -1
    try:
        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            directory_descriptor = os.open(directory.path, directory_flags)
            opened_directory = os.fstat(directory_descriptor)
            if (
                int(opened_directory.st_dev), int(opened_directory.st_ino)
            ) != directory.chain[-1][1]:
                fail(f"{label} directory changed while opened for commit")
            os.link(
                evidence.path.name,
                destination.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        else:
            os.link(evidence.path, destination, follow_symlinks=False)
    except FileExistsError:
        fail(f"refusing to replace existing final {label}")
    except OSError as error:
        fail(f"cannot commit final {label} without replacement: {error}")
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
    try:
        final_metadata = destination.lstat()
    except OSError as error:
        fail(f"cannot inspect committed final {label}: {error}")
    if (
        stat.S_ISLNK(final_metadata.st_mode)
        or has_reparse_point(final_metadata)
        or (int(final_metadata.st_dev), int(final_metadata.st_ino))
        != evidence.device_inode
        or final_metadata.st_size != evidence.size_bytes
    ):
        fail(f"committed final {label} is not the verified inode")
    final_sha256, final_size = sha256_file(destination)
    if final_sha256 != evidence.sha256 or final_size != evidence.size_bytes:
        fail(f"committed final {label} differs from verified bytes")
    recheck_output_directory(directory, f"{label} directory")


def unlink_verified_temporary(evidence: FileCommitEvidence) -> None:
    """Remove only the exact temporary inode created by this build."""

    try:
        metadata = evidence.path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        return
    if (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not has_reparse_point(metadata)
        and (int(metadata.st_dev), int(metadata.st_ino)) == evidence.device_inode
    ):
        try:
            evidence.path.unlink()
        except OSError:
            pass


def prepare_signed_results(
    root: Path,
    signed_output_manifest: Path,
    local_report: dict[str, Any],
    source: dict[str, Any],
) -> PreparedResults:
    signed_entries, signed_manifest_data = load_signed_output_manifest(
        signed_output_manifest, local_report
    )
    signed_by_path = {item["path"]: item for item in signed_entries}
    policy = verify_v404_release_acceptance._public_results_policy()
    if tuple(signed_by_path) != policy.private_paths:
        fail("signed strict output set differs from the exact 88-file private evidence tree")

    private_manifest_entries, private_manifest_data = load_manifest(root)
    if set(private_manifest_entries) != set(signed_by_path) - {MANIFEST_NAME}:
        fail("private production manifest differs from the signed strict output set")
    for relative, expected in private_manifest_entries.items():
        if signed_by_path[relative]["sha256"] != expected:
            fail(f"private production manifest differs from signed output: {relative}")
    if (
        signed_by_path[MANIFEST_NAME]["sha256"]
        != hashlib.sha256(private_manifest_data).hexdigest()
        or signed_by_path[MANIFEST_NAME]["size_bytes"] != len(private_manifest_data)
    ):
        fail("private production manifest bytes differ from the signed strict output")
    files, directories = enumerate_plain_files(root, "private production-evidence root")
    if files != set(signed_by_path) or directories != expected_directories(
        list(signed_by_path)
    ):
        fail("private production-evidence tree differs from its signed manifest")
    report_data = read_stable(
        root / REPORT_NAME, "private production report", maximum_bytes=4_000_000
    )
    private_observed = {
        relative: (item["sha256"], item["size_bytes"])
        for relative, item in signed_by_path.items()
    }
    private_report = verify_v404_release_acceptance._validate_private_results_report(
        report_data, private_observed, source
    )

    excluded_entries = [signed_by_path[path] for path in policy.excluded_paths]
    passthrough_entries = [signed_by_path[path] for path in policy.passthrough_paths]
    expected_projection_binding = {
        "public_projection_policy_sha256": policy.policy_sha256,
        "public_projection_file_count": len(policy.public_paths),
        "public_projection_excluded_file_count": len(policy.excluded_paths),
        "public_projection_excluded_file_set_sha256": canonical_entry_digest(
            excluded_entries
        ),
        "public_projection_passthrough_file_count": len(policy.passthrough_paths),
        "public_projection_passthrough_total_size_bytes": sum(
            item["size_bytes"] for item in passthrough_entries
        ),
        "public_projection_passthrough_file_set_sha256": canonical_entry_digest(
            passthrough_entries
        ),
        "public_projection_rewritten_manifest_count": len(policy.manifest_targets),
    }
    for field, expected in expected_projection_binding.items():
        if local_report.get(field) != expected:
            fail(f"signed local report differs from public projection binding: {field}")

    projected_members: dict[str, bytes] = {}
    projected_records: dict[str, tuple[str, int]] = {
        path: (signed_by_path[path]["sha256"], signed_by_path[path]["size_bytes"])
        for path in policy.passthrough_paths
    }
    for manifest_path, (private_targets, public_targets) in policy.manifest_targets.items():
        private_data = read_stable(
            root / Path(*PurePosixPath(manifest_path).parts),
            f"private scoped manifest {manifest_path}",
            maximum_bytes=2_000_000,
        )
        private_record = signed_by_path[manifest_path]
        if (
            hashlib.sha256(private_data).hexdigest() != private_record["sha256"]
            or len(private_data) != private_record["size_bytes"]
        ):
            fail(f"private scoped manifest differs from signed bytes: {manifest_path}")
        parsed = parse_scoped_manifest(private_data, manifest_path)
        expected_private = {
            target: signed_by_path[target]["sha256"] for target in private_targets
        }
        if parsed != expected_private:
            fail(f"private scoped manifest differs from its exact signed directory: {manifest_path}")
        public_data = render_scoped_manifest(
            manifest_path, public_targets, signed_by_path
        )
        projected_members[manifest_path] = public_data
        projected_records[manifest_path] = (
            hashlib.sha256(public_data).hexdigest(),
            len(public_data),
        )

    public_report = copy.deepcopy(private_report)
    public_report.pop("private_evidence_boundary")
    public_report["public_boundary"] = {
        "archive_scope": "separate-v4.0.4-results-package",
        "derived_aggregate_diagnostics_included": True,
        "mcmc_chain_files_copied": False,
        "private_logs_copied": False,
        "private_raw_chain_files_copied": False,
        "row_level_dr25_derived_files_copied": False,
        "row_level_host_files_copied": False,
        "third_party_input_files_copied": False,
    }
    public_report["public_projection"] = {
        "excluded_file_count": len(policy.excluded_paths),
        "excluded_file_set_sha256": local_report[
            "public_projection_excluded_file_set_sha256"
        ],
        "passthrough_file_count": len(policy.passthrough_paths),
        "passthrough_file_set_sha256": local_report[
            "public_projection_passthrough_file_set_sha256"
        ],
        "passthrough_total_size_bytes": local_report[
            "public_projection_passthrough_total_size_bytes"
        ],
        "policy_id": policy.policy["policy_id"],
        "policy_sha256": policy.policy_sha256,
        "private_evidence_file_count": len(policy.private_paths),
        "public_file_count": len(policy.public_paths),
        "retained_derived_file_count": len(policy.retained_derived_paths),
        "rewritten_scoped_manifest_count": len(policy.manifest_targets),
    }
    public_report["public_files"] = [
        {
            "path": path,
            "sha256": projected_records[path][0],
            "size_bytes": projected_records[path][1],
        }
        for path in policy.public_paths
        if path not in {REPORT_NAME, MANIFEST_NAME}
    ]
    projected_report_data = canonical_json_bytes(public_report)
    projected_members[REPORT_NAME] = projected_report_data
    projected_records[REPORT_NAME] = (
        hashlib.sha256(projected_report_data).hexdigest(),
        len(projected_report_data),
    )

    projected_manifest_data = "".join(
        f"{projected_records[path][0]}  {path}\n"
        for path in policy.public_paths
        if path != MANIFEST_NAME
    ).encode("utf-8")
    projected_members[MANIFEST_NAME] = projected_manifest_data
    projected_records[MANIFEST_NAME] = (
        hashlib.sha256(projected_manifest_data).hexdigest(),
        len(projected_manifest_data),
    )
    if tuple(sorted(projected_records)) != policy.public_paths:
        fail("public projection does not contain the exact canonical 70-file set")
    verify_v404_release_acceptance._validate_public_results_report(
        projected_report_data, projected_records, source
    )
    return PreparedResults(
        root=root,
        signed_by_path=signed_by_path,
        signed_manifest_data=signed_manifest_data,
        private_manifest_entries=private_manifest_entries,
        private_manifest_data=private_manifest_data,
        public_paths=policy.public_paths,
        projected_members=projected_members,
        projected_records=projected_records,
        policy_sha256=policy.policy_sha256,
        files=files,
        directories=directories,
    )


def assemble_verified_archive(
    prepared: PreparedResults, destination: Path | BinaryIO
) -> tuple[dict[str, tuple[str, int]], str, int]:
    observed: dict[str, tuple[str, int]] = {}
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=True,
    ) as archive:
        for relative in prepared.public_paths:
            if relative in prepared.projected_members:
                data = prepared.projected_members[relative]
                archive.writestr(
                    zip_info(f"{ARCHIVE_PREFIX}/{relative}"),
                    data,
                )
                observed[relative] = (
                    hashlib.sha256(data).hexdigest(),
                    len(data),
                )
            else:
                observed[relative] = add_verified_file(
                    archive,
                    prepared.root / Path(*PurePosixPath(relative).parts),
                    f"{ARCHIVE_PREFIX}/{relative}",
                    prepared.signed_by_path[relative]["sha256"],
                )
            if observed[relative] != prepared.projected_records[relative]:
                fail(f"public projection member differs from its prepared record: {relative}")
    if not isinstance(destination, (str, bytes, os.PathLike)):
        destination.flush()
        os.fsync(destination.fileno())
        destination.seek(0)
    files_after, directories_after = enumerate_plain_files(
        prepared.root, "private production-evidence root"
    )
    if files_after != prepared.files or directories_after != prepared.directories:
        fail("private production-evidence tree changed while it was packaged")
    if read_stable(
        prepared.root / MANIFEST_NAME,
        "private production manifest final recheck",
        maximum_bytes=2_000_000,
    ) != prepared.private_manifest_data:
        fail("private production manifest changed while it was packaged")
    if (
        verify_v404_release_acceptance._public_results_policy().policy_sha256
        != prepared.policy_sha256
    ):
        fail("public results boundary policy changed while packaging")

    expected_members = [
        f"{ARCHIVE_PREFIX}/{relative}" for relative in sorted(observed)
    ]
    with zipfile.ZipFile(destination, mode="r") as archive:
        names = archive.namelist()
        if names != expected_members or len(names) != len(set(names)):
            fail("results archive member set/order differs from the signed tree")
        if archive.testzip() is not None:
            fail("results archive CRC verification failed")
        for relative, (expected_digest, expected_size) in observed.items():
            digest = hashlib.sha256()
            size = 0
            with archive.open(f"{ARCHIVE_PREFIX}/{relative}", mode="r") as stream:
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
            if digest.hexdigest() != expected_digest or size != expected_size:
                fail(f"results archive member failed byte verification: {relative}")
    if isinstance(destination, (str, bytes, os.PathLike)):
        archive_sha256, archive_size = sha256_file(Path(destination))
    else:
        destination.flush()
        os.fsync(destination.fileno())
        destination.seek(0)
        before_fd = os.fstat(destination.fileno())
        digest = hashlib.sha256()
        archive_size = 0
        while True:
            block = destination.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            archive_size += len(block)
        after_fd = os.fstat(destination.fileno())
        if identity(before_fd) != identity(after_fd) or archive_size != after_fd.st_size:
            fail("results archive changed during its file-descriptor hash")
        archive_sha256 = digest.hexdigest()
        destination.seek(0)
    if not HASH_RE.fullmatch(archive_sha256) or archive_size <= 0:
        fail("results archive digest is invalid")
    return observed, archive_sha256, archive_size


def build(
    input_root: Path,
    output: Path,
    checksums: Path,
    *,
    repository_root: Path,
    signed_output_manifest: Path,
    verifiers: Any | None = None,
) -> dict[str, Any]:
    root = plain_root(input_root, "public production result root")
    release_root = plain_root(repository_root, "release repository root")
    destination = Path(os.path.abspath(output))
    checksum_destination = Path(os.path.abspath(checksums))
    if destination.name != verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME:
        fail("results archive output filename is not the canonical v4.0.4 name")
    if checksum_destination.name != verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME:
        fail("results checksum output filename is not the canonical v4.0.4 name")
    if paths_overlap(root, release_root):
        fail("public production result root must be outside the release workspace")
    if paths_overlap(Path(signed_output_manifest), root) or paths_overlap(
        Path(signed_output_manifest), release_root
    ):
        fail("signed strict output manifest must be outside output and workspace roots")
    if destination.exists() or destination.is_symlink():
        fail("results archive output already exists")
    if checksum_destination.exists() or checksum_destination.is_symlink():
        fail("results checksum output already exists")
    if Path(os.path.abspath(checksum_destination)) == Path(
        os.path.abspath(destination)
    ):
        fail("results archive and checksum outputs must be different paths")
    foundation = verify_v404_release_acceptance._verify_release_foundation(
        release_root, verifiers=verifiers
    )
    local_report = foundation["_local_report"]
    prepared = prepare_signed_results(
        root,
        Path(signed_output_manifest),
        local_report,
        foundation["computational_source"],
    )

    destination_parent = plain_root(destination.parent, "results archive output directory")
    checksum_parent = plain_root(
        checksum_destination.parent, "results checksum output directory"
    )
    if paths_overlap(destination_parent, root) or paths_overlap(destination_parent, release_root):
        fail("results archive output directory overlaps input or release workspace")
    if paths_overlap(checksum_parent, root) or paths_overlap(checksum_parent, release_root):
        fail("results checksum output directory overlaps input or release workspace")
    archive_directory = snapshot_output_directory(
        destination_parent, "results archive output directory"
    )
    checksum_directory = snapshot_output_directory(
        checksum_parent, "results checksum output directory"
    )
    archive_evidence: FileCommitEvidence | None = None
    checksum_evidence: FileCommitEvidence | None = None
    archive_handle: BinaryIO | None = None
    checksum_handle: BinaryIO | None = None
    try:
        temporary_path, archive_handle, archive_device_inode = create_bound_temporary_file(
            archive_directory, "results archive"
        )
        observed, measured_sha256, measured_size = assemble_verified_archive(
            prepared, archive_handle
        )
        archive_handle.close()
        archive_handle = None
        archive_evidence = snapshot_committable_file(
            temporary_path,
            archive_device_inode,
            measured_sha256,
            measured_size,
            archive_directory,
            "results archive",
        )

        (
            temporary_checksum_path,
            checksum_handle,
            checksum_device_inode,
        ) = create_bound_temporary_file(checksum_directory, "results checksum")
        checksum_data = f"{measured_sha256}  {destination.name}\n".encode("ascii")
        view = memoryview(checksum_data)
        while view:
            written = checksum_handle.write(view)
            if written is None or written <= 0:
                fail("cannot write results checksum temporary output")
            view = view[written:]
        checksum_handle.flush()
        os.fsync(checksum_handle.fileno())
        checksum_handle.close()
        checksum_handle = None
        checksum_evidence = snapshot_committable_file(
            temporary_checksum_path,
            checksum_device_inode,
            hashlib.sha256(checksum_data).hexdigest(),
            len(checksum_data),
            checksum_directory,
            "results checksum",
        )

        verified = verify_v404_release_acceptance.verify_release_acceptance(
            release_root,
            verifiers=verifiers,
            results_archive=archive_evidence.path,
            results_checksum=checksum_evidence.path,
        )
        locked_archive = verified["results_archive"]
        if (
            locked_archive["sha256"] != measured_sha256
            or locked_archive["size_bytes"] != measured_size
        ):
            fail("measured results archive differs from release acceptance")
        archive_evidence = snapshot_committable_file(
            archive_evidence.path,
            archive_evidence.device_inode,
            measured_sha256,
            measured_size,
            archive_directory,
            "results archive after acceptance",
        )
        checksum_evidence = snapshot_committable_file(
            checksum_evidence.path,
            checksum_evidence.device_inode,
            hashlib.sha256(checksum_data).hexdigest(),
            len(checksum_data),
            checksum_directory,
            "results checksum after acceptance",
        )
        promote_verified_file(
            archive_evidence, destination, archive_directory, "results archive"
        )
        promote_verified_file(
            checksum_evidence,
            checksum_destination,
            checksum_directory,
            "results checksum",
        )
        unlink_verified_temporary(archive_evidence)
        unlink_verified_temporary(checksum_evidence)

        final_verified = verify_v404_release_acceptance.verify_release_acceptance(
            release_root,
            verifiers=verifiers,
            results_archive=destination,
            results_checksum=checksum_destination,
        )
        if final_verified["acceptance_id"] != verified["acceptance_id"]:
            fail("final results assets changed their release acceptance identity")
    finally:
        if archive_handle is not None:
            archive_handle.close()
        if checksum_handle is not None:
            checksum_handle.close()
        if archive_evidence is not None:
            unlink_verified_temporary(archive_evidence)
        if checksum_evidence is not None:
            unlink_verified_temporary(checksum_evidence)

    archive_sha256, archive_size = sha256_file(destination)
    final_checksum_data = read_stable(
        checksum_destination, "final results checksum", maximum_bytes=1024
    )
    if (
        archive_sha256 != measured_sha256
        or archive_size != measured_size
        or final_checksum_data != checksum_data
        or archive_sha256 != verified["results_archive"]["sha256"]
        or archive_size != verified["results_archive"]["size_bytes"]
    ):
        fail("final results assets differ from measured and accepted bytes")
    return {
        "status": "PASS",
        "archive": destination.name,
        "sha256": archive_sha256,
        "size_bytes": archive_size,
        "file_count": len(observed),
        "source_manifest_sha256": hashlib.sha256(
            prepared.projected_members[MANIFEST_NAME]
        ).hexdigest(),
        "signed_output_manifest_sha256": hashlib.sha256(
            prepared.signed_manifest_data
        ).hexdigest(),
        "acceptance_id": verified["acceptance_id"],
    }


def measure_release_lock(
    input_root: Path,
    *,
    repository_root: Path,
    signed_output_manifest: Path,
    signed_local_report: Path,
    local_verifier: Any | None = None,
) -> dict[str, Any]:
    """Measure deterministic ZIP metadata without claiming release acceptance."""

    root = plain_root(input_root, "public production result root")
    release_root = plain_root(repository_root, "release repository root")
    if paths_overlap(root, release_root):
        fail("public production result root must be outside the release workspace")
    if paths_overlap(Path(signed_output_manifest), root) or paths_overlap(
        Path(signed_output_manifest), release_root
    ):
        fail("signed strict output manifest must be outside output and workspace roots")
    binding = verify_v404_release_acceptance.verify_local_report_contract_binding(
        release_root,
        signed_local_report,
        local_verifier=local_verifier,
    )
    prepared = prepare_signed_results(
        root,
        Path(signed_output_manifest),
        binding["report"],
        binding["source"],
    )
    with tempfile.TemporaryDirectory(prefix="v404-results-lock-measure-") as temporary:
        temporary_root = plain_root(Path(temporary), "temporary lock-measurement root")
        if paths_overlap(temporary_root, root) or paths_overlap(
            temporary_root, release_root
        ):
            fail("temporary lock-measurement root overlaps input or release workspace")
        archive_path = temporary_root / verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        observed, archive_sha256, archive_size = assemble_verified_archive(
            prepared, archive_path
        )
    return {
        "status": "MEASURED_CANDIDATE_NOT_RELEASE_ACCEPTED",
        "filename": verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME,
        "sha256_sidecar_filename": verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME,
        "sha256": archive_sha256,
        "size_bytes": archive_size,
        "source_manifest_sha256": hashlib.sha256(
            prepared.projected_members[MANIFEST_NAME]
        ).hexdigest(),
        "signed_output_manifest_sha256": hashlib.sha256(
            prepared.signed_manifest_data
        ).hexdigest(),
        "signed_local_report_sha256": binding["report_sha256"],
        "signed_local_candidate_id": binding["candidate_id"],
        "file_count": len(observed),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--input-root", required=True, type=Path)
        command.add_argument("--repository-root", required=True, type=Path)
        command.add_argument("--signed-output-manifest", required=True, type=Path)

    build_command = commands.add_parser(
        "build", help="build only when final release acceptance already locks the ZIP"
    )
    common(build_command)
    build_command.add_argument("--output", required=True, type=Path)
    build_command.add_argument("--checksums", required=True, type=Path)

    measure_command = commands.add_parser(
        "measure-lock", help="measure deterministic metadata for the pending acceptance"
    )
    common(measure_command)
    measure_command.add_argument("--signed-local-report", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "measure-lock":
        report = measure_release_lock(
            args.input_root,
            repository_root=args.repository_root,
            signed_output_manifest=args.signed_output_manifest,
            signed_local_report=args.signed_local_report,
        )
    else:
        report = build(
            args.input_root,
            args.output,
            args.checksums,
            repository_root=args.repository_root,
            signed_output_manifest=args.signed_output_manifest,
        )
    print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
