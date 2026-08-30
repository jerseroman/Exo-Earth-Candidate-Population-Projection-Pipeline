#!/usr/bin/env python3
"""Build and verify a deterministic license-cleared public source archive."""

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
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from types import ModuleType
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
# Versioned reproducibility timestamp, not the wall-clock build time. Keeping
# every ZIP member at the release date makes independent builds byte-identical.
SOURCE_DATE_UTC = (2026, 8, 30, 0, 0, 0)
REQUIRED_RELEASE_GATE_PATHS = {
    "provenance/V4_0_4_RELEASE_ACCEPTANCE.json",
    "scripts/verify_v404_release_acceptance.py",
}
REPARSE_POINT = 0x400


def _bootstrap_source_module(path: Path, module_name: str) -> ModuleType:
    """Load one bootstrap module from an exact stable ``.py`` snapshot."""

    candidate = Path(path)
    if candidate.suffix != ".py":
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: bytecode modules are forbidden")
    try:
        before = candidate.lstat()
    except OSError as error:
        raise SystemExit(f"Cannot inspect bootstrap source {candidate}: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_file_attributes", 0) & REPARSE_POINT)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: bootstrap source is not plain")
    identity_before = (
        int(before.st_dev), int(before.st_ino), int(before.st_size),
        int(before.st_mtime_ns), int(before.st_ctime_ns),
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after_fd = os.fstat(descriptor)
    except OSError as error:
        raise SystemExit(f"Cannot read bootstrap source {candidate}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = candidate.lstat()
    data = b"".join(blocks)
    identities = {
        identity_before,
        (
            int(opened.st_dev), int(opened.st_ino), int(opened.st_size),
            int(opened.st_mtime_ns), int(opened.st_ctime_ns),
        ),
        (
            int(after_fd.st_dev), int(after_fd.st_ino), int(after_fd.st_size),
            int(after_fd.st_mtime_ns), int(after_fd.st_ctime_ns),
        ),
        (
            int(after.st_dev), int(after.st_ino), int(after.st_size),
            int(after.st_mtime_ns), int(after.st_ctime_ns),
        ),
    }
    if len(identities) != 1 or len(data) != opened.st_size:
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: bootstrap source changed")
    try:
        code = compile(
            data, str(candidate), "exec", flags=0, dont_inherit=True, optimize=-1
        )
    except (SyntaxError, TypeError, ValueError) as error:
        raise SystemExit(f"Cannot compile bootstrap source {candidate}: {error}")
    module = ModuleType(module_name)
    module.__file__ = str(candidate)
    module.__package__ = ""
    module.__cached__ = None
    module.__loader__ = None
    module.__spec__ = None
    module.__dict__["__source_only_sha256__"] = hashlib.sha256(data).hexdigest()
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
    if module.__dict__.get("__cached__") is not None:
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: bytecode binding was enabled")
    return module


verify_v404_release_acceptance = _bootstrap_source_module(
    ROOT / "scripts" / "verify_v404_release_acceptance.py",
    "verify_v404_release_acceptance",
)
verify_v404_release_acceptance.load_source_only_module(
    ROOT,
    "scripts/build_license_matrix.py",
    "build_license_matrix",
    "license-matrix builder",
)
verify_license_policy = verify_v404_release_acceptance.load_source_only_module(
    ROOT,
    "scripts/verify_license_policy.py",
    "verify_license_policy",
    "license policy verifier",
)


@dataclass(frozen=True)
class SourceSnapshot:
    path: Path
    identity: tuple[int, int, int, int, int]
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class DirectorySnapshot:
    path: Path
    chain: tuple[tuple[Path, tuple[int, int, int, int, int]], ...]


@dataclass(frozen=True)
class OutputSnapshot:
    path: Path
    identity: tuple[int, int, int, int, int]
    sha256: str
    size_bytes: int


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & REPARSE_POINT
    )


def snapshot_plain_directory(path: Path, label: str) -> DirectorySnapshot:
    candidate = Path(os.path.abspath(path))
    paths = [candidate]
    while paths[-1] != paths[-1].parent:
        paths.append(paths[-1].parent)
    chain: list[tuple[Path, tuple[int, int, int, int, int]]] = []
    for current in reversed(paths):
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SystemExit(f"Cannot inspect {label} ancestor {current}: {error}")
        if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"{label} ancestor is not a plain directory: {current}")
        chain.append((current, file_identity(metadata)))
    return DirectorySnapshot(candidate, tuple(chain))


def recheck_directory(snapshot: DirectorySnapshot, label: str) -> None:
    for path, expected in snapshot.chain:
        try:
            current = path.lstat()
        except OSError as error:
            raise SystemExit(f"Cannot recheck {label} ancestor {path}: {error}")
        if (
            is_link_or_reparse(current)
            or not stat.S_ISDIR(current.st_mode)
            or file_identity(current)[:2] != expected[:2]
        ):
            raise SystemExit(f"{label} ancestor changed: {path}")


def ensure_output_directory(path: Path, label: str) -> DirectorySnapshot:
    candidate = Path(os.path.abspath(path))
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        parent = snapshot_plain_directory(candidate.parent, f"{label} parent")
        try:
            os.mkdir(candidate, 0o755)
        except OSError as error:
            raise SystemExit(f"Cannot create {label}: {error}")
        recheck_directory(parent, f"{label} parent")
    except OSError as error:
        raise SystemExit(f"Cannot inspect {label}: {error}")
    else:
        if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"{label} must be a plain directory")
    return snapshot_plain_directory(candidate, label)


def _read_bound_output(
    snapshot: OutputSnapshot, directory: DirectorySnapshot, label: str
) -> bytes:
    recheck_directory(directory, f"{label} directory")
    try:
        before = snapshot.path.lstat()
    except OSError as error:
        raise SystemExit(f"Cannot inspect final {label}: {error}")
    if is_link_or_reparse(before) or file_identity(before) != snapshot.identity:
        raise SystemExit(f"Final {label} identity changed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(snapshot.path, flags)
    try:
        opened = os.fstat(descriptor)
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(blocks)
    after = snapshot.path.lstat()
    if (
        file_identity(opened) != snapshot.identity
        or file_identity(after_fd) != snapshot.identity
        or file_identity(after) != snapshot.identity
        or is_link_or_reparse(after)
        or len(data) != snapshot.size_bytes
        or hashlib.sha256(data).hexdigest() != snapshot.sha256
    ):
        raise SystemExit(f"Final {label} bytes/identity changed")
    recheck_directory(directory, f"{label} directory")
    return data


def write_new_bound_file(
    directory: DirectorySnapshot,
    leaf: str,
    data: bytes,
    label: str,
) -> OutputSnapshot:
    if Path(leaf).name != leaf or leaf in {"", ".", ".."}:
        raise SystemExit(f"Unsafe {label} output filename")
    destination = directory.path / leaf
    recheck_directory(directory, f"{label} output directory")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise SystemExit(f"Cannot inspect {label} output: {error}")
    else:
        raise SystemExit(f"Refusing to replace existing {label}: {destination}")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = -1
    descriptor = -1
    try:
        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            directory_descriptor = os.open(directory.path, directory_flags)
            if file_identity(os.fstat(directory_descriptor)) != directory.chain[-1][1]:
                raise SystemExit(f"{label} output directory changed while opened")
            descriptor = os.open(
                leaf, flags, 0o644, dir_fd=directory_descriptor
            )
        else:
            # Windows has no Python dir_fd write API; O_EXCL prevents link or
            # victim replacement and the complete ancestor chain is rechecked.
            descriptor = os.open(destination, flags, 0o644)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SystemExit(f"{label} output is not a regular file")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SystemExit(f"Cannot write {label} output")
            view = view[written:]
        os.fsync(descriptor)
        after_fd = os.fstat(descriptor)
    except FileExistsError as error:
        raise SystemExit(f"Refusing to replace existing {label}: {destination}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
    observed_identity = file_identity(opened)
    if observed_identity[:2] != file_identity(after_fd)[:2] or after_fd.st_size != len(data):
        raise SystemExit(f"{label} output changed while written")
    observed_identity = file_identity(after_fd)
    snapshot = OutputSnapshot(
        path=destination,
        identity=observed_identity,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
    if _read_bound_output(snapshot, directory, label) != data:
        raise SystemExit(f"Final {label} differs from the verified bytes")
    return snapshot


def stable_source_read(relative: PurePosixPath) -> tuple[bytes, SourceSnapshot]:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit(f"Unsafe public path: {relative.as_posix()}")
    current = ROOT.resolve(strict=True)
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SystemExit(f"Cannot inspect public path {relative.as_posix()}: {error}")
        if is_link_or_reparse(metadata):
            raise SystemExit(f"Public path contains a link or reparse point: {relative.as_posix()}")
        last = index == len(relative.parts) - 1
        if not last and not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Public path has a non-directory parent: {relative.as_posix()}")
        if last and not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"Public path is not a regular file: {relative.as_posix()}")
    before = current.lstat()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(current, flags)
        opened = os.fstat(descriptor)
        if file_identity(opened) != file_identity(before):
            raise SystemExit(f"Public path changed while opened: {relative.as_posix()}")
        blocks = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after_fd = os.fstat(descriptor)
    except OSError as error:
        raise SystemExit(f"Cannot read public path {relative.as_posix()}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = current.lstat()
    identity = file_identity(opened)
    data = b"".join(blocks)
    if (
        identity != file_identity(after_fd)
        or identity != file_identity(after)
        or is_link_or_reparse(after)
        or len(data) != opened.st_size
    ):
        raise SystemExit(f"Public path changed while read: {relative.as_posix()}")
    return data, SourceSnapshot(
        current,
        identity,
        hashlib.sha256(data).hexdigest(),
        len(data),
    )


def recheck_sources(snapshots: list[SourceSnapshot]) -> None:
    for snapshot in snapshots:
        try:
            before = snapshot.path.lstat()
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(snapshot.path, flags)
            try:
                opened = os.fstat(descriptor)
                blocks: list[bytes] = []
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    blocks.append(block)
                after_fd = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after = snapshot.path.lstat()
        except OSError as error:
            raise SystemExit(f"Cannot recheck public source {snapshot.path}: {error}")
        data = b"".join(blocks)
        if (
            is_link_or_reparse(before)
            or is_link_or_reparse(after)
            or file_identity(before) != snapshot.identity
            or file_identity(opened) != snapshot.identity
            or file_identity(after_fd) != snapshot.identity
            or file_identity(after) != snapshot.identity
            or len(data) != snapshot.size_bytes
            or hashlib.sha256(data).hexdigest() != snapshot.sha256
        ):
            raise SystemExit(f"Public source changed after capture: {snapshot.path}")


def run_full_verification() -> None:
    make = shutil.which("make")
    if make is None:
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: make is required for make verify")
    try:
        completed = subprocess.run(
            [make, "verify"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except OSError as error:
        raise SystemExit(f"PUBLIC PACKAGE GATE FAIL: cannot run make verify: {error}")
    if completed.returncode != 0:
        raise SystemExit("PUBLIC PACKAGE GATE FAIL: make verify did not pass")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def project_version() -> str:
    data, _snapshot = stable_source_read(PurePosixPath("pyproject.toml"))
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SystemExit(f"Cannot decode project version metadata: {error}")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    if not match:
        raise SystemExit("Cannot determine project version")
    return match.group(1)


def validate_project_version(version: str) -> None:
    if version != verify_v404_release_acceptance.RELEASE_VERSION:
        raise SystemExit(
            "PUBLIC PACKAGE RELEASE GATE FAIL: project version differs from v4.0.4"
        )


def render_filtered_matrix(rows: list[dict[str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=verify_license_policy.build_license_matrix.FIELDNAMES,
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        if row["included_in_public_package"] == "yes":
            writer.writerow(row)
    return output.getvalue().encode("utf-8")


def public_sources(
    rows: list[dict[str, str]],
) -> tuple[list[tuple[dict[str, str], bytes]], list[SourceSnapshot]]:
    selected: list[tuple[dict[str, str], bytes]] = []
    snapshots: list[SourceSnapshot] = []
    filtered_matrix = render_filtered_matrix(rows)
    for row in rows:
        if row["included_in_public_package"] != "yes":
            continue
        relative = PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"Unsafe public path: {row['path']}")
        source_data, snapshot = stable_source_read(relative)
        snapshots.append(snapshot)
        if row["path"] == "provenance/LICENSE_MATRIX.csv":
            data = filtered_matrix
        elif row["path"] == "MANIFEST.sha256":
            data = b""
        else:
            data = source_data
        selected.append((row, data))
    selected.sort(key=lambda item: item[0]["path"])
    manifest = "".join(
        f"{sha256_bytes(data)}  {row['path']}\n"
        for row, data in selected
        if row["path"] != "MANIFEST.sha256"
    ).encode("utf-8")
    return (
        [
            (row, manifest if row["path"] == "MANIFEST.sha256" else data)
            for row, data in selected
        ],
        snapshots,
    )


def build_zip(files: list[tuple[dict[str, str], bytes]]) -> bytes:
    archive_files = [(row["path"], data) for row, data in files]

    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        "w",
        compression=zipfile.ZIP_STORED,
        strict_timestamps=True,
    ) as archive:
        for name, data in archive_files:
            info = zipfile.ZipInfo(name, date_time=SOURCE_DATE_UTC)
            # Stored members avoid zlib-version/platform drift at the release
            # boundary; content hashes, not compression ratios, are normative.
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def verify_zip(
    archive_bytes: bytes,
    files: list[tuple[dict[str, str], bytes]],
) -> None:
    expected = {row["path"]: data for row, data in files}
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        names = archive.namelist()
        if names != sorted(expected):
            raise SystemExit("Public ZIP inventory/order mismatch")
        if len(names) != len(set(names)):
            raise SystemExit("Duplicate path in public ZIP")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise SystemExit(f"Unsafe ZIP member: {name}")
            if archive.read(name) != expected[name]:
                raise SystemExit(f"ZIP byte mismatch: {name}")
            if archive.getinfo(name).compress_type != zipfile.ZIP_STORED:
                raise SystemExit(f"ZIP compression policy mismatch: {name}")


def inventory_csv(
    files: list[tuple[dict[str, str], bytes]],
) -> str:
    output = io.StringIO(newline="")
    fields = ("path", "sha256", "license", "origin")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row, data in files:
        writer.writerow(
            {
                "path": row["path"],
                "sha256": sha256_bytes(data),
                "license": row["license"],
                "origin": row["origin"],
            }
        )
    return output.getvalue()


def measure_public_release_locks() -> dict[str, object]:
    """Measure no-Git manifest locks before the self-referential final commit."""

    rows = verify_license_policy.verify()
    files, snapshots = public_sources(rows)
    by_path = {row["path"]: data for row, data in files}
    acceptance_data = by_path.get(
        verify_v404_release_acceptance.ACCEPTANCE_PATH
    )
    if acceptance_data is None:
        raise SystemExit("Public package omits its release acceptance document")
    acceptance = verify_v404_release_acceptance.load_json_bytes(
        acceptance_data, "pending release acceptance"
    )
    entries = {
        relative: sha256_bytes(data)
        for relative, data in by_path.items()
        if relative != "MANIFEST.sha256"
    }
    payload_sha256 = hashlib.sha256(
        verify_v404_release_acceptance._payload_manifest_bytes(entries)
    ).hexdigest()
    projection_sha256 = (
        verify_v404_release_acceptance.compute_computational_projection_sha256(
            entries, acceptance
        )
    )
    recheck_sources(snapshots)
    return {
        "status": "MEASURED_PUBLIC_NO_GIT_LOCKS_NOT_RELEASE_ACCEPTED",
        "public_payload_manifest_sha256": payload_sha256,
        "public_computational_projection_manifest_sha256": projection_sha256,
        "public_file_count_excluding_manifest": len(entries),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measure-public-release-locks", action="store_true")
    args = parser.parse_args([] if argv is None else argv)
    if args.measure_public_release_locks:
        print(json.dumps(measure_public_release_locks(), indent=2, sort_keys=True))
        return
    run_full_verification()
    try:
        verify_v404_release_acceptance.verify_release_acceptance(ROOT)
    except verify_v404_release_acceptance.ReleaseAcceptanceError as error:
        raise SystemExit(f"PUBLIC PACKAGE RELEASE GATE FAIL: {error}") from error
    version = project_version()
    validate_project_version(version)
    rows = verify_license_policy.verify()
    files, source_snapshots = public_sources(rows)
    public_paths = {row["path"] for row, _data in files}
    missing_release_paths = REQUIRED_RELEASE_GATE_PATHS.difference(public_paths)
    if missing_release_paths:
        raise SystemExit(
            "Public package omits its release acceptance evidence/verifier: "
            f"{sorted(missing_release_paths)}"
        )
    first = build_zip(files)
    second = build_zip(files)
    if first != second:
        raise SystemExit("Deterministic rebuild mismatch")
    verify_zip(first, files)
    recheck_sources(source_snapshots)
    try:
        verify_v404_release_acceptance.verify_release_acceptance(ROOT)
    except verify_v404_release_acceptance.ReleaseAcceptanceError as error:
        raise SystemExit(f"PUBLIC PACKAGE FINAL RELEASE GATE FAIL: {error}") from error
    recheck_sources(source_snapshots)

    output_directory = ensure_output_directory(DIST, "public package output directory")
    archive_name = (
        "exo-earth-candidate-population-projection-pipeline-"
        f"{version}-source.zip"
    )
    inventory = inventory_csv(files)
    digest = sha256_bytes(first)
    archive_output = write_new_bound_file(
        output_directory, archive_name, first, "public source ZIP"
    )
    inventory_output = write_new_bound_file(
        output_directory,
        "PUBLIC_RELEASE_FILE_INVENTORY.csv",
        inventory.encode("utf-8"),
        "public release inventory",
    )
    checksum_data = f"{digest}  {archive_name}\n".encode("ascii")
    checksum_output = write_new_bound_file(
        output_directory,
        "PUBLIC_SHA256SUMS",
        checksum_data,
        "public source checksum",
    )
    if _read_bound_output(archive_output, output_directory, "public source ZIP") != first:
        raise SystemExit("Final public source ZIP changed after commit")
    if _read_bound_output(
        inventory_output, output_directory, "public release inventory"
    ) != inventory.encode("utf-8"):
        raise SystemExit("Final public release inventory changed after commit")
    if _read_bound_output(
        checksum_output, output_directory, "public source checksum"
    ) != checksum_data:
        raise SystemExit("Final public source checksum changed after commit")
    print(
        f"PASS deterministic public package: {archive_name} "
        f"({len(files)} files, sha256={digest})"
    )


if __name__ == "__main__":
    main(sys.argv[1:])
