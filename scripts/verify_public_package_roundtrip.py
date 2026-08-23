#!/usr/bin/env python3
"""Verify a public ZIP and reproduce it byte-for-byte without Git metadata."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    for info in archive.infolist():
        relative = PurePosixPath(info.filename)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"Unsafe public ZIP path: {info.filename}")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise SystemExit(f"Symlink is not allowed in public ZIP: {info.filename}")
    archive.extractall(destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    source = args.archive.resolve()
    if not source.is_file():
        raise SystemExit(f"Missing public ZIP: {source}")
    make = shutil.which("make")
    if not make:
        raise SystemExit("The round-trip gate requires make")

    original = sha256(source)
    with tempfile.TemporaryDirectory(prefix="exoearth-public-no-git-") as raw:
        root = Path(raw)
        with zipfile.ZipFile(source, "r") as archive:
            safe_extract(archive, root)
        if (root / ".git").exists():
            raise SystemExit("Public ZIP unexpectedly contains .git")
        subprocess.run([make, "verify"], cwd=root, check=True)
        subprocess.run([make, "public-package"], cwd=root, check=True)
        rebuilt = root / "dist" / source.name
        actual = sha256(rebuilt)
        if actual != original:
            raise SystemExit(
                f"Public ZIP round-trip mismatch: expected {original}, got {actual}"
            )
    print(f"PASS no-Git public ZIP round trip: {original}")


if __name__ == "__main__":
    main()
