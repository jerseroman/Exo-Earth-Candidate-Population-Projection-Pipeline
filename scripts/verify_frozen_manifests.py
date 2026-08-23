#!/usr/bin/env python3
"""Verify every committed SHA-256 manifest for frozen audit products."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    manifests = sorted((ROOT / "research").rglob("SHA256SUMS*.txt"))
    if not manifests:
        raise SystemExit("No frozen manifests found")
    checked = 0
    for manifest in manifests:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            expected, name = line.split(maxsplit=1)
            target = (manifest.parent / name.strip().lstrip("*")).resolve()
            if not target.is_file():
                raise SystemExit(f"Missing manifest target: {target}")
            observed = sha256(target)
            if observed != expected:
                raise SystemExit(f"Checksum mismatch: {target}: {observed} != {expected}")
            checked += 1
    print(f"PASS frozen manifests ({len(manifests)} manifests, {checked} files)")


if __name__ == "__main__":
    main()
