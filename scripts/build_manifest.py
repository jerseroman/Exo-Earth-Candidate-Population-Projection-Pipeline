#!/usr/bin/env python3
"""Write or verify the deterministic repository-level SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
SKIP_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "local-artifacts",
    "outputs",
    "results",
    "dist",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entries() -> list[str]:
    rows: list[str] = []
    # Path ordering follows host-platform semantics on Windows versus Linux.
    # Sort explicit POSIX relative paths so the committed manifest is identical
    # on developer machines and GitHub Actions runners.
    paths = sorted(ROOT.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix())
    for path in paths:
        if not path.is_file() or path == MANIFEST:
            continue
        relative = path.relative_to(ROOT)
        if SKIP_PARTS.intersection(relative.parts):
            continue
        rows.append(f"{sha256(path)}  {relative.as_posix()}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = "\n".join(entries()) + "\n"
    if args.write:
        MANIFEST.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"WROTE {MANIFEST.name} ({len(entries())} files)")
        return
    if not MANIFEST.is_file():
        raise SystemExit(f"Missing {MANIFEST}")
    if MANIFEST.read_text(encoding="utf-8") != rendered:
        raise SystemExit("Repository manifest mismatch; run with --write after an audited change")
    print(f"PASS repository manifest ({len(entries())} files)")


if __name__ == "__main__":
    main()
