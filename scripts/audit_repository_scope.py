#!/usr/bin/env python3
"""Fail if unrelated project branding or publication artifacts enter the repository."""

from __future__ import annotations

import base64
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TEXT = tuple(
    base64.b64decode(encoded).decode("ascii")
    for encoded in (
        "YXJlLXdlLWFsb25lLWluLXRoZS11bml2ZXJzZQ==",
        "YXJld2VhbG9uZWludGhldW5pdmVyc2U=",
        "MTAuNTI4MS96ZW5vZG8uMjA0NzQ1Mjc=",
        "Y2FsY3VsYXRvcg==",
        "Rm9pc29yIENsaW5pY2FsIEhvc3BpdGFs",
    )
)
FORBIDDEN_SUFFIXES = {".tex", ".pdf"}
HISTORICAL_REPOSITORY_EVIDENCE_PATHS = {
    "provenance/EXTRACTION_AUDIT.json",
    "provenance/MIGRATION_RECORD.json",
    "provenance/RUN_PROVENANCE.json",
    "research/v4-validation/PHASE4_SENSITIVITY_FREEZE_REPORT.md",
    "research/v4-validation/audit_v4_statistical_baseline.py",
    "research/v4-validation/frozen-sensitivities/V4_SENSITIVITY_FREEZE.json",
    "research/v4-validation/frozen-statistical-baseline/V4_STATISTICAL_BASELINE_AUDIT.json",
    "research/v4-validation/frozen-statistical-baseline/V4_STATISTICAL_BASELINE_AUDIT.md",
    "research/v4-validation/sensitivity_freeze.py",
    "research/v4-validation/test_sensitivity_freeze.py",
    "research/v4-validation/test_v4_statistical_baseline.py",
    "research/v4-validation/v4_statistical_baseline_github_evidence.json",
    "scripts/verify_release_metadata.py",
}
PROVENANCE_REFERENCE_EXCEPTIONS = {
    path: {FORBIDDEN_TEXT[0]} for path in HISTORICAL_REPOSITORY_EVIDENCE_PATHS
}
FORBIDDEN_ROW_IDENTIFIER_PATTERNS = (
    re.compile(r"\bK\d{5}\.\d{2}\b", re.IGNORECASE),
)
FORBIDDEN_UNICODE_DASHES = {chr(code) for code in (*range(0x2010, 0x2016), 0x2212)}
SKIP_PARTS = {
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


def repository_files() -> list[Path]:
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not SKIP_PARTS.intersection(path.relative_to(ROOT).parts)
    ]


def main() -> None:
    failures: list[str] = []
    for path in repository_files():
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden publication artifact: {relative}")
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace").lower()
        if any(character in text for character in FORBIDDEN_UNICODE_DASHES):
            failures.append(f"forbidden Unicode dash character: {relative}")
        for token in FORBIDDEN_TEXT:
            allowed = PROVENANCE_REFERENCE_EXCEPTIONS.get(relative, set())
            if token.lower() in text and token.lower() not in allowed:
                failures.append(f"forbidden project reference {token!r}: {relative}")
        for pattern in FORBIDDEN_ROW_IDENTIFIER_PATTERNS:
            if pattern.search(text):
                failures.append(
                    f"forbidden row-level catalog identifier {pattern.pattern!r}: {relative}"
                )
    if failures:
        raise SystemExit("\n".join(sorted(set(failures))))
    print(f"PASS software-only scope audit ({len(repository_files())} files)")


if __name__ == "__main__":
    main()
