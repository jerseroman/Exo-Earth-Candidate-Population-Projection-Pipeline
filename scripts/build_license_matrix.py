#!/usr/bin/env python3
"""Render the authoritative path-level licensing and redistribution matrix."""

from __future__ import annotations

import csv
import io
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "provenance" / "LICENSE_MATRIX.csv"
ROMAN_MIT_ALLOWLIST = ROOT / "provenance" / "ROMAN_MIT_PATHS.txt"

GPL_PATHS = {
    "research/bryson-joint-posterior/catalog_perturbation_audit.py",
    "research/bryson-joint-posterior/likelihood_grid_convergence.py",
    "research/bryson-joint-posterior/run_hab2_joint_posterior.py",
    "research/bryson-joint-posterior/measurement_error.py",
    "research/bryson-joint-posterior/test_measurement_error.py",
    "research/bryson-joint-posterior/test_run_hab2_provenance.py",
}
HUBER_TABLE = "research/jj-host-export/reference-data/tams_parsec_danxhuber.txt"
BLOCKED_DR25_PATHS = {
    "research/v4-validation/frozen-dr25-support/dr25_nominal_near_support.csv",
    "research/v4-validation/frozen-dr25-support/dr25_perturbed_candidate_frequency.csv",
    "research/v4-validation/frozen-dr25-support/SHA256SUMS_dr25_support.txt",
}
PRIVATE_ONLY_PATHS = {
    "PUBLICATION_CHECKLIST.md",
}
FILESYSTEM_EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "local-artifacts",
    "outputs",
    "results",
    "dist",
}

FIELDNAMES = (
    "path",
    "origin",
    "copyright_holder",
    "license",
    "redistribution_status",
    "included_in_public_package",
    "reason",
)


def roman_mit_paths() -> set[str]:
    if not ROMAN_MIT_ALLOWLIST.is_file():
        raise SystemExit("Missing provenance/ROMAN_MIT_PATHS.txt")
    paths = [
        line.strip()
        for line in ROMAN_MIT_ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise SystemExit("Roman MIT path allowlist must be sorted and unique")
    return set(paths)


@dataclass(frozen=True)
class LicenseRow:
    path: str
    origin: str
    copyright_holder: str
    license: str
    redistribution_status: str
    included_in_public_package: str
    reason: str


def repository_paths() -> list[str]:
    command = [
        "git",
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        paths = {
            item.decode("utf-8").replace("\\", "/")
            for item in result.stdout.split(b"\0")
            if item
        }
    else:
        # A public source ZIP intentionally has no Git history.  Its license
        # gate must still enumerate exactly the unpacked source files.
        paths = {
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and not FILESYSTEM_EXCLUDED_PARTS.intersection(
                path.relative_to(ROOT).parts
            )
            and path.suffix.lower() not in {".pyc", ".pyo"}
        }
    paths.add(MATRIX.relative_to(ROOT).as_posix())
    return sorted(paths)


def classify(path: str) -> LicenseRow:
    if path in PRIVATE_ONLY_PATHS:
        return LicenseRow(
            path,
            "Private production publication-control material by Roman Jerše",
            "Roman Jerše",
            "MIT",
            "CLEAR",
            "no",
            "Maintainer-only publication-control source; excluded from the public package.",
        )
    if path in GPL_PATHS:
        return LicenseRow(
            path,
            "Modified from stevepur/DR25-occurrence-public@d200f54b6f0df49e0dae530e69983cdce5397bfb",
            "Upstream copyright holders and Roman Jerše",
            "GPL-2.0-only",
            "CLEAR_WITH_NOTICE",
            "yes",
            "Derivative component; preserve GPL text, source identification, and modification notice.",
        )
    if path == HUBER_TABLE:
        return LicenseRow(
            path,
            "danxhuber/evolstate@5e904afad81805c4e3ac4c3f78510a2a1df33d14:tams_parsec.txt",
            "Daniel Huber",
            "MIT",
            "CLEAR_WITH_NOTICE",
            "yes",
            "Verbatim table; redistribute with Daniel Huber's MIT notice.",
        )
    if path in BLOCKED_DR25_PATHS:
        return LicenseRow(
            path,
            "Derived from row-level DR25 catalog material",
            "NOASSERTION",
            "NOASSERTION",
            "REVIEW/BLOCK",
            "no",
            "Conservatively excluded pending an explicit data-redistribution determination.",
        )
    if path == "LICENSES/GPL-2.0-only.txt":
        return LicenseRow(
            path,
            "Verbatim upstream GNU GPL version 2 license text",
            "Free Software Foundation, Inc.",
            "GPL-2.0-only",
            "CLEAR_WITH_NOTICE",
            "yes",
            "Required license text for the GPL-covered derivative component.",
        )
    if path == "LICENSES/MIT-Daniel-Huber-evolstate.txt":
        return LicenseRow(
            path,
            "danxhuber/evolstate@5e904afad81805c4e3ac4c3f78510a2a1df33d14",
            "Daniel Huber",
            "MIT",
            "CLEAR_WITH_NOTICE",
            "yes",
            "Required notice for the redistributed PARSEC-TAMS table.",
        )
    if path == "LICENSES/MIT-jjmodel.txt":
        return LicenseRow(
            path,
            "askenja/jjmodel@2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54",
            "Dr. Kseniia Sysoliatina",
            "MIT",
            "CLEAR_WITH_NOTICE",
            "yes",
            "Reference notice for the pinned fetch-only JJModel dependency.",
        )
    if path == "LICENSE":
        return LicenseRow(
            path,
            "Repository mixed-license notice by Roman Jerše",
            "Roman Jerše",
            "LicenseRef-Mixed-Repository-Notice",
            "CLEAR",
            "yes",
            "Explains that exact path rows, not a blanket license, govern the collection.",
        )
    if path in roman_mit_paths():
        return LicenseRow(
            path,
            "Original repository material by Roman Jerše",
            "Roman Jerše",
            "MIT",
            "CLEAR",
            "yes",
            "Author-declared original material; MIT grant recorded in the repository.",
        )
    return LicenseRow(
        path,
        "Unreviewed repository path",
        "NOASSERTION",
        "NOASSERTION",
        "REVIEW/BLOCK",
        "no",
        "Fail-closed default: an explicit audited origin and license decision is required.",
    )


def rows() -> list[LicenseRow]:
    return [classify(path) for path in repository_paths()]


def render() -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    for row in rows():
        writer.writerow(row.__dict__)
    return output.getvalue()


def main() -> None:
    MATRIX.parent.mkdir(parents=True, exist_ok=True)
    MATRIX.write_text(render(), encoding="utf-8", newline="\n")
    print(f"WROTE {MATRIX.relative_to(ROOT).as_posix()} ({len(rows())} paths)")


if __name__ == "__main__":
    main()
