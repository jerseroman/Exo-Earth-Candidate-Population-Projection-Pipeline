#!/usr/bin/env python3
"""Fail closed when licensing, provenance, or public-package rules drift."""

from __future__ import annotations

import csv
import hashlib
import io
import re
from pathlib import Path

import build_license_matrix

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "provenance" / "LICENSE_MATRIX.csv"
EXCLUSIONS = ROOT / "provenance" / "PUBLIC_EXCLUSIONS.csv"
PRIVATE_GUARDS = {
    ".github/workflows/bryson-v4-corrected-pilot.yml": {
        "prepare-inputs",
        "pilot",
        "seed-stability",
    },
    ".github/workflows/bryson-v4-corrected-production.yml": {
        "prepare-inputs",
        "prepare-hosts",
        "reconstruct-shards",
        "aggregate",
        "propagate",
    },
    ".github/workflows/bryson-v4-corrected-zero-extended.yml": {
        "prepare-inputs",
        "prepare-hosts",
        "reconstruct-shards",
        "aggregate",
        "propagate",
    },
    ".github/workflows/bryson-v4-propagate-constant.yml": {"propagate"},
    ".github/workflows/jj-g-host-export.yml": {"jj-export"},
    ".github/workflows/jj-tams-metallicity-differential.yml": {"audit"},
    ".github/workflows/jj-tams-radial-convergence.yml": {"convergence"},
}
PINNED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
}
EXPECTED_HASHES = {
    "LICENSES/GPL-2.0-only.txt": "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643",
    "research/jj-host-export/reference-data/tams_parsec_danxhuber.txt": (
        "d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac"
    ),
}
EXPECTED_NOTICE_HASHES = {
    "LICENSES/MIT-Daniel-Huber-evolstate.txt": (
        "9e346db54943ac4138e419ff8c84d8262fa4530e774b33a268717941eabc3a54"
    ),
    "LICENSES/MIT-jjmodel.txt": (
        "88f80f50574c7476168ef3cb597d95b584c8833e3a22d8a1bd6565cac21ab006"
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"LICENSE GATE FAIL: {message}")


def matrix_rows() -> list[dict[str, str]]:
    if not MATRIX.is_file():
        fail("missing provenance/LICENSE_MATRIX.csv")
    committed = MATRIX.read_text(encoding="utf-8")
    expected = build_license_matrix.render()
    if committed != expected:
        fail("license matrix drift; run scripts/build_license_matrix.py after an audited change")
    return list(csv.DictReader(io.StringIO(committed)))


def job_block(text: str, job: str) -> str:
    lines = text.splitlines()
    marker = f"  {job}:"
    try:
        start = lines.index(marker)
    except ValueError:
        fail(f"missing workflow job {job!r}")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            end = index
            break
    return "\n".join(lines[start:end])


def verify() -> list[dict[str, str]]:
    unknown_probe = build_license_matrix.classify("__unreviewed__/third-party.bin")
    if (
        unknown_probe.redistribution_status != "REVIEW/BLOCK"
        or unknown_probe.included_in_public_package != "no"
        or unknown_probe.license != "NOASSERTION"
    ):
        fail("unknown-path classification is not fail-closed")
    rows = matrix_rows()
    paths = [row["path"] for row in rows]
    if len(paths) != len(set(paths)):
        fail("duplicate path in license matrix")
    missing_allowlisted = build_license_matrix.roman_mit_paths().difference(paths)
    if missing_allowlisted:
        fail(f"Roman MIT allowlist contains missing paths: {sorted(missing_allowlisted)}")
    allowed_statuses = {"CLEAR", "CLEAR_WITH_NOTICE", "REVIEW/BLOCK"}
    for row in rows:
        if row["redistribution_status"] not in allowed_statuses:
            fail(f"invalid redistribution status for {row['path']}")
        public = row["included_in_public_package"]
        if public not in {"yes", "no"}:
            fail(f"invalid public-package flag for {row['path']}")
        if public == "yes" and row["redistribution_status"] not in {
            "CLEAR",
            "CLEAR_WITH_NOTICE",
        }:
            fail(f"blocked path marked public: {row['path']}")
        if not row["license"] or not row["origin"] or not row["copyright_holder"]:
            fail(f"incomplete license row: {row['path']}")

    for relative, expected in EXPECTED_HASHES.items():
        actual = sha256(ROOT / relative)
        if actual != expected:
            fail(f"unexpected SHA-256 for {relative}: {actual}")
    for relative, expected in EXPECTED_NOTICE_HASHES.items():
        actual = sha256(ROOT / relative)
        if actual != expected:
            fail(f"upstream notice text drift for {relative}: {actual}")

    for relative in build_license_matrix.GPL_PATHS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if "SPDX-License-Identifier: GPL-2.0-only" not in text:
            fail(f"missing GPL SPDX identifier: {relative}")
        if "MODIFICATIONS_BRYSON.md" not in text:
            fail(f"missing Bryson modification pointer: {relative}")

    for workflow, jobs in PRIVATE_GUARDS.items():
        text = (ROOT / workflow).read_text(encoding="utf-8")
        for job in jobs:
            block = job_block(text, job)
            guard = "if: ${{ github.event.repository.private == true }}"
            if guard not in block:
                fail(f"private-only guard missing from {workflow}:{job}")

    observed_actions: set[str] = set()
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for action, ref in re.findall(
            r"uses:\s+(actions/[^@\s]+)@([^\s#]+)", text
        ):
            observed_actions.add(action)
            expected = PINNED_ACTIONS.get(action)
            if expected is None:
                fail(f"unreviewed GitHub Action in {workflow.name}: {action}")
            if ref != expected:
                fail(
                    f"GitHub Action is not pinned to its audited SHA in "
                    f"{workflow.name}: {action}@{ref}"
                )
    if observed_actions != set(PINNED_ACTIONS):
        fail(
            "GitHub Action pin set changed: "
            f"observed={sorted(observed_actions)}"
        )

    for path in sorted((ROOT / "research").rglob("*.py")):
        if path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"(?m)^\s*assert\s+", text):
            fail(
                "production validation must use explicit exceptions, not "
                f"optimization-removable assert statements: {path.relative_to(ROOT)}"
            )

    root_license = (ROOT / "LICENSE").read_text(encoding="utf-8").lower()
    if "mixed-license" not in root_license:
        fail("root LICENSE does not state the mixed-license boundary")
    for relative in ("LICENSE", "LICENSE_POLICY.md", "CITATION.cff", "pyproject.toml"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if "AGPL-3.0" in text:
            fail(f"obsolete blanket AGPL claim remains in {relative}")
    cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if re.search(r"(?m)^license:\s*", cff):
        fail("CITATION.cff must not express mixed component licenses as alternatives")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if 'license = {file = "LICENSE"}' not in project:
        fail("pyproject.toml must point to the mixed-license notice")

    required_notice_tokens = (
        "d200f54b6f0df49e0dae530e69983cdce5397bfb",
        "5e904afad81805c4e3ac4c3f78510a2a1df33d14",
        "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54",
    )
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for token in required_notice_tokens:
        if token not in notices:
            fail(f"third-party notice missing pinned source {token}")

    blocked = {
        row["path"]
        for row in rows
        if row["redistribution_status"] == "REVIEW/BLOCK"
    }
    present_paths = set(paths)
    expected_blocked = build_license_matrix.BLOCKED_DR25_PATHS & present_paths
    if blocked != expected_blocked:
        fail("the conservative DR25 matrix exclusion set changed")
    exclusion_rows = list(csv.DictReader(io.StringIO(EXCLUSIONS.read_text(encoding="utf-8"))))
    recorded_exclusions = {row["path"] for row in exclusion_rows}
    if recorded_exclusions != build_license_matrix.BLOCKED_DR25_PATHS:
        fail("provenance/PUBLIC_EXCLUSIONS.csv does not record the full exclusion set")
    if any(row["status"] != "REVIEW/BLOCK" or not row["reason"] for row in exclusion_rows):
        fail("incomplete public-exclusion record")

    row_by_path = {row["path"]: row for row in rows}
    for relative in build_license_matrix.PRIVATE_ONLY_PATHS:
        if relative in row_by_path and row_by_path[relative]["included_in_public_package"] != "no":
            fail(f"private-only publication path entered public package: {relative}")
    public_readme_path = ROOT / "provenance" / "PUBLIC_README.md"
    if not public_readme_path.is_file():
        public_readme_path = ROOT / "README.md"
    public_readme = public_readme_path.read_text(encoding="utf-8")
    normalized_public_readme = " ".join(public_readme.split())
    required_public_readme = (
        "license-cleared public software and reproducibility source tree",
        (
            "This works in an ordinary directory unpacked from the public ZIP; "
            "no `.git` directory or Git initialization is required."
        ),
        "Full numerical production",
        "provenance/DATA_LOCKS.json",
    )
    for token in required_public_readme:
        if token not in normalized_public_readme:
            fail(f"public README lacks required boundary text: {token}")
    for forbidden in (
        "This private development repository",
        "this repository must not be made public",
    ):
        if forbidden.lower() in public_readme.lower():
            fail(f"public README retains private-only wording: {forbidden}")
    print(
        f"PASS license gate ({len(rows)} paths; "
        f"{sum(row['included_in_public_package'] == 'yes' for row in rows)} public; "
        f"{len(blocked)} present-and-blocked; {len(recorded_exclusions)} recorded exclusions)"
    )
    return rows


def main() -> None:
    verify()


if __name__ == "__main__":
    main()
