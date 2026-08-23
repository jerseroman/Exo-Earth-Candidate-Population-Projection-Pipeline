#!/usr/bin/env python3
"""Validate the external-input registry and verify downloaded input bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "provenance" / "DATA_LOCKS.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = {
    "filename",
    "source_url",
    "source_version",
    "expected_sha256",
    "expected_size_bytes",
    "distribution_role",
    "license",
    "citation",
    "requires_terms_acceptance",
}


def fail(message: str) -> None:
    raise SystemExit(f"DATA LOCK FAIL: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_registry() -> dict:
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {REGISTRY.relative_to(ROOT).as_posix()}: {exc}")
    if data.get("schema_version") != 1:
        fail("unsupported DATA_LOCKS schema_version")
    locks = data.get("locks")
    if not isinstance(locks, dict) or not locks:
        fail("DATA_LOCKS must contain a non-empty locks object")
    return data


def verify_file(lock_id: str, path: Path, locks: dict) -> None:
    if lock_id not in locks:
        fail(f"unknown lock id {lock_id!r}")
    record = locks[lock_id]
    if not path.is_file() or path.is_symlink():
        fail(f"missing or unsafe input for {lock_id}: {path}")
    size = path.stat().st_size
    if size != record["expected_size_bytes"]:
        fail(
            f"size mismatch for {lock_id}: expected "
            f"{record['expected_size_bytes']}, got {size}"
        )
    actual = sha256(path)
    if actual != record["expected_sha256"]:
        fail(
            f"SHA-256 mismatch for {lock_id}: expected "
            f"{record['expected_sha256']}, got {actual}"
        )
    print(f"PASS data lock {lock_id}: {actual} ({size} bytes)")


def verify_registry() -> dict:
    data = load_registry()
    locks = data["locks"]
    filenames: set[str] = set()
    for lock_id, record in locks.items():
        if not re.fullmatch(r"[a-z0-9_]+", lock_id):
            fail(f"invalid lock id {lock_id!r}")
        missing = REQUIRED_FIELDS - set(record)
        if missing:
            fail(f"{lock_id} lacks fields: {sorted(missing)}")
        if not SHA256_RE.fullmatch(record["expected_sha256"]):
            fail(f"invalid SHA-256 for {lock_id}")
        if not isinstance(record["expected_size_bytes"], int) or record["expected_size_bytes"] <= 0:
            fail(f"invalid byte size for {lock_id}")
        if record["distribution_role"] not in {"fetch-only", "bundled"}:
            fail(f"invalid distribution role for {lock_id}")
        if not record["filename"] or record["filename"] in filenames:
            fail(f"missing or duplicate filename for {lock_id}")
        filenames.add(record["filename"])
        if record["distribution_role"] == "fetch-only" and not (
            record["source_url"] or record.get("derived_from")
        ):
            fail(f"fetch-only lock lacks a URL or derived_from: {lock_id}")
        if record["requires_terms_acceptance"] and not record.get("terms_url"):
            fail(f"terms acknowledgement lacks terms_url: {lock_id}")
        repository_path = record.get("repository_path")
        if repository_path:
            verify_file(lock_id, ROOT / repository_path, locks)

    requirements = data.get("workflow_requirements")
    if not isinstance(requirements, dict) or not requirements:
        fail("DATA_LOCKS must define workflow_requirements")
    for relative, required_ids in requirements.items():
        path = ROOT / relative
        if not path.is_file():
            fail(f"workflow requirement names missing file: {relative}")
        text = path.read_text(encoding="utf-8")
        for lock_id in required_ids:
            if lock_id not in locks:
                fail(f"workflow requirement uses unknown lock id {lock_id}")
            if lock_id not in text:
                fail(f"workflow {relative} does not enforce lock {lock_id}")
        if not (
            "verify_locked_inputs.py" in text or "fetch_locked_inputs.py" in text
        ):
            fail(f"workflow {relative} does not invoke the lock tooling")
    print(
        f"PASS data-lock registry ({len(locks)} locks; "
        f"{len(requirements)} guarded workflows)"
    )
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        metavar="LOCK_ID=PATH",
        help="verify one local file; may be repeated",
    )
    args = parser.parse_args()
    data = verify_registry()
    for item in args.check:
        if "=" not in item:
            fail(f"invalid --check value {item!r}; expected LOCK_ID=PATH")
        lock_id, raw_path = item.split("=", 1)
        verify_file(lock_id, Path(raw_path), data["locks"])


if __name__ == "__main__":
    main()
