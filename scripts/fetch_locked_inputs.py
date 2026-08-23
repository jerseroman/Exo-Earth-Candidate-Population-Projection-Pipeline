#!/usr/bin/env python3
"""Fetch externally hosted scientific inputs and fail closed on hash drift."""

from __future__ import annotations

import argparse
import os
import urllib.request
from pathlib import Path

import verify_locked_inputs


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "local-artifacts" / "locked-inputs"


def fetch(lock_id: str, destination: Path, accepted: set[str], locks: dict) -> None:
    record = locks[lock_id]
    if record["distribution_role"] != "fetch-only":
        raise SystemExit(f"{lock_id} is bundled and does not need downloading")
    if not record["source_url"]:
        raise SystemExit(
            f"{lock_id} is derived from {record.get('derived_from')}; "
            "verify the derived file with scripts/verify_locked_inputs.py"
        )
    if record["requires_terms_acceptance"] and lock_id not in accepted:
        raise SystemExit(
            f"{lock_id} requires acknowledgement of {record['terms_url']}; "
            f"rerun with --accept-terms {lock_id}"
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(
        record["source_url"], headers={"User-Agent": "Mozilla/5.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=900) as response, partial.open(
            "wb"
        ) as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        verify_locked_inputs.verify_file(lock_id, partial, locks)
        os.replace(partial, destination)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    print(f"WROTE {destination}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--id", action="append", default=[], dest="lock_ids")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--accept-terms", action="append", default=[])
    args = parser.parse_args()
    data = verify_locked_inputs.verify_registry()
    locks = data["locks"]

    if args.list:
        for lock_id, record in locks.items():
            print(
                f"{lock_id}\t{record['distribution_role']}\t"
                f"{record['expected_size_bytes']}\t{record['filename']}"
            )
        if not args.lock_ids:
            return
    if not args.lock_ids:
        parser.error("provide --id or --list")
    unknown = set(args.lock_ids) - set(locks)
    if unknown:
        parser.error(f"unknown lock ids: {sorted(unknown)}")
    if args.output and len(args.lock_ids) != 1:
        parser.error("--output is valid only with one --id")

    accepted = set(args.accept_terms)
    for lock_id in args.lock_ids:
        destination = args.output or (args.output_dir / locks[lock_id]["filename"])
        fetch(lock_id, destination, accepted, locks)


if __name__ == "__main__":
    main()
