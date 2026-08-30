#!/usr/bin/env python3
"""Regression tests for canonical and legacy host checksum manifests."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("promote_tams_provider.py")
SPEC = importlib.util.spec_from_file_location("promote_tams_provider", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot import {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def verify_manifest(directory: Path, manifest_name: str) -> list[str]:
    """Verify every listed file and return the manifest filenames."""
    names: list[str] = []
    manifest = directory / manifest_name
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        target = directory / name
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"checksum mismatch for {name}")
        names.append(name)
    return names


class PromoteTamsProviderTests(unittest.TestCase):
    def test_legacy_manifest_is_regenerated_with_actual_legacy_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source_names = [
                name
                for name in MODULE.CANONICAL
                if name != "SHA256SUMS_padova.txt"
            ]
            for index, name in enumerate(source_names):
                (out / name).write_bytes(f"fixture-{index}\n".encode("ascii"))
            (out / "SHA256SUMS_padova.txt").write_text(
                "0" * 64 + "  stale-canonical-name.csv\n",
                encoding="utf-8",
            )

            MODULE.preserve_legacy_files(out)

            manifest_name = MODULE.legacy_name("SHA256SUMS_padova.txt")
            listed = verify_manifest(out, manifest_name)
            expected = [MODULE.legacy_name(name) for name in source_names]
            self.assertEqual(listed, expected)
            self.assertNotIn("stale-canonical-name.csv", listed)
            self.assertTrue(all("_legacy_logg43" in name for name in listed))

    def test_manifest_writer_verifies_canonical_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            files = [out / "one.csv", out / "two.json"]
            files[0].write_bytes(b"one\n")
            files[1].write_bytes(b'{"two": 2}\n')
            MODULE.write_sha256_manifest(out / "SHA256SUMS.txt", files)

            self.assertEqual(
                verify_manifest(out, "SHA256SUMS.txt"),
                ["one.csv", "two.json"],
            )


if __name__ == "__main__":
    unittest.main()
