#!/usr/bin/env python3
"""Path-safety tests for canonical-host checksum verification."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("assert_canonical_tams.py")
SPEC = importlib.util.spec_from_file_location("assert_canonical_tams", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {MODULE_PATH}")
canonical = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canonical)


class AssertCanonicalTamsPathTests(unittest.TestCase):
    def test_manifest_names_are_portable_safe_leaves(self) -> None:
        unsafe_names = (
            "/x",
            "a/b",
            r"a\b",
            "foo/../bar",
            "../result.json",
            r"C:x",
            r"\\server\share\x",
            r"mixed/dir\result.json",
            ".",
            "..",
            "result.json/",
            "result.json\\",
            "result\x00.json",
        )
        self.assertTrue(canonical.is_portable_safe_leaf("result.json"))
        for unsafe_name in unsafe_names:
            with self.subTest(unsafe_name=repr(unsafe_name)):
                self.assertFalse(canonical.is_portable_safe_leaf(unsafe_name))

    def test_manifest_verifier_rejects_windows_and_posix_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_name = "SHA256SUMS.txt"
            for unsafe_name in (
                "/tmp/result.json",
                r"C:\temp\result.json",
                r"\\server\share\result.json",
                r"mixed/dir\result.json",
            ):
                with self.subTest(unsafe_name=repr(unsafe_name)):
                    (root / manifest_name).write_text(
                        f"{'0' * 64}  {unsafe_name}\n", encoding="utf-8"
                    )
                    with self.assertRaisesRegex(RuntimeError, "Unsafe checksum filename"):
                        canonical.verify_checksum_manifest(
                            root, manifest_name, (unsafe_name,)
                        )

    def test_manifest_verifier_accepts_one_safe_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "result.json"
            target.write_bytes(b"{}\n")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            manifest_name = "SHA256SUMS.txt"
            (root / manifest_name).write_text(
                f"{digest}  {target.name}\n", encoding="utf-8"
            )
            canonical.verify_checksum_manifest(
                root, manifest_name, (target.name,)
            )

    def test_json_loader_rejects_duplicate_key_and_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "summary.json"
            path.write_text('{"status":"PASS","status":"PASS","x":1e999}\n')
            with self.assertRaises(RuntimeError):
                canonical.load_strict_json(path, "test summary")

    def test_regular_reader_rejects_final_component_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            replacement = root / "replacement"
            source.write_bytes(b"original")
            replacement.write_bytes(b"replacement bytes")
            real_open = canonical.os.open
            swapped = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path) == source and not swapped:
                    try:
                        source.unlink()
                        source.symlink_to(replacement)
                    except OSError as exc:
                        self.skipTest(f"symlink creation unavailable: {exc}")
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(canonical.os, "open", side_effect=racing_open):
                with self.assertRaises(RuntimeError):
                    canonical.read_regular_bytes(source, "race-test file")


if __name__ == "__main__":
    unittest.main()
