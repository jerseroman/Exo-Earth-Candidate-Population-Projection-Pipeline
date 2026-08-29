#!/usr/bin/env python3
"""Fail-closed regression tests for immutable external scientific inputs."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import fetch_locked_inputs  # noqa: E402
import verify_locked_inputs  # noqa: E402


class DataLockTests(unittest.TestCase):
    def test_fetch_url_is_restricted_to_credential_free_https(self) -> None:
        valid = "https://example.org/science/input.csv"
        self.assertEqual(fetch_locked_inputs.validate_source_url(valid), valid)
        for invalid in (
            "http://example.org/input.csv",
            "file:///tmp/input.csv",
            "https://user:secret@example.org/input.csv",
            "not-a-url",
        ):
            with self.subTest(url=invalid):
                with self.assertRaises(SystemExit):
                    fetch_locked_inputs.validate_source_url(invalid)

    def test_required_inputs_and_workflow_bindings_are_declared(self) -> None:
        registry = verify_locked_inputs.verify_registry()
        locks = registry["locks"]
        self.assertEqual(
            {
                "bryson_rate_models_3d",
                "bryson_pc_catalog",
                "bryson_stellar_catalog_zip",
                "bryson_stellar_catalog_extracted",
                "completeness_constant",
                "completeness_zero",
                "jj_padova_multiband_archive",
                "huber_parsec_tams_table",
            },
            set(locks),
        )
        for workflow in (
            ".github/workflows/jj-g-host-export.yml",
            ".github/workflows/jj-tams-metallicity-differential.yml",
            ".github/workflows/jj-tams-radial-convergence.yml",
        ):
            self.assertIn(
                "huber_parsec_tams_table",
                registry["workflow_requirements"][workflow],
            )
        pc = locks["bryson_pc_catalog"]
        self.assertEqual(
            pc["expected_sha256"],
            "c8ae78fcfe4ed27bbe972b1041a3e370031a4f94afea4ad35dd7bd47834c140b",
        )
        self.assertEqual(
            pc["windows_crlf_checkout_sha256"],
            "5cf4805d8742507ead6916dcd1f7b118b7e5a28966b9ddd5b8d09fc6e181115c",
        )
        self.assertIn("2278", pc["line_ending_note"])

    def test_fetch_requests_the_complete_object_as_an_open_range(self) -> None:
        payload = b"locked scientific input\n"
        source_url = "https://example.org/science/input.bin"
        observed: dict[str, object] = {}

        class Response:
            def __init__(self) -> None:
                self.remaining = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def geturl(self) -> str:
                return source_url

            def read(self, _size: int) -> bytes:
                block, self.remaining = self.remaining, b""
                return block

        def fake_urlopen(request, timeout):
            observed["range"] = request.get_header("Range")
            observed["timeout"] = timeout
            return Response()

        locks = {
            "synthetic": {
                "source_url": source_url,
                "expected_sha256": hashlib.sha256(payload).hexdigest(),
                "expected_size_bytes": len(payload),
                "distribution_role": "fetch-only",
                "requires_terms_acceptance": False,
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "input.bin"
            with mock.patch.object(
                fetch_locked_inputs.urllib.request,
                "urlopen",
                side_effect=fake_urlopen,
            ):
                fetch_locked_inputs.fetch("synthetic", destination, set(), locks)
            self.assertEqual(destination.read_bytes(), payload)

        self.assertEqual(observed, {"range": "bytes=0-", "timeout": 900})

    def test_same_size_corruption_fails_sha256_gate(self) -> None:
        locks = verify_locked_inputs.load_registry()["locks"]
        record = locks["huber_parsec_tams_table"]
        with tempfile.TemporaryDirectory() as directory:
            corrupted = Path(directory) / record["filename"]
            corrupted.write_bytes(b"\0" * record["expected_size_bytes"])
            with self.assertRaises(SystemExit) as caught:
                verify_locked_inputs.verify_file(
                    "huber_parsec_tams_table", corrupted, locks
                )
        self.assertIn("SHA-256 mismatch", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
