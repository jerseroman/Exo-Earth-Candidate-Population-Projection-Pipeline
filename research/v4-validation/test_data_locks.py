#!/usr/bin/env python3
"""Fail-closed regression tests for immutable external scientific inputs."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import verify_locked_inputs  # noqa: E402


class DataLockTests(unittest.TestCase):
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
