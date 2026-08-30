#!/usr/bin/env python3
"""Integration tests for strict seed-family diagnostic ingestion."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import pandas as pd


class CompareMCMCSeedFamiliesTests(unittest.TestCase):
    @staticmethod
    def write_family(root: Path, suffix: str, mcmc_seed: int) -> Path:
        directory = root / f"family-{suffix}"
        directory.mkdir(parents=True)
        label = f"corrected-pilot-seed-{suffix}"
        pd.DataFrame(
            [
                {
                    "run_label": label,
                    "trial": 0,
                    "trial_seed": 17,
                    "mcmc_seed": mcmc_seed,
                    "production_step": row,
                    "walker": 0,
                    "F0": 1.0 + 0.1 * row,
                    "alpha": -1.0 + 0.1 * row,
                    "beta": -0.8 + 0.1 * row,
                    "gamma": -2.0 + 0.1 * row,
                }
                for row in range(4)
            ]
        ).to_csv(
            directory / f"joint_posterior_constant_{label}.csv", index=False
        )
        shared_rows = [
            {"run_label": label, "trial": 0, "source_row": 0, "value": 1.0}
        ]
        pd.DataFrame(shared_rows).to_csv(
            directory / f"perturbed_planets_constant_{label}.csv", index=False
        )
        pd.DataFrame(shared_rows).to_csv(
            directory / f"perturbation_audit_constant_{label}.csv", index=False
        )
        diagnostics = directory / f"trial_diagnostics_constant_{label}.json"
        diagnostics.write_text(
            json.dumps(
                [
                    {
                        "trial": 0,
                        "converged": True,
                        "production_steps_completed": 3000,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return diagnostics

    @staticmethod
    def run_comparison(
        root: Path, out: Path
    ) -> subprocess.CompletedProcess[str]:
        script = Path(__file__).with_name("compare_mcmc_seed_families.py")
        return subprocess.run(
            [
                sys.executable,
                *([] if __debug__ else ["-O"]),
                str(script),
                "--root",
                str(root),
                "--branch",
                "constant",
                "--out",
                str(out),
                "--expected-families",
                "2",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_valid_strict_diagnostics_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "families"
            self.write_family(root, "a", 101)
            self.write_family(root, "b", 201)
            completed = self.run_comparison(root, Path(temporary) / "out")
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_ambiguous_or_overflowing_diagnostics_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "families"
            diagnostics = self.write_family(root, "a", 101)
            self.write_family(root, "b", 201)
            original = diagnostics.read_text(encoding="utf-8")
            mutations = {
                "duplicate converged": original.replace(
                    '"converged": true',
                    '"converged": false, "converged": true',
                    1,
                ),
                "unused overflow_probe": original.replace(
                    "}]", ', "overflow_probe": 1e999}]', 1
                ),
            }
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    diagnostics.write_text(payload, encoding="utf-8")
                    completed = self.run_comparison(
                        root, Path(temporary) / f"out-{label.replace(' ', '-')}"
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("invalid strict JSON", completed.stderr)
                    diagnostics.write_text(original, encoding="utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
