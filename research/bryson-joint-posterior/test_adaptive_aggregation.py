#!/usr/bin/env python3
"""Integration test for adaptive-chain equal-mixture aggregation."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import pandas as pd

from measurement_error import QUANTILE_MATCHED_TWO_SIDED


class AdaptiveAggregationTests(unittest.TestCase):
    def test_variable_chains_are_equalized_and_cluster_diagnosed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            out = Path(temporary) / "combined"
            for shard in range(2):
                directory = root / f"artifact-{shard}"
                directory.mkdir(parents=True)
                label = f"production-shard-{shard}"
                rows = []
                diagnostics = []
                for trial, count in enumerate((4, 6)):
                    for row in range(count):
                        rows.append(
                            {
                                "branch": "constant",
                                "run_label": label,
                                "trial": trial,
                                "trial_seed": 100 * shard + trial,
                                "production_step": row,
                                "walker": row % 2,
                                "F0": 1.0 + shard + 0.1 * trial + 0.01 * row,
                                "alpha": -1.0 + 0.01 * row,
                                "beta": -0.8 + 0.01 * row,
                                "gamma": -2.0 + 0.01 * row,
                            }
                        )
                    diagnostics.append(
                        {
                            "trial": trial,
                            "measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED,
                            "mean_acceptance_fraction": 0.4,
                            "runtime_seconds": 1.0,
                            "selected_after_domain": 10,
                            "optimizer_success": True,
                            "autocorrelation_time": [1.0, 1.0, 1.0, 1.0],
                            "effective_sample_size_source_order": [8.0] * 4,
                            "production_steps_completed": count,
                            "adaptive_production": True,
                            "converged": True,
                        }
                    )
                pd.DataFrame(rows).to_csv(
                    directory / f"joint_posterior_constant_{label}.csv", index=False
                )
                (directory / f"trial_diagnostics_constant_{label}.json").write_text(
                    json.dumps(diagnostics), encoding="utf-8"
                )
                (directory / f"posterior_summary_constant_{label}.json").write_text(
                    json.dumps(
                        {
                            "branch": "constant",
                            "period_cutoff_days": None,
                            "burnin_steps": 10,
                            "measurement_error": {
                                "mode": QUANTILE_MATCHED_TWO_SIDED
                            },
                        }
                    ),
                    encoding="utf-8",
                )

            script = Path(__file__).with_name("aggregate_hab2_joint_posterior.py")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--root",
                    str(root),
                    "--branch",
                    "constant",
                    "--out",
                    str(out),
                    "--expected-shards",
                    "2",
                    "--trials-per-shard",
                    "2",
                    "--walkers",
                    "2",
                    "--steps",
                    "4",
                    "--runner-thin",
                    "1",
                    "--samples-per-realization",
                    "4",
                    "--require-all-converged",
                    "--cluster-bootstrap-replicates",
                    "20",
                    "--inner-chain-batches",
                    "2",
                    "--propagation-stride",
                    "1",
                    "--expected-measurement-error-mode",
                    QUANTILE_MATCHED_TWO_SIDED,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(
                (out / "joint_posterior_constant_aggregate_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(summary["total_trials"], 4)
            self.assertEqual(summary["full_sample_count"], 16)
            self.assertEqual(summary["diagnostics"]["adaptive_realizations_converged"], 4)
            self.assertIsNotNone(
                summary["posterior_quantile_monte_carlo_error"]
                ["outer_realization_cluster_bootstrap"]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
