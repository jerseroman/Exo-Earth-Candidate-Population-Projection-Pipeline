#!/usr/bin/env python3
"""Tests for equal-mixture and cluster-aware Monte Carlo diagnostics."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from clustered_monte_carlo import (
    DETERMINISTIC_GZIP_COMPRESSION,
    cluster_bootstrap_quantile_mcse,
    contiguous_batch_quantile_mcse,
    equalize_realizations,
)


class ClusteredMonteCarloTests(unittest.TestCase):
    def test_gzip_csv_configuration_is_byte_deterministic(self) -> None:
        frame = pd.DataFrame({"value": [1.0, 2.0], "label": ["a", "b"]})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first" / "output.csv.gz"
            second = root / "second" / "output.csv.gz"
            first.parent.mkdir()
            second.parent.mkdir()
            frame.to_csv(
                first,
                index=False,
                compression=DETERMINISTIC_GZIP_COMPRESSION,
            )
            frame.to_csv(
                second,
                index=False,
                compression=DETERMINISTIC_GZIP_COMPRESSION,
            )
            first_bytes = first.read_bytes()
            self.assertEqual(first_bytes, second.read_bytes())
            self.assertEqual(int.from_bytes(first_bytes[4:8], "little"), 0)

    def test_equalizer_uses_every_realization_with_equal_weight(self) -> None:
        frame = pd.DataFrame(
            {
                "trial": np.repeat([0, 1], [10, 14]),
                "value": np.concatenate([np.arange(10), np.arange(14)]),
            }
        )
        result = equalize_realizations(frame, "trial", 4)
        self.assertEqual(result.groupby("trial").size().tolist(), [4, 4])
        self.assertEqual(result.loc[result.trial == 0, "value"].tolist(), [1, 3, 6, 8])

    def test_cluster_bootstrap_is_zero_for_identical_clusters(self) -> None:
        frame = pd.DataFrame(
            {
                "trial": np.repeat(np.arange(8), 8),
                "value": np.tile(np.arange(8, dtype=float), 8),
            }
        )
        result = cluster_bootstrap_quantile_mcse(
            frame, ["value"], "trial", replicates=100, seed=219001
        )
        for summary in result["value"].values():
            self.assertAlmostEqual(summary["standard_error"], 0.0)

    def test_contiguous_batches_report_zero_for_repeated_blocks(self) -> None:
        frame = pd.DataFrame(
            {
                "trial": np.repeat(np.arange(4), 16),
                "value": np.tile(np.tile(np.arange(4), 4), 4),
            }
        )
        result = contiguous_batch_quantile_mcse(
            frame, ["value"], "trial", batches=4
        )
        for value in result["value"].values():
            self.assertAlmostEqual(value, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
