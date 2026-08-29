from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd
from propagate_hab2_joint_posterior import (
    collapse_host_measure,
    propagate_chunk,
)


class CollapseHostMeasureTests(unittest.TestCase):
    @staticmethod
    def complete_rows() -> list[dict[str, float]]:
        rows = []
        for radius in (7.0, 7.5, 8.0, 8.5, 9.0):
            rows.extend(
                [
                    {
                        "R_kpc": radius,
                        "Teff_K": 5500.0,
                        "N_surface_pc-2": 1.0,
                    },
                    {
                        "R_kpc": radius,
                        "Teff_K": 5600.0,
                        "N_surface_pc-2": 2.0,
                    },
                ]
            )
        return rows

    def test_declared_alternative_temperature_count(self) -> None:
        rows = self.complete_rows()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            collapsed = collapse_host_measure(
                path, expected_distinct_temperatures=2
            )
            self.assertEqual(list(collapsed.Teff_K), [5500.0, 5600.0])
            self.assertTrue((collapsed.integrated_host_weight > 0.0).all())
            with self.assertRaisesRegex(RuntimeError, "Expected 3"):
                collapse_host_measure(path, expected_distinct_temperatures=3)

    def test_negative_host_density_fails_closed(self) -> None:
        rows = self.complete_rows()
        rows[4]["N_surface_pc-2"] = -1.0
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            with self.assertRaisesRegex(RuntimeError, "Negative host"):
                collapse_host_measure(path, expected_distinct_temperatures=2)

    def test_non_finite_propagation_fails_closed(self) -> None:
        samples = pd.DataFrame(
            {
                "F0": [1.0],
                "alpha": [-1.0],
                "beta": [-1.0],
                "gamma": [-200.0],
            }
        )
        with self.assertRaisesRegex(FloatingPointError, "Non-finite"):
            propagate_chunk(
                samples,
                teff=pd.Series([5500.0]).to_numpy(),
                host_weight=pd.Series([1.0]).to_numpy(),
            )


if __name__ == "__main__":
    unittest.main()
