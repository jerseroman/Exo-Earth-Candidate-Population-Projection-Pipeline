from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from propagate_hab2_joint_posterior import collapse_host_measure


class CollapseHostMeasureTests(unittest.TestCase):
    def test_declared_alternative_temperature_count(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
