from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from host_tams_audit import assess_metallicity_surface, attach_radial_weights


class HostTamsAuditTests(unittest.TestCase):
    def test_composite_trapezoid_radial_measure(self) -> None:
        frame = pd.DataFrame(
            {
                "R_kpc": [7.0, 7.5, 8.0, 8.5, 9.0],
                "N_surface_pc_2": [1.0] * 5,
            }
        )
        weighted = attach_radial_weights(frame)
        expected = 2.0 * math.pi * 1.0e6 * (
            0.25 * 7.0 + 0.5 * 7.5 + 0.5 * 8.0 + 0.5 * 8.5 + 0.25 * 9.0
        )
        self.assertAlmostEqual(float(weighted.integrated_weight.sum()), expected)

    def test_metallicity_surface_rejects_giant_contamination(self) -> None:
        rows = []
        for metallicity in (0.001, 0.017):
            rows.extend(
                [
                    {
                        "Z": metallicity,
                        "Teff_K": 5200.0,
                        "R_Rsun": 1.1,
                        "mass": 0.7,
                        "age_Gyr": 25.0,
                    },
                    {
                        "Z": metallicity,
                        "Teff_K": 6100.0,
                        "R_Rsun": 1.7,
                        "mass": 1.2,
                        "age_Gyr": 6.0,
                    },
                ]
            )
        rows.append(
            {
                "Z": 0.001,
                "Teff_K": 5700.0,
                "R_Rsun": 100.0,
                "mass": 20.0,
                "age_Gyr": 0.1,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "points.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            result = assess_metallicity_surface(path)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["contaminating_point_count"], 1)
        self.assertEqual(result["metallicities_without_full_low_mass_coverage"], [])


if __name__ == "__main__":
    unittest.main()
