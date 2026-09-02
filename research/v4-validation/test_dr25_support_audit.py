from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from dr25_support_audit import (
    earth_analog_target_mask,
    rectangular_target_mask,
    seff,
    MAXIMUM_GREENHOUSE,
    PC_CATALOG_SOURCE_LF_SHA256,
    PC_CATALOG_WINDOWS_CRLF_SHA256,
    RUNAWAY_1MEARTH,
    pc_catalog_provenance,
    analyze_perturbation_branch,
    load_source_population_bytes,
)


class Dr25SupportMaskTests(unittest.TestCase):
    def test_pc_catalog_line_ending_provenance_is_fail_closed(self) -> None:
        self.assertNotEqual(
            PC_CATALOG_SOURCE_LF_SHA256,
            PC_CATALOG_WINDOWS_CRLF_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            unexpected = Path(directory) / "catalog.csv"
            unexpected.write_text("a,b\n1,2\n", encoding="utf-8", newline="\n")
            with self.assertRaises(RuntimeError):
                pc_catalog_provenance(unexpected)

    def test_target_boundaries_are_inclusive(self) -> None:
        teff = np.array([5300.0, 6000.0])
        radius = np.array([0.9, 1.1])
        inner = seff(teff, RUNAWAY_1MEARTH)
        instellation = np.minimum(1.1, inner)
        mask = earth_analog_target_mask(radius, instellation, teff)
        self.assertTrue(mask.all())

    def test_conservative_hz_mask_is_subset_of_rectangle(self) -> None:
        teff = np.linspace(5300.0, 6000.0, 100)
        radius = np.linspace(0.8, 1.2, 100)
        instellation = np.linspace(0.8, 1.2, 100)
        earth_analog = earth_analog_target_mask(radius, instellation, teff)
        rectangle = rectangular_target_mask(radius, instellation, teff)
        self.assertFalse(np.any(earth_analog & ~rectangle))

    def test_flux_outside_climate_intersection_is_rejected(self) -> None:
        teff = np.array([5300.0])
        inner = seff(teff, RUNAWAY_1MEARTH)
        self.assertLess(float(inner[0]), 1.1)
        mask = earth_analog_target_mask(
            np.array([1.0]), np.array([1.1]), teff
        )
        self.assertFalse(bool(mask[0]))
        outer = seff(teff, MAXIMUM_GREENHOUSE)
        self.assertLess(float(outer[0]), 0.9)

    def test_audit_integer_and_boolean_text_are_not_coerced(self) -> None:
        source = pd.DataFrame(
            {
                "kepoi_name": ["SYNTHETIC-1"],
                "gaia_iso_prad": [2.0],
                "gaia_iso_insol": [2.0],
                "gaia_iso_insol_errm": [0.1],
                "gaia_iso_insol_errp": [0.1],
                "teff": [5000.0],
                "totalReliability": [1.0],
            }
        )
        rows = pd.DataFrame(
            {
                "branch": ["constant"] * 400,
                "measurement_error_mode": ["quantile_matched_two_sided"] * 400,
                "global_trial": list(range(400)),
                "source_row": [0] * 400,
                "kepoi_name": ["SYNTHETIC-1"] * 400,
                "retained_by_active_policy": ["False"] * 400,
                "instellation_in_source_domain": ["False"] * 400,
                "radius_in_source_domain": ["True"] * 400,
                "teff_in_source_domain": ["True"] * 400,
                "perturbed_flux": [3.0] * 400,
                "perturbed_radius": [2.0] * 400,
                "perturbed_teff": [5000.0] * 400,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.csv"
            rows.to_csv(path, index=False, lineterminator="\n")
            summary, counts, _ = analyze_perturbation_branch(path, "constant", source)
            self.assertEqual(summary["realization_count"], 400)
            self.assertTrue((counts.retained_in_source_domain == 0).all())
            changed = rows.copy()
            changed.loc[0, "global_trial"] = "0.5"
            changed.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaises(RuntimeError):
                analyze_perturbation_branch(path, "constant", source)
            changed = rows.copy()
            changed.loc[0, "retained_by_active_policy"] = "yes"
            changed.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaises(RuntimeError):
                analyze_perturbation_branch(path, "constant", source)

    def test_missing_flux_uncertainty_is_allowed_only_as_canonical_rejection(self) -> None:
        source = pd.DataFrame(
            {
                "kepoi_name": ["SYNTHETIC-MISSING"],
                "gaia_iso_prad": [2.0],
                "gaia_iso_insol": [3.0],
                "gaia_iso_insol_errm": [np.nan],
                "gaia_iso_insol_errp": [np.nan],
                "teff": [5000.0],
                "totalReliability": [1.0],
            }
        )
        rows = pd.DataFrame(
            {
                "branch": ["constant"] * 400,
                "measurement_error_mode": ["quantile_matched_two_sided"] * 400,
                "global_trial": list(range(400)),
                "source_row": [0] * 400,
                "kepoi_name": ["SYNTHETIC-MISSING"] * 400,
                "retained_by_active_policy": ["False"] * 400,
                "instellation_in_source_domain": ["False"] * 400,
                "radius_in_source_domain": ["True"] * 400,
                "teff_in_source_domain": ["True"] * 400,
                "perturbed_flux": [""] * 400,
                "perturbed_radius": [2.0] * 400,
                "perturbed_teff": [5000.0] * 400,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.csv.gz"
            rows.to_csv(path, index=False, lineterminator="\n")
            summary, counts, _ = analyze_perturbation_branch(path, "constant", source)
            self.assertEqual(summary["missing_instellation_uncertainty_exclusions"], 400)
            self.assertTrue((counts.earth_analog_target_candidates == 0).all())

            changed = rows.copy()
            changed.loc[0, "perturbed_flux"] = "NaN"
            changed.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaises(RuntimeError):
                analyze_perturbation_branch(path, "constant", source)

            changed = rows.copy()
            changed.loc[0, "instellation_in_source_domain"] = "True"
            changed.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaisesRegex(RuntimeError, "domain flags"):
                analyze_perturbation_branch(path, "constant", source)

            changed = rows.copy()
            changed.loc[0, "retained_by_active_policy"] = "True"
            changed.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaisesRegex(RuntimeError, "retained flags"):
                analyze_perturbation_branch(path, "constant", source)

            finite_source = source.copy()
            finite_source[["gaia_iso_insol_errm", "gaia_iso_insol_errp"]] = 0.1
            rows.to_csv(path, index=False, lineterminator="\n")
            with self.assertRaisesRegex(RuntimeError, "unexplained"):
                analyze_perturbation_branch(path, "constant", finite_source)

    def test_source_loader_accepts_only_paired_missing_flux_uncertainties(self) -> None:
        pc = pd.DataFrame(
            {
                "kepoi_name": ["SYNTHETIC-MISSING", "SYNTHETIC-FINITE"],
                "kepid_x": [1, 2],
                "totalReliability": [0.8, 0.9],
                "gaia_iso_prad": [1.0, 1.1],
                "gaia_iso_insol": [3.0, 1.0],
                "gaia_iso_insol_errm": [np.nan, 0.1],
                "gaia_iso_insol_errp": [np.nan, 0.2],
                "teff": [5772.0, 5600.0],
            }
        )
        stellar = pd.DataFrame({"kepid": [1, 2], "logg": [4.4, 4.5]})

        def load(frame: pd.DataFrame) -> pd.DataFrame:
            return load_source_population_bytes(
                frame.to_csv(index=False, lineterminator="\n").encode("utf-8"),
                stellar.to_csv(index=False, lineterminator="\n").encode("utf-8"),
            )

        source = load(pc)
        self.assertEqual(int(source.gaia_iso_insol_errm.isna().sum()), 1)
        self.assertTrue(
            np.array_equal(
                source.gaia_iso_insol_errm.isna().to_numpy(),
                source.gaia_iso_insol_errp.isna().to_numpy(),
            )
        )

        mutations = {
            "one-sided missing": (0, "gaia_iso_insol_errp", 0.1),
            "infinite": (1, "gaia_iso_insol_errm", np.inf),
            "negative": (1, "gaia_iso_insol_errp", -0.1),
        }
        for case, (row, column, value) in mutations.items():
            changed = pc.copy()
            changed.loc[row, column] = value
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                load(changed)


if __name__ == "__main__":
    unittest.main()
