#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
#
# Tests exercise the modified Bryson-derived implementation documented in
# MODIFICATIONS_BRYSON.md and are distributed with it under GPL-2.0-only.
# Modified by Roman Jerše on 2026-08-21; see MODIFICATIONS_BRYSON.md.
"""Unit and regression tests for the v4 measurement-error modes."""
from __future__ import annotations

import math
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

from measurement_error import (
    LEGACY_SOURCE_MIXTURE,
    QUANTILE_MATCHED_TWO_SIDED,
    draw_asymmetric_measurement,
    perturb_planets,
)
from aggregate_hab2_joint_posterior import (
    resolve_measurement_error_mode,
    validate_diagnostic_modes,
)


def synthetic_catalog(teff: np.ndarray | None = None) -> pd.DataFrame:
    count = 64 if teff is None else len(teff)
    index = np.arange(count, dtype=float)
    if teff is None:
        teff = 5000.0 + 10.0 * index
    return pd.DataFrame(
        {
            "source_row": np.arange(count, dtype=int),
            "kepoi_name": [f"K{value:05d}" for value in range(count)],
            "kepid_x": np.arange(1000, 1000 + count, dtype=int),
            "totalReliability": 0.15 + 0.8 * ((index % 11.0) / 10.0),
            "koi_period": 50.0 + index,
            "gaia_iso_insol": 0.25 + 1.8 * ((index % 17.0) / 16.0),
            "gaia_iso_insol_errm": 0.02 + 0.001 * (index % 5.0),
            "gaia_iso_insol_errp": 0.03 + 0.001 * (index % 7.0),
            "gaia_iso_prad": 0.6 + 1.7 * ((index % 19.0) / 18.0),
            "gaia_iso_prad_errm": 0.04 + 0.002 * (index % 3.0),
            "gaia_iso_prad_errp": 0.05 + 0.002 * (index % 4.0),
            "teff": teff,
            "teff_err2": np.full(count, 80.0),
            "teff_err1": np.full(count, 120.0),
        }
    )


def legacy_reference(
    all_kois: pd.DataFrame, rng: np.random.RandomState
) -> pd.DataFrame:
    """Literal pre-v4 implementation used as the bitwise regression oracle."""

    selected_mask = rng.rand(len(all_kois)) < np.asarray(
        all_kois.totalReliability, dtype=float
    )
    selected = all_kois.loc[selected_mask].copy()

    flux = np.zeros(len(selected), dtype=float)
    plus = rng.rand(len(selected)) > 0.5
    minus = ~plus
    flux[plus] = (
        np.asarray(selected.loc[plus, "gaia_iso_insol"], dtype=float)
        + np.asarray(selected.loc[plus, "gaia_iso_insol_errp"], dtype=float)
        * rng.randn(int(np.sum(plus)))
    )
    flux[minus] = (
        np.asarray(selected.loc[minus, "gaia_iso_insol"], dtype=float)
        - np.asarray(selected.loc[minus, "gaia_iso_insol_errm"], dtype=float)
        * rng.randn(int(np.sum(minus)))
    )

    radius = np.zeros(len(selected), dtype=float)
    plus = rng.rand(len(selected)) > 0.5
    minus = ~plus
    radius[plus] = (
        np.asarray(selected.loc[plus, "gaia_iso_prad"], dtype=float)
        + np.asarray(selected.loc[plus, "gaia_iso_prad_errp"], dtype=float)
        * rng.randn(int(np.sum(plus)))
    )
    radius[minus] = (
        np.asarray(selected.loc[minus, "gaia_iso_prad"], dtype=float)
        - np.asarray(selected.loc[minus, "gaia_iso_prad_errm"], dtype=float)
        * rng.randn(int(np.sum(minus)))
    )

    perturbed_teff = np.zeros(len(selected), dtype=float)
    plus = rng.rand(len(selected)) > 0.5
    minus = ~plus
    perturbed_teff[plus] = (
        np.asarray(selected.loc[plus, "teff"], dtype=float)
        + np.asarray(selected.loc[plus, "teff_err1"], dtype=float)
        * rng.randn(int(np.sum(plus)))
    )
    perturbed_teff[minus] = (
        np.asarray(selected.loc[minus, "teff"], dtype=float)
        - np.asarray(selected.loc[minus, "teff_err2"], dtype=float)
        * rng.randn(int(np.sum(minus)))
    )

    in_domain = (
        (0.2 <= flux)
        & (flux <= 2.2)
        & np.isfinite(radius)
        & (0.5 <= radius)
        & (radius <= 2.5)
    )
    selected = selected.loc[in_domain].copy()
    selected["perturbed_flux"] = flux[in_domain]
    selected["perturbed_radius"] = radius[in_domain]
    selected["perturbed_teff"] = perturbed_teff[in_domain]
    return selected


class MeasurementErrorTests(unittest.TestCase):
    def test_legacy_mode_is_bitwise_identical_to_pre_v4_code(self) -> None:
        frame = synthetic_catalog()
        expected = legacy_reference(frame, np.random.RandomState(219001))
        actual = perturb_planets(
            frame,
            np.random.RandomState(219001),
            instellation_range=(0.2, 2.2),
            radius_range=(0.5, 2.5),
            teff_range=(3900.0, 6300.0),
            period_max_days=None,
            mode=LEGACY_SOURCE_MIXTURE,
        ).retained

        np.testing.assert_array_equal(
            actual.source_row.to_numpy(), expected.source_row.to_numpy()
        )
        for column in ("perturbed_flux", "perturbed_radius", "perturbed_teff"):
            np.testing.assert_array_equal(
                actual[column].to_numpy(), expected[column].to_numpy()
            )

    def test_corrected_mode_matches_requested_three_quantiles(self) -> None:
        count = 700_000
        center = 10.0
        sigma_minus = 2.0
        sigma_plus = 3.0
        values = draw_asymmetric_measurement(
            np.full(count, center),
            np.full(count, sigma_minus),
            np.full(count, sigma_plus),
            np.random.RandomState(219001),
            QUANTILE_MATCHED_TWO_SIDED,
        )
        lower_probability = 0.5 * math.erfc(1.0 / math.sqrt(2.0))
        quantiles = np.quantile(
            values, [lower_probability, 0.5, 1.0 - lower_probability]
        )
        np.testing.assert_allclose(
            quantiles,
            [center - sigma_minus, center, center + sigma_plus],
            atol=0.025,
            rtol=0.0,
        )

    def test_corrected_mode_reapplies_teff_domain_but_legacy_does_not(self) -> None:
        teff = np.array([3899.0, 3900.0, 5000.0, 6300.0, 6301.0])
        frame = synthetic_catalog(teff)
        frame["totalReliability"] = 1.0
        for column in (
            "gaia_iso_insol_errm",
            "gaia_iso_insol_errp",
            "gaia_iso_prad_errm",
            "gaia_iso_prad_errp",
            "teff_err2",
            "teff_err1",
        ):
            frame[column] = 0.0

        legacy = perturb_planets(
            frame,
            np.random.RandomState(7),
            (0.2, 2.2),
            (0.5, 2.5),
            (3900.0, 6300.0),
            None,
            LEGACY_SOURCE_MIXTURE,
        )
        corrected = perturb_planets(
            frame,
            np.random.RandomState(7),
            (0.2, 2.2),
            (0.5, 2.5),
            (3900.0, 6300.0),
            None,
            QUANTILE_MATCHED_TWO_SIDED,
        )

        self.assertEqual(legacy.retained.source_row.tolist(), [0, 1, 2, 3, 4])
        self.assertEqual(corrected.retained.source_row.tolist(), [1, 2, 3])
        self.assertEqual(legacy.counts["n_retained_with_teff_outside_source_domain"], 2)
        self.assertEqual(corrected.counts["n_retained_with_teff_outside_source_domain"], 0)
        self.assertTrue(
            legacy.audit.audit_status.str.contains("not_filtered_in_legacy").any()
        )

    def test_corrected_mode_rejects_negative_uncertainty(self) -> None:
        with self.assertRaisesRegex(ValueError, "negative finite uncertainty"):
            draw_asymmetric_measurement(
                [1.0],
                [-0.1],
                [0.2],
                np.random.RandomState(1),
                QUANTILE_MATCHED_TWO_SIDED,
            )

    def test_unknown_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown measurement-error mode"):
            draw_asymmetric_measurement(
                [1.0], [0.1], [0.2], np.random.RandomState(1), "unknown"
            )

    def test_aggregator_infers_pre_v4_summaries_as_legacy(self) -> None:
        mode, metadata = resolve_measurement_error_mode([{}, {}])
        self.assertEqual(mode, LEGACY_SOURCE_MIXTURE)
        self.assertTrue(metadata["metadata_inferred_from_pre_v4_shard_summaries"])

    def test_aggregator_rejects_mixed_modes(self) -> None:
        summaries = [
            {"measurement_error": {"mode": LEGACY_SOURCE_MIXTURE}},
            {"measurement_error": {"mode": QUANTILE_MATCHED_TWO_SIDED}},
        ]
        with self.assertRaisesRegex(RuntimeError, "Cannot mix"):
            resolve_measurement_error_mode(summaries)

    def test_aggregator_enforces_expected_mode(self) -> None:
        summaries = [
            {"measurement_error": {"mode": LEGACY_SOURCE_MIXTURE}},
        ]
        with self.assertRaisesRegex(RuntimeError, "mode mismatch"):
            resolve_measurement_error_mode(
                summaries, expected_mode=QUANTILE_MATCHED_TWO_SIDED
            )

    def test_aggregator_rejects_diagnostic_mode_mismatch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "do not match"):
            validate_diagnostic_modes(
                [{"measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED}],
                LEGACY_SOURCE_MIXTURE,
            )

    def test_aggregator_preserves_corrected_audit_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            shard = root / "shard-0"
            out = Path(temporary) / "aggregate"
            shard.mkdir(parents=True)
            label = "production-shard-0"

            pd.DataFrame(
                {
                    "branch": ["constant", "constant"],
                    "run_label": [label, label],
                    "trial": [0, 0],
                    "trial_seed": [11, 11],
                    "mcmc_seed": [22, 22],
                    "production_step": [0, 1],
                    "walker": [0, 0],
                    "F0": [1.0, 1.1],
                    "alpha": [-1.0, -0.9],
                    "beta": [-0.8, -0.7],
                    "gamma": [-2.0, -1.9],
                }
            ).to_csv(
                shard / f"joint_posterior_constant_{label}.csv", index=False
            )
            (shard / f"trial_diagnostics_constant_{label}.json").write_text(
                json.dumps(
                    [
                        {
                            "trial": 0,
                            "seed": 11,
                            "perturbation_seed": 11,
                            "mcmc_seed": 22,
                            "measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED,
                            "mean_acceptance_fraction": 0.4,
                            "runtime_seconds": 1.0,
                            "selected_after_domain": 2,
                            "optimizer_success": True,
                            "autocorrelation_time": None,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (shard / f"posterior_summary_constant_{label}.json").write_text(
                json.dumps(
                    {
                        "branch": "constant",
                        "run_label": label,
                        "period_cutoff_days": None,
                        "trials": 1,
                        "walkers": 1,
                        "burnin_steps": 1,
                        "production_steps_requested_minimum": 2,
                        "thin": 1,
                        "trial_diagnostics_file": (
                            f"trial_diagnostics_constant_{label}.json"
                        ),
                        "measurement_error": {
                            "mode": QUANTILE_MATCHED_TWO_SIDED
                        },
                        "perturbation_audit_file": (
                            f"perturbation_audit_constant_{label}.csv"
                        ),
                    }
                ),
                encoding="utf-8",
            )
            pd.DataFrame(
                {
                    "branch": ["constant", "constant"],
                    "run_label": [label, label],
                    "measurement_error_mode": [
                        QUANTILE_MATCHED_TWO_SIDED,
                        QUANTILE_MATCHED_TWO_SIDED,
                    ],
                    "trial": [0, 0],
                    "trial_seed": [11, 11],
                    "source_row": [3, 7],
                    "retained_by_active_policy": [True, False],
                }
            ).to_csv(
                shard / f"perturbation_audit_constant_{label}.csv", index=False
            )

            aggregator = Path(__file__).with_name(
                "aggregate_hab2_joint_posterior.py"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(aggregator),
                    "--root",
                    str(root),
                    "--branch",
                    "constant",
                    "--out",
                    str(out),
                    "--expected-shards",
                    "1",
                    "--trials-per-shard",
                    "1",
                    "--walkers",
                    "1",
                    "--steps",
                    "2",
                    "--runner-thin",
                    "1",
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
            audit_path = out / "perturbation_audit_constant_full.csv.gz"
            self.assertTrue(audit_path.is_file())
            combined = pd.read_csv(audit_path)
            self.assertEqual(combined.global_trial.tolist(), [0, 0])
            summary = json.loads(
                (out / "joint_posterior_constant_aggregate_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                summary["measurement_error"]["mode"],
                QUANTILE_MATCHED_TWO_SIDED,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
