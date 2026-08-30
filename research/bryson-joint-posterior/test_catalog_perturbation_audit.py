#!/usr/bin/env python3
"""Adversarial tests for locked-catalog perturbation reconstruction."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import numpy as np
import pandas as pd


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "catalog_perturbation_audit", HERE / "catalog_perturbation_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)

MEASUREMENT_SPEC = importlib.util.spec_from_file_location(
    "measurement_error_for_catalog_audit_test", HERE / "measurement_error.py"
)
assert MEASUREMENT_SPEC is not None and MEASUREMENT_SPEC.loader is not None
measurement = importlib.util.module_from_spec(MEASUREMENT_SPEC)
sys.modules[MEASUREMENT_SPEC.name] = measurement
MEASUREMENT_SPEC.loader.exec_module(measurement)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CatalogPerturbationAuditTests(unittest.TestCase):
    def build_fixture(
        self,
        root: Path,
        mode: str = audit.CORRECTED_MODE,
        seeds: tuple[int, int] | None = None,
    ) -> dict[str, Path]:
        pc = root / audit.PC_FILENAME
        stellar = root / audit.STELLAR_FILENAME
        aggregate = root / "aggregate"
        aggregate.mkdir()
        pc_frame = pd.DataFrame(
            {
                "kepoi_name": ["K1", "K2", "K3"],
                "kepid_x": [1, 2, 3],
                "totalReliability": [1.0, 0.55, 0.0],
                "koi_period": [100.0, 200.0, 300.0],
                "gaia_iso_insol": [1.0, 2.15, 1.1],
                "gaia_iso_insol_errm": [0.05, 0.10, 0.08],
                "gaia_iso_insol_errp": [0.06, 0.12, 0.09],
                "gaia_iso_prad": [1.0, 2.45, 1.2],
                "gaia_iso_prad_errm": [0.04, 0.08, 0.05],
                "gaia_iso_prad_errp": [0.05, 0.10, 0.06],
                "teff": [5700.0, 6250.0, 5000.0],
                "teff_err2": [50.0, 80.0, 60.0],
                "teff_err1": [60.0, 90.0, 70.0],
            }
        )
        stellar_frame = pd.DataFrame(
            {"kepid": [1, 2, 3], "logg": [4.4, 4.3, 4.5], "unused": [7, 8, 9]}
        )
        pc_frame.to_csv(pc, index=False, lineterminator="\n")
        stellar_frame.to_csv(stellar, index=False, lineterminator="\n")
        merged = pd.merge(
            pc_frame,
            stellar_frame[["kepid", "logg"]],
            left_on="kepid_x",
            right_on="kepid",
            how="inner",
        ).reset_index(drop=True)
        merged["source_row"] = range(len(merged))
        frames = []
        diagnostics = []
        if seeds is None:
            seeds = (2_026_082_200, 2_026_082_200 + 1_000_003)
        for trial, seed in enumerate(seeds):
            frame, counts = audit.replay_trial(
                merged,
                branch="constant",
                shard=0,
                trial=trial,
                global_trial=trial,
                trial_seed=seed,
                measurement_error_mode=mode,
            )
            frames.append(frame)
            diagnostics.append(
                {
                    "trial": trial,
                    "shard": 0,
                    "global_trial": trial,
                    "seed": seed,
                    "perturbation_seed": seed,
                    "mcmc_seed": seed + 3,
                    "measurement_error_mode": mode,
                    "selected_after_domain": counts["n_retained_by_active_policy"],
                    "perturbation_counts": counts,
                }
            )
        pd.concat(frames, ignore_index=True).to_csv(
            aggregate / "perturbation_audit_constant_full.csv.gz",
            index=False,
            compression={"method": "gzip", "mtime": 0},
        )
        diagnostics_path = aggregate / "trial_diagnostics_constant_full.jsonl"
        diagnostics_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in diagnostics),
            encoding="utf-8",
            newline="\n",
        )
        pc_sha = digest(pc)
        pc_size = pc.stat().st_size
        stellar_sha = digest(stellar)
        stellar_size = stellar.stat().st_size
        locks = root / "DATA_LOCKS.json"
        locks.write_text(
            json.dumps(
                {
                    "locks": {
                        audit.PC_LOCK_ID: {
                            "filename": pc.name,
                            "expected_sha256": pc_sha,
                            "expected_size_bytes": pc_size,
                        },
                        audit.STELLAR_LOCK_ID: {
                            "filename": stellar.name,
                            "expected_sha256": stellar_sha,
                            "expected_size_bytes": stellar_size,
                        },
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return {
            "pc": pc,
            "stellar": stellar,
            "aggregate": aggregate,
            "locks": locks,
            "diagnostics": diagnostics_path,
            "mode": mode,
            "pc_sha": pc_sha,
            "pc_size": pc_size,
            "stellar_sha": stellar_sha,
            "stellar_size": stellar_size,
        }

    def verify(self, fixture: dict[str, Path]) -> dict:
        with mock.patch.multiple(
            audit,
            PC_SHA256=fixture["pc_sha"],
            PC_SIZE_BYTES=fixture["pc_size"],
            STELLAR_SHA256=fixture["stellar_sha"],
            STELLAR_SIZE_BYTES=fixture["stellar_size"],
        ):
            return audit.verify_catalog_perturbations(
                branch="constant",
                aggregate_root=fixture["aggregate"],
                pc_catalog=fixture["pc"],
                stellar_catalog=fixture["stellar"],
                data_locks_path=fixture["locks"],
                expected_trials=2,
                measurement_error_mode=fixture["mode"],
            )

    def test_exact_reconstruction_and_report_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.build_fixture(root)
            report = self.verify(fixture)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["trials_verified"], 2)
            self.assertEqual(report["merged_catalog_rows"], 3)
            output = root / "report"
            report_path, manifest_path = audit.write_report(report, output)
            self.assertTrue(report_path.is_file())
            self.assertIn(digest(report_path), manifest_path.read_text(encoding="utf-8"))

    def test_legacy_source_mode_is_replayed_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary), audit.LEGACY_MODE)
            report = self.verify(fixture)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["measurement_error_mode"], audit.LEGACY_MODE)

    def test_independent_replay_matches_production_measurement_module(self) -> None:
        catalog = pd.DataFrame(
            {
                "source_row": [0, 1, 2, 3],
                "kepoi_name": ["A", "B", "C", "D"],
                "kepid_x": [1, 2, 3, 4],
                "totalReliability": [1.0, 0.8, 0.4, 0.0],
                "koi_period": [20.0, 40.0, 80.0, 160.0],
                "gaia_iso_insol": [1.0, 2.1, 0.22, 1.2],
                "gaia_iso_insol_errm": [0.1, 0.2, 0.03, 0.1],
                "gaia_iso_insol_errp": [0.2, 0.3, 0.04, 0.1],
                "gaia_iso_prad": [1.0, 2.4, 0.55, 1.4],
                "gaia_iso_prad_errm": [0.1, 0.2, 0.04, 0.1],
                "gaia_iso_prad_errp": [0.2, 0.3, 0.05, 0.1],
                "teff": [5700.0, 6250.0, 3920.0, 5000.0],
                "teff_err2": [60.0, 100.0, 50.0, 70.0],
                "teff_err1": [70.0, 120.0, 60.0, 80.0],
            }
        )
        for mode in (audit.CORRECTED_MODE, audit.LEGACY_MODE):
            seed = 90210
            np.random.seed(seed)
            production = measurement.perturb_planets(
                catalog,
                rng=np.random,
                instellation_range=(0.2, 2.2),
                radius_range=(0.5, 2.5),
                teff_range=(3900.0, 6300.0),
                period_max_days=None,
                mode=mode,
            )
            reconstructed, counts = audit.replay_trial(
                catalog,
                branch="constant",
                shard=0,
                trial=0,
                global_trial=0,
                trial_seed=seed,
                measurement_error_mode=mode,
            )
            observed = production.audit.copy()
            observed.insert(0, "trial_seed", seed)
            observed.insert(0, "global_trial", 0)
            observed.insert(0, "trial", 0)
            observed.insert(0, "shard", 0)
            observed.insert(0, "measurement_error_mode", mode)
            observed.insert(0, "run_label", "production-shard-0")
            observed.insert(0, "branch", "constant")
            audit.compare_frames(reconstructed, observed.loc[:, list(audit.AUDIT_COLUMNS)])
            self.assertEqual(counts, production.counts)

    def test_removed_selected_row_fails_after_audit_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary))
            path = fixture["aggregate"] / "perturbation_audit_constant_full.csv.gz"
            frame = pd.read_csv(path)
            frame.iloc[1:].to_csv(
                path,
                index=False,
                compression={"method": "gzip", "mtime": 0},
            )
            with self.assertRaisesRegex(audit.CatalogAuditError, "row count differs"):
                self.verify(fixture)

    def test_source_field_mutation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary))
            path = fixture["aggregate"] / "perturbation_audit_constant_full.csv.gz"
            frame = pd.read_csv(path)
            frame.loc[0, "totalReliability"] += 0.01
            frame.to_csv(
                path,
                index=False,
                compression={"method": "gzip", "mtime": 0},
            )
            with self.assertRaisesRegex(
                audit.CatalogAuditError, "totalReliability"
            ):
                self.verify(fixture)

    def test_duplicate_diagnostic_key_and_overflow_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary))
            lines = fixture["diagnostics"].read_text(encoding="utf-8").splitlines()
            first = lines[0][:-1] + ',"seed":1701,"unused":1e999}'
            fixture["diagnostics"].write_text(
                first + "\n" + lines[1] + "\n", encoding="utf-8", newline="\n"
            )
            with self.assertRaises(audit.CatalogAuditError):
                self.verify(fixture)

    def test_locked_catalog_byte_change_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary))
            with fixture["pc"].open("ab") as handle:
                handle.write(b"\n")
            with self.assertRaisesRegex(audit.CatalogAuditError, "SHA-256 mismatch"):
                self.verify(fixture)

    def test_self_consistent_arbitrary_seed_schedule_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary), seeds=(42, 777))
            with self.assertRaisesRegex(
                audit.CatalogAuditError, "perturbation-seed schedule mismatch"
            ):
                self.verify(fixture)

    def test_legacy_zero_combination_is_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.build_fixture(Path(temporary), audit.LEGACY_MODE)
            with mock.patch.multiple(
                audit,
                PC_SHA256=fixture["pc_sha"],
                PC_SIZE_BYTES=fixture["pc_size"],
                STELLAR_SHA256=fixture["stellar_sha"],
                STELLAR_SIZE_BYTES=fixture["stellar_size"],
            ):
                with self.assertRaisesRegex(
                    audit.CatalogAuditError, "only for the constant branch"
                ):
                    audit.verify_catalog_perturbations(
                        branch="zero",
                        aggregate_root=fixture["aggregate"],
                        pc_catalog=fixture["pc"],
                        stellar_catalog=fixture["stellar"],
                        data_locks_path=fixture["locks"],
                        expected_trials=2,
                        measurement_error_mode=audit.LEGACY_MODE,
                    )


if __name__ == "__main__":
    unittest.main()
