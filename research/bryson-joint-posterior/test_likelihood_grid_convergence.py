#!/usr/bin/env python3
"""Adversarial tests for the 31/61/121 likelihood-grid audit."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import numpy as np
import pandas as pd


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "likelihood_grid_convergence", HERE / "likelihood_grid_convergence.py"
)
assert SPEC is not None and SPEC.loader is not None
grid = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = grid
SPEC.loader.exec_module(grid)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_posterior(rows: int = 400) -> pd.DataFrame:
    index = np.arange(rows, dtype=float)
    return pd.DataFrame(
        {
            "branch": "constant",
            "global_trial": np.arange(rows) // 40,
            "production_step": np.arange(rows) % 40,
            "walker": np.arange(rows) % 8,
            "F0": 1.2 + 0.3 * np.sin(index / 17.0),
            "alpha": -1.1 + 0.4 * np.cos(index / 23.0),
            "beta": -0.8 + 0.25 * np.sin(index / 31.0 + 0.2),
            "gamma": -2.0 + 0.8 * np.cos(index / 29.0 + 0.4),
        }
    )


class LikelihoodGridTests(unittest.TestCase):
    def test_snapshot_rejects_final_component_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            target = root / "target.bin"
            destination = root / "snapshot.bin"
            source.write_bytes(b"locked source")
            target.write_bytes(b"replacement target with different identity")
            real_open = grid.os.open
            replaced = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if Path(path) == source and not replaced:
                    try:
                        source.unlink()
                        source.symlink_to(target)
                    except OSError as exc:
                        self.skipTest(f"symlink creation unavailable: {exc}")
                    replaced = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(grid.os, "open", side_effect=racing_open):
                with self.assertRaises(grid.GridAuditError):
                    grid.snapshot_file(source, destination, "race-test source")

    def test_diagonal_and_four_corner_rules_are_independently_evaluated(self) -> None:
        class Space:
            nTemp = 1
            period2D = np.zeros((2, 2), dtype=float)
            rp2D = np.zeros((2, 2), dtype=float)
            periodRange = (0.2, 2.2)
            rpRange = (0.5, 2.5)
            tempRange = (3900.0, 6300.0)
            vol2D = np.ones((1, 1), dtype=float)

        class Model:
            @staticmethod
            def rateModel(*_args):
                return np.asarray([[1.0, 2.0], [4.0, 8.0]])

        completeness = np.ones((2, 2, 1), dtype=float)
        theta = np.asarray([1.0, -1.0, -1.0, -2.0])
        diagonal = grid.expected_count(
            theta, Space(), Model(), completeness, np.asarray([5780.0])
        )
        four_corner = grid.expected_count(
            theta,
            Space(),
            Model(),
            completeness,
            np.asarray([5780.0]),
            cell_rule="four_corner_trapezoid",
        )
        self.assertEqual(diagonal, 4.5)
        self.assertEqual(four_corner, 3.75)
        with self.assertRaises(grid.GridAuditError):
            grid.expected_count(
                theta,
                Space(),
                Model(),
                completeness,
                np.asarray([5780.0]),
                cell_rule="unknown",
            )

    def test_joint_selection_is_deterministic_and_uses_actual_rows(self) -> None:
        posterior = grid.validate_posterior(synthetic_posterior(), "constant")
        first = grid.select_joint_parameter_rows(posterior)
        second = grid.select_joint_parameter_rows(posterior.sample(frac=1.0, random_state=4))
        self.assertGreaterEqual(len(first), 5)
        self.assertLessEqual(len(first), 17)
        self.assertEqual(int(first["is_central"].sum()), 1)
        self.assertEqual(
            set(map(tuple, first.loc[:, list(grid.PARAMETERS)].to_numpy())),
            set(map(tuple, second.loc[:, list(grid.PARAMETERS)].to_numpy())),
        )
        posterior_rows = set(
            map(tuple, posterior.loc[:, list(grid.PARAMETERS)].to_numpy())
        )
        self.assertTrue(
            set(map(tuple, first.loc[:, list(grid.PARAMETERS)].to_numpy())).issubset(
                posterior_rows
            )
        )

    def test_result_thresholds_are_recomputed(self) -> None:
        posterior = grid.validate_posterior(synthetic_posterior(), "constant")
        selected = grid.select_joint_parameter_rows(posterior)
        base = np.linspace(10.0, 12.0, len(selected))
        frame = grid.attach_results(
            selected,
            "constant",
            {31: list(base + 0.001), 61: list(base + 0.0005), 121: list(base)},
            list(base + 0.0001),
            True,
        )
        self.assertTrue(grid.summarize_results(frame)["accepted"])
        frame.loc[frame.index[0], "norm_121"] = frame.loc[frame.index[0], "norm_61"] + 1.0
        frame.loc[frame.index[0], "abs_delta_log_likelihood_61_121"] = 1.0
        frame.loc[frame.index[0], "relative_norm_delta_61_121"] = 1.0 / frame.loc[
            frame.index[0], "norm_121"
        ]
        self.assertFalse(grid.summarize_results(frame)["accepted"])

    def test_manifest_and_json_parsers_fail_closed(self) -> None:
        unsafe_names = (
            "/x",
            "a/b",
            r"a\b",
            "foo/../bar",
            "../escape",
            r"C:x",
            r"\\server\share\x",
            r"mixed/dir\escape",
            ".",
            "..",
            "escape/",
            "escape\\",
            "nul\x00escape",
        )
        self.assertTrue(grid.is_portable_safe_leaf("artifact.csv"))
        for unsafe_name in unsafe_names:
            with self.subTest(unsafe_name=repr(unsafe_name)):
                self.assertFalse(grid.is_portable_safe_leaf(unsafe_name))
                lock = {
                    "fixture": {
                        "expected_sha256": "0" * 64,
                        "expected_size_bytes": 1,
                        "filename": unsafe_name,
                    }
                }
                with self.assertRaises(grid.GridAuditError):
                    grid.locked_input(lock, "fixture")
                manifest = (
                    "0" * 64 + "  " + unsafe_name + "\n"
                ).encode("utf-8")
                with self.assertRaises(grid.GridAuditError):
                    grid.parse_manifest_bytes(manifest, "fixture")
        duplicate = (b"0" * 64 + b"  a.txt\n") * 2
        with self.assertRaises(grid.GridAuditError):
            grid.parse_manifest_bytes(duplicate, "fixture")
        with self.assertRaises(grid.GridAuditError):
            grid.strict_json_bytes(b'{"x":1e999}', "fixture")
        with self.assertRaises(grid.GridAuditError):
            grid.strict_json_bytes(b'{"x":1,"x":2}', "fixture")

    def test_exact_artifact_rebinds_selection_to_posterior(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            posterior_path = root / "joint_posterior_constant_full.csv.gz"
            posterior_source = synthetic_posterior()
            posterior_source.to_csv(
                posterior_path,
                index=False,
                compression={"method": "gzip", "mtime": 0},
                float_format="%.17g",
            )
            aggregate_manifest = root / "SHA256SUMS_constant_aggregate.txt"
            aggregate_manifest.write_text(
                f"{sha256(posterior_path)}  {posterior_path.name}\n",
                encoding="utf-8",
            )
            rate_model_source = root / "rateModels3D.py"
            rate_model_source.write_bytes(b"locked rate-model fixture\n")
            completeness_path = root / "constant.fits.gz"
            completeness_path.write_bytes(b"locked completeness fixture\n")
            locks_path = root / "DATA_LOCKS.json"
            locks_path.write_text(
                json.dumps(
                    {
                        "locks": {
                            "bryson_rate_models_3d": {
                                "filename": rate_model_source.name,
                                "expected_sha256": sha256(rate_model_source),
                                "expected_size_bytes": rate_model_source.stat().st_size,
                            },
                            "completeness_constant": {
                                "filename": completeness_path.name,
                                "expected_sha256": sha256(completeness_path),
                                "expected_size_bytes": completeness_path.stat().st_size,
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            posterior = grid.validate_posterior(
                pd.read_csv(posterior_path, float_precision="round_trip"),
                "constant",
            )
            selected = grid.select_joint_parameter_rows(posterior)
            base = np.linspace(10.0, 12.0, len(selected))
            result = grid.attach_results(
                selected,
                "constant",
                {31: list(base + 0.001), 61: list(base + 0.0005), 121: list(base)},
                list(base + 0.0001),
                True,
            )
            result.to_csv(
                artifact / grid.SELECTED_NAME,
                index=False,
                lineterminator="\n",
                float_format="%.17g",
            )
            locks = grid.load_data_locks(locks_path)
            source = grid.locked_input(locks, "bryson_rate_models_3d")
            completeness = grid.locked_input(locks, "completeness_constant")
            report = {
                "schema_version": 1,
                "status": "PASS",
                "branch": "constant",
                "method": grid._method(),
                "thresholds": grid._thresholds(),
                "inputs": {
                    "rate_model_source": {
                        "filename": source[2],
                        "sha256": source[0],
                        "size_bytes": source[1],
                        "lock_id": "bryson_rate_models_3d",
                    },
                    "completeness": {
                        "filename": completeness[2],
                        "sha256": completeness[0],
                        "size_bytes": completeness[1],
                        "lock_id": "completeness_constant",
                    },
                    "posterior": {
                        "filename": posterior_path.name,
                        "sha256": sha256(posterior_path),
                        "size_bytes": posterior_path.stat().st_size,
                        "row_count": len(posterior),
                    },
                    "aggregate_manifest": {
                        "filename": aggregate_manifest.name,
                        "sha256": sha256(aggregate_manifest),
                        "size_bytes": aggregate_manifest.stat().st_size,
                    },
                },
                "selected_points": {
                    "filename": grid.SELECTED_NAME,
                    "sha256": sha256(artifact / grid.SELECTED_NAME),
                    "size_bytes": (artifact / grid.SELECTED_NAME).stat().st_size,
                    "row_count": len(result),
                    "columns": list(grid.CSV_COLUMNS),
                },
                "results": grid.summarize_results(result),
                "runtime": {
                    "python": "3.10.12",
                    "platform": "fixture",
                    **grid.EXPECTED_LIBRARY_VERSIONS,
                    "environment": grid.EXPECTED_RUNTIME_ENVIRONMENT,
                },
            }
            (artifact / grid.REPORT_NAME).write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            grid.write_manifest(artifact)
            def verify_fixture() -> dict:
                with (
                    mock.patch.object(grid, "DATA_LOCKS_PATH", locks_path),
                    mock.patch.object(
                        grid, "load_rate_model_module", return_value=object()
                    ),
                    mock.patch.object(
                        grid, "load_completeness_arrays", return_value=object()
                    ),
                    mock.patch.object(
                        grid,
                        "evaluate_grids",
                        return_value=(
                            {
                                31: list(base + 0.001),
                                61: list(base + 0.0005),
                                121: list(base),
                            },
                            list(base + 0.0001),
                            True,
                        ),
                    ),
                ):
                    return grid._verify_likelihood_grid_artifact_in_snapshot_root(
                        artifact,
                        branch="constant",
                        posterior_path=posterior_path,
                        aggregate_manifest_path=aggregate_manifest,
                        rate_model_source_path=rate_model_source,
                        completeness_path=completeness_path,
                        temporary_root=root / "verification-snapshots",
                    )

            (root / "verification-snapshots").mkdir()
            verified = verify_fixture()
            self.assertEqual(verified["status"], "PASS")

            forged = grid.attach_results(
                selected,
                "constant",
                {31: list(base), 61: list(base), 121: list(base)},
                list(base),
                True,
            )
            forged.to_csv(
                artifact / grid.SELECTED_NAME,
                index=False,
                lineterminator="\n",
                float_format="%.17g",
            )
            report["selected_points"]["sha256"] = sha256(
                artifact / grid.SELECTED_NAME
            )
            report["selected_points"]["size_bytes"] = (
                artifact / grid.SELECTED_NAME
            ).stat().st_size
            report["results"] = grid.summarize_results(forged)
            (artifact / grid.REPORT_NAME).write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            grid.write_manifest(artifact)
            shutil.rmtree(root / "verification-snapshots")
            (root / "verification-snapshots").mkdir()
            with self.assertRaisesRegex(
                grid.GridAuditError, "numerical integrals differ"
            ):
                verify_fixture()

            result.to_csv(
                artifact / grid.SELECTED_NAME,
                index=False,
                lineterminator="\n",
                float_format="%.17g",
            )
            report["selected_points"]["sha256"] = sha256(
                artifact / grid.SELECTED_NAME
            )
            report["selected_points"]["size_bytes"] = (
                artifact / grid.SELECTED_NAME
            ).stat().st_size
            report["results"] = grid.summarize_results(result)

            result.loc[result.index[0], "F0"] += 0.01
            result.to_csv(
                artifact / grid.SELECTED_NAME,
                index=False,
                lineterminator="\n",
                float_format="%.17g",
            )
            report["selected_points"]["sha256"] = sha256(
                artifact / grid.SELECTED_NAME
            )
            report["selected_points"]["size_bytes"] = (
                artifact / grid.SELECTED_NAME
            ).stat().st_size
            (artifact / grid.REPORT_NAME).write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            grid.write_manifest(artifact)
            with self.assertRaisesRegex(
                grid.GridAuditError, "selected parameters differ"
            ):
                shutil.rmtree(root / "verification-snapshots")
                (root / "verification-snapshots").mkdir()
                verify_fixture()


if __name__ == "__main__":
    unittest.main()
