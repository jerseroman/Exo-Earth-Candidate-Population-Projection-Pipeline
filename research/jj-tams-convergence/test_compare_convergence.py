#!/usr/bin/env python3
"""Direct and adversarial tests for radial-convergence comparison."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compare_convergence", HERE / "compare_convergence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load compare_convergence.py")
compare = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare
SPEC.loader.exec_module(compare)

HOST_SPEC = importlib.util.spec_from_file_location(
    "host_tams_audit_for_radial_test", HERE.parent / "v4-validation" / "host_tams_audit.py"
)
if HOST_SPEC is None or HOST_SPEC.loader is None:
    raise RuntimeError("cannot load host_tams_audit.py")
host_audit = importlib.util.module_from_spec(HOST_SPEC)
sys.modules[HOST_SPEC.name] = host_audit
HOST_SPEC.loader.exec_module(host_audit)


class RadialConvergenceTests(unittest.TestCase):
    def fixture(self, root: Path, dr: float = 0.5) -> tuple[Path, dict]:
        radial = root / f"tams_radial_dr{compare.tag(dr)}.csv"
        rows = []
        count = int(round((14.0 - 4.0) / dr)) + 1
        for index in range(count):
            radius = 4.0 + index * dr
            sigma = 10.0 + radius
            dndr = 2.0 * math.pi * radius * 1.0e6 * sigma
            rows.append(
                {
                    "R_kpc": radius,
                    "dN_dR": dndr,
                    "dL1_dR": 0.4 * dndr,
                    "dL2_dR": 0.05 * dndr,
                    "Sigma_TAMS_pc-2": sigma,
                    "Sigma_thick_TAMS_pc-2": 0.2 * sigma,
                }
            )
        with radial.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(compare.RADIAL_COLUMNS))
            writer.writeheader()
            writer.writerows(rows)
        parsed = compare.read_radial_table(radial, dr)
        domains = {}
        for name, lo, hi in (
            ("lineweaver_7_9", 7.0, 9.0),
            ("full_JJ_4_14", 4.0, 14.0),
        ):
            n_g = compare.integrate_rows(parsed, "dN_dR", lo, hi)
            hz = compare.integrate_rows(parsed, "dL1_dR", lo, hi)
            earth = compare.integrate_rows(parsed, "dL2_dR", lo, hi)
            domains[name] = {
                "R_kpc": [lo, hi],
                "N_G": n_g,
                "Lambda_ESHZ": hz,
                "Lambda_earth10": earth,
                "mean_f_HZ": hz / n_g,
                "mean_f_earth10": earth / n_g,
                "L2_over_L1": earth / hz,
            }
        result = {
            "experiment": "final_TAMS_radial_convergence",
            "jj_commit": compare.JJ_SHA,
            "isochrone_family": "Padova",
            "dR_kpc": dr,
            "radial_nodes": len(rows),
            "host_selector": compare.EXPECTED_SELECTOR,
            "occurrence_branch": compare.EXPECTED_OCCURRENCE_BRANCH,
            "selected_stellar_assembly_rows": 42,
            "compact_remnant_rows_rejected": 2,
            "compact_remnant_surface_weight_rejected_sum_pc-2": 0.25,
            "C1": compare.EXPECTED_C1,
            "domains": domains,
        }
        return radial, result

    def canonical_anchor_fixture(self, root: Path, dr: float) -> tuple[Path, dict]:
        radial = root / f"tams_radial_dr{compare.tag(dr)}.csv"
        lineweaver_width = 2.0
        dndr = 263_061_992.36674243 / lineweaver_width
        dl1dr = 105_716_685.0799756 / lineweaver_width
        dl2dr = 3_376_462.6740267016 / lineweaver_width
        count = int(round((14.0 - 4.0) / dr)) + 1
        rows = []
        for index in range(count):
            radius = 4.0 + index * dr
            sigma = dndr / (2.0 * math.pi * radius * 1.0e6)
            rows.append(
                {
                    "R_kpc": radius,
                    "dN_dR": dndr,
                    "dL1_dR": dl1dr,
                    "dL2_dR": dl2dr,
                    "Sigma_TAMS_pc-2": sigma,
                    "Sigma_thick_TAMS_pc-2": 0.2 * sigma,
                }
            )
        with radial.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(compare.RADIAL_COLUMNS))
            writer.writeheader()
            writer.writerows(rows)
        parsed = compare.read_radial_table(radial, dr)
        domains = {}
        for name, lo, hi in (
            ("lineweaver_7_9", 7.0, 9.0),
            ("full_JJ_4_14", 4.0, 14.0),
        ):
            n_g = compare.integrate_rows(parsed, "dN_dR", lo, hi)
            hz = compare.integrate_rows(parsed, "dL1_dR", lo, hi)
            earth = compare.integrate_rows(parsed, "dL2_dR", lo, hi)
            domains[name] = {
                "R_kpc": [lo, hi],
                "N_G": n_g,
                "Lambda_ESHZ": hz,
                "Lambda_earth10": earth,
                "mean_f_HZ": hz / n_g,
                "mean_f_earth10": earth / n_g,
                "L2_over_L1": earth / hz,
            }
        return radial, {
            "experiment": "final_TAMS_radial_convergence",
            "jj_commit": compare.JJ_SHA,
            "isochrone_family": "Padova",
            "dR_kpc": dr,
            "radial_nodes": len(rows),
            "host_selector": compare.EXPECTED_SELECTOR,
            "occurrence_branch": compare.EXPECTED_OCCURRENCE_BRANCH,
            "selected_stellar_assembly_rows": 42,
            "compact_remnant_rows_rejected": 2,
            "compact_remnant_surface_weight_rejected_sum_pc-2": 0.25,
            "C1": compare.EXPECTED_C1,
            "domains": domains,
        }

    def test_result_is_rederived_from_radial_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            radial, result = self.fixture(Path(temporary))
            rows = compare.validate_run_result(result, radial, 0.5)
            self.assertEqual(len(rows), 21)

    def test_rehashed_self_consistent_json_cannot_override_radial_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            radial, result = self.fixture(Path(temporary))
            result["domains"]["lineweaver_7_9"]["N_G"] += 1.0e6
            with self.assertRaisesRegex(RuntimeError, "does not derive from CSV"):
                compare.validate_run_result(result, radial, 0.5)

    def test_radial_geometry_and_grid_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            radial, _ = self.fixture(Path(temporary))
            with radial.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            rows[3]["dN_dR"] = str(float(rows[3]["dN_dR"]) * 1.01)
            with radial.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(compare.RADIAL_COLUMNS))
                writer.writeheader()
                writer.writerows(rows)
            with self.assertRaisesRegex(RuntimeError, "geometry mismatch"):
                compare.read_radial_table(radial, 0.5)

    def test_strict_json_rejects_duplicate_and_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text('{"dR_kpc":0.5,"dR_kpc":1.0,"unused":1e999}\n')
            with self.assertRaises(RuntimeError):
                compare.load_strict_json(path)

    def test_stable_copy_rejects_final_component_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            replacement = root / "replacement"
            destination = root / "destination"
            source.write_bytes(b"first bytes")
            replacement.write_bytes(b"other bytes with a different identity")
            real_open = compare.os.open
            swapped = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path) == source and not swapped:
                    try:
                        source.unlink()
                        source.symlink_to(replacement)
                    except OSError as exc:
                        self.skipTest(f"symlink creation unavailable: {exc}")
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(compare.os, "open", side_effect=racing_open):
                with self.assertRaises(RuntimeError):
                    compare.stable_copy(source, destination)

    def test_runtime_parameters_and_sfr_are_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "parameters.original"
            runtime = root / "parameters.runtime"
            sfr = root / "sfrd_peaks_parameters"
            original_bytes = (
                b"header\nRmin 4 unit\nRmax 14 unit\ndR 1 unit\n"
                b"nprocess 4 unit\nfooter\n"
            )
            sfr_bytes = b"locked SFR configuration\n"
            original.write_bytes(original_bytes)
            runtime.write_bytes(compare.expected_runtime_parameters(original_bytes, 0.5))
            sfr.write_bytes(sfr_bytes)
            destinations = {
                "parameters_original": original,
                "parameters_runtime": runtime,
                "sfr_peaks_parameters": sfr,
            }
            with mock.patch.multiple(
                compare,
                TUTORIAL_PARAMETERS_SHA256=hashlib.sha256(original_bytes).hexdigest(),
                TUTORIAL_SFR_SHA256=hashlib.sha256(sfr_bytes).hexdigest(),
            ):
                compare.validate_runtime_inputs(destinations, 0.5)
                sfr.write_bytes(b"changed SFR\n")
                with self.assertRaisesRegex(RuntimeError, "sfrd_peaks_parameters"):
                    compare.validate_runtime_inputs(destinations, 0.5)

    def test_comparator_contract_passes_host_root_verifier_with_exact_sfr_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runs"
            root.mkdir()
            original_bytes = (
                b"Rmin 4 unit\nRmax 14 unit\ndR 1 unit\n"
                b"nprocess 4 unit\nscience_option fixed unit\n"
            )
            sfr_bytes = b"locked SFR configuration\n"
            runtime = {
                "schema_version": 1,
                "status": "PASS",
                "numpy_version": "1.23.5",
                "environment": {
                    "NPY_DISABLE_CPU_FEATURES": (
                        "AVX512F,AVX512CD,AVX512_SKX,"
                        "AVX512_CLX,AVX512_CNL,AVX512_ICL"
                    ),
                    "OPENBLAS_NUM_THREADS": "1",
                    "OMP_NUM_THREADS": "1",
                    "MKL_NUM_THREADS": "1",
                    "NUMEXPR_NUM_THREADS": "1",
                    "PYTHONHASHSEED": "0",
                },
                "selected_cpu_features": {
                    "AVX2": True,
                    "FMA3": True,
                    "AVX512F": False,
                    "AVX512CD": False,
                    "AVX512_KNL": False,
                    "AVX512_KNM": False,
                    "AVX512_SKX": False,
                    "AVX512_CLX": False,
                    "AVX512_CNL": False,
                    "AVX512_ICL": False,
                },
            }
            (root / "NUMERICAL_RUNTIME_POLICY.json").write_text(
                json.dumps(runtime, allow_nan=False), encoding="utf-8"
            )
            for dr in compare.DRS:
                run_root = root / f"dr{compare.tag(dr)}"
                run_root.mkdir()
                _, result = self.canonical_anchor_fixture(run_root, dr)
                (run_root / "parameters.original").write_bytes(original_bytes)
                (run_root / "parameters.runtime").write_bytes(
                    compare.expected_runtime_parameters(original_bytes, dr)
                )
                (run_root / "sfrd_peaks_parameters").write_bytes(sfr_bytes)
                (run_root / f"tams_result_dr{compare.tag(dr)}.json").write_text(
                    json.dumps(result, allow_nan=False), encoding="utf-8"
                )

            sfr_hash = hashlib.sha256(sfr_bytes).hexdigest()
            with mock.patch.multiple(
                compare,
                TUTORIAL_PARAMETERS_SHA256=hashlib.sha256(original_bytes).hexdigest(),
                TUTORIAL_SFR_SHA256=sfr_hash,
            ), mock.patch.object(
                sys,
                "argv",
                ["compare_convergence.py", "--root", str(root), "--out", str(root)],
            ):
                compare.main()

            with mock.patch.object(host_audit, "TAMS_TUTORIAL_SFR_SHA256", sfr_hash):
                report, evidence = host_audit.validate_tams_radial_convergence_root(
                    root / compare.CONTRACT_DIR
                )
            self.assertTrue(report["pass"])
            self.assertEqual(
                set(evidence["validated_files"]), set(host_audit.tams_convergence_target_names())
            )
            for dr in compare.DRS:
                self.assertIn(
                    f"sfrd_peaks_parameters_dr{compare.tag(dr)}.txt",
                    evidence["validated_files"],
                )


if __name__ == "__main__":
    unittest.main()
