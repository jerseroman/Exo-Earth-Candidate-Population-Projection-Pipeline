from __future__ import annotations

import copy
import csv
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "scripts" / "verify_metallicity_tams_audit.py"
SPEC = importlib.util.spec_from_file_location("verify_metallicity_tams_audit", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {VERIFIER_PATH}")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MetallicityTamsAuditVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "metallicity-audit"
        self.root.mkdir()
        self.data_locks = self.base / "DATA_LOCKS.json"
        self.solar_lock = {
            "filename": "Z0.017Y0.279.tar.gz",
            "expected_size_bytes": 18109804,
            "expected_sha256": "a" * 64,
            "distribution_role": "fetch-only",
        }
        self.failure_lock = {
            "filename": "Z0.001Y0.25.tar.gz",
            "expected_size_bytes": 123456,
            "expected_sha256": "b" * 64,
            "distribution_role": "fetch-only",
        }
        self.unrelated_fetch_lock = {
            "filename": "unrelated-science-input.bin",
            "expected_size_bytes": 42,
            "expected_sha256": "d" * 64,
            "distribution_role": "fetch-only",
        }
        self.data_locks.write_text(
            json.dumps(
                {
                    "locks": {
                        "parsec_tracks_z0017": self.solar_lock,
                        "parsec_tracks_z0001": self.failure_lock,
                        "unrelated_fetch_input": self.unrelated_fetch_lock,
                    }
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self._write_runtime()
        self._write_solar()
        self._write_provenance()
        self._write_report()
        self._write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_runtime(self) -> None:
        report = {
            "schema_version": 1,
            "status": "PASS",
            "python": "3.10.21 (fixture)",
            "python_executable": "/locked/venv/bin/python",
            "platform": "Linux-fixture",
            "machine": "x86_64",
            "numpy_version": "1.23.5",
            "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
            "numpy_cpu_dispatch_build": ["AVX2", "AVX512_SKX"],
            "selected_cpu_features": {
                "AVX2": True,
                "AVX512CD": False,
                "AVX512F": False,
                "AVX512_KNL": False,
                "AVX512_KNM": False,
                "AVX512_CLX": False,
                "AVX512_CNL": False,
                "AVX512_ICL": False,
                "AVX512_SKX": False,
                "FMA3": True,
            },
            "environment": dict(audit.EXPECTED_NUMERICAL_ENV),
        }
        self._write_json(self.root / audit.RUNTIME_NAME, report)

    def _solar_rows(self) -> list[list[object]]:
        return [list(row) for row in audit.EXPECTED_SOLAR_NODES]

    def _write_solar(self, rows: list[list[object]] | None = None) -> None:
        with (self.root / audit.SOLAR_POINTS_NAME).open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(audit.EXPECTED_SOLAR_COLUMNS)
            writer.writerows(rows if rows is not None else self._solar_rows())

    def _write_provenance(self) -> None:
        (self.root / audit.PROVENANCE_NAME).write_bytes(
            audit.SOURCE_PROVENANCE.read_bytes()
        )

    def _base_report(self) -> dict[str, object]:
        solar_metrics = audit.validate_solar_csv(self.root / audit.SOLAR_POINTS_NAME)
        parent_feh = audit.mh_from_z(0.001)
        return {
            "schema_version": 3,
            "experiment": "differential_metallicity_PARSEC_TAMS_coverage_audit",
            "status": audit.EXPECTED_STATUS,
            "decision": audit.EXPECTED_DECISION,
            "reason": audit.EXPECTED_REASON,
            "parent_input": {
                "filename": audit.EXPECTED_PARENT_FILENAME,
                "sha256": "e" * 64,
                "size_bytes": 987654,
                "row_count": 321,
                "feh_min": parent_feh,
                "feh_max": parent_feh,
            },
            "low_mass_filter": copy.deepcopy(audit.EXPECTED_LOW_MASS_FILTER),
            "coverage_failures": [
                {
                    "Z": 0.001,
                    "archive": self.failure_lock["filename"],
                    "archive_lock_id": "parsec_tracks_z0001",
                    "archive_size_bytes": self.failure_lock["expected_size_bytes"],
                    "archive_sha256": self.failure_lock["expected_sha256"],
                    "error": (
                        "Z=0.001: low-mass TAMS coverage 5400.0..6100.0 K "
                        "does not span 5300.0..6000.0 K"
                    ),
                }
            ],
            "coverage_evidence": {
                "required_lock_ids": [
                    "parsec_tracks_z0001",
                    "parsec_tracks_z0017",
                ],
                "successful_lock_ids": ["parsec_tracks_z0017"],
                "failed_lock_ids": ["parsec_tracks_z0001"],
            },
            "correction_policy": copy.deepcopy(audit.EXPECTED_CORRECTION_POLICY),
            "native_solar_reference": {
                "status": "PASS",
                "role": "validation_only_not_a_metallicity_correction",
                "metallicity_Z": 0.017,
                "points_file": audit.SOLAR_POINTS_NAME,
                "points_sha256": sha256_file(self.root / audit.SOLAR_POINTS_NAME),
                "node_count": 9,
                "reference_validation_node_count": 7,
                "max_abs_temperature_difference_K": solar_metrics[
                    "max_abs_temperature_difference_K"
                ],
                "max_relative_radius_difference": solar_metrics[
                    "max_relative_radius_difference"
                ],
                "archive_lock_id": "parsec_tracks_z0017",
                "archive_filename": self.solar_lock["filename"],
                "archive_size_bytes": self.solar_lock["expected_size_bytes"],
                "archive_sha256": self.solar_lock["expected_sha256"],
            },
        }

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write_report(self, report: dict[str, object] | None = None) -> None:
        self._write_json(
            self.root / audit.REPORT_NAME,
            report if report is not None else self._base_report(),
        )

    def _read_report(self) -> dict[str, object]:
        return json.loads((self.root / audit.REPORT_NAME).read_text(encoding="utf-8"))

    def _write_manifest(self) -> None:
        lines = [
            f"{sha256_file(self.root / name)}  {name}\n"
            for name in sorted(audit.MANIFEST_TARGETS)
        ]
        (self.root / audit.MANIFEST_NAME).write_text(
            "".join(lines), encoding="utf-8", newline="\n"
        )

    def _save_report_and_manifest(self, report: dict[str, object]) -> None:
        self._write_report(report)
        self._write_manifest()

    def _refresh_solar_evidence(self) -> None:
        report = self._read_report()
        solar = report["native_solar_reference"]
        if not isinstance(solar, dict):
            raise RuntimeError("fixture native_solar_reference is not an object")
        solar["points_sha256"] = sha256_file(self.root / audit.SOLAR_POINTS_NAME)
        self._save_report_and_manifest(report)

    def verify(self) -> dict[str, object]:
        return audit.verify_artifact(self.root, self.data_locks)

    def test_valid_exact_five_file_negative_artifact_passes(self) -> None:
        report = self.verify()
        self.assertEqual(report["status"], "FAIL_NOT_PUBLISHABLE")
        self.assertEqual(set(path.name for path in self.root.iterdir()), audit.EXPECTED_FILES)

    def test_repository_registry_contains_the_exact_twelve_parsec_locks(self) -> None:
        registry = json.loads(
            (ROOT / "provenance" / "DATA_LOCKS.json").read_text(encoding="utf-8")
        )["locks"]
        self.assertEqual(len(audit.PARSEC_LOCK_METALLICITIES), 12)
        for lock_id in audit.PARSEC_LOCK_METALLICITIES:
            with self.subTest(lock_id=lock_id):
                self.assertIn(lock_id, registry)
                self.assertEqual(registry[lock_id]["distribution_role"], "fetch-only")

    def test_every_nonnegative_correction_policy_is_rejected(self) -> None:
        baseline = self._read_report()
        mutations = (
            ("applied", True),
            ("publishable", True),
            ("emitted_files", ["correction.csv"]),
            ("applied", 0),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                report = copy.deepcopy(baseline)
                policy = report["correction_policy"]
                if not isinstance(policy, dict):
                    raise RuntimeError("fixture correction_policy is not an object")
                policy[key] = value
                self._save_report_and_manifest(report)
                with self.assertRaisesRegex(audit.AuditError, "correction policy"):
                    self.verify()

    def test_empty_and_unlocked_coverage_failures_are_rejected(self) -> None:
        baseline = self._read_report()
        report = copy.deepcopy(baseline)
        report["coverage_failures"] = []
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "non-empty"):
            self.verify()

        report = copy.deepcopy(baseline)
        failures = report["coverage_failures"]
        if not isinstance(failures, list) or not isinstance(failures[0], dict):
            raise RuntimeError("fixture coverage_failures is invalid")
        failures[0].update(
            {
                "archive": self.unrelated_fetch_lock["filename"],
                "archive_lock_id": "unrelated_fetch_input",
                "archive_size_bytes": self.unrelated_fetch_lock["expected_size_bytes"],
                "archive_sha256": self.unrelated_fetch_lock["expected_sha256"],
            }
        )
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "recognized PARSEC track lock"):
            self.verify()

        report = copy.deepcopy(baseline)
        failures = report["coverage_failures"]
        if not isinstance(failures, list) or not isinstance(failures[0], dict):
            raise RuntimeError("fixture coverage_failures is invalid")
        failures[0]["archive_sha256"] = "c" * 64
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "differs from its data lock"):
            self.verify()

        report = copy.deepcopy(baseline)
        failures = report["coverage_failures"]
        if not isinstance(failures, list) or not isinstance(failures[0], dict):
            raise RuntimeError("fixture coverage_failures is invalid")
        failures[0]["Z"] = 0.002
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "does not match its PARSEC lock"):
            self.verify()

    def test_solar_hash_count_and_lock_drift_are_rejected(self) -> None:
        baseline = self._read_report()
        mutations = (
            ("points_sha256", "c" * 64, "points SHA-256"),
            ("node_count", 8, "node_count"),
            ("archive_sha256", "c" * 64, "data lock"),
            ("archive_size_bytes", 1, "data lock"),
            ("archive_lock_id", "parsec_tracks_z0001", "Z=0.017 archive"),
        )
        for key, value, message in mutations:
            with self.subTest(key=key):
                report = copy.deepcopy(baseline)
                solar = report["native_solar_reference"]
                if not isinstance(solar, dict):
                    raise RuntimeError("fixture native_solar_reference is not an object")
                solar[key] = value
                self._save_report_and_manifest(report)
                with self.assertRaisesRegex(audit.AuditError, message):
                    self.verify()

    def test_solar_table_metallicity_filter_and_monotonicity_are_enforced(self) -> None:
        baseline_rows = self._solar_rows()
        mutations = (
            (0, 0, 0.018, "not Z=0.017"),
            (0, 5, 2.1, "invalid mass"),
            (0, 4, 10.0, "invalid radius"),
            (1, 4, 0.9, "not strictly increasing"),
        )
        for row_index, column_index, value, message in mutations:
            with self.subTest(row=row_index, column=column_index):
                rows = copy.deepcopy(baseline_rows)
                rows[row_index][column_index] = value
                self._write_solar(rows)
                self._refresh_solar_evidence()
                with self.assertRaisesRegex(audit.AuditError, message):
                    self.verify()

    def test_source_names_use_portable_leaf_rules_on_every_host(self) -> None:
        unsafe_names = (
            "/x",
            "a/b",
            r"a\b",
            "foo/../bar",
            "../source.DAT",
            r"C:x",
            r"\\server\share\x",
            r"mixed/dir\source.DAT",
            ".",
            "..",
            "source.DAT/",
            "source.DAT\\",
            "source\x00.DAT",
        )
        self.assertTrue(audit.is_portable_safe_leaf("source.DAT"))
        for unsafe_name in unsafe_names:
            with self.subTest(unsafe_name=repr(unsafe_name)):
                self.assertFalse(audit.is_portable_safe_leaf(unsafe_name))

        for unsafe_name in ("/tmp/source.DAT", r"C:\temp\source.DAT"):
            with self.subTest(integrated_name=repr(unsafe_name)):
                rows = self._solar_rows()
                rows[0][6] = unsafe_name
                self._write_solar(rows)
                with self.assertRaisesRegex(
                    audit.AuditError, "unsafe native solar TAMS source filename"
                ):
                    audit.validate_solar_csv(self.root / audit.SOLAR_POINTS_NAME)

    def test_all_nine_locked_solar_nodes_are_authenticated(self) -> None:
        for row_index, column_index, value in (
            (0, 3, 5150.0),
            (0, 4, 0.5),
            (1, 5, 2.0),
            (1, 7, 29.0),
            (4, 2, 0.0),
            (8, 6, "forged.DAT"),
        ):
            with self.subTest(row=row_index, column=column_index):
                rows = self._solar_rows()
                rows[row_index][column_index] = value
                self._write_solar(rows)
                self._refresh_solar_evidence()
                with self.assertRaisesRegex(audit.AuditError, "locked"):
                    self.verify()

    def test_solar_success_cannot_also_be_a_coverage_failure(self) -> None:
        report = self._read_report()
        failures = report["coverage_failures"]
        evidence = report["coverage_evidence"]
        if not isinstance(failures, list) or not isinstance(failures[0], dict):
            raise RuntimeError("fixture coverage_failures is invalid")
        if not isinstance(evidence, dict):
            raise RuntimeError("fixture coverage_evidence is invalid")
        failures[0] = {
            "Z": 0.017,
            "archive": self.solar_lock["filename"],
            "archive_lock_id": "parsec_tracks_z0017",
            "archive_size_bytes": self.solar_lock["expected_size_bytes"],
            "archive_sha256": self.solar_lock["expected_sha256"],
            "error": (
                "Z=0.017: low-mass TAMS coverage 5400.0..6100.0 K "
                "does not span 5300.0..6000.0 K"
            ),
        }
        evidence["successful_lock_ids"] = ["parsec_tracks_z0001"]
        evidence["failed_lock_ids"] = ["parsec_tracks_z0017"]
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "solar PARSEC lock"):
            self.verify()

    def test_parent_binding_and_coverage_partition_are_fail_closed(self) -> None:
        baseline = self._read_report()

        report = copy.deepcopy(baseline)
        parent = report["parent_input"]
        if not isinstance(parent, dict):
            raise RuntimeError("fixture parent_input is invalid")
        parent["sha256"] = "not-a-digest"
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "parent input SHA-256"):
            self.verify()

        report = copy.deepcopy(baseline)
        parent = report["parent_input"]
        if not isinstance(parent, dict):
            raise RuntimeError("fixture parent_input is invalid")
        parent["feh_max"] = audit.mh_from_z(0.004)
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "required locks"):
            self.verify()

        report = copy.deepcopy(baseline)
        evidence = report["coverage_evidence"]
        if not isinstance(evidence, dict):
            raise RuntimeError("fixture coverage_evidence is invalid")
        evidence["successful_lock_ids"] = []
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "exhaustive"):
            self.verify()

    def test_arbitrary_or_nonfailing_coverage_error_is_rejected(self) -> None:
        baseline = self._read_report()
        for error in (
            "download failed",
            "Z=0.001: insufficient low-mass TAMS points (4)",
            (
                "Z=0.001: low-mass TAMS coverage 5200.0..6100.0 K "
                "does not span 5300.0..6000.0 K"
            ),
        ):
            with self.subTest(error=error):
                report = copy.deepcopy(baseline)
                failures = report["coverage_failures"]
                if not isinstance(failures, list) or not isinstance(failures[0], dict):
                    raise RuntimeError("fixture coverage_failures is invalid")
                failures[0]["error"] = error
                self._save_report_and_manifest(report)
                with self.assertRaisesRegex(audit.AuditError, "coverage failure"):
                    self.verify()

    def test_wrong_solar_node_number_is_rejected(self) -> None:
        self._write_solar(self._solar_rows()[:-1])
        self._refresh_solar_evidence()
        with self.assertRaisesRegex(audit.AuditError, "exactly 9 rows"):
            self.verify()

    def test_all_forbidden_correction_names_reject_files_directories_and_symlinks(self) -> None:
        for name in sorted(audit.FORBIDDEN_CORRECTION_FILES):
            for kind in ("file", "directory", "symlink"):
                with self.subTest(name=name, kind=kind):
                    path = self.root / name
                    try:
                        if kind == "file":
                            path.write_text("forbidden\n", encoding="utf-8")
                        elif kind == "directory":
                            path.mkdir()
                        else:
                            try:
                                os.symlink("missing-correction-target", path)
                            except (OSError, NotImplementedError) as exc:
                                self.skipTest(f"symlinks unavailable: {exc}")
                        with self.assertRaisesRegex(
                            audit.AuditError, "forbidden correction artifact"
                        ):
                            self.verify()
                    finally:
                        if path.is_symlink() or path.is_file():
                            path.unlink()
                        elif path.is_dir():
                            path.rmdir()

    def test_extra_root_entry_is_rejected(self) -> None:
        (self.root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "exact five-file set"):
            self.verify()

    def test_manifest_traversal_duplicate_and_hash_mismatch_are_rejected(self) -> None:
        manifest = self.root / audit.MANIFEST_NAME
        baseline = manifest.read_text(encoding="utf-8").splitlines()
        variants = (
            [baseline[0].replace("  ", "  ../", 1), *baseline[1:]],
            [*baseline, baseline[0]],
            ["0" + baseline[0][1:], *baseline[1:]],
        )
        messages = ("invalid manifest line", "duplicate manifest entry", "SHA-256 mismatch")
        for lines, message in zip(variants, messages):
            with self.subTest(message=message):
                manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(audit.AuditError, message):
                    self.verify()

    def test_runtime_environment_feature_and_boolean_type_drift_are_rejected(self) -> None:
        runtime_path = self.root / audit.RUNTIME_NAME
        baseline = json.loads(runtime_path.read_text(encoding="utf-8"))
        variants = []
        value = copy.deepcopy(baseline)
        value["environment"]["OMP_NUM_THREADS"] = "2"
        variants.append((value, "environment differs"))
        value = copy.deepcopy(baseline)
        value["selected_cpu_features"]["AVX512_SKX"] = True
        variants.append((value, "feature state differs"))
        value = copy.deepcopy(baseline)
        value["selected_cpu_features"]["AVX2"] = 1
        variants.append((value, "must be JSON booleans"))
        value = copy.deepcopy(baseline)
        value["schema_version"] = True
        variants.append((value, "not schema-1 PASS"))
        for runtime, message in variants:
            with self.subTest(message=message):
                self._write_json(runtime_path, runtime)
                self._write_manifest()
                with self.assertRaisesRegex(audit.AuditError, message):
                    self.verify()

    def test_every_avx512_dispatch_target_must_be_disabled(self) -> None:
        runtime_path = self.root / audit.RUNTIME_NAME
        baseline = json.loads(runtime_path.read_text(encoding="utf-8"))
        for feature in sorted(
            name
            for name, expected in audit.EXPECTED_REQUIRED_CPU_FEATURE_STATES.items()
            if name.startswith("AVX512") and expected is False
        ):
            runtime = copy.deepcopy(baseline)
            runtime["selected_cpu_features"][feature] = True
            self._write_json(runtime_path, runtime)
            self._write_manifest()
            with self.subTest(feature=feature), self.assertRaisesRegex(
                audit.AuditError, "feature state differs"
            ):
                self.verify()

    def test_duplicate_keys_nonfinite_json_and_extra_report_keys_are_rejected(self) -> None:
        report_path = self.root / audit.REPORT_NAME
        baseline = report_path.read_text(encoding="utf-8")
        duplicate = '{\n  "status": "FAIL_NOT_PUBLISHABLE",' + baseline[1:]
        report_path.write_text(duplicate, encoding="utf-8")
        self._write_manifest()
        with self.assertRaisesRegex(audit.AuditError, "duplicate JSON key"):
            self.verify()

        report = self._base_report()
        report["schema_version"] = float("nan")
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "non-finite JSON"):
            self.verify()

        report = self._base_report()
        report["unexpected"] = "not allowed"
        self._save_report_and_manifest(report)
        with self.assertRaisesRegex(audit.AuditError, "key set changed"):
            self.verify()

    def test_provenance_must_state_negative_validation_and_solar_role(self) -> None:
        (self.root / audit.PROVENANCE_NAME).write_text(
            "incomplete provenance\n", encoding="utf-8"
        )
        self._write_manifest()
        with self.assertRaisesRegex(audit.AuditError, "differs from its reviewable source"):
            self.verify()

    def test_reviewable_source_provenance_is_copied_by_the_workflow(self) -> None:
        source = ROOT / "research" / "jj-host-export" / audit.PROVENANCE_NAME
        text = source.read_text(encoding="utf-8")
        self.assertIn(audit.EXPECTED_STATUS, text)
        self.assertIn("No metallicity-dependent TAMS correction", text)
        self.assertIn("validation-only solar", text)
        workflow = (
            ROOT / ".github" / "workflows" / "jj-tams-metallicity-differential.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("cat > results/metallicity-audit", workflow)
        self.assertIn(
            "research/jj-host-export/PROVENANCE_METALLICITY_DIFFERENTIAL.md",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
