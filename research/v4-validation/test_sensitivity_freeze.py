from __future__ import annotations

import base64
import hashlib
import json
import math
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sensitivity_freeze as sensitivity


class SensitivityFreezeTests(unittest.TestCase):
    @staticmethod
    def computational_source(digit: str = "1") -> dict[str, object]:
        return {
            "commit": digit * 40,
            "tree": "2" * 40,
            "archive_sha256": "3" * 64,
            "archive_size_bytes": 4321,
        }

    @classmethod
    def source_state(cls, digit: str = "1") -> dict[str, object]:
        source = cls.computational_source(digit)
        record = {
            "repository": "fixture/repository",
            "commit_sha": source["commit"],
            "git_tree_sha": source["tree"],
            "source_archive": {
                "sha256": source["archive_sha256"],
                "size_bytes": source["archive_size_bytes"],
            },
        }
        return {"public_source": dict(record), "private_source": dict(record)}

    def test_all_signed_qualification_sources_must_equal_local_source_a(self) -> None:
        state = self.source_state()
        age = {
            "source_state": state,
            "fresh_repetitions": [
                {"source_state": state},
                {"source_state": state},
            ],
        }
        radial = {
            "triplets": [
                {"source_provenance": state},
                {"source_provenance": state},
            ]
        }
        challenge = base64.b64encode(
            json.dumps(
                {"source_state": state}, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).decode("ascii")
        host = {
            "fresh_repetitions": [
                {
                    "embedded_signed_evidence": {
                        sensitivity.HOST_START_CHALLENGE_NAME: challenge
                    }
                },
                {
                    "embedded_signed_evidence": {
                        sensitivity.HOST_START_CHALLENGE_NAME: challenge
                    }
                },
            ]
        }
        sources = {
            "host": sensitivity.host_qualification_source_identity(host),
            "age": sensitivity.age_qualification_source_identity(age),
            "radial": sensitivity.radial_qualification_source_identity(radial),
            "local": self.computational_source(),
        }
        self.assertEqual(
            sensitivity.require_identical_computational_source(sources),
            self.computational_source(),
        )

        mixed_age = json.loads(json.dumps(age))
        mixed_age["fresh_repetitions"][1]["source_state"]["public_source"][
            "commit_sha"
        ] = "9" * 40
        with self.assertRaisesRegex(RuntimeError, "public/private"):
            sensitivity.age_qualification_source_identity(mixed_age)

        mixed_radial = json.loads(json.dumps(radial))
        mixed_radial["triplets"][1]["source_provenance"]["public_source"][
            "commit_sha"
        ] = "9" * 40
        mixed_radial["triplets"][1]["source_provenance"]["private_source"][
            "commit_sha"
        ] = "9" * 40
        with self.assertRaisesRegex(RuntimeError, "mixed computational sources"):
            sensitivity.radial_qualification_source_identity(mixed_radial)

        sources["age"] = self.computational_source("9")
        with self.assertRaisesRegex(RuntimeError, "mixed computational source"):
            sensitivity.require_identical_computational_source(sources)

    def test_local_accepted_source_lock_projects_exactly_to_host_schema(self) -> None:
        source = self.computational_source()
        contract = {
            "candidates": [
                {
                    "id": "accepted-local",
                    "production_accepted": True,
                    "source_lock": {
                        "public_repository": "fixture/public",
                        "private_repository": "fixture/private",
                        **source,
                    },
                }
            ]
        }
        report = {
            "source_commit": source["commit"],
            "source_tree": source["tree"],
            "source_archive_sha256": source["archive_sha256"],
            "source_archive_size_bytes": source["archive_size_bytes"],
        }
        self.assertEqual(
            sensitivity.local_qualification_source_identity(contract, report), source
        )
        host_lock = sensitivity.host_source_lock_from_local_contract(contract, source)
        self.assertEqual(
            host_lock["public_source"]["repository"], "fixture/public"
        )
        self.assertEqual(
            host_lock["private_source"]["repository"], "fixture/private"
        )
        self.assertEqual(host_lock["public_source"]["commit_sha"], source["commit"])

        report["source_archive_size_bytes"] = int(source["archive_size_bytes"]) + 1
        with self.assertRaisesRegex(RuntimeError, "differs from its exact source lock"):
            sensitivity.local_qualification_source_identity(contract, report)
        contract["candidates"][0]["production_accepted"] = False
        with self.assertRaisesRegex(RuntimeError, "accepted candidate"):
            sensitivity.local_qualification_source_identity(contract, report)

    def test_age_cut_wrapper_explicitly_allows_external_accepted_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "age-artifact"
            artifact.mkdir()
            targets = (
                "AGE_CUT_SENSITIVITY.json",
                "age_cut_radial.csv",
                "JJ_SSP_INPUT_SHA256SUMS.txt",
            )
            for name in targets:
                (artifact / name).write_bytes((name + "\n").encode("utf-8"))
            manifest = artifact / "SHA256SUMS_age_cut_sensitivity.txt"
            manifest.write_text(
                "".join(
                    f"{sensitivity.sha256(artifact / name)}  {name}\n"
                    for name in targets
                ),
                encoding="utf-8",
                newline="\n",
            )
            external = {}
            for name in ("age-contract.json", "age-report.json", "host-contract.json"):
                path = root / name
                path.write_text("{}\n", encoding="utf-8", newline="\n")
                external[name] = path
            captured = {}

            class AgeVerifier:
                JJ_SHA = "a" * 40

                @staticmethod
                def _verify_age_cut_artifact(artifact_root, **kwargs):
                    captured.update(kwargs)
                    return {"status": "PASS"}

            snapshot = sensitivity.read_file_snapshot(
                Path(sensitivity.__file__).resolve(), "fixture verifier source"
            )

            def loader(_path, *, module_name):
                if module_name == "verify_age_cut_sensitivity":
                    return AgeVerifier, snapshot
                return SimpleNamespace(), snapshot

            with mock.patch.object(
                sensitivity, "_load_repository_module_bytes", side_effect=loader
            ):
                _, evidence = sensitivity.verify_age_cut_root(
                    artifact,
                    jj_root=root / "jj",
                    ssp_repetition_root=root / "ssp",
                    canonical_host_root=root / "hosts",
                    age_ssp_contract=external["age-contract.json"],
                    ssp_qualification_report=external["age-report.json"],
                    host_artifact_contract=external["host-contract.json"],
                )
            self.assertFalse(captured["require_repository_contract_paths"])
            self.assertEqual(captured["expected_jj_commit"], "a" * 40)
            self.assertTrue(evidence["accepted_ssp_repetition_rederived"])

    def test_legacy_measurement_requires_semantically_accepted_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshots = {}
            for role in (
                "full",
                "propagation",
                "diagnostics",
                "perturbation_audit",
                "correlation",
            ):
                path = root / f"{role}.bin"
                path.write_bytes((role + "\n").encode("utf-8"))
                snapshots[role] = sensitivity.read_file_snapshot(path, role)
            pc = root / "pc.csv"
            stellar = root / "stellar.csv"
            pc.write_text("pc\n", encoding="utf-8")
            stellar.write_text("stellar\n", encoding="utf-8")
            summary = {"branch": "constant"}
            module = SimpleNamespace(
                LEGACY_SOURCE_MIXTURE="legacy_source_mixture",
                V404_LEGACY_SENSITIVITY_PROFILE=(
                    "v4.0.4-legacy-measurement-sensitivity"
                ),
                validate_aggregate_artifact_root=mock.Mock(
                    return_value=(summary, {"manifest_sha256": "1" * 64}, snapshots)
                ),
                validate_aggregate=mock.Mock(return_value={"status": "pass"}),
                validate_aggregate_posterior_artifacts=mock.Mock(
                    return_value=({"status": "pass"}, object())
                ),
                validate_aggregate_diagnostics_artifact=mock.Mock(
                    return_value={"status": "pass"}
                ),
                validate_aggregate_perturbation_audit=mock.Mock(
                    return_value=({"status": "pass"}, object())
                ),
                validate_aggregate_correlation_artifact=mock.Mock(
                    return_value={"status": "pass"}
                ),
                validate_catalog_perturbation_replay=mock.Mock(
                    return_value=(
                        {"audit_id": "sha256:" + "2" * 64},
                        {"exact_catalog_replay": True},
                    )
                ),
            )
            module_snapshot = sensitivity.read_file_snapshot(
                Path(sensitivity.__file__).resolve(), "fixture verifier"
            )
            with mock.patch.object(
                sensitivity,
                "_load_python_module_from_snapshot",
                return_value=(module, module_snapshot),
            ):
                posterior, evidence = sensitivity.verify_legacy_measurement_aggregate(
                    root,
                    pc_catalog=pc,
                    stellar_catalog=stellar,
                )
            self.assertEqual(posterior.sha256, snapshots["propagation"].sha256)
            self.assertTrue(
                evidence["catalog_perturbation_replay"]["exact_catalog_replay"]
            )
            module.validate_aggregate.assert_called_once_with(
                "constant",
                summary,
                expected_measurement_mode="legacy_source_mixture",
                expected_acceptance_profile=(
                    "v4.0.4-legacy-measurement-sensitivity"
                ),
            )
            replay_kwargs = module.validate_catalog_perturbation_replay.call_args.kwargs
            self.assertEqual(
                replay_kwargs["measurement_error_mode"], "legacy_source_mixture"
            )

    def run_git(self, root: Path, *args: str) -> bytes:
        process = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            self.fail(process.stderr.decode("utf-8", errors="replace"))
        return process.stdout

    def make_git_pair(self, root: Path) -> tuple[Path, Path]:
        production = root / "production"
        production.mkdir()
        self.run_git(production, "init", "-q")
        self.run_git(production, "config", "user.name", "Test")
        self.run_git(production, "config", "user.email", "test@example.invalid")
        (production / "release.txt").write_text("exact release tree\n", encoding="utf-8")
        self.run_git(production, "add", "release.txt")
        self.run_git(production, "commit", "-q", "-m", "fixture")
        release = root / "release"
        process = subprocess.run(
            ["git", "clone", "-q", "--no-hardlinks", str(production), str(release)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            self.fail(process.stderr.decode("utf-8", errors="replace"))
        return production, release

    def make_runtime_manifest(self, path: Path) -> None:
        scripts = Path(sensitivity.__file__).resolve().parents[2] / "scripts"
        module, _ = sensitivity._load_python_module_from_snapshot(
            scripts / "verify_numerical_runtime.py",
            module_name="_test_runtime_contract",
            label="test runtime verifier",
        )
        features = {name: True for name in module.REQUIRED_ENABLED}
        features.update({name: False for name in module.REQUIRED_DISABLED})
        payload = {
            "schema_version": 1,
            "status": "PASS",
            "python": "Python 3.10 fixture",
            "python_executable": "/usr/bin/python3",
            "platform": "Linux fixture",
            "machine": "x86_64",
            "numpy_version": module.EXPECTED_NUMPY_VERSION,
            "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
            "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
            "selected_cpu_features": features,
            "environment": dict(module.EXPECTED_ENV),
        }
        path.write_text(
            json.dumps(payload, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def make_local_provenance_fixture(self, root: Path):
        production, release = self.make_git_pair(root)
        git = sensitivity._git_checkout_evidence(production, "fixture")
        source_archive = root / "source.tar"
        source_archive.write_bytes(self.run_git(production, "archive", "--format=tar", "HEAD"))
        runtime = root / "NUMERICAL_RUNTIME_POLICY.json"
        self.make_runtime_manifest(runtime)
        command_plan = root / "LOCAL_PRODUCTION_PLAN.json"
        command_plan.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "plan_label": "fixture",
                    "commands": [],
                    "expected_output_files": ["audits/sensitivity/RUN_PROVENANCE.json"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        record = {
            "schema_version": 4,
            "execution_mode": "local_ubuntu_22_04_wsl2",
            "production": {
                "repository": sensitivity.EXPECTED_PRODUCTION_REPOSITORY,
                "repository_id": sensitivity.EXPECTED_PRODUCTION_REPOSITORY_ID,
                "private_commit": git["head_sha"],
                "tree_sha": git["tree_sha"],
                "tree_sha256": git["tree_sha256"],
                "source_archive_sha256": hashlib.sha256(source_archive.read_bytes()).hexdigest(),
                "os_runtime_manifest_sha256": sensitivity.sha256(runtime),
                "command_plan_sha256": sensitivity.sha256(command_plan),
                "artifact_name": sensitivity.EXPECTED_PRODUCTION_ARTIFACT_NAME,
            },
            "release": {
                "repository": sensitivity.EXPECTED_RELEASE_REPOSITORY,
                "repository_id": sensitivity.EXPECTED_RELEASE_REPOSITORY_ID,
                "head_sha": git["head_sha"],
                "tree_sha": git["tree_sha"],
                "tree_sha256": git["tree_sha256"],
            },
            "conclusion": "success",
            "maximum_mcmc_steps": None,
        }
        provenance = root / sensitivity.RUN_PROVENANCE_NAME
        provenance.write_text(
            json.dumps(record, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )
        return production, release, source_archive, runtime, command_plan, provenance, record

    def validate_local(self, fixture):
        production, release, archive, runtime, command_plan, provenance, _ = fixture
        return sensitivity.validate_run_provenance(
            sensitivity.read_file_snapshot(provenance, "provenance"),
            execution_mode="local_ubuntu_22_04_wsl2",
            production_checkout=production,
            release_checkout=release,
            source_archive=archive,
            os_runtime_manifest=runtime,
            command_plan=command_plan,
        )

    def test_local_provenance_binds_git_archive_runtime_and_command_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.make_local_provenance_fixture(Path(temporary))
            record, evidence = self.validate_local(fixture)
            self.assertEqual(record["execution_mode"], "local_ubuntu_22_04_wsl2")
            self.assertEqual(
                evidence["command_plan"]["sha256"],
                record["production"]["command_plan_sha256"],
            )
            self.assertNotIn('"path"', json.dumps(evidence))

    def test_local_provenance_mutations_fail_closed(self) -> None:
        for mutation in ("repository", "commit", "tree", "archive", "runtime", "plan"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = self.make_local_provenance_fixture(Path(temporary))
                production, _, archive, runtime, command_plan, provenance, record = fixture
                changed = json.loads(json.dumps(record))
                if mutation == "repository":
                    changed["production"]["repository_id"] += 1
                elif mutation == "commit":
                    changed["production"]["private_commit"] = "0" * 40
                elif mutation == "tree":
                    changed["release"]["tree_sha256"] = "0" * 64
                elif mutation == "archive":
                    archive.write_bytes(archive.read_bytes() + b"tamper")
                elif mutation == "runtime":
                    payload = json.loads(runtime.read_text(encoding="utf-8"))
                    payload["environment"]["OMP_NUM_THREADS"] = "2"
                    runtime.write_text(json.dumps(payload), encoding="utf-8")
                else:
                    command_plan.write_bytes(command_plan.read_bytes() + b"tamper")
                if mutation in {"repository", "commit", "tree"}:
                    provenance.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    self.validate_local(fixture)
                self.assertFalse((production / "release.txt").is_symlink())

    def test_github_actions_provenance_binds_downloaded_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production, release = self.make_git_pair(root)
            git = sensitivity._git_checkout_evidence(production, "fixture")
            artifact = root / "artifact.zip"
            artifact.write_bytes(b"downloaded artifact bytes")
            record = {
                "schema_version": 3,
                "execution_mode": "github_actions",
                "production": {
                    "repository": sensitivity.EXPECTED_PRODUCTION_REPOSITORY,
                    "repository_id": sensitivity.EXPECTED_PRODUCTION_REPOSITORY_ID,
                    "workflow_path": sensitivity.EXPECTED_PRODUCTION_WORKFLOW_PATH,
                    "workflow_ref": sensitivity.EXPECTED_PRODUCTION_WORKFLOW_REF,
                    "workflow_sha": git["head_sha"],
                    "head_sha": git["head_sha"],
                    "tree_sha": git["tree_sha"],
                    "tree_sha256": git["tree_sha256"],
                    "run_id": 123,
                    "run_attempt": 2,
                    "artifact_name": sensitivity.EXPECTED_PRODUCTION_ARTIFACT_NAME,
                    "upstream_artifact_digest": "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
                "release": {
                    "repository": sensitivity.EXPECTED_RELEASE_REPOSITORY,
                    "repository_id": sensitivity.EXPECTED_RELEASE_REPOSITORY_ID,
                    "head_sha": git["head_sha"],
                    "tree_sha": git["tree_sha"],
                    "tree_sha256": git["tree_sha256"],
                },
                "conclusion": "success",
                "maximum_mcmc_steps": None,
            }
            path = root / sensitivity.RUN_PROVENANCE_NAME
            path.write_text(json.dumps(record), encoding="utf-8")
            kwargs = dict(
                execution_mode="github_actions",
                production_checkout=production,
                release_checkout=release,
                production_artifact=artifact,
                production_run_id=123,
                production_run_attempt=2,
            )
            sensitivity.validate_run_provenance(
                sensitivity.read_file_snapshot(path, "provenance"), **kwargs
            )
            artifact.write_bytes(b"forged")
            with self.assertRaises(RuntimeError):
                sensitivity.validate_run_provenance(
                    sensitivity.read_file_snapshot(path, "provenance"), **kwargs
                )

    def test_manifest_is_exact_and_nonfinite_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in sensitivity.SENSITIVITY_ARTIFACT_NAMES:
                (root / name).write_text("{}\n", encoding="utf-8")
            manifest = root / sensitivity.SENSITIVITY_MANIFEST_NAME
            manifest.write_text(
                "".join(
                    f"{sensitivity.sha256(root / name)}  {name}\n"
                    for name in sensitivity.SENSITIVITY_ARTIFACT_NAMES
                ),
                encoding="utf-8",
            )
            sensitivity.validate_artifact_manifest(
                manifest, root, set(sensitivity.SENSITIVITY_ARTIFACT_NAMES)
            )
            (root / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                sensitivity.validate_artifact_manifest(
                    manifest, root, set(sensitivity.SENSITIVITY_ARTIFACT_NAMES)
                )
            with self.assertRaises(RuntimeError):
                sensitivity.load_json_bytes(b'{"x":1e999}', "overflow")

    def test_sensitivity_host_root_rejects_old_status_and_retracted_anchor(self) -> None:
        for payload in (
            {"status": "PASS_WITH_INVALID_METALLICITY_TEST_EXCLUDED"},
            {"status": sensitivity.EXPECTED_HOST_STATUS, "note": sensitivity.RETRACTED_METALLICITY_ANCHOR_NAME},
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                audit_path = root / sensitivity.HOST_AUDIT_NAME
                table_path = root / sensitivity.HOST_SELECTOR_TABLE_NAME
                audit_path.write_text(json.dumps(payload), encoding="utf-8")
                table_path.write_text("selector,N_star\n", encoding="utf-8")
                (root / sensitivity.HOST_AUDIT_MANIFEST_NAME).write_text(
                    f"{sensitivity.sha256(audit_path)}  {audit_path.name}\n"
                    f"{sensitivity.sha256(table_path)}  {table_path.name}\n",
                    encoding="utf-8",
                )
                with self.assertRaises(RuntimeError):
                    sensitivity.validate_host_tams_root(root)

    def test_fractional_change_and_radial_fine_denominator(self) -> None:
        self.assertAlmostEqual(sensitivity.fractional_change(110.0, 100.0), 0.1)
        with self.assertRaises(ValueError):
            sensitivity.fractional_change(1.0, 0.0)
        for value in (math.nan, math.inf, -math.inf):
            with self.assertRaises(RuntimeError):
                sensitivity.fractional_change(value, 1.0)
        record = {"Lambda_earth10": {"coarse": 0.99005, "fine": 1.0, "delta_fraction": 0.00995}}
        _, _, delta = sensitivity.validated_radial_delta(record)
        self.assertLess(delta, 0.01)
        self.assertGreater(sensitivity.fractional_change(1.0, 0.99005), 0.01)
        record["Lambda_earth10"]["delta_fraction"] = sensitivity.fractional_change(1.0, 0.99005)
        with self.assertRaises(RuntimeError):
            sensitivity.validated_radial_delta(record)

    def test_dr25_support_requires_zero_nominal_and_400_sparse_realizations(self) -> None:
        def branch(fraction_zero: float) -> dict[str, object]:
            return {
                "realization_count": 400,
                "earth_analog_target_candidates": {
                    "quantiles": {"q50": 0.0},
                    "fraction_zero": fraction_zero,
                },
            }

        report = {
            "status": "FAIL_LOCAL_EMPIRICAL_SUPPORT",
            "nominal_support": {"earth_analog_target": {"candidate_count": 0}},
            "corrected_measurement_realizations": {
                "constant": branch(0.9575),
                "zero": branch(0.9675),
            },
        }
        sensitivity.validate_dr25_local_support(report)
        report["corrected_measurement_realizations"]["constant"]["realization_count"] = 399
        with self.assertRaises(RuntimeError):
            sensitivity.validate_dr25_local_support(report)


if __name__ == "__main__":
    unittest.main()
