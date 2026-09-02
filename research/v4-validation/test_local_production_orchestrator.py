#!/usr/bin/env python3
"""Unit and adversarial tests for the local v4.0.4 production controller."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import py_compile
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_v404_local_production as controller  # noqa: E402
from scripts import verify_local_run_attestation as attestation  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def make_archive(path: Path, files: dict[str, bytes]) -> str:
    with tarfile.open(path, "w") as archive:
        directories: set[str] = set()
        for name in files:
            parent = Path(name).parent
            while parent.as_posix() != ".":
                directories.add(parent.as_posix())
                parent = parent.parent
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def materialize_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def dummy_configuration(root: Path) -> controller.Configuration:
    return controller.Configuration(
        source_root=root / "source",
        source_archive=root / "source.tar",
        expected_source_archive_sha256="a" * 64,
        python_executable=root / "venv" / "bin" / "python",
        rate_model_source=root / "inputs" / "rateModels3D.py",
        stellar_catalog=root / "inputs" / "stellar.txt",
        pc_catalog=root / "inputs" / "pc.csv",
        constant_completeness=root / "inputs" / "constant.fits.gz",
        zero_completeness=root / "inputs" / "zero.fits.gz",
        host_artifact_root=root / "hosts",
        host_contract=root / "accepted-host" / controller.HOST_CONTRACT_NAME,
        expected_host_contract_sha256="b" * 64,
        parent_hosts=root / "hosts" / controller.PARENT_HOST_NAME,
        canonical_hosts=root / "hosts" / controller.CANONICAL_HOST_NAME,
        legacy_hosts=root / "hosts" / controller.LEGACY_HOST_NAME,
        metallicity_audit_root=root / "metallicity-audit",
        production_checkout=root / "private-production-checkout",
        release_checkout=root / "public-release-checkout",
        command_plan=root / "LOCAL_PRODUCTION_PLAN.json",
        git_executable=root / "bin" / "git",
        private_work_root=root / "work",
        private_raw_root=root / "raw",
        public_output_root=root / "public",
        expected_bryson_source_sha256=controller.EXPECTED_BRYSON_SOURCE_SHA256,
        maximum_parallel_shards=4,
    )


def write_runtime_manifest(path: Path, python: Path) -> None:
    features = {name: True for name in attestation.REQUIRED_ENABLED_CPU}
    features.update({name: False for name in attestation.REQUIRED_DISABLED_CPU})
    write_json(
        path,
        {
            "schema_version": 1,
            "status": "PASS",
            "python": sys.version,
            "python_executable": str(python),
            "platform": sys.platform,
            "machine": "fixture-machine",
            "numpy_version": "1.23.5",
            "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
            "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
            "selected_cpu_features": features,
            "environment": dict(attestation.REQUIRED_RUNTIME_ENV),
        },
    )


def plan_fixture(root: Path) -> tuple[controller.Configuration, Path, Path]:
    plan = root / "LOCAL_PRODUCTION_PLAN.json"
    runtime = root / "NUMERICAL_RUNTIME_POLICY.json"
    python = Path(sys.executable).absolute()
    config = replace(
        dummy_configuration(root),
        python_executable=python,
        command_plan=plan,
        maximum_parallel_shards=2,
    )
    write_runtime_manifest(runtime, python)
    return config, runtime, plan


def build_plan_cli(
    config: controller.Configuration,
    runtime: Path,
    plan: Path,
    *,
    execution_root: Path | None = None,
) -> list[str]:
    execution = config.source_root if execution_root is None else execution_root
    return [
        "build-plan",
        "--source-root",
        str(config.source_root),
        "--source-archive",
        str(config.source_archive),
        "--expected-source-archive-sha256",
        config.expected_source_archive_sha256,
        "--python-executable",
        str(config.python_executable),
        "--rate-model-source",
        str(config.rate_model_source),
        "--stellar-catalog",
        str(config.stellar_catalog),
        "--pc-catalog",
        str(config.pc_catalog),
        "--constant-completeness",
        str(config.constant_completeness),
        "--zero-completeness",
        str(config.zero_completeness),
        "--host-artifact-root",
        str(config.host_artifact_root),
        "--host-contract",
        str(config.host_contract),
        "--expected-host-contract-sha256",
        config.expected_host_contract_sha256,
        "--parent-hosts",
        str(config.parent_hosts),
        "--canonical-hosts",
        str(config.canonical_hosts),
        "--legacy-hosts",
        str(config.legacy_hosts),
        "--metallicity-audit-root",
        str(config.metallicity_audit_root),
        "--production-checkout",
        str(config.production_checkout),
        "--release-checkout",
        str(config.release_checkout),
        "--local-command-plan",
        str(plan),
        "--git-executable",
        str(config.git_executable),
        "--private-work-root",
        str(config.private_work_root),
        "--private-raw-root",
        str(config.private_raw_root),
        "--public-output-root",
        str(config.public_output_root),
        "--expected-bryson-source-sha256",
        config.expected_bryson_source_sha256,
        "--maximum-parallel-shards",
        str(config.maximum_parallel_shards),
        "--execution-root",
        str(execution),
        "--runtime-manifest",
        str(runtime),
        "--output",
        str(plan),
    ]


def paired_summary(mode: str, *, seed: int = controller.CONSTANT_PILOT_SEED) -> dict:
    return {
        "branch": "constant",
        "base_seed": seed,
        "mcmc_seed_offset": controller.MCMC_SEED_OFFSET_A,
        "trials": controller.PILOT_TRIALS,
        "walkers": controller.WALKERS,
        "burnin_steps": controller.BURNIN,
        "production_steps_requested_minimum": controller.MINIMUM_STEPS,
        "production_steps_requested_maximum": 20_000,
        "thin": controller.RUNNER_THIN,
        "measurement_error": {"mode": mode},
        "adaptive_production": {
            "enabled": True,
            "converged_realizations": controller.PILOT_TRIALS,
        },
        "input_files": {
            "stellar_catalog": {"sha256": "1" * 64},
            "pc_catalog": {"sha256": "2" * 64},
            "completeness": {"sha256": "3" * 64},
        },
    }


class LocalProductionOrchestratorTests(unittest.TestCase):
    def test_recovery_configuration_is_all_or_nothing_and_argv_is_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-recovery-argv-") as temporary:
            root = Path(temporary).absolute()
            base = replace(
                dummy_configuration(root),
                python_executable=Path(sys.executable).absolute(),
            )
            partial = replace(base, recovery_contract=root / "recovery.json")
            with self.assertRaisesRegex(
                controller.OrchestrationError, "partially populated"
            ):
                controller.recovery_enabled(partial)
            recovery = replace(
                base,
                recovery_contract=root / "recovery.json",
                expected_recovery_contract_sha256="c" * 64,
                expected_recovery_contract_size_bytes=1234,
                donor_work_shard_root=root / "donor-work",
                donor_raw_root=root / "donor-raw",
                donor_evidence_root=root / "donor-evidence",
                donor_attestation_contract=root / "donor-contract.json",
                donor_command_plan=root / "donor-plan.json",
                donor_numerical_runtime_manifest=root / "donor-runtime.json",
                donor_source_archive=root / "donor-source.tar",
                source_transition_evidence=root / "transition.json",
                recovery_qualification_report=root / "qualification.json",
                ssh_keygen_executable=root / "bin" / "ssh-keygen",
            )
            argv = controller.local_production_run_argv(
                recovery,
                execution_root=root / "execution",
                plan_output=root / "recovery-plan.json",
            )
            self.assertEqual(argv[2], "recover-mcmc")
            expected_suffix_flags = (
                "--recovery-contract",
                "--expected-recovery-contract-sha256",
                "--expected-recovery-contract-size-bytes",
                "--donor-work-shard-root",
                "--donor-raw-root",
                "--donor-evidence-root",
                "--donor-attestation-contract",
                "--donor-command-plan",
                "--donor-numerical-runtime-manifest",
                "--donor-source-archive",
                "--source-transition-evidence",
                "--recovery-qualification-report",
                "--ssh-keygen-executable",
            )
            observed_suffix_flags = tuple(
                argv[position]
                for position in range(
                    len(argv) - 2 * len(expected_suffix_flags), len(argv), 2
                )
            )
            self.assertEqual(observed_suffix_flags, expected_suffix_flags)
            self.assertEqual(
                argv[argv.index("--expected-recovery-contract-size-bytes") + 1],
                "1234",
            )

    def test_stable_recovery_copy_is_a_new_inode_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-recovery-copy-") as temporary:
            root = Path(temporary).absolute()
            source_parent = root / "source"
            destination_parent = root / "destination"
            source_parent.mkdir()
            destination_parent.mkdir()
            source = source_parent / "artifact.bin"
            source.write_bytes(b"qualified MCMC bytes\x00\x01")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            copied = destination_parent / source.name
            snapshot = controller._stable_copy_recovery_file(
                source,
                copied,
                expected_sha256=digest,
                expected_size_bytes=source.stat().st_size,
                description="fixture MCMC artifact",
            )
            self.assertEqual(copied.read_bytes(), source.read_bytes())
            self.assertEqual(snapshot.sha256, digest)
            self.assertNotEqual(
                (source.stat().st_dev, source.stat().st_ino),
                (copied.stat().st_dev, copied.stat().st_ino),
            )
            with self.assertRaisesRegex(
                controller.OrchestrationError, "failed stable byte-copy verification"
            ):
                controller._stable_copy_recovery_file(
                    source,
                    destination_parent / "bad.bin",
                    expected_sha256="0" * 64,
                    expected_size_bytes=source.stat().st_size,
                    description="tampered MCMC artifact",
                )
            self.assertFalse((destination_parent / "bad.bin").exists())

    def test_build_recovery_plan_uses_second_exact_plan_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-recovery-plan-") as temporary:
            root = Path(temporary).absolute()
            config, runtime, plan_path = plan_fixture(root)
            recovery = replace(
                config,
                recovery_contract=root / "recovery-evidence" / "contract.json",
                expected_recovery_contract_sha256="c" * 64,
                expected_recovery_contract_size_bytes=1234,
                donor_work_shard_root=root / "donor-work",
                donor_raw_root=root / "donor-raw",
                donor_evidence_root=root / "donor-evidence",
                donor_attestation_contract=root / "donor-files" / "attestation.json",
                donor_command_plan=root / "donor-files" / "plan.json",
                donor_numerical_runtime_manifest=root / "donor-files" / "runtime.json",
                donor_source_archive=root / "donor-files" / "source.tar",
                source_transition_evidence=root / "recovery-evidence" / "transition.json",
                recovery_qualification_report=root / "recovery-evidence" / "qualification.json",
                ssh_keygen_executable=root / "bin" / "ssh-keygen",
            )
            plan, encoded = controller.build_plan_document(
                recovery,
                execution_root=recovery.source_root,
                runtime_manifest=runtime,
                output=plan_path,
            )
            command = plan["commands"][0]
            self.assertEqual(plan["plan_label"], controller.RECOVERY_PLAN_LABEL)
            self.assertEqual(command["command_id"], controller.RECOVERY_PLAN_COMMAND_ID)
            self.assertEqual(command["argv"][2], "recover-mcmc")
            self.assertEqual(len(plan["expected_output_files"]), 88)
            runtime_value = attestation.validate_numerical_runtime(
                json.loads(runtime.read_text(encoding="utf-8"))
            )
            self.assertEqual(
                encoded,
                attestation.canonical_json_bytes(
                    attestation.validate_plan(plan, runtime_value)
                ),
            )

    def test_recovery_manifest_parser_rejects_case_collision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-recovery-manifest-") as temporary:
            manifest = Path(temporary) / "SHA256SUMS.txt"
            manifest.write_text(
                f"{'1' * 64}  result.bin\n{'2' * 64}  RESULT.bin\n",
                encoding="utf-8",
                newline="\n",
            )
            snapshot = controller.snapshot_file(
                manifest, "fixture recovery manifest", collect=True
            )
            with self.assertRaisesRegex(
                controller.OrchestrationError, "case-collides"
            ):
                controller._parse_recovery_manifest(
                    snapshot,
                    expected_targets=("result.bin", "RESULT.bin"),
                    description="fixture recovery manifest",
                )

    def test_attestation_validator_loader_ignores_unchecked_bytecode_cache(self) -> None:
        module_name = "_exoearth_v404_local_run_attestation_validator"
        previous = sys.modules.pop(module_name, None)
        try:
            with tempfile.TemporaryDirectory(prefix="v404-controller-source-only-") as temporary:
                root = Path(temporary)
                scripts = root / "scripts"
                scripts.mkdir()
                controller_path = scripts / "run_v404_local_production.py"
                controller_path.write_text("# fixture controller\n", encoding="utf-8")
                validator = scripts / controller.ATTESTATION_VALIDATOR_NAME
                validator.write_text("VALUE = 'SOURCE'\n", encoding="utf-8")
                marker = root / "MALICIOUS_VALIDATOR_MARKER"
                malicious = root / "malicious_validator.py"
                malicious.write_text(
                    "from pathlib import Path\n"
                    f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                    "VALUE = 'BYTECODE'\n",
                    encoding="utf-8",
                )
                cache = scripts / "__pycache__" / (
                    "verify_local_run_attestation."
                    f"{sys.implementation.cache_tag}.pyc"
                )
                cache.parent.mkdir()
                py_compile.compile(
                    str(malicious),
                    cfile=str(cache),
                    doraise=True,
                    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                )
                with mock.patch.object(controller, "__file__", str(controller_path)):
                    module, snapshot = controller._load_attestation_validator()
                self.assertEqual(module.VALUE, "SOURCE")
                self.assertEqual(module.__source_only_sha256__, snapshot.sha256)
                self.assertIsNone(module.__cached__)
                self.assertFalse(marker.exists())
        finally:
            sys.modules.pop(module_name, None)
            if previous is not None:
                sys.modules[module_name] = previous

    def test_expected_public_output_set_is_exact_and_private_free(self) -> None:
        paths = controller.expected_public_files()
        self.assertEqual(len(paths), 88)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn(controller.REPORT_NAME, paths)
        self.assertIn(controller.PUBLIC_MANIFEST_NAME, paths)
        self.assertEqual(
            sum("/raw_unthinned_chain_audit_" in f"/{path}" for path in paths), 3
        )
        self.assertFalse(any(path.endswith(".bin") for path in paths))
        self.assertFalse(any("raw_chain_index_" in path for path in paths))
        self.assertFalse(any(Path(path).name == controller.CANONICAL_HOST_NAME for path in paths))
        self.assertEqual(
            sum("/qualification/seed-stability/" in f"/{path}" for path in paths),
            20,
        )
        self.assertEqual(
            sum("/qualification/likelihood-grid/" in f"/{path}" for path in paths),
            6,
        )
        self.assertEqual(
            sum("/audits/metallicity-tams/" in f"/{path}" for path in paths), 5
        )
        self.assertEqual(sum("/audits/host-tams/" in f"/{path}" for path in paths), 3)
        self.assertEqual(sum("/audits/dr25-support/" in f"/{path}" for path in paths), 3)
        self.assertEqual(
            sum("/audits/sensitivity-artifacts/" in f"/{path}" for path in paths),
            5,
        )

    def test_expected_output_cli_does_not_require_production_arguments(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            controller.main(["expected-output-set"])
        self.assertEqual(json.loads(output.getvalue()), list(controller.expected_public_files()))

    def test_build_plan_cli_writes_one_exact_roundtrip_validated_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            output = io.StringIO()
            with redirect_stdout(output):
                controller.main(build_plan_cli(config, runtime_path, plan_path))
            self.assertIn("PASS local v4.0.4 command plan", output.getvalue())
            encoded = plan_path.read_bytes()
            plan = json.loads(encoded.decode("utf-8"))
            self.assertEqual(encoded, attestation.canonical_json_bytes(plan))
            self.assertEqual(plan["schema_version"], 1)
            self.assertEqual(plan["plan_label"], controller.PLAN_LABEL)
            self.assertEqual(len(plan["commands"]), 1)
            command = plan["commands"][0]
            self.assertEqual(command["command_id"], controller.PLAN_COMMAND_ID)
            self.assertEqual(
                command["argv"][:3],
                [
                    str(config.python_executable),
                    controller.TRACKED_CONTROLLER_PATH,
                    "run",
                ],
            )
            plan_index = command["argv"].index("--local-command-plan")
            self.assertEqual(command["argv"][plan_index + 1], str(plan_path.resolve()))
            self.assertNotIn(hashlib.sha256(encoded).hexdigest(), command["argv"])
            self.assertEqual(
                command["env"],
                {
                    **controller.NUMERICAL_ENVIRONMENT,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "EXOEARTH_SOURCE_ROOT": str(config.source_root.resolve()),
                    "EXOEARTH_OUTPUT_ROOT": str(config.public_output_root.resolve()),
                    "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST": str(
                        runtime_path.resolve()
                    ),
                },
            )
            self.assertEqual(
                plan["expected_output_files"],
                list(controller.expected_public_files(final=True)),
            )
            self.assertEqual(len(plan["expected_output_files"]), 88)
            executable, chain_hash = attestation.executable_chain(
                config.python_executable
            )
            self.assertEqual(command["executable_sha256"], executable.sha256)
            self.assertEqual(command["executable_size_bytes"], executable.size_bytes)
            self.assertEqual(command["executable_chain_sha256"], chain_hash)
            for future_root in (
                config.source_root,
                config.public_output_root,
                config.private_work_root,
                config.private_raw_root,
            ):
                self.assertFalse(future_root.exists())

            runtime_value = attestation.validate_numerical_runtime(
                attestation.load_json_snapshot(runtime_path, "fixture runtime")[0]
            )
            validated = attestation.validate_plan(plan, runtime_value)
            attestation.validate_plan_bindings(
                validated,
                runtime_value,
                config.source_root.resolve(),
                config.public_output_root.resolve(),
                runtime_path,
                plan_path,
                config.git_executable,
                config.production_checkout,
                config.release_checkout,
                require_extracted_programs=False,
            )

    def test_build_plan_document_is_deterministic_for_one_exact_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            first_plan, first_bytes = controller.build_plan_document(
                config,
                execution_root=config.source_root,
                runtime_manifest=runtime_path,
                output=plan_path,
            )
            second_plan, second_bytes = controller.build_plan_document(
                config,
                execution_root=config.source_root,
                runtime_manifest=runtime_path,
                output=plan_path,
            )
            self.assertEqual(first_plan, second_plan)
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(first_bytes, attestation.canonical_json_bytes(first_plan))

    def test_plan_bindings_pin_trusted_git_and_checkout_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            plan, _encoded = controller.build_plan_document(
                config,
                execution_root=config.source_root,
                runtime_manifest=runtime_path,
                output=plan_path,
            )
            runtime = attestation.validate_numerical_runtime(
                attestation.load_json_snapshot(runtime_path, "fixture runtime")[0]
            )
            mutations = (
                ("--git-executable", root / "untrusted-git"),
                ("--production-checkout", root / "wrong-private-role"),
                ("--release-checkout", root / "wrong-public-role"),
            )
            for flag, replacement in mutations:
                mutated = json.loads(json.dumps(plan))
                argv = mutated["commands"][0]["argv"]
                argv[argv.index(flag) + 1] = str(replacement.resolve())
                validated = attestation.validate_plan(mutated, runtime)
                with self.subTest(flag=flag), self.assertRaisesRegex(
                    attestation.AttestationError, "canonical run path"
                ):
                    attestation.validate_plan_bindings(
                        validated,
                        runtime,
                        config.source_root.resolve(),
                        config.public_output_root.resolve(),
                        runtime_path,
                        plan_path,
                        config.git_executable,
                        config.production_checkout,
                        config.release_checkout,
                        require_extracted_programs=False,
                    )

            mutated = json.loads(json.dumps(plan))
            argv = mutated["commands"][0]["argv"]
            argv[argv.index("--host-contract") + 1] = str(
                (config.production_checkout / controller.HOST_CONTRACT_NAME).resolve()
            )
            validated = attestation.validate_plan(mutated, runtime)
            with self.assertRaisesRegex(
                attestation.AttestationError, "outside the private production"
            ):
                attestation.validate_plan_bindings(
                    validated,
                    runtime,
                    config.source_root.resolve(),
                    config.public_output_root.resolve(),
                    runtime_path,
                    plan_path,
                    config.git_executable,
                    config.production_checkout,
                    config.release_checkout,
                    require_extracted_programs=False,
                )

    def test_build_plan_exclusive_output_rejects_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            plan_path.write_bytes(b"do-not-overwrite")
            with self.assertRaisesRegex(controller.OrchestrationError, "already exists"):
                controller.write_local_command_plan(
                    config,
                    execution_root=config.source_root,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            self.assertEqual(plan_path.read_bytes(), b"do-not-overwrite")

    def test_build_plan_rejects_runtime_python_mismatch_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            runtime["python_executable"] = str((root / "different-python").resolve())
            write_json(runtime_path, runtime)
            with self.assertRaisesRegex(
                controller.OrchestrationError, "Python path differs"
            ):
                controller.write_local_command_plan(
                    config,
                    execution_root=config.source_root,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            self.assertFalse(plan_path.exists())

    def test_build_plan_rejects_execution_root_rebasing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            with self.assertRaisesRegex(
                controller.OrchestrationError, "exact future execution root"
            ):
                controller.write_local_command_plan(
                    config,
                    execution_root=root / "different-execution-root",
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            self.assertFalse(plan_path.exists())
            rebased = root / "unused-component" / ".." / config.source_root.name
            with self.assertRaisesRegex(
                controller.OrchestrationError, "lexical path rebasing"
            ):
                controller.write_local_command_plan(
                    config,
                    execution_root=rebased,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            self.assertFalse(plan_path.exists())
            relative_input = replace(config, source_archive=Path("relative-source.tar"))
            with self.assertRaisesRegex(controller.OrchestrationError, "must be an absolute"):
                controller.write_local_command_plan(
                    relative_input,
                    execution_root=relative_input.source_root,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            self.assertFalse(plan_path.exists())

    def test_build_plan_rejects_preexisting_or_nested_future_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, runtime_path, plan_path = plan_fixture(root)
            config.public_output_root.mkdir()
            with self.assertRaisesRegex(controller.OrchestrationError, "must not pre-exist"):
                controller.build_plan_document(
                    config,
                    execution_root=config.source_root,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )
            config.public_output_root.rmdir()
            nested = replace(
                config,
                private_raw_root=config.private_work_root / "raw",
            )
            with self.assertRaisesRegex(controller.OrchestrationError, "overlap"):
                controller.build_plan_document(
                    nested,
                    execution_root=nested.source_root,
                    runtime_manifest=runtime_path,
                    output=plan_path,
                )

    def test_runner_argv_fixes_release_scale_and_uses_explicit_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = dummy_configuration(root)
            argv = controller.runner_argv(
                config,
                bryson_root=root / "bryson",
                completeness=config.zero_completeness,
                branch="zero",
                output=root / "shard",
                private_raw=root / "raw-shard",
                seed=controller.PRODUCTION_BASE_SEED
                + controller.PRODUCTION_ZERO_OFFSET,
                mcmc_seed_offset=controller.MCMC_SEED_OFFSET_A,
                trials=controller.TRIALS_PER_SHARD,
                maximum_steps=30_000,
                measurement_mode=controller.CORRECTED_MODE,
                label="production-shard-0",
                run_status="production_candidate",
            )
        self.assertEqual(argv[0], str(config.python_executable))
        self.assertIn("--private-raw-chain-dir", argv)
        self.assertEqual(argv[argv.index("--trials") + 1], "25")
        self.assertEqual(argv[argv.index("--max-steps") + 1], "30000")
        self.assertEqual(argv[argv.index("--walkers") + 1], "16")
        self.assertEqual(argv[argv.index("--run-status") + 1], "production_candidate")
        self.assertEqual(
            argv[argv.index("--verified-bryson-source-sha256") + 1],
            controller.EXPECTED_BRYSON_SOURCE_SHA256,
        )

    def test_aggregate_argv_uses_exact_legacy_acceptance_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = dummy_configuration(root)
            legacy = controller.VARIANTS[2]
            argv = controller.aggregate_argv(
                config,
                legacy,
                shard_root=root / "shards",
                raw_root=root / "raw",
                output=root / "aggregate",
            )
        self.assertEqual(
            argv[argv.index("--acceptance-profile") + 1],
            "v4.0.4-legacy-measurement-sensitivity",
        )
        self.assertEqual(
            argv[argv.index("--expected-measurement-error-mode") + 1],
            controller.LEGACY_MODE,
        )
        self.assertIn("--require-all-converged", argv)
        self.assertEqual(argv[argv.index("--expected-shards") + 1], "16")
        self.assertEqual(argv[argv.index("--trials-per-shard") + 1], "25")
        self.assertEqual(argv[argv.index("--samples-per-realization") + 1], "1024")

    def test_legacy_propagation_uses_the_alternative_host_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = dummy_configuration(root)
            argv = controller.propagation_argv(
                config,
                branch="constant",
                hosts=config.legacy_hosts,
                samples=root / "samples.csv.gz",
                output=root / "out",
                selector="legacy",
            )
        self.assertIn("--skip-canonical-plugin-validation", argv)
        self.assertEqual(
            argv[argv.index("--expected-distinct-host-temperatures") + 1], "536"
        )
        self.assertEqual(
            argv[argv.index("--expected-host-count") + 1], "196679892.57673854"
        )
        self.assertEqual(
            argv[argv.index("--host-selection-label") + 1],
            "legacy 4.3 < logg < 7 selector",
        )

    def test_aggregate_swap_between_acceptance_and_propagation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = dummy_configuration(root)
            aggregate_path = root / "accepted-aggregate"
            aggregate_path.mkdir()
            for name in controller.aggregate_output_names("constant"):
                (aggregate_path / name).write_bytes((name + "\n").encode("utf-8"))
            aggregate = controller.snapshot_exact_aggregate(
                aggregate_path, "constant"
            )
            target = aggregate_path / "joint_posterior_constant_full.csv.gz"

            def swap_after_verifier(*_args, **_kwargs):
                replacement = aggregate_path / "replacement.tmp"
                replacement.write_bytes(target.read_bytes())
                replacement.replace(target)
                return mock.Mock()

            with mock.patch.object(
                controller, "run_command", side_effect=swap_after_verifier
            ):
                with self.assertRaisesRegex(
                    controller.OrchestrationError, "changed"
                ):
                    controller.propagate_variant(
                        config,
                        controller.VARIANTS[0],
                        aggregate_root=aggregate,
                        environment={},
                        log_root=root / "logs",
                    )

    def test_likelihood_grid_output_contract_is_31_61_121_audit_root(self) -> None:
        self.assertEqual(
            controller.likelihood_grid_output_names(),
            (
                "selected_joint_parameter_points.csv",
                "LIKELIHOOD_GRID_CONVERGENCE.json",
                "SHA256SUMS_likelihood_grid_convergence.txt",
            ),
        )
        for branch in ("constant", "zero"):
            names = controller.seed_stability_output_names(branch)
            self.assertEqual(len(names), 10)
            self.assertIn(f"mcmc_seed_stability_{branch}.json", names)
            self.assertIn(f"SHA256SUMS_mcmc_seed_stability_{branch}.txt", names)

    def test_source_archive_and_extracted_tree_must_match_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {
                "scripts/run_v404_local_production.py": b"controller\n",
                "research/model.py": b"value = 1\n",
                "README.md": b"release\n",
            }
            archive = root / "source.tar"
            digest = make_archive(archive, files)
            source = root / "source"
            source.mkdir()
            materialize_tree(source, files)
            evidence = controller.inspect_source_archive(archive, digest)
            controller.verify_source_tree(source, evidence)
            (source / "research" / "model.py").write_bytes(b"value = 2\n")
            with self.assertRaisesRegex(controller.OrchestrationError, "changed"):
                controller.verify_source_tree(source, evidence)

    def test_source_tree_rejects_an_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"scripts/run_v404_local_production.py": b"controller\n"}
            archive = root / "source.tar"
            digest = make_archive(archive, files)
            source = root / "source"
            source.mkdir()
            materialize_tree(source, files)
            (source / "unexpected.txt").write_text("extra", encoding="utf-8")
            evidence = controller.inspect_source_archive(archive, digest)
            with self.assertRaisesRegex(controller.OrchestrationError, "extra"):
                controller.verify_source_tree(source, evidence)

    def test_source_archive_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "unsafe.tar"
            with tarfile.open(archive_path, "w") as archive:
                controller_info = tarfile.TarInfo(
                    "scripts/run_v404_local_production.py"
                )
                controller_info.size = 1
                archive.addfile(controller_info, io.BytesIO(b"x"))
                unsafe = tarfile.TarInfo("../escape")
                unsafe.size = 1
                archive.addfile(unsafe, io.BytesIO(b"x"))
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(controller.OrchestrationError, "unsafe"):
                controller.inspect_source_archive(archive_path, digest)

    def test_source_archive_rejects_symlink_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "unsafe.tar"
            with tarfile.open(archive_path, "w") as archive:
                controller_info = tarfile.TarInfo(
                    "scripts/run_v404_local_production.py"
                )
                controller_info.size = 1
                archive.addfile(controller_info, io.BytesIO(b"x"))
                link = tarfile.TarInfo("research/link.py")
                link.type = tarfile.SYMTYPE
                link.linkname = "../target"
                archive.addfile(link)
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(controller.OrchestrationError, "non-regular"):
                controller.inspect_source_archive(archive_path, digest)

    def test_source_archive_rejects_portable_case_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "source.tar"
            digest = make_archive(
                archive_path,
                {
                    "scripts/run_v404_local_production.py": b"# fixture\n",
                    "research/Case.py": b"one\n",
                    "research/case.py": b"two\n",
                },
            )
            with self.assertRaisesRegex(
                controller.OrchestrationError, "case-colliding"
            ):
                controller.inspect_source_archive(archive_path, digest)

    def test_strict_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            path.write_text('{"status":"PASS","status":"FAIL"}', encoding="utf-8")
            with self.assertRaisesRegex(controller.OrchestrationError, "duplicate"):
                controller.load_strict_json(path, "record")
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(controller.OrchestrationError, "non-finite"):
                controller.load_strict_json(path, "record")

    def test_mutable_roots_reject_overlap_and_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir()
            with self.assertRaisesRegex(controller.OrchestrationError, "overlap"):
                controller.validate_mutable_roots(
                    {"work": root / "mutable", "raw": root / "mutable" / "raw"},
                    {"protected": protected},
                )
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "file").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(controller.OrchestrationError, "must be empty"):
                controller.validate_mutable_roots(
                    {"output": nonempty}, {"protected": protected}
                )

    def test_run_command_always_uses_shell_false_and_explicit_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = controller.CommandSpec(
                "safe-command", ("/python", "script.py", "--value", "x"), root / "run.log"
            )
            completed = subprocess.CompletedProcess(list(spec.argv), 0)
            with mock.patch.object(controller.subprocess, "run", return_value=completed) as run:
                result = controller.run_command(spec, cwd=root, environment={"A": "B"})
            self.assertEqual(result.returncode, 0)
            positional, keywords = run.call_args
            self.assertEqual(positional[0], list(spec.argv))
            self.assertIs(keywords["shell"], False)
            self.assertIs(keywords["check"], False)
            self.assertEqual(keywords["env"], {"A": "B"})

    def test_run_command_fails_closed_on_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = controller.CommandSpec("failing", ("/python", "x.py"), root / "run.log")
            completed = subprocess.CompletedProcess(list(spec.argv), 7)
            with mock.patch.object(controller.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(controller.OrchestrationError, "exit code 7"):
                    controller.run_command(spec, cwd=root, environment={})

    def test_parallel_executor_never_exceeds_four_processes(self) -> None:
        lock = threading.Lock()
        active = 0
        maximum = 0

        def runner(spec: controller.CommandSpec) -> controller.CommandResult:
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return controller.CommandResult(spec.command_id, 0, 0.02)

        specs = [
            controller.CommandSpec(f"shard-{index}", ("python",), Path(f"{index}.log"))
            for index in range(16)
        ]
        results = controller.run_bounded(specs, maximum_parallel=4, runner=runner)
        self.assertEqual(len(results), 16)
        self.assertLessEqual(maximum, 4)
        self.assertGreater(maximum, 1)

    def test_parallel_executor_rejects_more_than_four(self) -> None:
        with self.assertRaisesRegex(controller.OrchestrationError, "between 1 and 4"):
            controller.run_bounded([], maximum_parallel=5, runner=lambda value: value)

    def test_pip_freeze_requires_the_release_runtime_versions(self) -> None:
        valid = "\n".join(
            f"{name}=={version}"
            for name, version in controller.REQUIRED_RUNTIME_PINS.items()
        ).encode("utf-8")
        self.assertEqual(len(controller.validate_pip_freeze(valid)), 5)
        with self.assertRaisesRegex(controller.OrchestrationError, "versions differ"):
            controller.validate_pip_freeze(valid.replace(b"numpy==1.23.5", b"numpy==2.0.0"))

    def test_wsl_gate_requires_ubuntu_2204_and_microsoft_kernel(self) -> None:
        controller.validate_ubuntu_2204_wsl(
            platform_name="linux",
            kernel_release="5.15.0-microsoft-standard-WSL2",
            os_release_text='ID=ubuntu\nVERSION_ID="22.04"\n',
        )
        with self.assertRaisesRegex(controller.OrchestrationError, "not identified as WSL"):
            controller.validate_ubuntu_2204_wsl(
                platform_name="linux",
                kernel_release="6.8.0-generic",
                os_release_text='ID=ubuntu\nVERSION_ID="22.04"\n',
            )
        with self.assertRaisesRegex(controller.OrchestrationError, "Ubuntu 22.04"):
            controller.validate_ubuntu_2204_wsl(
                platform_name="linux",
                kernel_release="5.15.0-microsoft-standard-WSL2",
                os_release_text='ID=ubuntu\nVERSION_ID="24.04"\n',
            )

    def test_legacy_pair_report_requires_identical_seed_and_input_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corrected = root / "corrected"
            legacy = root / "legacy"
            corrected.mkdir()
            legacy.mkdir()
            write_json(
                corrected / "posterior_summary_constant_corrected-pilot-seed-1.json",
                paired_summary(controller.CORRECTED_MODE),
            )
            write_json(
                legacy / "posterior_summary_constant_legacy-pilot-paired.json",
                paired_summary(controller.LEGACY_MODE),
            )
            output = root / "gate"
            controller.write_legacy_pair_report(corrected, legacy, output)
            controller.ensure_exact_files(
                output,
                {
                    "legacy_measurement_pilot_pair_constant.json",
                    "SHA256SUMS_legacy_measurement_pilot_pair.txt",
                },
                "pair gate",
            )
            bad = paired_summary(controller.LEGACY_MODE, seed=1)
            write_json(
                legacy / "posterior_summary_constant_legacy-pilot-paired.json", bad
            )
            with self.assertRaisesRegex(controller.OrchestrationError, "policy mismatch"):
                controller.write_legacy_pair_report(corrected, legacy, root / "bad-gate")

    def test_raw_output_contract_is_exactly_25_payloads_plus_index_and_manifest(self) -> None:
        names = controller.raw_output_names("constant", "production-shard-3")
        self.assertEqual(len(names), 27)
        self.assertEqual(sum(name.endswith(".bin") for name in names), 25)
        self.assertIn(
            "raw_chain_index_constant_production-shard-3.json", names
        )

    def test_public_boundary_rejects_exact_copy_of_protected_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected.dat"
            protected.write_bytes(b"private-input")
            output = root / "public"
            output.mkdir()
            (output / "result.csv").write_bytes(b"private-input")
            snap = controller.snapshot_file(protected, "protected")
            with self.assertRaisesRegex(controller.OrchestrationError, "duplicates"):
                controller.public_output_inventory(
                    output,
                    expected={"result.csv"},
                    protected_snapshots=[snap],
                )

    def test_exact_file_gate_rejects_nested_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "expected.txt").write_text("ok", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(controller.OrchestrationError, "extra"):
                controller.ensure_exact_files(root, {"expected.txt"}, "output")

    def test_manifest_gate_rejects_wrong_digest_and_extra_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "result.json"
            target.write_text("{}\n", encoding="utf-8", newline="\n")
            manifest = root / "SHA256SUMS.txt"
            manifest.write_text(
                f"{'0' * 64}  result.json\n", encoding="utf-8", newline="\n"
            )
            with self.assertRaisesRegex(controller.OrchestrationError, "digest mismatch"):
                controller.validate_sha256_manifest_root(
                    root,
                    manifest_name=manifest.name,
                    target_names=(target.name,),
                    description="fixture",
                )
            manifest.write_text(
                f"{hashlib.sha256(target.read_bytes()).hexdigest()}  result.json\n",
                encoding="utf-8",
                newline="\n",
            )
            (root / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(controller.OrchestrationError, "extra"):
                controller.validate_sha256_manifest_root(
                    root,
                    manifest_name=manifest.name,
                    target_names=(target.name,),
                    description="fixture",
                )

    def test_release_safe_snapshot_copy_rejects_unsafe_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_text("{}\n", encoding="utf-8")
            snapshot = controller.snapshot_file(source, "source", collect=True)
            with self.assertRaisesRegex(controller.OrchestrationError, "unsafe"):
                controller._copy_snapshots_to_exact_root(
                    {"..\\source.json": snapshot},
                    root / "output",
                    description="fixture",
                )

    def test_propagation_summary_rewrite_removes_private_paths_and_rehashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "collapsed_host_temperature_measure.csv").write_text(
                "Teff_K,N_surface_pc-2\n5780,1\n", encoding="utf-8"
            )
            (root / "galactic_posterior_draws_constant.csv.gz").write_bytes(b"fixture")
            write_json(
                root / "galactic_posterior_summary_constant.json",
                {
                    "source_posterior_samples": {
                        "path": "/private/work/joint_posterior_constant.csv.gz"
                    },
                    "host_rows": {"path": r"C:\private\hosts\canonical.csv"},
                },
            )
            (root / "SHA256SUMS_galactic_constant.txt").write_text(
                "stale\n", encoding="utf-8"
            )
            controller.make_propagation_summary_release_safe(root, "constant")
            report = controller.load_strict_json(
                root / "galactic_posterior_summary_constant.json", "summary"
            )
            self.assertEqual(
                report["source_posterior_samples"]["path"],
                "joint_posterior_constant.csv.gz",
            )
            self.assertEqual(report["host_rows"]["path"], "canonical.csv")
            self.assertNotIn("private", json.dumps(report).lower())
            controller.validate_sha256_manifest_root(
                root,
                manifest_name="SHA256SUMS_galactic_constant.txt",
                target_names=(
                    "collapsed_host_temperature_measure.csv",
                    "galactic_posterior_draws_constant.csv.gz",
                    "galactic_posterior_summary_constant.json",
                ),
                description="fixture propagation",
            )

    def test_schema_v4_sensitivity_provenance_has_no_output_self_reference(self) -> None:
        archive_hash = "1" * 64
        production = controller.GitCheckoutEvidence(
            head_sha="a" * 40,
            tree_sha="b" * 40,
            tree_sha256="2" * 64,
            source_archive_sha256=archive_hash,
        )
        release = controller.GitCheckoutEvidence(
            head_sha="c" * 40,
            tree_sha=production.tree_sha,
            tree_sha256=production.tree_sha256,
            source_archive_sha256="3" * 64,
        )
        record = controller.build_sensitivity_run_provenance(
            source_archive_sha256=archive_hash,
            numerical_runtime_sha256="4" * 64,
            command_plan_sha256="5" * 64,
            production_git=production,
            release_git=release,
        )
        self.assertEqual(record["schema_version"], 4)
        self.assertEqual(
            record["production"]["command_plan_sha256"], "5" * 64
        )
        self.assertNotIn("output_manifest_sha256", record["production"])
        self.assertNotIn("path", json.dumps(record).lower())
        changed = controller.GitCheckoutEvidence(
            head_sha=release.head_sha,
            tree_sha="d" * 40,
            tree_sha256=release.tree_sha256,
            source_archive_sha256=release.source_archive_sha256,
        )
        with self.assertRaisesRegex(controller.OrchestrationError, "unequal Git trees"):
            controller.build_sensitivity_run_provenance(
                source_archive_sha256=archive_hash,
                numerical_runtime_sha256="4" * 64,
                command_plan_sha256="5" * 64,
                production_git=production,
                release_git=changed,
            )

    def test_git_checkout_evidence_uses_explicit_shell_free_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            checkout.mkdir()
            git_executable = root / "git"
            git_executable.write_bytes(b"fixture")
            tree_listing = b"100644 blob\x00file.py\x00"
            archive = b"archive bytes"

            def fake_run(argv, **kwargs):
                arguments = argv[3:]
                outputs = {
                    ("status", "--porcelain=v1", "--untracked-files=all"): b"",
                    ("remote", "get-url", "origin"): (
                        "https://github.com/fixture/repository.git\n"
                    ).encode(),
                    ("rev-parse", "HEAD"): ("a" * 40 + "\n").encode(),
                    ("rev-parse", "HEAD^{tree}"): ("b" * 40 + "\n").encode(),
                    ("ls-tree", "-r", "-z", "--full-tree", "b" * 40): tree_listing,
                    ("archive", "--format=tar", "HEAD"): archive,
                }
                return subprocess.CompletedProcess(argv, 0, outputs[tuple(arguments)], b"")

            with mock.patch.object(controller.subprocess, "run", side_effect=fake_run) as run:
                evidence = controller.git_checkout_evidence(
                    git_executable,
                    checkout,
                    label="fixture",
                    expected_repository="fixture/repository",
                    environment={"A": "B"},
                )
            self.assertEqual(
                evidence.source_archive_sha256, hashlib.sha256(archive).hexdigest()
            )
            self.assertEqual(evidence.tree_sha256, hashlib.sha256(tree_listing).hexdigest())
            self.assertTrue(run.call_args_list)
            for call in run.call_args_list:
                self.assertIs(call.kwargs["shell"], False)
                self.assertIs(call.kwargs["check"], False)
                self.assertEqual(call.args[0][0], str(git_executable))

            with mock.patch.object(controller.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(
                    controller.OrchestrationError, "exact repository role"
                ):
                    controller.git_checkout_evidence(
                        git_executable,
                        checkout,
                        label="fixture",
                        expected_repository="attacker/repository",
                        environment={"A": "B"},
                    )

    def test_git_origin_parser_accepts_only_canonical_github_forms(self) -> None:
        expected = "fixture/repository"
        for origin in (
            "https://github.com/fixture/repository.git",
            "git@github.com:fixture/repository.git",
            "ssh://git@github.com/fixture/repository.git",
        ):
            with self.subTest(origin=origin):
                self.assertEqual(
                    controller.canonical_github_repository_slug(origin), expected
                )
        for origin in (
            "https://github.com.evil/fixture/repository.git",
            "https://user@github.com/fixture/repository.git",
            "https://github.com:443/fixture/repository.git",
            "https://github.com/fixture/repository.git?x=1",
            "https://github.com/fixture/repository.git#x",
            "ssh://root@github.com/fixture/repository.git",
            "ssh://git@github.com:22/fixture/repository.git",
            "git@evil.example:fixture/repository.git",
            "C:/fixture/repository",
        ):
            with self.subTest(origin=origin), self.assertRaises(
                controller.OrchestrationError
            ):
                controller.canonical_github_repository_slug(origin)

    def test_execute_invokes_every_declared_release_safe_audit_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = dummy_configuration(Path(temporary))
            source = mock.Mock()
            source.snapshot = mock.Mock()
            source.snapshot.sha256 = "1" * 64
            production = controller.GitCheckoutEvidence(
                "a" * 40, "b" * 40, "2" * 64, "1" * 64
            )
            release = controller.GitCheckoutEvidence(
                "c" * 40, "b" * 40, "2" * 64, "3" * 64
            )
            host_binding = mock.Mock()
            aggregate_roots = {
                variant.name: Path(temporary) / "aggregate" / variant.name
                for variant in controller.VARIANTS
            }

            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(controller, "production_environment", return_value={})
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "validate_configuration",
                        return_value=(source, [], production, release, host_binding),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "make_empty_directory",
                        side_effect=lambda path, _description: Path(path),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller, "preflight_locked_inputs_and_hosts", return_value=[]
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "create_numerical_environment",
                        return_value=(Path("numerical.txt"), Path("runtime.json"), []),
                    )
                )
                metallicity = stack.enter_context(
                    mock.patch.object(
                        controller,
                        "stage_metallicity_audit",
                        return_value=(Path("metallicity"), []),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "create_bryson_projection",
                        return_value=Path("bryson"),
                    )
                )
                stack.enter_context(mock.patch.object(controller, "verify_source_tree"))
                stack.enter_context(
                    mock.patch.object(controller, "run_pilots", return_value=[])
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "run_production_shards",
                        return_value=(Path("shards"), Path("raw"), []),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller,
                        "aggregate_and_verify",
                        side_effect=lambda _config, variant, **_kwargs: (
                            aggregate_roots[variant.name],
                            [],
                        ),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        controller, "run_likelihood_grid_audits", return_value=[]
                    )
                )
                stack.enter_context(
                    mock.patch.object(controller, "propagate_variant", return_value=[])
                )
                host = stack.enter_context(
                    mock.patch.object(controller, "run_host_tams_audit", return_value=[])
                )
                dr25 = stack.enter_context(
                    mock.patch.object(controller, "run_dr25_support_audit", return_value=[])
                )
                sensitivity = stack.enter_context(
                    mock.patch.object(
                        controller, "run_sensitivity_artifacts", return_value=[]
                    )
                )
                stack.enter_context(mock.patch.object(controller, "recheck_snapshot"))
                stack.enter_context(
                    mock.patch.object(controller, "recheck_exact_aggregate")
                )
                stack.enter_context(
                    mock.patch.object(controller, "recheck_host_contract_binding")
                )
                stack.enter_context(
                    mock.patch.object(controller, "recheck_git_checkout_evidence")
                )
                stack.enter_context(
                    mock.patch.object(
                        controller, "reverify_accepted_aggregates", return_value=[]
                    )
                )
                stack.enter_context(
                    mock.patch.object(controller, "finalize_public_output")
                )
                stack.enter_context(mock.patch("builtins.print"))
                controller.execute(config)
            metallicity.assert_called_once()
            host.assert_called_once()
            dr25.assert_called_once()
            sensitivity.assert_called_once()

    def test_empty_recovery_stdout_is_narrowly_allowed_and_hash_locked(self) -> None:
        empty = {
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        }
        with self.assertRaisesRegex(controller.OrchestrationError, "size is invalid"):
            controller._validate_recovery_evidence(empty, "ordinary evidence")
        self.assertEqual(
            controller._validate_recovery_evidence(
                empty, "donor command stdout", allow_empty=True
            ),
            empty,
        )
        with self.assertRaisesRegex(
            controller.OrchestrationError, "empty-file SHA-256"
        ):
            controller._validate_recovery_evidence(
                {"sha256": "1" * 64, "size_bytes": 0},
                "donor command stdout",
                allow_empty=True,
            )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stdout.bin"
            path.write_bytes(b"")
            snapshot = controller.snapshot_file(path, "empty stdout")
            controller._matches_recovery_evidence(
                snapshot,
                empty,
                "donor command stdout",
                allow_empty=True,
            )

    def test_recovery_policy_lock_detects_constant_and_transitive_helper_changes(self) -> None:
        source = Path(controller.__file__).read_bytes()
        policy = controller._recovery_mcmc_policy_snapshot(source, "current source")
        changed_seed = source.replace(
            b"PRODUCTION_BASE_SEED = 2_026_082_200",
            b"PRODUCTION_BASE_SEED = 2_026_082_201",
            1,
        )
        self.assertNotEqual(
            policy,
            controller._recovery_mcmc_policy_snapshot(changed_seed, "changed seed"),
        )
        invariants = controller._recovery_controller_invariant_snapshot(
            source, "current source"
        )
        changed_helper = source.replace(
            b"return str(config.source_root / PurePosixPath(relative))",
            b"return str(config.source_root / 'redirected' / PurePosixPath(relative))",
            1,
        )
        self.assertNotEqual(source, changed_helper)
        self.assertNotEqual(
            invariants,
            controller._recovery_controller_invariant_snapshot(
                changed_helper, "changed helper"
            ),
        )

    def test_recovery_split_and_ast_policy_mutations_fail_normal_and_optimized(self) -> None:
        probe = r'''
from dataclasses import replace
import hashlib
from pathlib import Path

from scripts import run_v404_local_production as controller


def ast_policy_digest(source):
    scientific = controller._recovery_mcmc_policy_snapshot(source, "probe source")
    invariants = controller._recovery_controller_invariant_snapshot(
        source, "probe source"
    )
    return hashlib.sha256(
        controller.canonical_json_bytes(
            {
                "scientific_policy": scientific,
                "unchanged_controller_surface": invariants,
            }
        )
    ).hexdigest()


policy = {
    "copy_policy": controller.RECOVERY_COPY_POLICY,
    "mcmc_reused": True,
    "aggregates_and_downstream_recomputed": True,
    "shards_per_variant": controller.SHARDS,
    "trials_per_shard": controller.TRIALS_PER_SHARD,
    "total_realizations": (
        len(controller.VARIANTS) * controller.SHARDS * controller.TRIALS_PER_SHARD
    ),
    "work_file_count": controller.RECOVERY_WORK_FILE_COUNT,
    "raw_file_count": controller.RECOVERY_RAW_FILE_COUNT,
    "total_file_count": controller.RECOVERY_TOTAL_FILE_COUNT,
    "work_size_bytes": 3_498_332_085,
    "raw_size_bytes": 10_002_742_894,
    "total_size_bytes": controller.RECOVERY_TOTAL_SIZE_BYTES,
    "work_tree_sha256": (
        "971459488817641a29032aa36bfe37581a8a276ef3dd5ee11b7b07a307a05118"
    ),
    "raw_tree_sha256": (
        "98bb6ba382ccb626372a21b8dbf741e7b4fc6298e4104de0fb30b012052570d9"
    ),
    "mcmc_policy_sha256": (
        "206968f982cccee67caa00a6b23442602716289cc17d0304fedac38ac376a59e"
    ),
}
controller._validate_recovery_policy(policy)
source = Path(controller.__file__).read_bytes()
if ast_policy_digest(source) != controller.RECOVERY_MCMC_POLICY_SHA256:
    raise RuntimeError("live AST policy does not match its qualified lock")
changed_source = source.replace(
    b"PRODUCTION_BASE_SEED = 2_026_082_200",
    b"PRODUCTION_BASE_SEED = 2_026_082_201",
    1,
)
if (
    changed_source == source
    or ast_policy_digest(changed_source) == policy["mcmc_policy_sha256"]
):
    raise RuntimeError("MCMC AST mutation was not detected")

policy_mutations = {
    "mcmc_policy_sha256": "0" * 64,
    "work_size_bytes": controller.RECOVERY_WORK_SIZE_BYTES + 1,
    "raw_size_bytes": controller.RECOVERY_RAW_SIZE_BYTES + 1,
    "work_tree_sha256": "1" * 64,
    "raw_tree_sha256": "2" * 64,
}
for key, value in policy_mutations.items():
    changed = dict(policy)
    changed[key] = value
    try:
        controller._validate_recovery_policy(changed)
    except controller.OrchestrationError:
        pass
    else:
        raise RuntimeError(f"recovery contract mutation passed: {key}")

evidence = controller.RecoveryImportEvidence(
    snapshots=(),
    work_root=Path("work"),
    work_root_identity=(1, 2, 3, 4, 5),
    work_file_count=controller.RECOVERY_WORK_FILE_COUNT,
    work_size_bytes=controller.RECOVERY_WORK_SIZE_BYTES,
    work_tree_sha256=controller.RECOVERY_WORK_TREE_SHA256,
    raw_root=Path("raw"),
    raw_root_identity=(6, 7, 8, 9, 10),
    raw_file_count=controller.RECOVERY_RAW_FILE_COUNT,
    raw_size_bytes=controller.RECOVERY_RAW_SIZE_BYTES,
    raw_tree_sha256=controller.RECOVERY_RAW_TREE_SHA256,
)
controller._validate_recovery_import_policy(evidence, policy)
evidence_mutations = {
    "work_size_bytes": controller.RECOVERY_WORK_SIZE_BYTES + 1,
    "raw_size_bytes": controller.RECOVERY_RAW_SIZE_BYTES + 1,
    "work_tree_sha256": "1" * 64,
    "raw_tree_sha256": "2" * 64,
}
for key, value in evidence_mutations.items():
    changed = replace(evidence, **{key: value})
    try:
        controller._validate_recovery_import_policy(changed, policy)
    except controller.OrchestrationError:
        pass
    else:
        raise RuntimeError(f"recovery import mutation passed: {key}")

print("PASS")
'''
        for optimization in ((), ("-O",)):
            completed = subprocess.run(
                [sys.executable, *optimization, "-c", probe],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            self.assertEqual(completed.stdout.decode("ascii").strip(), "PASS")

    def test_recovery_import_recheck_rejects_deep_extra_file_added_during_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            raw = root / "raw"
            relative = "variant/shard/artifact.bin"
            directories = (".", "variant", "variant/shard")
            for tree in (work, raw):
                target = tree / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(tree.name.encode("ascii"))
            work_snapshot = controller.snapshot_file(work / relative, "work artifact")
            raw_snapshot = controller.snapshot_file(raw / relative, "raw artifact")
            work_root, work_identity = controller.snapshot_plain_directory_chain(
                work, "work root"
            )
            raw_root, raw_identity = controller.snapshot_plain_directory_chain(
                raw, "raw root"
            )
            evidence = controller.RecoveryImportEvidence(
                snapshots=(work_snapshot, raw_snapshot),
                work_root=work_root,
                work_root_identity=work_identity,
                work_file_count=1,
                work_size_bytes=work_snapshot.size_bytes,
                work_tree_sha256="1" * 64,
                raw_root=raw_root,
                raw_root_identity=raw_identity,
                raw_file_count=1,
                raw_size_bytes=raw_snapshot.size_bytes,
                raw_tree_sha256="2" * 64,
            )
            original_recheck = controller.recheck_snapshot
            injected = False

            def inject(snapshot, description):
                nonlocal injected
                original_recheck(snapshot, description)
                if not injected:
                    (work / "variant" / "shard" / "extra.bin").write_bytes(b"extra")
                    injected = True

            with mock.patch.object(
                controller,
                "_recovery_tree_paths",
                side_effect=lambda *, raw: ((relative,), directories),
            ), mock.patch.object(controller, "recheck_snapshot", side_effect=inject):
                with self.assertRaisesRegex(
                    controller.OrchestrationError, "exact tree mismatch"
                ):
                    controller.recheck_recovery_import(
                        evidence, "fixture import", rehash_files=True
                    )

    def test_recovery_lineage_rejects_merge_commit_with_donor_first_parent(self) -> None:
        head = "a" * 40
        donor = "b" * 40
        merge = subprocess.CompletedProcess(
            [], 0, f"{head} {donor} {'c' * 40}\n".encode("ascii"), b""
        )
        with mock.patch.object(controller.subprocess, "run", return_value=merge):
            with self.assertRaisesRegex(
                controller.OrchestrationError, "single-parent direct Git child"
            ):
                controller.validate_recovery_lineage(
                    Path("/git"),
                    Path("/checkout"),
                    expected_head=head,
                    donor_commit=donor,
                    environment={"A": "B"},
                    description="fixture",
                )
        direct = subprocess.CompletedProcess(
            [], 0, f"{head} {donor}\n".encode("ascii"), b""
        )
        with mock.patch.object(controller.subprocess, "run", return_value=direct) as run:
            controller.validate_recovery_lineage(
                Path("/git"),
                Path("/checkout"),
                expected_head=head,
                donor_commit=donor,
                environment={"A": "B"},
                description="fixture",
            )
        self.assertEqual(
            run.call_args.args[0][3:],
            ["rev-list", "--parents", "-n", "1", "HEAD"],
        )
        self.assertIs(run.call_args.kwargs["shell"], False)


if __name__ == "__main__":
    unittest.main()
