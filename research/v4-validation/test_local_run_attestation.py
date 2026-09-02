#!/usr/bin/env python3
"""Adversarial tests for the two-signer local production-run gate."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import verify_local_run_attestation as gate  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run(argv: list[str], *, cwd: Path | None = None) -> bytes:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"fixture command failed ({completed.returncode}): {argv!r}\n"
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="local-run-attestation-")
        self.root = Path(self.temporary.name)
        git_name = shutil.which("git")
        ssh_name = shutil.which("ssh-keygen")
        if git_name is None or ssh_name is None:
            self.cleanup()
            raise unittest.SkipTest("git and ssh-keygen are required")
        self.git = Path(git_name).resolve()
        self.ssh_keygen = Path(ssh_name).resolve()
        self.python = Path(sys.executable).resolve()
        self.source = self.root / "private-source"
        self.source.mkdir()
        run([str(self.git), "init", "-q"], cwd=self.source)
        run([str(self.git), "config", "user.name", "Local fixture"], cwd=self.source)
        run(
            [str(self.git), "config", "user.email", "fixture@example.invalid"],
            cwd=self.source,
        )
        run(
            [
                str(self.git),
                "remote",
                "add",
                "origin",
                "https://github.com/"
                + gate.PRIVATE_REPOSITORY
                + ".git",
            ],
            cwd=self.source,
        )
        writer = self.source / Path(*PurePosixPath(gate.V404_PROGRAM).parts)
        writer.parent.mkdir(parents=True)
        writer.write_text(
            "from pathlib import Path\n"
            "import os\n"
            "root = Path(os.environ['EXOEARTH_OUTPUT_ROOT'])\n"
            f"outputs = {gate.V404_EXPECTED_OUTPUT_FILES!r}\n"
            "for name in outputs:\n"
            "    target = root / name\n"
            "    target.parent.mkdir(parents=True, exist_ok=True)\n"
            "    target.write_bytes(('controlled-output:' + name + '\\n').encode())\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.source / ".gitattributes").write_text(
            "* text=auto eol=lf\n", encoding="utf-8", newline="\n"
        )
        (self.source / ".gitignore").write_text(
            "__pycache__/\n", encoding="utf-8", newline="\n"
        )
        workflow = self.source / ".github" / "workflows" / "fixture.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: fixture\non: workflow_dispatch\n", encoding="utf-8", newline="\n"
        )
        run([str(self.git), "add", "--all"], cwd=self.source)
        run([str(self.git), "commit", "-q", "-m", "fixture source"], cwd=self.source)
        self.public_source = self.root / "public-source"
        run(
            [str(self.git), "clone", "-q", str(self.source), str(self.public_source)]
        )
        run(
            [
                str(self.git),
                "remote",
                "set-url",
                "origin",
                "https://github.com/" + gate.PUBLIC_REPOSITORY + ".git",
            ],
            cwd=self.public_source,
        )

        self.key_a = self.root / "signer-a"
        self.key_b = self.root / "signer-b"
        self.key_wrong = self.root / "signer-wrong"
        for key, comment in (
            (self.key_a, "fixture-a"),
            (self.key_b, "fixture-b"),
            (self.key_wrong, "fixture-wrong"),
        ):
            run(
                [
                    str(self.ssh_keygen),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    comment,
                    "-f",
                    str(key),
                ]
            )
        self.signers = [
            {
                "signer_id": "fixture-signer-a",
                "public_key": self.key_a.with_suffix(".pub")
                .read_text(encoding="ascii")
                .strip(),
            },
            {
                "signer_id": "fixture-signer-b",
                "public_key": self.key_b.with_suffix(".pub")
                .read_text(encoding="ascii")
                .strip(),
            },
        ]

        self.output = self.root / "output"
        self.evidence = self.root / "evidence"
        self.execution = self.root / "execution"
        self.report = self.root / "public-report.json"
        self.runtime_path = self.root / "runtime.json"
        self.plan_path = self.root / "plan.json"
        self.contract_path = self.root / "contract.json"
        self.runtime = self.make_runtime()
        write_json(self.runtime_path, self.runtime)
        self.plan = self.make_plan()
        write_json(self.plan_path, self.plan)
        self.contract = self.make_contract()
        write_json(self.contract_path, self.contract)

    def cleanup(self) -> None:
        if hasattr(self, "temporary"):
            self.temporary.cleanup()

    def make_runtime(self) -> dict:
        features = {name: True for name in gate.REQUIRED_ENABLED_CPU}
        features.update({name: False for name in gate.REQUIRED_DISABLED_CPU})
        return {
            "schema_version": 1,
            "status": "PASS",
            "python": sys.version,
            "python_executable": str(self.python),
            "platform": sys.platform,
            "machine": "fixture-machine",
            "numpy_version": "1.23.5",
            "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
            "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
            "selected_cpu_features": features,
            "environment": dict(gate.REQUIRED_RUNTIME_ENV),
        }

    def make_plan(self) -> dict:
        env = dict(gate.REQUIRED_RUNTIME_ENV)
        env.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "EXOEARTH_SOURCE_ROOT": str(self.execution.resolve(strict=False)),
                "EXOEARTH_OUTPUT_ROOT": str(self.output.resolve(strict=False)),
                "EXOEARTH_NUMERICAL_RUNTIME_MANIFEST": str(
                    self.runtime_path.resolve()
                ),
            }
        )
        python_snapshot, python_chain = gate.executable_chain(self.python)
        values = {
            "--source-root": str(self.execution.resolve(strict=False)),
            "--source-archive": str((self.root / "source.tar").resolve()),
            "--expected-source-archive-sha256": "a" * 64,
            "--python-executable": str(self.python),
            "--rate-model-source": str((self.root / "inputs/rateModels3D.py").resolve()),
            "--stellar-catalog": str((self.root / "inputs/stellar.txt").resolve()),
            "--pc-catalog": str((self.root / "inputs/pc.csv").resolve()),
            "--constant-completeness": str((self.root / "inputs/constant.fits.gz").resolve()),
            "--zero-completeness": str((self.root / "inputs/zero.fits.gz").resolve()),
            "--host-artifact-root": str((self.root / "hosts").resolve()),
            "--host-contract": str(
                (self.root / "accepted-host/HOST_ARTIFACT_CONTRACT_v4_0_4.json").resolve()
            ),
            "--expected-host-contract-sha256": "b" * 64,
            "--parent-hosts": str((self.root / "hosts/jj_g_hosts_parent_prelogg_padova.csv").resolve()),
            "--canonical-hosts": str((self.root / "hosts/jj_g_hosts_raw_eligible_padova.csv").resolve()),
            "--legacy-hosts": str((self.root / "hosts/jj_g_hosts_raw_eligible_padova_legacy_logg43.csv").resolve()),
            "--metallicity-audit-root": str((self.root / "metallicity").resolve()),
            "--production-checkout": str(self.source.resolve()),
            "--release-checkout": str(self.public_source.resolve()),
            "--local-command-plan": str(self.plan_path.resolve()),
            "--git-executable": str(self.git),
            "--private-work-root": str((self.root / "private-work").resolve()),
            "--private-raw-root": str((self.root / "private-raw").resolve()),
            "--public-output-root": str(self.output.resolve(strict=False)),
            "--expected-bryson-source-sha256": gate.V404_BRYSON_SOURCE_SHA256,
            "--maximum-parallel-shards": "2",
        }
        argv = [str(self.python), gate.V404_PROGRAM, "run"]
        for flag in gate.V404_RUN_FLAGS:
            argv.extend((flag, values[flag]))
        return {
            "schema_version": 1,
            "plan_label": gate.V404_PLAN_LABEL,
            "commands": [
                {
                    "command_id": gate.V404_COMMAND_ID,
                    "argv": argv,
                    "cwd": ".",
                    "env": env,
                    "executable_sha256": python_snapshot.sha256,
                    "executable_size_bytes": python_snapshot.size_bytes,
                    "executable_chain_sha256": python_chain,
                }
            ],
            "expected_output_files": list(gate.V404_EXPECTED_OUTPUT_FILES),
        }

    def make_recovery_plan(self) -> dict:
        plan = self.make_plan()
        plan["plan_label"] = gate.V404_RECOVERY_PLAN_LABEL
        command = plan["commands"][0]
        command["command_id"] = gate.V404_RECOVERY_COMMAND_ID
        command["argv"][2] = "recover-mcmc"
        recovery_values = {
            "--recovery-contract": str((self.root / "recovery/contract.json").resolve()),
            "--expected-recovery-contract-sha256": "c" * 64,
            "--expected-recovery-contract-size-bytes": "12345",
            "--donor-work-shard-root": str((self.root / "donor/work").resolve()),
            "--donor-raw-root": str((self.root / "donor/raw").resolve()),
            "--donor-evidence-root": str((self.root / "donor/evidence").resolve()),
            "--donor-attestation-contract": str(
                (self.root / "donor/attestation-contract.json").resolve()
            ),
            "--donor-command-plan": str((self.root / "donor/plan.json").resolve()),
            "--donor-numerical-runtime-manifest": str(
                (self.root / "donor/runtime.json").resolve()
            ),
            "--donor-source-archive": str((self.root / "donor/source.tar").resolve()),
            "--source-transition-evidence": str(
                (self.root / "recovery/source-transition.json").resolve()
            ),
            "--recovery-qualification-report": str(
                (self.root / "recovery/qualification.json").resolve()
            ),
            "--ssh-keygen-executable": str(self.ssh_keygen),
        }
        for flag in gate.V404_RECOVERY_FLAGS:
            command["argv"].extend((flag, recovery_values[flag]))
        return plan

    def make_contract(self) -> dict:
        commit = run([str(self.git), "rev-parse", "HEAD"], cwd=self.source).decode().strip()
        tree = run(
            [str(self.git), "rev-parse", "HEAD^{tree}"], cwd=self.source
        ).decode().strip()
        archive = run(
            [str(self.git), "archive", "--format=tar", "HEAD"], cwd=self.source
        )
        controller_snapshot = gate.read_snapshot(Path(gate.__file__), "controller")
        git_snapshot = gate.read_snapshot(self.git, "git")
        ssh_snapshot = gate.read_snapshot(self.ssh_keygen, "ssh-keygen")
        plan_snapshot = gate.read_snapshot(self.plan_path, "plan")
        runtime_snapshot = gate.read_snapshot(self.runtime_path, "runtime")
        return {
            "schema_version": 1,
            "contract_id": "fixture-local-run-v1",
            "policy": {
                "start_signature_namespace": gate.START_NAMESPACE,
                "completion_signature_namespace": gate.COMPLETION_NAMESPACE,
                "nonce_bytes": 32,
                "required_distinct_signers": 2,
                "execution_controller": "verify_local_run_attestation.execute_plan",
                "command_execution": "subprocess_run_exact_argv_env_cwd_shell_false",
                "require_clean_exact_private_source": True,
                "require_archive_extracted_execution_tree": True,
                "require_exact_output_file_set": True,
                "require_shell_false": True,
                "public_report_disclosure": "hashes_status_counts_and_timings_only",
                "controller_sha256": controller_snapshot.sha256,
                "allowed_execution_environments": ["fixture_environment"],
            },
            "attestation_signers": copy.deepcopy(self.signers),
            "candidates": [
                {
                    "id": "fixture-candidate",
                    "role": "qualification_candidate",
                    "qualification_eligible": True,
                    "production_accepted": False,
                    "source_lock": {
                        "public_repository": gate.PUBLIC_REPOSITORY,
                        "private_repository": gate.PRIVATE_REPOSITORY,
                        "commit": commit,
                        "tree": tree,
                        "archive_sha256": hashlib.sha256(archive).hexdigest(),
                        "archive_size_bytes": len(archive),
                        "git_executable": gate.snapshot_evidence(git_snapshot),
                        "ssh_keygen_executable": gate.snapshot_evidence(ssh_snapshot),
                    },
                    "command_plan": gate.snapshot_evidence(plan_snapshot),
                    "numerical_runtime_manifest": gate.snapshot_evidence(
                        runtime_snapshot
                    ),
                    "accepted_report": None,
                    "note": "Synthetic qualification fixture.",
                }
            ],
        }

    def execute(self) -> dict:
        return gate.execute_plan(
            contract_path=self.contract_path,
            candidate_id="fixture-candidate",
            public_source_repo=self.public_source,
            source_repo=self.source,
            plan_path=self.plan_path,
            runtime_path=self.runtime_path,
            output_root=self.output,
            evidence_dir=self.evidence,
            execution_root=self.execution,
            start_signer_id="fixture-signer-a",
            start_signing_key=self.key_a,
            completion_signer_id="fixture-signer-b",
            completion_signing_key=self.key_b,
            execution_environment="fixture_environment",
            git_executable=self.git,
            ssh_keygen_executable=self.ssh_keygen,
            report_path=self.report,
        )

    def verify(self, *, qualification: bool = True, report: Path | None = None) -> dict:
        return gate.verify_run(
            contract_path=self.contract_path,
            candidate_id="fixture-candidate",
            public_source_repo=self.public_source,
            source_repo=self.source,
            plan_path=self.plan_path,
            runtime_path=self.runtime_path,
            output_root=self.output,
            evidence_dir=self.evidence,
            execution_root=self.execution,
            execution_environment="fixture_environment",
            git_executable=self.git,
            ssh_keygen_executable=self.ssh_keygen,
            report_path=report,
            qualification_mode=qualification,
        )


class LocalRunAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.cleanup()

    def assertFails(self, callable_object, pattern: str | None = None) -> None:
        with self.assertRaises(gate.AttestationError) as caught:
            callable_object()
        if pattern is not None:
            self.assertIn(pattern, str(caught.exception))

    def test_git_archive_paths_allow_dotfiles_and_reject_unsafe_forms(self) -> None:
        archive = run(
            [str(self.fixture.git), "archive", "--format=tar", "HEAD"],
            cwd=self.fixture.source,
        )
        files, directories = gate.archive_members(archive)
        self.assertIn(".gitattributes", files)
        self.assertIn(".gitignore", files)
        self.assertIn(".github", directories)
        self.assertIn(".github/workflows/fixture.yml", files)

        allowed = (
            (".gitattributes", False, ".gitattributes"),
            (".gitignore", False, ".gitignore"),
            (".github", True, ".github"),
            (".github/", True, ".github"),
            (".github/workflows/verify.yml", False, ".github/workflows/verify.yml"),
        )
        for value, is_directory, expected in allowed:
            with self.subTest(allowed=value):
                self.assertEqual(
                    gate.safe_archive_relative(
                        value, "archive fixture", is_directory=is_directory
                    ),
                    expected,
                )

        forbidden = (
            "",
            ".",
            "..",
            "../escape",
            "a/../escape",
            "/absolute",
            "a//b",
            "a\\b",
            "a:b",
            "C:/ads",
            "a\x00b",
            "a\rb",
            "a\nb",
            "regular-file/",
        )
        for value in forbidden:
            with self.subTest(forbidden=repr(value)):
                self.assertFails(
                    lambda value=value: gate.safe_archive_relative(
                        value, "archive fixture", is_directory=False
                    )
                )

    def test_git_archive_rejects_links_and_case_collisions(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            target = tarfile.TarInfo("target.txt")
            target.size = 1
            archive.addfile(target, io.BytesIO(b"x"))
            link = tarfile.TarInfo("link.txt")
            link.type = tarfile.SYMTYPE
            link.linkname = "target.txt"
            archive.addfile(link)
        self.assertFails(
            lambda: gate.archive_members(buffer.getvalue()),
            "link or special member",
        )

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name in ("README.md", "Readme.md"):
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        self.assertFails(
            lambda: gate.archive_members(buffer.getvalue()),
            "case-colliding paths",
        )

    def test_release_contract_has_one_valid_lifecycle_state_and_two_real_signers(self) -> None:
        contract_path = ROOT / "provenance" / "LOCAL_RUN_ATTESTATION_CONTRACT_v4_0_4.json"
        value, _snapshot = gate.load_json_snapshot(contract_path, "release contract")
        contract, candidates = gate.validate_contract(value)
        self.assertEqual(tuple(contract["attestation_signers"]), gate.PINNED_SIGNERS)
        candidate = candidates["v4.0.4-local-production-pending"]
        if candidate["production_accepted"]:
            self.assertIsNotNone(candidate["accepted_report"])
            self.assertTrue(
                all(
                    candidate["source_lock"][field] is not None
                    for field in (
                        "commit",
                        "tree",
                        "archive_sha256",
                        "archive_size_bytes",
                        "git_executable",
                        "ssh_keygen_executable",
                    )
                )
            )
        else:
            self.assertIsNone(candidate["accepted_report"])
            for field in (
                "commit",
                "tree",
                "archive_sha256",
                "archive_size_bytes",
                "git_executable",
                "ssh_keygen_executable",
            ):
                self.assertIsNone(candidate["source_lock"][field])
        controller = gate.read_snapshot(Path(gate.__file__), "release controller")
        self.assertEqual(
            contract["policy"]["controller_sha256"], controller.sha256
        )

    def test_git_origin_parser_accepts_only_canonical_github_forms(self) -> None:
        expected = "fixture/repository"
        for origin in (
            "https://github.com/fixture/repository.git",
            "git@github.com:fixture/repository.git",
            "ssh://git@github.com/fixture/repository.git",
        ):
            with self.subTest(origin=origin):
                self.assertEqual(gate.normalize_repository_slug(origin), expected)
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
            with self.subTest(origin=origin):
                self.assertFails(
                    lambda origin=origin: gate.normalize_repository_slug(origin),
                    "canonical",
                )

    def test_execute_and_verify_emit_hash_only_public_report(self) -> None:
        report = self.fixture.execute()
        self.assertEqual(report["qualification_status"], "PASS")
        self.assertEqual(report, self.fixture.verify())
        rendered = gate.canonical_json_bytes(report).decode("utf-8")
        for forbidden in (
            str(self.fixture.root),
            gate.V404_PROGRAM,
            "result.bin",
            "argv",
            "cwd",
            "environment",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_existing_public_report_is_verified_without_overwrite(self) -> None:
        report = self.fixture.execute()
        before = self.fixture.report.read_bytes()
        snapshot = gate.verify_existing_public_report(report, self.fixture.report)
        self.assertEqual(snapshot.data, before)
        self.assertEqual(self.fixture.report.read_bytes(), before)
        changed = dict(report)
        changed["output_file_count"] = report["output_file_count"] + 1
        self.fixture.report.write_bytes(gate.canonical_json_bytes(changed))
        self.assertFails(
            lambda: gate.verify_existing_public_report(report, self.fixture.report),
            "differs from reverified evidence",
        )

    def test_unaccepted_candidate_keeps_production_gate_closed(self) -> None:
        self.fixture.execute()
        self.assertFails(
            lambda: self.fixture.verify(qualification=False),
            "production gate remains closed",
        )

    def test_reviewed_report_can_be_hash_locked_without_changing_report(self) -> None:
        report = self.fixture.execute()
        report_bytes = gate.canonical_json_bytes(report)
        candidate = self.fixture.contract["candidates"][0]
        candidate["production_accepted"] = True
        candidate["accepted_report"] = {
            "report_id": report["report_id"],
            "sha256": hashlib.sha256(report_bytes).hexdigest(),
            "size_bytes": len(report_bytes),
        }
        write_json(self.fixture.contract_path, self.fixture.contract)
        self.assertEqual(report, self.fixture.verify(qualification=False))

    def test_plan_drift_is_rejected_before_execution(self) -> None:
        self.fixture.plan["plan_label"] = "drifted-plan"
        write_json(self.fixture.plan_path, self.fixture.plan)
        self.assertFails(self.fixture.execute, "command plan label must be exactly")

    def test_source_and_archive_drift_are_rejected(self) -> None:
        program = self.fixture.source / Path(*PurePosixPath(gate.V404_PROGRAM).parts)
        program.write_text(
            "raise SystemExit(0)\n", encoding="utf-8", newline="\n"
        )
        self.assertFails(self.fixture.execute, "shadow changes")
        run([str(self.fixture.git), "add", gate.V404_PROGRAM], cwd=self.fixture.source)
        run(
            [str(self.fixture.git), "commit", "-q", "-m", "archive drift"],
            cwd=self.fixture.source,
        )
        self.assertFails(self.fixture.execute, "identity differs")

    def test_private_roots_cannot_overlap_source_or_each_other(self) -> None:
        self.fixture.output = self.fixture.source / "private-output"
        self.fixture.plan = self.fixture.make_plan()
        write_json(self.fixture.plan_path, self.fixture.plan)
        plan_snapshot = gate.read_snapshot(self.fixture.plan_path, "overlap plan")
        self.fixture.contract["candidates"][0]["command_plan"] = gate.snapshot_evidence(
            plan_snapshot
        )
        write_json(self.fixture.contract_path, self.fixture.contract)
        self.assertFails(self.fixture.execute, "outside the private source")

    def test_output_swap_and_extra_shadow_file_are_rejected(self) -> None:
        self.fixture.execute()
        output = self.fixture.output / gate.V404_EXPECTED_OUTPUT_FILES[0]
        original = output.read_bytes()
        output.write_bytes(b"x" * len(original))
        self.assertFails(self.fixture.verify, "strict signed manifest")
        output.write_bytes(original)
        (self.fixture.output / "shadow.bin").write_bytes(b"shadow")
        self.assertFails(self.fixture.verify, "exact file set")

    def test_output_symlink_is_rejected(self) -> None:
        self.fixture.execute()
        output = self.fixture.output / gate.V404_EXPECTED_OUTPUT_FILES[0]
        target = self.fixture.root / "outside.bin"
        target.write_bytes(output.read_bytes())
        output.unlink()
        try:
            output.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assertFails(self.fixture.verify, "link/reparse")

    def test_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        original = self.fixture.plan_path.read_text(encoding="utf-8")
        self.fixture.plan_path.write_text(
            '{"schema_version":1,"schema_version":1}\n',
            encoding="utf-8",
            newline="\n",
        )
        self.assertFails(self.fixture.execute, "duplicate JSON key")
        self.fixture.plan_path.write_text(
            '{"schema_version":1,"plan_label":1e999}\n',
            encoding="utf-8",
            newline="\n",
        )
        self.assertFails(self.fixture.execute, "non-finite number")
        self.fixture.plan_path.write_text(original, encoding="utf-8", newline="\n")

    def test_wrong_key_and_same_signer_are_rejected(self) -> None:
        self.assertFails(
            lambda: gate.execute_plan(
                contract_path=self.fixture.contract_path,
                candidate_id="fixture-candidate",
                public_source_repo=self.fixture.public_source,
                source_repo=self.fixture.source,
                plan_path=self.fixture.plan_path,
                runtime_path=self.fixture.runtime_path,
                output_root=self.fixture.output,
                evidence_dir=self.fixture.evidence,
                execution_root=self.fixture.execution,
                start_signer_id="fixture-signer-a",
                start_signing_key=self.fixture.key_wrong,
                completion_signer_id="fixture-signer-b",
                completion_signing_key=self.fixture.key_b,
                execution_environment="fixture_environment",
                git_executable=self.fixture.git,
                ssh_keygen_executable=self.fixture.ssh_keygen,
                report_path=self.fixture.report,
            ),
            "does not match",
        )
        self.assertFails(
            lambda: gate.execute_plan(
                contract_path=self.fixture.contract_path,
                candidate_id="fixture-candidate",
                public_source_repo=self.fixture.public_source,
                source_repo=self.fixture.source,
                plan_path=self.fixture.plan_path,
                runtime_path=self.fixture.runtime_path,
                output_root=self.fixture.output,
                evidence_dir=self.fixture.evidence,
                execution_root=self.fixture.execution,
                start_signer_id="fixture-signer-a",
                start_signing_key=self.fixture.key_a,
                completion_signer_id="fixture-signer-a",
                completion_signing_key=self.fixture.key_a,
                execution_environment="fixture_environment",
                git_executable=self.fixture.git,
                ssh_keygen_executable=self.fixture.ssh_keygen,
                report_path=self.fixture.report,
            ),
            "must be distinct",
        )

    def test_self_rebased_output_manifest_cannot_bypass_signature(self) -> None:
        self.fixture.execute()
        output = self.fixture.output / gate.V404_EXPECTED_OUTPUT_FILES[0]
        output.write_bytes(b"attacker-rebased\n")
        manifest_path = self.fixture.evidence / gate.OUTPUT_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
        manifest["files"][0]["size_bytes"] = output.stat().st_size
        manifest_path.write_bytes(gate.canonical_json_bytes(manifest))
        manifest_snapshot = gate.read_snapshot(manifest_path, "modified manifest")
        completion_path = self.fixture.evidence / gate.COMPLETION_NAME
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        completion["output_manifest"] = gate.snapshot_evidence(manifest_snapshot)
        completion.pop("completion_id")
        completion = gate.document_with_id(completion, "completion_id")
        completion_path.write_bytes(gate.canonical_json_bytes(completion))
        self.assertFails(self.fixture.verify, "signature is invalid")

    def test_cross_run_completion_replay_is_rejected(self) -> None:
        self.fixture.execute()
        first_completion = (self.fixture.evidence / gate.COMPLETION_NAME).read_bytes()
        first_signature = (
            self.fixture.evidence / gate.COMPLETION_SIGNATURE_NAME
        ).read_bytes()
        shutil.rmtree(self.fixture.output)
        shutil.rmtree(self.fixture.evidence)
        shutil.rmtree(self.fixture.execution)
        self.fixture.report.unlink()
        self.fixture.execute()
        (self.fixture.evidence / gate.COMPLETION_NAME).write_bytes(first_completion)
        (self.fixture.evidence / gate.COMPLETION_SIGNATURE_NAME).write_bytes(
            first_signature
        )
        self.assertFails(self.fixture.verify, "completion attestation binding")

    def test_path_traversal_and_executable_drift_are_rejected(self) -> None:
        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"][0]["argv"][1] = "../writer.py"
        self.assertFails(
            lambda: gate.validate_plan(bad, self.fixture.runtime), "exact tracked"
        )
        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"][0]["executable_sha256"] = "0" * 64
        write_json(self.fixture.plan_path, bad)
        snapshot = gate.read_snapshot(self.fixture.plan_path, "bad plan")
        self.fixture.contract["candidates"][0]["command_plan"] = gate.snapshot_evidence(
            snapshot
        )
        write_json(self.fixture.contract_path, self.fixture.contract)
        self.assertFails(self.fixture.execute, "Python executable differs")

    def test_execute_rejects_plan_git_rebinding_from_attested_tool(self) -> None:
        bad = copy.deepcopy(self.fixture.plan)
        argv = bad["commands"][0]["argv"]
        argv[argv.index("--git-executable") + 1] = str(
            (self.fixture.root / "untrusted-git").resolve()
        )
        write_json(self.fixture.plan_path, bad)
        snapshot = gate.read_snapshot(self.fixture.plan_path, "rebound plan")
        self.fixture.contract["candidates"][0]["command_plan"] = (
            gate.snapshot_evidence(snapshot)
        )
        write_json(self.fixture.contract_path, self.fixture.contract)
        self.assertFails(self.fixture.execute, "canonical run path")

    def test_plan_rejects_noncanonical_command_outputs_and_environment(self) -> None:
        mutations = []

        bad = copy.deepcopy(self.fixture.plan)
        bad["plan_label"] = "arbitrary-production"
        mutations.append((bad, "plan label"))

        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"].append(copy.deepcopy(bad["commands"][0]))
        mutations.append((bad, "exactly one"))

        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"][0]["command_id"] = "arbitrary-command"
        mutations.append((bad, "command id"))

        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"][0]["argv"][1] = "research/arbitrary.py"
        mutations.append((bad, "exact tracked"))

        bad = copy.deepcopy(self.fixture.plan)
        bad["commands"][0]["argv"][3] = "--arbitrary-flag"
        mutations.append((bad, "flags/order"))

        bad = copy.deepcopy(self.fixture.plan)
        bad["expected_output_files"] = [gate.V404_EXPECTED_OUTPUT_FILES[0]]
        mutations.append((bad, "exact 88-file"))

        for extra in ("PYTHONPATH", "LD_PRELOAD", "ARBITRARY_EXTRA"):
            bad = copy.deepcopy(self.fixture.plan)
            bad["commands"][0]["env"][extra] = "untrusted"
            mutations.append((bad, "environment keys"))

        for mutated, expected in mutations:
            with self.subTest(expected=expected):
                self.assertFails(
                    lambda mutated=mutated: gate.validate_plan(
                        mutated, self.fixture.runtime
                    ),
                    expected,
                )

    def test_exact_recovery_plan_schema_and_bindings_fail_closed(self) -> None:
        recovery = self.fixture.make_recovery_plan()
        self.assertEqual(gate.validate_plan(recovery, self.fixture.runtime), recovery)
        gate.validate_plan_bindings(
            recovery,
            self.fixture.runtime,
            self.fixture.execution.resolve(strict=False),
            self.fixture.output.resolve(strict=False),
            self.fixture.runtime_path.resolve(),
            self.fixture.plan_path.resolve(),
            self.fixture.git,
            self.fixture.source,
            self.fixture.public_source,
            require_extracted_programs=False,
            trusted_ssh_keygen_executable=self.fixture.ssh_keygen,
        )

        mutations = []
        bad = copy.deepcopy(recovery)
        bad["commands"][0]["argv"][2] = "run"
        mutations.append((bad, "exact tracked"))
        bad = copy.deepcopy(recovery)
        bad["commands"][0]["command_id"] = gate.V404_COMMAND_ID
        mutations.append((bad, "command id"))
        bad = copy.deepcopy(recovery)
        argv = bad["commands"][0]["argv"]
        argv[argv.index("--expected-recovery-contract-size-bytes") + 1] = "012345"
        mutations.append((bad, "canonical positive integer"))
        bad = copy.deepcopy(recovery)
        argv = bad["commands"][0]["argv"]
        del argv[argv.index("--donor-raw-root") : argv.index("--donor-raw-root") + 2]
        mutations.append((bad, "string array"))
        for mutated, expected in mutations:
            with self.subTest(expected=expected):
                self.assertFails(
                    lambda mutated=mutated: gate.validate_plan(
                        mutated, self.fixture.runtime
                    ),
                    expected,
                )

        bad = copy.deepcopy(recovery)
        argv = bad["commands"][0]["argv"]
        argv[argv.index("--donor-raw-root") + 1] = argv[
            argv.index("--private-raw-root") + 1
        ]
        self.assertFails(
            lambda: gate.validate_plan_bindings(
                bad,
                self.fixture.runtime,
                self.fixture.execution.resolve(strict=False),
                self.fixture.output.resolve(strict=False),
                self.fixture.runtime_path.resolve(),
                self.fixture.plan_path.resolve(),
                self.fixture.git,
                self.fixture.source,
                self.fixture.public_source,
                require_extracted_programs=False,
                trusted_ssh_keygen_executable=self.fixture.ssh_keygen,
            ),
            "overlaps mutable",
        )

        self.assertFails(
            lambda: gate.validate_plan_bindings(
                recovery,
                self.fixture.runtime,
                self.fixture.execution.resolve(strict=False),
                self.fixture.output.resolve(strict=False),
                self.fixture.runtime_path.resolve(),
                self.fixture.plan_path.resolve(),
                self.fixture.git,
                self.fixture.source,
                self.fixture.public_source,
                require_extracted_programs=False,
                trusted_ssh_keygen_executable=self.fixture.key_wrong,
            ),
            "trusted attestation tool",
        )

    def test_executable_chain_rejects_linked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="executable-ancestor-") as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            executable = real / Path(sys.executable).name
            shutil.copy2(sys.executable, executable)
            linked = root / "linked"
            try:
                linked.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                if os.name != "nt":
                    self.skipTest(f"directory symlinks unavailable: {exc}")
                completed = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(linked), str(real)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    check=False,
                )
                if completed.returncode != 0:
                    self.skipTest("directory symlinks and junctions are unavailable")
            self.assertFails(
                lambda: gate.executable_chain(linked / executable.name),
                "symlink/reparse/junction ancestor",
            )

    def test_executable_chain_rechecks_ancestor_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="executable-replace-") as temporary:
            root = Path(temporary)
            ancestor = root / "ancestor"
            binary = ancestor / "bin" / Path(sys.executable).name
            binary.parent.mkdir(parents=True)
            shutil.copy2(sys.executable, binary)
            old = root / "ancestor-old"
            original_snapshot = gate.read_snapshot
            swapped = False

            def snapshot_then_replace(*args, **kwargs):
                nonlocal swapped
                snapshot = original_snapshot(*args, **kwargs)
                if args[1] == "runtime executable target" and not swapped:
                    ancestor.rename(old)
                    binary.parent.mkdir(parents=True)
                    shutil.copy2(sys.executable, binary)
                    swapped = True
                return snapshot

            with mock.patch.object(gate, "read_snapshot", snapshot_then_replace):
                self.assertFails(
                    lambda: gate.executable_chain(binary),
                    "ancestor was replaced or redirected",
                )

    def test_exclusive_writer_cannot_be_redirected_by_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="exclusive-parent-") as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            original_parent = root / "bound-parent"
            output = parent / "plan.json"
            original_open = gate._open_exclusive_child
            redirected = False

            def swap_then_open(binding, name, flags, mode):
                nonlocal redirected
                try:
                    parent.rename(original_parent)
                    parent.mkdir()
                    redirected = True
                except OSError:
                    # Windows holds a non-delete-share directory handle, so the
                    # attempted redirect is prevented before the child open.
                    pass
                return original_open(binding, name, flags, mode)

            with mock.patch.object(gate, "_open_exclusive_child", swap_then_open):
                try:
                    gate.atomic_write_new(output, b"locked\n", "test output")
                except gate.AttestationError as exc:
                    self.assertIn("replaced or redirected", str(exc))
                    self.assertTrue(redirected)
                    self.assertFalse(output.exists())
                    self.assertFalse((original_parent / output.name).exists())
                else:
                    self.assertFalse(redirected)
                    self.assertEqual(output.read_bytes(), b"locked\n")


if __name__ == "__main__":
    unittest.main()
