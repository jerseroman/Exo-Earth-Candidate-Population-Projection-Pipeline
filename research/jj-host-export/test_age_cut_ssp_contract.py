#!/usr/bin/env python3
"""Adversarial tests for the age-cut SSP qualification trust boundary."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from test_age_cut_sensitivity import Fixture, sha256  # noqa: E402
import verify_age_cut_sensitivity as age_verifier  # noqa: E402
import verify_age_cut_ssp_contract as contract_verifier  # noqa: E402
import verify_host_artifact_contract as host_contract  # noqa: E402


CANONICAL_CONTRACT = (
    REPOSITORY_ROOT / "provenance" / "AGE_CUT_SSP_CONTRACT_v4_0_4.json"
)


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def lock_report_hash(fixture: Fixture) -> None:
    contract = json.loads(fixture.ssp_contract.read_text(encoding="utf-8"))
    contract["artifact_sets"][0]["qualification_report"]["sha256"] = sha256(
        fixture.qualification_report
    )
    write_json(fixture.ssp_contract, contract)


def refresh_report_id(report: dict) -> None:
    body = dict(report)
    body.pop("qualification_id")
    report["qualification_id"] = "sha256:" + hashlib.sha256(
        contract_verifier.canonical_json_bytes(body)
    ).hexdigest()


class AgeCutSSPContractTests(unittest.TestCase):
    def test_controlled_executor_runs_twice_from_fresh_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def initialize_repository(path: Path, repository: str, files: dict[str, str]) -> str:
                for name, content in files.items():
                    target = path / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8", newline="\n")
                subprocess.check_call(["git", "init", "-q"], cwd=path)
                subprocess.check_call(
                    ["git", "config", "user.email", "fixture@example.invalid"], cwd=path
                )
                subprocess.check_call(
                    ["git", "config", "user.name", "Fresh Run Fixture"], cwd=path
                )
                subprocess.check_call(
                    ["git", "config", "core.autocrlf", "false"], cwd=path
                )
                subprocess.check_call(
                    [
                        "git",
                        "remote",
                        "add",
                        "origin",
                        f"https://github.com/{repository}.git",
                    ],
                    cwd=path,
                )
                subprocess.check_call(["git", "add", "."], cwd=path)
                subprocess.check_call(
                    ["git", "commit", "-q", "-m", "fixture"], cwd=path
                )
                return subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=path, text=True
                ).strip()

            runner = """#!/usr/bin/env python3
import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--jj-root'); p.add_argument('--run-dir'); p.add_argument('--out')
p.add_argument('--iso'); p.add_argument('--expected-radial-step-kpc')
a = p.parse_args()
tab = Path(a.run_dir) / 'output' / 'fresh' / 'pop' / 'tab'
tab.mkdir(parents=True)
header = 'N,age,FeH,Mini,Mf,logL,logT,logg,G_EDR3,GBP_EDR3,GRP_EDR3,disk_label\\n'
for i in range(21):
    radius = 4.0 + 0.5 * i
    for code, label in (('d', 0), ('t', 1)):
        name = f'SSP_R{radius:.1f}_{code}_Padova.csv'
        (tab / name).write_text(header + f'0.1,6,-0.1,1,1,0,3.76,4.4,5,5,5,{label}\\n', encoding='utf-8', newline='\\n')
"""
            source_files = {
                contract_verifier.GENERATION_PROGRAM: runner,
                "README.txt": "identical source tree\n",
            }
            public_root = root / "public"
            private_root = root / "private"
            public_root.mkdir()
            private_root.mkdir()
            initialize_repository(public_root, "owner/public", source_files)
            initialize_repository(private_root, "owner/private", source_files)

            jj_root = root / "jj"
            jj_root.mkdir()
            sfr_text = "# fixture\n3.5 3 0.7 9 1 26.3\n"
            jj_commit = initialize_repository(
                jj_root,
                "askenja/jjmodel",
                {
                    "jjmodel/tutorials/tutorial2/parameters": "run_mode 1\n",
                    "jjmodel/tutorials/tutorial2/sfrd_peaks_parameters": sfr_text,
                },
            )

            def archive(repository_root: Path, name: str) -> Path:
                destination = root / name
                destination.write_bytes(
                    subprocess.check_output(
                        ["git", "archive", "--format=tar", "HEAD"],
                        cwd=repository_root,
                    )
                )
                return destination

            public_archive = archive(public_root, "public.tar")
            private_archive = archive(private_root, "private.tar")
            jj_archive = archive(jj_root, "jj.tar")
            parameters = root / "parameters"
            parameters.write_text(
                "run_mode 1\nout_dir 'tutorial2'\nnprocess 2\nRmin 4.0\nRmax 14.0\ndR 0.5\nimfkey 0\n",
                encoding="utf-8",
                newline="\n",
            )
            sfr = root / "sfrd_peaks_parameters"
            sfr.write_text(sfr_text, encoding="utf-8", newline="\n")
            runtime = root / contract_verifier.RUNTIME_NAME
            runtime_document = {
                "schema_version": 1,
                "status": "PASS",
                "python": sys.version,
                "python_executable": sys.executable,
                "platform": sys.platform,
                "machine": "fixture",
                "numpy_version": "1.23.5",
                "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
                "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
                "selected_cpu_features": dict(contract_verifier.EXPECTED_CPU_FEATURES),
                "environment": dict(contract_verifier.EXPECTED_NUMERICAL_ENV),
            }
            write_json(runtime, runtime_document)
            padova = root / contract_verifier.PADOVA_FILENAME
            padova_member = b"fixture Padova isochrone bytes\n"
            with zipfile.ZipFile(padova, "w", compression=zipfile.ZIP_STORED) as archive_file:
                archive_file.writestr("fixture-isochrone.dat", padova_member)
            extracted = (
                jj_root
                / "jjmodel"
                / "input"
                / "isochrones"
                / "Padova"
                / "fixture-isochrone.dat"
            )
            extracted.parent.mkdir(parents=True)
            extracted.write_bytes(padova_member)

            old_values = (
                contract_verifier.JJ_SHA,
                contract_verifier.PADOVA_SHA256,
                contract_verifier.PADOVA_SIZE_BYTES,
            )
            old_environment_detector = contract_verifier.detect_execution_environment
            try:
                contract_verifier.JJ_SHA = jj_commit
                contract_verifier.PADOVA_SHA256 = sha256(padova)
                contract_verifier.PADOVA_SIZE_BYTES = padova.stat().st_size
                contract_verifier.detect_execution_environment = (
                    lambda: "local_ubuntu_22_04_wsl2"
                )
                document = json.loads(CANONICAL_CONTRACT.read_text(encoding="utf-8"))
                document["locked_inputs"]["jj_commit"] = jj_commit
                document["locked_inputs"]["padova_archive"]["sha256"] = sha256(padova)
                document["locked_inputs"]["padova_archive"]["size_bytes"] = padova.stat().st_size
                key_a = root / "key-a"
                key_b = root / "key-b"
                for key in (key_a, key_b):
                    subprocess.check_call(
                        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)]
                    )
                document["artifact_sets"][0]["attestation_signers"] = [
                    {
                        "signer_id": "fresh-authority-a",
                        "public_key": contract_verifier.signing_public_key(key_a),
                    },
                    {
                        "signer_id": "fresh-authority-b",
                        "public_key": contract_verifier.signing_public_key(key_b),
                    },
                ]
                contract_path = root / CANONICAL_CONTRACT.name
                write_json(contract_path, document)
                candidate_id = document["artifact_sets"][0]["id"]

                common = {
                    "contract_path": contract_path,
                    "jj_root": jj_root,
                    "jj_source_archive": jj_archive,
                    "runtime_parameters": parameters,
                    "sfr_peaks_parameters": sfr,
                    "numerical_runtime_manifest": runtime,
                    "padova_archive": padova,
                    "public_source_root": public_root,
                    "public_repository": "owner/public",
                    "public_source_archive": public_archive,
                    "private_source_root": private_root,
                    "private_repository": "owner/private",
                    "private_source_archive": private_archive,
                    "candidate_set_id": candidate_id,
                }
                first = contract_verifier.execute_fresh_repetition(
                    **common,
                    signer_id="fresh-authority-a",
                    signing_key=key_a,
                    repeat_label="controlled-a",
                    execution_root=root / "execution-a",
                    output_root=root / "repeat-a",
                )
                second = contract_verifier.execute_fresh_repetition(
                    **common,
                    signer_id="fresh-authority-b",
                    signing_key=key_b,
                    repeat_label="controlled-b",
                    execution_root=root / "execution-b",
                    output_root=root / "repeat-b",
                )
                self.assertNotEqual(first["execution_id"], second["execution_id"])
                self.assertNotEqual(first["nonce_hex"], second["nonce_hex"])
                report = contract_verifier.qualify_repetitions(
                    contract_path,
                    root / "repeat-a",
                    root / "repeat-b",
                    candidate_id,
                    root / "qualification.json",
                )
                self.assertEqual(report["status"], "PASS")

                marker = root / "TRANSIENT_MUTABLE_RUNNER_EXECUTED"
                mutable_runner = private_root / contract_verifier.GENERATION_PROGRAM
                original_runner = mutable_runner.read_bytes()
                original_subprocess_run = contract_verifier.subprocess.run

                def transient_swap(command, *args, **kwargs):
                    is_generator = (
                        isinstance(command, (list, tuple))
                        and len(command) >= 4
                        and command[0] == sys.executable
                        and command[1:3] == ["-I", "-B"]
                        and Path(command[3]).name == "run_jj_export.py"
                    )
                    if not is_generator:
                        return original_subprocess_run(command, *args, **kwargs)
                    mutable_runner.write_text(
                        "from pathlib import Path\n"
                        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                        "raise SystemExit('TRANSIENT_MUTABLE_RUNNER_EXECUTED')\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                    try:
                        return original_subprocess_run(command, *args, **kwargs)
                    finally:
                        mutable_runner.write_bytes(original_runner)

                with mock.patch.object(
                    contract_verifier.subprocess,
                    "run",
                    side_effect=transient_swap,
                ):
                    transient = contract_verifier.execute_fresh_repetition(
                        **common,
                        signer_id="fresh-authority-a",
                        signing_key=key_a,
                        repeat_label="controlled-transient-source-swap",
                        execution_root=root / "execution-transient",
                        output_root=root / "repeat-transient",
                    )
                self.assertEqual(
                    transient["label"], "controlled-transient-source-swap"
                )
                self.assertFalse(marker.exists())

                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.execute_fresh_repetition(
                        **common,
                        signer_id="fresh-authority-a",
                        signing_key=key_a,
                        repeat_label="controlled-reuse",
                        execution_root=root / "execution-a",
                        output_root=root / "repeat-reuse",
                    )
                extra_overlay = extracted.parent / "shadow.py"
                extra_overlay.write_text("VALUE = 1\n", encoding="utf-8")
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.execute_fresh_repetition(
                        **common,
                        signer_id="fresh-authority-a",
                        signing_key=key_a,
                        repeat_label="controlled-shadow",
                        execution_root=root / "execution-shadow",
                        output_root=root / "repeat-shadow",
                    )
                extra_overlay.unlink()

                ignored_marker = root / "IGNORED_JSON_SHADOW_EXECUTED"
                ignored_shadow = private_root / "json.py"
                ignored_shadow.write_text(
                    "from pathlib import Path\n"
                    f"Path({str(ignored_marker)!r}).write_text('executed', encoding='utf-8')\n"
                    "raise SystemExit('IGNORED_JSON_SHADOW_EXECUTED')\n",
                    encoding="utf-8",
                    newline="\n",
                )
                exclude = private_root / ".git" / "info" / "exclude"
                with exclude.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write("json.py\n")
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.execute_fresh_repetition(
                        **common,
                        signer_id="fresh-authority-a",
                        signing_key=key_a,
                        repeat_label="controlled-ignored-json-shadow",
                        execution_root=root / "execution-ignored-json",
                        output_root=root / "repeat-ignored-json",
                    )
                self.assertFalse(ignored_marker.exists())
            finally:
                (
                    contract_verifier.JJ_SHA,
                    contract_verifier.PADOVA_SHA256,
                    contract_verifier.PADOVA_SIZE_BYTES,
                ) = old_values
                contract_verifier.detect_execution_environment = old_environment_detector

    def test_repository_contract_is_initially_unaccepted(self) -> None:
        contract, _ = contract_verifier.load_contract(CANONICAL_CONTRACT)
        self.assertFalse(contract["artifact_sets"][0]["production_accepted"])
        with self.assertRaises(contract_verifier.SSPContractError):
            contract_verifier.accepted_candidate(contract)

    def test_canonical_accepted_contract_roundtrip_preserves_member_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            contract = json.loads(fixture.ssp_contract.read_text(encoding="utf-8"))
            fixture.ssp_contract.write_bytes(
                contract_verifier.canonical_json_bytes(contract)
            )
            result = contract_verifier.verify_accepted_repetition(
                fixture.ssp_contract,
                fixture.qualification_report,
                fixture.repeat_a,
            )
            self.assertEqual(
                result["artifact_set_id"],
                "v4.0.4-production-pending-qualification",
            )

            missing = json.loads(fixture.ssp_contract.read_text(encoding="utf-8"))
            missing_hashes = missing["artifact_sets"][0]["ssp_member_sha256"]
            removed_name = next(iter(missing_hashes))
            removed_digest = missing_hashes.pop(removed_name)
            fixture.ssp_contract.write_bytes(
                contract_verifier.canonical_json_bytes(missing)
            )
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.load_contract(fixture.ssp_contract)

            missing_hashes[removed_name] = removed_digest
            missing_hashes["SSP_R99.0_d_Padova.csv"] = "0" * 64
            fixture.ssp_contract.write_bytes(
                contract_verifier.canonical_json_bytes(missing)
            )
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.load_contract(fixture.ssp_contract)

    def test_same_root_and_exact_copytree_are_not_two_repetitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            for mode in ("same-root", "copytree"):
                with self.subTest(mode=mode):
                    second = fixture.repeat_a
                    if mode == "copytree":
                        second = fixture.root / "repeat-copy"
                        shutil.copytree(fixture.repeat_a, second)
                    destination = fixture.root / f"qualification-{mode}.json"
                    with self.assertRaises(contract_verifier.SSPContractError):
                        contract_verifier.qualify_repetitions(
                            fixture.ssp_contract,
                            fixture.repeat_a,
                            second,
                            json.loads(
                                fixture.ssp_contract.read_text(encoding="utf-8")
                            )["artifact_sets"][0]["id"],
                            destination,
                        )

    def test_duplicate_signer_id_or_public_key_contract_fails(self) -> None:
        for field in ("signer_id", "public_key"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                document = json.loads(fixture.ssp_contract.read_text(encoding="utf-8"))
                signers = document["artifact_sets"][0]["attestation_signers"]
                signers[1][field] = signers[0][field]
                write_json(fixture.ssp_contract, document)
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.load_contract(fixture.ssp_contract)

    def test_rehashed_fake_second_signature_fails_cryptographically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            report = json.loads(fixture.qualification_report.read_text(encoding="utf-8"))
            second = report["fresh_repetitions"][1]
            forged = b"not an OpenSSH signature"
            second["attestation_signature_base64"] = base64.b64encode(forged).decode(
                "ascii"
            )
            second["attestation_signature_sha256"] = hashlib.sha256(forged).hexdigest()
            refresh_report_id(report)
            write_json(fixture.qualification_report, report)
            lock_report_hash(fixture)
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.verify_accepted_repetition(
                    fixture.ssp_contract,
                    fixture.qualification_report,
                    fixture.repeat_a,
                )

    def test_fake_report_hash_and_self_identifier_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            report = json.loads(fixture.qualification_report.read_text(encoding="utf-8"))
            report["status"] = "FAIL"
            write_json(fixture.qualification_report, report)
            lock_report_hash(fixture)
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.verify_accepted_repetition(
                    fixture.ssp_contract,
                    fixture.qualification_report,
                    fixture.repeat_a,
                )

    def test_duplicate_label_and_source_provenance_forgery_fail(self) -> None:
        for mode in ("label", "source"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                report = json.loads(
                    fixture.qualification_report.read_text(encoding="utf-8")
                )
                second = report["fresh_repetitions"][1]
                if mode == "label":
                    second["label"] = report["fresh_repetitions"][0]["label"]
                else:
                    second["source_state"]["private_source"]["commit_sha"] = "7" * 40
                refresh_report_id(report)
                write_json(fixture.qualification_report, report)
                lock_report_hash(fixture)
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.verify_accepted_repetition(
                        fixture.ssp_contract,
                        fixture.qualification_report,
                        fixture.repeat_a,
                    )

    def test_changed_ssp_and_repetition_manifest_attacks_fail(self) -> None:
        for mode in ("ssp", "duplicate", "traversal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if mode == "ssp":
                    target = fixture.repeat_a / contract_verifier.SSP_MEMBERS[0]
                    target.write_bytes(target.read_bytes() + b"\n")
                else:
                    manifest = fixture.repeat_a / contract_verifier.REPETITION_MANIFEST_NAME
                    lines = manifest.read_text(encoding="utf-8").splitlines()
                    if mode == "duplicate":
                        lines[1] = lines[0]
                    else:
                        digest = lines[0].split("  ", 1)[0]
                        lines[0] = f"{digest}  ../{contract_verifier.PARAMETERS_NAME}"
                    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.verify_accepted_repetition(
                        fixture.ssp_contract,
                        fixture.qualification_report,
                        fixture.repeat_a,
                    )

    def test_unaccepted_host_contract_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))

            def rejected_host(_contract: Path, _root: Path) -> dict:
                raise host_contract.ContractError("candidate is not production accepted")

            with self.assertRaises(age_verifier.VerificationError):
                age_verifier._verify_age_cut_artifact(
                    fixture.artifact,
                    jj_root=fixture.jj_root,
                    run_dir=fixture.repeat_a,
                    canonical_host_root=fixture.canonical,
                    age_ssp_contract=fixture.ssp_contract,
                    ssp_qualification_report=fixture.qualification_report,
                    host_artifact_contract=fixture.host_contract,
                    expected_jj_commit=fixture.commit,
                    require_repository_contract_paths=False,
                    host_contract_check=rejected_host,
                )

    def test_contract_json_nonfinite_bool_and_coercion_fail(self) -> None:
        replacements = (
            ('"schema_version": 1', '"schema_version": 1e999'),
            ('"schema_version": 1', '"schema_version": true'),
            ('"schema_version": 1', '"schema_version": "1"'),
            (
                '"required_distinct_fresh_repetitions": 2',
                '"required_distinct_fresh_repetitions": 2.0',
            ),
        )
        for old, new in replacements:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / CANONICAL_CONTRACT.name
                content = CANONICAL_CONTRACT.read_text(encoding="utf-8")
                self.assertIn(old, content)
                path.write_text(content.replace(old, new, 1), encoding="utf-8")
                with self.assertRaises(contract_verifier.SSPContractError):
                    contract_verifier.load_contract(path)

    def test_untracked_shadow_and_non_git_archive_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            subprocess.check_call(["git", "init", "-q"], cwd=root)
            subprocess.check_call(
                ["git", "config", "user.email", "fixture@example.invalid"], cwd=root
            )
            subprocess.check_call(
                ["git", "config", "user.name", "Contract Fixture"], cwd=root
            )
            subprocess.check_call(
                [
                    "git",
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/owner/source.git",
                ],
                cwd=root,
            )
            (root / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "."], cwd=root)
            subprocess.check_call(["git", "commit", "-q", "-m", "fixture"], cwd=root)
            exact_archive = Path(temporary) / "source.tar"
            exact_archive.write_bytes(
                subprocess.check_output(
                    ["git", "archive", "--format=tar", "HEAD"], cwd=root
                )
            )
            accepted = contract_verifier.source_record(
                "public_release", "owner/source", root, exact_archive
            )
            self.assertEqual(accepted["repository"], "owner/source")
            (root / "shadow.py").write_text("VALUE = 2\n", encoding="utf-8")
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.source_record(
                    "public_release", "owner/source", root, exact_archive
                )
            (root / "shadow.py").unlink()
            arbitrary = Path(temporary) / "arbitrary.tar"
            arbitrary.write_bytes(b"not the committed archive")
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.source_record(
                    "public_release", "owner/source", root, arbitrary
                )

    @unittest.skipIf(not hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_symlinked_repetition_member_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            target = fixture.repeat_a / contract_verifier.SSP_MEMBERS[0]
            real = fixture.root / "real-ssp.csv"
            shutil.copyfile(target, real)
            target.unlink()
            try:
                target.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(contract_verifier.SSPContractError):
                contract_verifier.verify_accepted_repetition(
                    fixture.ssp_contract,
                    fixture.qualification_report,
                    fixture.repeat_a,
                )


if __name__ == "__main__":
    unittest.main()
