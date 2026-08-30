#!/usr/bin/env python3
"""Adversarial tests for the signed full JJ host-artifact contract."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import verify_host_artifact_contract as host  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    return digest(path.read_bytes())


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_manifest(root: Path, name: str, members: tuple[str, ...]) -> None:
    (root / name).write_text(
        "".join(f"{file_hash(root / member)}  {member}\n" for member in members),
        encoding="utf-8",
        newline="\n",
    )


class SignedHostFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract_path = self.root / "HOST_CONTRACT.json"
        self.report_path = self.root / "HOST_QUALIFICATION.json"
        self.original = (
            b"nprocess\t4\tcores\nRmin\t4\tkpc\nRmax\t14\tkpc\ndR\t1\tkpc\n"
        )
        self.runtime = (
            b"nprocess\t2\tcores\nRmin\t4.0\tkpc\nRmax\t14.0\tkpc\ndR\t0.5\tkpc\n"
        )
        self.sfr = b"fixture sfr parameters\n"
        self.old_locks = (
            host.PARAMETERS_ORIGINAL_SHA256,
            host.PARAMETERS_RUNTIME_SHA256,
            host.SFR_SHA256,
        )
        host.PARAMETERS_ORIGINAL_SHA256 = digest(self.original)
        host.PARAMETERS_RUNTIME_SHA256 = digest(self.runtime)
        host.SFR_SHA256 = digest(self.sfr)
        self.keys = [self._make_key("a"), self._make_key("b")]
        helper, _ = host._controller_helper()
        self.signers = [
            {
                "signer_id": f"fixture-signer-{label}",
                "public_key": helper.signing_public_key(key),
            }
            for label, key in zip(("a", "b"), self.keys)
        ]
        self.old_signers = host.PINNED_SIGNERS
        host.PINNED_SIGNERS = tuple(self.signers)
        self.runtime_document = {
            "schema_version": 1,
            "status": "PASS",
            "python": sys.version,
            "python_executable": sys.executable,
            "platform": "fixture-platform",
            "machine": "fixture-machine",
            "numpy_version": "1.23.5",
            "numpy_cpu_baseline": ["SSE"],
            "numpy_cpu_dispatch_build": ["AVX2"],
            "selected_cpu_features": dict(helper.EXPECTED_CPU_FEATURES),
            "environment": dict(helper.EXPECTED_NUMERICAL_ENV),
        }
        self.artifact = self.root / "artifact"
        self._write_artifact(self.artifact)
        self.contract = self._contract_document()
        self.write_contract()

    def cleanup(self) -> None:
        (
            host.PARAMETERS_ORIGINAL_SHA256,
            host.PARAMETERS_RUNTIME_SHA256,
            host.SFR_SHA256,
        ) = self.old_locks
        host.PINNED_SIGNERS = self.old_signers
        self.temporary.cleanup()

    def _make_key(self, label: str) -> Path:
        key = self.root / f"signer-{label}"
        result = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise unittest.SkipTest("OpenSSH Ed25519 tooling is unavailable")
        return key

    @staticmethod
    def _summary(provider: str) -> dict:
        return {
            "jj_commit": "2" * 40,
            "host_provider_id": provider,
            "N_G_hosts_age_ge_4p57_R4_14": 10.0,
            "host_estimand": {"explicit_metallicity_dimension": False},
            "tams_transfer_assumption": "fixture",
            "python": "fixture runtime",
        }

    @staticmethod
    def _parent_rows() -> list[list[object]]:
        return [
            [4.0, "thin", 5.0, 0.0, 1.0, 1.0, 0.0, 3.73, 5370.0, 4.5, 1.0, 1.0, 1.0, 2.0, 1, 1, 0.2, 0.1],
            [4.5, "thick", 6.0, -0.5, 1.0, 1.0, 0.0, 3.74, 5500.0, 4.5, 2.0, 3.0, 3.0, 2.0, 1, 0, 0.3, 0.2],
            [5.0, "thin", 7.0, 0.1, 1.0, 1.0, 0.0, 3.75, 5620.0, 4.2, 3.0, 3.0, 3.0, 2.0, 0, 0, 0.4, 0.3],
        ]

    def _write_artifact(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        with (root / host.EXPECTED_PARENT_FILE).open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(host.EXPECTED_PARENT_COLUMNS)
            writer.writerows(self._parent_rows())
        for names, selector, provider in (
            (host.EXPECTED_CANONICAL_FILES, (0,), "fixture-tams"),
            (host.EXPECTED_LEGACY_FILES, (0, 1), "fixture-legacy"),
        ):
            for name, text in zip(names[:3], ("radial\n", "temperature\n", "age\n")):
                (root / name).write_text(text, encoding="utf-8", newline="\n")
            with (root / names[3]).open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(host.EXPECTED_RAW_COLUMNS)
                for index in selector:
                    row = self._parent_rows()[index]
                    writer.writerow([row[0], row[1], row[8], row[2], row[9], row[10]])
            (root / names[4]).write_text(
                json.dumps(self._summary(provider), indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        write_manifest(root, host.EXPECTED_MANIFEST, host.EXPECTED_CANONICAL_FILES)
        write_manifest(
            root, host.EXPECTED_LEGACY_MANIFEST, host.EXPECTED_LEGACY_FILES
        )
        (root / host.EXPECTED_AUXILIARY_FILES[0]).write_text(
            "R_kpc,A_N,B_N\n4.0,1.0,1.0\n", encoding="utf-8", newline="\n"
        )
        (root / host.EXPECTED_AUXILIARY_FILES[1]).write_text(
            '{"status":"PASS","parent_rows":3}\n', encoding="utf-8", newline="\n"
        )
        runtime_values = (
            self.original,
            self.runtime,
            self.sfr,
            (json.dumps(self.runtime_document, sort_keys=True) + "\n").encode(),
        )
        for name, value in zip(host.FULL_RUNTIME_FILES, runtime_values):
            write_bytes(root / name, value)

    def _artifact_set(self, identifier: str, role: str, eligible: bool) -> dict:
        files = {
            name: file_hash(self.artifact / name)
            for name in host.EXPECTED_CANONICAL_FILES
        }
        summary = self._summary("fixture-tams")
        summary.pop("python")
        return {
            "id": identifier,
            "role": role,
            "production_accepted": False,
            "qualification_eligible": eligible,
            "manifest_sha256": file_hash(self.artifact / host.EXPECTED_MANIFEST),
            "file_sha256": files,
            "summary_sha256_without_python": digest(
                host.canonical_json_bytes(summary)
            ),
            "qualification_report": None,
            "note": "Synthetic signed-host fixture.",
        }

    def _full_contract(self) -> dict:
        return {
            "schema_version": 1,
            "parent_file": host.EXPECTED_PARENT_FILE,
            "parent_columns": list(host.EXPECTED_PARENT_COLUMNS),
            "projection_columns": list(host.EXPECTED_RAW_COLUMNS),
            "selector_columns": dict(host.EXPECTED_SELECTOR_COLUMNS),
            "canonical_manifest_name": host.EXPECTED_MANIFEST,
            "canonical_files": list(host.EXPECTED_CANONICAL_FILES),
            "legacy_manifest_name": host.EXPECTED_LEGACY_MANIFEST,
            "legacy_files": list(host.EXPECTED_LEGACY_FILES),
            "auxiliary_files": list(host.EXPECTED_AUXILIARY_FILES),
            "runtime_files": list(host.FULL_RUNTIME_FILES),
            "repetition_manifest_name": host.HOST_REPETITION_MANIFEST,
            "provenance_files": [
                host.HOST_PROVENANCE_NAME,
                host.HOST_START_CHALLENGE_NAME,
                host.HOST_START_SIGNATURE_NAME,
                host.HOST_EXECUTION_RECORD_NAME,
                host.HOST_ATTESTATION_NAME,
                host.HOST_ATTESTATION_SIGNATURE_NAME,
            ],
            "locked_inputs": {
                "jj_repository": "askenja/jjmodel",
                "jj_commit": host.JJ_SHA,
                "public_repository": host.PUBLIC_REPOSITORY,
                "private_repository": host.PRIVATE_REPOSITORY,
                "padova_archive": {
                    "data_lock_id": "jj_padova_multiband_archive",
                    "filename": host.PADOVA_FILENAME,
                    "sha256": host.PADOVA_SHA256,
                    "size_bytes": host.PADOVA_SIZE_BYTES,
                },
                "parameters_original_sha256": host.PARAMETERS_ORIGINAL_SHA256,
                "parameters_runtime_sha256": host.PARAMETERS_RUNTIME_SHA256,
                "sfr_peaks_parameters_sha256": host.SFR_SHA256,
                "generation_programs": list(host.GENERATION_PROGRAMS),
            },
            "attestation_signers": self.signers,
            "qualification_policy": {
                "required_distinct_fresh_repetitions": 2,
                "required_distinct_signers": 2,
                "nonce_bytes": 32,
                "attestation_namespace": host.HOST_ATTESTATION_NAMESPACE,
                "start_challenge_namespace": host.HOST_START_NAMESPACE,
                "fresh_execution_controller": "verify_host_artifact_contract.execute_fresh_repetition",
                "generation_argv_mode": "subprocess_no_shell_exact_pinned",
                "require_controller_created_empty_roots": True,
                "require_signed_pre_run_challenge": True,
                "require_signed_completion_attestation": True,
                "require_exact_clean_source_archives": True,
                "require_exact_padova_extraction": True,
                "require_runtime_executable_chain": True,
                "require_identical_source_state": True,
                "require_bit_identical_host_tuple": True,
                "public_report_contains_row_level_hosts": False,
                "allowed_execution_environments": [
                    "local_ubuntu_22_04_wsl2",
                    "github_actions_ubuntu_22_04",
                ],
                "exact_repeat_files": host._host_exact_repeat_files(),
            },
            "accepted_tuple": None,
        }

    def _contract_document(self) -> dict:
        canonical_raw = self.artifact / host.EXPECTED_CANONICAL_FILES[3]
        identity, rows, _ = host.identity_projection(
            canonical_raw,
            {
                "identity_projection": {
                    "columns": list(host.EXPECTED_RAW_COLUMNS[:-1])
                },
                "raw_schema": {"weight_column": host.EXPECTED_RAW_COLUMNS[-1]},
            },
        )
        summary = self._summary("fixture-tams")
        science = dict(summary)
        science.pop("python")
        science.pop("tams_transfer_assumption")
        historical = self._artifact_set(
            "historical-fixture", "historical_baseline", False
        )
        historical["manifest_sha256"] = digest(b"historical manifest")
        historical["file_sha256"] = {
            name: digest(("historical:" + name).encode())
            for name in host.EXPECTED_CANONICAL_FILES
        }
        return {
            "schema_version": 1,
            "contract_id": "fixture-host-v1",
            "manifest_name": host.EXPECTED_MANIFEST,
            "canonical_files": list(host.EXPECTED_CANONICAL_FILES),
            "raw_file": host.EXPECTED_CANONICAL_FILES[3],
            "summary_file": host.EXPECTED_CANONICAL_FILES[4],
            "raw_schema": {
                "columns": list(host.EXPECTED_RAW_COLUMNS),
                "row_count": rows,
                "weight_column": host.EXPECTED_RAW_COLUMNS[-1],
            },
            "identity_projection": {
                "algorithm": host.IDENTITY_ALGORITHM,
                "columns": list(host.EXPECTED_RAW_COLUMNS[:-1]),
                "encoding": "UTF-8",
                "csv_dialect": "Python csv.excel with newline='' and UTF-8 decoding",
                "row_serialization": "compact JSON array of original CSV field strings",
                "numeric_text_rule": "preserve decoded CSV field strings exactly; no numeric parsing or reformatting",
                "record_terminator": "LF after every row",
                "sha256": identity,
            },
            "summary_projection": {
                "algorithm": host.SUMMARY_ALGORITHM,
                "encoding": "UTF-8",
                "input_rule": "strict JSON; duplicate keys and non-finite constants rejected",
                "number_rule": "Python 3.10 json numeric parse and json.dumps emission; no numeric coercion",
                "excluded_top_level_keys": ["python", "tams_transfer_assumption"],
                "serialization": "JSON sort_keys=true, ensure_ascii=false, separators=(',',':'), allow_nan=false",
                "sha256": digest(host.canonical_json_bytes(science)),
            },
            "summary_required_values": {
                "jj_commit": "2" * 40,
                "host_provider_id": "fixture-tams",
                "N_G_hosts_age_ge_4p57_R4_14": 10.0,
                "host_estimand.explicit_metallicity_dimension": False,
            },
            "forbidden_summary_paths": ["host_estimand.logg"],
            "artifact_sets": [
                historical,
                self._artifact_set("candidate-fixture", "diagnostic_candidate", True),
            ],
            "qualification_policy": {
                "baseline_artifact_set_id": "historical-fixture",
                "required_distinct_fresh_repetitions": 2,
                "exact_repeat_files": [
                    host.EXPECTED_MANIFEST,
                    *host.EXPECTED_CANONICAL_FILES,
                ],
                "require_exact_identity_projection": True,
                "require_exact_summary_projection": True,
                "numeric_weight_comparison": {
                    "column": host.EXPECTED_RAW_COLUMNS[-1],
                    "relative_tolerance": 1e-12,
                    "absolute_tolerance": 0.0,
                },
            },
            "full_artifact_contract": self._full_contract(),
        }

    def write_contract(self) -> None:
        self.contract_path.write_text(
            json.dumps(self.contract, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _source(role: str, repository: str, commit: str, tree: str) -> dict:
        archive_name = role + ".tar"
        return {
            "role": role,
            "repository": repository,
            "commit_sha": commit,
            "git_tree_sha": tree,
            "source_archive": {
                "filename": archive_name,
                "sha256": digest(archive_name.encode()),
                "size_bytes": len(archive_name),
            },
        }

    def _planned_commands(self) -> list[dict]:
        return host._planned_host_commands(
            sys.executable,
            Path("/fixture/private"),
            Path("/fixture/jj"),
            Path("/fixture/run"),
            Path("/fixture/out"),
        )

    def make_repetition(self, label: str, signer_index: int) -> Path:
        root = self.root / f"repeat-{label}"
        shutil.copytree(self.artifact, root)
        contract = host.load_contract(self.contract_path)
        candidate = host.artifact_set_by_id(contract, "candidate-fixture")
        full_tuple = host.inspect_full_artifact(root, contract)
        signer = self.signers[signer_index]
        execution_id = str(uuid.uuid4())
        nonce = hashlib.sha256(label.encode()).hexdigest()
        tree = "3" * 40
        helper_snapshot = host.read_file_snapshot(
            ROOT / "scripts" / "verify_age_cut_ssp_contract.py", "fixture helper"
        )
        controller_snapshot = host.read_file_snapshot(
            ROOT / "scripts" / "verify_host_artifact_contract.py", "fixture controller"
        )
        source_state = {
            "jj_source": self._source(
                "jj_generator", "askenja/jjmodel", host.JJ_SHA, "4" * 40
            ),
            "public_source": self._source(
                "public_release", host.PUBLIC_REPOSITORY, "5" * 40, tree
            ),
            "private_source": self._source(
                "private_production", host.PRIVATE_REPOSITORY, "6" * 40, tree
            ),
            "padova_archive": contract["full_artifact_contract"]["locked_inputs"][
                "padova_archive"
            ],
            "padova_extraction": {
                "root_relative_path": "jjmodel/input/isochrones/Padova",
                "member_count": 2,
                "tree_sha256": "7" * 64,
            },
            "runtime_executable": host._runtime_executable_chain(sys.executable),
            "controller_program": host._evidence(controller_snapshot),
            "controller_helper": host._evidence(helper_snapshot),
        }
        runtime_evidence = {
            name: host._evidence(
                host.read_file_snapshot(root / name, f"fixture runtime {name}")
            )
            for name in host.FULL_RUNTIME_FILES
        }
        program_records = {
            name: {
                "relative_path": name,
                "sha256": digest(name.encode()),
                "size_bytes": len(name),
            }
            for name in host.GENERATION_PROGRAMS
        }
        commands = self._planned_commands()
        challenge_body = {
            "schema_version": 1,
            "namespace": host.HOST_START_NAMESPACE,
            "contract_id": contract["contract_id"],
            "candidate_artifact_set_id": candidate["id"],
            "signer_id": signer["signer_id"],
            "repeat_label": label,
            "execution_id": execution_id,
            "nonce_hex": nonce,
            "issued_utc": "2026-08-30T10:00:00.000000Z",
            "controller": "verify_host_artifact_contract.execute_fresh_repetition",
            "source_state": source_state,
            "source_state_sha256": digest(host.canonical_json_bytes(source_state)),
            "locked_inputs": contract["full_artifact_contract"]["locked_inputs"],
            "runtime_inputs": runtime_evidence,
            "generation_programs": program_records,
            "planned_commands": commands,
            "execution_root_created_empty": True,
        }
        challenge = {
            "challenge_id": "sha256:" + digest(host.canonical_json_bytes(challenge_body)),
            **challenge_body,
        }
        host._write_json_exclusive(root / host.HOST_START_CHALLENGE_NAME, challenge)
        helper, _ = host._controller_helper()
        helper.sign_document(
            root / host.HOST_START_CHALLENGE_NAME,
            self.keys[signer_index],
            namespace=host.HOST_START_NAMESPACE,
            destination_name=host.HOST_START_SIGNATURE_NAME,
        )
        command_records = [
            {
                **command,
                "return_code": 0,
                "stdout": {"sha256": digest(b""), "size_bytes": 0},
                "stderr": {"sha256": digest(b""), "size_bytes": 0},
            }
            for command in commands
        ]
        execution_body = {
            "schema_version": 1,
            "controller": "verify_host_artifact_contract.execute_fresh_repetition",
            "challenge_id": challenge["challenge_id"],
            "execution_id": execution_id,
            "nonce_hex": nonce,
            "commands": command_records,
            "run_directory_created_empty": True,
            "host_output_directory_created_empty": True,
            "run_started_utc": "2026-08-30T10:00:01.000000Z",
            "run_completed_utc": "2026-08-30T10:00:02.000000Z",
            "source_state_sha256": challenge["source_state_sha256"],
            "full_artifact_tuple": full_tuple,
        }
        execution = {
            "execution_record_id": "sha256:"
            + digest(host.canonical_json_bytes(execution_body)),
            **execution_body,
        }
        host._write_json_exclusive(root / host.HOST_EXECUTION_RECORD_NAME, execution)
        provenance = {
            "schema_version": 1,
            "repeat_label": label,
            "execution_id": execution_id,
            "execution_environment": "local_ubuntu_22_04_wsl2",
            "run_started_utc": execution["run_started_utc"],
            "run_completed_utc": execution["run_completed_utc"],
            "signer_id": signer["signer_id"],
            "controller": execution["controller"],
            "source_state": source_state,
            "generation_programs": program_records,
            "runtime_files": runtime_evidence,
            "full_artifact_tuple": full_tuple,
            "start_challenge": host._evidence(
                host.read_file_snapshot(
                    root / host.HOST_START_CHALLENGE_NAME, "fixture challenge"
                )
            ),
            "start_challenge_signature": host._evidence(
                host.read_file_snapshot(
                    root / host.HOST_START_SIGNATURE_NAME, "fixture start signature"
                )
            ),
            "execution_record": host._evidence(
                host.read_file_snapshot(
                    root / host.HOST_EXECUTION_RECORD_NAME, "fixture execution"
                )
            ),
        }
        host._write_json_exclusive(root / host.HOST_PROVENANCE_NAME, provenance)
        host._write_manifest(
            root / host.HOST_REPETITION_MANIFEST,
            host._host_repetition_manifest_members(),
            root,
        )
        snapshots = {
            name: host.read_file_snapshot(root / name, f"fixture {name}")
            for name in (
                *host._host_repetition_manifest_members(),
                host.HOST_REPETITION_MANIFEST,
            )
        }
        attestation_body = host._attestation_body(
            contract, candidate, challenge, full_tuple, snapshots
        )
        attestation = {
            "attestation_id": "sha256:"
            + digest(host.canonical_json_bytes(attestation_body)),
            **attestation_body,
        }
        host._write_json_exclusive(root / host.HOST_ATTESTATION_NAME, attestation)
        helper.sign_document(
            root / host.HOST_ATTESTATION_NAME,
            self.keys[signer_index],
            namespace=host.HOST_ATTESTATION_NAMESPACE,
            destination_name=host.HOST_ATTESTATION_SIGNATURE_NAME,
        )
        return root

    def activate(self, report: dict) -> None:
        candidate = self.contract["artifact_sets"][1]
        candidate["role"] = "qualified_candidate"
        candidate["production_accepted"] = True
        candidate["qualification_report"] = {
            "path": self.report_path.name,
            "sha256": file_hash(self.report_path),
        }
        self.contract["full_artifact_contract"]["accepted_tuple"] = report[
            "accepted_full_artifact_tuple"
        ]
        self.write_contract()


class SignedHostContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SignedHostFixture()

    def tearDown(self) -> None:
        self.fixture.cleanup()

    def test_repository_contract_has_one_valid_lifecycle_state(self) -> None:
        fixture_locks = (
            host.PARAMETERS_ORIGINAL_SHA256,
            host.PARAMETERS_RUNTIME_SHA256,
            host.SFR_SHA256,
            host.PINNED_SIGNERS,
        )
        try:
            (
                host.PARAMETERS_ORIGINAL_SHA256,
                host.PARAMETERS_RUNTIME_SHA256,
                host.SFR_SHA256,
            ) = self.fixture.old_locks
            host.PINNED_SIGNERS = self.fixture.old_signers
            contract = host.load_contract(
                ROOT / "provenance" / "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
            )
        finally:
            (
                host.PARAMETERS_ORIGINAL_SHA256,
                host.PARAMETERS_RUNTIME_SHA256,
                host.SFR_SHA256,
                host.PINNED_SIGNERS,
            ) = fixture_locks
        accepted = [
            item for item in contract["artifact_sets"] if item["production_accepted"]
        ]
        accepted_tuple = contract["full_artifact_contract"]["accepted_tuple"]
        if not accepted:
            self.assertIsNone(accepted_tuple)
            self.assertTrue(
                all(item["qualification_report"] is None for item in contract["artifact_sets"])
            )
        else:
            self.assertEqual(len(accepted), 1)
            self.assertIsNotNone(accepted_tuple)
            self.assertIsInstance(accepted[0]["qualification_report"], dict)
            host._validate_qualification_report(
                ROOT / "provenance" / "HOST_ARTIFACT_CONTRACT_v4_0_4.json",
                contract,
                accepted[0],
                include_source_state=True,
            )
        self.assertEqual(
            [item["signer_id"] for item in contract["full_artifact_contract"]["attestation_signers"]],
            ["v404-local-attestor-a", "v404-local-attestor-b"],
        )

    def test_full_parent_canonical_legacy_and_runtime_binding(self) -> None:
        contract = host.load_contract(self.fixture.contract_path)
        observed = host.inspect_full_artifact(self.fixture.artifact, contract)
        self.assertEqual(observed["parent"]["row_count"], 3)
        self.assertEqual(observed["projections"]["canonical"]["row_count"], 1)
        self.assertEqual(observed["projections"]["legacy"]["row_count"], 2)

    def test_two_independent_signers_qualify_and_activate(self) -> None:
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.assertNotIn(
            "Teff_K", json.dumps(report["fresh_repetitions"][0]["public_evidence"])
        )
        self.fixture.activate(report)
        result = host.verify_artifact(self.fixture.contract_path, first)
        self.assertEqual(result["full_artifact_tuple"]["parent"]["row_count"], 3)

    def test_contract_promotion_changes_only_acceptance_evidence(self) -> None:
        pending = copy.deepcopy(self.fixture.contract)
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.fixture.activate(report)
        accepted = copy.deepcopy(self.fixture.contract)
        _pending, _accepted, promoted = host.validate_contract_promotion(
            pending, accepted
        )
        self.assertEqual(promoted["id"], "candidate-fixture")

        mutations = []
        changed = copy.deepcopy(accepted)
        changed["qualification_policy"]["require_exact_identity_projection"] = False
        mutations.append(changed)
        changed = copy.deepcopy(accepted)
        changed["full_artifact_contract"]["locked_inputs"]["jj_commit"] = "f" * 40
        mutations.append(changed)
        changed = copy.deepcopy(accepted)
        changed["full_artifact_contract"]["attestation_signers"].reverse()
        mutations.append(changed)
        changed = copy.deepcopy(accepted)
        changed["artifact_sets"][1]["id"] = "different-candidate"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(change=changed), self.assertRaises(host.ContractError):
                host.validate_contract_promotion(pending, changed)

    def test_external_promotion_binds_hash_report_and_computational_source(self) -> None:
        pending = copy.deepcopy(self.fixture.contract)
        pending_path = self.fixture.root / "pending-host-contract.json"
        pending_path.write_text(
            json.dumps(pending, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.fixture.activate(report)

        def compact(record: dict) -> dict:
            return {
                "repository": record["repository"],
                "commit_sha": record["commit_sha"],
                "git_tree_sha": record["git_tree_sha"],
                "source_archive_sha256": record["source_archive"]["sha256"],
                "source_archive_size_bytes": record["source_archive"]["size_bytes"],
            }

        public = compact(report["qualified_source"]["public_source"])
        private = compact(report["qualified_source"]["private_source"])
        accepted_hash = file_hash(self.fixture.contract_path)
        evidence = host.validate_external_contract_promotion(
            pending_path,
            self.fixture.contract_path,
            accepted_hash,
            public,
            private,
        )
        self.assertEqual(evidence["source_lock"]["public_source"], public)
        self.assertEqual(evidence["qualification_id"], report["qualification_id"])
        with self.assertRaises(host.ContractError):
            host.validate_external_contract_promotion(
                pending_path,
                self.fixture.contract_path,
                "0" * 64,
                public,
                private,
            )
        with self.assertRaises(host.ContractError):
            host.validate_external_contract_promotion(
                pending_path,
                self.fixture.contract_path,
                accepted_hash,
                {**public, "commit_sha": "f" * 40},
                private,
            )
        self.fixture.report_path.write_bytes(b'{"status":"forged"}\n')
        with self.assertRaises(host.ContractError):
            host.validate_external_contract_promotion(
                pending_path,
                self.fixture.contract_path,
                accepted_hash,
                public,
                private,
            )

    def test_copied_repetition_cannot_impersonate_second_signer(self) -> None:
        first = self.fixture.make_repetition("fresh-a", 0)
        copied = self.fixture.root / "copied-as-b"
        shutil.copytree(first, copied)
        with self.assertRaises(host.ContractError):
            host.qualify_artifacts(
                self.fixture.contract_path,
                first,
                copied,
                "candidate-fixture",
                self.fixture.report_path,
            )

    def test_parent_mutation_preserving_canonical_is_rejected(self) -> None:
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.fixture.activate(report)
        parent = first / host.EXPECTED_PARENT_FILE
        rows = list(csv.reader(parent.read_text(encoding="utf-8").splitlines()))
        rows[2][3] = "-0.4"  # legacy-only row; canonical raw remains byte-identical.
        with parent.open("w", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerows(rows)
        write_manifest(
            first,
            host.HOST_REPETITION_MANIFEST,
            host._host_repetition_manifest_members(),
        )
        with self.assertRaises(host.ContractError):
            host.verify_artifact(self.fixture.contract_path, first)

    def test_self_manifest_rebase_does_not_bypass_accepted_tuple(self) -> None:
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.fixture.activate(report)
        target = first / host.EXPECTED_CANONICAL_FILES[0]
        target.write_text("rebased radial\n", encoding="utf-8")
        write_manifest(first, host.EXPECTED_MANIFEST, host.EXPECTED_CANONICAL_FILES)
        write_manifest(
            first,
            host.HOST_REPETITION_MANIFEST,
            host._host_repetition_manifest_members(),
        )
        with self.assertRaises(host.ContractError):
            host.verify_artifact(self.fixture.contract_path, first)

    def test_shadow_extra_and_manifest_extra_are_rejected(self) -> None:
        repetition = self.fixture.make_repetition("fresh-a", 0)
        (repetition / "shadow.py").write_text("pass\n", encoding="utf-8")
        contract = host.load_contract(self.fixture.contract_path)
        candidate = host.artifact_set_by_id(contract, "candidate-fixture")
        with self.assertRaises(host.ContractError):
            host.inspect_signed_repetition(repetition, contract, candidate)
        (repetition / "shadow.py").unlink()
        with (repetition / host.HOST_REPETITION_MANIFEST).open(
            "a", encoding="utf-8"
        ) as handle:
            handle.write(f"{'0' * 64}  extra.txt\n")
        with self.assertRaises(host.ContractError):
            host.inspect_signed_repetition(repetition, contract, candidate)

    def test_nonfinite_parent_and_duplicate_or_overflow_json_are_rejected(self) -> None:
        contract = host.load_contract(self.fixture.contract_path)
        parent = self.fixture.artifact / host.EXPECTED_PARENT_FILE
        text = parent.read_text(encoding="utf-8").replace(
            ",0.0,1.0,", ",NaN,1.0,", 1
        )
        parent.write_text(text, encoding="utf-8", newline="\n")
        with self.assertRaises(host.ContractError):
            host.inspect_full_artifact(self.fixture.artifact, contract)
        shutil.rmtree(self.fixture.artifact)
        self.fixture._write_artifact(self.fixture.artifact)
        runtime = self.fixture.artifact / host.FULL_RUNTIME_FILES[-1]
        runtime.write_text(
            '{"status":"PASS","status":"PASS","unused":1e999}\n',
            encoding="utf-8",
        )
        with self.assertRaises(host.ContractError):
            host.inspect_full_artifact(self.fixture.artifact, contract)

    def test_symlink_member_is_rejected(self) -> None:
        repetition = self.fixture.make_repetition("fresh-a", 0)
        target = repetition / host.EXPECTED_AUXILIARY_FILES[0]
        replacement = self.fixture.root / "outside.csv"
        replacement.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(replacement)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        contract = host.load_contract(self.fixture.contract_path)
        candidate = host.artifact_set_by_id(contract, "candidate-fixture")
        with self.assertRaises(host.ContractError):
            host.inspect_signed_repetition(repetition, contract, candidate)

    def test_stable_reader_detects_deterministic_path_swap(self) -> None:
        path = self.fixture.root / "swap.txt"
        replacement = self.fixture.root / "replacement.txt"
        path.write_text("before", encoding="utf-8")
        replacement.write_text("after", encoding="utf-8")
        real_open = os.open
        swapped = False

        def swapping_open(
            candidate: object, flags: int, *args: object, **kwargs: object
        ) -> int:
            nonlocal swapped
            if Path(candidate) == path and not swapped:
                swapped = True
                path.unlink()
                replacement.replace(path)
            return real_open(candidate, flags, *args, **kwargs)

        with mock.patch.object(host.os, "open", side_effect=swapping_open):
            with self.assertRaises(host.ContractError):
                host.read_file_snapshot(path, "deterministic swap")

    def test_report_rebase_with_rehashed_contract_still_needs_signatures(self) -> None:
        first = self.fixture.make_repetition("fresh-a", 0)
        second = self.fixture.make_repetition("fresh-b", 1)
        report = host.qualify_artifacts(
            self.fixture.contract_path,
            first,
            second,
            "candidate-fixture",
            self.fixture.report_path,
        )
        self.fixture.activate(report)
        forged = copy.deepcopy(report)
        forged["fresh_repetitions"][1]["label"] = "forged-b"
        body = dict(forged)
        body.pop("qualification_id")
        forged["qualification_id"] = "sha256:" + digest(
            host.canonical_json_bytes(body)
        )
        self.fixture.report_path.write_text(
            json.dumps(forged, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.fixture.contract["artifact_sets"][1]["qualification_report"][
            "sha256"
        ] = file_hash(self.fixture.report_path)
        self.fixture.write_contract()
        with self.assertRaises(host.ContractError):
            host.verify_artifact(self.fixture.contract_path, first)

    @unittest.skipUnless(
        sys.platform == "linux", "controlled host production execution is Linux-only"
    )
    def test_execute_controller_builds_fresh_roots_and_exact_argv(self) -> None:
        public = self.fixture.root / "public-source"
        private = self.fixture.root / "private-source"
        jj = self.fixture.root / "jj-source"
        public.mkdir()
        output_names = tuple(
            name
            for name in host._host_exact_repeat_files()
            if name not in host.FULL_RUNTIME_FILES
        )
        fixture_output = public / "fixture_outputs"
        fixture_output.mkdir()
        for name in output_names:
            shutil.copy2(self.fixture.artifact / name, fixture_output / name)
        controller_sources = (
            "scripts/verify_host_artifact_contract.py",
            "scripts/verify_age_cut_ssp_contract.py",
        )
        for relative in controller_sources:
            destination = public / Path(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / Path(relative), destination)
        copy_program = (
            "import argparse,os,shutil,subprocess\n"
            "from pathlib import Path\n"
            "p=argparse.ArgumentParser()\n"
            "p.add_argument('--jj-root');p.add_argument('--run-dir');"
            "p.add_argument('--out',required=True);p.add_argument('--iso');"
            "p.add_argument('--expected-radial-step-kpc')\n"
            "a=p.parse_args();jj=Path(a.jj_root);"
            "head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=jj,text=True).strip();"
            "valid_head=len(head)==40 and all(c in '0123456789abcdef' for c in head);"
            "origin=subprocess.check_output(['git','remote','get-url','origin'],cwd=jj,text=True).strip();"
            "(_ for _ in ()).throw(RuntimeError('invalid JJ Git identity')) "
            "if not valid_head or origin!='https://github.com/askenja/jjmodel.git' else None;"
            "subprocess.run(['git','diff','--quiet','HEAD','--'],cwd=jj,check=True);"
            "subprocess.run(['git','diff','--cached','--quiet','HEAD','--'],cwd=jj,check=True);"
            "committed=subprocess.check_output(['git','show','HEAD:jjmodel/tutorials/tutorial2/parameters'],cwd=jj);"
            "(_ for _ in ()).throw(RuntimeError('JJ tracked bytes changed')) "
            "if committed!=(jj/'jjmodel/tutorials/tutorial2/parameters').read_bytes() else None;"
            "(jj/'unexpected-empty-directory').mkdir() "
            "if os.environ.get('HOST_CONTRACT_TEST_MUTATE_JJ')=='1' else None;"
            "src=Path(__file__).resolve().parents[2]/'fixture_outputs';"
            f"names={output_names!r}\n"
            "[shutil.copy2(src/name,Path(a.out)/name) for name in names]\n"
        )
        noop_program = (
            "import argparse\n"
            "p=argparse.ArgumentParser();p.add_argument('--jj-root');"
            "p.add_argument('--run-dir');p.add_argument('--out',required=True);"
            "p.add_argument('--iso');p.add_argument('--expected-radial-step-kpc');"
            "p.parse_args()\n"
        )
        for index, relative in enumerate(host.GENERATION_PROGRAMS):
            path = public / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                copy_program if index == 0 else noop_program,
                encoding="utf-8",
                newline="\n",
            )

        def initialize(root: Path, remote: str) -> str:
            commands = (
                ["git", "init", "-q"],
                ["git", "config", "user.name", "Fixture"],
                ["git", "config", "user.email", "fixture@example.invalid"],
                ["git", "add", "."],
                ["git", "commit", "-q", "-m", "fixture"],
                ["git", "remote", "add", "origin", remote],
            )
            for command in commands:
                subprocess.run(command, cwd=root, check=True)
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()

        initialize(public, "https://github.com/fixture/public.git")
        shutil.copytree(public, private)
        subprocess.run(
            ["git", "remote", "set-url", "origin", "https://github.com/fixture/private.git"],
            cwd=private,
            check=True,
        )
        (jj / Path(host.JJ_PARAMETERS_PATH)).parent.mkdir(parents=True)
        write_bytes(jj / Path(host.JJ_PARAMETERS_PATH), self.fixture.original)
        write_bytes(jj / Path(host.JJ_SFR_PATH), self.fixture.sfr)
        jj_commit = initialize(jj, "https://github.com/askenja/jjmodel.git")

        archives: dict[str, Path] = {}
        for label, root in (("public", public), ("private", private), ("jj", jj)):
            result = subprocess.run(
                ["git", "archive", "--format=tar", "HEAD"],
                cwd=root,
                stdout=subprocess.PIPE,
                check=True,
            )
            archive = self.fixture.root / f"{label}.tar"
            archive.write_bytes(result.stdout)
            archives[label] = archive
        padova = self.fixture.root / host.PADOVA_FILENAME
        with zipfile.ZipFile(padova, "w") as archive:
            archive.writestr("multiband/fixture.txt", b"locked padova fixture\n")
        runtime_manifest = self.fixture.artifact / host.FULL_RUNTIME_FILES[-1]

        old_values = (
            host.JJ_SHA,
            host.PUBLIC_REPOSITORY,
            host.PRIVATE_REPOSITORY,
            host.PADOVA_SHA256,
            host.PADOVA_SIZE_BYTES,
        )
        try:
            host.JJ_SHA = jj_commit
            host.PUBLIC_REPOSITORY = "fixture/public"
            host.PRIVATE_REPOSITORY = "fixture/private"
            host.PADOVA_SHA256 = file_hash(padova)
            host.PADOVA_SIZE_BYTES = padova.stat().st_size
            locked = self.fixture.contract["full_artifact_contract"]["locked_inputs"]
            locked["jj_repository"] = "askenja/jjmodel"
            locked["jj_commit"] = jj_commit
            locked["public_repository"] = "fixture/public"
            locked["private_repository"] = "fixture/private"
            locked["padova_archive"] = {
                "data_lock_id": "jj_padova_multiband_archive",
                "filename": host.PADOVA_FILENAME,
                "sha256": host.PADOVA_SHA256,
                "size_bytes": host.PADOVA_SIZE_BYTES,
            }
            self.fixture.write_contract()
            result = host.execute_fresh_repetition(
                self.fixture.contract_path,
                jj_root=jj,
                jj_source_archive=archives["jj"],
                padova_archive=padova,
                public_source_root=public,
                public_source_archive=archives["public"],
                private_source_root=private,
                private_source_archive=archives["private"],
                numerical_runtime_manifest=runtime_manifest,
                candidate_set_id="candidate-fixture",
                signer_id=self.fixture.signers[0]["signer_id"],
                signing_key=self.fixture.keys[0],
                repeat_label="controller-a",
                execution_root=self.fixture.root / "controller-execution",
                output_root=self.fixture.root / "controller-repetition",
            )
            self.assertEqual(result["signer_id"], self.fixture.signers[0]["signer_id"])
            self.assertEqual(result["full_artifact_tuple"]["parent"]["row_count"], 3)
            with mock.patch.dict(
                os.environ, {"HOST_CONTRACT_TEST_MUTATE_JJ": "1"}, clear=False
            ), self.assertRaises(host.ContractError):
                host.execute_fresh_repetition(
                    self.fixture.contract_path,
                    jj_root=jj,
                    jj_source_archive=archives["jj"],
                    padova_archive=padova,
                    public_source_root=public,
                    public_source_archive=archives["public"],
                    private_source_root=private,
                    private_source_archive=archives["private"],
                    numerical_runtime_manifest=runtime_manifest,
                    candidate_set_id="candidate-fixture",
                    signer_id=self.fixture.signers[1]["signer_id"],
                    signing_key=self.fixture.keys[1],
                    repeat_label="jj-mutation-b",
                    execution_root=self.fixture.root / "jj-mutation-execution",
                    output_root=self.fixture.root / "jj-mutation-repetition",
                )
            (private / "shadow.py").write_text("pass\n", encoding="utf-8")
            with self.assertRaises(host.ContractError):
                host.execute_fresh_repetition(
                    self.fixture.contract_path,
                    jj_root=jj,
                    jj_source_archive=archives["jj"],
                    padova_archive=padova,
                    public_source_root=public,
                    public_source_archive=archives["public"],
                    private_source_root=private,
                    private_source_archive=archives["private"],
                    numerical_runtime_manifest=runtime_manifest,
                    candidate_set_id="candidate-fixture",
                    signer_id=self.fixture.signers[1]["signer_id"],
                    signing_key=self.fixture.keys[1],
                    repeat_label="shadow-b",
                    execution_root=self.fixture.root / "shadow-execution",
                    output_root=self.fixture.root / "shadow-repetition",
                )
        finally:
            (
                host.JJ_SHA,
                host.PUBLIC_REPOSITORY,
                host.PRIVATE_REPOSITORY,
                host.PADOVA_SHA256,
                host.PADOVA_SIZE_BYTES,
            ) = old_values

    def test_contract_rejects_one_signer_and_runtime_lock_rebind(self) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["full_artifact_contract"][
            "attestation_signers"
        ] = self.fixture.signers[:1]
        with self.assertRaises(host.ContractError):
            host.validate_contract(contract)
        contract = copy.deepcopy(self.fixture.contract)
        contract["full_artifact_contract"]["locked_inputs"][
            "parameters_runtime_sha256"
        ] = "0" * 64
        with self.assertRaises(host.ContractError):
            host.validate_contract(contract)


if __name__ == "__main__":
    unittest.main()
