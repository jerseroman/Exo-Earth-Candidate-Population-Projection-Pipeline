#!/usr/bin/env python3
"""Adversarial tests for the standalone age-cut producer and verifier."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import age_cut_sensitivity as producer  # noqa: E402
import verify_age_cut_sensitivity as verifier  # noqa: E402
import verify_age_cut_ssp_contract as ssp_contract  # noqa: E402
import verify_host_artifact_contract as host_contract  # noqa: E402


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(path: Path, names: tuple[str, ...], root: Path) -> None:
    path.write_text(
        "".join(f"{sha256(root / name)}  {name}\n" for name in names),
        encoding="utf-8",
        newline="\n",
    )


def git(command: list[str], cwd: Path) -> str:
    return subprocess.check_output(
        ["git", *command], cwd=cwd, text=True, stderr=subprocess.STDOUT
    ).strip()


class Fixture:
    """Small but structurally complete 42-SSP production analogue."""

    def __init__(self, parent: Path) -> None:
        self.root = parent
        self.jj_root = parent / "jjmodel-src"
        self.run_dir = parent / "jj-run"
        self.canonical = parent / "canonical"
        self.artifact = parent / "age-cut"
        self._make_jj_repository()
        self._make_run()
        self._make_canonical()
        producer._create_artifact(
            jj_root=self.jj_root,
            run_dir=self.run_dir,
            canonical_host_root=self.canonical,
            output_root=self.artifact,
            expected_jj_commit=self.commit,
        )
        self._make_qualification()

    @staticmethod
    def official_parameters() -> str:
        return """# compact tutorial2 test fixture
run_mode 1
out_dir 'tutorial2'
nprocess 4
Rmin 4
Rmax 14
dR 1
imfkey 0
a0 1.31
"""

    @staticmethod
    def runtime_parameters() -> str:
        return """# compact tutorial2 test fixture
run_mode 1
out_dir 'tutorial2'
nprocess 2
Rmin 4.0
Rmax 14.0
dR 0.5
imfkey 0
a0 1.31
"""

    def _make_jj_repository(self) -> None:
        tutorial = self.jj_root / "jjmodel" / "tutorials" / "tutorial2"
        tutorial.mkdir(parents=True)
        (tutorial / "parameters").write_text(
            self.official_parameters(), encoding="utf-8", newline="\n"
        )
        (tutorial / "sfrd_peaks_parameters").write_text(
            "# fixture\n3.5 3 0.7 9 1 26.3\n", encoding="utf-8", newline="\n"
        )
        git(["init", "-q"], self.jj_root)
        git(["config", "user.email", "fixture@example.invalid"], self.jj_root)
        git(["config", "user.name", "Age Cut Fixture"], self.jj_root)
        git(["add", "."], self.jj_root)
        git(["commit", "-q", "-m", "fixture"], self.jj_root)
        self.commit = git(["rev-parse", "HEAD"], self.jj_root)

    def _make_run(self) -> None:
        self.run_dir.mkdir()
        (self.run_dir / "parameters").write_text(
            self.runtime_parameters(), encoding="utf-8", newline="\n"
        )
        source_sfr = (
            self.jj_root
            / "jjmodel"
            / "tutorials"
            / "tutorial2"
            / "sfrd_peaks_parameters"
        )
        shutil.copyfile(source_sfr, self.run_dir / "sfrd_peaks_parameters")
        tables = self.run_dir / "output" / "fixture" / "pop" / "tab"
        tables.mkdir(parents=True)
        header = list(producer.SSP_COLUMNS)
        ages = (0.5, 2.0, 4.57, 6.0, 8.0, 10.0)
        temperatures = (5300.0, 5400.0, 5600.0, 5772.0, 5900.0, 6000.0)
        for radius in producer.RADII:
            for code, _, disk_label in producer.COMPONENTS:
                path = tables / producer.ssp_name(radius, code)
                with path.open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.writer(handle, lineterminator="\n")
                    writer.writerow(header)
                    for index, (age, temperature) in enumerate(zip(ages, temperatures)):
                        weight = (
                            0.05
                            + 0.002 * radius
                            + 0.003 * disk_label
                            + 0.001 * index
                        )
                        writer.writerow(
                            [
                                weight,
                                age,
                                -0.1 - 0.2 * disk_label,
                                1.0,
                                1.0,
                                0.0,
                                math.log10(temperature),
                                4.438,
                                5.0,
                                5.1,
                                4.9,
                                disk_label,
                            ]
                        )
                    # Valid but outside Teff, radius, or compact-remnant domains.
                    writer.writerow(
                        [0.9, 12.0, -0.1, 1.0, 1.0, 0.0, math.log10(5200.0), 4.438, 5, 5, 5, disk_label]
                    )
                    writer.writerow(
                        [0.8, 12.0, -0.1, 1.0, 1.0, 0.0, math.log10(5700.0), 2.0, 5, 5, 5, disk_label]
                    )
                    writer.writerow(
                        [0.7, 12.0, -0.1, 1.0, 1.0, 0.0, math.log10(5700.0), 7.0, 5, 5, 5, disk_label]
                    )

    def _make_canonical(self) -> None:
        self.canonical.mkdir()
        ssp = producer.discover_ssp_snapshots(self.run_dir)
        rows = producer.aggregate_ssp_tables(ssp)
        age_rows = [row for row in rows if row["age_threshold_Gyr"] == 4.57]
        radial_name = producer.CANONICAL_RADIAL_NAME
        with (self.canonical / radial_name).open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            fields = [
                "R_kpc",
                "Sigma_G_thin_pc-2",
                "Sigma_G_thick_pc-2",
                "Sigma_G_total_pc-2",
                "dN_dR_stars_kpc-1",
            ]
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows({key: row[key] for key in fields} for row in age_rows)
        for name in producer.CANONICAL_MANIFEST_MEMBERS[1:3]:
            (self.canonical / name).write_text("fixture\n", encoding="utf-8")
        (self.canonical / producer.CANONICAL_MANIFEST_MEMBERS[3]).write_text(
            "R_kpc,component,Teff_K,age_Gyr,logg,N_surface_pc-2\n",
            encoding="utf-8",
            newline="\n",
        )
        summary = {
            "jj_commit": self.commit,
            "isochrone_family": "Padova/PARSEC",
            "host_provider_id": "jj_padova_dr05_parsec_tams_v1",
            "host_estimand": {"age_Gyr_min": 4.57},
        }
        (self.canonical / producer.CANONICAL_SUMMARY_NAME).write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        write_manifest(
            self.canonical / producer.CANONICAL_MANIFEST_NAME,
            producer.CANONICAL_MANIFEST_MEMBERS,
            self.canonical,
        )
        with (self.canonical / producer.TAMS_AB_RADIAL_NAME).open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            fields = ["R_kpc", "A_N", "B_N", "A_L1", "B_L1", "A_L2", "B_L2"]
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for row in age_rows:
                writer.writerow(
                    {
                        "R_kpc": row["R_kpc"],
                        "A_N": row["dN_dR_stars_kpc-1"],
                        "B_N": row["dN_dR_stars_kpc-1"],
                        "A_L1": row["dLambda_HZ_dR_kpc-1"],
                        "B_L1": row["dLambda_HZ_dR_kpc-1"],
                        "A_L2": row["dLambda_Earth10_dR_kpc-1"],
                        "B_L2": row["dLambda_Earth10_dR_kpc-1"],
                    }
                )
        domains = {}
        for name, lo, hi in (
            ("lineweaver_7_9", 7.0, 9.0),
            ("full_JJ_4_14", 4.0, 14.0),
        ):
            values = {
                "N_G": producer.trapz_rows(
                    rows, 4.57, "dN_dR_stars_kpc-1", lo, hi
                ),
                "Lambda_ESHZ": producer.trapz_rows(
                    rows, 4.57, "dLambda_HZ_dR_kpc-1", lo, hi
                ),
                "Lambda_earth10": producer.trapz_rows(
                    rows, 4.57, "dLambda_Earth10_dR_kpc-1", lo, hi
                ),
            }
            domains[name] = {"A": values, "B": values, "delta_B_vs_A": {}}
        (self.canonical / producer.TAMS_AB_RESULTS_NAME).write_text(
            json.dumps({"domains": domains}, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _runtime_manifest() -> dict:
        return {
            "schema_version": 1,
            "status": "PASS",
            "python": "3.10 fixture",
            "python_executable": "/fixture/python",
            "platform": "fixture-linux",
            "machine": "x86_64",
            "numpy_version": "1.23.5",
            "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
            "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
            "selected_cpu_features": dict(ssp_contract.EXPECTED_CPU_FEATURES),
            "environment": dict(ssp_contract.EXPECTED_NUMERICAL_ENV),
        }

    def _generate_key(self, name: str) -> tuple[Path, str]:
        key = self.root / name
        subprocess.check_call(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)]
        )
        public = subprocess.check_output(
            ["ssh-keygen", "-y", "-f", str(key)], text=True
        ).strip()
        return key, public

    def _make_qualification(self) -> None:
        canonical_contract = (
            REPOSITORY_ROOT / "provenance" / "AGE_CUT_SSP_CONTRACT_v4_0_4.json"
        )
        contract = json.loads(canonical_contract.read_text(encoding="utf-8"))
        self.key_a, public_a = self._generate_key("age-run-a-key")
        self.key_b, public_b = self._generate_key("age-run-b-key")
        candidate = contract["artifact_sets"][0]
        candidate["attestation_signers"] = [
            {"signer_id": "run-a-authority", "public_key": public_a},
            {"signer_id": "run-b-authority", "public_key": public_b},
        ]
        self.ssp_contract = self.root / "AGE_CUT_SSP_CONTRACT_v4_0_4.json"
        self.ssp_contract.write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        self.repeat_a = self.root / "repeat-a"
        self.repeat_b = self.root / "repeat-b"
        self._make_repetition(
            self.repeat_a,
            label="fresh-a",
            execution_id="11111111-1111-4111-8111-111111111111",
            signer_id="run-a-authority",
            key=self.key_a,
            nonce="11" * 32,
            started="2026-08-30T00:00:00Z",
            completed="2026-08-30T00:05:00Z",
        )
        self._make_repetition(
            self.repeat_b,
            label="fresh-b",
            execution_id="22222222-2222-4222-8222-222222222222",
            signer_id="run-b-authority",
            key=self.key_b,
            nonce="22" * 32,
            started="2026-08-30T01:00:00Z",
            completed="2026-08-30T01:05:00Z",
        )
        self.qualification_report = self.root / "AGE_CUT_SSP_QUALIFICATION.json"
        report = ssp_contract.qualify_repetitions(
            self.ssp_contract,
            self.repeat_a,
            self.repeat_b,
            candidate["id"],
            self.qualification_report,
        )
        exact = report["exact_repeat_sha256"]
        candidate["role"] = "qualified_candidate"
        candidate["production_accepted"] = True
        for field in (
            "ssp_manifest_sha256",
            "ssp_member_sha256",
            "runtime_parameters_sha256",
            "sfr_peaks_parameters_sha256",
            "numerical_runtime_manifest_sha256",
        ):
            candidate[field] = exact[field]
        candidate["qualification_report"] = {
            "path": self.qualification_report.name,
            "sha256": sha256(self.qualification_report),
        }
        self.ssp_contract.write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        self.host_contract = self.root / "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
        self.host_contract.write_text("{}\n", encoding="utf-8")

    def _source_state(self) -> tuple[dict, dict, dict]:
        common_tree = "c" * 40
        jj = {
            "role": "jj_generator",
            "repository": "askenja/jjmodel",
            "commit_sha": ssp_contract.JJ_SHA,
            "git_tree_sha": "f" * 40,
            "source_archive": {
                "filename": "jj-source.tar",
                "sha256": "9" * 64,
                "size_bytes": 103,
            },
        }
        public = {
            "role": "public_release",
            "repository": "owner/public-release",
            "commit_sha": "a" * 40,
            "git_tree_sha": common_tree,
            "source_archive": {
                "filename": "public-source.tar",
                "sha256": "d" * 64,
                "size_bytes": 101,
            },
        }
        private = {
            "role": "private_production",
            "repository": "owner/private-production",
            "commit_sha": "b" * 40,
            "git_tree_sha": common_tree,
            "source_archive": {
                "filename": "private-source.tar",
                "sha256": "e" * 64,
                "size_bytes": 102,
            },
        }
        return jj, public, private

    def _make_repetition(
        self,
        root: Path,
        *,
        label: str,
        execution_id: str,
        signer_id: str,
        key: Path,
        nonce: str,
        started: str,
        completed: str,
    ) -> None:
        root.mkdir()
        shutil.copyfile(self.run_dir / "parameters", root / ssp_contract.PARAMETERS_NAME)
        shutil.copyfile(
            self.run_dir / "sfrd_peaks_parameters", root / ssp_contract.SFR_NAME
        )
        (root / ssp_contract.RUNTIME_NAME).write_text(
            json.dumps(self._runtime_manifest(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        for name in ssp_contract.SSP_MEMBERS:
            shutil.copyfile(next(self.run_dir.rglob(name)), root / name)
        write_manifest(
            root / ssp_contract.SSP_MANIFEST_NAME,
            ssp_contract.SSP_MEMBERS,
            root,
        )
        jj, public, private = self._source_state()
        program = ssp_contract.synthetic_snapshot(
            "run_jj_export.py", b"fixture pinned generation program\n"
        )
        issued = (
            datetime.fromisoformat(started[:-1] + "+00:00")
            - timedelta(seconds=1)
        ).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        contract = ssp_contract.load_contract(self.ssp_contract)[0]
        candidate = contract["artifact_sets"][0]
        source_state = {
            "jj_source": jj,
            "public_source": public,
            "private_source": private,
            "padova_archive": {
                "data_lock_id": ssp_contract.PADOVA_LOCK_ID,
                "filename": ssp_contract.PADOVA_FILENAME,
                "sha256": ssp_contract.PADOVA_SHA256,
                "size_bytes": ssp_contract.PADOVA_SIZE_BYTES,
            },
            "padova_extraction": {
                "root_relative_path": "jjmodel/input/isochrones/Padova",
                "member_count": 1,
                "tree_sha256": "8" * 64,
            },
        }
        challenge_body = ssp_contract.start_challenge_body(
            contract,
            candidate,
            signer_id=signer_id,
            repeat_label=label,
            execution_id=execution_id,
            nonce_hex=nonce,
            issued_utc=issued,
            generation_program=program,
            source_state_value=source_state,
            runtime_parameters=ssp_contract.read_snapshot(
                root / ssp_contract.PARAMETERS_NAME, "fixture parameters"
            ),
            sfr_peaks_parameters=ssp_contract.read_snapshot(
                root / ssp_contract.SFR_NAME, "fixture SFR peaks"
            ),
            numerical_runtime_manifest=ssp_contract.read_snapshot(
                root / ssp_contract.RUNTIME_NAME, "fixture runtime manifest"
            ),
        )
        challenge = {
            "challenge_id": "sha256:"
            + hashlib.sha256(
                ssp_contract.canonical_json_bytes(challenge_body)
            ).hexdigest(),
            **challenge_body,
        }
        challenge_path = root / ssp_contract.START_CHALLENGE_NAME
        challenge_path.write_text(
            json.dumps(challenge, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        ssp_contract.sign_document(
            challenge_path,
            key,
            namespace=ssp_contract.START_CHALLENGE_NAMESPACE,
            destination_name=ssp_contract.START_CHALLENGE_SIGNATURE_NAME,
        )
        execution_body = {
            "schema_version": 1,
            "controller": "verify_age_cut_ssp_contract.execute_fresh_repetition",
            "challenge_id": challenge["challenge_id"],
            "execution_id": execution_id,
            "nonce_hex": nonce,
            "argv": [
                "/fixture/python",
                "-I",
                "-B",
                "/fixture/private/research/jj-host-export/run_jj_export.py",
                "--jj-root",
                "/fixture/jj",
                "--run-dir",
                "/fixture/run",
                "--out",
                "/fixture/out",
                "--iso",
                "Padova",
                "--expected-radial-step-kpc",
                "0.5",
            ],
            "cwd": "/fixture/private",
            "shell": False,
            "run_directory_created_empty": True,
            "host_output_directory_created_empty": True,
            "run_started_utc": started,
            "run_completed_utc": completed,
            "return_code": 0,
            "stdout": {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0},
            "stderr": {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0},
            "ssp_member_sha256": {
                name: sha256(root / name) for name in ssp_contract.SSP_MEMBERS
            },
        }
        execution = {
            "execution_record_id": "sha256:"
            + hashlib.sha256(
                ssp_contract.canonical_json_bytes(execution_body)
            ).hexdigest(),
            **execution_body,
        }
        (root / ssp_contract.EXECUTION_RECORD_NAME).write_text(
            json.dumps(execution, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        provenance = {
            "schema_version": 1,
            "repeat_label": label,
            "execution_id": execution_id,
            "execution_environment": "local_ubuntu_22_04_wsl2",
            "run_started_utc": started,
            "run_completed_utc": completed,
            "generation_program": ssp_contract.evidence(program),
            "jj_source": jj,
            "padova_archive": {
                "data_lock_id": ssp_contract.PADOVA_LOCK_ID,
                "filename": ssp_contract.PADOVA_FILENAME,
                "sha256": ssp_contract.PADOVA_SHA256,
                "size_bytes": ssp_contract.PADOVA_SIZE_BYTES,
            },
            "padova_extraction": source_state["padova_extraction"],
            "public_source": public,
            "private_source": private,
            "runtime_parameters": self._evidence(root / ssp_contract.PARAMETERS_NAME),
            "sfr_peaks_parameters": self._evidence(root / ssp_contract.SFR_NAME),
            "numerical_runtime_manifest": self._evidence(
                root / ssp_contract.RUNTIME_NAME
            ),
            "ssp_manifest": self._evidence(root / ssp_contract.SSP_MANIFEST_NAME),
            "start_challenge": self._evidence(
                root / ssp_contract.START_CHALLENGE_NAME
            ),
            "start_challenge_signature": self._evidence(
                root / ssp_contract.START_CHALLENGE_SIGNATURE_NAME
            ),
            "execution_record": self._evidence(
                root / ssp_contract.EXECUTION_RECORD_NAME
            ),
        }
        (root / ssp_contract.PROVENANCE_NAME).write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        write_manifest(
            root / ssp_contract.REPETITION_MANIFEST_NAME,
            ssp_contract.REPETITION_MANIFEST_MEMBERS,
            root,
        )
        snapshots = {
            name: ssp_contract.read_snapshot(root / name, f"fixture {name}")
            for name in (
                *ssp_contract.REPETITION_MANIFEST_MEMBERS,
                ssp_contract.REPETITION_MANIFEST_NAME,
            )
        }
        body = ssp_contract.attestation_body(
            contract, candidate, provenance, snapshots, signer_id, nonce
        )
        attestation = {
            "attestation_id": "sha256:"
            + hashlib.sha256(ssp_contract.canonical_json_bytes(body)).hexdigest(),
            **body,
        }
        (root / ssp_contract.ATTESTATION_NAME).write_text(
            json.dumps(attestation, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        ssp_contract.sign_attestation(root / ssp_contract.ATTESTATION_NAME, key)

    @staticmethod
    def _evidence(path: Path) -> dict:
        return {
            "filename": path.name,
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }

    def verify(self) -> dict:
        return verifier._verify_age_cut_artifact(
            self.artifact,
            jj_root=self.jj_root,
            run_dir=self.repeat_a,
            canonical_host_root=self.canonical,
            age_ssp_contract=self.ssp_contract,
            ssp_qualification_report=self.qualification_report,
            host_artifact_contract=self.host_contract,
            expected_jj_commit=self.commit,
            require_repository_contract_paths=False,
            host_contract_check=lambda _contract, _root: {
                "artifact_set": {"production_accepted": True}
            },
        )

    def refresh_output_manifest(self) -> None:
        write_manifest(
            self.artifact / producer.OUTPUT_MANIFEST_NAME,
            producer.OUTPUT_MANIFEST_MEMBERS,
            self.artifact,
        )

    def refresh_ssp_binding(self, name: str) -> None:
        source = next(self.run_dir.rglob(name))
        manifest = self.artifact / producer.SSP_MANIFEST_NAME
        lines = manifest.read_text(encoding="utf-8").splitlines()
        replaced = False
        for index, line in enumerate(lines):
            _, listed_name = line.split("  ", 1)
            if listed_name == name:
                lines[index] = f"{sha256(source)}  {name}"
                replaced = True
        if not replaced:
            raise RuntimeError(f"fixture SSP manifest does not contain {name}")
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report_path = self.artifact / producer.REPORT_NAME
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["jj"]["ssp_manifest"] = {
            "filename": producer.SSP_MANIFEST_NAME,
            "sha256": sha256(manifest),
            "size_bytes": manifest.stat().st_size,
        }
        report_path.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        self.refresh_output_manifest()

    def rebind_repetition(self, root: Path, key: Path) -> None:
        write_manifest(
            root / ssp_contract.SSP_MANIFEST_NAME,
            ssp_contract.SSP_MEMBERS,
            root,
        )
        execution_path = root / ssp_contract.EXECUTION_RECORD_NAME
        execution = json.loads(execution_path.read_text(encoding="utf-8"))
        execution.pop("execution_record_id")
        execution["ssp_member_sha256"] = {
            name: sha256(root / name) for name in ssp_contract.SSP_MEMBERS
        }
        rebound_execution = {
            "execution_record_id": "sha256:"
            + hashlib.sha256(
                ssp_contract.canonical_json_bytes(execution)
            ).hexdigest(),
            **execution,
        }
        execution_path.write_text(
            json.dumps(rebound_execution, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        provenance_path = root / ssp_contract.PROVENANCE_NAME
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["ssp_manifest"] = self._evidence(
            root / ssp_contract.SSP_MANIFEST_NAME
        )
        provenance["execution_record"] = self._evidence(execution_path)
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        write_manifest(
            root / ssp_contract.REPETITION_MANIFEST_NAME,
            ssp_contract.REPETITION_MANIFEST_MEMBERS,
            root,
        )
        previous = json.loads(
            (root / ssp_contract.ATTESTATION_NAME).read_text(encoding="utf-8")
        )
        contract = ssp_contract.load_contract(self.ssp_contract)[0]
        candidate = contract["artifact_sets"][0]
        snapshots = {
            name: ssp_contract.read_snapshot(root / name, f"rebound fixture {name}")
            for name in (
                *ssp_contract.REPETITION_MANIFEST_MEMBERS,
                ssp_contract.REPETITION_MANIFEST_NAME,
            )
        }
        body = ssp_contract.attestation_body(
            contract,
            candidate,
            provenance,
            snapshots,
            previous["signer_id"],
            previous["nonce_hex"],
        )
        attestation = {
            "attestation_id": "sha256:"
            + hashlib.sha256(ssp_contract.canonical_json_bytes(body)).hexdigest(),
            **body,
        }
        (root / ssp_contract.ATTESTATION_NAME).write_text(
            json.dumps(attestation, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        signature = root / ssp_contract.ATTESTATION_SIGNATURE_NAME
        signature.unlink()
        ssp_contract.sign_attestation(root / ssp_contract.ATTESTATION_NAME, key)


class AgeCutProducerTests(unittest.TestCase):
    def test_exact_thresholds_and_no_row_level_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            report = json.loads((fixture.artifact / producer.REPORT_NAME).read_text())
            self.assertEqual(
                report["host_estimand"]["age_thresholds_Gyr"],
                [0.0, 2.0, 4.57, 6.0, 8.0],
            )
            self.assertFalse(report["row_level_host_output_emitted"])
            self.assertEqual(
                {path.name for path in fixture.artifact.iterdir()},
                set(producer.OUTPUT_FILES),
            )

    def test_incomplete_ssp_set_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            shutil.rmtree(fixture.artifact)
            missing = next(fixture.run_dir.rglob(producer.ssp_name(4.0, "d")))
            missing.unlink()
            with self.assertRaises(producer.AgeCutError):
                producer._create_artifact(
                    jj_root=fixture.jj_root,
                    run_dir=fixture.run_dir,
                    canonical_host_root=fixture.canonical,
                    output_root=fixture.artifact,
                    expected_jj_commit=fixture.commit,
                )

    def test_nonfinite_and_negative_ssp_values_fail(self) -> None:
        for column, replacement in ((0, "1e999"), (0, "-0.1"), (2, "NaN")):
            with self.subTest(column=column, replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                shutil.rmtree(fixture.artifact)
                path = next(fixture.run_dir.rglob(producer.ssp_name(4.0, "d")))
                lines = path.read_text(encoding="utf-8").splitlines()
                fields = lines[1].split(",")
                fields[column] = replacement
                lines[1] = ",".join(fields)
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaises(producer.AgeCutError):
                    producer._create_artifact(
                        jj_root=fixture.jj_root,
                        run_dir=fixture.run_dir,
                        canonical_host_root=fixture.canonical,
                        output_root=fixture.artifact,
                        expected_jj_commit=fixture.commit,
                    )

    def test_runtime_config_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            shutil.rmtree(fixture.artifact)
            parameters = fixture.run_dir / "parameters"
            parameters.write_text(
                parameters.read_text().replace("dR 0.5", "dR 1.0"), encoding="utf-8"
            )
            with self.assertRaises(producer.AgeCutError):
                producer._create_artifact(
                    jj_root=fixture.jj_root,
                    run_dir=fixture.run_dir,
                    canonical_host_root=fixture.canonical,
                    output_root=fixture.artifact,
                    expected_jj_commit=fixture.commit,
                )

    def test_canonical_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            shutil.rmtree(fixture.artifact)
            radial = fixture.canonical / producer.CANONICAL_RADIAL_NAME
            text = radial.read_text(encoding="utf-8").replace(",", ",", 1)
            lines = text.splitlines()
            fields = lines[1].split(",")
            fields[-1] = str(float(fields[-1]) * 1.01)
            lines[1] = ",".join(fields)
            radial.write_text("\n".join(lines) + "\n", encoding="utf-8")
            write_manifest(
                fixture.canonical / producer.CANONICAL_MANIFEST_NAME,
                producer.CANONICAL_MANIFEST_MEMBERS,
                fixture.canonical,
            )
            with self.assertRaises(producer.AgeCutError):
                producer._create_artifact(
                    jj_root=fixture.jj_root,
                    run_dir=fixture.run_dir,
                    canonical_host_root=fixture.canonical,
                    output_root=fixture.artifact,
                    expected_jj_commit=fixture.commit,
                )

    def test_exact_monotonicity_guard_rejects_inversion(self) -> None:
        rows = []
        for threshold in producer.AGE_THRESHOLDS:
            for radius in producer.RADII:
                value = 10.0 - threshold
                rows.append(
                    {
                        "age_threshold_Gyr": threshold,
                        "R_kpc": radius,
                        **{field: value for field in producer.RADIAL_COLUMNS[2:]},
                    }
                )
        rows[-1]["dLambda_HZ_dR_kpc-1"] = 100.0
        with self.assertRaises(producer.AgeCutError):
            producer.validate_monotonicity(rows)


class AgeCutVerifierTests(unittest.TestCase):
    def test_valid_artifact_is_independently_rederived(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            report = fixture.verify()
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["jj"]["ssp_file_count"], 42)

    def test_forged_internally_consistent_age_zero_outputs_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            radial_path = fixture.artifact / producer.RADIAL_NAME
            with radial_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
                fields = list(rows[0])
            for row in rows:
                if float(row["age_threshold_Gyr"]) == 0.0:
                    for field in producer.RADIAL_COLUMNS[2:]:
                        row[field] = str(float(row[field]) * 2.0)
            with radial_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            report_path = fixture.artifact / producer.REPORT_NAME
            report = json.loads(report_path.read_text(encoding="utf-8"))
            for domain in report["domains"].values():
                for key in ("N_G", "Lambda_HZ", "Lambda_Earth10"):
                    domain["by_threshold"][0][key] *= 2.0
            report_path.write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
            )
            fixture.refresh_output_manifest()
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()

    def test_mutated_or_incomplete_ssp_input_fails(self) -> None:
        for remove in (False, True):
            with self.subTest(remove=remove), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                path = fixture.repeat_a / producer.ssp_name(4.0, "d")
                if remove:
                    path.unlink()
                else:
                    path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_rebound_nonfinite_unused_ssp_field_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            name = producer.ssp_name(4.0, "d")
            path = fixture.repeat_a / name
            lines = path.read_text(encoding="utf-8").splitlines()
            fields = lines[1].split(",")
            fields[2] = "1e999"
            lines[1] = ",".join(fields)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            fixture.rebind_repetition(fixture.repeat_a, fixture.key_a)
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()

    def test_reviewer_age_mutation_with_all_self_bindings_regenerated_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            name = producer.ssp_name(4.0, "d")
            path = fixture.repeat_a / name
            lines = path.read_text(encoding="utf-8").splitlines()
            changed = False
            for index in range(1, len(lines)):
                fields = lines[index].split(",")
                if float(fields[1]) == 6.0:
                    fields[1] = "9.0"
                    lines[index] = ",".join(fields)
                    changed = True
                    break
            self.assertTrue(changed)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            fixture.rebind_repetition(fixture.repeat_a, fixture.key_a)
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()

    def test_output_manifest_rejects_duplicate_and_traversal(self) -> None:
        for mode in ("duplicate", "traversal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                path = fixture.artifact / producer.OUTPUT_MANIFEST_NAME
                lines = path.read_text(encoding="utf-8").splitlines()
                if mode == "duplicate":
                    lines[1] = lines[0]
                else:
                    digest = lines[0].split("  ", 1)[0]
                    lines[0] = f"{digest}  ../{producer.REPORT_NAME}"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_ssp_manifest_rejects_duplicate_and_traversal(self) -> None:
        for mode in ("duplicate", "traversal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                path = fixture.artifact / producer.SSP_MANIFEST_NAME
                lines = path.read_text(encoding="utf-8").splitlines()
                if mode == "duplicate":
                    lines[1] = lines[0]
                else:
                    digest = lines[0].split("  ", 1)[0]
                    lines[0] = f"{digest}  ../{producer.ssp_name(4.0, 'd')}"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                fixture.refresh_output_manifest()
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_json_nan_overflow_duplicate_key_fail(self) -> None:
        replacements = (
            ('"schema_version": 1', '"schema_version": NaN'),
            ('"minimum": 4.0', '"minimum": 1e999'),
            ('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
        )
        for old, new in replacements:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                report = fixture.artifact / producer.REPORT_NAME
                content = report.read_text(encoding="utf-8")
                self.assertIn(old, content)
                report.write_text(content.replace(old, new, 1), encoding="utf-8")
                fixture.refresh_output_manifest()
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_integer_bool_and_string_coercions_fail(self) -> None:
        replacements = (
            ('"schema_version": 1', '"schema_version": 1.0'),
            ('"schema_version": 1', '"schema_version": true'),
            ('"schema_version": 1', '"schema_version": "1"'),
            ('"ssp_file_count": 42', '"ssp_file_count": 42.5'),
        )
        for old, new in replacements:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                report = fixture.artifact / producer.REPORT_NAME
                content = report.read_text(encoding="utf-8")
                self.assertIn(old, content)
                report.write_text(content.replace(old, new, 1), encoding="utf-8")
                fixture.refresh_output_manifest()
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_reported_monotonicity_inversion_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            radial = fixture.artifact / producer.RADIAL_NAME
            with radial.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
                fields = list(rows[0])
            target = next(
                row
                for row in rows
                if float(row["age_threshold_Gyr"]) == 8.0
                and float(row["R_kpc"]) == 4.0
            )
            target["dN_dR_stars_kpc-1"] = "1e100"
            with radial.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            fixture.refresh_output_manifest()
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()

    def test_canonical_and_tams_mutations_fail(self) -> None:
        for name in (producer.CANONICAL_RADIAL_NAME, producer.TAMS_AB_RADIAL_NAME):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                target = fixture.canonical / name
                target.write_bytes(target.read_bytes() + b"\n")
                if name == producer.CANONICAL_RADIAL_NAME:
                    write_manifest(
                        fixture.canonical / producer.CANONICAL_MANIFEST_NAME,
                        producer.CANONICAL_MANIFEST_MEMBERS,
                        fixture.canonical,
                    )
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_extra_artifact_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            (fixture.artifact / "extra.txt").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()

    @unittest.skipIf(not hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_symlinked_artifact_member_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            report = fixture.artifact / producer.REPORT_NAME
            real = fixture.root / "real-report.json"
            shutil.copyfile(report, real)
            report.unlink()
            try:
                report.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(verifier.VerificationError):
                fixture.verify()


if __name__ == "__main__":
    unittest.main()
