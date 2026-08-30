#!/usr/bin/env python3
"""Adversarial tests for the private radial SSP qualification boundary."""

from __future__ import annotations

import hashlib
import csv
import json
import math
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import verify_radial_ssp_contract as verifier  # noqa: E402


CANONICAL_CONTRACT = (
    REPOSITORY_ROOT / "provenance" / "RADIAL_SSP_CONTRACT_v4_0_4.json"
)


class RadialBootstrapIsolationTests(unittest.TestCase):
    def test_help_never_executes_numpy_source_or_sourceless_pyc_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            controller = root / "verify_radial_ssp_contract.py"
            shutil.copyfile(REPOSITORY_ROOT / "scripts" / controller.name, controller)
            marker = root / "NUMPY_SHADOW_EXECUTED"
            source = root / "numpy.py"
            source.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                "raise SystemExit('NUMPY_SHADOW_EXECUTED')\n",
                encoding="utf-8",
                newline="\n",
            )
            py_compile.compile(
                str(source), cfile=str(root / "numpy.pyc"), doraise=True
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(root)
            for optimisation in ((), ("-O",)):
                with self.subTest(optimisation=optimisation, shadow="source"):
                    result = subprocess.run(
                        [sys.executable, *optimisation, str(controller), "--help"],
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        shell=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())
            source.unlink()
            marker.unlink(missing_ok=True)
            result = subprocess.run(
                [sys.executable, str(controller), "--help"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def initialize_repository(path: Path, repository: str, files: dict[str, bytes]) -> str:
    path.mkdir()
    for name, content in files.items():
        destination = path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    subprocess.check_call(["git", "init", "-q"], cwd=path)
    subprocess.check_call(
        ["git", "config", "user.email", "fixture@example.invalid"], cwd=path
    )
    subprocess.check_call(
        ["git", "config", "user.name", "Radial Fixture"], cwd=path
    )
    subprocess.check_call(["git", "config", "core.autocrlf", "false"], cwd=path)
    subprocess.check_call(
        ["git", "remote", "add", "origin", f"https://github.com/{repository}.git"],
        cwd=path,
    )
    subprocess.check_call(["git", "add", "."], cwd=path)
    subprocess.check_call(["git", "commit", "-q", "-m", "fixture"], cwd=path)
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True
    ).strip()


def git_archive(root: Path, destination: Path) -> Path:
    destination.write_bytes(
        subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=root)
    )
    return destination


class RadialSSPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.old_globals = {
            "JJ_SHA": verifier.JJ_SHA,
            "PADOVA_SHA256": verifier.PADOVA_SHA256,
            "PADOVA_SIZE_BYTES": verifier.PADOVA_SIZE_BYTES,
            "TUTORIAL_PARAMETERS_SHA256": verifier.TUTORIAL_PARAMETERS_SHA256,
            "TUTORIAL_SFR_SHA256": verifier.TUTORIAL_SFR_SHA256,
        }
        cls.old_detector = verifier.secure.detect_execution_environment
        verifier.secure.detect_execution_environment = lambda: "local_ubuntu_22_04_wsl2"

        original_text = (
            "run_mode 1\n"
            "out_dir 'tutorial2'\n"
            "nprocess 4 workers\n"
            "Rmin 4 kpc\n"
            "Rmax 14 kpc\n"
            "dR 1 kpc\n"
            "imfkey 0\n"
        )
        sfr_text = "# canonical fixture\n3.5 3 0.7 9 1 26.3\n"
        cls.original = cls.root / "parameters"
        cls.original.write_text(original_text, encoding="utf-8", newline="\n")
        cls.sfr = cls.root / "sfrd_peaks_parameters"
        cls.sfr.write_text(sfr_text, encoding="utf-8", newline="\n")

        module_path = str(HERE).replace("\\", "\\\\")
        generator = f'''#!/usr/bin/env python3
import argparse, csv, json, math, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, r"{module_path}")
import radial_ssp_rederive as rr
p = argparse.ArgumentParser()
p.add_argument('--jj-root'); p.add_argument('--run-dir'); p.add_argument('--out'); p.add_argument('--iso')
a = p.parse_args()
parameters = (Path(a.run_dir) / 'parameters').read_text(encoding='utf-8')
match = re.search(r'(?m)^dR\\s+([0-9.]+)\\s+', parameters)
dr = float(match.group(1))
tab = Path(a.run_dir) / 'output' / 'pop' / 'tab'
tab.mkdir(parents=True)
header = 'N,age,FeH,Mini,Mf,logL,logT,logg,G_EDR3,GBP_EDR3,GRP_EDR3,disk_label\\n'
for radius in rr.radii_for_dr(dr):
    for code, label in (('d', 0), ('t', 1)):
        weight = (15.0 - radius) * (1.0 if code == 'd' else 0.25)
        rows = (
            f'{{weight}},6,-0.1,1,1,0,{{math.log10(5700.0)}},4.44,5,5,5,{{label}}\\n'
            f'0.01,7,-0.1,1,1,0,{{math.log10(5700.0)}},8.0,5,5,5,{{label}}\\n'
        )
        (tab / f'SSP_R{{float(radius)}}_{{code}}_Padova.csv').write_text(header + rows, encoding='utf-8', newline='\\n')
derived = rr.rederive_private_run(Path(a.run_dir), dr)
out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
with (out / f'tams_radial_dr{{rr.tag(dr)}}.csv').open('w', encoding='utf-8', newline='') as handle:
    writer = csv.DictWriter(handle, fieldnames=rr.RADIAL_COLUMNS)
    writer.writeheader(); writer.writerows(derived['radial_rows'])
result = {{
    'experiment': 'final_TAMS_radial_convergence',
    'jj_commit': subprocess.check_output(['git','rev-parse','HEAD'], cwd=a.jj_root, text=True).strip(),
    'isochrone_family': 'Padova', 'dR_kpc': dr,
    'radial_nodes': derived['radial_nodes'],
    'host_selector': '5300<=Teff<=6000 K; age>=4.57 Gyr; thin+thick; Rstar<=PARSEC-TAMS(Teff); logg<7 remnant veto',
    'occurrence_branch': 'Bryson Model 1 hab2 constant-completeness + Kopparapu conservative HZ',
    'selected_stellar_assembly_rows': derived['selected_stellar_assembly_rows'],
    'compact_remnant_rows_rejected': derived['compact_remnant_rows_rejected'],
    'compact_remnant_surface_weight_rejected_sum_pc-2': derived['compact_remnant_surface_weight_rejected_sum_pc-2'],
    'C1': derived['C1'], 'domains': derived['domains'],
}}
(out / f'tams_result_dr{{rr.tag(dr)}}.json').write_text(json.dumps(result, indent=2, allow_nan=False), encoding='utf-8', newline='\\n')
'''.encode("utf-8")
        tams_bytes = verifier.rederive.independent_reference.TAMS_PATH.read_bytes()
        source_files = {
            verifier.GENERATOR_RELATIVE: generator,
            "research/jj-host-export/reference-data/tams_parsec_danxhuber.txt": tams_bytes,
            "README.txt": b"identical production tree\n",
        }
        for relative in verifier.CONTROLLER_RELATIVES:
            source_files[relative] = (REPOSITORY_ROOT / relative).read_bytes()
        cls.public_root = cls.root / "public"
        cls.private_root = cls.root / "private"
        initialize_repository(cls.public_root, "owner/public", source_files)
        initialize_repository(cls.private_root, "owner/private", source_files)

        cls.jj_root = cls.root / "jj"
        jj_commit = initialize_repository(
            cls.jj_root,
            "askenja/jjmodel",
            {
                "jjmodel/tutorials/tutorial2/parameters": original_text.encode("utf-8"),
                "jjmodel/tutorials/tutorial2/sfrd_peaks_parameters": sfr_text.encode("utf-8"),
            },
        )
        verifier.JJ_SHA = jj_commit
        cls.public_archive = git_archive(cls.public_root, cls.root / "public.tar")
        cls.private_archive = git_archive(cls.private_root, cls.root / "private.tar")
        cls.jj_archive = git_archive(cls.jj_root, cls.root / "jj.tar")

        cls.padova = cls.root / verifier.PADOVA_FILENAME
        member_bytes = b"fixture Padova isochrone bytes\n"
        with zipfile.ZipFile(cls.padova, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("fixture.dat", member_bytes)
        extracted = (
            cls.jj_root
            / "jjmodel"
            / "input"
            / "isochrones"
            / "Padova"
            / "fixture.dat"
        )
        extracted.parent.mkdir(parents=True)
        extracted.write_bytes(member_bytes)
        verifier.PADOVA_SHA256 = sha256(cls.padova)
        verifier.PADOVA_SIZE_BYTES = cls.padova.stat().st_size
        verifier.TUTORIAL_PARAMETERS_SHA256 = sha256(cls.original)
        verifier.TUTORIAL_SFR_SHA256 = sha256(cls.sfr)

        cls.runtime = cls.root / verifier.secure.RUNTIME_NAME
        write_json(
            cls.runtime,
            {
                "schema_version": 1,
                "status": "PASS",
                "python": sys.version,
                "python_executable": sys.executable,
                "platform": sys.platform,
                "machine": "fixture",
                "numpy_version": "1.23.5",
                "numpy_cpu_baseline": ["SSE", "SSE2", "SSE3"],
                "numpy_cpu_dispatch_build": ["AVX2", "FMA3"],
                "selected_cpu_features": dict(verifier.secure.EXPECTED_CPU_FEATURES),
                "environment": dict(verifier.secure.EXPECTED_NUMERICAL_ENV),
            },
        )
        cls.key_a = cls.root / "key-a"
        cls.key_b = cls.root / "key-b"
        for key in (cls.key_a, cls.key_b):
            subprocess.check_call(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)]
            )
        contract = json.loads(CANONICAL_CONTRACT.read_text(encoding="utf-8"))
        contract["locked_inputs"]["jj_commit"] = verifier.JJ_SHA
        contract["locked_inputs"]["padova_archive"]["sha256"] = verifier.PADOVA_SHA256
        contract["locked_inputs"]["padova_archive"]["size_bytes"] = verifier.PADOVA_SIZE_BYTES
        contract["locked_inputs"]["tutorial_parameters_sha256"] = verifier.TUTORIAL_PARAMETERS_SHA256
        contract["locked_inputs"]["tutorial_sfr_sha256"] = verifier.TUTORIAL_SFR_SHA256
        contract["artifact_sets"][0]["attestation_signers"] = [
            {
                "signer_id": "fixture-attestor-a",
                "public_key": verifier.secure.signing_public_key(cls.key_a),
            },
            {
                "signer_id": "fixture-attestor-b",
                "public_key": verifier.secure.signing_public_key(cls.key_b),
            },
        ]
        cls.contract = cls.root / "RADIAL_SSP_CONTRACT.json"
        write_json(cls.contract, contract)
        cls.candidate_id = contract["artifact_sets"][0]["id"]
        cls.common = {
            "jj_root": cls.jj_root,
            "jj_source_archive": cls.jj_archive,
            "tutorial_parameters": cls.original,
            "sfr_peaks_parameters": cls.sfr,
            "numerical_runtime_manifest": cls.runtime,
            "padova_archive": cls.padova,
            "public_source_root": cls.public_root,
            "public_repository": "owner/public",
            "public_source_archive": cls.public_archive,
            "private_source_root": cls.private_root,
            "private_repository": "owner/private",
            "private_source_archive": cls.private_archive,
            "candidate_set_id": cls.candidate_id,
        }
        cls.triplet_a = cls.root / "triplet-a"
        cls.triplet_b = cls.root / "triplet-b"
        verifier.execute_fresh_triplet(
            cls.contract,
            **cls.common,
            signer_id="fixture-attestor-a",
            signing_key=cls.key_a,
            triplet_label="fresh-triplet-a",
            execution_root=cls.root / "execution-a",
            output_root=cls.triplet_a,
        )
        verifier.execute_fresh_triplet(
            cls.contract,
            **cls.common,
            signer_id="fixture-attestor-b",
            signing_key=cls.key_b,
            triplet_label="fresh-triplet-b",
            execution_root=cls.root / "execution-b",
            output_root=cls.triplet_b,
        )
        cls.report = cls.root / "RADIAL_SSP_QUALIFICATION.json"
        verifier.qualify_triplets(
            cls.contract,
            cls.triplet_a,
            cls.triplet_b,
            cls.candidate_id,
            cls.report,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        verifier.secure.detect_execution_environment = cls.old_detector
        for name, value in cls.old_globals.items():
            setattr(verifier, name, value)
        cls.temporary.cleanup()

    def private_copy(self, name: str = "copy") -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / name
        shutil.copytree(self.triplet_a, destination)
        return temporary, destination

    def accepted_contract(self, directory: Path) -> tuple[Path, Path]:
        report = directory / self.report.name
        shutil.copy2(self.report, report)
        document = json.loads(self.contract.read_text(encoding="utf-8"))
        candidate = document["artifact_sets"][0]
        evidence = json.loads(report.read_text(encoding="utf-8"))[
            "qualified_public_evidence_sha256"
        ]
        candidate["role"] = "qualified_candidate"
        candidate["production_accepted"] = True
        candidate["qualified_public_evidence_sha256"] = evidence
        candidate["qualification_report"] = {
            "path": report.name,
            "sha256": sha256(report),
        }
        contract = directory / self.contract.name
        write_json(contract, document)
        return contract, report

    def rebind_forged_run(self, triplet: Path, dr: float, key: Path) -> None:
        """Create an internally consistent, validly signed one-triplet forgery."""

        run_name = verifier.RUN_DIR_NAMES[dr]
        run = triplet / run_name
        ssp_path = run / "ssp" / verifier.rederive.expected_ssp_names(dr)[0]
        source = ssp_path.read_text(encoding="utf-8")
        first_weight = (15.0 - 4.0)
        ssp_path.write_text(
            source.replace(f"{first_weight},6", f"{first_weight + 1.0},6", 1),
            encoding="utf-8",
            newline="\n",
        )
        derived = verifier.rederive.rederive_private_run(run / "ssp", dr)
        with (run / "tams_radial.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=verifier.rederive.RADIAL_COLUMNS)
            writer.writeheader()
            writer.writerows(derived["radial_rows"])
        result_path = run / "tams_result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result.update(
            {
                "dR_kpc": dr,
                "radial_nodes": derived["radial_nodes"],
                "selected_stellar_assembly_rows": derived[
                    "selected_stellar_assembly_rows"
                ],
                "compact_remnant_rows_rejected": derived[
                    "compact_remnant_rows_rejected"
                ],
                "compact_remnant_surface_weight_rejected_sum_pc-2": derived[
                    "compact_remnant_surface_weight_rejected_sum_pc-2"
                ],
                "C1": derived["C1"],
                "domains": derived["domains"],
            }
        )
        write_json(result_path, result)
        names = verifier.rederive.expected_ssp_names(dr)
        snapshots = {
            name: verifier.secure.read_snapshot(run / "ssp" / name, name)
            for name in names
        }
        (run / "SSP_SHA256SUMS.txt").unlink()
        verifier.write_manifest(run / "SSP_SHA256SUMS.txt", names, snapshots)
        radial_snapshot = verifier.secure.read_snapshot(
            run / "tams_radial.csv", "forged radial CSV"
        )
        result_snapshot = verifier.secure.read_snapshot(
            result_path, "forged radial result"
        )
        execution_path = run / verifier.secure.EXECUTION_RECORD_NAME
        execution = json.loads(execution_path.read_text(encoding="utf-8"))
        execution["ssp_member_sha256"] = derived["ssp_member_sha256"]
        execution["generated_radial"] = verifier.evidence(radial_snapshot)
        execution["generated_result"] = verifier.evidence(result_snapshot)
        execution_body = dict(execution)
        execution_body.pop("execution_record_id")
        execution = verifier.document_with_id(execution_body, "execution_record_id")
        write_json(execution_path, execution)
        provenance_path = run / "RUN_PRIVATE_PROVENANCE.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["execution_record"] = verifier.evidence(
            verifier.secure.read_snapshot(execution_path, "forged execution record")
        )
        provenance["ssp_manifest"] = verifier.evidence(
            verifier.secure.read_snapshot(
                run / "SSP_SHA256SUMS.txt", "forged SSP manifest"
            )
        )
        provenance["generated_radial"] = verifier.evidence(radial_snapshot)
        provenance["generated_result"] = verifier.evidence(result_snapshot)
        write_json(provenance_path, provenance)
        contract = verifier.load_contract(self.contract)[0]
        candidate = verifier.artifact_set(contract, self.candidate_id)
        challenge = verifier.secure.read_snapshot(
            run / verifier.secure.START_CHALLENGE_NAME, "forged package challenge"
        )
        challenge_signature = verifier.secure.read_snapshot(
            run / verifier.secure.START_CHALLENGE_SIGNATURE_NAME,
            "forged package challenge signature",
        )
        execution_snapshot = verifier.secure.read_snapshot(
            execution_path, "forged package execution record"
        )
        provenance_snapshot = verifier.secure.read_snapshot(
            provenance_path, "forged package provenance"
        )
        manifest_snapshot = verifier.secure.read_snapshot(
            run / "SSP_SHA256SUMS.txt", "forged package manifest"
        )
        completion = verifier.document_with_id(
            verifier.completion_body(
                contract=contract,
                candidate=candidate,
                provenance=provenance,
                challenge=challenge,
                challenge_signature=challenge_signature,
                execution_record=execution_snapshot,
                private_provenance=provenance_snapshot,
                ssp_manifest=manifest_snapshot,
                radial=radial_snapshot,
                result=result_snapshot,
                derived_summary=verifier.result_summary(derived),
            ),
            "completion_id",
        )
        completion_path = run / "RUN_COMPLETION_ATTESTATION.json"
        signature_path = run / "RUN_COMPLETION_ATTESTATION.sig"
        completion_path.unlink()
        signature_path.unlink()
        write_json(completion_path, completion)
        verifier.sign_document(
            completion_path,
            key,
            verifier.COMPLETION_NAMESPACE,
            signature_path.name,
        )
        triplet_provenance_path = triplet / "TRIPLET_PRIVATE_PROVENANCE.json"
        triplet_provenance = json.loads(
            triplet_provenance_path.read_text(encoding="utf-8")
        )
        triplet_provenance["runs"][str(dr)]["completion"] = verifier.evidence(
            verifier.secure.read_snapshot(completion_path, "forged completion")
        )
        triplet_provenance["runs"][str(dr)][
            "completion_signature"
        ] = verifier.evidence(
            verifier.secure.read_snapshot(signature_path, "forged completion signature")
        )
        write_json(triplet_provenance_path, triplet_provenance)
        inspected = {
            spacing: verifier.inspect_private_run(
                triplet / verifier.RUN_DIR_NAMES[spacing],
                contract,
                candidate,
                spacing,
            )
            for spacing in verifier.DRS
        }
        scientific = verifier.scientific_evidence(inspected)
        run_snapshots = {
            spacing: (
                verifier.secure.read_snapshot(
                    triplet
                    / verifier.RUN_DIR_NAMES[spacing]
                    / "RUN_COMPLETION_ATTESTATION.json",
                    "forged triplet completion",
                ),
                verifier.secure.read_snapshot(
                    triplet
                    / verifier.RUN_DIR_NAMES[spacing]
                    / "RUN_COMPLETION_ATTESTATION.sig",
                    "forged triplet completion signature",
                ),
            )
            for spacing in verifier.DRS
        }
        triplet_attestation = verifier.document_with_id(
            verifier.triplet_body(
                contract=contract,
                candidate=candidate,
                provenance=triplet_provenance,
                run_snapshots=run_snapshots,
                scientific=scientific,
            ),
            "triplet_attestation_id",
        )
        triplet_path = triplet / "TRIPLET_ATTESTATION.json"
        triplet_signature_path = triplet / "TRIPLET_ATTESTATION.sig"
        triplet_path.unlink()
        triplet_signature_path.unlink()
        write_json(triplet_path, triplet_attestation)
        verifier.sign_document(
            triplet_path,
            key,
            verifier.TRIPLET_NAMESPACE,
            triplet_signature_path.name,
        )

    def test_private_triplet_and_public_qualification_are_valid(self) -> None:
        first = verifier.inspect_private_triplet(self.contract, self.triplet_a)
        second = verifier.inspect_private_triplet(self.contract, self.triplet_b)
        self.assertNotEqual(first["signer_id"], second["signer_id"])
        report = json.loads(self.report.read_text(encoding="utf-8"))
        verifier.validate_public_report(
            verifier.load_contract(self.contract)[0],
            verifier.artifact_set(verifier.load_contract(self.contract)[0], self.candidate_id),
            report,
        )

    def test_contract_is_fail_closed_until_production_acceptance(self) -> None:
        with self.assertRaisesRegex(verifier.RadialContractError, "production-accepted"):
            verifier.verify_public_qualification(self.contract, self.report)

    def test_public_report_contains_no_raw_ssp_or_radial_rows(self) -> None:
        data = self.report.read_text(encoding="utf-8")
        self.assertNotIn('"radial_rows":', data)
        self.assertNotIn("N,age,FeH,Mini", data)
        self.assertNotIn("dN_dR,dL1_dR", data)

    def test_incomplete_ssp_set_fails(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            next((triplet / "dr0p5" / "ssp").iterdir()).unlink()
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_ssp_swap_between_radii_fails(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            first = triplet / "dr1p0" / "ssp" / "SSP_R4.0_d_Padova.csv"
            second = triplet / "dr1p0" / "ssp" / "SSP_R5.0_d_Padova.csv"
            first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
            first.write_bytes(second_bytes)
            second.write_bytes(first_bytes)
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_internally_consistent_signed_ssp_forgery_needs_second_repeat(self) -> None:
        temporary, triplet = self.private_copy("forged")
        try:
            self.rebind_forged_run(triplet, 1.0, self.key_a)
            verifier.inspect_private_triplet(self.contract, triplet)
            with self.assertRaisesRegex(
                verifier.RadialContractError, "not bit-identical"
            ):
                verifier.qualify_triplets(
                    self.contract,
                    triplet,
                    self.triplet_b,
                    self.candidate_id,
                    Path(temporary.name) / "forged-report.json",
                )
        finally:
            temporary.cleanup()

    def test_nonfinite_ssp_1e999_fails(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            path = triplet / "dr0p25" / "ssp" / "SSP_R4.0_d_Padova.csv"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("11.0,6", "1e999,6", 1), encoding="utf-8", newline="\n")
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_manifest_path_traversal_fails(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            manifest = triplet / "dr1p0" / "SSP_SHA256SUMS.txt"
            lines = manifest.read_text(encoding="utf-8").splitlines()
            digest = lines[0].split()[0]
            lines[0] = f"{digest}  ../outside.csv"
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_nonfinite_generated_result_fails_before_attestation(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            result = triplet / "dr0p5" / "tams_result.json"
            data = result.read_text(encoding="utf-8")
            result.write_text(
                data.replace('"C1": 2714133632.1901126', '"C1": 1e999', 1),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_symlinked_ssp_fails(self) -> None:
        temporary, triplet = self.private_copy()
        try:
            path = triplet / "dr1p0" / "ssp" / "SSP_R4.0_d_Padova.csv"
            target = triplet / "saved.csv"
            target.write_bytes(path.read_bytes())
            path.unlink()
            try:
                os.symlink(target, path)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(verifier.RadialContractError):
                verifier.inspect_private_triplet(self.contract, triplet)
        finally:
            temporary.cleanup()

    def test_copytree_is_not_a_second_fresh_triplet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "copied"
            shutil.copytree(self.triplet_a, copied)
            with self.assertRaisesRegex(verifier.RadialContractError, "labels|signers|execution"):
                verifier.qualify_triplets(
                    self.contract,
                    self.triplet_a,
                    copied,
                    self.candidate_id,
                    Path(temporary) / "report.json",
                )

    def test_duplicate_json_key_and_nonfinite_report_fail(self) -> None:
        report = self.report.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text(
                report.replace('"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,', 1),
                encoding="utf-8",
            )
            with self.assertRaises(verifier.RadialContractError):
                verifier.strict_json_snapshot(duplicate, "duplicate report")
            nonfinite = Path(temporary) / "nonfinite.json"
            nonfinite.write_text('{"value":1e999}\n', encoding="utf-8")
            with self.assertRaises(verifier.RadialContractError):
                verifier.strict_json_snapshot(nonfinite, "nonfinite report")

    def test_bool_or_coercible_contract_fields_fail(self) -> None:
        for value in (True, "2"):
            document = json.loads(self.contract.read_text(encoding="utf-8"))
            document["qualification_policy"]["required_distinct_fresh_triplets"] = value
            with self.assertRaises(verifier.RadialContractError):
                verifier.validate_contract(document)

    def test_accepted_public_report_and_convergence_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract, report = self.accepted_contract(root)
            public = root / "freeze-contract"
            public.mkdir()
            for dr, run_name in verifier.RUN_DIR_NAMES.items():
                tag = verifier.rederive.tag(dr)
                shutil.copy2(
                    self.triplet_a / run_name / "tams_radial.csv",
                    public / f"tams_radial_dr{tag}.csv",
                )
                shutil.copy2(
                    self.triplet_a / run_name / "tams_result.json",
                    public / f"tams_result_dr{tag}.json",
                )
            result = verifier.bind_public_convergence(contract, report, root)
            self.assertEqual(result["status"], "PASS")
            with (public / "tams_radial_dr0p5.csv").open("ab") as handle:
                handle.write(b"\n")
            with self.assertRaises(verifier.RadialContractError):
                verifier.bind_public_convergence(contract, report, root)

    def test_rehashed_fake_public_report_fails_accepted_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract, report = self.accepted_contract(root)
            document = json.loads(report.read_text(encoding="utf-8"))
            document["created_utc"] = "2026-01-01T00:00:00Z"
            body = dict(document)
            body.pop("qualification_id")
            document["qualification_id"] = "sha256:" + hashlib.sha256(
                verifier.canonical_bytes(body)
            ).hexdigest()
            write_json(report, document)
            with self.assertRaises(verifier.RadialContractError):
                verifier.verify_public_qualification(contract, report)

    def test_untracked_source_shadow_and_arbitrary_archive_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            public = root / "public"
            jj = root / "jj"
            shutil.copytree(self.private_root, private)
            shutil.copytree(self.public_root, public)
            shutil.copytree(self.jj_root, jj)
            shadow = private / "research" / "jj-tams-convergence" / "shadow.py"
            shadow.write_text("raise RuntimeError('shadow')\n", encoding="utf-8")
            common = dict(self.common)
            common.update(
                {
                    "jj_root": jj,
                    "public_source_root": public,
                    "private_source_root": private,
                }
            )
            with self.assertRaises(verifier.RadialContractError):
                verifier.execute_fresh_triplet(
                    self.contract,
                    **common,
                    signer_id="fixture-attestor-a",
                    signing_key=self.key_a,
                    triplet_label="shadow-triplet",
                    execution_root=root / "execution-shadow",
                    output_root=root / "output-shadow",
                )
            shadow.unlink()
            forged_archive = root / "private-forged.tar"
            forged_archive.write_bytes(self.private_archive.read_bytes() + b"forged")
            common["private_source_archive"] = forged_archive
            with self.assertRaises(verifier.RadialContractError):
                verifier.execute_fresh_triplet(
                    self.contract,
                    **common,
                    signer_id="fixture-attestor-a",
                    signing_key=self.key_a,
                    triplet_label="archive-triplet",
                    execution_root=root / "execution-archive",
                    output_root=root / "output-archive",
                )

    def test_untracked_jj_shadow_outside_padova_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            public = root / "public"
            jj = root / "jj"
            shutil.copytree(self.private_root, private)
            shutil.copytree(self.public_root, public)
            shutil.copytree(self.jj_root, jj)
            (jj / "jjmodel" / "shadow.py").write_text("value = 1\n", encoding="utf-8")
            common = dict(self.common)
            common.update(
                {
                    "jj_root": jj,
                    "public_source_root": public,
                    "private_source_root": private,
                }
            )
            with self.assertRaises(verifier.RadialContractError):
                verifier.execute_fresh_triplet(
                    self.contract,
                    **common,
                    signer_id="fixture-attestor-a",
                    signing_key=self.key_a,
                    triplet_label="jj-shadow-triplet",
                    execution_root=root / "execution",
                    output_root=root / "output",
                )

    def test_gitignored_source_shadow_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            public = root / "public"
            jj = root / "jj"
            shutil.copytree(self.private_root, private)
            shutil.copytree(self.public_root, public)
            shutil.copytree(self.jj_root, jj)
            exclude = private / ".git" / "info" / "exclude"
            with exclude.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write("shadow.py\n")
            (private / "shadow.py").write_text("value = 1\n", encoding="utf-8")
            common = dict(self.common)
            common.update(
                {
                    "jj_root": jj,
                    "public_source_root": public,
                    "private_source_root": private,
                }
            )
            with self.assertRaisesRegex(verifier.RadialContractError, "ignored"):
                verifier.execute_fresh_triplet(
                    self.contract,
                    **common,
                    signer_id="fixture-attestor-a",
                    signing_key=self.key_a,
                    triplet_label="ignored-shadow-triplet",
                    execution_root=root / "execution",
                    output_root=root / "output",
                )


if __name__ == "__main__":
    unittest.main()
