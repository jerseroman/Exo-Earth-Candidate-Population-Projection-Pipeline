#!/usr/bin/env python3
"""Adversarial fixtures for the public v4.0.4 release-acceptance gate."""

from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import py_compile
import shutil
import stat
import subprocess
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from scripts import build_public_package as package  # noqa: E402
from scripts import verify_public_package_roundtrip as roundtrip  # noqa: E402
from scripts import verify_local_run_attestation as local_gate  # noqa: E402
from scripts import verify_v404_release_acceptance as gate  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


RECOVERY_MANIFEST_LOCK_FIXTURE = (
    ("484ee95e0f7eba4da867f96892b5f1e1cd760883d19e099ad705946c8da6fc5d", 782, "8a9f6b9e481b51e8fe197c204c897f1683db5e3d613d97c8162c6c2ff8f0f864", 3340),
    ("fde2db800710ee1e1131e6616ebc0a2a45d8d365ef9a85fb15d07a7a9a53ffbc", 782, "b9963e2e2d76817545b5825d14250af9791628972df9c6e19bce57776ed2d47d", 3340),
    ("e881f824a8e4c30c4c410ce4ba3adfbbe21c4bf8e396618f90d914d665fc6e16", 782, "0972a76c3d16dfe61788784e9af5176d8b9dd89d0302272d73d7627435c518b6", 3340),
    ("6cddb61b194f6a78ec7a1f66fd2f8cddebd77c62d17e2cee7408ae5cdf3acd5c", 782, "c93a53fd421e1699aacf7d122eecf0c5d653b0ecefded59391af41a937263c08", 3340),
    ("1b4787ba61e299b32e89772b6dfc4d66d9bd5daea49695895d0c9515f5b05ddb", 782, "7657082af13fe9e0da981ecc8a063cf26abc9a9c0bb5053bbfdb27bf716e1c87", 3340),
    ("76e60423ac14d0965335eb3e2e072c8f6d290f06f57c5749781a2138e70afbe2", 782, "7404a164cb5855052990e7ef39799844c607ffbe6bc60854375f6d1f5779beef", 3340),
    ("a2eac7d1c698dbbec637bf220d185c6b215e968aac8e0a1faf892848ac9f56ea", 782, "05ded53f781d9c91d2b86e1b944b762bfe602d13132d0ac1261f43ce85da10e1", 3340),
    ("687a03be3adbeb4614d6a015b4abf5aaada47ade7723958d1071ddfc3c4da4e7", 782, "667846e630a041abeaed516c3750e2b3d8ed9231a4ccf99a3ce62ddaa5d374e1", 3340),
    ("f97e3cc271e6681a06ce464553084e942db9c23aba6f715c6efd1ac5a7765d59", 782, "76337bf4df0b71b1d0cc7885107a2ee901df470d3401ff5ecb95938e59cfafd2", 3340),
    ("8bfe5cf84b2b01d7bcf7914e1d97cf4ed45fa227dd05a548175a68259ed711e4", 782, "a17d2cef638ba4aa85065333628a241ac70aca0080ea1ccdaf5ec84e0189e10a", 3340),
    ("43cdce45a5c5ea6aa1e4a58d474a8c2a6e5a61a5b84e07cdc62341a0200c5614", 788, "07319b2d89fea87240ad45081539fa8037e9785690bb81f8942ef6c5dfdd324c", 3366),
    ("2c825e124eb833efe1254eb99424a20ab15d802a8ce6cb31c849a7698483e190", 788, "5ad39d02f904c435b2e5410f0a88cd1130213b569518455b6716887080f412bc", 3366),
    ("4b6c3a6ec972d3abb986911c85001b29ed60d28ad793ca8fa8f700c69372f987", 788, "ea9e9668a411cbae5df2397e6f0b8bb95fa2cf4603c1c3c73fbec79de3d92635", 3366),
    ("bc33fe1f8a161d4fb0eb104379c0943ff18c2a2a802171d73350947a98a271ac", 788, "3a4dec0fa2df022eea43d6274bed8946444acf03730ece09c9d33893fb297a21", 3366),
    ("97235e68315e071bd71b6b93fbb9842c97eb5a8baadac4a397759be6e27dc2f6", 788, "d5ffb19599d7cddcfe055e217a7b731a917715ccbfc6a2cf8c9dc8849ab1e802", 3366),
    ("308aee7ed2a20ac3984c53690b91533367aaa55cce9e3041d5bcd10a99d5b182", 788, "9250dbf4e402efca36d8789b378384cc702e6b8ffc78d70cc6dcffa3b3bacb7a", 3366),
    ("2cfa06beac4a7962e7a16a46998ae97e7400bf5dda8d17c074eb7ea17e9160c0", 758, "1926f1bd4e3b840b0671e9befd211fd82cf2405cd4557cc7dcf5bffcff6bcad3", 3236),
    ("1dd18c11a5cda8b2dc08457e8729c41f5daed326d244b62131e35365ec6d4486", 758, "78006c7217f06d5958166dd3c56328567ec3382a4e6ed49b03beeeddc004ee0e", 3236),
    ("770fc815a87929e8788558da75b6d722e98a10804451ebcd92d105ddbe3748e2", 758, "8c2969980e23f3d3bb7ea3b10ba1c73820f350052fe58cd3e5b701ff2b3f1665", 3236),
    ("4e15742592ba708d44c26bc4e5689ac39204fe9ce73b07c64c70abb2a3b376fd", 758, "bf126bddbf5cc2fcdae853308446c09f8f22fa741bcce391b00ea4dc6edc6f90", 3236),
    ("eb6026290639790537f6cceeeadfca7ac60923995763d277e47b7b6bd7650a2d", 758, "8c7854554754ad8435a1dff29efcdd59ec22b9b562acc5e30633559a1aac41eb", 3236),
    ("bfa78642edfb6318af4cd5fed333ca60aebcd894653ae8b487b1cabda2bf9601", 758, "da7dadc9cb304083eed014a4466c57f3afde28caef66149cf31c3c2cfbd748bb", 3236),
    ("69449aa89919dbe1c7f092cb0f2afc9323b67d1347ee5d4f72c14addac1fdb15", 758, "19fd9190aa21458fe36f16586ba8565e5f628f7e91aee70722c02fb70904584b", 3236),
    ("ad25788f41266c836ee38c21b9ea5442ae6d3d4fcad02a1892461b6cd1c9e438", 758, "ec3988ccf79bb904aa3badc4cca8e880e5e4279de8c82f37b0ceeabd97712a2b", 3236),
    ("807a281b2af205d8ef08c6c06121e8de6be431d028a03fc941135766d31208ea", 758, "b13c069be632fd1370348f94b435d8f075c944bbbe6995d99d071c51003c3231", 3236),
    ("a8bc68fe2aed9af4b0535876b9395f12137cea7076d9ce10bfcba1fdc6c57fa6", 758, "ecfacdda42e5af5c801019cf201920995be23c24902276b7632fe4d1af835893", 3236),
    ("d3067fbd6055fcee6dfb5559a71530ce87ac7da6fe94d97b7c3f49fefc9207e2", 764, "a4c467fb9002c97bce8cd254f977cf00a3131305d76e46e8970b699de8426e23", 3262),
    ("78909c53f94de62b62733d464c71e2b2a6d6a5193a514b764c4a8c2c05d482f8", 764, "ec2bc2d52790f95fe8bb10c6e8084ee531594178f544a0cdc9d2ca115e8fbf12", 3262),
    ("492b920970f1e33c127e828235b7ba88450805433cbed1f06b61919fa1feef79", 764, "09ad9247ea3f61e0052c940ac4aaa6aa206f6f57721f3193865c7ba6fd948b68", 3262),
    ("e184a777c132e86be3809621ada34d42f1038fee5db3d607b0b2dce6685c1aa5", 764, "9feeecda056f9857d6577c32aba6e97373d56e1957de51dfb2f1f5dc4df35934", 3262),
    ("f85f901b122c34be11d409cb1ce6f3af60d639afb9dcda801f631e746f016800", 764, "6a2a1e713c7f512d4c0f29d60201568b4e267e3bc09bea53affd592bd2a3aef9", 3262),
    ("b35c7c56337fac3cb88b65f6ff2f7c98674c02cb1128f8514255f5f5dc993935", 764, "e1960ee098f879f66de090dca0980c779e96e1f05b8dec8289d13dba7fd26a60", 3262),
    ("8e481d1f78a85241e892b1c0abba240da0b9ca6131ea60713e7cf993545f2dbe", 782, "c767f2e2174e91403ee6aeb7a455bdadb94750f40b5e460423d1d63ded44373e", 3340),
    ("40e56fd52499ade7a5b76e32423bb02c7fe16b80cb6185152de5b9abc8133fac", 782, "74e9b321bfec0e19afa160244dd96ff2d9a28c34db6af52cb8a598aa76535da4", 3340),
    ("0ee0e79c2702b89d0a26c6d7d178da397f82b97d42feda617e75a9b8f7941926", 782, "4f3d1a694eaa56e6919cb7ccb606a6417947b644d4bf660c84f30992bd8f072c", 3340),
    ("7a1205e45b72d326a49ec39c3096373b7444a6850cfc4bceb63d0b90cacb92dc", 782, "7672571c05f9655949c3c2dd1dda9a4e785ff6f4b51a579f7955b35016944b51", 3340),
    ("eb52c77a302169dca25bfb25a7ee1ae363720c0ae2645ea34fc40abb65faf1f4", 782, "f772f80496271c4757e00b75e854500467ef7ba2635694fa20c8a978379e3911", 3340),
    ("aebb521d09eec8203923df53999db5b1ca5a013bbfb33256aa1aec9f168bafad", 782, "8e752f868586394dcf83e7787219e73a3f3a73813b7ecb55f6ba2dd15c68b926", 3340),
    ("7b5949c03940e8477172b45cadc76eb131c2ab0f1f58bd7a737f5c3c48511452", 782, "898172e3a05439d6223f70238e7423bcc053f1478d12703ed26a753abdcb476c", 3340),
    ("f45130b6d82f2b6eb02251f9741cbafbe6760205bd173c891a4a564cc558c3b9", 782, "0bd238c33495ac4ee7844fd4864c8206dfe28075ee5ca88f170953a442794543", 3340),
    ("025145bbf34cf19591ad807a00c62fbbd8512aa7db9473ce020a3f8c9127ede0", 782, "c24f1b44ce638e72f7fddc0c74805b246250e7858ed4f800e7566d4ff4ad4ffe", 3340),
    ("85f22a01f3bccfa1fa63ca45054baf2d8fc1938f35af1910025459ec48f66171", 782, "5957a2bedeb8f57f3073458476b3d826e0b88d4ba97bad42444e09db0b1b8a83", 3340),
    ("30e0340c03238cb5fa7b8dd8093472f27cac76fa098939bece57e507ca7c578b", 788, "8f9ce7e3e63b2fe533e1fd09387f544b00149ce63de7d465e29ae9e6d7642464", 3366),
    ("886f7e3764d21cf1265187835ff87549cd83fb0d08afb13e908b6b49a9dde065", 788, "96bf017b2e17e92a435ae4dfd38a194fd1b8edf979d9bcf73d8dd8393d78d7c7", 3366),
    ("52e2b2d12e51b37293dbda029290f24c558fe638554fc7e069a73a0d54c96d1a", 788, "da99f9819a7781fcb246349fc41bfe1e3ff6170656fd3011eceab2c58bf17eb0", 3366),
    ("0dee1a096f8e99dfeaeeed99e41481cb8a5b2de72236d5fbcc14713040bc4dbf", 788, "2c403f07e8d736e7a2f94a62128ae8502d4b7447a5553356a363ebec5dac6130", 3366),
    ("17482f6b20e2907df6782483f5b12861e7dbef86565334c57fc4856cc6e10ce1", 788, "5f3f7795eed99fd8964d2857e06c3a319c4a21aa4c6d834bac70a6fdbf1d3bf2", 3366),
    ("f3366b0b90e91dbdf36b7e7826230ba6d5a280b045d0072e9d70c711c6e7aafb", 788, "02c7820633a43fb6a7ca6f71b58384f75dc050a1ab074f1b6aa083a6de2a9737", 3366),
)


def read_json(path: Path) -> dict[str, object]:
    return gate.load_json_bytes(path.read_bytes(), path.name)


class FakeHost:
    HOST_START_CHALLENGE_NAME = "HOST_RUN_START_CHALLENGE.json"

    @staticmethod
    def load_contract(path: Path) -> dict[str, object]:
        return read_json(path)


class FakeAge:
    @staticmethod
    def load_contract(path: Path) -> tuple[dict[str, object], object]:
        return read_json(path), object()

    @staticmethod
    def accepted_candidate(contract: dict[str, object]) -> dict[str, object]:
        return [
            item
            for item in contract["artifact_sets"]
            if item["production_accepted"] is True
        ][0]

    @staticmethod
    def validate_report_document(
        report: dict[str, object],
        _contract: dict[str, object],
        _candidate: dict[str, object],
    ) -> dict[str, object]:
        return report


class FakeRadial:
    @staticmethod
    def load_contract(path: Path) -> tuple[dict[str, object], object]:
        return read_json(path), object()

    @staticmethod
    def accepted_candidate(contract: dict[str, object]) -> dict[str, object]:
        return [
            item
            for item in contract["artifact_sets"]
            if item["production_accepted"] is True
        ][0]

    @staticmethod
    def verify_public_qualification(
        contract_path: Path, _report_path: Path
    ) -> dict[str, object]:
        contract = read_json(contract_path)
        candidate = FakeRadial.accepted_candidate(contract)
        return {"artifact_set_id": candidate["id"]}


class FakeLocal:
    @staticmethod
    def validate_contract(
        contract: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        return contract, {item["id"]: item for item in contract["candidates"]}

    @staticmethod
    def validate_report_disclosure(_report: dict[str, object]) -> None:
        return None

    canonical_json_bytes = staticmethod(gate.canonical_json_bytes)


class ReleaseFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="v404-release-gate-")
        self.root = Path(self.temporary.name)
        self.computational_source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "archive_sha256": "3" * 64,
            "archive_size_bytes": 123456,
        }
        self.posterior = {
            "corrected_constant_full": "4" * 64,
            "corrected_constant_propagation": "5" * 64,
            "corrected_zero_full": "6" * 64,
            "corrected_zero_propagation": "7" * 64,
            "legacy_constant_full": "8" * 64,
            "legacy_constant_propagation": "9" * 64,
        }
        self.report_ids = {
            "host": "sha256:" + "a" * 64,
            "age": "sha256:" + "b" * 64,
            "radial": "sha256:" + "c" * 64,
        }
        self.report_names = {
            "host": "HOST_PUBLIC_QUALIFICATION.json",
            "age": "AGE_PUBLIC_QUALIFICATION.json",
            "radial": "RADIAL_PUBLIC_QUALIFICATION.json",
            "local": "LOCAL_RUN_PUBLIC_REPORT.json",
        }
        self.accepted_ids = {
            "host": "host-production",
            "age": "age-production",
            "radial": "radial-production",
            "local": "local-production",
        }
        (self.root / "provenance").mkdir(parents=True)
        (self.root / "scripts").mkdir()
        self.verifier_bytes = b"fixture release verifier\n"
        (self.root / "scripts" / "verify_v404_release_acceptance.py").write_bytes(
            self.verifier_bytes
        )
        (self.root / "README.md").write_bytes(b"fixture release payload\n")
        self.recovery_disclosure: dict[str, object] | None = None
        self._prepare_results_assets()
        self._write_reports_and_contracts()
        self._write_freezes()
        self._write_acceptance()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @contextmanager
    def trusted_source_anchor(self):
        """Create the separately supplied outer ZIP/checksum trust boundary."""

        with tempfile.TemporaryDirectory(prefix="v404-source-anchor-") as temporary:
            root = Path(temporary)
            archive_path = root / gate.SOURCE_ARCHIVE_NAME
            checksum_path = root / gate.SOURCE_CHECKSUM_NAME
            manifest = gate._parse_repository_manifest(
                gate.read_snapshot(self.root, "MANIFEST.sha256", "fixture manifest")
            )
            members = sorted((*manifest, "MANIFEST.sha256"))
            with zipfile.ZipFile(
                archive_path, "w", compression=zipfile.ZIP_STORED
            ) as archive:
                for relative in members:
                    info = zipfile.ZipInfo(relative, date_time=gate.SOURCE_ZIP_TIME)
                    info.compress_type = zipfile.ZIP_STORED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, (self.root / relative).read_bytes())
            archive_sha = digest(archive_path.read_bytes())
            checksum_path.write_text(
                f"{archive_sha}  {archive_path.name}\n",
                encoding="ascii",
                newline="\n",
            )
            yield archive_path, checksum_path

    @property
    def verifiers(self) -> SimpleNamespace:
        return SimpleNamespace(
            host=FakeHost,
            age=FakeAge,
            radial=FakeRadial,
            local=FakeLocal,
        )

    def _source_record(self, role: str) -> dict[str, object]:
        return {
            "role": role,
            "repository": f"fixture/{role}",
            "commit_sha": self.computational_source["commit"],
            "git_tree_sha": self.computational_source["tree"],
            "source_archive": {
                "filename": f"{role}.tar",
                "sha256": self.computational_source["archive_sha256"],
                "size_bytes": self.computational_source["archive_size_bytes"],
            },
        }

    def _source_state(self) -> dict[str, object]:
        return {
            "public_source": self._source_record("public_release"),
            "private_source": self._source_record("private_production"),
        }

    def _write_json(self, relative: str, value: object, *, canonical: bool = False) -> None:
        path = self.root / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (
            gate.canonical_json_bytes(value)
            if canonical
            else (
                json.dumps(value, indent=2, allow_nan=False) + "\n"
            ).encode("utf-8")
        )
        path.write_bytes(data)

    def _write_recovery_json(self, relative: str, value: object) -> None:
        path = self.root / Path(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gate._recovery_canonical_json_bytes(value))

    def _local_report(self) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": 1,
            "qualification_status": "PASS",
            "contract_id": "local-production-run-v4.0.4",
            "candidate_id": self.accepted_ids["local"],
            "source_commit": self.computational_source["commit"],
            "source_tree": self.computational_source["tree"],
            "source_archive_sha256": self.computational_source["archive_sha256"],
            "source_archive_size_bytes": self.computational_source[
                "archive_size_bytes"
            ],
            "source_file_set_sha256": "d" * 64,
            "command_plan_sha256": "e" * 64,
            "numerical_runtime_manifest_sha256": "f" * 64,
            "run_id_sha256": "0" * 64,
            "challenge_id": "a" * 64,
            "start_signer_id": "signer-a",
            "start_challenge_sha256": "1" * 64,
            "start_signature_sha256": "2" * 64,
            "completion_id": "b" * 64,
            "completion_signer_id": "signer-b",
            "completion_attestation_sha256": "3" * 64,
            "completion_signature_sha256": "4" * 64,
            "execution_started_utc": "2026-08-30T00:00:00Z",
            "execution_ended_utc": "2026-08-30T01:00:00Z",
            "command_results": [
                {
                    "command_index": 0,
                    "exit_code": 0,
                    "started_utc": "2026-08-30T00:00:01Z",
                    "ended_utc": "2026-08-30T00:00:02Z",
                    "stdout_sha256": "5" * 64,
                    "stdout_size_bytes": 1,
                    "stderr_sha256": "6" * 64,
                    "stderr_size_bytes": 0,
                }
            ],
            "output_manifest_sha256": digest(self.strict_output_manifest),
            "output_file_count": len(self.output_entries),
            "output_total_size_bytes": sum(
                item["size_bytes"] for item in self.output_entries
            ),
            "output_file_set_sha256": digest(
                gate.canonical_json_bytes(self.output_entries)
            ),
        }
        body["report_id"] = digest(gate.canonical_json_bytes(body))
        return body

    def _prepare_results_assets(self) -> None:
        paths = list(gate._expected_results_paths())
        members: dict[str, bytes] = {
            relative: f"fixture result: {relative}\n".encode("utf-8")
            for relative in paths
            if relative
            not in {gate.PUBLIC_RESULTS_REPORT_NAME, gate.PUBLIC_RESULTS_MANIFEST_NAME}
        }
        for branch, relative in gate.HEADLINE_SUMMARY_PATHS.items():
            q50 = 123.0 if branch == "constant" else 456.0
            draw_csv = (
                "Lambda_EE,global_trial\n"
                f"{q50 - 10.0},0\n"
                f"{q50},0\n"
                f"{q50},1\n"
                f"{q50 + 10.0},1\n"
            ).encode("utf-8")
            compressed = io.BytesIO()
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=compressed,
                mtime=0,
            ) as stream:
                stream.write(draw_csv)
            members[gate.HEADLINE_DRAW_PATHS[branch]] = compressed.getvalue()
            members[relative] = gate.canonical_json_bytes(
                {
                    "branch": branch,
                    "source_posterior_samples": {
                        "sha256": self.posterior[
                            f"corrected_{branch}_propagation"
                        ],
                        "row_count": 4,
                    },
                    "posterior_quantiles": {
                        "Lambda_EE": {"q50": q50}
                    },
                }
            )
        public_files = [
            {
                "path": relative,
                "sha256": digest(members[relative]),
                "size_bytes": len(members[relative]),
            }
            for relative in paths
            if relative
            not in {gate.PUBLIC_RESULTS_REPORT_NAME, gate.PUBLIC_RESULTS_MANIFEST_NAME}
        ]
        public_report = {
            "schema_version": 1,
            "status": "PASS",
            "release_candidate": "v4.0.4",
            "execution_environment": "fixture",
            "source_archive": {
                "sha256": self.computational_source["archive_sha256"],
                "size_bytes": self.computational_source["archive_size_bytes"],
                "regular_files_verified": 10,
                "execution_tree_byte_identical": True,
            },
            "production_design": {
                "fixture": True,
                "mcmc_recovery": copy.deepcopy(self.recovery_disclosure)
                if self.recovery_disclosure is not None
                else {
                    "mcmc_reused": False,
                    "aggregates_and_downstream_recomputed": True,
                },
            },
            "acceptance": {"fixture": True},
            "public_boundary": {
                "third_party_input_files_copied": False,
                "row_level_host_files_copied": False,
                "private_raw_chain_files_copied": False,
                "private_logs_copied": False,
            },
            "public_files": public_files,
            "command_count": 1,
            "runtime_seconds_by_stage": {"fixture": 1.0},
            "total_runtime_seconds": 1.0,
            "completed_utc": "2026-08-30T01:00:00Z",
        }
        members[gate.PUBLIC_RESULTS_REPORT_NAME] = gate.canonical_json_bytes(public_report)
        manifest_paths = sorted(set(paths) - {gate.PUBLIC_RESULTS_MANIFEST_NAME})
        members[gate.PUBLIC_RESULTS_MANIFEST_NAME] = "".join(
            f"{digest(members[relative])}  {relative}\n" for relative in manifest_paths
        ).encode("utf-8")
        self.output_entries = [
            {
                "path": relative,
                "sha256": digest(members[relative]),
                "size_bytes": len(members[relative]),
            }
            for relative in paths
        ]
        strict = {
            "schema_version": 1,
            "algorithm": "sha256",
            "files": self.output_entries,
        }
        self.strict_output_manifest = gate.canonical_json_bytes(strict)
        dist = self.root / "dist"
        dist.mkdir(exist_ok=True)
        archive_path = dist / gate.RESULTS_ARCHIVE_NAME
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for relative in paths:
                info = zipfile.ZipInfo(
                    f"{gate.RESULTS_ARCHIVE_PREFIX}/{relative}",
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, members[relative])
        archive_sha = digest(archive_path.read_bytes())
        (dist / gate.RESULTS_CHECKSUM_NAME).write_text(
            f"{archive_sha}  {gate.RESULTS_ARCHIVE_NAME}\n",
            encoding="ascii",
            newline="\n",
        )
        self.result_lock = {
            "filename": gate.RESULTS_ARCHIVE_NAME,
            "sha256_sidecar_filename": gate.RESULTS_CHECKSUM_NAME,
            "sha256": archive_sha,
            "size_bytes": archive_path.stat().st_size,
            "source_manifest_sha256": digest(
                members[gate.PUBLIC_RESULTS_MANIFEST_NAME]
            ),
        }

    def _write_reports_and_contracts(self) -> None:
        state = self._source_state()
        challenge = gate.canonical_json_bytes({"source_state": state})
        encoded_challenge = base64.b64encode(challenge).decode("ascii")
        embedded = {
            FakeHost.HOST_START_CHALLENGE_NAME: encoded_challenge,
        }
        host_report = {
            "qualification_id": self.report_ids["host"],
            "fresh_repetitions": [
                {"embedded_signed_evidence": embedded},
                {"embedded_signed_evidence": embedded},
            ],
        }
        age_report = {
            "qualification_id": self.report_ids["age"],
            "source_state": state,
        }
        radial_report = {
            "qualification_id": self.report_ids["radial"],
            "triplets": [
                {"source_provenance": state},
                {"source_provenance": state},
            ],
        }
        local_report = self._local_report()
        reports = {
            "host": host_report,
            "age": age_report,
            "radial": radial_report,
            "local": local_report,
        }
        for role, report in reports.items():
            self._write_json(
                f"provenance/{self.report_names[role]}",
                report,
                canonical=role == "local",
            )

        for role in ("host", "age", "radial"):
            report_path = self.root / "provenance" / self.report_names[role]
            contract = {
                "artifact_sets": [
                    {
                        "id": self.accepted_ids[role],
                        "production_accepted": True,
                        "qualification_report": {
                            "path": self.report_names[role],
                            "sha256": digest(report_path.read_bytes()),
                        },
                    }
                ]
            }
            self._write_json(gate.CONTRACT_PATHS[role], contract)

        local_path = self.root / "provenance" / self.report_names["local"]
        local_contract = {
            "contract_id": "local-production-run-v4.0.4",
            "attestation_signers": [
                {"signer_id": "signer-a"},
                {"signer_id": "signer-b"},
            ],
            "candidates": [
                {
                    "id": self.accepted_ids["local"],
                    "production_accepted": True,
                    "source_lock": {
                        **self.computational_source,
                        "public_repository": "fixture/public",
                        "private_repository": "fixture/private",
                    },
                    "accepted_report": {
                        "report_id": local_report["report_id"],
                        "sha256": digest(local_path.read_bytes()),
                        "size_bytes": local_path.stat().st_size,
                    },
                }
            ],
        }
        self._write_json(gate.CONTRACT_PATHS["local"], local_contract)
        self.report_ids["local"] = local_report["report_id"]

    def _host_binding(self, role: str) -> dict[str, object]:
        contract_path = self.root / Path(*gate.CONTRACT_PATHS["host"].split("/"))
        report_path = self.root / "provenance" / self.report_names["host"]
        return {
            "production_accepted": True,
            "contract_sha256": digest(contract_path.read_bytes()),
            "artifact_set_id": self.accepted_ids["host"],
            "qualification_reports": {
                self.report_names["host"]: digest(report_path.read_bytes())
            },
            "role": role,
        }

    def _radial_binding(self) -> dict[str, object]:
        contract_path = self.root / Path(*gate.CONTRACT_PATHS["radial"].split("/"))
        report_path = self.root / "provenance" / self.report_names["radial"]
        return {
            "status": "PASS",
            "contract_sha256": digest(contract_path.read_bytes()),
            "qualification_report_sha256": digest(report_path.read_bytes()),
            "artifact_set_id": self.accepted_ids["radial"],
        }

    def _local_binding(self) -> dict[str, object]:
        contract_path = self.root / Path(*gate.CONTRACT_PATHS["local"].split("/"))
        report_path = self.root / "provenance" / self.report_names["local"]
        report = read_json(report_path)
        return {
            "status": "PASS",
            "report_id": report["report_id"],
            "contract_sha256": digest(contract_path.read_bytes()),
            "public_report_sha256": digest(report_path.read_bytes()),
            "candidate_id": self.accepted_ids["local"],
            "source_archive_sha256": report["source_archive_sha256"],
            "source_archive_size_bytes": report["source_archive_size_bytes"],
            "command_plan_sha256": report["command_plan_sha256"],
            "numerical_runtime_manifest_sha256": report[
                "numerical_runtime_manifest_sha256"
            ],
            "output_manifest_sha256": report["output_manifest_sha256"],
            "output_file_set_sha256": report["output_file_set_sha256"],
            "output_file_count": report["output_file_count"],
            "output_total_size_bytes": report["output_total_size_bytes"],
        }

    def _write_freeze_set(
        self, role: str, document: dict[str, object]
    ) -> None:
        spec = gate.FREEZE_SPECS[role]
        freeze_root = self.root / Path(*spec["root"].split("/"))
        freeze_root.mkdir(parents=True, exist_ok=True)
        for name in spec["targets"]:
            path = freeze_root / name
            if name == spec["json"]:
                self._write_json(f"{spec['root']}/{name}", document)
            elif name.endswith(".csv"):
                path.write_bytes(b"field,value\nfixture,1\n")
            else:
                path.write_bytes(b"# Fixture freeze\n")
        (freeze_root / spec["manifest"]).write_text(
            "".join(
                f"{digest((freeze_root / name).read_bytes())}  {name}\n"
                for name in spec["targets"]
            ),
            encoding="utf-8",
            newline="\n",
        )

    def _write_freezes(self) -> None:
        shared_roots = {
            "host_artifact_contract": self._host_binding("freeze"),
            "radial_ssp_qualification": self._radial_binding(),
            "signed_local_production_run": self._local_binding(),
        }
        numerical = {
            "status": "PASS",
            "inputs": {
                "constant_full_posterior_samples": {
                    "sha256": self.posterior["corrected_constant_full"]
                },
                "constant_posterior_samples": {
                    "sha256": self.posterior["corrected_constant_propagation"]
                },
                "zero_full_posterior_samples": {
                    "sha256": self.posterior["corrected_zero_full"]
                },
                "zero_posterior_samples": {
                    "sha256": self.posterior["corrected_zero_propagation"]
                },
            },
            "artifact_roots": copy.deepcopy(shared_roots),
            "galactic_results": {
                "canonical": {
                    "constant": {"Lambda_EE": {"q50": 123.0}},
                    "zero": {"Lambda_EE": {"q50": 456.0}},
                }
            },
        }
        age_contract = self.root / Path(*gate.CONTRACT_PATHS["age"].split("/"))
        age_report = self.root / "provenance" / self.report_names["age"]
        sensitivity_roots = copy.deepcopy(shared_roots)
        sensitivity_roots["age_cut_sensitivity"] = {
            "status": "PASS",
            "age_ssp_contract_sha256": digest(age_contract.read_bytes()),
            "ssp_qualification_report_sha256": digest(age_report.read_bytes()),
            "accepted_ssp_repetition_rederived": True,
        }
        sensitivity_roots["legacy_measurement_accepted_aggregate"] = {
            "accepted_root": {
                "full_samples_sha256": self.posterior["legacy_constant_full"],
                "propagation_samples_sha256": self.posterior[
                    "legacy_constant_propagation"
                ],
            }
        }
        sensitivity = {
            "status": "SENSITIVITY_REGISTER_FROZEN",
            "scientific_readiness": "CONDITIONAL_MODEL_PROJECTION_ONLY",
            "inputs": {
                "constant_posterior_samples": {
                    "sha256": self.posterior["corrected_constant_propagation"]
                },
                "zero_posterior_samples": {
                    "sha256": self.posterior["corrected_zero_propagation"]
                },
                "legacy_measurement_posterior_samples": {
                    "sha256": self.posterior["legacy_constant_propagation"]
                },
            },
            "artifact_roots": sensitivity_roots,
            "canonical_posterior_q50": {
                "constant_Lambda_EE": 123.0,
                "zero_Lambda_EE": 456.0,
            },
        }
        self._write_freeze_set("numerical", numerical)
        self._write_freeze_set("sensitivity", sensitivity)

    def _contract_entry(self, role: str) -> dict[str, object]:
        contract = self.root / Path(*gate.CONTRACT_PATHS[role].split("/"))
        report_relative = f"provenance/{self.report_names[role]}"
        report = self.root / Path(*report_relative.split("/"))
        return {
            "contract_path": gate.CONTRACT_PATHS[role],
            "contract_sha256": digest(contract.read_bytes()),
            "contract_size_bytes": contract.stat().st_size,
            "accepted_id": self.accepted_ids[role],
            "report_path": report_relative,
            "report_sha256": digest(report.read_bytes()),
            "report_size_bytes": report.stat().st_size,
            "report_id": self.report_ids[role],
        }

    def _freeze_entry(self, role: str) -> dict[str, object]:
        spec = gate.FREEZE_SPECS[role]
        freeze_root = self.root / Path(*spec["root"].split("/"))
        files = {
            name: {
                "sha256": digest((freeze_root / name).read_bytes()),
                "size_bytes": (freeze_root / name).stat().st_size,
            }
            for name in spec["targets"]
        }
        manifest = freeze_root / spec["manifest"]
        return {
            "root": spec["root"],
            "manifest": {
                "path": f"{spec['root']}/{spec['manifest']}",
                "sha256": digest(manifest.read_bytes()),
                "size_bytes": manifest.stat().st_size,
            },
            "files": files,
        }

    def _acceptance_document(self) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": 2,
            "release_version": "4.0.4",
            "production_accepted": True,
            "computational_source": copy.deepcopy(self.computational_source),
            "release_source": {
                "lineage_commit": "a" * 40,
                "lineage_tree": "b" * 40,
                "lineage_relationship": "direct_parent_of_final_release",
                "manifest_path": "MANIFEST.sha256",
                "payload_manifest_sha256": self.payload_manifest_sha256(),
                "public_payload_manifest_sha256": self.payload_manifest_sha256(),
                "computational_projection_manifest_sha256": "0" * 64,
                "public_computational_projection_manifest_sha256": "0" * 64,
                "post_computation_policy": gate.POST_COMPUTATION_POLICY,
                "acceptance_verifier_sha256": digest(self.verifier_bytes),
                "allowed_finalization_paths": list(gate.FINALIZATION_PATHS),
                "final_binding": "direct-parent-exact-diff-and-payload-manifest",
            },
            "results_archive": copy.deepcopy(self.result_lock),
            "contracts": {
                role: self._contract_entry(role) for role in gate.CONTRACT_PATHS
            },
            "freezes": {
                role: self._freeze_entry(role) for role in gate.FREEZE_SPECS
            },
            "posterior_artifacts": copy.deepcopy(self.posterior),
        }
        projection_entries = {
            path.relative_to(self.root).as_posix(): digest(path.read_bytes())
            for path in self.manifest_files(include_acceptance=False)
        }
        body["release_source"]["computational_projection_manifest_sha256"] = (
            gate.compute_computational_projection_sha256(projection_entries, body)
        )
        body["release_source"][
            "public_computational_projection_manifest_sha256"
        ] = body["release_source"]["computational_projection_manifest_sha256"]
        acceptance = dict(body)
        acceptance["acceptance_id"] = "sha256:" + digest(
            gate.canonical_json_bytes(body)
        )
        return acceptance

    def _write_acceptance(self, value: dict[str, object] | None = None) -> None:
        acceptance = value if value is not None else self._acceptance_document()
        self._write_json(gate.ACCEPTANCE_PATH, acceptance)
        self.rebuild_repository_manifest()

    @staticmethod
    def _with_self_id(value: dict[str, object]) -> dict[str, object]:
        report = copy.deepcopy(value)
        report["report_id"] = digest(gate._recovery_canonical_json_bytes(value))
        return report

    def enable_recovery(self) -> None:
        donor_source = {
            "commit": gate.RECOVERY_DONOR["source_commit"],
            "tree": gate.RECOVERY_DONOR["source_tree"],
            "archive_sha256": gate.RECOVERY_DONOR["source_archive"]["sha256"],
            "archive_size_bytes": gate.RECOVERY_DONOR["source_archive"][
                "size_bytes"
            ],
        }
        donor = copy.deepcopy(gate.RECOVERY_DONOR)
        protected = []
        for relative in gate.RECOVERY_PROTECTED_PATHS:
            source_path = ROOT / Path(*PurePosixPath(relative).parts)
            source_data = source_path.read_bytes()
            file_digest = digest(source_data)
            file_size = len(source_data)
            protected.append(
                {
                    "path": relative,
                    "from_sha256": file_digest,
                    "from_size_bytes": file_size,
                    "to_sha256": file_digest,
                    "to_size_bytes": file_size,
                    "bit_identical": True,
                }
            )
        transition = self._with_self_id(
            {
                "schema_version": 1,
                "transition_id": gate.RECOVERY_TRANSITION_ID,
                "status": "PASS",
                "from_source": donor_source,
                "to_source": copy.deepcopy(self.computational_source),
                "protected_paths": protected,
            }
        )
        transition_data = gate._recovery_canonical_json_bytes(transition)
        transition_lock = {
            "sha256": digest(transition_data),
            "size_bytes": len(transition_data),
        }
        qualification = self._with_self_id(
            {
                "schema_version": 1,
                "status": "PASS",
                "decision": gate.RECOVERY_DECISION,
                "donor_run_id": donor["run_id"],
                "recovery_contract_id": gate.RECOVERY_CONTRACT_ID,
                "source_transition_sha256": transition_lock["sha256"],
                "completion_attestation_present": False,
                "work_manifest_count": 48,
                "raw_manifest_count": 48,
                "mcmc_realizations": gate.RECOVERY_REALIZATIONS,
                "total_file_count": gate.RECOVERY_TOTAL_FILE_COUNT,
                "total_size_bytes": gate.RECOVERY_TOTAL_SIZE_BYTES,
            }
        )
        qualification_data = gate._recovery_canonical_json_bytes(qualification)
        qualification_lock = {
            "report_id": qualification["report_id"],
            "sha256": digest(qualification_data),
            "size_bytes": len(qualification_data),
        }
        variants = []
        for variant_index, (
            name,
            branch,
            measurement_mode,
            maximum_steps,
        ) in enumerate(gate.RECOVERY_VARIANTS):
            shards = []
            for shard in range(gate.RECOVERY_SHARDS_PER_VARIANT):
                work_sha, work_size, raw_sha, raw_size = (
                    RECOVERY_MANIFEST_LOCK_FIXTURE[
                        variant_index * gate.RECOVERY_SHARDS_PER_VARIANT + shard
                    ]
                )
                shards.append(
                    {
                        "shard": shard,
                        "work_manifest": {
                            "sha256": work_sha,
                            "size_bytes": work_size,
                        },
                        "raw_manifest": {
                            "sha256": raw_sha,
                            "size_bytes": raw_size,
                        },
                    }
                )
            variants.append(
                {
                    "name": name,
                    "branch": branch,
                    "measurement_error_mode": measurement_mode,
                    "maximum_steps": maximum_steps,
                    "shards": shards,
                }
            )
        contract = {
            "schema_version": 2,
            "contract_id": gate.RECOVERY_CONTRACT_ID,
            "status": "ACCEPTED",
            "donor": donor,
            "policy": {
                "copy_policy": gate.RECOVERY_COPY_POLICY,
                "mcmc_reused": True,
                "aggregates_and_downstream_recomputed": True,
                "shards_per_variant": gate.RECOVERY_SHARDS_PER_VARIANT,
                "trials_per_shard": gate.RECOVERY_TRIALS_PER_SHARD,
                "total_realizations": gate.RECOVERY_REALIZATIONS,
                "work_file_count": gate.RECOVERY_WORK_FILE_COUNT,
                "raw_file_count": gate.RECOVERY_RAW_FILE_COUNT,
                "total_file_count": gate.RECOVERY_TOTAL_FILE_COUNT,
                "total_size_bytes": gate.RECOVERY_TOTAL_SIZE_BYTES,
                "mcmc_policy_sha256": gate.RECOVERY_MCMC_POLICY_SHA256,
                "work_size_bytes": gate.RECOVERY_WORK_SIZE_BYTES,
                "raw_size_bytes": gate.RECOVERY_RAW_SIZE_BYTES,
                "work_tree_sha256": gate.RECOVERY_WORK_TREE_SHA256,
                "raw_tree_sha256": gate.RECOVERY_RAW_TREE_SHA256,
            },
            "variants": variants,
            "source_transition": transition_lock,
            "qualification_report": qualification_lock,
        }
        contract_data = gate._recovery_canonical_json_bytes(contract)
        evidence = {
            "contract": (contract, contract_data),
            "source_transition": (transition, transition_data),
            "qualification": (qualification, qualification_data),
        }
        for role, (_value, data) in evidence.items():
            relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS[role]
            path = self.root / Path(*PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        self.recovery_disclosure = {
            "mcmc_reused": True,
            "fresh_preflight_runtime_and_pilots_recomputed": True,
            "aggregates_and_downstream_recomputed": True,
            "donor_completion_attestation_present_in_qualified_evidence_set": False,
            "donor_run_id": donor["run_id"],
            "donor_source_commit": donor["source_commit"],
            "donor_source_tree": donor["source_tree"],
            "donor_source_archive_sha256": donor["source_archive"]["sha256"],
            "donor_source_archive_size_bytes": donor["source_archive"]["size_bytes"],
            "donor_source_file_set_sha256": donor["source_file_set_sha256"],
            "donor_source_file_count": donor["source_file_count"],
            "donor_attestation_contract_sha256": donor["attestation_contract"]["sha256"],
            "donor_attestation_contract_size_bytes": donor["attestation_contract"]["size_bytes"],
            "donor_command_plan_sha256": donor["command_plan"]["sha256"],
            "donor_numerical_runtime_sha256": donor["numerical_runtime_manifest"]["sha256"],
            "donor_start_challenge_sha256": donor["start_challenge"]["sha256"],
            "donor_start_signature_sha256": donor["start_signature"]["sha256"],
            "recovery_contract_sha256": digest(contract_data),
            "recovery_contract_size_bytes": len(contract_data),
            "mcmc_policy_sha256": gate.RECOVERY_MCMC_POLICY_SHA256,
            "recovery_source_commit": self.computational_source["commit"],
            "recovery_source_tree": self.computational_source["tree"],
            "source_transition_report_id": transition["report_id"],
            "source_transition_report_sha256": transition_lock["sha256"],
            "qualification_report_id": qualification["report_id"],
            "qualification_report_sha256": qualification_lock["sha256"],
            "reused_realizations": gate.RECOVERY_REALIZATIONS,
            "imported_work_file_count": gate.RECOVERY_WORK_FILE_COUNT,
            "imported_work_size_bytes": gate.RECOVERY_WORK_SIZE_BYTES,
            "imported_work_tree_sha256": gate.RECOVERY_WORK_TREE_SHA256,
            "imported_raw_file_count": gate.RECOVERY_RAW_FILE_COUNT,
            "imported_raw_size_bytes": gate.RECOVERY_RAW_SIZE_BYTES,
            "imported_raw_tree_sha256": gate.RECOVERY_RAW_TREE_SHA256,
        }
        self._prepare_results_assets()
        self._write_reports_and_contracts()
        self._write_freezes()
        self._write_acceptance()

    def manifest_files(self, *, include_acceptance: bool) -> list[Path]:
        files = [
            self.root / "README.md",
            self.root / "scripts" / "verify_v404_release_acceptance.py",
        ]
        if include_acceptance:
            files.append(self.root / gate.ACCEPTANCE_PATH)
        for role in gate.CONTRACT_PATHS:
            files.append(self.root / Path(*gate.CONTRACT_PATHS[role].split("/")))
            files.append(self.root / "provenance" / self.report_names[role])
        for role, spec in gate.FREEZE_SPECS.items():
            freeze_root = self.root / Path(*spec["root"].split("/"))
            files.extend(freeze_root / name for name in (*spec["targets"], spec["manifest"]))
        files.extend(
            self.root / Path(*PurePosixPath(relative).parts)
            for relative in gate.RECOVERY_PUBLIC_EVIDENCE_PATHS.values()
            if os.path.lexists(self.root / Path(*PurePosixPath(relative).parts))
        )
        return sorted(set(files), key=lambda item: item.relative_to(self.root).as_posix())

    def payload_manifest_sha256(self) -> str:
        rows = []
        for path in self.manifest_files(include_acceptance=False):
            relative = path.relative_to(self.root).as_posix()
            rows.append(f"{digest(path.read_bytes())}  {relative}\n")
        return digest("".join(rows).encode("utf-8"))

    def rebuild_repository_manifest(self) -> None:
        files = self.manifest_files(include_acceptance=True)
        rows = []
        for path in files:
            relative = path.relative_to(self.root).as_posix()
            rows.append(f"{digest(path.read_bytes())}  {relative}\n")
        (self.root / "MANIFEST.sha256").write_text(
            "".join(rows), encoding="utf-8", newline="\n"
        )

    def rewrite_acceptance(self, mutate) -> None:
        value = self._acceptance_document()
        mutate(value)
        body = dict(value)
        body.pop("acceptance_id", None)
        value["acceptance_id"] = "sha256:" + digest(gate.canonical_json_bytes(body))
        self._write_acceptance(value)

    def rewrite_host_contract(self, mutate) -> None:
        path = self.root / Path(*gate.CONTRACT_PATHS["host"].split("/"))
        value = read_json(path)
        mutate(value)
        self._write_json(gate.CONTRACT_PATHS["host"], value)
        self._write_freezes()
        self._write_acceptance()

    def rewrite_age_source_commit(self, commit: str) -> None:
        report_path = self.root / "provenance" / self.report_names["age"]
        report = read_json(report_path)
        report["source_state"]["public_source"]["commit_sha"] = commit
        report["source_state"]["private_source"]["commit_sha"] = commit
        self._write_json(f"provenance/{self.report_names['age']}", report)
        contract_path = self.root / Path(*gate.CONTRACT_PATHS["age"].split("/"))
        contract = read_json(contract_path)
        contract["artifact_sets"][0]["qualification_report"]["sha256"] = digest(
            report_path.read_bytes()
        )
        self._write_json(gate.CONTRACT_PATHS["age"], contract)
        self._write_freezes()
        self._write_acceptance()


class ReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ReleaseFixture()

    def tearDown(self) -> None:
        self.fixture.cleanup()

    def test_source_only_loader_ignores_unchecked_malicious_pyc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-source-only-") as temporary:
            root = Path(temporary)
            source = root / "protected_verifier.py"
            source.write_text("VALUE = 'MALICIOUS_BYTECODE'\n", encoding="utf-8")
            cache = root / "__pycache__" / "protected_verifier.pyc"
            cache.parent.mkdir()
            py_compile.compile(
                str(source),
                cfile=str(cache),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            source.write_text("VALUE = 'STABLE_SOURCE'\n", encoding="utf-8")
            name = "v404_adversarial_protected_verifier"
            try:
                module = gate.load_source_only_module(
                    root,
                    "protected_verifier.py",
                    name,
                    "adversarial protected verifier",
                )
                self.assertEqual(module.VALUE, "STABLE_SOURCE")
                self.assertIsNone(module.__cached__)
                self.assertRegex(module.__source_only_sha256__, r"^[0-9a-f]{64}$")
                with self.assertRaisesRegex(
                    gate.ReleaseAcceptanceError, "rejects bytecode"
                ):
                    gate.load_source_only_module(
                        root,
                        "__pycache__/protected_verifier.pyc",
                        name + "_cache",
                        "adversarial bytecode cache",
                    )
            finally:
                sys.modules.pop(name, None)

    def test_release_import_chain_is_source_only(self) -> None:
        modules = gate._default_verifiers()
        protected = (
            modules.age,
            modules.host,
            modules.local,
            modules.radial,
            sys.modules["verify_age_cut_sensitivity"],
            sys.modules["radial_ssp_rederive"],
        )
        for module in protected:
            self.assertIsNone(module.__cached__)
            self.assertRegex(module.__source_only_sha256__, r"^[0-9a-f]{64}$")
        gate._expected_results_paths()
        controller = sys.modules["run_v404_local_production"]
        self.assertIsNone(controller.__cached__)
        self.assertRegex(controller.__source_only_sha256__, r"^[0-9a-f]{64}$")

    def verify(self) -> dict[str, object]:
        with self.fixture.trusted_source_anchor() as (archive, checksum):
            return gate.verify_release_acceptance(
                self.fixture.root,
                verifiers=self.fixture.verifiers,
                trusted_source_archive=archive,
                trusted_source_checksum=checksum,
            )

    def prepare_git_release_lineage(
        self, *, code_drift: bool = False, unrelated_source: bool = False
    ) -> tuple[object, str, str]:
        executable = shutil.which("git")
        if executable is None:
            self.skipTest("Git is required for lineage test")

        def git(*arguments: str) -> str:
            completed = subprocess.run(
                [executable, "-C", str(self.fixture.root), *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            return completed.stdout.decode("ascii", errors="strict").strip()

        git("init", "-q")
        git("config", "user.name", "Release fixture")
        git("config", "user.email", "release-fixture@example.invalid")

        def add_manifest_tree() -> None:
            entries = gate._parse_repository_manifest(
                gate.read_snapshot(
                    self.fixture.root, "MANIFEST.sha256", "fixture manifest"
                )
            )
            git("add", "--", "MANIFEST.sha256", *sorted(entries))

        add_manifest_tree()
        git("commit", "-q", "-m", "computational source A")
        source_commit = git("rev-parse", "HEAD")
        source_tree = git("rev-parse", "HEAD^{tree}")
        if unrelated_source:
            source_commit = git(
                "commit-tree", source_tree, "-m", "unrelated computational source"
            )
        self.fixture.computational_source["commit"] = source_commit
        self.fixture.computational_source["tree"] = source_tree
        self.fixture._prepare_results_assets()
        self.fixture._write_reports_and_contracts()
        self.fixture._write_freezes()
        if code_drift:
            self.fixture.verifier_bytes = b"fixture release verifier code drift\n"
            (
                self.fixture.root
                / "scripts"
                / "verify_v404_release_acceptance.py"
            ).write_bytes(self.fixture.verifier_bytes)
        self.fixture._write_acceptance()
        add_manifest_tree()
        git("commit", "-q", "-m", "pre-final release B")
        lineage_commit = git("rev-parse", "HEAD")
        lineage_tree = git("rev-parse", "HEAD^{tree}")

        acceptance = self.fixture._acceptance_document()
        acceptance["release_source"]["lineage_commit"] = lineage_commit
        acceptance["release_source"]["lineage_tree"] = lineage_tree
        body = dict(acceptance)
        body.pop("acceptance_id")
        acceptance["acceptance_id"] = "sha256:" + digest(
            gate.canonical_json_bytes(body)
        )
        self.fixture._write_acceptance(acceptance)
        git("add", "--", gate.ACCEPTANCE_PATH, "MANIFEST.sha256")
        git("commit", "-q", "-m", "final binding C")
        return git, source_commit, lineage_commit

    def test_complete_public_fixture_passes(self) -> None:
        evidence = self.verify()
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["release_version"], "4.0.4")
        self.assertEqual(
            evidence["computational_source"], self.fixture.computational_source
        )
        self.assertEqual(
            gate.compute_payload_manifest_sha256(self.fixture.root),
            evidence["release_source"]["payload_manifest_sha256"],
        )

    def test_local_report_producer_and_release_consumer_schemas_match(self) -> None:
        snapshot = SimpleNamespace(sha256="a" * 64)
        contract = {"contract_id": "local-production-run-v4.0.4"}
        candidate = {"id": self.fixture.accepted_ids["local"]}
        challenge = {
            "run_id": "fixture-run",
            "challenge_id": "b" * 64,
            "start_signer_id": "signer-a",
        }
        completion = {
            "source_state_after": {
                "commit": self.fixture.computational_source["commit"],
                "tree": self.fixture.computational_source["tree"],
                "archive_sha256": self.fixture.computational_source[
                    "archive_sha256"
                ],
                "archive_size_bytes": self.fixture.computational_source[
                    "archive_size_bytes"
                ],
            },
            "source_file_set_sha256": "c" * 64,
            "command_plan": {"sha256": "d" * 64},
            "numerical_runtime_manifest": {"sha256": "e" * 64},
            "completion_id": "f" * 64,
            "completion_signer_id": "signer-b",
            "execution_started_utc": "2026-08-30T00:00:00Z",
            "execution_ended_utc": "2026-08-30T01:00:00Z",
            "command_results": [
                {
                    "command_index": 0,
                    "exit_code": 0,
                    "started_utc": "2026-08-30T00:00:01Z",
                    "ended_utc": "2026-08-30T00:00:02Z",
                    "stdout": {"sha256": "0" * 64, "size_bytes": 1},
                    "stderr": {"sha256": "1" * 64, "size_bytes": 0},
                }
            ],
        }
        output_entries = [
            {"path": "result.bin", "sha256": "2" * 64, "size_bytes": 1}
        ]
        report = local_gate.build_public_report(
            contract,
            candidate,
            challenge,
            completion,
            snapshot,
            snapshot,
            snapshot,
            snapshot,
            snapshot,
            output_entries,
        )

        self.assertEqual(
            gate._validate_local_report(
                report,
                contract,
                candidate,
                local_gate,
            ),
            report,
        )
        self.assertEqual(
            report["source_archive_size_bytes"],
            self.fixture.computational_source["archive_size_bytes"],
        )

    def test_release_lock_must_be_production_accepted(self) -> None:
        self.fixture.rewrite_acceptance(
            lambda value: value.__setitem__("production_accepted", False)
        )
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "production_accepted is not true"
        ):
            self.verify()

    def test_pending_component_contract_is_rejected(self) -> None:
        self.fixture.rewrite_host_contract(
            lambda value: value["artifact_sets"][0].__setitem__(
                "production_accepted", False
            )
        )
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "exactly one production-accepted"
        ):
            self.verify()

    def test_duplicate_acceptance_key_is_rejected(self) -> None:
        path = self.fixture.root / gate.ACCEPTANCE_PATH
        text = path.read_text(encoding="utf-8")
        text = text.replace(
            '"production_accepted": true,',
            '"production_accepted": true,\n  "production_accepted": true,',
            1,
        )
        path.write_text(text, encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(gate.ReleaseAcceptanceError, "duplicate JSON key"):
            self.verify()

    def test_extra_freeze_member_is_rejected(self) -> None:
        spec = gate.FREEZE_SPECS["numerical"]
        root = self.fixture.root / Path(*spec["root"].split("/"))
        (root / "unlocked.bin").write_bytes(b"not accepted\n")
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "(?:freeze file set changed|manifest does not describe the exact no-Git)",
        ):
            self.verify()

    def test_repository_manifest_must_bind_acceptance_bytes(self) -> None:
        manifest = self.fixture.root / "MANIFEST.sha256"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace(
            digest((self.fixture.root / gate.ACCEPTANCE_PATH).read_bytes()),
            "0" * 64,
            1,
        )
        manifest.write_text(text, encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "(?:manifest hash differs|does not bind release file)",
        ):
            self.verify()

    def test_posterior_lock_must_match_freeze_bytes(self) -> None:
        self.fixture.rewrite_acceptance(
            lambda value: value["posterior_artifacts"].__setitem__(
                "corrected_constant_propagation", "0" * 64
            )
        )
        with self.assertRaisesRegex(gate.ReleaseAcceptanceError, "posterior hash"):
            self.verify()

    def test_all_signed_reports_must_share_computational_source(self) -> None:
        self.fixture.rewrite_age_source_commit("0" * 40)
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "does not bind the release source lock"
        ):
            self.verify()

    def test_local_report_archive_size_must_match_source_lock(self) -> None:
        report_path = (
            self.fixture.root
            / "provenance"
            / self.fixture.report_names["local"]
        )
        report = read_json(report_path)
        report["source_archive_size_bytes"] = (
            self.fixture.computational_source["archive_size_bytes"] + 1
        )
        report.pop("report_id")
        report["report_id"] = digest(gate.canonical_json_bytes(report))
        report_path.write_bytes(gate.canonical_json_bytes(report))

        contract_path = self.fixture.root / Path(
            *gate.CONTRACT_PATHS["local"].split("/")
        )
        contract = read_json(contract_path)
        contract["candidates"][0]["accepted_report"] = {
            "report_id": report["report_id"],
            "sha256": digest(report_path.read_bytes()),
            "size_bytes": report_path.stat().st_size,
        }
        self.fixture._write_json(gate.CONTRACT_PATHS["local"], contract)

        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "differs from its source lock"
        ):
            gate.verify_local_report_contract_binding(
                self.fixture.root,
                report_path,
                local_verifier=FakeLocal,
            )

    def test_end_to_end_local_report_archive_size_must_match_source(self) -> None:
        report_path = (
            self.fixture.root
            / "provenance"
            / self.fixture.report_names["local"]
        )
        report = read_json(report_path)
        report["source_archive_size_bytes"] = (
            self.fixture.computational_source["archive_size_bytes"] + 1
        )
        report.pop("report_id")
        report["report_id"] = digest(gate.canonical_json_bytes(report))
        report_path.write_bytes(gate.canonical_json_bytes(report))

        contract_path = self.fixture.root / Path(
            *gate.CONTRACT_PATHS["local"].split("/")
        )
        contract = read_json(contract_path)
        contract["candidates"][0]["accepted_report"] = {
            "report_id": report["report_id"],
            "sha256": digest(report_path.read_bytes()),
            "size_bytes": report_path.stat().st_size,
        }
        self.fixture._write_json(gate.CONTRACT_PATHS["local"], contract)
        self.fixture.report_ids["local"] = report["report_id"]
        self.fixture._write_freezes()
        self.fixture._write_acceptance()

        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "local public report does not bind the release source",
        ):
            self.verify()

    def test_freeze_local_archive_size_binding_is_exact(self) -> None:
        spec = gate.FREEZE_SPECS["numerical"]
        freeze_root = self.fixture.root / Path(*spec["root"].split("/"))
        freeze = read_json(freeze_root / spec["json"])
        freeze["artifact_roots"]["signed_local_production_run"][
            "source_archive_size_bytes"
        ] += 1
        self.fixture._write_freeze_set("numerical", freeze)
        self.fixture._write_acceptance()

        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "local-run source_archive_size_bytes",
        ):
            self.verify()

    def test_computational_source_is_separate_from_release_lineage(self) -> None:
        evidence = self.verify()
        self.assertNotEqual(
            evidence["computational_source"]["commit"],
            evidence["release_source"]["lineage_commit"],
        )

    def test_results_archive_lock_is_exact_and_separate(self) -> None:
        evidence = self.verify()
        self.assertEqual(
            evidence["results_archive"]["filename"], gate.RESULTS_ARCHIVE_NAME
        )
        self.fixture.rewrite_acceptance(
            lambda value: value["results_archive"].__setitem__(
                "filename", "unreviewed-results.zip"
            )
        )
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "results archive filename"
        ):
            self.verify()

    def test_results_archive_and_sidecar_are_required_actual_files(self) -> None:
        archive = self.fixture.root / "dist" / gate.RESULTS_ARCHIVE_NAME
        sidecar = self.fixture.root / "dist" / gate.RESULTS_CHECKSUM_NAME
        archive.unlink()
        with self.assertRaisesRegex(gate.ReleaseAcceptanceError, "results ZIP archive"):
            self.verify()
        self.fixture.cleanup()
        self.fixture = ReleaseFixture()
        sidecar = self.fixture.root / "dist" / gate.RESULTS_CHECKSUM_NAME
        sidecar.write_text("0" * 64 + f"  {gate.RESULTS_ARCHIVE_NAME}\n", encoding="ascii")
        with self.assertRaisesRegex(gate.ReleaseAcceptanceError, "sidecar differs"):
            self.verify()

    def test_recovery_disclosure_is_exact_and_not_self_asserted(self) -> None:
        archive_path = self.fixture.root / "dist" / gate.RESULTS_ARCHIVE_NAME
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = {
                info.filename.split("/", 1)[1]: archive.read(info)
                for info in archive.infolist()
            }
        observed = {
            relative: (digest(data), len(data)) for relative, data in members.items()
        }
        report = gate.load_json_bytes(
            members[gate.PUBLIC_RESULTS_REPORT_NAME], "fixture public report"
        )
        report["production_design"]["mcmc_recovery"] = {
            "mcmc_reused": True,
            "aggregates_and_downstream_recomputed": True,
        }
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "recovery MCMC disclosure"
        ):
            gate._validate_public_results_report(
                gate.canonical_json_bytes(report),
                observed,
                self.fixture.computational_source,
            )

    def test_complete_recovery_disclosure_is_accepted_and_binds_current_source(self) -> None:
        archive_path = self.fixture.root / "dist" / gate.RESULTS_ARCHIVE_NAME
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = {
                info.filename.split("/", 1)[1]: archive.read(info)
                for info in archive.infolist()
            }
        observed = {
            relative: (digest(data), len(data)) for relative, data in members.items()
        }
        report = gate.load_json_bytes(
            members[gate.PUBLIC_RESULTS_REPORT_NAME], "fixture public report"
        )
        current = self.fixture.computational_source
        hash_value = "1" * 64
        report["production_design"]["mcmc_recovery"] = {
            "mcmc_reused": True,
            "fresh_preflight_runtime_and_pilots_recomputed": True,
            "aggregates_and_downstream_recomputed": True,
            "donor_completion_attestation_present_in_qualified_evidence_set": False,
            "donor_run_id": "2" * 64,
            "donor_source_commit": "3" * 40,
            "donor_source_tree": "4" * 40,
            "donor_source_archive_sha256": hash_value,
            "donor_source_archive_size_bytes": 100,
            "donor_source_file_set_sha256": hash_value,
            "donor_source_file_count": 183,
            "donor_attestation_contract_sha256": hash_value,
            "donor_attestation_contract_size_bytes": 100,
            "donor_command_plan_sha256": hash_value,
            "donor_numerical_runtime_sha256": hash_value,
            "donor_start_challenge_sha256": hash_value,
            "donor_start_signature_sha256": hash_value,
            "recovery_contract_sha256": hash_value,
            "recovery_contract_size_bytes": 100,
            "mcmc_policy_sha256": hash_value,
            "recovery_source_commit": current["commit"],
            "recovery_source_tree": current["tree"],
            "source_transition_report_id": "5" * 64,
            "source_transition_report_sha256": hash_value,
            "qualification_report_id": "6" * 64,
            "qualification_report_sha256": hash_value,
            "reused_realizations": 1_200,
            "imported_work_file_count": 384,
            "imported_work_size_bytes": 3_498_332_085,
            "imported_work_tree_sha256": hash_value,
            "imported_raw_file_count": 1_296,
            "imported_raw_size_bytes": 10_002_742_894,
            "imported_raw_tree_sha256": hash_value,
        }
        gate._validate_public_results_report(
            gate.canonical_json_bytes(report), observed, current
        )
        report["production_design"]["mcmc_recovery"]["recovery_source_tree"] = "7" * 40
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "does not bind the release source"
        ):
            gate._validate_public_results_report(
                gate.canonical_json_bytes(report), observed, current
            )

    def test_public_recovery_evidence_is_fully_bound_and_keeps_88_outputs(self) -> None:
        self.fixture.enable_recovery()
        evidence = self.verify()
        self.assertEqual(len(gate._expected_results_paths()), 88)
        self.assertEqual(
            evidence["mcmc_recovery_evidence"],
            {
                "status": "PASS",
                "mcmc_reused": True,
                "contract_sha256": self.fixture.recovery_disclosure[
                    "recovery_contract_sha256"
                ],
                "source_transition_sha256": self.fixture.recovery_disclosure[
                    "source_transition_report_sha256"
                ],
                "qualification_sha256": self.fixture.recovery_disclosure[
                    "qualification_report_sha256"
                ],
            },
        )

    def test_results_assets_are_rechecked_after_recovery_verification(self) -> None:
        cases = (
            (gate.RESULTS_ARCHIVE_NAME, "results ZIP archive"),
            (gate.RESULTS_CHECKSUM_NAME, "results SHA-256 sidecar"),
        )
        for case_index, (filename, label) in enumerate(cases):
            with self.subTest(filename=filename):
                if case_index:
                    self.fixture.cleanup()
                    self.fixture = ReleaseFixture()
                self.fixture.enable_recovery()
                target = self.fixture.root / "dist" / filename
                original = gate._verify_public_recovery_evidence

                def remove_result_asset(*args: object, **kwargs: object):
                    target.unlink()
                    return original(*args, **kwargs)

                with mock.patch.object(
                    gate,
                    "_verify_public_recovery_evidence",
                    side_effect=remove_result_asset,
                ), self.assertRaisesRegex(
                    gate.ReleaseAcceptanceError, f"cannot recheck {label}"
                ):
                    self.verify()

    def test_public_recovery_contract_rejects_noncanonical_bytes(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["contract"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        value = read_json(path)
        path.write_bytes(gate.canonical_json_bytes(value))
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(gate.ReleaseAcceptanceError, "not canonical JSON"):
            self.verify()

    def test_public_recovery_contract_rejects_wrong_qualified_donor(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["contract"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        value = read_json(path)
        value["donor"]["command_plan"]["sha256"] = "f" * 64
        self.fixture._write_recovery_json(relative, value)
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "differs from the exact qualified A7 evidence"
        ):
            self.verify()

    def test_public_recovery_contract_hash_must_match_signed_report(self) -> None:
        self.fixture.enable_recovery()
        self.fixture.recovery_disclosure["recovery_contract_sha256"] = "f" * 64
        self.fixture._prepare_results_assets()
        self.fixture._write_reports_and_contracts()
        self.fixture._write_freezes()
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "does not bind signed field recovery_contract_sha256",
        ):
            self.verify()

    def test_public_recovery_rejects_coherently_rebound_shard_manifest_lock(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["contract"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        contract = read_json(path)
        contract["variants"][0]["shards"][0]["work_manifest"]["sha256"] = "f" * 64
        contract_data = gate._recovery_canonical_json_bytes(contract)
        path.write_bytes(contract_data)
        self.fixture.recovery_disclosure["recovery_contract_sha256"] = digest(
            contract_data
        )
        self.fixture.recovery_disclosure["recovery_contract_size_bytes"] = len(
            contract_data
        )
        self.fixture._prepare_results_assets()
        self.fixture._write_reports_and_contracts()
        self.fixture._write_freezes()
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "shard-manifest locks differ from the exact A7 donor set",
        ):
            self.verify()

    def test_public_recovery_report_rejects_wrong_mcmc_policy_hash(self) -> None:
        self.fixture.enable_recovery()
        self.fixture.recovery_disclosure["mcmc_policy_sha256"] = "f" * 64
        self.fixture._prepare_results_assets()
        self.fixture._write_reports_and_contracts()
        self.fixture._write_freezes()
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "does not bind signed field mcmc_policy_sha256",
        ):
            self.verify()

    def test_public_recovery_contract_rejects_all_split_tree_policy_mutations(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["contract"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        contract = read_json(path)
        mutations = {
            "mcmc_policy_sha256": "f" * 64,
            "work_size_bytes": gate.RECOVERY_WORK_SIZE_BYTES + 1,
            "raw_size_bytes": gate.RECOVERY_RAW_SIZE_BYTES + 1,
            "work_tree_sha256": "f" * 64,
            "raw_tree_sha256": "f" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(contract)
                changed["policy"][field] = replacement
                with self.assertRaisesRegex(
                    gate.ReleaseAcceptanceError,
                    "policy differs from the qualified donor",
                ):
                    gate._validate_public_recovery_contract(changed)

    def test_public_recovery_report_rejects_wrong_imported_tree_hash(self) -> None:
        self.fixture.enable_recovery()
        self.fixture.recovery_disclosure["imported_work_tree_sha256"] = "f" * 64
        self.fixture._prepare_results_assets()
        self.fixture._write_reports_and_contracts()
        self.fixture._write_freezes()
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "does not bind signed field imported_work_tree_sha256",
        ):
            self.verify()

    def test_public_recovery_transition_requires_exact_sorted_path_set(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["source_transition"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        value = read_json(path)
        value["protected_paths"][0], value["protected_paths"][1] = (
            value["protected_paths"][1],
            value["protected_paths"][0],
        )
        body = dict(value)
        body.pop("report_id")
        value["report_id"] = digest(gate._recovery_canonical_json_bytes(body))
        self.fixture._write_recovery_json(relative, value)
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "protected source changed across A7 to A8"
        ):
            self.verify()

    def test_public_recovery_transition_requires_exact_a7_source_record_hash(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["source_transition"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        value = read_json(path)
        value["protected_paths"][0]["from_sha256"] = "f" * 64
        value["protected_paths"][0]["to_sha256"] = "f" * 64
        body = dict(value)
        body.pop("report_id")
        value["report_id"] = digest(gate._recovery_canonical_json_bytes(body))
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "differ from the exact A7/A8 set"
        ):
            gate._validate_public_source_transition(
                value,
                donor=gate.RECOVERY_DONOR,
                source=self.fixture.computational_source,
            )

    def test_public_recovery_git_lineage_requires_exact_a8_to_a7_parent(self) -> None:
        (self.fixture.root / ".git").mkdir()
        source = self.fixture.computational_source
        donor = gate.RECOVERY_DONOR

        def git_result(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
            command = arguments[3:]
            if command == ["rev-list", "--parents", "-n", "1", source["commit"]]:
                output = f"{source['commit']} {donor['source_commit']}\n".encode("ascii")
            elif command == ["rev-parse", f"{source['commit']}^{{tree}}"]:
                output = f"{source['tree']}\n".encode("ascii")
            elif command == ["rev-parse", f"{donor['source_commit']}^{{tree}}"]:
                output = f"{donor['source_tree']}\n".encode("ascii")
            else:
                self.fail(f"unexpected Git command: {command}")
            return subprocess.CompletedProcess(arguments, 0, output, b"")

        with mock.patch.object(gate.shutil, "which", return_value="git"), mock.patch.object(
            gate.subprocess,
            "run",
            side_effect=lambda arguments, **_kwargs: git_result(arguments),
        ):
            gate._verify_recovery_git_lineage_if_available(
                self.fixture.root, source, donor
            )

        def wrong_parent(arguments: list[str], **_kwargs: object):
            result = git_result(arguments)
            if arguments[3:5] == ["rev-list", "--parents"]:
                result.stdout = f"{source['commit']} {'f' * 40}\n".encode("ascii")
            return result

        with mock.patch.object(gate.shutil, "which", return_value="git"), mock.patch.object(
            gate.subprocess, "run", side_effect=wrong_parent
        ), self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "exact sole child of donor A7"
        ):
            gate._verify_recovery_git_lineage_if_available(
                self.fixture.root, source, donor
            )

    def test_public_recovery_qualification_rejects_false_transition(self) -> None:
        self.fixture.enable_recovery()
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["qualification"]
        path = self.fixture.root / Path(*PurePosixPath(relative).parts)
        value = read_json(path)
        value["source_transition_sha256"] = "f" * 64
        body = dict(value)
        body.pop("report_id")
        value["report_id"] = digest(gate._recovery_canonical_json_bytes(body))
        self.fixture._write_recovery_json(relative, value)
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "qualification decision changed"
        ):
            self.verify()

    def test_full_run_rejects_stale_recovery_evidence(self) -> None:
        relative = gate.RECOVERY_PUBLIC_EVIDENCE_PATHS["qualification"]
        self.fixture._write_json(relative, {"stale": True}, canonical=True)
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "unexpected MCMC recovery evidence"
        ):
            self.verify()

    def test_internally_rebased_zip_cannot_escape_signed_local_output(self) -> None:
        archive_path = self.fixture.root / "dist" / gate.RESULTS_ARCHIVE_NAME
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = {info.filename.split("/", 1)[1]: archive.read(info) for info in archive.infolist()}
        payload = next(
            relative
            for relative in gate._expected_results_paths()
            if relative
            not in {gate.PUBLIC_RESULTS_MANIFEST_NAME, gate.PUBLIC_RESULTS_REPORT_NAME}
        )
        members[payload] = b"coherent but unattested replacement\n"
        report = gate.load_json_bytes(
            members[gate.PUBLIC_RESULTS_REPORT_NAME], "fixture public report"
        )
        for item in report["public_files"]:
            if item["path"] == payload:
                item["sha256"] = digest(members[payload])
                item["size_bytes"] = len(members[payload])
        members[gate.PUBLIC_RESULTS_REPORT_NAME] = gate.canonical_json_bytes(report)
        members[gate.PUBLIC_RESULTS_MANIFEST_NAME] = "".join(
            f"{digest(members[relative])}  {relative}\n"
            for relative in sorted(
                set(gate._expected_results_paths())
                - {gate.PUBLIC_RESULTS_MANIFEST_NAME}
            )
        ).encode("utf-8")
        archive_path.unlink()
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for relative in gate._expected_results_paths():
                info = zipfile.ZipInfo(
                    f"{gate.RESULTS_ARCHIVE_PREFIX}/{relative}",
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, members[relative])
        archive_sha = digest(archive_path.read_bytes())
        self.fixture.result_lock.update(
            {
                "sha256": archive_sha,
                "size_bytes": archive_path.stat().st_size,
                "source_manifest_sha256": digest(
                    members[gate.PUBLIC_RESULTS_MANIFEST_NAME]
                ),
            }
        )
        (self.fixture.root / "dist" / gate.RESULTS_CHECKSUM_NAME).write_text(
            f"{archive_sha}  {gate.RESULTS_ARCHIVE_NAME}\n",
            encoding="ascii",
            newline="\n",
        )
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "(?:byte total|file-set hash) differs"
        ):
            self.verify()

    def test_payload_manifest_rejects_added_descendant_file(self) -> None:
        rogue = self.fixture.root / "research" / "unbound-scientific-result.txt"
        rogue.parent.mkdir(parents=True, exist_ok=True)
        rogue.write_bytes(b"unbound\n")
        manifest = self.fixture.root / "MANIFEST.sha256"
        entries = gate._parse_repository_manifest(
            gate.read_snapshot(
                self.fixture.root, "MANIFEST.sha256", "fixture manifest"
            )
        )
        entries[rogue.relative_to(self.fixture.root).as_posix()] = digest(
            rogue.read_bytes()
        )
        manifest.write_text(
            "".join(
                f"{entries[relative]}  {relative}\n" for relative in sorted(entries)
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "payload manifest differs"
        ):
            self.verify()

    def test_manifest_hashes_every_non_gate_payload_file(self) -> None:
        (self.fixture.root / "README.md").write_bytes(b"modified after lock\n")
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "manifest hash differs for README.md"
        ):
            self.verify()

    def test_no_git_projection_rejects_coherently_rebased_code_payload(self) -> None:
        acceptance = self.fixture._acceptance_document()
        locked_projection = acceptance["release_source"][
            "computational_projection_manifest_sha256"
        ]
        verifier = (
            self.fixture.root / "scripts" / "verify_v404_release_acceptance.py"
        )
        verifier.write_bytes(b"coherently rebased but post-computation code\n")
        acceptance["release_source"]["acceptance_verifier_sha256"] = digest(
            verifier.read_bytes()
        )
        acceptance["release_source"]["payload_manifest_sha256"] = (
            self.fixture.payload_manifest_sha256()
        )
        acceptance["release_source"]["public_payload_manifest_sha256"] = (
            self.fixture.payload_manifest_sha256()
        )
        acceptance["release_source"][
            "computational_projection_manifest_sha256"
        ] = locked_projection
        body = dict(acceptance)
        body.pop("acceptance_id")
        acceptance["acceptance_id"] = "sha256:" + digest(
            gate.canonical_json_bytes(body)
        )
        self.fixture._write_acceptance(acceptance)
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "computational projection differs"
        ):
            self.verify()

    def test_no_git_coherent_public_rebase_fails_external_source_anchor(self) -> None:
        with self.fixture.trusted_source_anchor() as (archive, checksum):
            self.fixture.verifier_bytes = (
                b"coherently rebased verifier and computational source payload\n"
            )
            (
                self.fixture.root
                / "scripts"
                / "verify_v404_release_acceptance.py"
            ).write_bytes(self.fixture.verifier_bytes)
            # Recompute both public locks, the projection, acceptance_id, and
            # repository MANIFEST exactly as the reproduced attacker did.
            self.fixture._write_acceptance()
            with self.assertRaisesRegex(
                gate.ReleaseAcceptanceError,
                "trusted source ZIP (?:bytes differ|inventory differs)",
            ):
                gate.verify_release_acceptance(
                    self.fixture.root,
                    verifiers=self.fixture.verifiers,
                    trusted_source_archive=archive,
                    trusted_source_checksum=checksum,
                )

    def test_headline_q50_is_bound_to_signed_propagation_output(self) -> None:
        numerical_spec = gate.FREEZE_SPECS["numerical"]
        sensitivity_spec = gate.FREEZE_SPECS["sensitivity"]
        numerical_path = (
            self.fixture.root
            / numerical_spec["root"]
            / numerical_spec["json"]
        )
        sensitivity_path = (
            self.fixture.root
            / sensitivity_spec["root"]
            / sensitivity_spec["json"]
        )
        numerical = read_json(numerical_path)
        sensitivity = read_json(sensitivity_path)
        for branch in ("constant", "zero"):
            numerical["galactic_results"]["canonical"][branch]["Lambda_EE"][
                "q50"
            ] = 999_999_999.0
            sensitivity["canonical_posterior_q50"][
                f"{branch}_Lambda_EE"
            ] = 999_999_999.0
        self.fixture._write_json(
            f"{numerical_spec['root']}/{numerical_spec['json']}", numerical
        )
        self.fixture._write_json(
            f"{sensitivity_spec['root']}/{sensitivity_spec['json']}", sensitivity
        )
        for spec in (numerical_spec, sensitivity_spec):
            freeze_root = self.fixture.root / spec["root"]
            (freeze_root / spec["manifest"]).write_text(
                "".join(
                    f"{digest((freeze_root / name).read_bytes())}  {name}\n"
                    for name in spec["targets"]
                ),
                encoding="utf-8",
                newline="\n",
            )
        self.fixture._write_acceptance()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "headline q50 versus signed local production output",
        ):
            self.verify()

    def test_signed_summary_q50_must_equal_rederived_draw_median(self) -> None:
        archive_path = self.fixture.root / "dist" / gate.RESULTS_ARCHIVE_NAME
        embedded: dict[str, bytes] = {}
        with zipfile.ZipFile(archive_path, "r") as archive:
            for relative in (
                *gate.HEADLINE_SUMMARY_PATHS.values(),
                *gate.HEADLINE_DRAW_PATHS.values(),
            ):
                embedded[relative] = archive.read(
                    f"{gate.RESULTS_ARCHIVE_PREFIX}/{relative}"
                )
        constant_path = gate.HEADLINE_SUMMARY_PATHS["constant"]
        constant = gate.load_json_bytes(
            embedded[constant_path], "fixture constant propagation summary"
        )
        constant["posterior_quantiles"]["Lambda_EE"]["q50"] = 999_999_999.0
        embedded[constant_path] = gate.canonical_json_bytes(constant)
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "differs from the rederived accepted draws"
        ):
            gate._signed_headline_q50(embedded, self.fixture.posterior)

    def test_legacy_repository_numpy_pyc_is_rejected_before_import(self) -> None:
        marker = self.fixture.root / "MALICIOUS_IMPORT_MARKER"
        source = self.fixture.root / "malicious_numpy_source.py"
        source.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
            "raise RuntimeError('malicious numpy bytecode executed')\n",
            encoding="utf-8",
        )
        legacy_cache = self.fixture.root / "scripts" / "numpy.pyc"
        py_compile.compile(str(source), cfile=str(legacy_cache), doraise=True)
        source.unlink()
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "import boundary contains bytecode"
        ):
            self.verify()
        self.assertFalse(marker.exists())

    def test_change_record_allowlist_is_exact(self) -> None:
        acceptance = self.fixture._acceptance_document()
        allowed = gate.post_computation_allowed_paths(acceptance)
        self.assertIn("provenance/RELEASE_4_0_4_CHANGE_RECORD.json", allowed)
        self.assertTrue(
            gate.is_post_computation_allowed_path(
                "provenance/RELEASE_4_0_4_CHANGE_RECORD.json", allowed
            )
        )
        self.assertFalse(
            gate.is_post_computation_allowed_path(
                "provenance/ARBITRARY_RELEASE_RECORD.json", allowed
            )
        )

    def test_no_git_uses_public_manifest_locks_not_full_git_locks(self) -> None:
        self.fixture.rewrite_acceptance(
            lambda value: value["release_source"].__setitem__(
                "payload_manifest_sha256", "0" * 64
            )
        )
        self.assertEqual(self.verify()["status"], "PASS")
        self.fixture.rewrite_acceptance(
            lambda value: value["release_source"].__setitem__(
                "public_payload_manifest_sha256", "0" * 64
            )
        )
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "public no-Git payload manifest differs"
        ):
            self.verify()

    @unittest.skipUnless(shutil.which("git"), "Git is required for lineage test")
    def test_git_lineage_requires_one_exact_finalization_child(self) -> None:
        git, _source_commit, _lineage_commit = self.prepare_git_release_lineage()
        self.assertEqual(self.verify()["status"], "PASS")
        rogue = self.fixture.root / "research" / "descendant-change.txt"
        rogue.parent.mkdir(parents=True, exist_ok=True)
        rogue.write_bytes(b"not bound by the finalization commit\n")
        git("add", "--", rogue.relative_to(self.fixture.root).as_posix())
        git("commit", "-q", "-m", "rogue descendant")
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError, "sole direct parent"
        ):
            self.verify()

    @unittest.skipUnless(shutil.which("git"), "Git is required for lineage test")
    def test_git_lineage_rejects_post_computation_code_drift(self) -> None:
        self.prepare_git_release_lineage(code_drift=True)
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "post-computation release diff changes computational code",
        ):
            self.verify()

    @unittest.skipUnless(shutil.which("git"), "Git is required for lineage test")
    def test_git_lineage_rejects_nonancestor_computational_source(self) -> None:
        self.prepare_git_release_lineage(unrelated_source=True)
        with self.assertRaisesRegex(
            gate.ReleaseAcceptanceError,
            "computational source is not an ancestor",
        ):
            self.verify()

    def test_direct_package_builder_checks_gate_before_license_or_write(self) -> None:
        rejection = package.verify_v404_release_acceptance.ReleaseAcceptanceError(
            "pending acceptance"
        )
        with mock.patch.object(
            package, "run_full_verification"
        ) as full_check, mock.patch.object(
            package.verify_v404_release_acceptance,
            "verify_release_acceptance",
            side_effect=rejection,
        ) as release_check, mock.patch.object(
            package.verify_license_policy, "verify"
        ) as license_check:
            with self.assertRaisesRegex(SystemExit, "PUBLIC PACKAGE RELEASE GATE FAIL"):
                package.main()
        full_check.assert_called_once_with()
        release_check.assert_called_once_with(package.ROOT)
        license_check.assert_not_called()

    def test_direct_source_packager_requires_exact_project_version(self) -> None:
        package.validate_project_version("4.0.4")
        with self.assertRaisesRegex(SystemExit, "project version differs"):
            package.validate_project_version("4.0.5")

    def test_direct_source_packager_rechecks_captured_file_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-source-snapshot-") as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_bytes(b"first\n")
            with mock.patch.object(package, "ROOT", root):
                data, snapshot = package.stable_source_read(
                    PurePosixPath("source.txt")
                )
                self.assertEqual(data, b"first\n")
                source.unlink()
                source.write_bytes(b"other\n")
                # Some overlay filesystems can immediately reuse the same
                # inode and coarse timestamps after unlink+create.  Force the
                # identity collision: the content hash must still reject the
                # replacement deterministically.
                with mock.patch.object(
                    package, "file_identity", return_value=snapshot.identity
                ):
                    with self.assertRaisesRegex(SystemExit, "changed after capture"):
                        package.recheck_sources([snapshot])

    def test_public_output_refuses_predestined_symlink_and_preserves_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-public-output-") as temporary:
            root = Path(temporary)
            output = root / "dist"
            output.mkdir()
            victim = root / "victim.txt"
            victim.write_bytes(b"victim-must-survive\n")
            link = output / "release.zip"
            try:
                link.symlink_to(victim)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            directory = package.snapshot_plain_directory(output, "test output")
            with self.assertRaisesRegex(SystemExit, "Refusing to replace"):
                package.write_new_bound_file(
                    directory, "release.zip", b"attacker bytes", "test archive"
                )
            self.assertEqual(victim.read_bytes(), b"victim-must-survive\n")

    def test_public_output_rejects_replaced_parent_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-public-parent-") as temporary:
            root = Path(temporary)
            output = root / "dist"
            output.mkdir()
            directory = package.snapshot_plain_directory(output, "test output")
            moved = root / "original-dist"
            output.rename(moved)
            output.mkdir()
            with self.assertRaisesRegex(SystemExit, "ancestor changed"):
                package.write_new_bound_file(
                    directory, "release.zip", b"blocked", "test archive"
                )
            self.assertFalse((output / "release.zip").exists())

    def test_public_source_zip_uses_stored_members(self) -> None:
        files = [
            (
                {
                    "path": "README.md",
                    "license": "MIT",
                    "origin": "fixture",
                },
                b"fixture\n",
            )
        ]
        archive_bytes = package.build_zip(files)
        package.verify_zip(archive_bytes, files)
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            self.assertEqual(
                archive.getinfo("README.md").compress_type, zipfile.ZIP_STORED
            )

    def test_public_no_git_locks_are_measured_from_filtered_bytes(self) -> None:
        acceptance = self.fixture._acceptance_document()
        acceptance_bytes = gate.canonical_json_bytes(acceptance)
        code_bytes = b"public computational code\n"
        files = [
            ({"path": gate.ACCEPTANCE_PATH}, acceptance_bytes),
            ({"path": "scripts/public_model.py"}, code_bytes),
            ({"path": "MANIFEST.sha256"}, b""),
        ]
        with mock.patch.object(
            package.verify_license_policy, "verify", return_value=[]
        ), mock.patch.object(
            package, "public_sources", return_value=(files, [])
        ):
            measured = package.measure_public_release_locks()
        code_sha = digest(code_bytes)
        expected = digest(f"{code_sha}  scripts/public_model.py\n".encode("utf-8"))
        self.assertEqual(measured["public_payload_manifest_sha256"], expected)
        self.assertEqual(
            measured["public_computational_projection_manifest_sha256"], expected
        )

    def test_source_acceptance_derives_exact_results_api_digests(self) -> None:
        with self.fixture.trusted_source_anchor() as (archive, _checksum):
            evidence = roundtrip.accepted_results_api_evidence(
                archive.read_bytes()
            )
        result_sha = self.fixture.result_lock["sha256"]
        result_size = self.fixture.result_lock["size_bytes"]
        checksum_bytes = (
            f"{result_sha}  {roundtrip.RESULTS_ARCHIVE_NAME}\n"
        ).encode("ascii")
        self.assertEqual(
            evidence[roundtrip.RESULTS_ARCHIVE_NAME],
            (result_size, "sha256:" + result_sha),
        )
        self.assertEqual(
            evidence[roundtrip.RESULTS_CHECKSUM_NAME],
            (
                len(checksum_bytes),
                "sha256:" + hashlib.sha256(checksum_bytes).hexdigest(),
            ),
        )

    def test_release_state_uses_numeric_rest_asset_id_and_api_digest(self) -> None:
        asset_id = 534_972_290
        document = {
            "tagName": roundtrip.RELEASE_TAG,
            "isDraft": False,
            "databaseId": 378_921_698,
            "targetCommitish": "main",
            "assets": [
                {
                    "id": "RA_kwDOUBoyN84f4weC",
                    "apiUrl": (
                        "https://api.github.com/repos/"
                        f"{roundtrip.REPOSITORY}/releases/assets/{asset_id}"
                    ),
                    "name": roundtrip.RESULTS_ARCHIVE_NAME,
                    "size": 123,
                    "state": "uploaded",
                    "digest": "sha256:" + "a" * 64,
                }
            ],
        }
        completed = subprocess.CompletedProcess(
            ["gh"], 0, stdout=gate.canonical_json_bytes(document), stderr=b""
        )
        with mock.patch.object(roundtrip, "run_gh", return_value=completed):
            state = roundtrip.release_asset_state("gh")
        self.assertEqual(state.release_id, document["databaseId"])
        self.assertEqual(
            state.assets[roundtrip.RESULTS_ARCHIVE_NAME],
            roundtrip.ReleaseAsset(asset_id, 123, "sha256:" + "a" * 64),
        )

        forged = copy.deepcopy(document)
        forged["assets"][0]["apiUrl"] = (
            "https://api.github.com/repos/attacker/repository/releases/assets/1"
        )
        completed = subprocess.CompletedProcess(
            ["gh"], 0, stdout=gate.canonical_json_bytes(forged), stderr=b""
        )
        with mock.patch.object(roundtrip, "run_gh", return_value=completed):
            with self.assertRaisesRegex(SystemExit, "exact name/id/size/digest"):
                roundtrip.release_asset_state("gh")

    def test_release_asset_publication_is_no_clobber_and_byte_rechecked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-release-upload-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"deterministic-source-zip\n"
            source.write_bytes(source_bytes)
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            digest = hashlib.sha256(source_bytes).hexdigest()
            checksum_bytes = f"{digest}  {source.name}\n".encode("ascii")
            checksum.write_bytes(checksum_bytes)
            download = root / "download-recheck"
            baseline = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                }
            )
            after_source = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    **baseline.assets,
                    source.name: roundtrip.ReleaseAsset(
                        3, len(source_bytes), "sha256:" + digest
                    ),
                }
            )
            after_both = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    **after_source.assets,
                    checksum.name: roundtrip.ReleaseAsset(
                        4,
                        len(checksum_bytes),
                        "sha256:" + hashlib.sha256(checksum_bytes).hexdigest(),
                    ),
                }
            )
            uploaded_bytes: dict[str, bytes] = {}

            def fake_run(_gh: str, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
                if arguments[:2] == ["release", "upload"]:
                    staged = Path(arguments[3])
                    uploaded_bytes[staged.name] = staged.read_bytes()
                    if staged.name == source.name:
                        source.write_bytes(b"POST-READ-LOCAL-PATH-SWAP\n")
                if arguments[:2] == ["release", "download"]:
                    download.mkdir(exist_ok=True)
                    (download / source.name).write_bytes(source_bytes)
                    (download / checksum.name).write_bytes(checksum_bytes)
                return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip,
                "release_asset_state",
                side_effect=[baseline, after_source, after_both, after_both],
            ), mock.patch.object(
                roundtrip, "run_gh", side_effect=fake_run
            ) as gh_call:
                observed = roundtrip.publish_v404_source_assets(
                    source, checksum, download
                )
            self.assertEqual(observed, digest)
            upload_arguments = gh_call.call_args_list[0].args[1]
            self.assertEqual(upload_arguments[:3], ["release", "upload", "v4.0.4"])
            self.assertNotIn("--clobber", upload_arguments)
            self.assertNotEqual(Path(upload_arguments[3]), source)
            self.assertEqual(uploaded_bytes[source.name], source_bytes)
            self.assertEqual(uploaded_bytes[checksum.name], checksum_bytes)
            self.assertEqual((download / source.name).read_bytes(), source_bytes)
            self.assertEqual((download / checksum.name).read_bytes(), checksum_bytes)

    def test_release_asset_publication_refuses_existing_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-release-overwrite-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source.write_bytes(b"source\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            checksum.write_text(
                f"{digest}  {source.name}\n", encoding="ascii", newline="\n"
            )
            existing = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 1, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 1, "sha256:" + "2" * 64
                    ),
                    source.name: roundtrip.ReleaseAsset(
                        3, source.stat().st_size, "sha256:" + digest
                    ),
                }
            )
            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (1, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (1, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip, "release_asset_state", return_value=existing
            ), mock.patch.object(roundtrip, "run_gh") as gh_call:
                with self.assertRaisesRegex(SystemExit, "Refusing to overwrite"):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            gh_call.assert_not_called()

    def test_release_asset_publication_refuses_stale_baseline_asset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-release-stale-baseline-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"source\n"
            source.write_bytes(source_bytes)
            digest = hashlib.sha256(source_bytes).hexdigest()
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            checksum.write_text(
                f"{digest}  {source.name}\n", encoding="ascii", newline="\n"
            )
            baseline = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                    "stale-debug.txt": roundtrip.ReleaseAsset(
                        9, 5, "sha256:" + "9" * 64
                    ),
                },
            )
            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip, "release_asset_state", return_value=baseline
            ), mock.patch.object(roundtrip, "run_gh") as gh_call:
                with self.assertRaisesRegex(SystemExit, "asset inventory changed"):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            gh_call.assert_not_called()

    def test_successful_upload_then_state_query_failure_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-upload-query-recovery-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"bound-source\n"
            source.write_bytes(source_bytes)
            source_digest = hashlib.sha256(source_bytes).hexdigest()
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            checksum.write_text(
                f"{source_digest}  {source.name}\n", encoding="ascii", newline="\n"
            )
            baseline = roundtrip.ReleaseState(
                404,
                "main",
                {
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                },
            )
            after_source = roundtrip.ReleaseState(
                404,
                "main",
                {
                    **baseline.assets,
                    source.name: roundtrip.ReleaseAsset(
                        3, len(source_bytes), "sha256:" + source_digest
                    ),
                },
            )
            deleted: list[int] = []

            def fake_run(
                _gh: str, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                if arguments[:3] == ["api", "--method", "DELETE"]:
                    deleted.append(int(arguments[3].rsplit("/", 1)[1]))
                return subprocess.CompletedProcess(
                    arguments, 0, stdout=b"", stderr=b""
                )

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip,
                "release_asset_state",
                side_effect=[
                    baseline,
                    SystemExit("simulated immediate state query failure"),
                    after_source,
                    baseline,
                ],
            ), mock.patch.object(roundtrip, "run_gh", side_effect=fake_run):
                with self.assertRaisesRegex(
                    SystemExit, "simulated immediate state query failure"
                ):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            self.assertEqual(deleted, [3])

    def test_ambiguous_upload_exception_and_failed_recovery_query_roll_back(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-upload-exception-recovery-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"bound-source\n"
            source.write_bytes(source_bytes)
            source_digest = hashlib.sha256(source_bytes).hexdigest()
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            checksum.write_text(
                f"{source_digest}  {source.name}\n", encoding="ascii", newline="\n"
            )
            baseline = roundtrip.ReleaseState(
                404,
                "main",
                {
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                },
            )
            after_source = roundtrip.ReleaseState(
                404,
                "main",
                {
                    **baseline.assets,
                    source.name: roundtrip.ReleaseAsset(
                        3, len(source_bytes), "sha256:" + source_digest
                    ),
                },
            )
            deleted: list[int] = []
            upload_calls = 0

            def fake_run(
                _gh: str, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal upload_calls
                if arguments[:2] == ["release", "upload"]:
                    upload_calls += 1
                    raise SystemExit("simulated ambiguous upload response")
                if arguments[:3] == ["api", "--method", "DELETE"]:
                    deleted.append(int(arguments[3].rsplit("/", 1)[1]))
                return subprocess.CompletedProcess(
                    arguments, 0, stdout=b"", stderr=b""
                )

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip,
                "release_asset_state",
                side_effect=[
                    baseline,
                    SystemExit("simulated recovery state query failure"),
                    after_source,
                    baseline,
                ],
            ), mock.patch.object(roundtrip, "run_gh", side_effect=fake_run):
                with self.assertRaisesRegex(
                    SystemExit, "simulated ambiguous upload response"
                ):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            self.assertEqual(upload_calls, 1)
            self.assertEqual(deleted, [3])

    def test_unresolved_recovery_state_never_deletes_and_requires_manual_action(self) -> None:
        baseline = roundtrip.ReleaseState(
            404,
            "main",
            {
                roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                    1, 10, "sha256:" + "1" * 64
                ),
                roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                    2, 20, "sha256:" + "2" * 64
                ),
            },
        )
        with mock.patch.object(
            roundtrip,
            "release_asset_state",
            side_effect=SystemExit("simulated unavailable release state"),
        ) as state_call, mock.patch.object(roundtrip, "run_gh") as gh_call:
            with self.assertRaisesRegex(SystemExit, "manual-recovery-required"):
                roundtrip.recover_attempted_source_uploads(
                    "gh", baseline, {roundtrip.SOURCE_ARCHIVE_NAME}
                )
        self.assertEqual(state_call.call_count, 3)
        gh_call.assert_not_called()

    def test_recovery_never_deletes_unknown_concurrent_asset(self) -> None:
        baseline = roundtrip.ReleaseState(
            404,
            "main",
            {
                roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                    1, 10, "sha256:" + "1" * 64
                ),
                roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                    2, 20, "sha256:" + "2" * 64
                ),
            },
        )
        observed = roundtrip.ReleaseState(
            404,
            "main",
            {
                **baseline.assets,
                roundtrip.SOURCE_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                    3, 30, "sha256:" + "3" * 64
                ),
                "concurrent-unknown.txt": roundtrip.ReleaseAsset(
                    99, 40, "sha256:" + "9" * 64
                ),
            },
        )
        with mock.patch.object(
            roundtrip, "release_asset_state", return_value=observed
        ), mock.patch.object(roundtrip, "run_gh") as gh_call:
            with self.assertRaisesRegex(SystemExit, "manual-recovery-required"):
                roundtrip.recover_attempted_source_uploads(
                    "gh", baseline, {roundtrip.SOURCE_ARCHIVE_NAME}
                )
        gh_call.assert_not_called()

    def test_confirmed_upload_absent_after_bounded_queries_requires_manual_action(
        self,
    ) -> None:
        baseline = roundtrip.ReleaseState(
            404,
            "main",
            {
                roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                    1, 10, "sha256:" + "1" * 64
                ),
                roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                    2, 20, "sha256:" + "2" * 64
                ),
            },
        )
        with mock.patch.object(
            roundtrip, "release_asset_state", return_value=baseline
        ) as state_call, mock.patch.object(roundtrip, "run_gh") as gh_call:
            with self.assertRaisesRegex(SystemExit, "manual-recovery-required"):
                roundtrip.recover_attempted_source_uploads(
                    "gh",
                    baseline,
                    {roundtrip.SOURCE_ARCHIVE_NAME},
                    confirmed_upload_names={roundtrip.SOURCE_ARCHIVE_NAME},
                )
        self.assertEqual(state_call.call_count, 3)
        gh_call.assert_not_called()

    def test_release_asset_api_digest_mismatch_rolls_back_new_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-release-api-mismatch-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"bound-source\n"
            source.write_bytes(source_bytes)
            source_digest = hashlib.sha256(source_bytes).hexdigest()
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            checksum.write_text(
                f"{source_digest}  {source.name}\n", encoding="ascii", newline="\n"
            )
            baseline = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                },
            )
            mismatched = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    **baseline.assets,
                    source.name: roundtrip.ReleaseAsset(
                        31, len(source_bytes), "sha256:" + "f" * 64
                    ),
                },
            )
            deleted: list[int] = []

            def fake_run(
                _gh: str, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                if arguments[:3] == ["api", "--method", "DELETE"]:
                    deleted.append(int(arguments[3].rsplit("/", 1)[1]))
                return subprocess.CompletedProcess(
                    arguments, 0, stdout=b"", stderr=b""
                )

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip,
                "release_asset_state",
                side_effect=[baseline, mismatched, mismatched, baseline],
            ), mock.patch.object(roundtrip, "run_gh", side_effect=fake_run):
                with self.assertRaisesRegex(
                    SystemExit, "API digest/size differs"
                ):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            self.assertEqual(deleted, [31])

    def test_release_publication_requires_exact_event_tag_commit(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/tags/v4.0.5",
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "v4.0.5",
                "GITHUB_SHA": "a" * 40,
            },
            clear=False,
        ), mock.patch.object(roundtrip, "run_gh") as gh_call:
            with self.assertRaisesRegex(SystemExit, "exact v4.0.4 tag ref"):
                roundtrip.exact_event_tag_commit("gh")
        gh_call.assert_not_called()

        completed = subprocess.CompletedProcess(
            ["gh"], 0, stdout=("b" * 40 + "\n").encode("ascii"), stderr=b""
        )
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/tags/v4.0.4",
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "v4.0.4",
                "GITHUB_SHA": "a" * 40,
            },
            clear=False,
        ), mock.patch.object(roundtrip, "run_gh", return_value=completed):
            with self.assertRaisesRegex(SystemExit, "differs from GITHUB_SHA"):
                roundtrip.exact_event_tag_commit("gh")

        with self.assertRaisesRegex(SystemExit, "targetCommitish is not canonical main"):
            roundtrip.require_same_release_target(
                roundtrip.ReleaseState(404, roundtrip.RELEASE_TAG, {}),
                roundtrip.ReleaseState(404, roundtrip.RELEASE_TAG, {}),
                "a" * 40,
            )

    def test_partial_release_upload_rolls_back_only_new_asset_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v404-release-rollback-") as temporary:
            root = Path(temporary)
            source = root / roundtrip.SOURCE_ARCHIVE_NAME
            source_bytes = b"bound-source\n"
            source.write_bytes(source_bytes)
            checksum = root / roundtrip.SOURCE_CHECKSUM_NAME
            source_digest = hashlib.sha256(source_bytes).hexdigest()
            checksum_bytes = f"{source_digest}  {source.name}\n".encode("ascii")
            checksum.write_bytes(checksum_bytes)
            baseline = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    roundtrip.RESULTS_ARCHIVE_NAME: roundtrip.ReleaseAsset(
                        1, 10, "sha256:" + "1" * 64
                    ),
                    roundtrip.RESULTS_CHECKSUM_NAME: roundtrip.ReleaseAsset(
                        2, 20, "sha256:" + "2" * 64
                    ),
                },
            )
            after_source = roundtrip.ReleaseState(
                release_id=404,
                target_commitish="main",
                assets={
                    **baseline.assets,
                    source.name: roundtrip.ReleaseAsset(
                        3, len(source_bytes), "sha256:" + source_digest
                    ),
                },
            )
            deleted: list[int] = []

            def fake_run(_gh: str, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
                if arguments[:2] == ["release", "upload"]:
                    staged = Path(arguments[3])
                    if staged.name == checksum.name:
                        raise SystemExit("simulated second-asset upload failure")
                if arguments[:3] == ["api", "--method", "DELETE"]:
                    deleted.append(int(arguments[3].rsplit("/", 1)[1]))
                return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

            with mock.patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": roundtrip.REPOSITORY,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/tags/v4.0.4",
                    "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF_NAME": "v4.0.4",
                    "GITHUB_SHA": "a" * 40,
                },
                clear=False,
            ), mock.patch.object(
                roundtrip.shutil, "which", return_value="gh"
            ), mock.patch.object(
                roundtrip, "exact_event_tag_commit", return_value="a" * 40
            ), mock.patch.object(
                roundtrip,
                "accepted_results_api_evidence",
                return_value={
                    roundtrip.RESULTS_ARCHIVE_NAME: (10, "sha256:" + "1" * 64),
                    roundtrip.RESULTS_CHECKSUM_NAME: (20, "sha256:" + "2" * 64),
                },
            ), mock.patch.object(
                roundtrip,
                "release_asset_state",
                side_effect=[
                    baseline,
                    after_source,
                    after_source,
                    after_source,
                    after_source,
                    baseline,
                ],
            ), mock.patch.object(roundtrip, "run_gh", side_effect=fake_run):
                with self.assertRaisesRegex(SystemExit, "second-asset upload failure"):
                    roundtrip.publish_v404_source_assets(
                        source, checksum, root / "download"
                    )
            self.assertEqual(deleted, [3])


if __name__ == "__main__":
    unittest.main()
