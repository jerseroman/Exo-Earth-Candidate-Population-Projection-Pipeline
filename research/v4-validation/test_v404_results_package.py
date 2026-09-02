from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
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

SCRIPT = ROOT / "scripts" / "build_v404_results_package.py"
SPEC = importlib.util.spec_from_file_location("build_v404_results_package", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load v4.0.4 results packager")
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)

FIXTURE_SCRIPT = Path(__file__).with_name("test_v404_release_acceptance.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "v404_release_fixture_for_packager", FIXTURE_SCRIPT
)
if FIXTURE_SPEC is None or FIXTURE_SPEC.loader is None:
    raise RuntimeError("cannot load v4.0.4 release fixture")
fixture_module = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixture_module)
ReleaseFixture = fixture_module.ReleaseFixture


class ResultsPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ReleaseFixture()
        self.anchor_context = self.fixture.trusted_source_anchor()
        self.trusted_archive, self.trusted_checksum = self.anchor_context.__enter__()
        self.anchor_environment = mock.patch.dict(
            os.environ,
            {
                package.verify_v404_release_acceptance.TRUSTED_SOURCE_ARCHIVE_ENV: str(
                    self.trusted_archive
                ),
                package.verify_v404_release_acceptance.TRUSTED_SOURCE_CHECKSUM_ENV: str(
                    self.trusted_checksum
                ),
            },
            clear=False,
        )
        self.anchor_environment.start()
        self.work = tempfile.TemporaryDirectory(prefix="v404-results-package-")
        self.work_root = Path(self.work.name)
        self.source = self.work_root / "signed-results"
        self.source.mkdir()
        for relative, data in self.fixture.private_members.items():
            target = self.source / Path(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.signed_manifest = (
            self.work_root / "private-evidence" / "LOCAL_RUN_OUTPUT_SHA256.json"
        )
        self.signed_manifest.parent.mkdir()
        self.signed_manifest.write_bytes(self.fixture.strict_output_manifest)
        self.delivery = self.work_root / "delivery"
        self.delivery.mkdir()

    def tearDown(self) -> None:
        self.work.cleanup()
        self.anchor_environment.stop()
        self.anchor_context.__exit__(None, None, None)
        self.fixture.cleanup()

    def build(self, stem: str = "one") -> tuple[Path, Path, dict[str, object]]:
        directory = self.delivery / stem
        directory.mkdir()
        archive = directory / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        checksum = directory / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        report = package.build(
            self.source,
            archive,
            checksum,
            repository_root=self.fixture.root,
            signed_output_manifest=self.signed_manifest,
            verifiers=self.fixture.verifiers,
        )
        return archive, checksum, report

    def write_archive(
        self, stem: str, members: dict[str, bytes]
    ) -> tuple[dict[str, object], Path, Path]:
        directory = self.delivery / stem
        directory.mkdir()
        archive_path = directory / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        checksum_path = directory / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for relative in sorted(members):
                info = zipfile.ZipInfo(
                    f"{package.ARCHIVE_PREFIX}/{relative}",
                    date_time=package.FIXED_ZIP_TIME,
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (0o100644 << 16)
                archive.writestr(info, members[relative])
        archive_data = archive_path.read_bytes()
        archive_sha = hashlib.sha256(archive_data).hexdigest()
        checksum_path.write_text(
            f"{archive_sha}  {archive_path.name}\n", encoding="ascii", newline="\n"
        )
        lock = {
            "filename": archive_path.name,
            "sha256_sidecar_filename": checksum_path.name,
            "sha256": archive_sha,
            "size_bytes": len(archive_data),
            "source_manifest_sha256": hashlib.sha256(
                members[package.MANIFEST_NAME]
            ).hexdigest(),
        }
        return lock, archive_path, checksum_path

    def verify_archive_directly(
        self, lock: dict[str, object], archive: Path, checksum: Path
    ) -> object:
        return package.verify_v404_release_acceptance._verify_results_archive(
            lock,
            self.fixture._local_report(),
            self.fixture.computational_source,
            self.fixture.posterior,
            archive,
            checksum,
        )

    def test_package_is_deterministic_and_accepted_byte_for_byte(self) -> None:
        first, first_checksum, first_report = self.build("first")
        second, second_checksum, _second_report = self.build("second")
        locked = (
            self.fixture.root
            / "dist"
            / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.read_bytes(), locked.read_bytes())
        self.assertEqual(first_checksum.read_bytes(), second_checksum.read_bytes())
        self.assertEqual(first_report["sha256"], self.fixture.result_lock["sha256"])
        with zipfile.ZipFile(first, "r") as archive:
            for info in archive.infolist():
                self.assertEqual(info.date_time, package.FIXED_ZIP_TIME)
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual((info.external_attr >> 16) & 0o777, 0o644)

    def test_public_projection_is_exact_and_rewrites_every_scoped_control(self) -> None:
        archive_path, _checksum, report = self.build("exact-projection")
        policy = package.verify_v404_release_acceptance._public_results_policy()
        self.assertEqual(report["file_count"], 70)
        self.assertEqual(len(policy.private_paths), 88)
        self.assertEqual(len(policy.excluded_paths), 18)
        self.assertEqual(len(policy.manifest_targets), 5)
        self.assertEqual(len(policy.passthrough_paths), 63)
        with zipfile.ZipFile(archive_path, "r") as archive:
            names = archive.namelist()
            logical = [name.split("/", 1)[1] for name in names]
            self.assertEqual(logical, list(policy.public_paths))
            self.assertTrue(set(policy.excluded_paths).isdisjoint(logical))
            for relative in policy.passthrough_paths:
                self.assertEqual(
                    archive.read(f"{package.ARCHIVE_PREFIX}/{relative}"),
                    self.fixture.private_members[relative],
                )
            for manifest_path, (_private_targets, public_targets) in (
                policy.manifest_targets.items()
            ):
                public_data = archive.read(
                    f"{package.ARCHIVE_PREFIX}/{manifest_path}"
                )
                self.assertNotEqual(
                    public_data, self.fixture.private_members[manifest_path]
                )
                parsed = package.verify_v404_release_acceptance._parse_public_scoped_manifest(
                    public_data, manifest_path
                )
                self.assertEqual(set(parsed), set(public_targets))
            projected_report = package.verify_v404_release_acceptance.load_json_bytes(
                archive.read(
                    f"{package.ARCHIVE_PREFIX}/{package.REPORT_NAME}"
                ),
                "projected fixture report",
            )
            self.assertEqual(
                projected_report["public_projection"]["public_file_count"], 70
            )
            self.assertEqual(
                projected_report["public_projection"]["excluded_file_count"], 18
            )
            root_manifest = package.verify_v404_release_acceptance._parse_public_results_manifest(
                archive.read(f"{package.ARCHIVE_PREFIX}/{package.MANIFEST_NAME}")
            )
            self.assertEqual(
                set(root_manifest), set(policy.public_paths) - {package.MANIFEST_NAME}
            )

    def test_legacy_88_member_results_archive_is_rejected(self) -> None:
        lock, archive, checksum = self.write_archive(
            "legacy-private-archive", self.fixture.private_members
        )
        with self.assertRaisesRegex(
            package.verify_v404_release_acceptance.ReleaseAcceptanceError,
            "member set/order",
        ):
            self.verify_archive_directly(lock, archive, checksum)

    def test_input_case_collision_and_symlink_fail_closed(self) -> None:
        collision = self.source / "Audits" / "case-collision.txt"
        collision.parent.mkdir()
        collision.write_bytes(b"unsigned\n")
        with self.assertRaisesRegex(package.PackageError, "signed manifest"):
            self.build("case-collision")
        collision.unlink()
        collision.parent.rmdir()

        target_relative = package.verify_v404_release_acceptance._public_results_policy().passthrough_paths[0]
        target = self.source / Path(*target_relative.split("/"))
        original = target.read_bytes()
        victim = self.work_root / "symlink-victim.bin"
        victim.write_bytes(original)
        target.unlink()
        try:
            target.symlink_to(victim)
        except OSError as error:
            target.write_bytes(original)
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises(package.PackageError):
            self.build("input-symlink")

    def test_row_identifier_and_chain_headers_fail_even_under_allowed_names(self) -> None:
        policy = package.verify_v404_release_acceptance._public_results_policy()

        def compressed(data: bytes) -> bytes:
            output = io.BytesIO()
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0
            ) as stream:
                stream.write(data)
            return output.getvalue()

        row_members = dict(self.fixture.public_members)
        row_target = package.verify_v404_release_acceptance.HEADLINE_DRAW_PATHS[
            "constant"
        ]
        row_members[row_target] = compressed(
            b"source_row,kepoi_name,kepid_x,Lambda_EE\n1,K00001,1,1\n"
        )
        row_lock, row_archive, row_checksum = self.write_archive(
            "renamed-row-data", row_members
        )
        with self.assertRaisesRegex(
            package.verify_v404_release_acceptance.ReleaseAcceptanceError,
            "row-level DR25 identifier",
        ):
            self.verify_archive_directly(row_lock, row_archive, row_checksum)

        chain_members = dict(self.fixture.public_members)
        chain_target = next(
            path
            for path in policy.retained_derived_paths
            if path.endswith("for_galactic_propagation.csv.gz")
        )
        chain_members[chain_target] = compressed(
            b"production_step,walker,log_probability,F0\n1,0,-1,1\n"
        )
        chain_lock, chain_archive, chain_checksum = self.write_archive(
            "renamed-chain-data", chain_members
        )
        with self.assertRaisesRegex(
            package.verify_v404_release_acceptance.ReleaseAcceptanceError,
            "serialized MCMC trajectory",
        ):
            self.verify_archive_directly(chain_lock, chain_archive, chain_checksum)

    def test_pre_final_measurement_matches_final_accepted_archive(self) -> None:
        report = package.measure_release_lock(
            self.source,
            repository_root=self.fixture.root,
            signed_output_manifest=self.signed_manifest,
            signed_local_report=(
                self.fixture.root
                / "provenance"
                / self.fixture.report_names["local"]
            ),
            local_verifier=fixture_module.FakeLocal,
        )
        self.assertEqual(report["status"], "MEASURED_CANDIDATE_NOT_RELEASE_ACCEPTED")
        for field in (
            "filename",
            "sha256_sidecar_filename",
            "sha256",
            "size_bytes",
            "source_manifest_sha256",
        ):
            self.assertEqual(report[field], self.fixture.result_lock[field])

    def test_self_declared_manifest_cannot_rebase_signed_output(self) -> None:
        payload = (
            self.source
            / "aggregates"
            / "corrected-constant"
            / "posterior_samples_constant.csv"
        )
        payload.write_bytes(b"attacker-controlled replacement\n")
        public_manifest = self.source / package.MANIFEST_NAME
        rows = []
        for path in sorted(
            (
                item
                for item in self.source.rglob("*")
                if item.is_file() and item != public_manifest
            ),
            key=lambda item: item.relative_to(self.source).as_posix(),
        ):
            relative = path.relative_to(self.source).as_posix()
            rows.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n"
            )
        public_manifest.write_text("".join(rows), encoding="utf-8", newline="\n")
        with self.assertRaises(package.PackageError):
            self.build("blocked-rebase")

    def test_shadow_directory_is_not_part_of_exact_signed_tree(self) -> None:
        (self.source / "empty-shadow-directory").mkdir()
        with self.assertRaisesRegex(package.PackageError, "signed manifest"):
            self.build("blocked-shadow-directory")

    def test_extra_private_raw_and_workspace_paths_fail_closed(self) -> None:
        for forbidden in (
            "private/raw_chain.bin",
            "logs/command.log",
            "C:/workspace/results.csv",
            "/workspace/results.csv",
            "../workspace/results.csv",
            "unexpected/public-note.txt",
        ):
            with self.subTest(forbidden=forbidden):
                report = copy.deepcopy(self.fixture._local_report())
                entries = copy.deepcopy(self.fixture.output_entries)
                entries.append(
                    {"path": forbidden, "sha256": "0" * 64, "size_bytes": 1}
                )
                report["output_file_count"] = len(entries)
                report["output_total_size_bytes"] = sum(
                    item["size_bytes"] for item in entries
                )
                report["output_file_set_sha256"] = hashlib.sha256(
                    package.verify_v404_release_acceptance.canonical_json_bytes(entries)
                ).hexdigest()
                manifest = {
                    "schema_version": 1,
                    "algorithm": "sha256",
                    "files": entries,
                }
                data = package.verify_v404_release_acceptance.canonical_json_bytes(
                    manifest
                )
                report["output_manifest_sha256"] = hashlib.sha256(data).hexdigest()
                with self.assertRaises(
                    package.verify_v404_release_acceptance.ReleaseAcceptanceError
                ):
                    package.verify_v404_release_acceptance.validate_local_output_manifest_bytes(
                        data, report
                    )

    def test_output_and_private_manifest_must_be_outside_workspace_and_results(self) -> None:
        archive = (
            self.fixture.root
            / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        )
        checksum = (
            self.fixture.root
            / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        )
        with self.assertRaisesRegex(package.PackageError, "output directory overlaps"):
            package.build(
                self.source,
                archive,
                checksum,
                repository_root=self.fixture.root,
                signed_output_manifest=self.signed_manifest,
                verifiers=self.fixture.verifiers,
            )
        inside = self.source / "LOCAL_RUN_OUTPUT_SHA256.json"
        inside.write_bytes(self.fixture.strict_output_manifest)
        with self.assertRaisesRegex(package.PackageError, "strict output manifest"):
            package.build(
                self.source,
                self.delivery
                / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME,
                self.delivery
                / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME,
                repository_root=self.fixture.root,
                signed_output_manifest=inside,
                verifiers=self.fixture.verifiers,
            )

    def test_archive_and_sidecar_names_are_exact(self) -> None:
        with self.assertRaisesRegex(package.PackageError, "archive output filename"):
            package.build(
                self.source,
                self.delivery / "wrong.zip",
                self.delivery
                / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME,
                repository_root=self.fixture.root,
                signed_output_manifest=self.signed_manifest,
                verifiers=self.fixture.verifiers,
            )
        with self.assertRaisesRegex(package.PackageError, "checksum output filename"):
            package.build(
                self.source,
                self.delivery
                / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME,
                self.delivery / "wrong.sha256",
                repository_root=self.fixture.root,
                signed_output_manifest=self.signed_manifest,
                verifiers=self.fixture.verifiers,
            )

    def test_predestined_archive_symlink_cannot_overwrite_victim(self) -> None:
        directory = self.delivery / "symlink-output"
        directory.mkdir()
        victim = self.work_root / "victim.bin"
        victim.write_bytes(b"victim-must-survive\n")
        archive = directory / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        checksum = directory / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        try:
            archive.symlink_to(victim)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(package.PackageError, "already exists"):
            package.build(
                self.source,
                archive,
                checksum,
                repository_root=self.fixture.root,
                signed_output_manifest=self.signed_manifest,
                verifiers=self.fixture.verifiers,
            )
        self.assertEqual(victim.read_bytes(), b"victim-must-survive\n")

    def test_post_acceptance_commit_swap_fails_closed(self) -> None:
        directory = self.delivery / "post-verify-swap"
        directory.mkdir()
        archive = directory / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        checksum = directory / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        real_link = package.os.link
        calls = 0

        def adversarial_link(source: object, target: object, *args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                # Reproduce the reviewed exploit: the commit primitive claims
                # success but places bytes that never passed acceptance.
                archive.write_bytes(b"POST-VERIFY-SWAP")
                return
            real_link(source, target, *args, **kwargs)

        with mock.patch.object(package.os, "link", side_effect=adversarial_link):
            with self.assertRaisesRegex(
                package.PackageError, "not the verified inode"
            ):
                package.build(
                    self.source,
                    archive,
                    checksum,
                    repository_root=self.fixture.root,
                    signed_output_manifest=self.signed_manifest,
                    verifiers=self.fixture.verifiers,
                )
        self.assertEqual(archive.read_bytes(), b"POST-VERIFY-SWAP")
        self.assertFalse(checksum.exists())

    def test_output_parent_swap_after_acceptance_fails_closed(self) -> None:
        directory = self.delivery / "parent-swap"
        directory.mkdir()
        archive = directory / package.verify_v404_release_acceptance.RESULTS_ARCHIVE_NAME
        checksum = directory / package.verify_v404_release_acceptance.RESULTS_CHECKSUM_NAME
        original_verify = package.verify_v404_release_acceptance.verify_release_acceptance
        calls = 0

        def adversarial_verify(*args: object, **kwargs: object) -> dict[str, object]:
            nonlocal calls
            result = original_verify(*args, **kwargs)
            calls += 1
            if calls == 1:
                moved = directory.with_name(directory.name + "-original")
                directory.rename(moved)
                directory.mkdir()
            return result

        with mock.patch.object(
            package.verify_v404_release_acceptance,
            "verify_release_acceptance",
            side_effect=adversarial_verify,
        ):
            with self.assertRaisesRegex(package.PackageError, "ancestor identity changed"):
                package.build(
                    self.source,
                    archive,
                    checksum,
                    repository_root=self.fixture.root,
                    signed_output_manifest=self.signed_manifest,
                    verifiers=self.fixture.verifiers,
                )
        self.assertFalse(archive.exists())
        self.assertFalse(checksum.exists())


if __name__ == "__main__":
    unittest.main()
