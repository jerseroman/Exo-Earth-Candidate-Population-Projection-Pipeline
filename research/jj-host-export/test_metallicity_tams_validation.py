from __future__ import annotations

import csv
import io
import hashlib
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from metallicity_tams_differential_sensitivity import (
    ANCHOR_LOCK_IDS,
    ANCHORS,
    CoverageValidationError,
    DEFAULT_DATA_LOCKS,
    REPORT_NAME,
    RUNTIME_NAME,
    load_archive_locks,
    main,
    mh_from_z,
    native_solar_rows,
    prepare_output_root,
    validate_low_mass_curve_points,
    validated_track_members,
    verify_archive_lock,
    write_native_solar_nodes,
)


class LowMassTamsCurveValidationTests(unittest.TestCase):
    @staticmethod
    def archive_with(member: tarfile.TarInfo, payload: bytes = b"") -> io.BytesIO:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            if member.isfile():
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))
            else:
                handle.addfile(member)
        archive.seek(0)
        return archive

    def test_tar_member_validation_accepts_regular_track(self) -> None:
        archive = self.archive_with(tarfile.TarInfo("tracks/model.DAT"), b"ok\n")
        with tarfile.open(fileobj=archive, mode="r") as handle:
            members = validated_track_members(handle)
        self.assertEqual([member.name for member in members], ["tracks/model.DAT"])

    def test_tar_member_validation_rejects_path_traversal(self) -> None:
        archive = self.archive_with(tarfile.TarInfo("../escape.DAT"), b"bad")
        with tarfile.open(fileobj=archive, mode="r") as handle:
            with self.assertRaisesRegex(RuntimeError, "unsafe TAR member"):
                validated_track_members(handle)

    def test_tar_member_validation_rejects_symbolic_link(self) -> None:
        member = tarfile.TarInfo("tracks/link.DAT")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside.DAT"
        archive = self.archive_with(member)
        with tarfile.open(fileobj=archive, mode="r") as handle:
            with self.assertRaisesRegex(RuntimeError, "unsupported TAR member"):
                validated_track_members(handle)

    def test_tar_member_validation_rejects_duplicate_member(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            for payload in (b"first\n", b"second\n"):
                member = tarfile.TarInfo("tracks/model.DAT")
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r") as handle:
            with self.assertRaisesRegex(RuntimeError, "duplicate TAR member"):
                validated_track_members(handle)

    def test_massive_giants_cannot_supply_temperature_coverage(self) -> None:
        points = [
            (5200.0, 100.0, 20.0, "giant-low.DAT", 0.1),
            (5400.0, 1.2, 0.8, "m080.DAT", 20.0),
            (5550.0, 1.3, 0.9, "m090.DAT", 15.0),
            (5750.0, 1.5, 1.0, "m100.DAT", 10.0),
            (5900.0, 1.7, 1.1, "m110.DAT", 7.0),
            (6100.0, 200.0, 40.0, "giant-high.DAT", 0.05),
        ]
        with self.assertRaisesRegex(RuntimeError, "low-mass TAMS coverage"):
            validate_low_mass_curve_points(points, 0.001)

    def test_valid_low_mass_curve_is_retained(self) -> None:
        points = [
            (5200.0, 1.1, 0.7, "m070.DAT", 25.0),
            (5400.0, 1.2, 0.8, "m080.DAT", 20.0),
            (5700.0, 1.4, 1.0, "m100.DAT", 10.0),
            (6100.0, 1.7, 1.2, "m120.DAT", 6.0),
            (5800.0, 50.0, 10.0, "giant.DAT", 0.1),
        ]
        retained, temperatures, radii = validate_low_mass_curve_points(
            points, 0.017
        )
        self.assertEqual(len(retained), 4)
        self.assertEqual(list(temperatures), [5200.0, 5400.0, 5700.0, 6100.0])
        self.assertTrue((radii < 10.0).all())

    def test_every_parsec_archive_has_an_exact_data_lock(self) -> None:
        locks = load_archive_locks(DEFAULT_DATA_LOCKS)
        self.assertEqual(set(locks), {name for _, _, name in ANCHORS})
        self.assertEqual(len({lock["lock_id"] for lock in locks.values()}), 12)
        self.assertEqual(
            {name: lock["lock_id"] for name, lock in locks.items()},
            ANCHOR_LOCK_IDS,
        )

    def test_archive_lock_rejects_size_and_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "archive.tar.gz"
            path.write_bytes(b"locked bytes")
            lock = {
                "lock_id": "fixture",
                "expected_size_bytes": path.stat().st_size,
                "expected_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            self.assertEqual(verify_archive_lock(path, lock)["lock_id"], "fixture")

            path.write_bytes(b"locked bytez")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                verify_archive_lock(path, lock)

            path.write_bytes(b"short")
            with self.assertRaisesRegex(RuntimeError, "size mismatch"):
                verify_archive_lock(path, lock)

    def test_archive_lock_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.tar.gz"
            target.write_bytes(b"locked bytes")
            link = root / "archive.tar.gz"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            lock = {
                "lock_id": "fixture",
                "expected_size_bytes": target.stat().st_size,
                "expected_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
            with self.assertRaisesRegex(RuntimeError, "unsafe regular file"):
                verify_archive_lock(link, lock)

    def test_output_root_starts_with_only_the_runtime_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / RUNTIME_NAME).write_text("{}\n", encoding="utf-8")
            prepare_output_root(root)

            forbidden = root / "metallicity_tams_differential_radial.csv"
            forbidden.mkdir()
            with self.assertRaisesRegex(RuntimeError, "initially contain only"):
                prepare_output_root(root)

    def test_native_solar_export_is_exactly_nine_monotonic_nodes(self) -> None:
        temperatures = [
            5151.337446989074,
            5304.812032718946,
            5390.13944,
            5517.85139,
            5633.13293,
            5738.25706,
            5844.13178,
            5951.82290,
            6060.24246,
        ]
        radii = [
            1.011706953863964,
            1.0337124217916671,
            1.22926,
            1.28542,
            1.35053,
            1.42375,
            1.49188,
            1.55332,
            1.61155,
        ]
        solar = {
            "Z": 0.017,
            "Y": 0.279,
            "MH": -0.075,
            "points": [
                (temperature, radius, 0.75 + 0.05 * index, f"m{index}.DAT", 27.0 - 2.0 * index)
                for index, (temperature, radius) in enumerate(zip(temperatures, radii))
            ],
        }
        rows = native_solar_rows(solar)
        self.assertEqual(len(rows), 9)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "native_solar_tams_nodes.csv"
            write_native_solar_nodes(output, solar, rows)
            with output.open(encoding="utf-8", newline="") as handle:
                exported = list(csv.DictReader(handle))
            self.assertEqual(len(exported), 9)
            self.assertTrue(all(float(row["Z"]) == 0.017 for row in exported))

            with self.assertRaisesRegex(RuntimeError, "non-exclusive output path"):
                write_native_solar_nodes(output, solar, rows)

    def test_main_emits_schema3_parent_binding_and_exact_coverage_partition(self) -> None:
        temperatures = [
            5151.337446989074,
            5304.812032718946,
            5390.139436325507,
            5517.851394729554,
            5633.132932779186,
            5738.257064157849,
            5844.131775573857,
            5951.822899428788,
            6060.242461424597,
        ]
        radii = [
            1.011706953863964,
            1.0337124217916671,
            1.2292627883933631,
            1.2854190594305617,
            1.3505315525272714,
            1.4237532717384762,
            1.4918828965541018,
            1.553315711522533,
            1.611553527393026,
        ]
        ages = [
            27.202020114,
            21.0708279315,
            18.3962474249,
            14.8576832197,
            12.1056313313,
            9.949438865,
            8.19537291074,
            6.7592173605,
            5.58853443962,
        ]
        solar_points = [
            (
                temperature,
                radius,
                0.75 + 0.05 * index,
                f"Z0.017Y0.279OUTA1.74_F7_M{0.75 + 0.05 * index:07.3f}.DAT",
                age,
            )
            for index, (temperature, radius, age) in enumerate(
                zip(temperatures, radii, ages)
            )
        ]
        archive_locks = {
            name: {
                "lock_id": ANCHOR_LOCK_IDS[name],
                "filename": name,
                "expected_size_bytes": 123,
                "expected_sha256": "a" * 64,
            }
            for _, _, name in ANCHORS
        }

        def build_curve(z, y, name, _cache, locks):
            if z == 0.001:
                raise CoverageValidationError(
                    "Z=0.001: low-mass TAMS coverage 5400.0..6100.0 K "
                    "does not span 5300.0..6000.0 K"
                )
            self.assertEqual(z, 0.017)
            lock = locks[name]
            return {
                "Z": z,
                "Y": y,
                "MH": mh_from_z(z),
                "archive": name,
                "archive_lock_id": lock["lock_id"],
                "archive_size_bytes": lock["expected_size_bytes"],
                "archive_sha256": lock["expected_sha256"],
                "points": solar_points,
            }

        def verify_archive(_path, lock):
            return {
                "lock_id": lock["lock_id"],
                "filename": lock["filename"],
                "size_bytes": lock["expected_size_bytes"],
                "sha256": lock["expected_sha256"],
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "jj_g_hosts_parent_prelogg_padova.csv"
            parent.write_text(f"FeH\n{mh_from_z(0.001)!r}\n", encoding="utf-8")
            reference = root / "reference.txt"
            reference.write_text("locked fixture\n", encoding="utf-8")
            cache = root / "cache"
            output = root / "metallicity-audit"
            output.mkdir()
            (output / RUNTIME_NAME).write_text("{}\n", encoding="utf-8")
            argv = [
                "metallicity_tams_differential_sensitivity.py",
                "--input",
                str(parent),
                "--reference-tams",
                str(reference),
                "--cache",
                str(cache),
                "--out",
                str(output),
            ]
            with (
                patch("metallicity_tams_differential_sensitivity.load_archive_locks", return_value=archive_locks),
                patch("metallicity_tams_differential_sensitivity.build_curve", side_effect=build_curve),
                patch("metallicity_tams_differential_sensitivity.verify_archive_lock", side_effect=verify_archive),
                patch("metallicity_tams_differential_sensitivity.validate_solar", return_value=([], 0.0, 0.0)),
                patch("builtins.print"),
                patch.object(sys, "argv", argv),
            ):
                main()
            report = json.loads((output / REPORT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], 3)
            self.assertEqual(report["parent_input"]["sha256"], hashlib.sha256(parent.read_bytes()).hexdigest())
            self.assertEqual(report["parent_input"]["row_count"], 1)
            self.assertEqual(
                report["coverage_evidence"],
                {
                    "required_lock_ids": ["parsec_tracks_z0001", "parsec_tracks_z0017"],
                    "successful_lock_ids": ["parsec_tracks_z0017"],
                    "failed_lock_ids": ["parsec_tracks_z0001"],
                },
            )


if __name__ == "__main__":
    unittest.main()
