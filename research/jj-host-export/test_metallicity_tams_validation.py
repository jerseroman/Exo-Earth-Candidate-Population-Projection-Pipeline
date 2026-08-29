from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from metallicity_tams_differential_sensitivity import (
    safe_extract,
    validate_low_mass_curve_points,
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

    def test_safe_extract_accepts_regular_file(self) -> None:
        archive = self.archive_with(tarfile.TarInfo("tracks/model.DAT"), b"ok\n")
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(fileobj=archive, mode="r") as handle:
                safe_extract(handle, Path(tmp))
            self.assertEqual((Path(tmp) / "tracks" / "model.DAT").read_bytes(), b"ok\n")

    def test_safe_extract_rejects_path_traversal(self) -> None:
        archive = self.archive_with(tarfile.TarInfo("../escape.DAT"), b"bad")
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(fileobj=archive, mode="r") as handle:
                with self.assertRaisesRegex(RuntimeError, "escape.DAT"):
                    safe_extract(handle, Path(tmp))

    def test_safe_extract_rejects_symbolic_link(self) -> None:
        member = tarfile.TarInfo("tracks/link.DAT")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside.DAT"
        archive = self.archive_with(member)
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(fileobj=archive, mode="r") as handle:
                with self.assertRaisesRegex(RuntimeError, "unsupported TAR member"):
                    safe_extract(handle, Path(tmp))

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


if __name__ == "__main__":
    unittest.main()
