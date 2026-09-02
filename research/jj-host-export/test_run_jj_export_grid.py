#!/usr/bin/env python3
"""Regression tests for the pinned production JJ radial grid."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np


MODULE_PATH = Path(__file__).with_name("run_jj_export.py")
SPEC = importlib.util.spec_from_file_location("run_jj_export", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RadialGridTests(unittest.TestCase):
    def test_workflow_step_assertion_accepts_only_exact_half_kpc(self) -> None:
        self.assertEqual(str(MODULE.exact_radial_step("0.5")), "0.5")
        self.assertEqual(str(MODULE.exact_radial_step("0.50")), "0.50")
        for value in ("1", "0", "-0.5", "nan", "inf", "-inf", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(
                MODULE.argparse.ArgumentTypeError
            ):
                MODULE.exact_radial_step(value)

    def test_exact_inclusive_half_kpc_grid_is_accepted(self) -> None:
        grid = np.arange(4.0, 14.0 + 0.25, 0.5)
        observed = MODULE.validate_radial_grid(4.0, 14.0, 0.5, grid)
        np.testing.assert_array_equal(observed, grid)
        self.assertEqual(observed.size, 21)

    def test_configuration_and_realized_grid_are_fail_closed(self) -> None:
        exact = np.arange(4.0, 14.0 + 0.25, 0.5)
        cases = (
            (4.5, 14.0, 0.5, exact),
            (4.0, 13.5, 0.5, exact),
            (4.0, 14.0, 1.0, exact),
            (4.0, 14.0, 0.5, exact[:-1]),
            (4.0, 14.0, 0.5, exact[::-1]),
            (4.0, 14.0, 0.5, np.append(exact[:-1], np.nan)),
            (4.0, 14.0, 0.5, exact.reshape(3, 7)),
        )
        for rmin, rmax, dr, grid in cases:
            with self.subTest(rmin=rmin, rmax=rmax, dr=dr, shape=grid.shape):
                with self.assertRaises(RuntimeError):
                    MODULE.validate_radial_grid(rmin, rmax, dr, grid)

    def test_jj_worktree_allows_only_padova_inputs_as_untracked(self) -> None:
        clean = SimpleNamespace(returncode=0)
        with mock.patch.object(MODULE.subprocess, "run", return_value=clean), mock.patch.object(
            MODULE,
            "git",
            return_value=(
                "jjmodel/input/isochrones/Padova/multiband/Metadata\n"
                "jjmodel/input/isochrones/Padova/grid.dat"
            ),
        ):
            MODULE.verify_jj_worktree(Path("jj"))
        with mock.patch.object(MODULE.subprocess, "run", return_value=clean), mock.patch.object(
            MODULE, "git", return_value="jjmodel/shadow_module.py"
        ):
            with self.assertRaisesRegex(RuntimeError, "untracked files"):
                MODULE.verify_jj_worktree(Path("jj"))

    def test_jj_worktree_rejects_tracked_modification(self) -> None:
        with mock.patch.object(
            MODULE.subprocess, "run", return_value=SimpleNamespace(returncode=1)
        ):
            with self.assertRaisesRegex(RuntimeError, "tracked source"):
                MODULE.verify_jj_worktree(Path("jj"))


if __name__ == "__main__":
    unittest.main()
