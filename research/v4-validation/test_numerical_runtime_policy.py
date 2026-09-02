#!/usr/bin/env python3
"""Unit tests for the fail-closed numerical-runtime policy."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "verify_numerical_runtime.py"
SPEC = importlib.util.spec_from_file_location("verify_numerical_runtime", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot import {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NumericalRuntimePolicyTests(unittest.TestCase):
    def test_exact_environment_is_required(self) -> None:
        expected = dict(MODULE.EXPECTED_ENV)
        self.assertEqual(MODULE.validate_environment(expected), expected)
        for key in expected:
            drifted = dict(expected)
            drifted[key] = "unexpected"
            with self.assertRaisesRegex(RuntimeError, "environment mismatch"):
                MODULE.validate_environment(drifted)

    def test_cpu_dispatch_family_must_be_disabled(self) -> None:
        features = {
            name: True for name in MODULE.REQUIRED_ENABLED
        }
        features.update({name: False for name in MODULE.REQUIRED_DISABLED})
        MODULE.validate_cpu_features(features)

        for name in MODULE.REQUIRED_DISABLED:
            drifted = dict(features)
            drifted[name] = True
            with self.assertRaisesRegex(RuntimeError, "dispatch target is active"):
                MODULE.validate_cpu_features(drifted)

    def test_avx2_and_fma3_are_required(self) -> None:
        features = {
            name: True for name in MODULE.REQUIRED_ENABLED
        }
        features.update({name: False for name in MODULE.REQUIRED_DISABLED})
        for name in MODULE.REQUIRED_ENABLED:
            drifted = dict(features)
            drifted[name] = False
            with self.assertRaisesRegex(RuntimeError, "feature is inactive"):
                MODULE.validate_cpu_features(drifted)

    def test_direct_controllers_bootstrap_before_py_or_pyc_shadows(self) -> None:
        controllers = (
            "verify_age_cut_ssp_contract.py",
            "verify_radial_ssp_contract.py",
            "verify_host_artifact_contract.py",
            "verify_local_run_attestation.py",
            "verify_numerical_runtime.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "SHADOW_EXECUTED"
            payload = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                "raise SystemExit('SHADOW_EXECUTED')\n"
            )
            for name in controllers:
                shutil.copyfile(ROOT / "scripts" / name, root / name)
            for shadow_name in ("json", "numpy"):
                source = root / f"{shadow_name}.py"
                source.write_text(payload, encoding="utf-8", newline="\n")
                py_compile.compile(
                    str(source),
                    cfile=str(root / f"{shadow_name}.pyc"),
                    doraise=True,
                )

            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(root)
            for optimisation in ((), ("-O",)):
                for name in controllers:
                    with self.subTest(controller=name, optimisation=optimisation):
                        marker.unlink(missing_ok=True)
                        result = subprocess.run(
                            [
                                sys.executable,
                                *optimisation,
                                str(root / name),
                                "--help",
                            ],
                            env=environment,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                            shell=False,
                        )
                        self.assertEqual(
                            result.returncode,
                            0,
                            result.stdout.decode(errors="replace")
                            + result.stderr.decode(errors="replace"),
                        )
                        self.assertFalse(marker.exists())

            (root / "json.py").unlink()
            (root / "numpy.py").unlink()
            for name in controllers:
                with self.subTest(controller=name, shadow="sourceless-pyc"):
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(
                        [sys.executable, str(root / name), "--help"],
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        shell=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
