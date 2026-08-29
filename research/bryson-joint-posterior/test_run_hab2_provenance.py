#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
#
# Tests exercise the modified Bryson-derived runner documented in
# MODIFICATIONS_BRYSON.md and are distributed with it under GPL-2.0-only.
# Modified by Roman Jerše on 2026-08-29; see MODIFICATIONS_BRYSON.md.
"""Focused regression tests for standalone run status and source provenance."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


RUNNER_PATH = Path(__file__).with_name("run_hab2_joint_posterior.py")


def load_runner_module():
    """Load the runner while stubbing optional numerical runtime dependencies."""

    emcee = types.ModuleType("emcee")
    emcee.__version__ = "test-stub"

    astropy = types.ModuleType("astropy")
    astropy.__path__ = []
    astropy_io = types.ModuleType("astropy.io")
    astropy_io.fits = types.SimpleNamespace()
    astropy.io = astropy_io

    scipy = types.ModuleType("scipy")
    scipy.__path__ = []
    scipy_interpolate = types.ModuleType("scipy.interpolate")
    scipy_interpolate.interp2d = object()
    scipy_optimize = types.ModuleType("scipy.optimize")
    scipy_optimize.minimize = object()

    stubs = {
        "emcee": emcee,
        "astropy": astropy,
        "astropy.io": astropy_io,
        "scipy": scipy,
        "scipy.interpolate": scipy_interpolate,
        "scipy.optimize": scipy_optimize,
    }
    spec = importlib.util.spec_from_file_location("run_hab2_test_target", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


RUNNER = load_runner_module()


def make_source(root: Path, content: bytes = b"MODEL_VERSION = 1\n") -> Path:
    source = root / "insolation" / "rateModels3D.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(content)
    return source


class RunStatusTests(unittest.TestCase):
    def test_production_text_in_run_label_cannot_promote_status(self) -> None:
        parser = argparse.ArgumentParser()
        RUNNER.add_run_metadata_arguments(parser)
        args = parser.parse_args(["--run-label", "production-shard-7"])

        status, method = RUNNER.resolve_run_status(args.run_status)

        self.assertEqual(status, "pilot_only")
        self.assertEqual(method, "safe_default")

    def test_production_candidate_requires_explicit_cli_choice(self) -> None:
        parser = argparse.ArgumentParser()
        RUNNER.add_run_metadata_arguments(parser)
        args = parser.parse_args(
            [
                "--run-label",
                "pilot-looking-name",
                "--run-status",
                "production_candidate",
            ]
        )

        status, method = RUNNER.resolve_run_status(args.run_status)

        self.assertEqual(status, "production_candidate")
        self.assertEqual(method, "explicit_cli")

    def test_runner_contains_no_claimed_pinned_commit(self) -> None:
        text = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("d200f54b6f0df49e0dae530e69983cdce5397bfb", text)
        self.assertNotIn('if "pilot" in args.run_label', text)


class BrysonSourceProvenanceTests(unittest.TestCase):
    def test_unverified_snapshot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "snapshot"
            source = make_source(root)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()

            with mock.patch.object(
                RUNNER, "locked_bryson_source_sha256", return_value=digest
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "could not be verified fail-closed"
                ):
                    RUNNER.verify_bryson_source(root)

    def test_explicit_sha256_must_match_executed_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "snapshot"
            source = make_source(root)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()

            with mock.patch.object(
                RUNNER, "locked_bryson_source_sha256", return_value=digest
            ):
                provenance = RUNNER.verify_bryson_source(root, digest.upper())
                self.assertEqual(
                    provenance["verification_method"], "explicit_cli_sha256"
                )
                self.assertEqual(provenance["source_file"]["sha256"], digest)
                self.assertIsNone(provenance["source_commit"])

                with self.assertRaisesRegex(RuntimeError, "data lock"):
                    RUNNER.verify_bryson_source(root, "0" * 64)

    def test_canonical_artifact_manifest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifact"
            source = make_source(root)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            (root / "SHA256SUMS.txt").write_text(
                f"{digest}  ./insolation/rateModels3D.py\n", encoding="utf-8"
            )

            with mock.patch.object(
                RUNNER, "locked_bryson_source_sha256", return_value=digest
            ):
                provenance = RUNNER.verify_bryson_source(root)
                self.assertEqual(
                    provenance["verification_method"], "artifact_sha256_manifest"
                )
                self.assertEqual(provenance["source_file"]["sha256"], digest)
                self.assertIsNone(provenance["source_commit"])

                source.write_bytes(b"MODIFIED = True\n")
                with self.assertRaisesRegex(RuntimeError, "repository data lock"):
                    RUNNER.verify_bryson_source(root)

    @unittest.skipUnless(shutil.which("git"), "Git is required for this test")
    def test_clean_git_checkout_records_actual_head_and_rejects_modified_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            root.mkdir()
            make_source(root)
            commands = (
                ("init",),
                ("config", "user.email", "provenance-test@example.invalid"),
                ("config", "user.name", "Provenance Test"),
                ("config", "core.autocrlf", "false"),
                (
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/stevepur/DR25-occurrence-public.git",
                ),
                ("add", "insolation/rateModels3D.py"),
                ("commit", "-m", "source"),
            )
            for command in commands:
                subprocess.run(
                    ["git", "-C", str(root), *command],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            expected_commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            digest = hashlib.sha256(
                (root / "insolation" / "rateModels3D.py").read_bytes()
            ).hexdigest()
            with mock.patch.object(
                RUNNER, "locked_bryson_source_sha256", return_value=digest
            ):
                provenance = RUNNER.verify_bryson_source(root)
                self.assertEqual(
                    provenance["verification_method"], "git_head_source_bytes"
                )
                self.assertEqual(provenance["source_commit"], expected_commit)

                make_source(root, b"MODIFIED = True\n")
                with self.assertRaisesRegex(RuntimeError, "repository data lock"):
                    RUNNER.verify_bryson_source(root)

    def test_loaded_module_must_match_verified_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "snapshot"
            source = make_source(root)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with mock.patch.object(
                RUNNER, "locked_bryson_source_sha256", return_value=digest
            ):
                provenance = RUNNER.verify_bryson_source(root, digest)

            RUNNER.verify_loaded_bryson_module(
                types.SimpleNamespace(__file__=str(source)), provenance
            )
            wrong = root / "elsewhere.py"
            wrong.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "does not match verified source"):
                RUNNER.verify_loaded_bryson_module(
                    types.SimpleNamespace(__file__=str(wrong)), provenance
                )

            source.write_bytes(b"MUTATED_AFTER_VERIFICATION = True\n")
            with self.assertRaisesRegex(RuntimeError, "source bytes changed"):
                RUNNER.verify_loaded_bryson_module(
                    types.SimpleNamespace(__file__=str(source)), provenance
                )


class RunnerInputProvenanceTests(unittest.TestCase):
    def test_original_input_symlink_fails_closed_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = {
                "stellar_catalog": root / "stellar.csv",
                "pc_catalog": root / "pc.csv",
                "completeness": root / "completeness.fits.gz",
            }
            for key, path in regular.items():
                path.write_bytes(f"locked-{key}\n".encode("utf-8"))

            linked_stellar = root / "stellar-link.csv"
            try:
                linked_stellar.symlink_to(regular["stellar_catalog"])
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"OS account cannot create a test symlink: {exc}")

            expected = {
                key: hashlib.sha256(path.read_bytes()).hexdigest()
                for key, path in regular.items()
            }
            with mock.patch.object(
                RUNNER, "locked_runner_input_sha256", return_value=expected
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "Symlinked runner input is not allowed"
                ):
                    RUNNER.verify_runner_inputs(
                        "constant",
                        linked_stellar,
                        regular["pc_catalog"],
                        regular["completeness"],
                    )

    def test_inputs_are_locked_before_use_and_reverified_after_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "stellar_catalog": root / "stellar.csv",
                "pc_catalog": root / "pc.csv",
                "completeness": root / "completeness.fits.gz",
            }
            for key, path in paths.items():
                path.write_bytes(f"locked-{key}\n".encode("utf-8"))
            expected = {
                key: hashlib.sha256(path.read_bytes()).hexdigest()
                for key, path in paths.items()
            }
            with mock.patch.object(
                RUNNER, "locked_runner_input_sha256", return_value=expected
            ):
                records = RUNNER.verify_runner_inputs(
                    "constant",
                    paths["stellar_catalog"],
                    paths["pc_catalog"],
                    paths["completeness"],
                )
            RUNNER.reverify_runner_inputs(records)
            paths["pc_catalog"].write_bytes(b"changed-after-load\n")
            with self.assertRaisesRegex(RuntimeError, "changed after use"):
                RUNNER.reverify_runner_inputs(records)

    def test_wrong_preflight_input_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / name for name in ("stellar", "pc", "completeness")]
            for path in paths:
                path.write_bytes(b"input\n")
            with mock.patch.object(
                RUNNER,
                "locked_runner_input_sha256",
                return_value={
                    "stellar_catalog": "0" * 64,
                    "pc_catalog": "0" * 64,
                    "completeness": "0" * 64,
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                    RUNNER.verify_runner_inputs("constant", *paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
