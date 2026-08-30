#!/usr/bin/env python3
"""Unit and adversarial tests for private raw-chain evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import numpy as np

import raw_chain_evidence as raw

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import verify_accepted_aggregate as accepted  # noqa: E402


class RawChainEvidenceTests(unittest.TestCase):
    @staticmethod
    def write_probe(directory: Path, offset: float = 0.0) -> dict:
        values = np.arange(4 * 2 * 4, dtype=float).reshape(4, 2, 4) + offset
        log_probability = -np.sum(values**2, axis=2)
        return raw.write_raw_chain(
            directory,
            branch="constant",
            run_label="production-shard-0",
            trial=0,
            trial_seed=11,
            mcmc_seed=500014,
            chain_source_order=values,
            log_probability=log_probability,
        )

    def test_deterministic_binary_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = self.write_probe(directory)
            chain, log_probability = raw.read_raw_chain(
                directory / record["file"],
                branch="constant",
                run_label="production-shard-0",
                record=record,
            )
            expected = np.arange(4 * 2 * 4, dtype=float).reshape(4, 2, 4)
            self.assertTrue(np.array_equal(chain, expected))
            self.assertTrue(
                np.array_equal(log_probability, -np.sum(expected**2, axis=2))
            )
            self.assertEqual(
                record["size_bytes"],
                raw.RAW_CHAIN_HEADER.size + 4 * 2 * 5 * 8,
            )

    def test_bundle_has_exact_file_and_identity_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = self.write_probe(directory)
            binding = raw.finalize_raw_chain_bundle(
                directory,
                branch="constant",
                run_label="production-shard-0",
                records=[record],
            )
            verified = raw.verify_raw_chain_bundle(
                directory,
                branch="constant",
                run_label="production-shard-0",
                expected_trials={0: (11, 500014)},
                binding=binding,
            )
            self.assertEqual(verified, {0: record})
            (directory / "unexpected.bin").write_bytes(b"unexpected")
            with self.assertRaisesRegex(
                raw.RawChainEvidenceError, "extra or missing files"
            ):
                raw.verify_raw_chain_bundle(
                    directory,
                    branch="constant",
                    run_label="production-shard-0",
                    expected_trials={0: (11, 500014)},
                    binding=binding,
                )

    def test_same_size_swap_after_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first_directory = Path(temporary) / "first"
            second_directory = Path(temporary) / "second"
            first_directory.mkdir()
            second_directory.mkdir()
            first = self.write_probe(first_directory, offset=0.0)
            second = self.write_probe(second_directory, offset=100.0)
            first_path = first_directory / first["file"]
            replacement = (second_directory / second["file"]).read_bytes()
            self.assertEqual(len(replacement), first_path.stat().st_size)
            original_digest = raw._digest_bytes

            def swap_after_hash(data: bytes) -> str:
                digest = original_digest(data)
                first_path.write_bytes(replacement)
                return digest

            with mock.patch.object(raw, "_digest_bytes", side_effect=swap_after_hash):
                with self.assertRaisesRegex(
                    raw.RawChainEvidenceError, "changed during its stable read"
                ):
                    raw.read_raw_chain(
                        first_path,
                        branch="constant",
                        run_label="production-shard-0",
                        record=first,
                    )

    def test_index_and_manifest_swap_after_hash_are_rejected(self) -> None:
        for target_name in ("index_file", "manifest_file"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                record = self.write_probe(directory)
                binding = raw.finalize_raw_chain_bundle(
                    directory,
                    branch="constant",
                    run_label="production-shard-0",
                    records=[record],
                )
                target = directory / binding[target_name]
                original = target.read_bytes()
                replacement = bytes([original[0] ^ 1]) + original[1:]
                original_digest = raw._digest_bytes
                swapped = False

                def swap_target_after_hash(data: bytes) -> str:
                    nonlocal swapped
                    digest = original_digest(data)
                    if not swapped and data == original:
                        target.write_bytes(replacement)
                        swapped = True
                    return digest

                with mock.patch.object(
                    raw, "_digest_bytes", side_effect=swap_target_after_hash
                ), self.assertRaisesRegex(
                    raw.RawChainEvidenceError, "changed during its stable read"
                ):
                    raw.verify_raw_chain_bundle(
                        directory,
                        branch="constant",
                        run_label="production-shard-0",
                        expected_trials={0: (11, 500014)},
                        binding=binding,
                    )

    def test_symlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = self.write_probe(directory)
            target = directory / record["file"]
            link = directory / "link.bin"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are not available in this environment")
            with self.assertRaises(raw.RawChainEvidenceError):
                raw.read_stable_file_bytes(link, "symlink probe")

    @staticmethod
    def make_public_audit(root: Path) -> tuple[dict, dict, dict, Path]:
        policy = {
            "requested_minimum_steps": 3000,
            "requested_maximum_steps": 20000,
            "check_interval": 1000,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
        }
        bundles = []
        trials = []
        identity_projection = []
        for shard in range(16):
            label = f"production-shard-{shard}"
            bundles.append(
                {
                    "shard": shard,
                    "run_label": label,
                    "index_file": f"raw_chain_index_constant_{label}.json",
                    "index_sha256": hashlib.sha256(
                        f"index:{shard}".encode()
                    ).hexdigest(),
                    "manifest_file": f"SHA256SUMS_raw_chain_constant_{label}.txt",
                    "manifest_sha256": hashlib.sha256(
                        f"manifest:{shard}".encode()
                    ).hexdigest(),
                    "trial_count": 25,
                }
            )
            for trial in range(25):
                global_trial = shard * 25 + trial
                trial_seed = 2026082200 + shard * 1000 + 1_000_003 * trial
                mcmc_seed = trial_seed + 500000003
                raw_hash = hashlib.sha256(
                    f"raw:{global_trial}".encode()
                ).hexdigest()
                tau = [10.0] * 4
                checks = [
                    {
                        "production_steps": 3000,
                        "autocorrelation_time": tau,
                        "length_ok": True,
                        "stable": False,
                        "max_relative_tau_change": None,
                        "stable_check_streak": 0,
                    },
                    {
                        "production_steps": 4000,
                        "autocorrelation_time": tau,
                        "length_ok": True,
                        "stable": True,
                        "max_relative_tau_change": 0.0,
                        "stable_check_streak": 1,
                    },
                    {
                        "production_steps": 5000,
                        "autocorrelation_time": tau,
                        "length_ok": True,
                        "stable": True,
                        "max_relative_tau_change": 0.0,
                        "stable_check_streak": 2,
                    },
                ]
                record = {
                    "global_trial": global_trial,
                    "shard": shard,
                    "run_label": label,
                    "trial": trial,
                    "trial_seed": trial_seed,
                    "mcmc_seed": mcmc_seed,
                    "raw_chain_file": (
                        f"raw_production_chain_constant_{label}_trial-{trial:03d}.bin"
                    ),
                    "raw_chain_sha256": raw_hash,
                    "raw_chain_size_bytes": 76 + 5000 * 16 * 5 * 8,
                    "production_steps": 5000,
                    "walkers": 16,
                    "recomputed_autocorrelation_time_source_order": tau,
                    "recomputed_effective_sample_size_source_order": [8000.0] * 4,
                    "recomputed_convergence_checks": checks,
                    "first_accepted_steps": 5000,
                    "converged": True,
                    "serialized_thinned_chain_match": True,
                }
                trials.append(record)
                identity_projection.append(
                    {
                        key: record[key]
                        for key in (
                            "global_trial",
                            "shard",
                            "trial",
                            "run_label",
                            "trial_seed",
                            "mcmc_seed",
                            "raw_chain_sha256",
                        )
                    }
                )
        identity_sha = hashlib.sha256(
            json.dumps(
                identity_projection,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        helper_sha = accepted.sha256(accepted.RAW_CHAIN_HELPER)
        report = {
            "schema_version": 1,
            "status": "PASS",
            "branch": "constant",
            "format": accepted.RAW_CHAIN_FORMAT,
            "storage_policy": accepted.RAW_CHAIN_STORAGE_POLICY,
            "parameter_order_source": ["F0", "beta_inst", "alpha_radius", "gamma"],
            "payload_field_order": [
                "F0",
                "beta_inst",
                "alpha_radius",
                "gamma",
                "log_probability",
            ],
            "audit_algorithm": "test fixture",
            "audit_helper_file": accepted.RAW_CHAIN_HELPER.name,
            "audit_helper_sha256": helper_sha,
            "adaptive_production_policy": policy,
            "trials_verified": 400,
            "expected_global_trials": 400,
            "global_trial_identity_sha256": identity_sha,
            "bundles": bundles,
            "trials": trials,
            "raw_files_copied_to_public_artifact": False,
        }
        report_path = root / "raw_unthinned_chain_audit_constant.json"
        report_path.write_text(
            json.dumps(report, sort_keys=True, allow_nan=False), encoding="utf-8"
        )
        report_sha = accepted.sha256(report_path)
        summary = {
            "production_acceptance_gate": {
                "adaptive_production_policy": policy,
                "minimum_ess_per_realization": 1000.0,
            },
            "raw_unthinned_chain_acceptance_gate": {
                "required": True,
                "verified": True,
                "schema_version": 1,
                "format": accepted.RAW_CHAIN_FORMAT,
                "trials_verified": 400,
                "global_trial_identity_sha256": identity_sha,
                "evidence_report_file": report_path.name,
                "evidence_report_sha256": report_sha,
                "audit_helper_file": accepted.RAW_CHAIN_HELPER.name,
                "audit_helper_sha256": helper_sha,
                "raw_files_copied_to_public_artifact": False,
            },
        }
        entries = {report_path.name: report_sha}
        return report, summary, entries, report_path

    @staticmethod
    def rewrite_public_audit(
        report: dict, summary: dict, entries: dict, report_path: Path
    ) -> None:
        report_path.write_text(
            json.dumps(report, sort_keys=True, allow_nan=False), encoding="utf-8"
        )
        digest = accepted.sha256(report_path)
        entries[report_path.name] = digest
        summary["raw_unthinned_chain_acceptance_gate"][
            "evidence_report_sha256"
        ] = digest

    def test_public_raw_audit_schema_rejects_rebound_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, summary, entries, report_path = self.make_public_audit(root)
            accepted.verify_raw_chain_audit(root, "constant", summary, entries)

            forged_size = copy.deepcopy(report)
            forged_size["trials"][0]["raw_chain_size_bytes"] += 1
            self.rewrite_public_audit(forged_size, summary, entries, report_path)
            with self.assertRaisesRegex(SystemExit, "exact binary schema"):
                accepted.verify_raw_chain_audit(root, "constant", summary, entries)

            forged_checkpoint = copy.deepcopy(report)
            forged_checkpoint["trials"][0]["recomputed_convergence_checks"][1][
                "stable_check_streak"
            ] = 2
            self.rewrite_public_audit(
                forged_checkpoint, summary, entries, report_path
            )
            with self.assertRaisesRegex(SystemExit, "stable streak"):
                accepted.verify_raw_chain_audit(root, "constant", summary, entries)


if __name__ == "__main__":
    unittest.main(verbosity=2)
