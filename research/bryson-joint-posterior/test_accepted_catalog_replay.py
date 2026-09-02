#!/usr/bin/env python3
"""Direct tests for accepted-aggregate catalog replay integration."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import verify_accepted_aggregate as accepted  # noqa: E402


class AcceptedAggregateSnapshotTests(unittest.TestCase):
    @staticmethod
    def write_minimal_manifest_root(
        root: Path, branch: str = "constant"
    ) -> dict[str, bytes]:
        root.mkdir(parents=True)
        payloads = {
            name: f"stable payload for {name}\n".encode("utf-8")
            for name in accepted.expected_aggregate_files(branch)
        }
        for name, payload in payloads.items():
            (root / name).write_bytes(payload)
        manifest = root / f"SHA256SUMS_{branch}_aggregate.txt"
        manifest.write_text(
            "".join(
                f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
                for name in sorted(payloads)
            ),
            encoding="utf-8",
            newline="\n",
        )
        return payloads

    def test_completed_snapshot_is_independent_of_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            stable = base / "stable"
            payloads = self.write_minimal_manifest_root(source)
            entries = accepted.snapshot_exact_aggregate_root(
                source,
                "constant",
                stable,
            )
            target_name = "joint_posterior_constant_aggregate_summary.json"
            (source / target_name).write_bytes(b"mutated after completed snapshot")

            self.assertEqual((stable / target_name).read_bytes(), payloads[target_name])
            self.assertEqual(accepted.verify_manifest(stable, "constant"), entries)

    def test_nested_directory_is_rejected_from_exact_flat_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            self.write_minimal_manifest_root(source)
            leak = source / "nested-private-data"
            leak.mkdir()
            (leak / "raw-chain.bin").write_bytes(b"must not be ignored")

            with self.assertRaisesRegex(SystemExit, "file set differs"):
                accepted.snapshot_exact_aggregate_root(
                    source,
                    "constant",
                    base / "stable",
                )

    def test_post_hash_source_swap_is_rejected_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            payloads = self.write_minimal_manifest_root(source)
            target_name = "joint_posterior_constant_aggregate_summary.json"
            target = source / target_name
            original_snapshot = accepted._snapshot_regular_file
            swapped = False

            def snapshot_then_swap(path, description, **kwargs):
                nonlocal swapped
                result = original_snapshot(path, description, **kwargs)
                if Path(path) == target and not swapped:
                    replacement = source / "same-size-replacement.tmp"
                    replacement.write_bytes(b"X" * len(payloads[target_name]))
                    replacement.replace(target)
                    swapped = True
                return result

            with mock.patch.object(
                accepted,
                "_snapshot_regular_file",
                side_effect=snapshot_then_swap,
            ), self.assertRaisesRegex(SystemExit, "changed while its stable snapshot"):
                accepted.snapshot_exact_aggregate_root(
                    source,
                    "constant",
                    base / "stable",
                )
            self.assertTrue(swapped)


class AcceptedCatalogReplayTests(unittest.TestCase):
    @staticmethod
    def summary(profile: str, mode: str) -> dict:
        return {
            "production_acceptance_gate": {"profile": profile},
            "measurement_error": {"mode": mode},
            "locked_input_sha256": {
                "pc_catalog": "1" * 64,
                "stellar_catalog": "2" * 64,
                "completeness": "3" * 64,
            },
        }

    def test_self_consistent_legacy_mode_cannot_claim_primary_profile(self) -> None:
        forged = self.summary(
            accepted.V404_ACCEPTANCE_PROFILE, "legacy_source_mixture"
        )
        with self.assertRaisesRegex(SystemExit, "does not match"):
            accepted.measurement_mode_for_profile("constant", forged)

        sensitivity = self.summary(
            accepted.V404_LEGACY_SENSITIVITY_PROFILE,
            "legacy_source_mixture",
        )
        self.assertEqual(
            accepted.measurement_mode_for_profile("constant", sensitivity),
            "legacy_source_mixture",
        )
        with self.assertRaisesRegex(SystemExit, "constant branch"):
            accepted.measurement_mode_for_profile("zero", sensitivity)

    @staticmethod
    def valid_report() -> tuple[dict, dict, dict, dict]:
        summary = AcceptedCatalogReplayTests.summary(
            accepted.V404_ACCEPTANCE_PROFILE,
            "quantile_matched_two_sided",
        )
        entries = {
            "perturbation_audit_constant_full.csv.gz": "4" * 64,
            "trial_diagnostics_constant_full.jsonl": "5" * 64,
        }
        body = {
            "schema_version": 1,
            "status": "PASS",
            "branch": "constant",
            "measurement_error_mode": "quantile_matched_two_sided",
            "trials_verified": 400,
            "merged_catalog_rows": 100,
            "audit_rows_verified": 200,
            "locked_inputs": {
                "bryson_pc_catalog": {
                    "filename": "PCs_dr25_hab2.csv",
                    "sha256": "1" * 64,
                    "size_bytes": 10,
                },
                "bryson_stellar_catalog_extracted": {
                    "filename": "dr25_stellar_berger2020_clean_hab2.txt",
                    "sha256": "2" * 64,
                    "size_bytes": 20,
                },
            },
            "data_locks": {
                "filename": "DATA_LOCKS.json",
                "sha256": "6" * 64,
                "size_bytes": 30,
            },
            "verifier_source": {"sha256": "7" * 64, "size_bytes": 40},
            "aggregate_inputs": {
                "perturbation_audit": {
                    "filename": "perturbation_audit_constant_full.csv.gz",
                    "sha256": "4" * 64,
                    "size_bytes": 50,
                },
                "trial_diagnostics": {
                    "filename": "trial_diagnostics_constant_full.jsonl",
                    "sha256": "5" * 64,
                    "size_bytes": 60,
                },
            },
            "seed_schedule_sha256": "8" * 64,
            "count_projection_sha256": "9" * 64,
            "verification_scope": (
                "exact source merge, reliability selection, asymmetric draws, "
                "domain masks, row identities, source fields, perturbed values, "
                "audit statuses, and per-realization counts"
            ),
        }
        audit_id = "sha256:" + hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return {"audit_id": audit_id, **body}, summary, entries, {
            "data_locks_sha256": "6" * 64,
            "data_locks_size": 30,
            "helper_sha256": "7" * 64,
            "helper_size": 40,
        }

    def test_report_binds_catalogs_audit_diagnostics_locks_and_helper(self) -> None:
        report, summary, entries, evidence = self.valid_report()
        accepted.validate_catalog_replay_report(
            report,
            branch="constant",
            measurement_error_mode="quantile_matched_two_sided",
            summary=summary,
            entries=entries,
            pc_catalog=Path("PCs_dr25_hab2.csv"),
            stellar_catalog=Path("dr25_stellar_berger2020_clean_hab2.txt"),
            **evidence,
        )
        mutations = {
            "audit": ("aggregate_inputs", "perturbation_audit", "sha256"),
            "diagnostics": ("aggregate_inputs", "trial_diagnostics", "sha256"),
            "DATA_LOCKS": ("data_locks", "sha256"),
            "helper": ("verifier_source", "sha256"),
        }
        for description, keys in mutations.items():
            with self.subTest(binding=description):
                forged = copy.deepcopy(report)
                target = forged
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = "a" * 64
                with self.assertRaises(SystemExit):
                    accepted.validate_catalog_replay_report(
                        forged,
                        branch="constant",
                        measurement_error_mode="quantile_matched_two_sided",
                        summary=summary,
                        entries=entries,
                        pc_catalog=Path("PCs_dr25_hab2.csv"),
                        stellar_catalog=Path(
                            "dr25_stellar_berger2020_clean_hab2.txt"
                        ),
                        **evidence,
                    )

    def test_catalog_helper_is_loaded_from_the_stable_snapshot_path(self) -> None:
        source, digest = accepted.read_stable_regular_file(
            accepted.CATALOG_AUDIT_HELPER,
            "catalog audit helper test",
            maximum_bytes=accepted.MAX_CATALOG_AUDIT_HELPER_BYTES,
        )
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / accepted.CATALOG_AUDIT_HELPER.name
            snapshot.write_bytes(source)
            module = accepted._load_catalog_audit_module(snapshot, digest)
            self.assertEqual(Path(module.__file__).resolve(), snapshot.resolve())
            self.assertTrue(callable(module.verify_catalog_perturbations))


if __name__ == "__main__":
    unittest.main()
