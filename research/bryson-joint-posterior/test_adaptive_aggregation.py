#!/usr/bin/env python3
"""Integration tests for fail-closed adaptive-chain aggregation."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import numpy as np
import pandas as pd

import aggregate_hab2_joint_posterior as aggregator
from measurement_error import LEGACY_SOURCE_MIXTURE, QUANTILE_MATCHED_TWO_SIDED
from aggregate_hab2_joint_posterior import (
    PARAMETERS,
    StrictJSONError,
    V404_ACCEPTANCE_PROFILE,
    V404_LEGACY_SENSITIVITY_PROFILE,
    expected_bryson_source_sha256,
    expected_input_sha256,
    load_strict_json,
    sha256,
    validate_convergence_evidence,
    validate_mcse_acceptance,
)
from raw_chain_evidence import (
    RAW_CHAIN_HEADER,
    finalize_raw_chain_bundle,
    recompute_adaptive_evidence,
    write_raw_chain,
)

SCRIPTS_ROOT = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))
from verify_accepted_aggregate import (  # noqa: E402
    require_finite_number as accepted_finite_number,
    verify_locked_inputs as verify_aggregate_locked_inputs,
    verify_mcse_record as verify_aggregate_mcse_record,
)

TEST_SOURCE_SHA256 = expected_bryson_source_sha256()
TEST_INPUT_SHA256 = expected_input_sha256("constant")


class AdaptiveAggregationTests(unittest.TestCase):
    @staticmethod
    def rewrite_shard_manifest(directory: Path) -> None:
        manifest = directory / "SHA256SUMS_complete.txt"
        manifest.write_text(
            "".join(
                f"{sha256(path)}  ./{path.name}\n"
                for path in sorted(directory.iterdir(), key=lambda item: item.name)
                if path.is_file() and path != manifest
            ),
            encoding="utf-8",
        )

    def write_shards(
        self,
        root: Path,
        *,
        shard_ids: tuple[int, ...] = (0, 1),
        optimizer_failure: tuple[int, int] | None = None,
        ess_overrides: dict[tuple[int, int], list[float | None]] | None = None,
        chain_trial_seed_delta: dict[tuple[int, int], int] | None = None,
        diagnostic_seed_override: dict[tuple[int, int], int] | None = None,
        diagnostic_name_override: dict[int, str] | None = None,
        source_sha256_override: dict[int, str] | None = None,
        truncate_chain: tuple[int, int] | None = None,
        round_trip_probe: bool = False,
        tau_overrides: dict[tuple[int, int], float] | None = None,
        shard_value_offset: bool = False,
    ) -> None:
        ess_overrides = ess_overrides or {}
        chain_trial_seed_delta = chain_trial_seed_delta or {}
        diagnostic_seed_override = diagnostic_seed_override or {}
        diagnostic_name_override = diagnostic_name_override or {}
        source_sha256_override = source_sha256_override or {}
        tau_overrides = tau_overrides or {}
        for shard in shard_ids:
            directory = root / f"artifact-{shard}"
            directory.mkdir(parents=True)
            raw_directory = root.parent / "private-raw" / f"artifact-{shard}"
            raw_directory.mkdir(parents=True)
            label = f"production-shard-{shard}"
            diagnostics_name = f"trial_diagnostics_constant_{label}.json"
            rows = []
            diagnostics = []
            raw_records = []
            for trial in range(2):
                trial_seed = diagnostic_seed_override.get(
                    (shard, trial), 100 * shard + trial + 11
                )
                mcmc_seed = trial_seed + 500_003
                chain_seed = trial_seed + chain_trial_seed_delta.get((shard, trial), 0)
                rng = np.random.default_rng(10_000 + 100 * shard + trial)
                candidate_chain = rng.normal(size=(10_000, 2, 4))
                offset = float(shard) if shard_value_offset else 0.0
                for sample_index, raw_index in enumerate(range(249, 10_000, 250)):
                    for walker in range(2):
                        pattern = 0.1 * float((sample_index + walker) % 2)
                        candidate_chain[raw_index, walker] = np.asarray(
                            [1.0, -0.8, -1.0, -2.0], dtype=float
                        ) + offset + pattern
                        if (
                            round_trip_probe
                            and shard == 0
                            and trial == 0
                            and (sample_index + walker) % 2 == 1
                        ):
                            candidate_chain[raw_index, walker, 0] = np.float64(
                                "1.0999999999001921"
                            )
                candidate_log_probability = -np.sum(candidate_chain**2, axis=2)
                preview = recompute_adaptive_evidence(
                    candidate_chain,
                    minimum_steps=1000,
                    maximum_steps=10000,
                    check_interval=1000,
                    tau_multiple=100.0,
                    relative_tolerance=0.05,
                    required_stable_checks=2,
                    require_terminal_decision=False,
                )
                count = preview["first_accepted_steps"]
                if count is None:
                    raise AssertionError("Deterministic test chain did not converge")
                raw_chain = candidate_chain[:count]
                raw_log_probability = candidate_log_probability[:count]
                recomputed = recompute_adaptive_evidence(
                    raw_chain,
                    minimum_steps=1000,
                    maximum_steps=10000,
                    check_interval=1000,
                    tau_multiple=100.0,
                    relative_tolerance=0.05,
                    required_stable_checks=2,
                )
                raw_record = write_raw_chain(
                    raw_directory,
                    branch="constant",
                    run_label=label,
                    trial=trial,
                    trial_seed=trial_seed,
                    mcmc_seed=mcmc_seed,
                    chain_source_order=raw_chain,
                    log_probability=raw_log_probability,
                )
                raw_records.append(raw_record)
                raw_indices = np.arange(249, count, 250, dtype=int)
                for step_index, raw_index in enumerate(raw_indices):
                    for walker in range(2):
                        if (
                            truncate_chain == (shard, trial)
                            and step_index == len(raw_indices) - 1
                            and walker == 1
                        ):
                            continue
                        theta = raw_chain[raw_index, walker]
                        rows.append(
                            {
                                "branch": "constant",
                                "run_label": label,
                                "trial": trial,
                                "trial_seed": chain_seed,
                                "mcmc_seed": mcmc_seed,
                                "production_step": step_index * 250,
                                "walker": walker,
                                "log_probability": raw_log_probability[
                                    raw_index, walker
                                ],
                                "F0": theta[0],
                                "alpha": theta[2],
                                "beta": theta[1],
                                "gamma": theta[3],
                            }
                        )
                tau = list(recomputed["autocorrelation_time"])
                if (shard, trial) in tau_overrides:
                    tau = [tau_overrides[(shard, trial)]] * 4
                ess = list(recomputed["effective_sample_size_source_order"])
                diagnostics.append(
                    {
                        "trial": trial,
                        "seed": trial_seed,
                        "perturbation_seed": trial_seed,
                        "mcmc_seed": mcmc_seed,
                        "measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED,
                        "mean_acceptance_fraction": 0.4,
                        "runtime_seconds": 1.0,
                        "selected_after_domain": 10,
                        "optimizer_success": (shard, trial) != optimizer_failure,
                        "autocorrelation_time": tau,
                        "effective_sample_size_source_order": ess_overrides.get(
                            (shard, trial), ess
                        ),
                        "production_steps_completed": count,
                        "adaptive_production": True,
                        "converged": True,
                        "convergence_checks": recomputed["convergence_checks"],
                        "private_raw_chain": raw_record,
                    }
                )
            raw_bundle = finalize_raw_chain_bundle(
                raw_directory,
                branch="constant",
                run_label=label,
                records=raw_records,
            )
            pd.DataFrame(rows).to_csv(
                directory / f"joint_posterior_constant_{label}.csv", index=False
            )
            (directory / diagnostics_name).write_text(
                json.dumps(diagnostics), encoding="utf-8"
            )
            (directory / f"posterior_summary_constant_{label}.json").write_text(
                json.dumps(
                    {
                        "status": "production_candidate",
                        "status_assignment": {
                            "method": "explicit_cli",
                            "run_label_used_for_status": False,
                        },
                        "branch": "constant",
                        "run_label": label,
                        "period_cutoff_days": None,
                        "trials": 2,
                        "walkers": 2,
                        "burnin_steps": 10,
                        "production_steps_requested_minimum": 1000,
                        "production_steps_requested_maximum": 10000,
                        "production_steps_completed": [
                            entry["production_steps_completed"]
                            for entry in diagnostics
                        ],
                        "thin": 250,
                        "trial_diagnostics_file": diagnostic_name_override.get(
                            shard, diagnostics_name
                        ),
                        "measurement_error": {
                            "mode": QUANTILE_MATCHED_TWO_SIDED
                        },
                        "adaptive_production": {
                            "enabled": True,
                            "check_interval": 1000,
                            "tau_multiple": 100.0,
                            "tau_relative_tolerance": 0.05,
                            "required_consecutive_stable_checks": 2,
                            "converged_realizations": 2,
                        },
                        "perturbation_audit_file": (
                            f"perturbation_audit_constant_{label}.csv"
                        ),
                        "private_raw_chain_bundle": raw_bundle,
                        "input_files": {
                            key: {"path": f"/locked/{key}", "sha256": value}
                            for key, value in TEST_INPUT_SHA256.items()
                        },
                        "source_repository": "stevepur/DR25-occurrence-public",
                        "source_commit": None,
                        "source_provenance": {
                            "verified": True,
                            "verification_method": "artifact_sha256_manifest",
                            "source_repository": "stevepur/DR25-occurrence-public",
                            "source_commit": None,
                            "source_file": {
                                "relative_path": "insolation/rateModels3D.py",
                                "sha256": source_sha256_override.get(
                                    shard, TEST_SOURCE_SHA256
                                ),
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            pd.DataFrame(
                [
                    {
                        "branch": "constant",
                        "run_label": label,
                        "measurement_error_mode": QUANTILE_MATCHED_TWO_SIDED,
                        "trial": trial,
                        "trial_seed": diagnostics[trial]["perturbation_seed"],
                        "source_row": trial,
                    }
                    for trial in range(2)
                ]
            ).to_csv(
                directory / f"perturbation_audit_constant_{label}.csv",
                index=False,
            )
            pd.DataFrame(
                [{"branch": "constant", "run_label": label, "trial": 0}]
            ).to_csv(
                directory / f"perturbed_planets_constant_{label}.csv",
                index=False,
            )
            runner_manifest = directory / f"SHA256SUMS_constant_{label}.txt"
            runner_targets = [
                directory / f"joint_posterior_constant_{label}.csv",
                directory / f"perturbed_planets_constant_{label}.csv",
                directory / f"perturbation_audit_constant_{label}.csv",
                directory / diagnostics_name,
                directory / f"posterior_summary_constant_{label}.json",
            ]
            runner_manifest.write_text(
                "".join(
                    f"{sha256(path)}  {path.name}\n"
                    for path in sorted(runner_targets, key=lambda item: item.name)
                ),
                encoding="utf-8",
            )
            (directory / "numerical_environment.txt").write_text(
                "numpy==test\nscipy==test\n", encoding="utf-8"
            )
            self.rewrite_shard_manifest(directory)

    def run_aggregator(
        self,
        root: Path,
        out: Path,
        *,
        expected_shards: int = 2,
        minimum_ess: float | None = 1000.0,
        include_mcse: bool = True,
        outer_mcse_limit: float = 0.10,
        inner_mcse_limit: float = 0.05,
        steps: int = 1000,
        acceptance_profile: str | None = None,
        include_private_raw_root: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        script = Path(__file__).with_name("aggregate_hab2_joint_posterior.py")
        command = [
            sys.executable,
            *([] if __debug__ else ["-O"]),
            str(script),
            "--root",
            str(root),
            "--branch",
            "constant",
            "--out",
            str(out),
            "--expected-shards",
            str(expected_shards),
            "--trials-per-shard",
            "2",
            "--walkers",
            "2",
            "--steps",
            str(steps),
            "--runner-thin",
            "250",
            "--samples-per-realization",
            "16",
            "--require-all-converged",
            "--propagation-stride",
            "1",
            "--expected-measurement-error-mode",
            QUANTILE_MATCHED_TWO_SIDED,
            "--expected-bryson-source-sha256",
            TEST_SOURCE_SHA256,
            "--maximum-outer-q50-mcse-fraction",
            str(outer_mcse_limit),
            "--maximum-inner-q50-mcse-fraction",
            str(inner_mcse_limit),
        ]
        if include_private_raw_root:
            command.extend(
                ["--private-raw-chain-root", str(root.parent / "private-raw")]
            )
        if acceptance_profile is not None:
            command.extend(["--acceptance-profile", acceptance_profile])
        if minimum_ess is not None:
            command.extend(["--minimum-ess-per-realization", str(minimum_ess)])
        if include_mcse:
            command.extend(
                [
                    "--cluster-bootstrap-replicates",
                    "1000",
                    "--inner-chain-batches",
                    "8",
                ]
            )
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )

    def run_acceptance_verifier(
        self, out: Path
    ) -> subprocess.CompletedProcess[str]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "verify_accepted_aggregate.py"
        return subprocess.run(
            [
                sys.executable,
                str(script),
                "--artifact-root",
                str(out),
                "--branch",
                "constant",
                "--pc-catalog",
                str(out / "PCs_dr25_hab2.csv"),
                "--stellar-catalog",
                str(out / "dr25_stellar_berger2020_clean_hab2.txt"),
                "--expected-bryson-source-sha256",
                TEST_SOURCE_SHA256,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_variable_chains_pass_all_acceptance_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            out = Path(temporary) / "combined"
            self.write_shards(root)
            completed = self.run_aggregator(root, out)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(
                (out / "joint_posterior_constant_aggregate_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(summary["total_trials"], 4)
            self.assertEqual(summary["full_sample_count"], 64)
            self.assertEqual(
                summary["diagnostics"]["adaptive_realizations_converged"], 4
            )
            self.assertEqual(
                summary["diagnostics"]
                ["realizations_with_valid_effective_sample_size"],
                4,
            )
            gate = summary["production_acceptance_gate"]
            self.assertTrue(gate["required"])
            self.assertTrue(gate["accepted"])
            self.assertEqual(gate["minimum_ess_per_realization"], 1000.0)
            self.assertEqual(
                set(gate["q50_mcse_by_parameter"]),
                {"F0", "alpha", "beta", "gamma"},
            )
            verified = self.run_acceptance_verifier(out)
            self.assertNotEqual(verified.returncode, 0)
            self.assertIn("acceptance profile is not valid", verified.stderr)

            summary["production_acceptance_gate"]["accepted"] = False
            summary_path = out / "joint_posterior_constant_aggregate_summary.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path = out / "SHA256SUMS_constant_aggregate.txt"
            names = [
                line.split("  ", 1)[1]
                for line in manifest_path.read_text(encoding="utf-8").splitlines()
            ]
            manifest_path.write_text(
                "".join(f"{sha256(out / name)}  {name}\n" for name in names),
                encoding="utf-8",
            )
            rejected = self.run_acceptance_verifier(out)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not explicitly required and accepted", rejected.stderr)

    def test_acceptance_verifier_rejects_nested_unmanifested_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            out = Path(temporary) / "combined"
            self.write_shards(root)
            completed = self.run_aggregator(root, out)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            leak = out / "leak"
            leak.mkdir()
            (leak / "raw_chain.bin").write_bytes(b"private evidence")
            rejected = self.run_acceptance_verifier(out)

            self.assertNotEqual(rejected.returncode, 0)
            self.assertRegex(
                rejected.stderr, r"(?:exact flat tree|artifact root file set differs)"
            )

    def test_non_candidate_summary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("posterior_summary_constant_production-shard-0.json"))
            summary = json.loads(path.read_text(encoding="utf-8"))
            summary["status"] = "pilot_only"
            path.write_text(json.dumps(summary), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("not a production candidate", completed.stderr)

    def test_rebound_manifest_cannot_hide_ambiguous_or_overflowing_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(
                root.rglob("posterior_summary_constant_production-shard-0.json")
            )
            original = path.read_text(encoding="utf-8")
            mutations = {
                "duplicate status": original.replace(
                    '"status": "production_candidate"',
                    '"status": "pilot_only", "status": "production_candidate"',
                    1,
                ),
                "unused overflow_probe": (
                    original[:-1] + ', "overflow_probe": 1e999}'
                ),
            }
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    path.write_text(payload, encoding="utf-8")
                    self.rewrite_shard_manifest(path.parent)
                    completed = self.run_aggregator(
                        root, Path(temporary) / f"out-{label.replace(' ', '-')}"
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("invalid strict JSON", completed.stderr)
                    path.write_text(original, encoding="utf-8")
                    self.rewrite_shard_manifest(path.parent)

    def test_production_gate_requires_private_raw_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            completed = self.run_aggregator(
                root,
                Path(temporary) / "out",
                include_private_raw_root=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "requires --private-raw-chain-root", completed.stderr
            )

    def test_rebound_raw_chain_mutation_is_recomputed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            raw_directory = Path(temporary) / "private-raw" / "artifact-0"
            raw_path = (
                raw_directory
                / "raw_production_chain_constant_production-shard-0_trial-000.bin"
            )
            payload = bytearray(raw_path.read_bytes())
            selected_value_offset = RAW_CHAIN_HEADER.size + (249 * 2 * 5) * 8
            original_value = struct.unpack_from("<d", payload, selected_value_offset)[0]
            struct.pack_into(
                "<d", payload, selected_value_offset, original_value + 10.0
            )
            raw_path.write_bytes(payload)

            index_path = (
                raw_directory
                / "raw_chain_index_constant_production-shard-0.json"
            )
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["trials"][0]["sha256"] = sha256(raw_path)
            index_path.write_text(
                json.dumps(index, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            private_manifest = (
                raw_directory
                / "SHA256SUMS_raw_chain_constant_production-shard-0.txt"
            )
            private_manifest.write_text(
                "".join(
                    f"{sha256(path)}  {path.name}\n"
                    for path in sorted(
                        raw_directory.iterdir(), key=lambda item: item.name
                    )
                    if path.is_file() and path != private_manifest
                ),
                encoding="utf-8",
            )

            public_directory = root / "artifact-0"
            diagnostics_path = (
                public_directory
                / "trial_diagnostics_constant_production-shard-0.json"
            )
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            diagnostics[0]["private_raw_chain"]["sha256"] = sha256(raw_path)
            diagnostics_path.write_text(json.dumps(diagnostics), encoding="utf-8")
            summary_path = (
                public_directory
                / "posterior_summary_constant_production-shard-0.json"
            )
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["private_raw_chain_bundle"]["index_sha256"] = sha256(
                index_path
            )
            summary["private_raw_chain_bundle"]["manifest_sha256"] = sha256(
                private_manifest
            )
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            self.rewrite_shard_manifest(public_directory)

            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(
                completed.stderr,
                r"(Raw-chain tau/ESS audit failed|Serialized posterior is not)",
            )

    def test_strict_json_loader_rejects_nonfinite_constants_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.json"
            for token in ("NaN", "Infinity", "-Infinity", "1e999"):
                with self.subTest(token=token):
                    path.write_text(f'{{"probe": {token}}}', encoding="utf-8")
                    with self.assertRaises(StrictJSONError):
                        load_strict_json(path)
            path.write_bytes(b'{"probe":"\xff"}')
            with self.assertRaises(StrictJSONError):
                load_strict_json(path)

    def test_data_locks_use_strict_json_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "DATA_LOCKS.json"
            payloads = (
                '{"locks": {}, "locks": {}}',
                '{"locks": {}, "overflow_probe": 1e999}',
            )
            for payload in payloads:
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with mock.patch.object(aggregator, "DATA_LOCKS_PATH", path):
                        with self.assertRaisesRegex(
                            RuntimeError, "Cannot load production input locks"
                        ):
                            expected_input_sha256("constant")

    def test_shard_diagnostics_use_strict_json_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(
                root.rglob("trial_diagnostics_constant_production-shard-0.json")
            )
            original = path.read_text(encoding="utf-8")
            mutations = {
                "duplicate converged": original.replace(
                    '"converged": true',
                    '"converged": false, "converged": true',
                    1,
                ),
                "unused overflow_probe": original.replace(
                    "}]", ', "overflow_probe": 1e999}]', 1
                ),
            }
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    path.write_text(payload, encoding="utf-8")
                    self.rewrite_shard_manifest(path.parent)
                    completed = self.run_aggregator(
                        root,
                        Path(temporary) / f"diagnostic-out-{label.replace(' ', '-')}",
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("invalid strict JSON", completed.stderr)
                    path.write_text(original, encoding="utf-8")
                    self.rewrite_shard_manifest(path.parent)

    def test_optimizer_failure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, optimizer_failure=(1, 0))
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Optimizer failed for global trials [2]", completed.stderr)

    def test_default_minimum_ess_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, tau_overrides={(0, 0): 16.0 / 999.0})
            completed = self.run_aggregator(
                root, Path(temporary) / "out", minimum_ess=None
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Final autocorrelation-time mismatch", completed.stderr)

    def test_nonfinite_ess_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, ess_overrides={(0, 1): [None] * 4})
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("non-positive ESS for global trials [1]", completed.stderr)

    def test_missing_mcse_diagnostics_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            completed = self.run_aggregator(
                root, Path(temporary) / "out", include_mcse=False
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "requires at least 1000 --cluster-bootstrap-replicates",
                completed.stderr,
            )

    def test_q50_mcse_threshold_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, shard_value_offset=True)
            completed = self.run_aggregator(
                root,
                Path(temporary) / "out",
                outer_mcse_limit=1.0e-12,
                inner_mcse_limit=1.0e-12,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"(Outer|Inner) q50 MCSE gate failed")

    def test_nonfinite_q50_mcse_is_rejected(self) -> None:
        quantiles = {
            parameter: {"q16": 0.0, "q84": 1.0} for parameter in PARAMETERS
        }
        outer = {
            parameter: {"q50": {"standard_error": 0.01}}
            for parameter in PARAMETERS
        }
        inner = {parameter: {"q50": 0.01} for parameter in PARAMETERS}
        outer["F0"]["q50"]["standard_error"] = float("nan")
        args = SimpleNamespace(
            maximum_outer_q50_mcse_fraction=0.10,
            maximum_inner_q50_mcse_fraction=0.05,
        )
        with self.assertRaisesRegex(RuntimeError, "Non-finite or invalid"):
            validate_mcse_acceptance(quantiles, outer, inner, args)

    def test_exact_shard_id_set_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, shard_ids=(0, 2))
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Chain shard IDs mismatch", completed.stderr)
            self.assertIn("missing [1]", completed.stderr)
            self.assertIn("unexpected [2]", completed.stderr)

    def test_chain_diagnostic_seed_pairing_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, chain_trial_seed_delta={(0, 0): 1})
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "Chain/diagnostic trial_seed mismatch for shard 0, trial 0",
                completed.stderr,
            )

    def test_summary_diagnostic_filename_pairing_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(
                root,
                diagnostic_name_override={
                    0: "trial_diagnostics_constant_production-shard-1.json"
                },
            )
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Summary/diagnostic pairing mismatch", completed.stderr)

    def test_duplicate_outer_seed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(
                root,
                diagnostic_seed_override={(1, 0): 11},
            )
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Duplicate perturbation seed 11", completed.stderr)

    def test_truncated_chain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, truncate_chain=(1, 1))
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Serialized/raw-chain row count mismatch", completed.stderr)

    def test_source_provenance_hash_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root, source_sha256_override={1: "b" * 64})
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Bryson source SHA-256 mismatch", completed.stderr)

    def test_relaxed_production_thresholds_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_aggregator(
                Path(temporary) / "unused",
                Path(temporary) / "out",
                minimum_ess=5.0,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "requires minimum-ess-per-realization >= 1000",
                completed.stderr,
            )

    def test_missing_explicit_ess_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("trial_diagnostics_constant_production-shard-0.json"))
            diagnostics = json.loads(path.read_text(encoding="utf-8"))
            diagnostics[0].pop("effective_sample_size_source_order")
            path.write_text(json.dumps(diagnostics), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("non-positive ESS for global trials [0]", completed.stderr)

    def test_contradictory_convergence_checks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("trial_diagnostics_constant_production-shard-0.json"))
            diagnostics = json.loads(path.read_text(encoding="utf-8"))
            diagnostics[0]["convergence_checks"][-1]["length_ok"] = False
            path.write_text(json.dumps(diagnostics), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Convergence length gate mismatch", completed.stderr)

    def test_each_serialized_tau_check_is_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(
                root.rglob("trial_diagnostics_constant_production-shard-0.json")
            )
            diagnostics = json.loads(path.read_text(encoding="utf-8"))
            diagnostics[0]["convergence_checks"][-2]["autocorrelation_time"] = [
                1.0e9
            ] * 4
            path.write_text(json.dumps(diagnostics), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Convergence length gate mismatch", completed.stderr)

    def test_convergence_check_schedule_cannot_omit_an_interval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(
                root.rglob("trial_diagnostics_constant_production-shard-0.json")
            )
            diagnostics = json.loads(path.read_text(encoding="utf-8"))
            del diagnostics[1]["convergence_checks"][2]
            path.write_text(json.dumps(diagnostics), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Incomplete convergence-check schedule", completed.stderr)

    def test_completed_steps_must_lie_on_the_adaptive_chunk_schedule(self) -> None:
        policy = {
            "requested_minimum_steps": 4,
            "requested_maximum_steps": 16,
            "check_interval": 2,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
        }
        entry = {
            "global_trial": 0,
            "production_steps_completed": 15,
            "convergence_checks": [{}, {}, {}],
        }
        with self.assertRaisesRegex(
            RuntimeError, "Completed steps violate the adaptive schedule"
        ):
            validate_convergence_evidence(entry, policy)

    def test_convergence_checks_stop_at_first_accepted_streak(self) -> None:
        policy = {
            "requested_minimum_steps": 4,
            "requested_maximum_steps": 16,
            "check_interval": 2,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
        }
        checks = []
        for index, step in enumerate((4, 6, 8, 10)):
            checks.append(
                {
                    "production_steps": step,
                    "autocorrelation_time": [0.01] * 4,
                    "length_ok": True,
                    "stable": index > 0,
                    "max_relative_tau_change": 0.0 if index > 0 else None,
                    "stable_check_streak": index,
                }
            )
        entry = {
            "global_trial": 0,
            "production_steps_completed": 10,
            "autocorrelation_time": [0.01] * 4,
            "convergence_checks": checks,
        }
        with self.assertRaisesRegex(
            RuntimeError, "continue after the stopping gate"
        ):
            validate_convergence_evidence(entry, policy)

    def test_completed_steps_cannot_be_below_requested_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            for path in root.rglob(
                "posterior_summary_constant_production-shard-*.json"
            ):
                summary = json.loads(path.read_text(encoding="utf-8"))
                summary["production_steps_requested_minimum"] = 10000
                path.write_text(json.dumps(summary), encoding="utf-8")
                self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(
                root, Path(temporary) / "out", steps=10000
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("below the declared minimum", completed.stderr)

    def test_v404_release_profile_rejects_noncanonical_scale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_aggregator(
                Path(temporary) / "unused",
                Path(temporary) / "out",
                acceptance_profile=V404_ACCEPTANCE_PROFILE,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("v4.0.4-production profile mismatch", completed.stderr)

    def test_legacy_sensitivity_profile_has_exact_constant_branch_contract(self) -> None:
        arguments = [
            "aggregate_hab2_joint_posterior.py",
            "--root",
            "unused",
            "--branch",
            "constant",
            "--out",
            "unused-out",
            "--private-raw-chain-root",
            "unused-private",
            "--expected-shards",
            "16",
            "--trials-per-shard",
            "25",
            "--walkers",
            "16",
            "--steps",
            "3000",
            "--runner-thin",
            "20",
            "--samples-per-realization",
            "1024",
            "--require-all-converged",
            "--acceptance-profile",
            V404_LEGACY_SENSITIVITY_PROFILE,
            "--cluster-bootstrap-replicates",
            "1000",
            "--inner-chain-batches",
            "8",
            "--propagation-stride",
            "2",
            "--expected-measurement-error-mode",
            LEGACY_SOURCE_MIXTURE,
            "--expected-bryson-source-sha256",
            TEST_SOURCE_SHA256,
        ]
        with mock.patch.object(sys, "argv", arguments):
            parsed = aggregator.parse_args()
        self.assertEqual(parsed.branch, "constant")
        self.assertEqual(
            parsed.expected_measurement_error_mode, LEGACY_SOURCE_MIXTURE
        )

        corrected = list(arguments)
        corrected[corrected.index(LEGACY_SOURCE_MIXTURE)] = QUANTILE_MATCHED_TWO_SIDED
        with mock.patch.object(sys, "argv", corrected), self.assertRaises(SystemExit):
            aggregator.parse_args()

        zero = list(arguments)
        zero[zero.index("constant")] = "zero"
        with mock.patch.object(sys, "argv", zero), self.assertRaises(SystemExit):
            aggregator.parse_args()

    def test_accepted_verifier_rejects_nan_and_string_numbers(self) -> None:
        for value in (float("nan"), "nan", "1000"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                accepted_finite_number(value, "probe")

    def test_accepted_verifier_requires_complete_mcse_evidence(self) -> None:
        with self.assertRaises(SystemExit):
            verify_aggregate_mcse_record(
                {
                    "q50_mcse_by_parameter": {
                        parameter: {} for parameter in PARAMETERS
                    }
                }
            )

    def test_accepted_verifier_requires_exact_locked_inputs(self) -> None:
        with self.assertRaises(SystemExit):
            verify_aggregate_locked_inputs(
                {"locked_input_sha256": {"unrelated": "truthy"}}, "constant"
            )

    def test_status_assignment_must_be_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("posterior_summary_constant_production-shard-0.json"))
            summary = json.loads(path.read_text(encoding="utf-8"))
            summary["status_assignment"]["method"] = "safe_default"
            path.write_text(json.dumps(summary), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Invalid production status assignment", completed.stderr)

    def test_branch_specific_input_hash_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("posterior_summary_constant_production-shard-1.json"))
            summary = json.loads(path.read_text(encoding="utf-8"))
            summary["input_files"]["completeness"]["sha256"] = "b" * 64
            path.write_text(json.dumps(summary), encoding="utf-8")
            self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Locked input SHA-256 mismatch", completed.stderr)

    def test_complete_shard_manifest_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            environment = root / "artifact-1" / "numerical_environment.txt"
            environment.write_text("tampered\n", encoding="utf-8")
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Complete shard manifest SHA-256 mismatch", completed.stderr)

    def test_complete_shard_manifest_rejects_nested_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            leak = root / "artifact-0" / "private"
            leak.mkdir()
            (leak / "raw-chain.bin").write_bytes(b"private evidence")

            completed = self.run_aggregator(root, Path(temporary) / "out")

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("exact flat tree", completed.stderr)

    def test_manifest_bound_chain_uses_round_trip_float_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            out = Path(temporary) / "out"
            self.write_shards(root, round_trip_probe=True)

            completed = self.run_aggregator(root, out)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            frame = pd.read_csv(
                out / "joint_posterior_constant_full.csv.gz",
                float_precision="round_trip",
            )
            expected_bits = np.float64("1.0999999999001921").view(np.uint64)
            observed_bits = frame["F0"].to_numpy(dtype=np.float64).view(np.uint64)
            self.assertIn(expected_bits, observed_bits)

    def test_chain_path_swap_after_raw_audit_cannot_change_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            out = Path(temporary) / "out"
            self.write_shards(root)
            args = SimpleNamespace(
                root=root,
                branch="constant",
                out=out,
                expected_shards=2,
                trials_per_shard=2,
                walkers=2,
                steps=1000,
                runner_thin=250,
                samples_per_realization=16,
                require_all_converged=True,
                acceptance_profile=aggregator.CUSTOM_ACCEPTANCE_PROFILE,
                minimum_ess_per_realization=1000.0,
                maximum_outer_q50_mcse_fraction=0.10,
                maximum_inner_q50_mcse_fraction=0.05,
                cluster_bootstrap_replicates=1000,
                bootstrap_seed=2026082101,
                inner_chain_batches=8,
                expected_measurement_error_mode=QUANTILE_MATCHED_TWO_SIDED,
                expected_bryson_source_sha256=TEST_SOURCE_SHA256,
                propagation_stride=1,
                private_raw_chain_root=root.parent / "private-raw",
            )
            real_audit = aggregator.audit_private_raw_chains

            def audit_then_swap(**kwargs):
                result = real_audit(**kwargs)
                chain_path = root / "artifact-0" / (
                    "joint_posterior_constant_production-shard-0.csv"
                )
                changed = pd.read_csv(chain_path, float_precision="round_trip")
                changed.loc[:, "F0"] = 1.0e9
                changed.to_csv(chain_path, index=False)
                return result

            with mock.patch.object(
                aggregator, "parse_args", return_value=args
            ), mock.patch.object(
                aggregator,
                "audit_private_raw_chains",
                side_effect=audit_then_swap,
            ), mock.patch("sys.stdout", new=io.StringIO()):
                aggregator.main()

            frame = pd.read_csv(
                out / "joint_posterior_constant_full.csv.gz",
                float_precision="round_trip",
            )
            self.assertLess(float(frame["F0"].max()), 1.0e8)

    def test_large_distinct_integer_seeds_do_not_collapse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(
                root,
                diagnostic_seed_override={
                    (0, 0): 2**53,
                    (0, 1): 2**53 + 1,
                },
            )
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
