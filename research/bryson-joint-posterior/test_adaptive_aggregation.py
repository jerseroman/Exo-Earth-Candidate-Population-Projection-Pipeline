#!/usr/bin/env python3
"""Integration tests for fail-closed adaptive-chain aggregation."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import pandas as pd

from measurement_error import QUANTILE_MATCHED_TWO_SIDED
from aggregate_hab2_joint_posterior import (
    PARAMETERS,
    V404_ACCEPTANCE_PROFILE,
    expected_bryson_source_sha256,
    expected_input_sha256,
    sha256,
    validate_convergence_evidence,
    validate_mcse_acceptance,
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
            label = f"production-shard-{shard}"
            diagnostics_name = f"trial_diagnostics_constant_{label}.json"
            rows = []
            diagnostics = []
            for trial, count in enumerate((8, 16)):
                trial_seed = diagnostic_seed_override.get(
                    (shard, trial), 100 * shard + trial + 11
                )
                mcmc_seed = trial_seed + 500_003
                chain_seed = trial_seed + chain_trial_seed_delta.get((shard, trial), 0)
                for step in range(count):
                    for walker in range(2):
                        if (
                            truncate_chain == (shard, trial)
                            and step == count - 1
                            and walker == 1
                        ):
                            continue
                        row = step * 2 + walker
                        pattern = float((step + walker) % 2)
                        offset = float(shard) if shard_value_offset else 0.0
                        rows.append(
                            {
                                "branch": "constant",
                                "run_label": label,
                                "trial": trial,
                                "trial_seed": chain_seed,
                                "mcmc_seed": mcmc_seed,
                                "production_step": step,
                                "walker": walker,
                                "log_probability": -1.0 - 0.01 * row,
                                "F0": 1.0 + offset + 0.1 * pattern,
                                "alpha": -1.0 + offset + 0.1 * pattern,
                                "beta": -0.8 + offset + 0.1 * pattern,
                                "gamma": -2.0 + offset + 0.1 * pattern,
                            }
                        )
                tau = tau_overrides.get((shard, trial), 0.01)
                ess = float(2 * count / tau)
                check_steps = list(range(4, count + 1, 2))
                check_taus = [
                    (
                        tau
                        if index >= len(check_steps) - 3
                        else tau * (1.8 - 0.2 * index)
                    )
                    for index in range(len(check_steps))
                ]
                convergence_checks = []
                previous_tau = None
                stable_streak = 0
                for production_steps, check_tau in zip(check_steps, check_taus):
                    stable = bool(
                        previous_tau is not None
                        and abs(check_tau - previous_tau) / check_tau <= 0.05
                    )
                    length_ok = bool(production_steps >= 100.0 * check_tau)
                    stable_streak = (
                        stable_streak + 1 if stable and length_ok else 0
                    )
                    convergence_checks.append(
                        {
                            "production_steps": production_steps,
                            "autocorrelation_time": [check_tau] * 4,
                            "length_ok": length_ok,
                            "stable": stable,
                            "max_relative_tau_change": (
                                abs(check_tau - previous_tau) / check_tau
                                if previous_tau is not None
                                else None
                            ),
                            "stable_check_streak": stable_streak,
                        }
                    )
                    previous_tau = check_tau
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
                        "autocorrelation_time": [tau] * 4,
                        "effective_sample_size_source_order": ess_overrides.get(
                            (shard, trial), [ess] * 4
                        ),
                        "production_steps_completed": count,
                        "adaptive_production": True,
                        "converged": True,
                        "convergence_checks": convergence_checks,
                    }
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
                        "production_steps_requested_minimum": 4,
                        "production_steps_requested_maximum": 16,
                        "production_steps_completed": [8, 16],
                        "thin": 1,
                        "trial_diagnostics_file": diagnostic_name_override.get(
                            shard, diagnostics_name
                        ),
                        "measurement_error": {
                            "mode": QUANTILE_MATCHED_TWO_SIDED
                        },
                        "adaptive_production": {
                            "enabled": True,
                            "check_interval": 2,
                            "tau_multiple": 100.0,
                            "tau_relative_tolerance": 0.05,
                            "required_consecutive_stable_checks": 2,
                            "converged_realizations": 2,
                        },
                        "perturbation_audit_file": (
                            f"perturbation_audit_constant_{label}.csv"
                        ),
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
        steps: int = 4,
        acceptance_profile: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        script = Path(__file__).with_name("aggregate_hab2_joint_posterior.py")
        command = [
            sys.executable,
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
            "1",
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

    def test_non_candidate_summary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "shards"
            self.write_shards(root)
            path = next(root.rglob("posterior_summary_constant_production-shard-0.json"))
            summary = json.loads(path.read_text(encoding="utf-8"))
            summary["status"] = "pilot_only"
            path.write_text(json.dumps(summary), encoding="utf-8")
            completed = self.run_aggregator(root, Path(temporary) / "out")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("not a production candidate", completed.stderr)

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
            self.assertIn("Minimum ESS below 1000", completed.stderr)

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
            self.assertIn("Chain row count mismatch", completed.stderr)

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
                summary["production_steps_requested_minimum"] = 12
                path.write_text(json.dumps(summary), encoding="utf-8")
                self.rewrite_shard_manifest(path.parent)
            completed = self.run_aggregator(
                root, Path(temporary) / "out", steps=12
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
