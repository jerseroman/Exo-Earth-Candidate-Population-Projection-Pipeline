from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np
import pandas as pd

import freeze_v4_numerical_results as freeze


CORRECTION_POLICY = {
    "applied": False,
    "publishable": False,
    "role": "EXCLUDED_OPEN_SYSTEMATIC",
    "interpretation": (
        "The independently verified differential correction is not publishable, "
        "is not applied to the host selector, and remains an explicit host-model "
        "systematic."
    ),
}


class FreezeV4NumericalResultsTests(unittest.TestCase):
    @staticmethod
    def computational_source(digit: str = "1") -> dict[str, object]:
        return {
            "commit": digit * 40,
            "tree": "2" * 40,
            "archive_sha256": "3" * 64,
            "archive_size_bytes": 1234,
        }

    @classmethod
    def source_state(cls, digit: str = "1") -> dict[str, object]:
        source = cls.computational_source(digit)
        record = {
            "repository": "fixture/repository",
            "commit_sha": source["commit"],
            "git_tree_sha": source["tree"],
            "source_archive": {
                "sha256": source["archive_sha256"],
                "size_bytes": source["archive_size_bytes"],
            },
        }
        return {"public_source": dict(record), "private_source": dict(record)}

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def test_external_contract_accepts_only_hash_locked_promoted_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "HOST_QUALIFICATION.json"
            self.write_json(
                report_path, {"qualification_id": "sha256:" + "4" * 64}
            )
            report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            contract_path = root / "HOST_CONTRACT.json"
            accepted = {
                "artifact_sets": [
                    {
                        "id": "candidate-a",
                        "production_accepted": True,
                        "qualification_report": {
                            "path": report_path.name,
                            "sha256": report_sha,
                        },
                    }
                ]
            }
            self.write_json(contract_path, accepted)
            contract = freeze.read_file_snapshot(contract_path, "contract")
            report = freeze.read_file_snapshot(report_path, "report")
            evidence = freeze.validate_external_contract_report_pair(
                "host", contract, report
            )
            self.assertEqual(evidence["report_sha256"], report.sha256)
            self.assertEqual(evidence["contract_sha256"], contract.sha256)

            accepted["artifact_sets"][0].update(
                {"production_accepted": False, "qualification_report": None}
            )
            self.write_json(contract_path, accepted)
            pending = freeze.read_file_snapshot(contract_path, "pending contract")
            with self.assertRaisesRegex(RuntimeError, "production-accepted"):
                freeze.validate_external_contract_report_pair(
                    "host", pending, report
                )

    def test_external_lock_rejects_wrong_hash_size_swap_symlink_and_reparse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "evidence.json"
            path.write_bytes(b'{"status":"accepted"}\n')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            size = path.stat().st_size
            with self.assertRaisesRegex(RuntimeError, "explicit external evidence lock"):
                freeze.validate_external_evidence_lock(
                    path,
                    expected_sha256="0" * 64,
                    expected_size_bytes=size,
                    label="fixture",
                )
            with self.assertRaisesRegex(RuntimeError, "explicit external evidence lock"):
                freeze.validate_external_evidence_lock(
                    path,
                    expected_sha256=digest,
                    expected_size_bytes=size + 1,
                    label="fixture",
                )
            snapshot = freeze.validate_external_evidence_lock(
                path,
                expected_sha256=digest,
                expected_size_bytes=size,
                label="fixture",
            )
            path.write_bytes(b'{"status":"swapped"}\n')
            with self.assertRaisesRegex(RuntimeError, "changed after"):
                freeze.recheck_external_evidence_locks({"fixture": snapshot})

            target = root / "target.json"
            target.write_bytes(b"{}\n")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                    freeze.validate_external_evidence_lock(
                        link,
                        expected_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                        expected_size_bytes=target.stat().st_size,
                        label="symlink fixture",
                    )

            ordinary = target.lstat()
            fake_reparse = SimpleNamespace(
                st_mode=ordinary.st_mode,
                st_file_attributes=0x400,
            )
            with mock.patch.object(Path, "lstat", return_value=fake_reparse):
                with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                    freeze.validate_external_evidence_lock(
                        target,
                        expected_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                        expected_size_bytes=target.stat().st_size,
                        label="reparse fixture",
                    )

    def test_signed_source_identity_and_all_four_role_gate_fail_closed(self) -> None:
        source_state = self.source_state()
        encoded = base64.b64encode(
            json.dumps(
                {"source_state": source_state},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii")
        report = {
            "fresh_repetitions": [
                {
                    "embedded_signed_evidence": {
                        freeze.HOST_START_CHALLENGE_NAME: encoded
                    }
                },
                {
                    "embedded_signed_evidence": {
                        freeze.HOST_START_CHALLENGE_NAME: encoded
                    }
                },
            ]
        }
        expected = self.computational_source()
        self.assertEqual(freeze.host_qualification_source_identity(report), expected)
        all_sources = {
            role: dict(expected) for role in ("host", "age", "radial", "local")
        }
        self.assertEqual(
            freeze.require_identical_computational_source(all_sources), expected
        )
        all_sources["age"]["commit"] = "9" * 40
        with self.assertRaisesRegex(RuntimeError, "mixed computational source"):
            freeze.require_identical_computational_source(all_sources)
        with self.assertRaisesRegex(RuntimeError, "all host/age/radial/local"):
            freeze.require_identical_computational_source({"local": expected})

        mixed_state = self.source_state("9")
        mixed_encoded = base64.b64encode(
            json.dumps(
                {"source_state": mixed_state},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii")
        report["fresh_repetitions"][1]["embedded_signed_evidence"][
            freeze.HOST_START_CHALLENGE_NAME
        ] = mixed_encoded
        with self.assertRaisesRegex(RuntimeError, "mixed computational sources"):
            freeze.host_qualification_source_identity(report)

    def test_external_lock_is_fail_closed_under_optimized_python(self) -> None:
        module_root = Path(freeze.__file__).resolve().parent
        code = (
            "import pathlib,tempfile,freeze_v4_numerical_results as f;"
            "p=pathlib.Path(tempfile.mkdtemp())/'x';p.write_bytes(b'x');"
            "\ntry:f.validate_external_evidence_lock(p,expected_sha256='0'*64,"
            "expected_size_bytes=1,label='optimized')\n"
            "except RuntimeError:raise SystemExit(0)\n"
            "raise SystemExit(7)"
        )
        process = subprocess.run(
            [sys.executable, "-O", "-c", code],
            cwd=module_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            process.returncode,
            0,
            process.stderr.decode("utf-8", errors="replace"),
        )

    def test_catalog_replay_is_bound_to_exact_freeze_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {}
            for name, payload in (
                ("audit.csv.gz", b"audit-bytes"),
                ("diagnostics.jsonl", b"diagnostic-bytes"),
                ("pc.csv", b"pc-bytes"),
                ("stellar.csv", b"stellar-bytes"),
                ("DATA_LOCKS.json", b"locks-bytes"),
            ):
                path = root / name
                path.write_bytes(payload)
                files[name] = freeze.read_file_snapshot(path, name)
            module_snapshot = freeze.read_file_snapshot(
                Path(freeze.__file__).resolve().parent
                / "catalog_perturbation_audit.py",
                "catalog replay helper",
            )

            class ReplayModule:
                PC_LOCK_ID = "bryson_pc_catalog"
                STELLAR_LOCK_ID = "bryson_stellar_catalog_extracted"

                @staticmethod
                def verify_catalog_perturbations(**kwargs):
                    self.assertEqual(kwargs["expected_trials"], 400)
                    self.assertEqual(
                        kwargs["measurement_error_mode"],
                        freeze.QUANTILE_MATCHED_TWO_SIDED,
                    )
                    aggregate = kwargs["aggregate_root"]
                    audit_path = aggregate / "perturbation_audit_constant_full.csv.gz"
                    diagnostic_path = aggregate / "trial_diagnostics_constant_full.jsonl"
                    return {
                        "audit_id": "sha256:" + "1" * 64,
                        "status": "PASS",
                        "branch": "constant",
                        "measurement_error_mode": freeze.QUANTILE_MATCHED_TWO_SIDED,
                        "trials_verified": 400,
                        "audit_rows_verified": 10,
                        "seed_schedule_sha256": "2" * 64,
                        "count_projection_sha256": "3" * 64,
                        "aggregate_inputs": {
                            "perturbation_audit": {
                                "sha256": freeze.sha256(audit_path)
                            },
                            "trial_diagnostics": {
                                "sha256": freeze.sha256(diagnostic_path)
                            },
                        },
                        "locked_inputs": {
                            ReplayModule.PC_LOCK_ID: {
                                "sha256": freeze.sha256(kwargs["pc_catalog"])
                            },
                            ReplayModule.STELLAR_LOCK_ID: {
                                "sha256": freeze.sha256(kwargs["stellar_catalog"])
                            },
                        },
                        "data_locks": {
                            "sha256": freeze.sha256(kwargs["data_locks_path"])
                        },
                        "verifier_source": {"sha256": module_snapshot.sha256},
                    }

            with mock.patch.object(
                freeze,
                "_load_python_module_from_snapshot",
                return_value=(ReplayModule, module_snapshot),
            ):
                report, evidence = freeze.validate_catalog_perturbation_replay(
                    branch="constant",
                    aggregate_root=root,
                    perturbation_audit_snapshot=files["audit.csv.gz"],
                    diagnostics_snapshot=files["diagnostics.jsonl"],
                    pc_catalog_snapshot=files["pc.csv"],
                    stellar_catalog_snapshot=files["stellar.csv"],
                    data_locks_snapshot=files["DATA_LOCKS.json"],
                )
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(evidence["exact_catalog_replay"])
            self.assertEqual(
                evidence["perturbation_audit_sha256"], files["audit.csv.gz"].sha256
            )

    def test_legacy_sensitivity_freeze_hook_is_exact_and_separate(self) -> None:
        aggregate = {
            "branch": "constant",
            "measurement_error": {
                "mode": freeze.LEGACY_SOURCE_MIXTURE,
                "source_faithful": True,
                "post_perturbation_teff_filter": False,
            },
            "shards": 16,
            "trials_per_shard": 25,
            "total_trials": 400,
            "walkers": 16,
            "burnin_steps": 1000,
            "production_steps_requested_minimum": 3000,
            "runner_thin": 20,
            "equalized_samples_per_realization": 1024,
            "full_sample_count": 409600,
            "propagation_stride_within_each_realization": 2,
            "galactic_propagation_sample_count": 204800,
            "parameter_order": ["F0", "alpha_radius", "beta_inst", "gamma"],
            "source_provenance": {"verified_for_every_shard": True},
            "production_acceptance_gate": {
                "required": True,
                "accepted": True,
                "profile": freeze.V404_LEGACY_SENSITIVITY_PROFILE,
                "minimum_ess_per_realization": 1000.0,
            },
            "raw_unthinned_chain_acceptance_gate": {
                "required": True,
                "verified": True,
                "raw_files_copied_to_public_artifact": False,
                "trials_verified": 400,
                "global_trial_identity_sha256": "1" * 64,
                "evidence_report_sha256": "2" * 64,
                "audit_helper_sha256": "3" * 64,
            },
        }
        with self.assertRaisesRegex(RuntimeError, "diagnostics are missing"):
            freeze.validate_aggregate(
                "constant",
                aggregate,
                expected_measurement_mode=freeze.LEGACY_SOURCE_MIXTURE,
                expected_acceptance_profile=freeze.V404_LEGACY_SENSITIVITY_PROFILE,
            )
        with self.assertRaisesRegex(RuntimeError, "Unexpected measurement mode"):
            freeze.validate_aggregate("constant", aggregate)

        aggregate["production_acceptance_gate"]["profile"] = (
            freeze.V404_ACCEPTANCE_PROFILE
        )
        with self.assertRaisesRegex(
            RuntimeError, "Legacy measurement sensitivity profile binding failed"
        ):
            freeze.validate_aggregate(
                "constant",
                aggregate,
                expected_measurement_mode=freeze.LEGACY_SOURCE_MIXTURE,
                expected_acceptance_profile=freeze.V404_ACCEPTANCE_PROFILE,
            )

    @staticmethod
    def make_host_root(root: Path, extra_text: str = "") -> dict[str, object]:
        audit = {
            "status": freeze.EXPECTED_HOST_STATUS,
            "metallicity_correction_policy": CORRECTION_POLICY,
            "note": extra_text,
        }
        audit_path = root / freeze.HOST_AUDIT_NAME
        table_path = root / freeze.HOST_SELECTOR_TABLE_NAME
        audit_path.write_text(json.dumps(audit), encoding="utf-8")
        table_path.write_text("selector,N_star\ncanonical,1\n", encoding="utf-8")
        (root / freeze.HOST_AUDIT_MANIFEST_NAME).write_text(
            f"{freeze.sha256(audit_path)}  {audit_path.name}\n"
            f"{freeze.sha256(table_path)}  {table_path.name}\n",
            encoding="utf-8",
        )
        return audit

    def test_host_root_requires_exact_manifest_status_and_no_retracted_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_host_root(root)
            audit, evidence = freeze.validate_host_tams_audit_root(root)
            self.assertEqual(audit["status"], freeze.EXPECTED_HOST_STATUS)
            self.assertEqual(
                set(evidence["validated_files"]),
                {freeze.HOST_AUDIT_NAME, freeze.HOST_SELECTOR_TABLE_NAME},
            )
            (root / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                freeze.validate_host_tams_audit_root(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_host_root(root, freeze.RETRACTED_METALLICITY_ANCHOR_NAME)
            with self.assertRaises(RuntimeError):
                freeze.validate_host_tams_audit_root(root)

    def test_freeze_cross_checks_all_actual_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots, inputs = {}, {}
            evidence = {"canonical": {}, "legacy": {}}
            names = {
                ("canonical", "constant"): "canonical_constant",
                ("canonical", "zero"): "canonical_zero",
                ("legacy", "constant"): "legacy_constant",
                ("legacy", "zero"): "legacy_zero",
            }
            for index, (key, name) in enumerate(names.items()):
                artifact_root = root / f"propagation-{index}"
                artifact_root.mkdir()
                roots[key] = artifact_root
                summary_sha = f"{index + 1:x}" * 64
                summary_sha = summary_sha[:64]
                manifest_sha = f"{index + 5:x}" * 64
                manifest_sha = manifest_sha[:64]
                inputs[name] = {
                    "artifact_root": str(artifact_root),
                    "sha256": summary_sha,
                    "manifest_sha256": manifest_sha,
                }
                selector, branch = key
                evidence[selector][branch] = {
                    "summary_sha256": summary_sha,
                    "manifest_sha256": manifest_sha,
                    "collapsed_host_sha256": "1" * 64 if selector == "canonical" else "2" * 64,
                    "distinct_host_temperatures": 539 if selector == "canonical" else 536,
                    "host_count": 263061992.36674237 if selector == "canonical" else 196679892.57673854,
                    "posterior_artifact": {"sha256": "a" * 64 if branch == "constant" else "b" * 64, "size_bytes": 10, "row_count": 204800},
                    "host_artifact": {"sha256": "c" * 64 if selector == "canonical" else "d" * 64, "size_bytes": 20, "row_count": 30},
                }
            parent = {
                "filename": "jj_g_hosts_parent_prelogg_padova.csv",
                "sha256": "e" * 64,
                "size_bytes": 100,
                "row_count": 200,
                "feh_min": -1.0,
                "feh_max": 0.5,
            }
            inputs.update(
                {
                    "host_artifact_contract": {
                        "contract_sha256": "3" * 64,
                        "contract_verifier_sha256": "4" * 64,
                        "manifest_sha256": "5" * 64,
                        "artifact_set_id": "qualified-r4",
                        "representation_match": "exact",
                        "production_accepted": True,
                        "raw_parent_projection_sha256": "6" * 64,
                        "qualification_reports": {"qualification.json": "7" * 64},
                    },
                    "parent": dict(parent),
                    "constant_posterior_samples": evidence["canonical"]["constant"]["posterior_artifact"],
                    "zero_posterior_samples": evidence["canonical"]["zero"]["posterior_artifact"],
                    "canonical_hosts": evidence["canonical"]["constant"]["host_artifact"],
                    "legacy_hosts": evidence["legacy"]["constant"]["host_artifact"],
                    "native_solar_tams_points": {"sha256": "f" * 64},
                }
            )
            metallicity_report = {"status": "FAIL_NOT_PUBLISHABLE"}
            metallicity_evidence = {
                "report_sha256": "9" * 64,
                "native_solar_tams_points_sha256": "f" * 64,
            }
            host_audit = {
                "inputs": inputs,
                "verified_metallicity_artifact": dict(metallicity_evidence),
                "metallicity_dependent_TAMS_audit": metallicity_report,
                "derived_collapsed_host_measures": {
                    "canonical": {"csv_sha256": "1" * 64, "row_count": 539, "N_star": 263061992.36674237},
                    "legacy": {"csv_sha256": "2" * 64, "row_count": 536, "N_star": 196679892.57673854},
                },
            }
            host_contract = dict(inputs["host_artifact_contract"])
            freeze.cross_check_fresh_freeze_inputs(
                host_audit, roots, evidence, metallicity_report,
                metallicity_evidence, parent, host_contract,
            )
            host_audit["inputs"]["legacy_zero"]["manifest_sha256"] = "0" * 64
            with self.assertRaises(RuntimeError):
                freeze.cross_check_fresh_freeze_inputs(
                    host_audit, roots, evidence, metallicity_report,
                    metallicity_evidence, parent, host_contract,
                )

    @staticmethod
    def make_aggregate_root(root: Path, branch: str) -> Path:
        posterior = pd.DataFrame(
            {
                "branch": [branch] * 4,
                "global_trial": [0, 0, 1, 1],
                "F0": [1.0, 1.1, 1.2, 1.3],
                "alpha": [-1.2, -1.1, -1.0, -0.9],
                "beta": [-1.0, -0.9, -0.8, -0.7],
                "gamma": [-3.0, -2.9, -2.8, -2.7],
            }
        )
        names = freeze.aggregate_target_names(branch)
        for name in names:
            path = root / name
            if name.endswith("for_galactic_propagation.csv.gz"):
                posterior.to_csv(path, index=False, compression={"method": "gzip", "mtime": 0})
            elif name.endswith("aggregate_summary.json"):
                path.write_text(json.dumps({"branch": branch}), encoding="utf-8")
            else:
                path.write_bytes(b"fixture\n")
        manifest = root / f"SHA256SUMS_{branch}_aggregate.txt"
        manifest.write_text(
            "".join(f"{freeze.sha256(root / name)}  {name}\n" for name in names),
            encoding="utf-8",
        )
        return root

    def test_aggregate_root_is_exact_and_quantiles_come_from_actual_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_aggregate_root(Path(temporary), "constant")
            verifier = SimpleNamespace(
                expected_bryson_source_sha256=lambda: "a" * 64,
                verify_manifest=lambda artifact_root, branch: {},
                verify_summary=lambda artifact_root, branch, source, entries: None,
            )
            verifier_snapshot = freeze.read_file_snapshot(
                Path(freeze.__file__).resolve().parents[2]
                / "scripts"
                / "verify_accepted_aggregate.py",
                "fixture verifier",
            )
            with mock.patch.object(
                freeze,
                "_load_python_module_from_snapshot",
                return_value=(verifier, verifier_snapshot),
            ):
                summary, evidence, snapshots = freeze.validate_aggregate_artifact_root(
                    root, "constant"
                )
            self.assertEqual(summary, {"branch": "constant"})
            self.assertEqual(
                snapshots["propagation"].sha256,
                evidence["propagation_samples_sha256"],
            )

            (root / "extra.txt").write_text("extra\n", encoding="utf-8")
            with mock.patch.object(
                freeze,
                "_load_python_module_from_snapshot",
                return_value=(verifier, verifier_snapshot),
            ), self.assertRaises(RuntimeError):
                freeze.validate_aggregate_artifact_root(root, "constant")

    @staticmethod
    def seed_report(branch: str) -> dict[str, object]:
        families = {}
        base = 2026082101 + (100000 if branch == "zero" else 0)
        for number, offset in ((1, 500000003), (2, 900000007)):
            name = f"corrected-pilot-seed-{number}"
            shift = 0.01 * number
            families[name] = {
                "chain_file": f"chain-{number}.csv",
                "chain_sha256": str(number) * 64,
                "mcmc_seeds": [base + offset + trial * 1_000_003 for trial in range(3)],
                "production_steps": [3000, 4000, 5000],
                "posterior_quantiles": {
                    parameter: {"q2.5": 0.5 + shift, "q16": 0.8 + shift, "q50": 1.0 + shift, "q84": 1.2 + shift, "q97.5": 1.5 + shift}
                    for parameter in freeze.PARAMETERS
                },
            }
        stability = {}
        for parameter in freeze.PARAMETERS:
            combined = {"q2.5": 0.5, "q16": 0.8, "q50": 1.0, "q84": 1.2, "q97.5": 1.5}
            width = combined["q84"] - combined["q16"]
            differences = {}
            for quantile in ("q16", "q50", "q84"):
                values = [families[name]["posterior_quantiles"][parameter][quantile] for name in sorted(families)]
                value_range = max(values) - min(values)
                differences[quantile] = {"absolute_family_range": value_range, "fraction_of_combined_q16_q84_width": value_range / width}
            stability[parameter] = {
                "combined_quantiles": combined,
                "family_differences": differences,
                "maximum_width_fraction": max(value["fraction_of_combined_q16_q84_width"] for value in differences.values()),
                "passed": True,
            }
        return {
            "status": "pass", "branch": branch,
            "outer_realizations_identical_across_families": True,
            "independent_mcmc_seed_families": True,
            "all_trials_converged": True,
            "equalized_samples_per_outer_realization": 1600,
            "maximum_allowed_quantile_width_fraction": 0.15,
            "families": families, "stability": stability, "gate_failures": [],
        }

    def test_seed_stability_recomputes_exact_schedule_and_differences(self) -> None:
        report = self.seed_report("constant")
        report["schema_version"] = 2
        report["adaptive_production_policy"] = {
            "requested_minimum_steps": 3000,
            "requested_maximum_steps": 20000,
            "check_interval": 1000,
            "tau_multiple": 100.0,
            "tau_relative_tolerance": 0.05,
            "required_consecutive_stable_checks": 2,
            "walkers": 16,
            "runner_thin": 20,
        }
        snapshots = {
            name: freeze.FileSnapshot(Path(name), b"fixture", "a" * 64, 7)
            for name in freeze.seed_stability_target_names("constant")
        }
        for family_name, family in report["families"].items():
            family["chain_file"] = f"joint_posterior_constant_{family_name}.csv"
            for role in ("diagnostics", "planets", "perturbation_audit"):
                if role == "diagnostics":
                    filename = f"trial_diagnostics_constant_{family_name}.json"
                elif role == "planets":
                    filename = f"perturbed_planets_constant_{family_name}.csv"
                else:
                    filename = f"perturbation_audit_constant_{family_name}.csv"
                family[f"{role}_file"] = filename
                family[f"{role}_sha256"] = snapshots[filename].sha256
            family["chain_sha256"] = snapshots[family["chain_file"]].sha256
        report["families"]["corrected-pilot-seed-1"]["chain_sha256"] = int("1" * 64)
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            freeze.validate_seed_stability("constant", report, snapshots)

    def test_likelihood_wrapper_passes_exact_source_and_completeness_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "selected_joint_parameter_points.csv"
            report_path = root / "LIKELIHOOD_GRID_CONVERGENCE.json"
            selected.write_text("fixture\n", encoding="utf-8")
            report_path.write_text("{}\n", encoding="utf-8")
            manifest = root / "SHA256SUMS_likelihood_grid_convergence.txt"
            manifest.write_text(
                f"{freeze.sha256(selected)}  {selected.name}\n"
                f"{freeze.sha256(report_path)}  {report_path.name}\n",
                encoding="utf-8",
            )
            source = freeze.FileSnapshot(Path("rateModels3D.py"), b"source", "1" * 64, 6)
            completeness = freeze.FileSnapshot(Path("completeness.fits.gz"), b"fits", "2" * 64, 4)
            posterior = freeze.FileSnapshot(Path("posterior.csv.gz"), b"posterior", "3" * 64, 9)
            aggregate_manifest = freeze.FileSnapshot(Path("aggregate.txt"), b"manifest", "4" * 64, 8)

            def verify(_root, **kwargs):
                self.assertEqual(kwargs["rate_model_source_path"].read_bytes(), b"source")
                self.assertEqual(kwargs["completeness_path"].read_bytes(), b"fits")
                self.assertEqual(kwargs["posterior_path"].read_bytes(), b"posterior")
                self.assertEqual(kwargs["aggregate_manifest_path"].read_bytes(), b"manifest")
                return {
                    "status": "PASS",
                    "branch": "constant",
                    "selected_points": {},
                    "results": {},
                }

            module = SimpleNamespace(verify_likelihood_grid_artifact=verify)
            module_snapshot = freeze.read_file_snapshot(
                Path(freeze.__file__).resolve().parent / "likelihood_grid_convergence.py",
                "likelihood verifier fixture",
            )
            with mock.patch.object(
                freeze,
                "_load_python_module_from_snapshot",
                return_value=(module, module_snapshot),
            ):
                _, evidence = freeze.validate_likelihood_grid_root(
                    root,
                    branch="constant",
                    full_snapshot=posterior,
                    aggregate_manifest_snapshot=aggregate_manifest,
                    rate_model_source_snapshot=source,
                    completeness_snapshot=completeness,
                )
            self.assertEqual(evidence["rate_model_source_sha256"], "1" * 64)
            self.assertEqual(evidence["completeness_sha256"], "2" * 64)


if __name__ == "__main__":
    unittest.main()
