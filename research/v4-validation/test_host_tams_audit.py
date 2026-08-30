from __future__ import annotations

import contextlib
import hashlib
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np
import pandas as pd

import host_tams_audit as audit


class HostTamsAuditTests(unittest.TestCase):
    def test_json_loader_rejects_overflow_and_nonfinite_literals(self) -> None:
        for payload in (b'{"x":1e999}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                audit.load_json_bytes(payload, "adversarial JSON")

    @staticmethod
    def host_frame(selector: str) -> pd.DataFrame:
        rows = []
        for radius in audit.EXPECTED_RADIAL_NODES:
            rows += [
                [radius, "thin", 5500.0, 5.0, 4.5, 1.0],
                [
                    radius,
                    "thick",
                    5700.0 if selector == "canonical" else 5800.0,
                    7.0,
                    4.6,
                    2.0 if selector == "canonical" else 1.5,
                ],
            ]
        return pd.DataFrame(rows, columns=audit.HOST_COLUMNS)

    @staticmethod
    def collapsed(frame: pd.DataFrame) -> pd.DataFrame:
        weighted = audit.attach_radial_weights(
            frame.rename(columns={"N_surface_pc-2": "N_surface_pc_2"})
        )
        return audit.collapsed_host_measure_frame(
            weighted, np.ones(len(weighted), dtype=bool)
        )

    @staticmethod
    def posterior(branch: str, offset: float = 0.0) -> pd.DataFrame:
        trial = np.repeat(np.arange(2), 8)
        # Both clusters contain the same low/high mixture, while each matched
        # inner batch contains one low and one high row.  Thus the fixture has
        # a positive posterior width but exact-zero MCSE under both frozen
        # estimators, which makes it a compact passing contract fixture.
        phase = np.concatenate(
            [np.tile([0.0, 1.0], 4), np.tile([1.0, 0.0], 4)]
        )
        return pd.DataFrame(
            {
                "branch": [branch] * 16,
                "global_trial": trial,
                "F0": 0.8 + offset + 0.1 * phase,
                "alpha": -1.3 + 0.05 * phase,
                "beta": -1.2 + 0.05 * phase,
                "gamma": -3.0 + 0.05 * phase,
            },
            columns=audit.POSTERIOR_COLUMNS,
        )

    @staticmethod
    def quantiles(values: np.ndarray) -> dict[str, float]:
        numbers = np.quantile(values, [0.025, 0.16, 0.5, 0.84, 0.975])
        return dict(zip(audit.QUANTILES, map(float, numbers)))

    @staticmethod
    def rewrite_manifest(root: Path, branch: str) -> None:
        names = (
            audit.GALACTIC_ARTIFACT_STEMS["collapsed"],
            audit.GALACTIC_ARTIFACT_STEMS["draws"].format(branch=branch),
            audit.GALACTIC_ARTIFACT_STEMS["summary"].format(branch=branch),
        )
        manifest = root / audit.GALACTIC_ARTIFACT_STEMS["manifest"].format(
            branch=branch
        )
        manifest.write_text(
            "".join(f"{audit.sha256(root / name)}  {name}\n" for name in names),
            encoding="utf-8",
        )

    @classmethod
    def write_root(
        cls,
        root: Path,
        selector: str,
        branch: str,
        posterior_path: Path,
        host_path: Path,
    ) -> None:
        root.mkdir()
        posterior = pd.read_csv(posterior_path)
        collapsed = cls.collapsed(pd.read_csv(host_path))
        collapsed_path = root / audit.GALACTIC_ARTIFACT_STEMS["collapsed"]
        collapsed.to_csv(collapsed_path, index=False, lineterminator="\n")
        bryson = Path(audit.__file__).resolve().parents[1] / "bryson-joint-posterior"
        if str(bryson) not in sys.path:
            sys.path.insert(0, str(bryson))
        propagation = __import__("propagate_hab2_joint_posterior")
        count = float(collapsed.integrated_host_weight.sum())
        hz, ee = propagation.propagate_chunk(
            posterior,
            collapsed.Teff_K.to_numpy(float),
            collapsed.integrated_host_weight.to_numpy(float),
        )
        draws = posterior.copy()
        draws["N_star"] = count
        draws["mean_f_HZ"] = hz / count
        draws["mean_f_EE"] = ee / count
        draws["Lambda_HZ"] = hz
        draws["Lambda_EE"] = ee
        draws["Lambda_EE_over_Lambda_HZ"] = ee / hz
        draws_path = root / audit.GALACTIC_ARTIFACT_STEMS["draws"].format(branch=branch)
        draws.to_csv(
            draws_path,
            index=False,
            compression={"method": "gzip", "mtime": 0},
        )
        posterior_quantiles = {
            name: cls.quantiles(draws[name].to_numpy(float))
            for name in audit.GALACTIC_QUANTITIES
        }
        diagnostics = __import__("clustered_monte_carlo")
        outer = diagnostics.cluster_bootstrap_quantile_mcse(
            draws,
            audit.GALACTIC_QUANTITIES,
            "global_trial",
            1000,
            2026082102,
        )
        inner = diagnostics.contiguous_batch_quantile_mcse(
            draws,
            audit.GALACTIC_QUANTITIES,
            "global_trial",
            8,
        )
        label = audit.EXPECTED_SELECTOR_LABELS[selector]
        summary = {
            "status": (
                "occurrence-posterior propagation conditional on the declared "
                f"host selector ({label}) and 1-Mearth conservative-HZ model"
            ),
            "branch": branch,
            "source_posterior_samples": {
                "path": str(posterior_path),
                "sha256": audit.sha256(posterior_path),
                "row_count": 16,
                "outer_realizations": 2,
                "equal_samples_per_outer_realization": 8,
            },
            "host_rows": {
                "path": str(host_path),
                "sha256": audit.sha256(host_path),
                "N_star_7_9_kpc": count,
                "exact_distinct_Teff_values": len(collapsed),
                "host_selection_label": label,
                "collapsed_measure_file": collapsed_path.name,
                "collapsed_measure_sha256": audit.sha256(collapsed_path),
            },
            "plugin_validation": (
                {
                    name: {
                        "calculated": 1.0,
                        "reference": 1.0,
                        "relative_difference": 0.0,
                    }
                    for name in ("Lambda_HZ", "Lambda_EE")
                }
                if selector == "canonical"
                else {
                    "status": "not_applicable_to_alternative_host_selector",
                    "host_selection_label": label,
                }
            ),
            "posterior_quantiles": posterior_quantiles,
            "posterior_quantile_monte_carlo_error": {
                "outer_realization_cluster_bootstrap": outer,
                "outer_realization_cluster_bootstrap_replicates": 1000,
                "outer_realization_cluster_bootstrap_seed": 2026082102,
                "inner_chain_contiguous_batch_mcse": inner,
                "inner_chain_batches": 8,
                "interpretation": "Whole-realization and contiguous-chain MCSE.",
            },
            "runtime_seconds": 1.0,
            "software": {
                "python": "test",
                "platform": "test",
                "numpy": np.__version__,
                "pandas": pd.__version__,
            },
            "included_uncertainty": "test fixture",
            "excluded_systematics": ["test fixture"],
        }
        summary_path = root / audit.GALACTIC_ARTIFACT_STEMS["summary"].format(
            branch=branch
        )
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        cls.rewrite_manifest(root, branch)

    @classmethod
    def fixture(cls, root: Path) -> dict[str, object]:
        posterior_paths, host_paths = {}, {}
        for branch, offset in (("constant", 0.0), ("zero", 0.2)):
            path = root / f"posterior-{branch}.csv"
            cls.posterior(branch, offset).to_csv(path, index=False, lineterminator="\n")
            posterior_paths[branch] = path
        counts, temperatures = {}, {}
        for selector in ("canonical", "legacy"):
            path = root / f"hosts-{selector}.csv"
            frame = cls.host_frame(selector)
            frame.to_csv(path, index=False, lineterminator="\n")
            collapsed = cls.collapsed(frame)
            host_paths[selector] = path
            counts[selector] = float(collapsed.integrated_host_weight.sum())
            temperatures[selector] = len(collapsed)
        roots = {}
        for selector in ("canonical", "legacy"):
            for branch in ("constant", "zero"):
                artifact = root / f"{selector}-{branch}"
                roots[(selector, branch)] = artifact
                cls.write_root(
                    artifact,
                    selector,
                    branch,
                    posterior_paths[branch],
                    host_paths[selector],
                )
        return {
            "roots": roots,
            "posterior_paths": posterior_paths,
            "host_paths": host_paths,
            "host_counts": counts,
            "temperature_counts": temperatures,
        }

    @staticmethod
    @contextlib.contextmanager
    def small_contract(fixture: dict[str, object]):
        with contextlib.ExitStack() as stack:
            for name, value in (
                ("EXPECTED_POSTERIOR_ROW_COUNT", 16),
                ("EXPECTED_OUTER_REALIZATIONS", 2),
                ("EXPECTED_SAMPLES_PER_REALIZATION", 8),
                ("EXPECTED_SELECTOR_HOST_COUNTS", fixture["host_counts"]),
                ("EXPECTED_SELECTOR_TEMPERATURE_COUNTS", fixture["temperature_counts"]),
                ("CANONICAL_N_STAR", fixture["host_counts"]["canonical"]),
            ):
                stack.enter_context(mock.patch.object(audit, name, value))
            yield

    @classmethod
    def update_summary(cls, root: Path, branch: str, update) -> None:
        path = root / audit.GALACTIC_ARTIFACT_STEMS["summary"].format(branch=branch)
        record = json.loads(path.read_text(encoding="utf-8"))
        update(record)
        path.write_text(json.dumps(record), encoding="utf-8")
        cls.rewrite_manifest(root, branch)

    def test_composite_trapezoid_radial_measure(self) -> None:
        frame = pd.DataFrame(
            {"R_kpc": audit.EXPECTED_RADIAL_NODES, "N_surface_pc_2": [1.0] * 5}
        )
        weighted = audit.attach_radial_weights(frame)
        expected = 2 * math.pi * 1e6 * sum(
            weight * radius
            for weight, radius in zip((0.25, 0.5, 0.5, 0.5, 0.25), range(7, 12))
        )
        # The explicit expression avoids concealing the endpoint half-weights.
        expected = 2 * math.pi * 1e6 * (
            0.25 * 7 + 0.5 * 7.5 + 0.5 * 8 + 0.5 * 8.5 + 0.25 * 9
        )
        self.assertAlmostEqual(float(weighted.integrated_weight.sum()), expected)

    def test_fresh_set_recomputes_actual_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            with self.small_contract(fixture):
                summaries, evidence = audit.validate_fresh_propagation_set(
                    fixture["roots"],
                    posterior_paths=fixture["posterior_paths"],
                    host_paths=fixture["host_paths"],
                )
        self.assertEqual(summaries[("canonical", "constant")]["branch"], "constant")
        self.assertEqual(evidence["legacy"]["zero"]["posterior_row_count"], 16)

    def test_patched_declarations_cannot_hide_tampering(self) -> None:
        for mutation in ("draw", "posterior", "extra-column"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(Path(temporary))
                roots = fixture["roots"]
                if mutation in {"draw", "extra-column"}:
                    target = roots[("legacy", "constant")]
                    path = target / audit.GALACTIC_ARTIFACT_STEMS["draws"].format(
                        branch="constant"
                    )
                    draws = pd.read_csv(path)
                    if mutation == "draw":
                        draws.loc[0, "Lambda_EE"] *= 1.01
                        draws.loc[0, "mean_f_EE"] = draws.loc[0, "Lambda_EE"] / draws.loc[0, "N_star"]
                        draws.loc[0, "Lambda_EE_over_Lambda_HZ"] = draws.loc[0, "Lambda_EE"] / draws.loc[0, "Lambda_HZ"]
                    else:
                        draws["ignored"] = 1.0
                    draws.to_csv(path, index=False, compression={"method": "gzip", "mtime": 0})
                    if mutation == "draw":
                        def update(record):
                            for quantity in ("mean_f_EE", "Lambda_EE", "Lambda_EE_over_Lambda_HZ"):
                                record["posterior_quantiles"][quantity] = self.quantiles(draws[quantity].to_numpy(float))
                        self.update_summary(target, "constant", update)
                    self.rewrite_manifest(target, "constant")
                else:
                    posterior = fixture["posterior_paths"]["constant"]
                    frame = pd.read_csv(posterior)
                    frame.loc[0, "F0"] += 0.1
                    frame.to_csv(posterior, index=False, lineterminator="\n")
                    digest = audit.sha256(posterior)
                    for selector in ("canonical", "legacy"):
                        self.update_summary(
                            roots[(selector, "constant")],
                            "constant",
                            lambda record: record["source_posterior_samples"].__setitem__("sha256", digest),
                        )
                with self.small_contract(fixture), self.assertRaises(RuntimeError):
                    audit.validate_fresh_propagation_set(
                        roots,
                        posterior_paths=fixture["posterior_paths"],
                        host_paths=fixture["host_paths"],
                    )

    def test_manifest_mcse_and_trial_layout_fail_closed(self) -> None:
        for mutation in (
            "extra-root-file",
            "negative-mcse",
            "forged-low-mcse",
            "truthy-trial",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(Path(temporary))
                target = fixture["roots"][("canonical", "zero")]
                if mutation == "extra-root-file":
                    (target / "extra.txt").write_text("extra\n", encoding="utf-8")
                elif mutation == "negative-mcse":
                    self.update_summary(
                        target,
                        "zero",
                        lambda record: record["posterior_quantile_monte_carlo_error"]["inner_chain_contiguous_batch_mcse"]["Lambda_EE"].__setitem__("q50", -1.0),
                    )
                elif mutation == "forged-low-mcse":
                    self.update_summary(
                        target,
                        "zero",
                        lambda record: record["posterior_quantile_monte_carlo_error"]["inner_chain_contiguous_batch_mcse"]["Lambda_EE"].__setitem__("q50", 1.0),
                    )
                else:
                    posterior = fixture["posterior_paths"]["zero"]
                    frame = pd.read_csv(posterior)
                    frame.loc[0, "global_trial"] = "true"
                    frame.to_csv(posterior, index=False, lineterminator="\n")
                with self.small_contract(fixture), self.assertRaises(RuntimeError):
                    audit.validate_fresh_propagation_set(
                        fixture["roots"],
                        posterior_paths=fixture["posterior_paths"],
                        host_paths=fixture["host_paths"],
                    )

    @staticmethod
    def parent_frame() -> pd.DataFrame:
        jj_host = Path(audit.__file__).resolve().parents[1] / "jj-host-export"
        if str(jj_host) not in sys.path:
            sys.path.insert(0, str(jj_host))
        tams = __import__("tams_reference")
        occurrence = __import__("occurrence_reference")
        rows = []
        templates = (
            ("thin", 5500.0, 4.5, -0.1),
            ("thick", 5700.0, 4.5, -0.5),
            ("thin", 5600.0, 4.2, -0.2),
            ("thick", 5800.0, 4.2, -0.6),
        )
        for radius in audit.EXPECTED_PARENT_RADIAL_NODES:
            for component, teff, logg, feh in templates:
                final_mass = 1.0
                rstar = math.sqrt(final_mass * 10 ** (4.438 - logg))
                log_l = 2 * math.log10(rstar * (teff / 5772.0) ** 2)
                r_tams = float(tams.tams_radius_rsun(teff))
                rows.append(
                    [
                        radius, component, 5.0, feh, 1.05, final_mass, log_l,
                        math.log10(teff), teff, logg, 1.0, rstar, rstar, r_tams,
                        int(4.3 < logg < 7.0), int(rstar <= r_tams and logg < 7.0),
                        float(occurrence.f_hz(teff)), float(occurrence.f_earth10(teff)),
                    ]
                )
        return pd.DataFrame(rows, columns=audit.PARENT_COLUMNS)

    @contextlib.contextmanager
    def parent_contract(self, frame: pd.DataFrame):
        weighted = audit.attach_radial_weights(frame.rename(columns={"N_surface_pc-2": "N_surface_pc_2"}))
        masks = {
            "canonical": weighted.B_TAMS_MS.to_numpy(bool),
            "legacy": weighted.A_logg.to_numpy(bool),
        }
        collapsed = {key: audit.collapsed_host_measure_frame(weighted, value) for key, value in masks.items()}
        counts = {key: float(value.integrated_host_weight.sum()) for key, value in collapsed.items()}
        temperatures = {key: len(value) for key, value in collapsed.items()}
        with mock.patch.object(audit, "EXPECTED_SELECTOR_HOST_COUNTS", counts), mock.patch.object(audit, "EXPECTED_SELECTOR_TEMPERATURE_COUNTS", temperatures):
            yield

    def test_parent_reconstructs_all_derived_fields_and_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            frame = self.parent_frame()
            path = Path(temporary) / "jj_g_hosts_parent_prelogg_padova.csv"
            frame.to_csv(path, index=False, lineterminator="\n")
            with self.parent_contract(frame):
                _, masks, _, hosts, _, evidence = audit.validate_parent_artifact(path)
        self.assertGreater(np.sum(masks["canonical"]), np.sum(masks["legacy"]))
        self.assertEqual(set(hosts), {"canonical", "legacy"})
        self.assertLessEqual(abs(evidence["decomposition_relative_closure_error"]), 1e-13)

    def test_occurrence_reference_matches_independent_formula_anchors(self) -> None:
        jj_host = Path(audit.__file__).resolve().parents[1] / "jj-host-export"
        if str(jj_host) not in sys.path:
            sys.path.insert(0, str(jj_host))
        occurrence = __import__("occurrence_reference")
        audit.validate_occurrence_reference_anchors(occurrence)
        broken = SimpleNamespace(
            f_hz=lambda temperature: occurrence.f_hz(temperature) + 1e-8,
            f_earth10=occurrence.f_earth10,
        )
        with self.assertRaises(RuntimeError):
            audit.validate_occurrence_reference_anchors(broken)

    def test_parent_rejects_derived_field_and_domain_mutations(self) -> None:
        mutations = {
            "f_HZ": lambda f: f.__setitem__("f_HZ", f.f_HZ + 1e-4),
            "f_earth10": lambda f: f.__setitem__("f_earth10", f.f_earth10 + 1e-4),
            "selector": lambda f: f.loc.__setitem__((0, "A_logg"), 0),
            "radius": lambda f: f.loc.__setitem__((0, "Rstar_g_Rsun"), f.loc[0, "Rstar_g_Rsun"] + 0.01),
            "TAMS": lambda f: f.loc.__setitem__((0, "R_TAMS_Rsun"), f.loc[0, "R_TAMS_Rsun"] + 0.01),
            "age": lambda f: f.loc.__setitem__((0, "age_Gyr"), 4.0),
            "component": lambda f: f.loc.__setitem__((0, "component"), "halo"),
        }
        baseline = self.parent_frame()
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                frame = baseline.copy()
                mutate(frame)
                path = Path(temporary) / "jj_g_hosts_parent_prelogg_padova.csv"
                frame.to_csv(path, index=False, lineterminator="\n")
                with self.parent_contract(baseline), self.assertRaises(RuntimeError):
                    audit.validate_parent_artifact(path)

    def test_metallicity_root_is_reverified_and_parent_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            points = root / audit.NATIVE_SOLAR_POINTS_NAME
            points.write_text("Z,Teff_K\n0.017,5780\n", encoding="utf-8")
            parent = {
                "filename": "jj_g_hosts_parent_prelogg_padova.csv", "sha256": "a" * 64,
                "size_bytes": 100, "row_count": 20, "feh_min": -0.8, "feh_max": 0.2,
            }
            report = {
                "schema_version": 3, "status": "FAIL_NOT_PUBLISHABLE",
                "correction_policy": {"applied": False, "publishable": False, "emitted_files": []},
                "parent_input": dict(parent),
                "native_solar_reference": {"points_file": audit.NATIVE_SOLAR_POINTS_NAME, "points_sha256": audit.sha256(points)},
            }
            (root / audit.METALLICITY_REPORT_NAME).write_text(json.dumps(report), encoding="utf-8")
            verifier = SimpleNamespace(verify_artifact=lambda artifact_root: report)
            with mock.patch("host_tams_audit.importlib.import_module", return_value=verifier):
                _, evidence = audit.verify_metallicity_audit_root(root, points, parent)
            self.assertEqual(evidence["parent_input"], parent)
            with mock.patch("host_tams_audit.importlib.import_module", return_value=verifier), self.assertRaises(RuntimeError):
                audit.verify_metallicity_audit_root(root, points, dict(parent, row_count=21))

    def test_snapshot_rejects_symlink_and_tams_parses_hashed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_text("1 2\n3 4\n", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                link = None
            if link is not None:
                with self.assertRaises(RuntimeError):
                    audit.read_file_snapshot(link, "symlink fixture")
            jj_host = Path(audit.__file__).resolve().parents[1] / "jj-host-export"
            if str(jj_host) not in sys.path:
                sys.path.insert(0, str(jj_host))
            tams = __import__("tams_reference")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            with mock.patch.object(tams, "REFERENCE_PATH", target), mock.patch.object(tams, "EXPECTED_SHA256", digest), mock.patch.object(tams, "EXPECTED_ROWS", 2), mock.patch.object(tams.np, "loadtxt", wraps=np.loadtxt) as loader:
                temperature, radius = tams.load_full_tams_table()
            self.assertEqual(list(temperature), [1.0, 3.0])
            self.assertEqual(list(radius), [2.0, 4.0])
            self.assertTrue(hasattr(loader.call_args.args[0], "read"))

    def test_host_contract_binding_requires_acceptance_and_exact_canonical_rows(self) -> None:
        repository_root = Path(audit.__file__).resolve().parents[2]
        verifier_snapshot = audit.read_file_snapshot(
            repository_root / "scripts" / "verify_host_artifact_contract.py",
            "contract verifier fixture",
        )
        canonical = self.host_frame("canonical")
        expected_source_lock = {
            "public_source": {
                "repository": "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline",
                "commit_sha": "a" * 40,
                "git_tree_sha": "b" * 40,
                "source_archive_sha256": "c" * 64,
                "source_archive_size_bytes": 123,
            },
            "private_source": {
                "repository": "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production",
                "commit_sha": "a" * 40,
                "git_tree_sha": "b" * 40,
                "source_archive_sha256": "c" * 64,
                "source_archive_size_bytes": 123,
            },
        }

        def expanded_source(record: dict, role: str) -> dict:
            return {
                "role": role,
                "repository": record["repository"],
                "commit_sha": record["commit_sha"],
                "git_tree_sha": record["git_tree_sha"],
                "source_archive": {
                    "filename": "source.tar",
                    "sha256": record["source_archive_sha256"],
                    "size_bytes": record["source_archive_size_bytes"],
                },
            }

        def run(accepted: bool, mutate: bool = False) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                contract = root / audit.HOST_CONTRACT_NAME
                report_path = root / "HOST_QUALIFICATION.json"
                report_path.write_text('{"status":"PASS"}\n', encoding="utf-8")
                report_hash = audit.sha256(report_path)
                contract_document = {
                    "artifact_sets": [
                        {
                            "id": "qualified-r4",
                            "production_accepted": True,
                            "qualification_report": {
                                "path": report_path.name,
                                "sha256": report_hash,
                            },
                        }
                    ]
                }
                contract.write_text("{}\n", encoding="utf-8")
                raw = canonical.copy()
                if mutate:
                    raw.loc[0, "N_surface_pc-2"] += 1e-6
                raw.to_csv(
                    root / "jj_g_hosts_raw_eligible_padova.csv",
                    index=False,
                    lineterminator="\n",
                )
                for name in audit.HOST_CONTRACT_FILES:
                    path = root / name
                    if path.exists():
                        continue
                    if name.endswith(".json"):
                        path.write_text("{}\n", encoding="utf-8")
                    else:
                        path.write_text("fixture\n", encoding="utf-8")
                (root / audit.HOST_CONTRACT_MANIFEST_NAME).write_text(
                    "fixture manifest\n", encoding="utf-8"
                )
                verifier = SimpleNamespace(
                    load_json_bytes=lambda *_: contract_document,
                    validate_contract=lambda value: value,
                    verify_artifact=lambda _contract, _root: {
                        "artifact_set": {
                            "id": "qualified-r4",
                            "production_accepted": accepted,
                        },
                        "representation_match": "exact",
                    },
                    _validate_qualification_report=lambda *_args, **_kwargs: {
                        "report": {"qualification_id": "sha256:" + "d" * 64},
                        "source_state": {
                            "public_source": expanded_source(
                                expected_source_lock["public_source"], "public_release"
                            ),
                            "private_source": expanded_source(
                                expected_source_lock["private_source"], "private_production"
                            ),
                        },
                    },
                )
                with mock.patch.object(
                    audit,
                    "_load_python_module_from_snapshot",
                    return_value=(verifier, verifier_snapshot),
                ):
                    audit.verify_host_artifact_contract_binding(
                        contract,
                        root,
                        canonical,
                        expected_contract_sha256=audit.sha256(contract),
                        expected_contract_size_bytes=contract.stat().st_size,
                        expected_qualification_report_sha256=report_hash,
                        expected_qualification_report_size_bytes=report_path.stat().st_size,
                        expected_source_lock=expected_source_lock,
                    )

        run(True)
        with self.assertRaisesRegex(RuntimeError, "not production accepted"):
            run(False)
        with self.assertRaisesRegex(RuntimeError, "numerical rows differ"):
            run(True, mutate=True)

    def test_sha256_types_and_release_evidence_are_fail_closed(self) -> None:
        with self.assertRaises(RuntimeError):
            audit._require_sha256(int("1" * 64), "integer digest")
        safe = audit.release_safe_evidence(
            {
                "artifact_root": r"C:\\private\\artifact",
                "path": r"C:\\private\\artifact\\result.json",
                "sha256": "a" * 64,
            }
        )
        self.assertNotIn("artifact_root", safe)
        self.assertEqual(safe["filename"], "result.json")
        self.assertNotIn("private", json.dumps(safe))
        posix_safe = audit.release_safe_evidence(
            {"path": "/private/artifact/result.json", "sha256": "b" * 64}
        )
        self.assertEqual(posix_safe["filename"], "result.json")
        for malformed in (
            r"C:\\private\\artifact\\",
            "/private/artifact/",
            "..",
            "C:",
            "bad\x00name.json",
        ):
            with self.subTest(path=malformed), self.assertRaisesRegex(
                RuntimeError, "malformed path"
            ):
                audit.release_safe_evidence({"path": malformed})
        for unsafe_leaf in (
            r"C:\\private\\qualification.json",
            r"..\\qualification.json",
            "/private/qualification.json",
            "../qualification.json",
            "C:qualification.json",
            "qualification.json/",
        ):
            with self.subTest(leaf=unsafe_leaf), self.assertRaises(RuntimeError):
                audit._portable_leaf_name(unsafe_leaf, "fixture leaf")
        self.assertEqual(
            audit._portable_leaf_name("qualification.json", "fixture leaf"),
            "qualification.json",
        )

    def test_tams_runtime_policy_accepts_the_shared_producer_contract(self) -> None:
        repository_root = Path(audit.__file__).resolve().parents[2]
        producer, _ = audit._load_python_module_from_snapshot(
            repository_root / "scripts" / "verify_numerical_runtime.py",
            module_name="_host_test_numerical_runtime",
            label="runtime producer fixture",
        )
        features = {name: True for name in producer.REQUIRED_ENABLED}
        features.update({name: False for name in producer.REQUIRED_DISABLED})
        report = {
            "schema_version": 1,
            "status": "PASS",
            "numpy_version": producer.EXPECTED_NUMPY_VERSION,
            "environment": dict(producer.EXPECTED_ENV),
            "selected_cpu_features": features,
        }
        audit.validate_tams_numerical_runtime_policy(report)
        changed = json.loads(json.dumps(report))
        changed["environment"]["OMP_NUM_THREADS"] = "2"
        with self.assertRaises(RuntimeError):
            audit.validate_tams_numerical_runtime_policy(changed)
        changed = json.loads(json.dumps(report))
        changed["selected_cpu_features"]["AVX512_KNL"] = True
        with self.assertRaises(RuntimeError):
            audit.validate_tams_numerical_runtime_policy(changed)

    def test_radial_ssp_binding_requires_exact_external_locks_and_signed_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / audit.RADIAL_SSP_CONTRACT_NAME
            contract.write_text("{}\n", encoding="utf-8")
            report = root / "RADIAL_SSP_QUALIFICATION_v4_0_4.json"
            source_record = {
                "commit_sha": "a" * 40,
                "git_tree_sha": "b" * 40,
                "source_archive": {
                    "sha256": "c" * 64,
                    "size_bytes": 123,
                },
            }
            source_state = {
                "public_source": dict(source_record),
                "private_source": dict(source_record),
            }
            report_document = {
                "qualification_id": "sha256:" + "d" * 64,
                "triplets": [
                    {"source_provenance": source_state},
                    {"source_provenance": source_state},
                ],
            }
            report.write_text(json.dumps(report_document), encoding="utf-8")
            convergence = root / "convergence"
            convergence.mkdir()
            (convergence / audit.TAMS_CONVERGENCE_MANIFEST_NAME).write_text(
                "fixture manifest\n", encoding="utf-8"
            )
            for name in audit.tams_convergence_target_names():
                (convergence / name).write_bytes((name + "\n").encode("utf-8"))
            verifier_file = root / "verifier.py"
            verifier_file.write_text("# fixture\n", encoding="utf-8")
            verifier_snapshot = audit.read_file_snapshot(
                verifier_file, "radial verifier fixture"
            )

            def bind(contract: Path, qualification: Path, artifacts: Path) -> dict:
                self.assertEqual(contract.parent, qualification.parent)
                self.assertTrue(artifacts.is_dir())
                return {
                    "status": "PASS",
                    "artifact_set_id": "accepted-radial",
                    "qualified_public_evidence_sha256": "c" * 64,
                    "runs": {
                        str(dr): {
                            "generated_radial": {"sha256": "a" * 64},
                            "generated_result": {"sha256": "b" * 64},
                        }
                        for dr in audit.TAMS_CONVERGENCE_DRS
                    },
                }

            fake = SimpleNamespace(bind_public_convergence=bind)
            with mock.patch.object(
                audit,
                "_load_python_module_from_snapshot",
                return_value=(fake, verifier_snapshot),
            ):
                evidence = audit.verify_radial_ssp_contract_binding(
                    contract,
                    report,
                    convergence,
                    expected_contract_sha256=audit.sha256(contract),
                    expected_contract_size_bytes=contract.stat().st_size,
                    expected_qualification_report_sha256=audit.sha256(report),
                    expected_qualification_report_size_bytes=report.stat().st_size,
                    expected_computational_source={
                        "commit": "a" * 40,
                        "tree": "b" * 40,
                        "archive_sha256": "c" * 64,
                        "archive_size_bytes": 123,
                    },
                )
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["artifact_set_id"], "accepted-radial")
            self.assertEqual(set(evidence["bound_run_files"]), {"1.0", "0.5", "0.25"})

            forged = root / "forged-contract.json"
            forged.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exact lock"):
                audit.verify_radial_ssp_contract_binding(
                    forged,
                    report,
                    convergence,
                    expected_contract_sha256="f" * 64,
                    expected_contract_size_bytes=forged.stat().st_size,
                    expected_qualification_report_sha256=audit.sha256(report),
                    expected_qualification_report_size_bytes=report.stat().st_size,
                    expected_computational_source={
                        "commit": "a" * 40,
                        "tree": "b" * 40,
                        "archive_sha256": "c" * 64,
                        "archive_size_bytes": 123,
                    },
                )

    def test_local_run_binding_requires_accepted_external_contract_and_exact_report(self) -> None:
        public_report = {
            "report_id": "report-fixture",
            "candidate_id": "candidate-fixture",
            "source_commit": "1" * 40,
            "source_tree": "2" * 40,
            "source_archive_sha256": "a" * 64,
            "source_archive_size_bytes": 456,
            "command_plan_sha256": "b" * 64,
            "numerical_runtime_manifest_sha256": "c" * 64,
            "output_manifest_sha256": "d" * 64,
            "output_file_set_sha256": "e" * 64,
            "output_file_count": 3,
            "output_total_size_bytes": 123,
        }
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / audit.LOCAL_RUN_CONTRACT_NAME
            contract.write_text("{}\n", encoding="utf-8")
            report_path = root / "LOCAL_RUN_QUALIFICATION.json"
            report_path.write_bytes(canonical(public_report))
            verifier_file = root / "verifier.py"
            verifier_file.write_text("# fixture\n", encoding="utf-8")
            verifier_snapshot = audit.read_file_snapshot(
                verifier_file, "local-run verifier fixture"
            )
            runtime_snapshot = SimpleNamespace(sha256="c" * 64)
            plan_snapshot = SimpleNamespace(sha256="b" * 64)
            manifest_snapshot = SimpleNamespace(sha256="d" * 64)

            def load_fixture(path: Path, _label: str):
                if Path(path).name == "runtime.json":
                    return {}, runtime_snapshot
                if Path(path).name == "plan.json":
                    return {}, plan_snapshot
                return {}, manifest_snapshot

            fake = SimpleNamespace(
                OUTPUT_MANIFEST_NAME="LOCAL_RUN_OUTPUT_SHA256.json",
                select_contract=lambda *_: (
                    {},
                    {
                        "production_accepted": True,
                        "source_lock": {
                            "commit": "1" * 40,
                            "tree": "2" * 40,
                            "archive_sha256": "a" * 64,
                            "archive_size_bytes": 456,
                        },
                    },
                    SimpleNamespace(),
                ),
                load_json_snapshot=load_fixture,
                validate_numerical_runtime=lambda _: {},
                validate_plan=lambda *_: {
                    "expected_output_files": ["artifact/result.json"]
                },
                validate_output_manifest=lambda *_: [
                    {
                        "path": "artifact/result.json",
                        "sha256": "f" * 64,
                        "size_bytes": 17,
                    }
                ],
                verify_run=lambda **_: dict(public_report),
                validate_report_disclosure=lambda _: None,
                canonical_json_bytes=canonical,
                recheck_snapshot=lambda *_: None,
            )
            with mock.patch.object(
                audit,
                "_load_python_module_from_snapshot",
                return_value=(fake, verifier_snapshot),
            ):
                evidence = audit.verify_local_run_attestation_binding(
                    contract,
                    candidate_id="candidate-fixture",
                    public_report_path=report_path,
                    expected_contract_sha256=audit.sha256(contract),
                    expected_contract_size_bytes=contract.stat().st_size,
                    expected_public_report_sha256=audit.sha256(report_path),
                    expected_public_report_size_bytes=report_path.stat().st_size,
                    expected_computational_source={
                        "commit": "1" * 40,
                        "tree": "2" * 40,
                        "archive_sha256": "a" * 64,
                        "archive_size_bytes": 456,
                    },
                    public_source_repo=root / "public",
                    private_source_repo=root / "private",
                    plan_path=root / "plan.json",
                    runtime_manifest_path=root / "runtime.json",
                    output_root=root / "output",
                    evidence_dir=root / "evidence",
                    execution_root=root / "execution",
                    execution_environment="local_ubuntu_22_04_wsl2",
                    git_executable=root / "git",
                    ssh_keygen_executable=root / "ssh-keygen",
                )
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["candidate_id"], "candidate-fixture")
            self.assertEqual(evidence["output_file_count"], 3)
            self.assertEqual(
                evidence["_signed_output_files"]["artifact/result.json"]["sha256"],
                "f" * 64,
            )

            report_path.write_bytes(canonical({**public_report, "output_file_count": 4}))
            with mock.patch.object(
                audit,
                "_load_python_module_from_snapshot",
                return_value=(fake, verifier_snapshot),
            ), self.assertRaisesRegex(RuntimeError, "regenerated bytes"):
                audit.verify_local_run_attestation_binding(
                    contract,
                    candidate_id="candidate-fixture",
                    public_report_path=report_path,
                    expected_contract_sha256=audit.sha256(contract),
                    expected_contract_size_bytes=contract.stat().st_size,
                    expected_public_report_sha256=audit.sha256(report_path),
                    expected_public_report_size_bytes=report_path.stat().st_size,
                    expected_computational_source={
                        "commit": "1" * 40,
                        "tree": "2" * 40,
                        "archive_sha256": "a" * 64,
                        "archive_size_bytes": 456,
                    },
                    public_source_repo=root / "public",
                    private_source_repo=root / "private",
                    plan_path=root / "plan.json",
                    runtime_manifest_path=root / "runtime.json",
                    output_root=root / "output",
                    evidence_dir=root / "evidence",
                    execution_root=root / "execution",
                    execution_environment="local_ubuntu_22_04_wsl2",
                    git_executable=root / "git",
                    ssh_keygen_executable=root / "ssh-keygen",
                )

    def test_consumed_output_roots_require_exact_signed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            first = output / "aggregate"
            second = output / "propagation"
            first.mkdir(parents=True)
            second.mkdir()
            (first / "result.json").write_bytes(b'{"status":"PASS"}\n')
            (second / "draws.csv").write_bytes(b"x,y\n1,2\n")

            signed = {}
            for relative in (
                "aggregate/result.json",
                "propagation/draws.csv",
            ):
                payload = (output / Path(*relative.split("/"))).read_bytes()
                signed[relative] = {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            evidence = audit.verify_attested_output_roots(
                output,
                {"aggregate": first, "propagation": second},
                signed,
            )
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["root_count"], 2)
            self.assertEqual(evidence["file_count"], 2)

            (first / "result.json").write_bytes(b'{"status":"FAIL"}\n')
            with self.assertRaisesRegex(RuntimeError, "differs from the signed manifest"):
                audit.verify_attested_output_roots(
                    output, {"aggregate": first, "propagation": second}, signed
                )

            (first / "result.json").write_bytes(b'{"status":"PASS"}\n')
            (first / "unsigned.txt").write_text("unsigned\n", encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError, "(?:file set|output tree) differs"
            ):
                audit.verify_attested_output_roots(
                    output, {"aggregate": first, "propagation": second}, signed
                )


if __name__ == "__main__":
    unittest.main()
