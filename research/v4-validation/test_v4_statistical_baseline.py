import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "research" / "v4-validation" / "frozen-statistical-baseline"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class V4StatisticalBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = json.loads(
            (BASELINE / "V4_STATISTICAL_BASELINE_AUDIT.json").read_text(encoding="utf-8")
        )

    def test_selected_runs_are_not_misrepresented(self) -> None:
        runs = self.audit["actions_runs"]
        self.assertEqual(
            self.audit["source_actions_repository"],
            "jerseroman/are-we-alone-in-the-universe",
        )
        self.assertEqual(
            self.audit["run_provenance_record"],
            "provenance/RUN_PROVENANCE.json",
        )
        self.assertEqual(runs["initial_production"]["conclusion"], "failure")
        self.assertEqual(
            runs["initial_production"]["selected_successful_job"]["conclusion"],
            "success",
        )
        self.assertEqual(runs["zero_extended_rerun"]["conclusion"], "success")
        self.assertEqual(runs["constant_galactic_propagation"]["conclusion"], "success")
        expected_ceilings = {
            "pilot_seed_stability": 20000,
            "initial_production": 20000,
            "zero_extended_rerun": 30000,
            "constant_galactic_propagation": None,
        }
        for name, ceiling in expected_ceilings.items():
            self.assertEqual(runs[name]["maximum_mcmc_steps"], ceiling)
            self.assertEqual(
                runs[name]["url"],
                "https://github.com/jerseroman/are-we-alone-in-the-universe/"
                f"actions/runs/{runs[name]['id']}",
            )

    def test_all_800_selected_realizations_pass(self) -> None:
        self.assertEqual(self.audit["status"], "PASS")
        self.assertEqual(self.audit["selected_realizations_total"], 800)
        for branch in ("constant", "zero"):
            data = self.audit["branches"][branch]
            self.assertEqual(data["selected_realizations"], 400)
            self.assertEqual(data["convergence"]["converged"], 400)
            self.assertEqual(data["convergence"]["optimizer_failures"], 0)
            self.assertGreaterEqual(
                min(
                    item["minimum_ess_per_realization"]
                    for item in data["parameter_ess_mcse"].values()
                ),
                1000.0,
            )

    def test_headline_medians_are_frozen_products(self) -> None:
        expected = {"constant": 3.224, "zero": 4.572}
        for branch, reported in expected.items():
            origin = self.audit["branches"][branch]["headline_median_origin"]
            self.assertAlmostEqual(
                origin["N_star_7_9_kpc"] * origin["mean_f_EE_q50"],
                origin["artifact_Lambda_EE_q50"],
                places=6,
            )
            self.assertEqual(origin["reported_million_3dp"], reported)

    def test_baseline_checksum_manifest(self) -> None:
        manifest = BASELINE / "SHA256SUMS_v4_statistical_baseline.txt"
        for line in manifest.read_text(encoding="utf-8").splitlines():
            expected, name = line.split(maxsplit=1)
            target = (BASELINE / name.strip().lstrip("*")).resolve()
            self.assertTrue(target.is_file(), target)
            self.assertEqual(sha256(target), expected)


if __name__ == "__main__":
    unittest.main()
