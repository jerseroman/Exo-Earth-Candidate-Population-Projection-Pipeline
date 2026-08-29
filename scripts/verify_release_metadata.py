#!/usr/bin/env python3
"""Fail closed when v4.0.3 publication metadata or provenance drifts."""

from __future__ import annotations

import json
import hashlib
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "4.0.3"
RELEASE_DATE = "2026-08-29"
DOI = "10.5281/zenodo.22158798"
ORCID = "https://orcid.org/0009-0001-5003-5354"
PUBLIC_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
)
LEGACY_REPOSITORY = "jerseroman/are-we-alone-in-the-universe"
PRIVATE_PRODUCTION_REPOSITORY = (
    "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production"
)
EXPECTED_RUNS = {
    "31358271145": (LEGACY_REPOSITORY, None),
    "32470830404": (LEGACY_REPOSITORY, 20000),
    "32472776218": (LEGACY_REPOSITORY, 20000),
    "32506666772": (LEGACY_REPOSITORY, 30000),
    "32527877921": (LEGACY_REPOSITORY, None),
    "32581407634": (PRIVATE_PRODUCTION_REPOSITORY, 20000),
    "32581659930": (PRIVATE_PRODUCTION_REPOSITORY, None),
    "32582964364": (PRIVATE_PRODUCTION_REPOSITORY, 20000),
    "32582966433": (PRIVATE_PRODUCTION_REPOSITORY, 30000),
}


def fail(message: str) -> None:
    raise SystemExit(f"RELEASE METADATA FAIL: {message}")


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def sha256(relative: str) -> str:
    digest = hashlib.sha256()
    with (ROOT / relative).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_text(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} lacks {token!r}")


def main() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', project)
    if not match or match.group(1) != VERSION:
        fail("pyproject.toml version is not the final release version")

    cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    for token in (
        f'version: "{VERSION}"',
        f'date-released: "{RELEASE_DATE}"',
        f'doi: "{DOI}"',
        f'orcid: "{ORCID}"',
        f'repository-code: "https://github.com/{PUBLIC_REPOSITORY}"',
        f"/blob/v{VERSION}/LICENSE_POLICY.md",
        "Reproducible astrophysical analysis, validation, and archival pipeline",
    ):
        require_text(cff, token, "CITATION.cff")
    if re.search(r"(?i)(?:\.dev\d*|-dev|placeholder|x{4,})", cff):
        fail("CITATION.cff contains development or placeholder metadata")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for token in (VERSION, DOI, f"/releases/tag/v{VERSION}"):
        require_text(readme, token, "README.md")
    if "4.0.0" in readme:
        fail("README.md retains obsolete v4.0.0 metadata")
    require_text(readme, "provenance/SOURCE_LOCKS.json", "README.md")
    require_text(
        readme,
        "approximately 3.2 million and 4.6 million",
        "README.md scientific-status rounding",
    )
    require_text(
        readme,
        "separate completeness scenarios, not bounds",
        "README.md completeness interpretation",
    )
    require_text(
        readme,
        "not a direct locally candidate-supported measurement",
        "README.md local-support limitation",
    )
    if "Their exact URLs" in readme:
        fail("README overstates URL availability for derived data locks")

    run_map = load_json("provenance/RUN_PROVENANCE.json")
    if run_map.get("status") != "VERIFIED_2026-08-23":
        fail("run provenance is not verified")
    if set(run_map.get("runs", {})) != set(EXPECTED_RUNS):
        fail("run provenance does not contain the exact audited run set")
    repositories = run_map["repositories"]
    for run_id, (repository, ceiling) in EXPECTED_RUNS.items():
        record = run_map["runs"][run_id]
        repository_key = record["repository"]
        if repositories[repository_key]["name"] != repository:
            fail(f"wrong repository for run {run_id}")
        if record.get("maximum_mcmc_steps") != ceiling:
            fail(f"wrong MCMC ceiling for run {run_id}")
        expected_url = f"https://github.com/{repository}/actions/runs/{run_id}"
        if record.get("url") != expected_url:
            fail(f"wrong URL for run {run_id}")

    baseline_evidence = load_json(
        "research/v4-validation/v4_statistical_baseline_github_evidence.json"
    )
    if baseline_evidence.get("repository") != LEGACY_REPOSITORY:
        fail("baseline Actions evidence has no explicit source repository")
    for record in baseline_evidence["actions_runs"].values():
        if not record.get("url") or "actions/runs/" not in record["url"]:
            fail("baseline Actions evidence contains a null or malformed URL")

    sensitivity = load_json(
        "research/v4-validation/frozen-sensitivities/V4_SENSITIVITY_FREEZE.json"
    )["artifact_run"]
    if sensitivity.get("repository") != LEGACY_REPOSITORY:
        fail("sensitivity record has the wrong source repository")
    if sensitivity.get("maximum_mcmc_steps") is not None:
        fail("host/TAMS sensitivity run incorrectly has an MCMC ceiling")

    numerical = load_json(
        "research/bryson-joint-posterior/frozen-v4/V4_NUMERICAL_FREEZE.json"
    )
    sensitivities = numerical["host_model"]
    old_key = "native_solar_selector_without_5200_anchor"
    new_key = old_key + "_fractional_change_vs_canonical"
    if old_key in sensitivities or new_key not in sensitivities:
        fail("numerical-freeze host sensitivity has ambiguous units")

    locks = load_json("provenance/DATA_LOCKS.json")["locks"]["bryson_pc_catalog"]
    if locks.get("windows_crlf_checkout_sha256") != (
        "5cf4805d8742507ead6916dcd1f7b118b7e5a28966b9ddd5b8d09fc6e181115c"
    ):
        fail("PC-catalog line-ending provenance is incomplete")

    audit = load_json("provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.json")
    if audit["scientific_configuration"].get("measurement_error_mode") != (
        "quantile_matched_two_sided"
    ):
        fail("independent audit does not record the canonical measurement-error mode")
    if audit["comparison"].get("quantiles_compared") != ["q50"]:
        fail("independent audit does not explicitly limit aggregate comparisons to q50")
    if "not agreement of the full posterior intervals" not in audit.get(
        "conclusion", ""
    ):
        fail("independent audit overstates its q50-only comparison scope")
    if "limited to the checked q50" not in audit.get("immutability_statement", ""):
        fail("independent audit overstates whole-baseline cross-environment validation")
    if not audit.get("scope", "").startswith("Hybrid cross-environment audit"):
        fail("independent audit incorrectly claims a full independent rerun")
    control = audit["control_comparison"]
    if "outer_measurement_inputs_exactly_identical" in control:
        fail("control comparison makes an unsupported byte-identity claim")
    if not control.get(
        "outer_measurement_inputs_value_identical_after_documented_normalization"
    ):
        fail("control comparison lacks the normalized value-identity result")
    require_text(
        control.get("outer_measurement_comparison_method", ""),
        "pandas.DataFrame.equals",
        "control-comparison method",
    )
    evidence_checks = [
        audit["local_platform"]["representative_environment_record"],
        audit["control_comparison"],
        {
            "distributed_path": audit["comparison"]["comparison_record_distributed_path"],
            "sha256": audit["comparison"]["comparison_record_sha256"],
        },
    ]
    for branch in ("constant", "zero"):
        record = audit["branches"][branch]
        evidence_checks.extend(
            [
                {
                    "distributed_path": record["aggregate_summary_distributed_path"],
                    "sha256": record["aggregate_summary_sha256"],
                },
                {
                    "distributed_path": record["aggregate_manifest_distributed_path"],
                    "sha256": record["aggregate_manifest_sha256"],
                },
                {
                    "distributed_path": record["galactic_manifest_distributed_path"],
                    "sha256": record["galactic_manifest_sha256"],
                },
            ]
        )
    for record in evidence_checks:
        path = record["distributed_path"]
        if sha256(path) != record["sha256"]:
            fail(f"independent-audit evidence hash mismatch: {path}")

    adjusted = audit["frozen_records"]["distributed_metadata_adjusted_records"]
    for prefix in ("baseline", "numerical"):
        if sha256(adjusted[f"{prefix}_path"]) != adjusted[f"{prefix}_sha256"]:
            fail(f"distributed {prefix} hash provenance drift")

    phase2 = (
        ROOT
        / "research/bryson-joint-posterior/PHASE2_NUMERICAL_FREEZE_REPORT.md"
    ).read_text(encoding="utf-8")
    require_text(
        phase2,
        audit["frozen_records"]["audit_time_numerical_sha256"],
        "PHASE2 numerical-freeze report",
    )
    require_text(
        phase2,
        adjusted["numerical_sha256"],
        "PHASE2 numerical-freeze report",
    )

    dr25_path = "research/v4-validation/frozen-dr25-support/dr25_support_audit.json"
    phase3 = (ROOT / "research/v4-validation/PHASE3_DR25_SUPPORT_REPORT.md").read_text(
        encoding="utf-8"
    )
    require_text(phase3, sha256(dr25_path), "PHASE3 DR25-support report")

    license_policy = (ROOT / "LICENSE_POLICY.md").read_text(encoding="utf-8")
    if "combined Bryson execution must satisfy" in license_policy:
        fail("license policy incorrectly treats execution as GPL distribution")
    require_text(
        license_policy,
        "Merely running the software is not presented here as a distribution event.",
        "LICENSE_POLICY.md",
    )
    if "Public verification jobs use only committed, cleared material" in license_policy:
        fail("license policy ignores ordinary external Python dependencies")
    for stale in (
        "path-level matrix governs these copies",
        "fetched from pinned upstream locations",
        "CFF interprets multiple license identifiers as alternative licensing",
    ):
        if stale in license_policy:
            fail(f"license policy retains overbroad wording: {stale}")
    if not re.search(
        r"does not express the path-specific\s+mapping\s+unambiguously",
        license_policy,
    ):
        fail("license policy does not explain the path-specific CFF limitation")

    root_license = (ROOT / "LICENSE").read_text(encoding="utf-8")
    require_text(root_license, "Unrecognized paths are not presumed MIT.", "LICENSE")
    if "unless a path-level entry states otherwise" in root_license:
        fail("root license retains a blanket MIT default")

    licenses_readme = (ROOT / "LICENSES/README.md").read_text(encoding="utf-8")
    if "combined Bryson execution" in licenses_readme:
        fail("license index incorrectly treats execution as GPL distribution")

    migration = load_json("provenance/MIGRATION_RECORD.json")
    if migration.get("frozen_baseline_status") != (
        "IMPORTED_BASELINE_CHECKED_Q50_VALUES_CROSS_ENVIRONMENT_VERIFIED_NOT_REPLACED"
    ):
        fail("migration record overstates independent whole-baseline validation")
    if migration["independent_audit"].get("comparison_quantile") != "q50":
        fail("migration record does not identify the compared quantile")

    audit_report = (
        ROOT / "provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.md"
    ).read_text(encoding="utf-8")
    if "checksum-locked\nWSL2/Python environment" in audit_report:
        fail("audit report overstates the locked execution environment")
    if "perturbed catalog and perturbation audit were byte-identical" in audit_report:
        fail("audit report overstates normalized value equality as byte identity")

    control_evidence = load_json(
        "provenance/independent-audit-evidence/control_comparison.json"
    )["outer_measurement"]
    require_text(
        control_evidence.get("comparison_method", ""),
        "pandas.DataFrame.equals",
        "public control-comparison evidence",
    )
    if any("exactly_identical" in key for key in control_evidence):
        fail("public control evidence retains an unsupported exact-identity key")

    evidence_readme = (
        ROOT / "provenance/independent-audit-evidence/README.md"
    ).read_text(encoding="utf-8")
    for token in ("upstream output inventories", "posterior correlation CSV files"):
        require_text(evidence_readme, token, "independent-audit evidence README")

    mcmc_protocol = (
        ROOT / "research/bryson-joint-posterior/MCMC_PROTOCOL.md"
    ).read_text(encoding="utf-8")
    if "serialized\nrounding" in mcmc_protocol:
        fail("MCMC protocol misattributes the weaker ESS sanity gate to rounding")
    require_text(mcmc_protocol, "separate, weaker sanity gate", "MCMC protocol")

    tams_note = (ROOT / "research/jj-host-export/TAMS_METHOD_NOTE.md").read_text(
        encoding="utf-8"
    )
    if "currently public PARSEC" in tams_note or "current phase-7" in tams_note:
        fail("TAMS note uses mutable upstream-state wording")

    figure_script = (
        ROOT / "research/v4-validation/make_v4_figures.py"
    ).read_text(encoding="utf-8")
    require_text(figure_script, '"Author": "Roman Jerše"', "figure metadata")

    reproducibility = (ROOT / "REPRODUCIBILITY.md").read_text(encoding="utf-8")
    if "four primary-literature" in reproducibility:
        fail("reproducibility guide contains a stale test count")
    if "workflows from `main`" in reproducibility:
        fail("reproducibility guide uses a mutable workflow ref")
    for token in (f"exact `v{VERSION}` tag", "must not be promoted into the baseline"):
        require_text(reproducibility, token, "REPRODUCIBILITY.md")

    changes = load_json("provenance/RELEASE_4_0_3_CHANGE_RECORD.json")
    if (
        changes.get("release_version") != VERSION
        or changes.get("base_release_version") != "4.0.2"
        or changes.get("reserved_zenodo_doi") != DOI
        or changes.get("scientific_logic_changed") is not False
        or changes.get("mcmc_configuration_or_seeds_changed") is not False
        or changes.get("frozen_numerical_values_changed") is not False
    ):
        fail("release change record has inconsistent scientific-scope metadata")
    recorded_paths = [
        path
        for group in changes.get("change_groups", [])
        for path in group.get("paths", [])
    ]
    if len(recorded_paths) != len(set(recorded_paths)):
        fail("release change record contains duplicate paths")
    missing_paths = [path for path in recorded_paths if not (ROOT / path).is_file()]
    if missing_paths:
        fail(f"release change record contains missing paths: {missing_paths}")

    base = changes["base_release_commit"]
    release_ref = f"v{VERSION}"
    try:
        base_exists = subprocess.run(
            ["git", "cat-file", "-e", f"{base}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
        release_exists = subprocess.run(
            ["git", "cat-file", "-e", f"{release_ref}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    except FileNotFoundError:
        base_exists = False
        release_exists = False
    if base_exists:
        diff_args = ["git", "diff", "--name-only", base]
        if release_exists:
            diff_args.append(release_ref)
        changed = set(
            subprocess.run(
                diff_args,
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
        )
        if changed != set(recorded_paths):
            fail(
                "release change record path mismatch; missing="
                f"{sorted(changed.difference(recorded_paths))}, extra="
                f"{sorted(set(recorded_paths).difference(changed))}"
            )

    print(
        f"PASS release metadata (v{VERSION}, DOI {DOI}, "
        f"{len(EXPECTED_RUNS)} audited Actions runs)"
    )


if __name__ == "__main__":
    main()
