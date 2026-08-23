#!/usr/bin/env python3
"""Audit direct DR25 support for the v4 Earth-analog integration domain."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


SOURCE_RADIUS = (0.5, 2.5)
SOURCE_INSTELLATION = (0.2, 2.2)
SOURCE_TEMPERATURE = (3900.0, 6300.0)
TARGET_RADIUS = (0.9, 1.1)
TARGET_INSTELLATION = (0.9, 1.1)
TARGET_TEMPERATURE = (5300.0, 6000.0)
EXPECTED_TRIALS = 400
CORRECTED_MODE = "quantile_matched_two_sided"
QUANTILE_PROBABILITIES = (0.025, 0.16, 0.5, 0.84, 0.975)
QUANTILE_NAMES = ("q2.5", "q16", "q50", "q84", "q97.5")

RUNAWAY_1MEARTH = (
    1.107,
    1.332e-4,
    1.580e-8,
    -8.308e-12,
    -1.931e-15,
)

PC_CATALOG_SOURCE_LF_SHA256 = (
    "c8ae78fcfe4ed27bbe972b1041a3e370031a4f94afea4ad35dd7bd47834c140b"
)
PC_CATALOG_WINDOWS_CRLF_SHA256 = (
    "5cf4805d8742507ead6916dcd1f7b118b7e5a28966b9ddd5b8d09fc6e181115c"
)
MAXIMUM_GREENHOUSE = (
    0.356,
    6.171e-5,
    1.698e-9,
    -3.198e-12,
    -5.575e-16,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pc_catalog_provenance(path: Path) -> dict[str, Any]:
    observed = sha256(path)
    representations = {
        PC_CATALOG_SOURCE_LF_SHA256: "pinned_source_lf",
        PC_CATALOG_WINDOWS_CRLF_SHA256: "historical_windows_crlf_checkout",
    }
    if observed not in representations:
        raise RuntimeError(f"Unexpected PC-catalog representation: {observed}")
    return {
        "path": str(path),
        "sha256": observed,
        "source_locked_sha256": PC_CATALOG_SOURCE_LF_SHA256,
        "representation": representations[observed],
        "line_ending_note": (
            "The pinned source uses LF. The historical Windows checkout used "
            "CRLF for all 2278 lines; parsed CSV fields are unchanged."
        ),
    }


def seff(teff: np.ndarray, coefficients: tuple[float, ...]) -> np.ndarray:
    temperature = np.asarray(teff, dtype=float)
    delta = temperature - 5780.0
    s0, a, b, c, d = coefficients
    return s0 + a * delta + b * delta**2 + c * delta**3 + d * delta**4


def finite_mask(*arrays: np.ndarray) -> np.ndarray:
    result = np.ones(len(np.asarray(arrays[0])), dtype=bool)
    for values in arrays:
        result &= np.isfinite(np.asarray(values, dtype=float))
    return result


def rectangular_target_mask(
    radius: np.ndarray, instellation: np.ndarray, teff: np.ndarray
) -> np.ndarray:
    radius = np.asarray(radius, dtype=float)
    instellation = np.asarray(instellation, dtype=float)
    teff = np.asarray(teff, dtype=float)
    return (
        finite_mask(radius, instellation, teff)
        & (TARGET_RADIUS[0] <= radius)
        & (radius <= TARGET_RADIUS[1])
        & (TARGET_INSTELLATION[0] <= instellation)
        & (instellation <= TARGET_INSTELLATION[1])
        & (TARGET_TEMPERATURE[0] <= teff)
        & (teff <= TARGET_TEMPERATURE[1])
    )


def earth_analog_target_mask(
    radius: np.ndarray, instellation: np.ndarray, teff: np.ndarray
) -> np.ndarray:
    """Return the exact 0.9--1.1 R/I intersection with the conservative HZ."""

    radius = np.asarray(radius, dtype=float)
    instellation = np.asarray(instellation, dtype=float)
    teff = np.asarray(teff, dtype=float)
    outer = seff(teff, MAXIMUM_GREENHOUSE)
    inner = seff(teff, RUNAWAY_1MEARTH)
    lower = np.maximum(TARGET_INSTELLATION[0], outer)
    upper = np.minimum(TARGET_INSTELLATION[1], inner)
    return (
        finite_mask(radius, instellation, teff, lower, upper)
        & (TARGET_RADIUS[0] <= radius)
        & (radius <= TARGET_RADIUS[1])
        & (TARGET_TEMPERATURE[0] <= teff)
        & (teff <= TARGET_TEMPERATURE[1])
        & (lower <= instellation)
        & (instellation <= upper)
        & (lower <= upper)
    )


def summarize_nominal(mask: np.ndarray, reliability: np.ndarray) -> dict[str, Any]:
    active = np.asarray(mask, dtype=bool)
    weights = np.asarray(reliability, dtype=float)
    return {
        "candidate_count": int(np.sum(active)),
        "sum_totalReliability": float(np.sum(weights[active])),
    }


def count_summary(counts: np.ndarray) -> dict[str, Any]:
    values = np.asarray(counts, dtype=float)
    quantiles = np.quantile(values, QUANTILE_PROBABILITIES)
    return {
        "quantiles": {
            name: float(value) for name, value in zip(QUANTILE_NAMES, quantiles)
        },
        "minimum": int(np.min(values)),
        "maximum": int(np.max(values)),
        "mean": float(np.mean(values)),
        "fraction_zero": float(np.mean(values == 0.0)),
    }


def load_source_population(pc_path: Path, stellar_path: Path) -> pd.DataFrame:
    pc = pd.read_csv(pc_path)
    stellar = pd.read_csv(stellar_path, usecols=["kepid", "logg"])
    source = pd.merge(
        pc,
        stellar,
        left_on="kepid_x",
        right_on="kepid",
        how="inner",
    ).reset_index(drop=True)
    source["source_row"] = np.arange(len(source), dtype=int)
    required = {
        "source_row",
        "kepoi_name",
        "kepid_x",
        "totalReliability",
        "gaia_iso_prad",
        "gaia_iso_insol",
        "teff",
    }
    missing = required.difference(source.columns)
    if missing:
        raise RuntimeError(f"DR25 source population lacks columns: {sorted(missing)}")
    for column in (
        "totalReliability",
        "gaia_iso_prad",
        "gaia_iso_insol",
        "teff",
    ):
        source[column] = pd.to_numeric(source[column], errors="raise")
    reliability = source.totalReliability.to_numpy(dtype=float)
    if np.any(~np.isfinite(reliability)) or np.any((reliability < 0.0) | (reliability > 1.0)):
        raise RuntimeError("Invalid totalReliability outside [0, 1]")
    return source


def analyze_perturbation_branch(
    path: Path,
    branch: str,
    source: pd.DataFrame,
) -> tuple[dict[str, Any], pd.DataFrame, pd.DataFrame]:
    columns = [
        "branch",
        "measurement_error_mode",
        "global_trial",
        "source_row",
        "kepoi_name",
        "retained_by_active_policy",
        "perturbed_flux",
        "perturbed_radius",
        "perturbed_teff",
    ]
    audit = pd.read_csv(path, usecols=columns)
    if set(audit.branch.unique()) != {branch}:
        raise RuntimeError(f"Unexpected branch labels in {path}")
    if set(audit.measurement_error_mode.unique()) != {CORRECTED_MODE}:
        raise RuntimeError(f"Unexpected measurement-error mode in {path}")
    trials = np.sort(audit.global_trial.unique())
    if not np.array_equal(trials, np.arange(EXPECTED_TRIALS)):
        raise RuntimeError(f"Expected trials 0..{EXPECTED_TRIALS - 1} for {branch}")
    if audit.duplicated(["global_trial", "source_row"]).any():
        raise RuntimeError(f"Duplicate source row within a {branch} trial")
    source_rows = audit.source_row.to_numpy(dtype=int)
    if source_rows.min() < 0 or source_rows.max() >= len(source):
        raise RuntimeError(f"Out-of-range source_row in {branch}")
    expected_names = source.kepoi_name.to_numpy(dtype=str)[source_rows]
    if not np.array_equal(audit.kepoi_name.to_numpy(dtype=str), expected_names):
        raise RuntimeError(f"Source-row identity mismatch in {branch}")

    radius = audit.perturbed_radius.to_numpy(dtype=float)
    instellation = audit.perturbed_flux.to_numpy(dtype=float)
    teff = audit.perturbed_teff.to_numpy(dtype=float)
    rectangle = rectangular_target_mask(radius, instellation, teff)
    earth_analog = earth_analog_target_mask(radius, instellation, teff)
    if np.any(earth_analog & ~rectangle):
        raise RuntimeError("Earth-analog mask is not a subset of its rectangle")
    retained = audit.retained_by_active_policy.to_numpy(dtype=bool)
    if np.any(earth_analog & ~retained):
        raise RuntimeError("A target-domain row was removed by the active source policy")

    trial_index = audit.global_trial.to_numpy(dtype=int)
    selected_counts = np.bincount(trial_index, minlength=EXPECTED_TRIALS)
    retained_counts = np.bincount(
        trial_index, weights=retained.astype(int), minlength=EXPECTED_TRIALS
    ).astype(int)
    rectangle_counts = np.bincount(
        trial_index, weights=rectangle.astype(int), minlength=EXPECTED_TRIALS
    ).astype(int)
    earth_analog_counts = np.bincount(
        trial_index, weights=earth_analog.astype(int), minlength=EXPECTED_TRIALS
    ).astype(int)

    trial_table = pd.DataFrame(
        {
            "branch": branch,
            "global_trial": np.arange(EXPECTED_TRIALS),
            "reliability_selected_before_domain": selected_counts,
            "retained_in_source_domain": retained_counts,
            "rectangular_target_candidates": rectangle_counts,
            "earth_analog_target_candidates": earth_analog_counts,
        }
    )
    candidate_rows = audit.loc[
        earth_analog,
        [
            "global_trial",
            "source_row",
            "kepoi_name",
            "perturbed_radius",
            "perturbed_flux",
            "perturbed_teff",
        ],
    ].copy()
    if len(candidate_rows):
        frequency = (
            candidate_rows.groupby(["source_row", "kepoi_name"], as_index=False)
            .agg(
                candidate_realizations=("global_trial", "size"),
                minimum_perturbed_radius=("perturbed_radius", "min"),
                maximum_perturbed_radius=("perturbed_radius", "max"),
                minimum_perturbed_flux=("perturbed_flux", "min"),
                maximum_perturbed_flux=("perturbed_flux", "max"),
                minimum_perturbed_teff=("perturbed_teff", "min"),
                maximum_perturbed_teff=("perturbed_teff", "max"),
            )
        )
        frequency.insert(0, "branch", branch)
        frequency["fraction_of_trials"] = (
            frequency.candidate_realizations / EXPECTED_TRIALS
        )
        nominal_lookup = source[
            [
                "source_row",
                "gaia_iso_prad",
                "gaia_iso_insol",
                "teff",
                "totalReliability",
            ]
        ].rename(
            columns={
                "gaia_iso_prad": "nominal_radius",
                "gaia_iso_insol": "nominal_flux",
                "teff": "nominal_teff",
            }
        )
        frequency = frequency.merge(nominal_lookup, on="source_row", how="left")
    else:
        frequency = pd.DataFrame(
            columns=[
                "branch",
                "source_row",
                "kepoi_name",
                "candidate_realizations",
                "minimum_perturbed_radius",
                "maximum_perturbed_radius",
                "minimum_perturbed_flux",
                "maximum_perturbed_flux",
                "minimum_perturbed_teff",
                "maximum_perturbed_teff",
                "fraction_of_trials",
            ]
        )

    summary = {
        "input_sha256": sha256(path),
        "audit_rows": int(len(audit)),
        "reliability_selected_before_domain": count_summary(selected_counts),
        "retained_in_source_domain": count_summary(retained_counts),
        "rectangular_target_candidates": count_summary(rectangle_counts),
        "earth_analog_target_candidates": count_summary(earth_analog_counts),
        "total_earth_analog_candidate_realizations": int(np.sum(earth_analog)),
        "unique_sources_entering_earth_analog_domain": int(
            candidate_rows.source_row.nunique()
        ),
    }
    return summary, trial_table, frequency


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pc-catalog", required=True, type=Path)
    parser.add_argument("--stellar-catalog", required=True, type=Path)
    parser.add_argument("--constant-audit", required=True, type=Path)
    parser.add_argument("--zero-audit", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = load_source_population(args.pc_catalog, args.stellar_catalog)
    radius = source.gaia_iso_prad.to_numpy(dtype=float)
    instellation = source.gaia_iso_insol.to_numpy(dtype=float)
    teff = source.teff.to_numpy(dtype=float)
    reliability = source.totalReliability.to_numpy(dtype=float)

    rectangle = rectangular_target_mask(radius, instellation, teff)
    earth_analog = earth_analog_target_mask(radius, instellation, teff)
    if np.any(earth_analog & ~rectangle):
        raise RuntimeError("Nominal Earth-analog mask is not a subset of its rectangle")
    source_fit_domain = (
        finite_mask(radius, instellation, teff)
        & (SOURCE_RADIUS[0] <= radius)
        & (radius <= SOURCE_RADIUS[1])
        & (SOURCE_INSTELLATION[0] <= instellation)
        & (instellation <= SOURCE_INSTELLATION[1])
        & (SOURCE_TEMPERATURE[0] <= teff)
        & (teff <= SOURCE_TEMPERATURE[1])
    )
    if np.any(earth_analog & ~source_fit_domain):
        raise RuntimeError("Nominal target is not contained in the source fit domain")

    temperature_ok = (
        np.isfinite(teff)
        & (TARGET_TEMPERATURE[0] <= teff)
        & (teff <= TARGET_TEMPERATURE[1])
    )
    radius_ok = (
        np.isfinite(radius)
        & (TARGET_RADIUS[0] <= radius)
        & (radius <= TARGET_RADIUS[1])
    )
    fixed_flux_ok = (
        np.isfinite(instellation)
        & (TARGET_INSTELLATION[0] <= instellation)
        & (instellation <= TARGET_INSTELLATION[1])
    )
    hz_flux_ok = (
        np.isfinite(instellation)
        & (np.maximum(TARGET_INSTELLATION[0], seff(teff, MAXIMUM_GREENHOUSE)) <= instellation)
        & (instellation <= np.minimum(TARGET_INSTELLATION[1], seff(teff, RUNAWAY_1MEARTH)))
    )

    branch_summaries: dict[str, Any] = {}
    trial_tables: list[pd.DataFrame] = []
    frequency_tables: list[pd.DataFrame] = []
    for branch, path in (
        ("constant", args.constant_audit),
        ("zero", args.zero_audit),
    ):
        summary, trial_table, frequency = analyze_perturbation_branch(
            path, branch, source
        )
        branch_summaries[branch] = summary
        trial_tables.append(trial_table)
        frequency_tables.append(frequency)

    nominal = {
        "merged_pc_rows": int(len(source)),
        "sum_totalReliability_all_rows": float(np.sum(reliability)),
        "source_fit_domain": summarize_nominal(source_fit_domain, reliability),
        "temperature_only": summarize_nominal(temperature_ok, reliability),
        "temperature_and_radius": summarize_nominal(
            temperature_ok & radius_ok, reliability
        ),
        "temperature_and_conservative_hz_instellation": summarize_nominal(
            temperature_ok & hz_flux_ok, reliability
        ),
        "radius_and_fixed_0p9_1p1_instellation": summarize_nominal(
            radius_ok & fixed_flux_ok, reliability
        ),
        "rectangular_target": summarize_nominal(rectangle, reliability),
        "earth_analog_target": summarize_nominal(earth_analog, reliability),
    }

    source_containment = {
        "status": "PASS",
        "source_radius_R_earth": list(SOURCE_RADIUS),
        "source_instellation_I_earth": list(SOURCE_INSTELLATION),
        "source_temperature_K": list(SOURCE_TEMPERATURE),
        "target_radius_R_earth": list(TARGET_RADIUS),
        "target_instellation_I_earth_intersect_conservative_HZ": list(
            TARGET_INSTELLATION
        ),
        "target_temperature_K": list(TARGET_TEMPERATURE),
        "interpretation": (
            "The target is geometrically contained in the fitted rectangular "
            "source domain; this does not establish local empirical support."
        ),
    }
    local_support_fail = nominal["earth_analog_target"]["candidate_count"] == 0
    perturbation_sparse = all(
        branch_summaries[branch]["earth_analog_target_candidates"]["quantiles"][
            "q50"
        ]
        == 0.0
        for branch in ("constant", "zero")
    )
    if not (local_support_fail and perturbation_sparse):
        raise RuntimeError("Expected predeclared sparse-support condition was not met")

    result = {
        "status": "FAIL_LOCAL_EMPIRICAL_SUPPORT",
        "engineering_validation": "PASS",
        "scope": (
            "Direct DR25 planet-candidate support for the v4 0.9--1.1 "
            "R_earth / conservative-HZ-intersected 0.9--1.1 I_earth / "
            "5300--6000 K target."
        ),
        "inputs": {
            "pc_catalog": pc_catalog_provenance(args.pc_catalog),
            "stellar_catalog": {
                "path": str(args.stellar_catalog),
                "sha256": sha256(args.stellar_catalog),
            },
            "constant_perturbation_audit": {
                "path": str(args.constant_audit),
                "sha256": sha256(args.constant_audit),
            },
            "zero_perturbation_audit": {
                "path": str(args.zero_audit),
                "sha256": sha256(args.zero_audit),
            },
        },
        "source_domain_containment": source_containment,
        "nominal_support": nominal,
        "corrected_measurement_realizations": branch_summaries,
        "scientific_interpretation": (
            "The frozen Lambda_EE result is a separable power-law model "
            "projection into a locally data-empty target region, not a direct "
            "DR25 candidate-supported measurement. Posterior intervals do not "
            "include this model-form/local-support uncertainty."
        ),
        "decision": (
            "Retain the numerical result only with explicit projection language, "
            "freeze model-form sensitivity separately, and do not describe the "
            "target occurrence as directly constrained by local DR25 candidates."
        ),
    }

    result_path = output / "dr25_support_audit.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")

    trial_path = output / "dr25_target_counts_by_trial.csv"
    with trial_path.open("w", encoding="utf-8", newline="\n") as handle:
        pd.concat(trial_tables, ignore_index=True).to_csv(
            handle, index=False, lineterminator="\n"
        )

    frequency_path = output / "dr25_perturbed_candidate_frequency.csv"
    with frequency_path.open("w", encoding="utf-8", newline="\n") as handle:
        pd.concat(frequency_tables, ignore_index=True).to_csv(
            handle, index=False, lineterminator="\n"
        )

    near = source.loc[
        (temperature_ok.astype(int) + radius_ok.astype(int) + fixed_flux_ok.astype(int))
        >= 2,
        [
            "source_row",
            "kepoi_name",
            "kepid_x",
            "gaia_iso_prad",
            "gaia_iso_insol",
            "teff",
            "totalReliability",
        ],
    ].copy()
    near["temperature_5300_6000"] = temperature_ok[near.index]
    near["radius_0p9_1p1"] = radius_ok[near.index]
    near["fixed_instellation_0p9_1p1"] = fixed_flux_ok[near.index]
    near["conservative_hz_instellation_intersection"] = hz_flux_ok[near.index]
    near_path = output / "dr25_nominal_near_support.csv"
    with near_path.open("w", encoding="utf-8", newline="\n") as handle:
        near.to_csv(handle, index=False, lineterminator="\n")

    manifest_path = output / "SHA256SUMS_dr25_support.txt"
    generated = [result_path, trial_path, frequency_path, near_path]
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "".join(f"{sha256(path)}  {path.name}\n" for path in generated)
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
