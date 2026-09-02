#!/usr/bin/env python3
"""Audit direct DR25 support for the v4 Earth-analog integration domain."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
from dataclasses import dataclass
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
STELLAR_CATALOG_SHA256 = "79744e4daf1f46414dacada9f91be017b2dcfed68028ef18544e3764fe5a4fa3"
STELLAR_CATALOG_SIZE_BYTES = 100_194_836
PUBLIC_MANIFEST_NAME = "SHA256SUMS_dr25_support_public.txt"
PUBLIC_FILES = ("dr25_support_audit.json", "dr25_target_counts_by_trial.csv")
MAXIMUM_GREENHOUSE = (
    0.356,
    6.171e-5,
    1.698e-9,
    -3.198e-12,
    -5.575e-16,
)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes
    sha256: str
    size_bytes: int


def read_file_snapshot(path: Path, label: str) -> FileSnapshot:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"{label} cannot be inspected: {candidate}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise RuntimeError(f"{label} cannot be opened safely: {candidate}") from error
    with os.fdopen(descriptor, "rb") as stream:
        opened_before = os.fstat(stream.fileno())
        data = stream.read()
        opened_after = os.fstat(stream.fileno())
    try:
        after = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"{label} disappeared while being read: {candidate}") from error
    identities = (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_size,
            opened_before.st_mtime_ns,
        ),
        (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_size,
            opened_after.st_mtime_ns,
        ),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    )
    if len(set(identities)) != 1 or len(data) != opened_after.st_size:
        raise RuntimeError(f"{label} changed while being read: {candidate}")
    return FileSnapshot(
        candidate.resolve(), data, hashlib.sha256(data).hexdigest(), len(data)
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pc_catalog_provenance_snapshot(snapshot: Any) -> dict[str, Any]:
    observed = snapshot.sha256
    representations = {
        PC_CATALOG_SOURCE_LF_SHA256: "pinned_source_lf",
        PC_CATALOG_WINDOWS_CRLF_SHA256: "historical_windows_crlf_checkout",
    }
    if observed not in representations:
        raise RuntimeError(f"Unexpected PC-catalog representation: {observed}")
    return {
        "filename": snapshot.path.name,
        "sha256": observed,
        "size_bytes": snapshot.size_bytes,
        "source_locked_sha256": PC_CATALOG_SOURCE_LF_SHA256,
        "representation": representations[observed],
        "line_ending_note": (
            "The pinned source uses LF. The historical Windows checkout used "
            "CRLF for all 2278 lines; parsed CSV fields are unchanged."
        ),
    }


def pc_catalog_provenance(path: Path) -> dict[str, Any]:
    return pc_catalog_provenance_snapshot(read_file_snapshot(path, "DR25 PC catalog"))


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


def load_source_population_bytes(pc_data: bytes, stellar_data: bytes) -> pd.DataFrame:
    pc = pd.read_csv(io.BytesIO(pc_data), float_precision="round_trip")
    stellar = pd.read_csv(
        io.BytesIO(stellar_data),
        usecols=["kepid", "logg"],
        float_precision="round_trip",
    )
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


def load_source_population(pc_path: Path, stellar_path: Path) -> pd.DataFrame:
    pc_snapshot = read_file_snapshot(pc_path, "DR25 PC catalog")
    stellar_snapshot = read_file_snapshot(stellar_path, "DR25 stellar catalog")
    return load_source_population_bytes(pc_snapshot.data, stellar_snapshot.data)


def _parse_nonnegative_integer_column(frame: pd.DataFrame, column: str) -> np.ndarray:
    raw = frame[column].astype(str)
    if raw.map(lambda value: re.fullmatch(r"0|[1-9][0-9]*", value) is not None).eq(
        False
    ).any():
        raise RuntimeError(f"DR25 audit column is not exact non-negative integer text: {column}")
    values = raw.map(int).to_numpy(dtype=np.int64)
    return values


def _parse_boolean_column(frame: pd.DataFrame, column: str) -> np.ndarray:
    raw = frame[column].astype(str)
    if not set(raw).issubset({"True", "False"}):
        raise RuntimeError(f"DR25 audit column is not exact Boolean text: {column}")
    return raw.eq("True").to_numpy(dtype=bool)


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
    snapshot = read_file_snapshot(path, f"{branch} DR25 perturbation audit")
    audit = pd.read_csv(
        io.BytesIO(snapshot.data),
        compression="gzip" if snapshot.path.name.endswith(".gz") else None,
        usecols=columns,
        dtype=str,
        keep_default_na=False,
    )
    if set(audit.branch.unique()) != {branch}:
        raise RuntimeError(f"Unexpected branch labels in {path}")
    if set(audit.measurement_error_mode.unique()) != {CORRECTED_MODE}:
        raise RuntimeError(f"Unexpected measurement-error mode in {path}")
    global_trial = _parse_nonnegative_integer_column(audit, "global_trial")
    source_rows = _parse_nonnegative_integer_column(audit, "source_row")
    audit["global_trial"] = global_trial
    audit["source_row"] = source_rows
    trials = np.sort(np.unique(global_trial))
    if not np.array_equal(trials, np.arange(EXPECTED_TRIALS)):
        raise RuntimeError(f"Expected trials 0..{EXPECTED_TRIALS - 1} for {branch}")
    if audit.duplicated(["global_trial", "source_row"]).any():
        raise RuntimeError(f"Duplicate source row within a {branch} trial")
    if source_rows.min() < 0 or source_rows.max() >= len(source):
        raise RuntimeError(f"Out-of-range source_row in {branch}")
    expected_names = source.kepoi_name.to_numpy(dtype=str)[source_rows]
    if not np.array_equal(audit.kepoi_name.to_numpy(dtype=str), expected_names):
        raise RuntimeError(f"Source-row identity mismatch in {branch}")

    try:
        radius = pd.to_numeric(audit.perturbed_radius, errors="raise").to_numpy(dtype=float)
        instellation = pd.to_numeric(audit.perturbed_flux, errors="raise").to_numpy(dtype=float)
        teff = pd.to_numeric(audit.perturbed_teff, errors="raise").to_numpy(dtype=float)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"Non-numeric DR25 perturbation values for {branch}") from error
    if not finite_mask(radius, instellation, teff).all():
        raise RuntimeError(f"Non-finite DR25 perturbation values for {branch}")
    audit["perturbed_radius"] = radius
    audit["perturbed_flux"] = instellation
    audit["perturbed_teff"] = teff
    rectangle = rectangular_target_mask(radius, instellation, teff)
    earth_analog = earth_analog_target_mask(radius, instellation, teff)
    if np.any(earth_analog & ~rectangle):
        raise RuntimeError("Earth-analog mask is not a subset of its rectangle")
    retained = _parse_boolean_column(audit, "retained_by_active_policy")
    if np.any(earth_analog & ~retained):
        raise RuntimeError("A target-domain row was removed by the active source policy")

    trial_index = global_trial
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
        "input_sha256": snapshot.sha256,
        "realization_count": EXPECTED_TRIALS,
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
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise RuntimeError("DR25 support output directory must be absent or empty")
    pc_snapshot = read_file_snapshot(args.pc_catalog, "DR25 PC catalog")
    stellar_snapshot = read_file_snapshot(args.stellar_catalog, "DR25 stellar catalog")
    pc_provenance = pc_catalog_provenance_snapshot(pc_snapshot)
    if pc_provenance["representation"] != "pinned_source_lf":
        raise RuntimeError("Fresh DR25 audit requires the exact pinned LF PC catalog")
    if (
        stellar_snapshot.sha256 != STELLAR_CATALOG_SHA256
        or stellar_snapshot.size_bytes != STELLAR_CATALOG_SIZE_BYTES
    ):
        raise RuntimeError("Fresh DR25 audit requires the exact locked stellar catalog")
    source = load_source_population_bytes(pc_snapshot.data, stellar_snapshot.data)
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
            "pc_catalog": pc_provenance,
            "stellar_catalog": {
                "filename": stellar_snapshot.path.name,
                "sha256": stellar_snapshot.sha256,
                "size_bytes": stellar_snapshot.size_bytes,
            },
            "constant_perturbation_audit": {
                "filename": args.constant_audit.name,
                "sha256": branch_summaries["constant"]["input_sha256"],
            },
            "zero_perturbation_audit": {
                "filename": args.zero_audit.name,
                "sha256": branch_summaries["zero"]["input_sha256"],
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

    public_output = output / "public"
    private_output = output / "private"
    public_output.mkdir(parents=True)
    private_output.mkdir(parents=True)
    result_path = public_output / "dr25_support_audit.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write("\n")

    trial_path = public_output / "dr25_target_counts_by_trial.csv"
    with trial_path.open("w", encoding="utf-8", newline="\n") as handle:
        pd.concat(trial_tables, ignore_index=True).to_csv(
            handle, index=False, lineterminator="\n"
        )

    frequency_path = private_output / "dr25_perturbed_candidate_frequency.csv"
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
    near_path = private_output / "dr25_nominal_near_support.csv"
    with near_path.open("w", encoding="utf-8", newline="\n") as handle:
        near.to_csv(handle, index=False, lineterminator="\n")

    manifest_path = public_output / PUBLIC_MANIFEST_NAME
    generated = [result_path, trial_path]
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "".join(f"{sha256(path)}  {path.name}\n" for path in generated)
        )
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
