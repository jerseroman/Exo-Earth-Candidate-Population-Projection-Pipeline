#!/usr/bin/env python3
"""Weighted host-selector and native-PARSEC TAMS audit for manuscript v4."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


LOW_T_NATIVE_K = 5390.13944
CANONICAL_N_STAR = 263061992.36674237
EXPECTED_RADIAL_NODES = np.array([7.0, 7.5, 8.0, 8.5, 9.0])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def attach_radial_weights(frame: pd.DataFrame) -> pd.DataFrame:
    selected = frame.loc[
        frame.R_kpc.between(EXPECTED_RADIAL_NODES[0], EXPECTED_RADIAL_NODES[-1])
    ].copy()
    nodes = np.sort(selected.R_kpc.unique())
    if not np.array_equal(nodes, EXPECTED_RADIAL_NODES):
        raise RuntimeError(f"Unexpected radial nodes: {nodes}")
    coefficients = np.empty(len(nodes), dtype=float)
    coefficients[0] = 0.5 * (nodes[1] - nodes[0])
    coefficients[-1] = 0.5 * (nodes[-1] - nodes[-2])
    coefficients[1:-1] = 0.5 * (nodes[2:] - nodes[:-2])
    coefficient_by_radius = dict(zip(nodes, coefficients))
    selected["integrated_weight"] = (
        selected.N_surface_pc_2
        * 2.0
        * math.pi
        * selected.R_kpc
        * 1.0e6
        * selected.R_kpc.map(coefficient_by_radius)
    )
    if not np.isfinite(selected.integrated_weight).all():
        raise RuntimeError("Non-finite integrated host weight")
    if (selected.integrated_weight < 0.0).any():
        raise RuntimeError("Negative integrated host weight")
    return selected


def weighted_quantile(
    values: np.ndarray, weights: np.ndarray, probabilities: tuple[float, ...]
) -> list[float]:
    order = np.argsort(values)
    sorted_values = np.asarray(values, dtype=float)[order]
    sorted_weights = np.asarray(weights, dtype=float)[order]
    cumulative = np.cumsum(sorted_weights)
    cumulative /= cumulative[-1]
    return [
        float(np.interp(probability, cumulative, sorted_values))
        for probability in probabilities
    ]


def selection_summary(frame: pd.DataFrame, mask: np.ndarray) -> dict[str, float]:
    weights = frame.integrated_weight.to_numpy(dtype=float)
    active = np.asarray(mask, dtype=bool)
    n_star = float(np.sum(weights[active]))
    lambda_hz = float(np.sum(weights[active] * frame.f_HZ.to_numpy(dtype=float)[active]))
    lambda_ee = float(
        np.sum(weights[active] * frame.f_earth10.to_numpy(dtype=float)[active])
    )
    return {
        "N_star": n_star,
        "mean_f_HZ_plugin": lambda_hz / n_star,
        "mean_f_EE_plugin": lambda_ee / n_star,
        "Lambda_HZ_plugin": lambda_hz,
        "Lambda_EE_plugin": lambda_ee,
    }


def fractional_change(value: float, reference: float) -> float:
    return (value - reference) / reference


def validate_native_solar_points(path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    points = pd.read_csv(path)
    required = {"Z", "Teff_K", "R_Rsun", "mass", "age_Gyr", "file"}
    missing = required.difference(points.columns)
    if missing:
        raise RuntimeError(f"Native TAMS table missing columns: {sorted(missing)}")
    for column in ("Z", "Teff_K", "R_Rsun", "mass", "age_Gyr"):
        points[column] = pd.to_numeric(points[column], errors="raise")

    solar_low_mass = points.loc[
        np.isclose(points.Z, 0.017)
        & (points.mass <= 2.0)
        & (points.R_Rsun < 10.0)
        & (points.age_Gyr < 30.0)
        & points.Teff_K.between(5150.0, 6060.3)
    ].copy()
    solar_low_mass.sort_values("Teff_K", inplace=True)
    if len(solar_low_mass) != 9:
        raise RuntimeError(
            f"Expected nine low-mass native solar TAMS nodes, found {len(solar_low_mass)}"
        )
    if not (np.diff(solar_low_mass.Teff_K) > 0.0).all():
        raise RuntimeError("Native solar TAMS temperatures are not increasing")
    if not (np.diff(solar_low_mass.R_Rsun) > 0.0).all():
        raise RuntimeError("Native solar TAMS radii are not increasing")

    # The public generator's age<20 Gyr subset starts at 5390 K. These seven
    # nodes must reproduce the immutable Berger/Huber reference. The two lower
    # mass native phase-7 nodes bracket the manuscript's 5300-K boundary but
    # have formal TAMS ages above 20 Gyr; they are used only to test whether the
    # special 5200-K anchor changes classification.
    reference_subset = solar_low_mass.loc[
        (solar_low_mass.age_Gyr < 20.0)
        & (solar_low_mass.Teff_K >= LOW_T_NATIVE_K - 0.01)
    ].copy()
    if len(reference_subset) != 7:
        raise RuntimeError(
            f"Expected seven age<20 Gyr validation nodes, found {len(reference_subset)}"
        )

    reference_teff = np.array(
        [
            5390.13944,
            5517.85139,
            5633.13293,
            5738.25706,
            5844.13178,
            5951.82290,
            6060.24246,
        ]
    )
    reference_radius = np.array(
        [1.22926, 1.28542, 1.35053, 1.42375, 1.49188, 1.55332, 1.61155]
    )
    max_abs_teff = float(
        np.max(np.abs(reference_subset.Teff_K.to_numpy() - reference_teff))
    )
    max_rel_radius = float(
        np.max(
            np.abs(reference_subset.R_Rsun.to_numpy() - reference_radius)
            / reference_radius
        )
    )
    if max_abs_teff > 0.01 or max_rel_radius > 1.0e-4:
        raise RuntimeError("Native solar PARSEC nodes do not reproduce the reference")
    return solar_low_mass, {
        "status": "PASS",
        "reference_validation_node_count": int(len(reference_subset)),
        "reference_validation_temperature_range_K": [
            float(reference_subset.Teff_K.min()),
            float(reference_subset.Teff_K.max()),
        ],
        "full_native_selector_node_count": int(len(solar_low_mass)),
        "full_native_selector_temperature_range_K": [
            float(solar_low_mass.Teff_K.min()),
            float(solar_low_mass.Teff_K.max()),
        ],
        "mass_range_Msun": [
            float(solar_low_mass.mass.min()),
            float(solar_low_mass.mass.max()),
        ],
        "age_range_Gyr": [
            float(solar_low_mass.age_Gyr.min()),
            float(solar_low_mass.age_Gyr.max()),
        ],
        "low_temperature_bracketing_nodes": solar_low_mass.loc[
            solar_low_mass.Teff_K < LOW_T_NATIVE_K,
            ["Teff_K", "R_Rsun", "mass", "age_Gyr", "file"],
        ].to_dict(orient="records"),
        "max_abs_temperature_difference_K": max_abs_teff,
        "max_relative_radius_difference": max_rel_radius,
        "excluded_anchor": "5200 K, 1.15 Rsun",
        "interpretation": (
            "The 5300--5390 K classification test is bracketed by native "
            "0.75 and 0.80 Msun phase-7 nodes with formal TAMS ages above "
            "20 Gyr. No 5200-K boundary anchor or extrapolation is used."
        ),
    }


def assess_metallicity_surface(points_path: Path) -> dict[str, Any]:
    points = pd.read_csv(points_path)
    for column in ("Z", "Teff_K", "R_Rsun", "mass", "age_Gyr"):
        points[column] = pd.to_numeric(points[column], errors="raise")
    contaminants = points.loc[(points.mass > 2.0) | (points.R_Rsun >= 10.0)].copy()
    coverage: dict[str, Any] = {}
    for metallicity, group in points.groupby("Z"):
        low_mass = group.loc[(group.mass <= 2.0) & (group.R_Rsun < 10.0)]
        minimum = float(low_mass.Teff_K.min()) if len(low_mass) else None
        maximum = float(low_mass.Teff_K.max()) if len(low_mass) else None
        coverage[f"{float(metallicity):.6g}"] = {
            "low_mass_point_count": int(len(low_mass)),
            "temperature_range_K": [minimum, maximum],
            "covers_5300_to_6000_K_without_extrapolation": bool(
                len(low_mass) and minimum <= 5300.0 and maximum >= 6000.0
            ),
        }
    incomplete = [
        metallicity
        for metallicity, result in coverage.items()
        if not result["covers_5300_to_6000_K_without_extrapolation"]
    ]
    status = "FAIL" if len(contaminants) or incomplete else "PASS"
    return {
        "status": status,
        "reason": (
            "The archived differential surface mixes massive phase-7 giant or "
            "supergiant points into Teff interpolation, while several low-mass "
            "metallicity tracks do not cover 5300--6000 K without extrapolation."
            if status == "FAIL"
            else "All anchors form a low-mass TAMS surface with full coverage."
        ),
        "contaminating_point_count": int(len(contaminants)),
        "contaminating_Z_values": sorted(
            {float(value) for value in contaminants.Z.to_numpy()}
        ),
        "maximum_contaminating_mass_Msun": (
            float(contaminants.mass.max()) if len(contaminants) else None
        ),
        "maximum_contaminating_radius_Rsun": (
            float(contaminants.R_Rsun.max()) if len(contaminants) else None
        ),
        "low_mass_coverage": coverage,
        "metallicities_without_full_low_mass_coverage": incomplete,
        "decision": "Exclude the reported metallicity-TAMS delta from v4.",
    }


def posterior_selector_summary(
    canonical: dict[str, Any], legacy: dict[str, Any]
) -> dict[str, Any]:
    quantities = ("mean_f_HZ", "mean_f_EE", "Lambda_HZ", "Lambda_EE")
    result: dict[str, Any] = {
        "canonical_N_star": canonical["host_rows"]["N_star_7_9_kpc"],
        "legacy_N_star": legacy["host_rows"]["N_star_7_9_kpc"],
        "legacy_quantiles": {},
        "legacy_q50_fractional_change_vs_canonical": {},
    }
    for quantity in quantities:
        result["legacy_quantiles"][quantity] = legacy["posterior_quantiles"][quantity]
        result["legacy_q50_fractional_change_vs_canonical"][quantity] = fractional_change(
            float(legacy["posterior_quantiles"][quantity]["q50"]),
            float(canonical["posterior_quantiles"][quantity]["q50"]),
        )
    result["N_star_fractional_change_vs_canonical"] = fractional_change(
        float(result["legacy_N_star"]), float(result["canonical_N_star"])
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--native-tams-points", required=True, type=Path)
    parser.add_argument("--kepler-stars", required=True, type=Path)
    parser.add_argument("--canonical-constant", required=True, type=Path)
    parser.add_argument("--canonical-zero", required=True, type=Path)
    parser.add_argument("--legacy-constant", required=True, type=Path)
    parser.add_argument("--legacy-zero", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    parent = pd.read_csv(args.parent)
    parent.rename(columns={"N_surface_pc-2": "N_surface_pc_2"}, inplace=True)
    required = {
        "R_kpc",
        "Teff_K",
        "logg",
        "N_surface_pc_2",
        "Rstar_g_Rsun",
        "R_TAMS_Rsun",
        "A_logg",
        "B_TAMS_MS",
        "f_HZ",
        "f_earth10",
    }
    missing = required.difference(parent.columns)
    if missing:
        raise RuntimeError(f"Parent host table missing columns: {sorted(missing)}")
    numeric = required.difference({"component"})
    for column in numeric:
        parent[column] = pd.to_numeric(parent[column], errors="raise")
    parent = attach_radial_weights(parent)

    canonical = parent.B_TAMS_MS.to_numpy(dtype=int) == 1
    legacy = parent.A_logg.to_numpy(dtype=int) == 1
    below_tams = parent.Rstar_g_Rsun.to_numpy() <= parent.R_TAMS_Rsun.to_numpy()
    compact_veto = below_tams & (parent.logg.to_numpy() >= 7.0)
    tams_radius_rejected = ~below_tams
    weights = parent.integrated_weight.to_numpy(dtype=float)
    parent_weight = float(np.sum(weights))
    canonical_summary = selection_summary(parent, canonical)
    if abs(canonical_summary["N_star"] - CANONICAL_N_STAR) > 0.1:
        raise RuntimeError(f"Canonical host count mismatch: {canonical_summary['N_star']}")

    native, native_validation = validate_native_solar_points(args.native_tams_points)
    parent_teff = parent.Teff_K.to_numpy(dtype=float)
    native_min = float(native.Teff_K.min())
    native_max = float(native.Teff_K.max())
    if float(parent_teff.min()) < native_min or float(parent_teff.max()) > native_max:
        raise RuntimeError(
            "Native solar TAMS interpolation would extrapolate: "
            f"parent={parent_teff.min()}..{parent_teff.max()} K, "
            f"native={native_min}..{native_max} K"
        )
    native_radius_full = 10.0 ** np.interp(
        parent_teff,
        native.Teff_K.to_numpy(),
        np.log10(native.R_Rsun.to_numpy()),
    )
    native_full = (
        parent.Rstar_g_Rsun.to_numpy() <= native_radius_full
    ) & (parent.logg.to_numpy() < 7.0)
    native_full_summary = selection_summary(parent, native_full)
    shared = parent_teff >= LOW_T_NATIVE_K
    native_radius = 10.0 ** np.interp(
        parent.loc[shared, "Teff_K"].to_numpy(),
        native.Teff_K.to_numpy(),
        np.log10(native.R_Rsun.to_numpy()),
    )
    native_shared = np.zeros(len(parent), dtype=bool)
    native_shared[shared] = (
        parent.loc[shared, "Rstar_g_Rsun"].to_numpy() <= native_radius
    ) & (parent.loc[shared, "logg"].to_numpy() < 7.0)
    canonical_shared = canonical & shared
    shared_disagreement_weight = float(
        np.sum(weights[native_shared != canonical_shared])
    )
    native_shared_summary = selection_summary(parent, native_shared)
    canonical_shared_summary = selection_summary(parent, canonical_shared)

    low_band = canonical & (parent_teff < LOW_T_NATIVE_K)
    low_summary = selection_summary(parent, low_band)
    native_low_summary = selection_summary(
        parent, native_full & (parent_teff < LOW_T_NATIVE_K)
    )
    legacy_plugin_summary = selection_summary(parent, legacy)

    jj_radius = parent.loc[canonical, "Rstar_g_Rsun"].to_numpy(dtype=float)
    jj_weight = weights[canonical]
    jj_q16, jj_median, jj_q84 = weighted_quantile(
        jj_radius, jj_weight, (0.16, 0.5, 0.84)
    )
    jj_mean = float(np.average(jj_radius, weights=jj_weight))
    jj_above_135 = float(np.sum(jj_weight[jj_radius > 1.35]) / np.sum(jj_weight))

    kepler = pd.read_csv(args.kepler_stars, usecols=["teff", "radius"])
    kepler = kepler.loc[
        pd.to_numeric(kepler.teff, errors="coerce").between(5300.0, 6000.0)
    ].copy()
    kepler.radius = pd.to_numeric(kepler.radius, errors="coerce")
    kepler.dropna(subset=["radius"], inplace=True)
    kepler_mean = float(kepler.radius.mean())
    kepler_median = float(kepler.radius.median())
    kepler_above_135 = float(np.mean(kepler.radius.to_numpy() > 1.35))

    canonical_constant = load_json(args.canonical_constant)
    canonical_zero = load_json(args.canonical_zero)
    legacy_constant = load_json(args.legacy_constant)
    legacy_zero = load_json(args.legacy_zero)

    low_fractional = {
        quantity: low_summary[quantity] / canonical_summary[quantity]
        for quantity in ("N_star", "Lambda_HZ_plugin", "Lambda_EE_plugin")
    }
    native_full_change = {
        quantity: fractional_change(
            native_full_summary[quantity], canonical_summary[quantity]
        )
        for quantity in ("N_star", "Lambda_HZ_plugin", "Lambda_EE_plugin")
    }
    drop_low_band_change = {
        quantity: fractional_change(
            native_shared_summary[quantity], canonical_summary[quantity]
        )
        for quantity in ("N_star", "Lambda_HZ_plugin", "Lambda_EE_plugin")
    }
    maximum_native_change = max(abs(value) for value in native_full_change.values())
    if maximum_native_change > 0.05:
        anchor_gate = "REASSESS_CANONICAL_SELECTOR"
    elif maximum_native_change > 0.02:
        anchor_gate = "INCLUDE_IN_MAIN_SENSITIVITY_TABLE"
    else:
        anchor_gate = "PASS"

    result = {
        "status": (
            "REASSESS_CANONICAL_SELECTOR"
            if anchor_gate == "REASSESS_CANONICAL_SELECTOR"
            else "PASS_WITH_INVALID_METALLICITY_TEST_EXCLUDED"
        ),
        "scope": "JJ 7--9 kpc host-selector validation; plug-in occurrence is diagnostic only.",
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in {
                "parent": args.parent,
                "native_tams_points": args.native_tams_points,
                "kepler_stars": args.kepler_stars,
                "canonical_constant": args.canonical_constant,
                "canonical_zero": args.canonical_zero,
                "legacy_constant": args.legacy_constant,
                "legacy_zero": args.legacy_zero,
            }.items()
        },
        "weighted_selector_decomposition": {
            "parent_N_star": parent_weight,
            "canonical_N_star": canonical_summary["N_star"],
            "TAMS_radius_rejected_N_star": float(np.sum(weights[tams_radius_rejected])),
            "TAMS_radius_rejected_fraction_of_parent": float(
                np.sum(weights[tams_radius_rejected]) / parent_weight
            ),
            "compact_veto_N_star": float(np.sum(weights[compact_veto])),
            "compact_veto_fraction_of_parent": float(
                np.sum(weights[compact_veto]) / parent_weight
            ),
            "compact_veto_fraction_of_below_TAMS_population": float(
                np.sum(weights[compact_veto]) / np.sum(weights[below_tams])
            ),
            "decomposition_relative_closure_error": float(
                (
                    np.sum(weights[tams_radius_rejected])
                    + np.sum(weights[compact_veto])
                    + np.sum(weights[canonical])
                    - parent_weight
                )
                / parent_weight
            ),
        },
        "canonical_plugin": canonical_summary,
        "legacy_plugin": legacy_plugin_summary,
        "native_solar_TAMS_validation": native_validation,
        "shared_domain_native_vs_canonical": {
            "temperature_domain_K": [LOW_T_NATIVE_K, 6000.0],
            "canonical": canonical_shared_summary,
            "native": native_shared_summary,
            "disagreement_integrated_weight": shared_disagreement_weight,
            "N_star_fractional_change": fractional_change(
                native_shared_summary["N_star"], canonical_shared_summary["N_star"]
            ),
        },
        "low_temperature_anchor_dependence": {
            "temperature_domain_K": [5300.0, LOW_T_NATIVE_K],
            "interval_convention": "lower-inclusive, upper-exclusive",
            "contribution": low_summary,
            "fraction_of_canonical": low_fractional,
            "native_selector_without_5200_K_anchor": native_full_summary,
            "native_low_temperature_contribution": native_low_summary,
            "native_selector_fractional_change_vs_canonical": native_full_change,
            "drop_low_temperature_band_stress_test_fractional_change": (
                drop_low_band_change
            ),
            "drop_band_interpretation": (
                "Removing the full 5300--5390 K estimand is a domain-truncation "
                "stress test, not the native-PARSEC selector comparison."
            ),
            "gate": anchor_gate,
        },
        "stellar_radius_diagnostics": {
            "JJ_canonical_weighted": {
                "mean_Rsun": jj_mean,
                "q16_Rsun": jj_q16,
                "median_Rsun": jj_median,
                "q84_Rsun": jj_q84,
                "fraction_Rstar_gt_1p35_Rsun": jj_above_135,
            },
            "Kepler_Hab2_5300_6000_unweighted": {
                "star_count": int(len(kepler)),
                "mean_Rsun": kepler_mean,
                "median_Rsun": kepler_median,
                "fraction_Rstar_gt_1p35_Rsun": kepler_above_135,
            },
            "linear_width_ratio_diagnostic": {
                "mean_to_mean_ratio": kepler_mean / jj_mean,
                "mean_to_mean_fractional_difference": kepler_mean / jj_mean - 1.0,
                "median_to_median_ratio": kepler_median / jj_median,
                "median_to_median_fractional_difference": (
                    kepler_median / jj_median - 1.0
                ),
                "inconsistent_mean_to_median_ratio": kepler_mean / jj_median,
                "warning": (
                    "The previously suggested approximately 1.028/0.999 ratio "
                    "mixes a Kepler mean with a JJ median. It is not a valid "
                    "like-for-like width diagnostic and must not be used."
                ),
                "interpretation": (
                    "At fixed Teff and instellation interval, semimajor-axis "
                    "width scales linearly with stellar radius. This remains a "
                    "denominator-mismatch diagnostic, not a post-fit correction."
                ),
            },
        },
        "posterior_legacy_selector": {
            "constant": posterior_selector_summary(
                canonical_constant, legacy_constant
            ),
            "zero": posterior_selector_summary(canonical_zero, legacy_zero),
        },
        "metallicity_dependent_TAMS_audit": assess_metallicity_surface(
            args.native_tams_points
        ),
        "radial_migration_limitation": (
            "Present-day R=7--9 kpc is not a birth-radius selection. Radial "
            "migration can mix ages, metallicities, and disk components; no "
            "migration correction is inferred from the JJ snapshot."
        ),
        "threshold_policy": {
            "above_2_percent": "include in the main sensitivity table",
            "above_5_percent": "reassess the canonical host selector",
        },
    }

    result_path = output / "host_tams_audit.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    rows = []
    for name, summary in (
        ("canonical", canonical_summary),
        ("legacy", legacy_plugin_summary),
        ("canonical_shared_native_domain", canonical_shared_summary),
        ("native_shared_domain", native_shared_summary),
        ("native_full_without_5200_anchor", native_full_summary),
        ("low_temperature_contribution", low_summary),
        ("native_low_temperature_contribution", native_low_summary),
    ):
        rows.append({"selector": name, **summary})
    selector_path = output / "host_selector_sensitivity.csv"
    with selector_path.open("w", encoding="utf-8", newline="\n") as handle:
        pd.DataFrame(rows).to_csv(handle, index=False, lineterminator="\n")
    manifest = output / "SHA256SUMS_host_tams_audit.txt"
    generated = [result_path, selector_path]
    with manifest.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "".join(f"{sha256(path)}  {path.name}\n" for path in generated)
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
