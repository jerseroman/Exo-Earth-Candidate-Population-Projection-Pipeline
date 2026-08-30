#!/usr/bin/env python3
"""Independently rederive radial-convergence observables from private JJ SSP bytes."""

from __future__ import annotations

import csv
import io
import math
from pathlib import Path
import re
import sys
from typing import Any

import numpy as np


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import verify_age_cut_sensitivity as independent_reference  # noqa: E402
import verify_age_cut_ssp_contract as secure_io  # noqa: E402


DRS = (1.0, 0.5, 0.25)
COMPONENTS = (("d", "thin", 0), ("t", "thick", 1))
AGE_MIN_GYR = 4.57
LOGG_MAX = 7.0
LOGG_SUN = 4.438
RADIAL_COLUMNS = (
    "R_kpc",
    "dN_dR",
    "dL1_dR",
    "dL2_dR",
    "Sigma_TAMS_pc-2",
    "Sigma_thick_TAMS_pc-2",
)
SSP_PATTERN = re.compile(r"^SSP_R[0-9]+(?:\.[0-9]+)?_[dt]_Padova\.csv$")
DOMAINS = {
    "lineweaver_7_9": (7.0, 9.0),
    "full_JJ_4_14": (4.0, 14.0),
}


class RadialDerivationError(RuntimeError):
    """Raised when private SSP evidence cannot be rederived safely."""


def fail(message: str) -> None:
    raise RadialDerivationError(message)


def radii_for_dr(dr: float) -> tuple[float, ...]:
    if type(dr) is not float or dr not in DRS:
        fail(f"unsupported exact radial spacing: {dr!r}")
    count = int(round((14.0 - 4.0) / dr)) + 1
    radii = tuple(4.0 + index * dr for index in range(count))
    if radii[0] != 4.0 or radii[-1] != 14.0:
        fail("radial grid endpoints are not exact")
    return radii


def tag(dr: float) -> str:
    return str(dr).replace(".", "p")


def ssp_name(radius: float, component: str) -> str:
    if component not in {"d", "t"}:
        fail("invalid JJ disk component")
    return f"SSP_R{str(float(radius))}_{component}_Padova.csv"


def expected_ssp_names(dr: float) -> tuple[str, ...]:
    return tuple(
        ssp_name(radius, component)
        for radius in radii_for_dr(dr)
        for component, _, _ in COMPONENTS
    )


def discover_private_ssp(run_dir_path: Path, dr: float) -> dict[str, secure_io.FileSnapshot]:
    root = secure_io.require_directory(run_dir_path, "private JJ radial run root")
    snapshots: dict[str, secure_io.FileSnapshot] = {}
    parents: set[Path] = set()
    for name in expected_ssp_names(dr):
        matches = [path for path in root.rglob(name) if path.is_file() or path.is_symlink()]
        if len(matches) != 1:
            fail(f"expected exactly one private SSP member {name}, found {len(matches)}")
        try:
            snapshot = secure_io.read_snapshot(matches[0], f"private SSP member {name}")
        except secure_io.SSPContractError as exc:
            fail(str(exc))
        snapshots[name] = snapshot
        parents.add(snapshot.path.parent)
    if len(parents) != 1:
        fail("private SSP members do not share one JJ output directory")
    parent = next(iter(parents))
    observed = {
        path.name
        for path in parent.iterdir()
        if path.is_file() or path.is_symlink()
        if SSP_PATTERN.fullmatch(path.name) is not None
    }
    if observed != set(expected_ssp_names(dr)):
        fail("private JJ output has an incomplete or extra Padova SSP member set")
    return snapshots


def occurrence_normalization() -> float:
    def power_integral(lo: float, hi: float, exponent: float) -> float:
        return (hi ** (exponent + 1.0) - lo ** (exponent + 1.0)) / (
            exponent + 1.0
        )

    radius = power_integral(0.5, 2.5, independent_reference.ALPHA)
    instellation = power_integral(0.2, 2.2, independent_reference.BETA)
    q1 = independent_reference.GAMMA + 3.16
    q2 = independent_reference.GAMMA + 4.49
    geometric = (
        10.0 ** (-11.839)
        * power_integral(independent_reference.T0, independent_reference.T_BREAK, q1)
        + 10.0 ** (-16.769)
        * power_integral(independent_reference.T_BREAK, independent_reference.T1, q2)
    ) / (independent_reference.T1 - independent_reference.T0)
    result = 1.0 / (radius * instellation * geometric)
    if not math.isfinite(result) or result <= 0.0:
        fail("occurrence normalization is invalid")
    return result


def rederive_private_run(
    run_dir: Path,
    dr: float,
) -> dict[str, Any]:
    snapshots = discover_private_ssp(run_dir, dr)
    try:
        tams_temperature, tams_radius = independent_reference.load_tams_reference()
    except independent_reference.VerificationError as exc:
        fail(str(exc))
    radial: list[dict[str, float]] = []
    selected_rows = 0
    compact_rows = 0
    compact_weight = 0.0
    for radius in radii_for_dr(dr):
        sigma_total = 0.0
        sigma_thick = 0.0
        weighted_hz = 0.0
        weighted_earth = 0.0
        for code, component, disk_label in COMPONENTS:
            name = ssp_name(radius, code)
            try:
                weights, ages, temperatures, masses, gravities = (
                    independent_reference.parse_ssp_independently(
                        snapshots[name], disk_label
                    )
                )
            except independent_reference.VerificationError as exc:
                fail(str(exc))
            stellar_radius = np.sqrt(
                masses * np.power(10.0, LOGG_SUN - gravities)
            )
            boundary = np.power(
                10.0,
                np.interp(temperatures, tams_temperature, np.log10(tams_radius)),
            )
            if (
                not np.isfinite(stellar_radius).all()
                or np.any(stellar_radius <= 0.0)
                or not np.isfinite(boundary).all()
                or np.any(boundary <= 0.0)
            ):
                fail(f"invalid TAMS-radius reconstruction in {name}")
            old_enough = ages >= AGE_MIN_GYR
            below_tams = old_enough & (stellar_radius <= boundary)
            compact = below_tams & (gravities >= LOGG_MAX)
            selected = below_tams & (gravities < LOGG_MAX)
            compact_rows += int(np.count_nonzero(compact))
            compact_weight += math.fsum(weights[compact].tolist())
            selected_rows += int(np.count_nonzero(selected))
            selected_weights = weights[selected]
            selected_temperatures = temperatures[selected]
            try:
                hz, earth = independent_reference.occurrence_weights(
                    selected_temperatures
                )
            except independent_reference.VerificationError as exc:
                fail(str(exc))
            if (
                not np.isfinite(hz).all()
                or not np.isfinite(earth).all()
                or np.any(hz < 0.0)
                or np.any(earth < 0.0)
                or np.any(earth > hz + 1.0e-15)
            ):
                fail(f"invalid occurrence weights in {name}")
            sigma = math.fsum(selected_weights.tolist())
            sigma_total += sigma
            if component == "thick":
                sigma_thick += sigma
            weighted_hz += math.fsum((selected_weights * hz).tolist())
            weighted_earth += math.fsum((selected_weights * earth).tolist())
        factor = 2.0 * math.pi * radius * 1.0e6
        radial.append(
            {
                "R_kpc": radius,
                "dN_dR": factor * sigma_total,
                "dL1_dR": factor * weighted_hz,
                "dL2_dR": factor * weighted_earth,
                "Sigma_TAMS_pc-2": sigma_total,
                "Sigma_thick_TAMS_pc-2": sigma_thick,
            }
        )
    domains: dict[str, Any] = {}
    for domain, (lo, hi) in DOMAINS.items():
        selected = [row for row in radial if lo <= row["R_kpc"] <= hi]
        if not selected or selected[0]["R_kpc"] != lo or selected[-1]["R_kpc"] != hi:
            fail(f"radial domain endpoints missing for {domain}")

        def integrate(field: str) -> float:
            return math.fsum(
                0.5
                * (left[field] + right[field])
                * (right["R_kpc"] - left["R_kpc"])
                for left, right in zip(selected, selected[1:])
            )

        n_g = integrate("dN_dR")
        hz = integrate("dL1_dR")
        earth = integrate("dL2_dR")
        if not (n_g > 0.0 and 0.0 <= earth <= hz):
            fail(f"invalid independently integrated ordering for {domain}")
        domains[domain] = {
            "R_kpc": [lo, hi],
            "N_G": n_g,
            "Lambda_ESHZ": hz,
            "Lambda_earth10": earth,
            "mean_f_HZ": hz / n_g,
            "mean_f_earth10": earth / n_g,
            "L2_over_L1": earth / hz,
        }
    return {
        "dR_kpc": dr,
        "radial_nodes": len(radial),
        "ssp_file_count": len(snapshots),
        "ssp_member_sha256": {
            name: snapshots[name].sha256 for name in expected_ssp_names(dr)
        },
        "radial_rows": radial,
        "selected_stellar_assembly_rows": selected_rows,
        "compact_remnant_rows_rejected": compact_rows,
        "compact_remnant_surface_weight_rejected_sum_pc-2": compact_weight,
        "C1": occurrence_normalization(),
        "domains": domains,
    }


def parse_generated_radial(path: Path, dr: float) -> list[dict[str, float]]:
    try:
        snapshot = secure_io.read_snapshot(path, "generated radial CSV")
        reader = csv.DictReader(io.StringIO(snapshot.data.decode("utf-8"), newline=""))
        if tuple(reader.fieldnames or ()) != RADIAL_COLUMNS:
            fail("generated radial CSV schema changed")
        raw_rows = list(reader)
    except (UnicodeError, csv.Error, secure_io.SSPContractError) as exc:
        fail(f"cannot parse generated radial CSV: {exc}")
    rows: list[dict[str, float]] = []
    for row_number, raw in enumerate(raw_rows, 2):
        if set(raw) != set(RADIAL_COLUMNS) or any(value is None for value in raw.values()):
            fail(f"malformed generated radial row {row_number}")
        parsed: dict[str, float] = {}
        for name in RADIAL_COLUMNS:
            try:
                value = float(raw[name])
            except (TypeError, ValueError, OverflowError) as exc:
                fail(f"invalid generated radial value at row {row_number}: {exc}")
            if not math.isfinite(value):
                fail(f"non-finite generated radial value at row {row_number}")
            parsed[name] = value
        rows.append(parsed)
    if [row["R_kpc"] for row in rows] != list(radii_for_dr(dr)):
        fail("generated radial CSV grid differs from the exact requested grid")
    return rows


def compare_radial_rows(
    observed: list[dict[str, float]], expected: list[dict[str, float]]
) -> None:
    if len(observed) != len(expected):
        fail("generated and independently derived radial row counts differ")
    for index, (left, right) in enumerate(zip(observed, expected)):
        for field in RADIAL_COLUMNS:
            absolute = abs(left[field] - right[field])
            relative = absolute / max(abs(right[field]), 1.0)
            if absolute > 1.0e-5 and relative > 5.0e-12:
                fail(
                    f"generated radial value differs from raw-SSP derivation "
                    f"at row {index + 2}, {field}"
                )
