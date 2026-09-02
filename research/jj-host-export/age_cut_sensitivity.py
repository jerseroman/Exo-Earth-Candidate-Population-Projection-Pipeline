#!/usr/bin/env python3
"""Recompute the canonical JJ/PARSEC host projection across age cuts.

This is deliberately a separate sensitivity product.  It reads the 42 thin-
and thick-disk JJ stellar-assembly tables *before* any age cut, applies the
same PARSEC-TAMS host selector used by the canonical provider, and reports
only radial aggregates.  No row-level stellar catalogue is emitted.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Iterable

import numpy as np

from occurrence_reference import f_earth10, f_hz
from tams_reference import EXPECTED_SHA256 as TAMS_REFERENCE_SHA256
from tams_reference import tams_radius_rsun


JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
AGE_THRESHOLDS = (0.0, 2.0, 4.57, 6.0, 8.0)
RADII = tuple(float(value) for value in np.arange(4.0, 14.0 + 0.25, 0.5))
COMPONENTS = (("d", "thin", 0), ("t", "thick", 1))
ISOCHRONE_LABEL = "Padova"
TMIN_K = 5300.0
TMAX_K = 6000.0
LOGG_SUN = 4.438
LOGG_COMPACT_VETO = 7.0

REPORT_NAME = "AGE_CUT_SENSITIVITY.json"
RADIAL_NAME = "age_cut_radial.csv"
SSP_MANIFEST_NAME = "JJ_SSP_INPUT_SHA256SUMS.txt"
OUTPUT_MANIFEST_NAME = "SHA256SUMS_age_cut_sensitivity.txt"
OUTPUT_FILES = (REPORT_NAME, RADIAL_NAME, SSP_MANIFEST_NAME, OUTPUT_MANIFEST_NAME)
OUTPUT_MANIFEST_MEMBERS = (REPORT_NAME, RADIAL_NAME, SSP_MANIFEST_NAME)

CANONICAL_MANIFEST_NAME = "SHA256SUMS_padova.txt"
CANONICAL_MANIFEST_MEMBERS = (
    "jj_g_hosts_radial_padova.csv",
    "jj_g_hosts_R_T_padova.csv",
    "jj_g_hosts_R_T_age_padova.csv",
    "jj_g_hosts_raw_eligible_padova.csv",
    "jj_g_hosts_summary_padova.json",
)
CANONICAL_RADIAL_NAME = CANONICAL_MANIFEST_MEMBERS[0]
CANONICAL_SUMMARY_NAME = CANONICAL_MANIFEST_MEMBERS[-1]
TAMS_AB_RADIAL_NAME = "tams_ab_radial.csv"
TAMS_AB_RESULTS_NAME = "tams_ab_results.json"

SSP_COLUMNS = (
    "N",
    "age",
    "FeH",
    "Mini",
    "Mf",
    "logL",
    "logT",
    "logg",
    "G_EDR3",
    "GBP_EDR3",
    "GRP_EDR3",
    "disk_label",
)
RADIAL_COLUMNS = (
    "age_threshold_Gyr",
    "R_kpc",
    "Sigma_G_thin_pc-2",
    "Sigma_G_thick_pc-2",
    "Sigma_G_total_pc-2",
    "dN_dR_stars_kpc-1",
    "dLambda_HZ_dR_kpc-1",
    "dLambda_Earth10_dR_kpc-1",
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")


class AgeCutError(RuntimeError):
    """Raised when the age-cut product cannot be made fail-closed."""


def fail(message: str) -> None:
    raise AgeCutError(message)


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    sha256: str
    size_bytes: int


def snapshot(path: Path, description: str, *, maximum_bytes: int | None = None) -> Snapshot:
    """Read one stable regular-file snapshot without following the final symlink."""

    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{description} must be a regular, non-symlink file: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
    except OSError as exc:
        fail(f"cannot read {description}: {exc}")
    try:
        after = candidate.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1 or len(data) != opened_after.st_size:
        fail(f"{description} changed while it was read: {candidate}")
    if maximum_bytes is not None and len(data) > maximum_bytes:
        fail(f"{description} exceeds {maximum_bytes} bytes")
    return Snapshot(
        path=candidate.resolve(),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def require_directory(path: Path, description: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_dir():
        fail(f"{description} must be an existing non-symlink directory: {candidate}")
    return candidate.resolve()


def strict_json(data: bytes, description: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key in {description}: {key!r}")
            result[key] = value
        return result

    def reject_constant(token: str) -> None:
        fail(f"non-finite JSON constant in {description}: {token}")

    def finite_float(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            fail(f"non-finite JSON number in {description}: {token}")
        return value

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse strict UTF-8 JSON {description}: {exc}")


def parse_manifest(
    manifest: Snapshot, expected_names: tuple[str, ...], root: Path
) -> dict[str, Snapshot]:
    try:
        lines = manifest.data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode manifest {manifest.path.name}: {exc}")
    if len(lines) != len(expected_names):
        fail(f"manifest {manifest.path.name} has the wrong number of entries")
    observed_names: list[str] = []
    result: dict[str, Snapshot] = {}
    for line in lines:
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            fail(f"malformed or unsafe manifest line in {manifest.path.name}: {line!r}")
        expected_sha, name = match.groups()
        if name in result:
            fail(f"duplicate manifest entry in {manifest.path.name}: {name}")
        member = snapshot(root / name, f"manifest member {name}")
        if member.sha256 != expected_sha:
            fail(f"manifest hash mismatch for {name}")
        observed_names.append(name)
        result[name] = member
    if tuple(observed_names) != expected_names:
        fail(
            f"manifest {manifest.path.name} member order/set changed: "
            f"{observed_names!r}"
        )
    return result


def git_output(jj_root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", *arguments], cwd=jj_root, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot verify JJ git checkout: {exc}")


def verify_jj_checkout(jj_root: Path, expected_commit: str) -> tuple[str, bytes, bytes]:
    root = require_directory(jj_root, "JJ root")
    commit = git_output(root, "rev-parse", "HEAD").decode("ascii", "strict").strip()
    if commit != expected_commit:
        fail(f"JJ commit mismatch: {commit} != {expected_commit}")
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False
    )
    if dirty.returncode != 0:
        fail("JJ checkout contains tracked modifications")
    parameters = git_output(
        root, "show", "HEAD:jjmodel/tutorials/tutorial2/parameters"
    )
    sfr = git_output(
        root, "show", "HEAD:jjmodel/tutorials/tutorial2/sfrd_peaks_parameters"
    )
    return commit, parameters, sfr


def parse_parameter_bytes(data: bytes, description: str) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        content = line.strip()
        if not content or content.startswith("#"):
            continue
        fields = content.split()
        if len(fields) < 2:
            fail(f"malformed {description} line {line_number}")
        key, value = fields[:2]
        if key in result:
            fail(f"duplicate parameter {key!r} in {description}")
        result[key] = value
    return result


def finite_token(token: str, description: str) -> float:
    try:
        value = float(token)
    except (TypeError, ValueError) as exc:
        fail(f"invalid numeric value for {description}: {token!r} ({exc})")
    if not math.isfinite(value):
        fail(f"non-finite numeric value for {description}: {token!r}")
    return value


def finite_json_number(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} must be a JSON number without coercion")
    try:
        result = float(value)
    except OverflowError as exc:
        fail(f"{description} exceeds the finite floating-point range: {exc}")
    if not math.isfinite(result):
        fail(f"{description} must be finite")
    return result


def validate_run_configuration(
    run_dir: Path, committed_parameters: bytes, committed_sfr: bytes
) -> tuple[dict[str, Any], Snapshot, Snapshot]:
    root = require_directory(run_dir, "JJ run directory")
    runtime_parameters = snapshot(root / "parameters", "JJ runtime parameters")
    runtime_sfr = snapshot(root / "sfrd_peaks_parameters", "JJ SFR-peak parameters")
    if runtime_sfr.data != committed_sfr:
        fail("runtime SFR-peak parameters differ from the locked tutorial2 file")
    official = parse_parameter_bytes(committed_parameters, "locked tutorial2 parameters")
    runtime = parse_parameter_bytes(runtime_parameters.data, "runtime JJ parameters")
    if set(official) != set(runtime):
        fail("runtime JJ parameter names differ from locked tutorial2")
    mutable = {"Rmin", "Rmax", "dR", "nprocess"}
    for key in sorted(set(official) - mutable):
        if runtime[key] != official[key]:
            fail(f"runtime JJ parameter {key!r} differs from locked tutorial2")
    radial = {
        "Rmin_kpc": finite_token(runtime["Rmin"], "Rmin"),
        "Rmax_kpc": finite_token(runtime["Rmax"], "Rmax"),
        "dR_kpc": finite_token(runtime["dR"], "dR"),
    }
    if radial != {"Rmin_kpc": 4.0, "Rmax_kpc": 14.0, "dR_kpc": 0.5}:
        fail(f"runtime JJ radial grid is not exactly 4--14 kpc at dR=0.5: {radial}")
    nprocess_value = finite_token(runtime["nprocess"], "nprocess")
    if not nprocess_value.is_integer() or nprocess_value <= 0:
        fail("runtime JJ nprocess must be a positive integer")
    imfkey = finite_token(runtime["imfkey"], "imfkey")
    run_mode = finite_token(runtime["run_mode"], "run_mode")
    if imfkey != 0.0 or run_mode != 1.0:
        fail("age-cut audit requires tutorial2 run_mode=1 and imfkey=0")
    return (
        {
            **radial,
            "node_count": len(RADII),
            "nprocess": int(nprocess_value),
            "imfkey": 0,
            "run_mode": 1,
        },
        runtime_parameters,
        runtime_sfr,
    )


def ssp_name(radius: float, component_code: str) -> str:
    return f"SSP_R{radius:.1f}_{component_code}_{ISOCHRONE_LABEL}.csv"


def expected_ssp_names() -> tuple[str, ...]:
    return tuple(ssp_name(radius, component[0]) for radius in RADII for component in COMPONENTS)


def discover_ssp_snapshots(run_dir: Path) -> dict[str, Snapshot]:
    root = require_directory(run_dir, "JJ run directory")
    result: dict[str, Snapshot] = {}
    for name in expected_ssp_names():
        matches = [path for path in root.rglob(name) if path.is_file() or path.is_symlink()]
        if len(matches) != 1:
            fail(f"expected exactly one pre-age-filter JJ SSP table {name}, found {len(matches)}")
        result[name] = snapshot(matches[0], f"JJ SSP table {name}")
    parents = {item.path.parent for item in result.values()}
    if len(parents) != 1:
        fail("the 42 JJ SSP tables do not come from one common pop/tab directory")
    table_root = next(iter(parents))
    if table_root.name != "tab" or table_root.parent.name != "pop":
        fail("JJ SSP tables are not located in one JJ pop/tab output directory")
    observed_disk_tables = {
        path.name
        for path in table_root.iterdir()
        if path.is_file()
        and re.fullmatch(r"SSP_R[^/\\]+_[dt]_Padova\.csv", path.name)
    }
    if observed_disk_tables != set(expected_ssp_names()):
        fail("JJ pop/tab directory does not contain exactly the expected 42 disk SSP tables")
    return result


def parse_ssp(
    source: Snapshot, component_label: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    try:
        reader = csv.reader(io.StringIO(source.data.decode("utf-8"), newline=""))
        header = next(reader)
    except (UnicodeError, csv.Error, StopIteration) as exc:
        fail(f"cannot parse JJ SSP CSV {source.path.name}: {exc}")
    if tuple(header) != SSP_COLUMNS:
        fail(f"JJ SSP header changed in {source.path.name}: {header!r}")
    weights: list[float] = []
    ages: list[float] = []
    temperatures: list[float] = []
    masses: list[float] = []
    gravities: list[float] = []
    for row_number, row in enumerate(reader, 2):
        if len(row) != len(SSP_COLUMNS):
            fail(f"JJ SSP row width changed in {source.path.name}:{row_number}")
        numeric = [
            finite_token(token, f"{source.path.name}:{row_number} {column}")
            for column, token in zip(SSP_COLUMNS, row)
        ]
        weight, age = numeric[0], numeric[1]
        initial_mass, mass = numeric[3], numeric[4]
        log_temperature, gravity = numeric[6], numeric[7]
        disk_label_value = numeric[11]
        if weight < 0.0 or age < 0.0 or initial_mass <= 0.0 or mass <= 0.0:
            fail(f"negative/invalid physical value in {source.path.name}:{row_number}")
        if disk_label_value != float(component_label):
            fail(f"disk label does not match SSP component in {source.path.name}:{row_number}")
        temperature = 10.0**log_temperature
        if not math.isfinite(temperature) or temperature <= 0.0:
            fail(f"invalid Teff reconstruction in {source.path.name}:{row_number}")
        if TMIN_K <= temperature <= TMAX_K:
            weights.append(weight)
            ages.append(age)
            temperatures.append(temperature)
            masses.append(mass)
            gravities.append(gravity)
    return tuple(
        np.asarray(values, dtype=float)
        for values in (weights, ages, temperatures, masses, gravities)
    )  # type: ignore[return-value]


def aggregate_ssp_tables(ssp: dict[str, Snapshot]) -> list[dict[str, float]]:
    accumulators: dict[tuple[float, float], dict[str, float]] = {}
    for radius in RADII:
        for code, component, disk_label in COMPONENTS:
            name = ssp_name(radius, code)
            weights, ages, temperatures, masses, gravities = parse_ssp(
                ssp[name], disk_label
            )
            if len(weights):
                radii = np.sqrt(masses * np.power(10.0, LOGG_SUN - gravities))
                boundaries = np.asarray(tams_radius_rsun(temperatures), dtype=float)
                if not np.isfinite(radii).all() or np.any(radii <= 0.0):
                    fail(f"invalid stellar-radius reconstruction in {name}")
                if not np.isfinite(boundaries).all() or np.any(boundaries <= 0.0):
                    fail(f"invalid TAMS interpolation in {name}")
                canonical = (radii <= boundaries) & (gravities < LOGG_COMPACT_VETO)
                hz = np.asarray(f_hz(temperatures), dtype=float)
                earth = np.asarray(f_earth10(temperatures), dtype=float)
                if (
                    not np.isfinite(hz).all()
                    or not np.isfinite(earth).all()
                    or np.any(hz < 0.0)
                    or np.any(earth < 0.0)
                    or np.any(earth > hz + 1.0e-15)
                ):
                    fail(f"invalid occurrence weights in {name}")
            else:
                canonical = np.zeros(0, dtype=bool)
                hz = np.zeros(0, dtype=float)
                earth = np.zeros(0, dtype=float)
            for threshold in AGE_THRESHOLDS:
                selected = canonical & (ages >= threshold)
                selected_weights = weights[selected]
                accumulators[(threshold, radius, component)] = {
                    "sigma": math.fsum(selected_weights.tolist()),
                    "hz_sigma": math.fsum((selected_weights * hz[selected]).tolist()),
                    "earth_sigma": math.fsum(
                        (selected_weights * earth[selected]).tolist()
                    ),
                }

    rows: list[dict[str, float]] = []
    for threshold in AGE_THRESHOLDS:
        for radius in RADII:
            thin = accumulators[(threshold, radius, "thin")]
            thick = accumulators[(threshold, radius, "thick")]
            total = thin["sigma"] + thick["sigma"]
            factor = 2.0 * math.pi * radius * 1.0e6
            rows.append(
                {
                    "age_threshold_Gyr": threshold,
                    "R_kpc": radius,
                    "Sigma_G_thin_pc-2": thin["sigma"],
                    "Sigma_G_thick_pc-2": thick["sigma"],
                    "Sigma_G_total_pc-2": total,
                    "dN_dR_stars_kpc-1": factor * total,
                    "dLambda_HZ_dR_kpc-1": factor
                    * (thin["hz_sigma"] + thick["hz_sigma"]),
                    "dLambda_Earth10_dR_kpc-1": factor
                    * (thin["earth_sigma"] + thick["earth_sigma"]),
                }
            )
    validate_monotonicity(rows)
    return rows


def validate_monotonicity(rows: list[dict[str, float]]) -> None:
    fields = (
        "Sigma_G_thin_pc-2",
        "Sigma_G_thick_pc-2",
        "Sigma_G_total_pc-2",
        "dN_dR_stars_kpc-1",
        "dLambda_HZ_dR_kpc-1",
        "dLambda_Earth10_dR_kpc-1",
    )
    lookup = {(row["age_threshold_Gyr"], row["R_kpc"]): row for row in rows}
    for radius in RADII:
        for field in fields:
            values = [lookup[(threshold, radius)][field] for threshold in AGE_THRESHOLDS]
            if any(later > earlier for earlier, later in zip(values, values[1:])):
                fail(f"age-cut monotonicity failed at R={radius:g} kpc for {field}")


def trapz_rows(
    rows: list[dict[str, float]], threshold: float, field: str, lo: float, hi: float
) -> float:
    selected = [
        row
        for row in rows
        if row["age_threshold_Gyr"] == threshold and lo <= row["R_kpc"] <= hi
    ]
    if [row["R_kpc"] for row in selected] != [r for r in RADII if lo <= r <= hi]:
        fail(f"radial integration grid incomplete for {threshold=} {lo=} {hi=}")
    return math.fsum(
        0.5
        * (left[field] + right[field])
        * (right["R_kpc"] - left["R_kpc"])
        for left, right in zip(selected, selected[1:])
    )


def evidence(item: Snapshot) -> dict[str, Any]:
    return {
        "filename": item.path.name,
        "sha256": item.sha256,
        "size_bytes": item.size_bytes,
    }


def load_csv_dicts(source: Snapshot, expected_header: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(source.data.decode("utf-8"), newline=""))
        if tuple(reader.fieldnames or ()) != expected_header:
            fail(f"CSV header changed in {source.path.name}: {reader.fieldnames!r}")
        rows = list(reader)
    except (UnicodeError, csv.Error) as exc:
        fail(f"cannot parse CSV {source.path.name}: {exc}")
    if any(set(row) != set(expected_header) or any(value is None for value in row.values()) for row in rows):
        fail(f"malformed CSV row in {source.path.name}")
    return rows


def canonical_inputs(
    root_path: Path, expected_commit: str
) -> tuple[dict[str, Any], dict[str, Snapshot], Any, Any, Any]:
    root = require_directory(root_path, "canonical host root")
    manifest = snapshot(root / CANONICAL_MANIFEST_NAME, "canonical host manifest", maximum_bytes=20_000)
    members = parse_manifest(manifest, CANONICAL_MANIFEST_MEMBERS, root)
    tams_radial = snapshot(root / TAMS_AB_RADIAL_NAME, "TAMS A/B radial table")
    tams_results = snapshot(root / TAMS_AB_RESULTS_NAME, "TAMS A/B results", maximum_bytes=1_000_000)
    canonical_radial_rows = load_csv_dicts(
        members[CANONICAL_RADIAL_NAME],
        (
            "R_kpc",
            "Sigma_G_thin_pc-2",
            "Sigma_G_thick_pc-2",
            "Sigma_G_total_pc-2",
            "dN_dR_stars_kpc-1",
        ),
    )
    tams_radial_rows = load_csv_dicts(
        tams_radial,
        ("R_kpc", "A_N", "B_N", "A_L1", "B_L1", "A_L2", "B_L2"),
    )
    summary = strict_json(members[CANONICAL_SUMMARY_NAME].data, "canonical host summary")
    results = strict_json(tams_results.data, "TAMS A/B results")
    if not isinstance(summary, dict) or not isinstance(results, dict):
        fail("canonical host summary and TAMS A/B results must be JSON objects")
    if summary.get("jj_commit") != expected_commit:
        fail("canonical host summary uses a different JJ commit")
    if summary.get("isochrone_family") != "Padova/PARSEC":
        fail("canonical host summary is not Padova/PARSEC")
    estimand = summary.get("host_estimand")
    if not isinstance(estimand, dict) or estimand.get("age_Gyr_min") != 4.57:
        fail("canonical host summary is not the age>=4.57 estimand")
    all_snapshots = {
        CANONICAL_MANIFEST_NAME: manifest,
        **members,
        TAMS_AB_RADIAL_NAME: tams_radial,
        TAMS_AB_RESULTS_NAME: tams_results,
    }
    binding = {name: evidence(all_snapshots[name]) for name in (
        CANONICAL_MANIFEST_NAME,
        CANONICAL_RADIAL_NAME,
        CANONICAL_SUMMARY_NAME,
        TAMS_AB_RADIAL_NAME,
        TAMS_AB_RESULTS_NAME,
    )}
    return binding, all_snapshots, canonical_radial_rows, tams_radial_rows, results


def close_value(observed: float, expected: float, description: str) -> tuple[float, float]:
    if not math.isfinite(observed) or not math.isfinite(expected):
        fail(f"non-finite value in {description}")
    absolute = abs(observed - expected)
    relative = absolute / max(abs(expected), 1.0)
    if absolute > 1.0e-5 and relative > 5.0e-12:
        fail(f"{description} mismatch: observed={observed!r}, expected={expected!r}")
    return absolute, relative


def cross_check_canonical(
    rows: list[dict[str, float]],
    canonical_radial_rows: list[dict[str, str]],
    tams_radial_rows: list[dict[str, str]],
    tams_results: Any,
) -> dict[str, Any]:
    age_rows = [row for row in rows if row["age_threshold_Gyr"] == 4.57]
    if len(age_rows) != len(RADII) or len(canonical_radial_rows) != len(RADII) or len(tams_radial_rows) != len(RADII):
        fail("4.57-Gyr canonical cross-check does not contain 21 radial nodes")
    maximum_absolute = 0.0
    maximum_relative = 0.0
    for expected_radius, age_row, canonical, tams in zip(
        RADII, age_rows, canonical_radial_rows, tams_radial_rows
    ):
        for source_name, source in (("canonical", canonical), ("tams_ab", tams)):
            radius = finite_token(source["R_kpc"], f"{source_name} R_kpc")
            if radius != expected_radius or age_row["R_kpc"] != expected_radius:
                fail(f"radial order mismatch in {source_name}")
        comparisons = (
            (age_row["Sigma_G_thin_pc-2"], finite_token(canonical["Sigma_G_thin_pc-2"], "canonical thin sigma"), "canonical thin sigma"),
            (age_row["Sigma_G_thick_pc-2"], finite_token(canonical["Sigma_G_thick_pc-2"], "canonical thick sigma"), "canonical thick sigma"),
            (age_row["Sigma_G_total_pc-2"], finite_token(canonical["Sigma_G_total_pc-2"], "canonical total sigma"), "canonical total sigma"),
            (age_row["dN_dR_stars_kpc-1"], finite_token(canonical["dN_dR_stars_kpc-1"], "canonical dN/dR"), "canonical dN/dR"),
            (age_row["dN_dR_stars_kpc-1"], finite_token(tams["B_N"], "TAMS B_N"), "TAMS B_N"),
            (age_row["dLambda_HZ_dR_kpc-1"], finite_token(tams["B_L1"], "TAMS B_L1"), "TAMS B_L1"),
            (age_row["dLambda_Earth10_dR_kpc-1"], finite_token(tams["B_L2"], "TAMS B_L2"), "TAMS B_L2"),
        )
        for observed, expected, description in comparisons:
            absolute, relative = close_value(observed, expected, f"R={expected_radius:g} {description}")
            maximum_absolute = max(maximum_absolute, absolute)
            maximum_relative = max(maximum_relative, relative)

    if not isinstance(tams_results, dict):
        fail("TAMS A/B results must be an object")
    domains = tams_results.get("domains")
    if not isinstance(domains, dict):
        fail("TAMS A/B results lack domains")
    domain_checks: dict[str, Any] = {}
    for domain_name, lo, hi in (("lineweaver_7_9", 7.0, 9.0), ("full_JJ_4_14", 4.0, 14.0)):
        domain = domains.get(domain_name)
        branch = domain.get("B") if isinstance(domain, dict) else None
        if not isinstance(branch, dict):
            fail(f"TAMS A/B results lack domain B values for {domain_name}")
        expected_values = {
            "N_G": trapz_rows(rows, 4.57, "dN_dR_stars_kpc-1", lo, hi),
            "Lambda_ESHZ": trapz_rows(rows, 4.57, "dLambda_HZ_dR_kpc-1", lo, hi),
            "Lambda_earth10": trapz_rows(rows, 4.57, "dLambda_Earth10_dR_kpc-1", lo, hi),
        }
        checked: dict[str, float] = {}
        for key, expected in expected_values.items():
            observed = finite_json_number(
                branch.get(key), f"TAMS {domain_name} B {key}"
            )
            absolute, relative = close_value(expected, observed, f"TAMS {domain_name} B {key}")
            maximum_absolute = max(maximum_absolute, absolute)
            maximum_relative = max(maximum_relative, relative)
            checked[key] = expected
        domain_checks[domain_name] = checked
    return {
        "status": "PASS",
        "age_threshold_Gyr": 4.57,
        "radial_node_count": len(RADII),
        "maximum_absolute_difference": maximum_absolute,
        "maximum_relative_difference": maximum_relative,
        "domains": domain_checks,
    }


def domain_results(rows: list[dict[str, float]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, lo, hi in (("lineweaver_7_9", 7.0, 9.0), ("full_JJ_4_14", 4.0, 14.0)):
        by_threshold = []
        for threshold in AGE_THRESHOLDS:
            by_threshold.append(
                {
                    "age_threshold_Gyr": threshold,
                    "N_G": trapz_rows(rows, threshold, "dN_dR_stars_kpc-1", lo, hi),
                    "Lambda_HZ": trapz_rows(rows, threshold, "dLambda_HZ_dR_kpc-1", lo, hi),
                    "Lambda_Earth10": trapz_rows(rows, threshold, "dLambda_Earth10_dR_kpc-1", lo, hi),
                }
            )
        for field in ("N_G", "Lambda_HZ", "Lambda_Earth10"):
            values = [row[field] for row in by_threshold]
            if any(later > earlier for earlier, later in zip(values, values[1:])):
                fail(f"integrated age-cut monotonicity failed for {name}/{field}")
        result[name] = {"R_kpc": [lo, hi], "by_threshold": by_threshold}
    return result


def write_manifest(path: Path, names: tuple[str, ...], root: Path) -> None:
    lines = []
    for name in names:
        member = snapshot(root / name, f"generated artifact {name}")
        lines.append(f"{member.sha256}  {name}\n")
    path.write_text("".join(lines), encoding="utf-8", newline="\n")


def _create_artifact(
    *,
    jj_root: Path,
    run_dir: Path,
    canonical_host_root: Path,
    output_root: Path,
    expected_jj_commit: str,
) -> dict[str, Any]:
    if expected_jj_commit != JJ_SHA and not HEX40.fullmatch(expected_jj_commit):
        fail("test-only expected JJ commit is invalid")
    output = Path(output_root)
    if output.is_symlink() or output.exists():
        fail("age-cut output root must not already exist")
    commit, official_parameters, official_sfr = verify_jj_checkout(
        Path(jj_root), expected_jj_commit
    )
    runtime, parameter_snapshot, sfr_snapshot = validate_run_configuration(
        Path(run_dir), official_parameters, official_sfr
    )
    ssp = discover_ssp_snapshots(Path(run_dir))
    if tuple(ssp) != expected_ssp_names():
        fail("JJ SSP snapshot set/order changed")
    rows = aggregate_ssp_tables(ssp)
    binding, _, canonical_radial, tams_radial, tams_results = canonical_inputs(
        Path(canonical_host_root), expected_jj_commit
    )
    canonical_check = cross_check_canonical(
        rows, canonical_radial, tams_radial, tams_results
    )
    domains = domain_results(rows)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".age-cut-", dir=output.parent))
    try:
        ssp_manifest = temporary / SSP_MANIFEST_NAME
        ssp_manifest.write_text(
            "".join(f"{ssp[name].sha256}  {name}\n" for name in expected_ssp_names()),
            encoding="utf-8",
            newline="\n",
        )
        ssp_manifest_snapshot = snapshot(ssp_manifest, "generated SSP manifest")

        radial_path = temporary / RADIAL_NAME
        with radial_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RADIAL_COLUMNS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

        report = {
            "schema_version": 1,
            "status": "PASS",
            "experiment": "age_threshold_sensitivity_canonical_parsec_tams",
            "jj": {
                "repository": "askenja/jjmodel",
                "commit": commit,
                "version_expected": "1.0.1",
                "isochrone_label": ISOCHRONE_LABEL,
                "isochrone_family": "Padova/PARSEC",
                "runtime_parameters": evidence(parameter_snapshot),
                "sfr_peaks_parameters": evidence(sfr_snapshot),
                "runtime_configuration": runtime,
                "ssp_manifest": evidence(ssp_manifest_snapshot),
                "ssp_file_count": len(ssp),
            },
            "host_estimand": {
                "Teff_K": [TMIN_K, TMAX_K],
                "temperature_interval": "closed",
                "age_thresholds_Gyr": list(AGE_THRESHOLDS),
                "age_interval": "age_Gyr >= threshold",
                "components": ["thin", "thick"],
                "main_sequence_selector": (
                    "Rstar_g <= PARSEC TAMS radius at Teff, plus logg < 7 "
                    "compact-remnant veto"
                ),
                "radius_reconstruction": "Rstar/Rsun = sqrt(Mf * 10^(4.438-logg))",
                "tams_reference_sha256": TAMS_REFERENCE_SHA256,
                "occurrence_model": (
                    "Bryson Model 1 hab2 constant-completeness median with "
                    "Kopparapu conservative HZ"
                ),
                "surface_to_radial_factor": "2*pi*R_kpc*1e6",
                "radial_integration": (
                    "composite trapezoid on the inclusive 0.5-kpc JJ grid"
                ),
                "radial_grid_kpc": {
                    "minimum": 4.0,
                    "maximum": 14.0,
                    "spacing": 0.5,
                    "node_count": len(RADII),
                },
            },
            "canonical_inputs": binding,
            "canonical_age_4p57_cross_check": canonical_check,
            "domains": domains,
            "monotonicity": {
                "status": "PASS",
                "direction": "nonincreasing with increasing minimum age",
                "radial_checks": len(RADII) * 6 * (len(AGE_THRESHOLDS) - 1),
                "integrated_checks": 2 * 3 * (len(AGE_THRESHOLDS) - 1),
                "exact_comparison": True,
            },
            "row_level_host_output_emitted": False,
        }
        report_path = temporary / REPORT_NAME
        with report_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, allow_nan=False)
            handle.write("\n")
        write_manifest(
            temporary / OUTPUT_MANIFEST_NAME, OUTPUT_MANIFEST_MEMBERS, temporary
        )
        if {path.name for path in temporary.iterdir()} != set(OUTPUT_FILES):
            fail("generated age-cut root does not contain the exact four-file set")
        os.replace(temporary, output)
        return report
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def create_artifact(
    *,
    jj_root: Path,
    run_dir: Path,
    canonical_host_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Create a production artifact locked to the single audited JJ commit."""

    return _create_artifact(
        jj_root=jj_root,
        run_dir=run_dir,
        canonical_host_root=canonical_host_root,
        output_root=output_root,
        expected_jj_commit=JJ_SHA,
    )


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--jj-root", required=True, type=Path)
    argument_parser.add_argument("--run-dir", required=True, type=Path)
    argument_parser.add_argument("--canonical-host-root", required=True, type=Path)
    argument_parser.add_argument("--out", required=True, type=Path)
    argument_parser.add_argument("--iso", default=ISOCHRONE_LABEL, choices=[ISOCHRONE_LABEL])
    return argument_parser


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    report = create_artifact(
        jj_root=args.jj_root,
        run_dir=args.run_dir,
        canonical_host_root=args.canonical_host_root,
        output_root=args.out,
    )
    print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
