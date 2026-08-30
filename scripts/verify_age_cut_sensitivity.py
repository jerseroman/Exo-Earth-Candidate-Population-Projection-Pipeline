#!/usr/bin/env python3
"""Independently verify the manifest-bound JJ age-cut sensitivity artifact.

The verifier does not import ``age_cut_sensitivity.py``.  It reparses the
locked JJ SSP bytes, implements the TAMS interpolation and occurrence equations
independently, and rederives every radial and integrated value before accepting
the four-file artifact.
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
import stat
import subprocess
from typing import Any, Iterable

import numpy as np

import verify_age_cut_ssp_contract as ssp_contract_verifier
import verify_host_artifact_contract as host_contract_verifier


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SSP_CONTRACT_PATH = (
    REPOSITORY_ROOT / "provenance" / "AGE_CUT_SSP_CONTRACT_v4_0_4.json"
)
CANONICAL_HOST_CONTRACT_PATH = (
    REPOSITORY_ROOT / "provenance" / "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
)
TAMS_PATH = (
    REPOSITORY_ROOT
    / "research"
    / "jj-host-export"
    / "reference-data"
    / "tams_parsec_danxhuber.txt"
)
TAMS_SHA256 = "d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac"
JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
AGE_THRESHOLDS = (0.0, 2.0, 4.57, 6.0, 8.0)
RADII = tuple(4.0 + 0.5 * index for index in range(21))
COMPONENTS = (("d", "thin", 0), ("t", "thick", 1))
TMIN_K = 5300.0
TMAX_K = 6000.0
LOGG_SUN = 4.438
LOGG_COMPACT_VETO = 7.0

REPORT_NAME = "AGE_CUT_SENSITIVITY.json"
RADIAL_NAME = "age_cut_radial.csv"
SSP_MANIFEST_NAME = "JJ_SSP_INPUT_SHA256SUMS.txt"
OUTPUT_MANIFEST_NAME = "SHA256SUMS_age_cut_sensitivity.txt"
OUTPUT_FILES = {REPORT_NAME, RADIAL_NAME, SSP_MANIFEST_NAME, OUTPUT_MANIFEST_NAME}
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
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_REPORT_BYTES = 2_000_000
MAX_MANIFEST_BYTES = 20_000
MAX_RADIAL_BYTES = 2_000_000

# Independent copy of the fixed Bryson Model-1 / Kopparapu reference constants.
F0 = 1.107
ALPHA = -1.082
BETA = -0.839
GAMMA = -2.671
T0 = 3900.0
T_BREAK = 5117.0
T1 = 6300.0
RUNAWAY = (1.107, 1.332e-4, 1.58e-8, -8.308e-12, -1.931e-15)
MAXIMUM = (0.356, 6.171e-5, 1.698e-9, -3.198e-12, -5.575e-16)


class VerificationError(RuntimeError):
    """Raised when an artifact or any bound input fails closed."""


def fail(message: str) -> None:
    raise VerificationError(message)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes
    sha256: str
    size_bytes: int


def read_snapshot(
    path: Path, description: str, *, maximum_bytes: int | None = None
) -> FileSnapshot:
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
    return FileSnapshot(
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


def load_strict_json(data: bytes, description: str) -> Any:
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


def exact_keys(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object")
    observed = set(value)
    if observed != expected:
        fail(
            f"{description} keys differ: missing={sorted(expected - observed)!r}, "
            f"extra={sorted(observed - expected)!r}"
        )
    return value


def parse_manifest_bytes(
    data: bytes, expected_names: tuple[str, ...], description: str
) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    if len(lines) != len(expected_names):
        fail(f"{description} has the wrong entry count")
    result: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            fail(f"malformed or unsafe line in {description}: {line!r}")
        digest, name = match.groups()
        if name in result:
            fail(f"duplicate manifest entry in {description}: {name}")
        result[name] = digest
        order.append(name)
    if tuple(order) != expected_names:
        fail(f"{description} member order/set changed: {order!r}")
    return result


def finite_number(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} must be a JSON number without coercion")
    try:
        result = float(value)
    except OverflowError as exc:
        fail(f"{description} exceeds the finite floating-point range: {exc}")
    if not math.isfinite(result):
        fail(f"{description} must be finite")
    return result


def finite_csv(token: Any, description: str) -> float:
    if not isinstance(token, str) or token == "":
        fail(f"{description} is missing")
    try:
        value = float(token)
    except ValueError as exc:
        fail(f"invalid numeric token for {description}: {token!r} ({exc})")
    if not math.isfinite(value):
        fail(f"non-finite numeric token for {description}: {token!r}")
    return value


def git_bytes(jj_root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", *arguments], cwd=jj_root, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot inspect JJ git checkout: {exc}")


def verify_jj_checkout(
    jj_root_path: Path, expected_commit: str
) -> tuple[str, bytes, bytes]:
    root = require_directory(jj_root_path, "JJ root")
    commit = git_bytes(root, "rev-parse", "HEAD").decode("ascii", "strict").strip()
    if not HEX40.fullmatch(commit) or commit != expected_commit:
        fail(f"JJ commit mismatch: {commit!r} != {expected_commit!r}")
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False
    )
    if dirty.returncode != 0:
        fail("JJ checkout contains tracked modifications")
    parameters = git_bytes(
        root, "show", "HEAD:jjmodel/tutorials/tutorial2/parameters"
    )
    sfr = git_bytes(
        root, "show", "HEAD:jjmodel/tutorials/tutorial2/sfrd_peaks_parameters"
    )
    return commit, parameters, sfr


def parameter_map(data: bytes, description: str) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 2:
            fail(f"malformed line {line_number} in {description}")
        if fields[0] in result:
            fail(f"duplicate parameter {fields[0]!r} in {description}")
        result[fields[0]] = fields[1]
    return result


def run_configuration(
    run_dir_path: Path, official_parameters: bytes, official_sfr: bytes
) -> tuple[dict[str, Any], FileSnapshot, FileSnapshot]:
    root = require_directory(run_dir_path, "JJ run directory")
    parameters_snapshot = read_snapshot(root / "parameters", "runtime JJ parameters")
    sfr_snapshot = read_snapshot(root / "sfrd_peaks_parameters", "runtime JJ SFR peaks")
    if sfr_snapshot.data != official_sfr:
        fail("runtime SFR-peak parameters differ from locked tutorial2")
    official = parameter_map(official_parameters, "locked tutorial2 parameters")
    runtime = parameter_map(parameters_snapshot.data, "runtime JJ parameters")
    if set(runtime) != set(official):
        fail("runtime JJ parameter names differ from locked tutorial2")
    mutable = {"Rmin", "Rmax", "dR", "nprocess"}
    if any(runtime[key] != official[key] for key in set(runtime) - mutable):
        fail("runtime JJ parameters differ outside the allowed radial/process fields")
    rmin = finite_csv(runtime["Rmin"], "runtime Rmin")
    rmax = finite_csv(runtime["Rmax"], "runtime Rmax")
    dr = finite_csv(runtime["dR"], "runtime dR")
    nprocess = finite_csv(runtime["nprocess"], "runtime nprocess")
    imfkey = finite_csv(runtime["imfkey"], "runtime imfkey")
    mode = finite_csv(runtime["run_mode"], "runtime run_mode")
    if (rmin, rmax, dr) != (4.0, 14.0, 0.5):
        fail("runtime JJ radial grid is not exactly 4--14 kpc at dR=0.5")
    if not nprocess.is_integer() or nprocess <= 0:
        fail("runtime JJ nprocess must be a positive integer")
    if (imfkey, mode) != (0.0, 1.0):
        fail("runtime JJ must use tutorial2 imfkey=0 and run_mode=1")
    return (
        {
            "Rmin_kpc": rmin,
            "Rmax_kpc": rmax,
            "dR_kpc": dr,
            "node_count": 21,
            "nprocess": int(nprocess),
            "imfkey": 0,
            "run_mode": 1,
        },
        parameters_snapshot,
        sfr_snapshot,
    )


def ssp_name(radius: float, code: str) -> str:
    return f"SSP_R{radius:.1f}_{code}_Padova.csv"


def ssp_names() -> tuple[str, ...]:
    return tuple(ssp_name(radius, code) for radius in RADII for code, _, _ in COMPONENTS)


def snapshot_ssp_set(
    run_dir_path: Path, *, allow_qualified_flat_root: bool = False
) -> dict[str, FileSnapshot]:
    root = require_directory(run_dir_path, "JJ run directory")
    result: dict[str, FileSnapshot] = {}
    for name in ssp_names():
        matches = [path for path in root.rglob(name) if path.is_file() or path.is_symlink()]
        if len(matches) != 1:
            fail(f"expected exactly one JJ SSP table {name}, found {len(matches)}")
        result[name] = read_snapshot(matches[0], f"JJ SSP table {name}")
    parents = {item.path.parent for item in result.values()}
    if len(parents) != 1:
        fail("the 42 JJ SSP tables do not share one pop/tab directory")
    table_root = next(iter(parents))
    is_jj_layout = table_root.name == "tab" and table_root.parent.name == "pop"
    is_qualified_flat_root = allow_qualified_flat_root and table_root == root
    if not is_jj_layout and not is_qualified_flat_root:
        fail("JJ SSP inputs are not in one JJ pop/tab output directory")
    observed_disk_tables = {
        path.name
        for path in table_root.iterdir()
        if path.is_file()
        and re.fullmatch(r"SSP_R[^/\\]+_[dt]_Padova\.csv", path.name)
    }
    if observed_disk_tables != set(ssp_names()):
        fail("JJ pop/tab directory does not contain exactly the expected 42 disk SSP tables")
    return result


def load_tams_reference() -> tuple[np.ndarray, np.ndarray]:
    reference = read_snapshot(TAMS_PATH, "locked PARSEC TAMS reference", maximum_bytes=100_000)
    if reference.sha256 != TAMS_SHA256:
        fail("PARSEC TAMS reference SHA-256 mismatch")
    try:
        data = np.loadtxt(io.BytesIO(reference.data), dtype=float)
    except (ValueError, OSError) as exc:
        fail(f"cannot parse PARSEC TAMS reference: {exc}")
    if data.shape != (49, 2) or not np.isfinite(data).all():
        fail(f"PARSEC TAMS reference shape/content changed: {data.shape}")
    use = data[:, 0] <= 6060.24246 + 1.0e-9
    temperatures = data[use, 0]
    radii = data[use, 1]
    if len(temperatures) != 8 or np.any(np.diff(temperatures) <= 0.0) or np.any(radii <= 0.0):
        fail("validated G-star TAMS segment changed")
    if temperatures[0] > TMIN_K or temperatures[-1] < TMAX_K:
        fail("TAMS segment does not bracket the audited Teff range")
    return temperatures, radii


def occurrence_weights(temperature: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    def power_integral(lower: float, upper: float, exponent: float) -> float:
        return (upper ** (exponent + 1.0) - lower ** (exponent + 1.0)) / (
            exponent + 1.0
        )

    radius_fit = power_integral(0.5, 2.5, ALPHA)
    instellation_fit = power_integral(0.2, 2.2, BETA)
    q1 = GAMMA + 3.16
    q2 = GAMMA + 4.49
    geometric_mean = (
        10.0 ** (-11.839) * power_integral(T0, T_BREAK, q1)
        + 10.0 ** (-16.769) * power_integral(T_BREAK, T1, q2)
    ) / (T1 - T0)
    normalization = 1.0 / (radius_fit * instellation_fit * geometric_mean)
    offset = temperature - 5780.0
    inner = sum(coefficient * offset**power for power, coefficient in enumerate(RUNAWAY))
    outer = sum(coefficient * offset**power for power, coefficient in enumerate(MAXIMUM))
    geometric = np.where(
        temperature <= T_BREAK,
        10.0 ** (-11.839) * temperature**3.16,
        10.0 ** (-16.769) * temperature**4.49,
    )
    prefactor = F0 * normalization * temperature**GAMMA * geometric
    instellation = (inner ** (BETA + 1.0) - outer ** (BETA + 1.0)) / (
        BETA + 1.0
    )
    hz = prefactor * power_integral(0.5, 1.5, ALPHA) * instellation
    lower = np.maximum(0.9, outer)
    upper = np.minimum(1.1, inner)
    earth_inst = np.where(
        upper > lower,
        (upper ** (BETA + 1.0) - lower ** (BETA + 1.0)) / (BETA + 1.0),
        0.0,
    )
    earth = prefactor * power_integral(0.9, 1.1, ALPHA) * earth_inst
    return hz, earth


def parse_ssp_independently(
    source: FileSnapshot, expected_disk_label: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    try:
        reader = csv.DictReader(io.StringIO(source.data.decode("utf-8"), newline=""))
        if tuple(reader.fieldnames or ()) != SSP_COLUMNS:
            fail(f"SSP header changed in {source.path.name}: {reader.fieldnames!r}")
        rows = list(reader)
    except (UnicodeError, csv.Error) as exc:
        fail(f"cannot parse SSP table {source.path.name}: {exc}")
    weights: list[float] = []
    ages: list[float] = []
    teffs: list[float] = []
    masses: list[float] = []
    gravities: list[float] = []
    for row_number, row in enumerate(rows, 2):
        if set(row) != set(SSP_COLUMNS) or any(row[key] is None for key in SSP_COLUMNS):
            fail(f"malformed SSP row {source.path.name}:{row_number}")
        numeric = {
            column: finite_csv(
                row[column], f"{source.path.name}:{row_number} {column}"
            )
            for column in SSP_COLUMNS
        }
        weight, age = numeric["N"], numeric["age"]
        initial_mass, mass = numeric["Mini"], numeric["Mf"]
        log_temperature, gravity = numeric["logT"], numeric["logg"]
        disk_label = numeric["disk_label"]
        if weight < 0.0 or age < 0.0 or initial_mass <= 0.0 or mass <= 0.0:
            fail(f"invalid nonnegative/positive SSP field at {source.path.name}:{row_number}")
        if disk_label != float(expected_disk_label):
            fail(f"disk label mismatch at {source.path.name}:{row_number}")
        teff = math.pow(10.0, log_temperature)
        if not math.isfinite(teff) or teff <= 0.0:
            fail(f"invalid Teff at {source.path.name}:{row_number}")
        if TMIN_K <= teff <= TMAX_K:
            weights.append(weight)
            ages.append(age)
            teffs.append(teff)
            masses.append(mass)
            gravities.append(gravity)
    return tuple(
        np.asarray(values, dtype=float)
        for values in (weights, ages, teffs, masses, gravities)
    )  # type: ignore[return-value]


def recompute_radial(ssp: dict[str, FileSnapshot]) -> list[dict[str, float]]:
    tams_temperature, tams_radius = load_tams_reference()
    aggregate: dict[tuple[float, float, str], tuple[float, float, float]] = {}
    for radius in RADII:
        for code, component, disk_label in COMPONENTS:
            name = ssp_name(radius, code)
            weights, ages, temperatures, masses, gravities = parse_ssp_independently(
                ssp[name], disk_label
            )
            if len(weights):
                stellar_radius = np.sqrt(masses * np.power(10.0, LOGG_SUN - gravities))
                boundary = 10.0 ** np.interp(
                    temperatures, tams_temperature, np.log10(tams_radius)
                )
                if not np.isfinite(stellar_radius).all() or np.any(stellar_radius <= 0.0):
                    fail(f"invalid stellar-radius reconstruction in {name}")
                selector = (stellar_radius <= boundary) & (gravities < LOGG_COMPACT_VETO)
                hz, earth = occurrence_weights(temperatures)
                if (
                    not np.isfinite(hz).all()
                    or not np.isfinite(earth).all()
                    or np.any(hz < 0.0)
                    or np.any(earth < 0.0)
                    or np.any(earth > hz + 1.0e-15)
                ):
                    fail(f"invalid independently calculated occurrence values in {name}")
            else:
                selector = np.zeros(0, dtype=bool)
                hz = np.zeros(0, dtype=float)
                earth = np.zeros(0, dtype=float)
            for threshold in AGE_THRESHOLDS:
                use = selector & (ages >= threshold)
                selected = weights[use]
                aggregate[(threshold, radius, component)] = (
                    math.fsum(selected.tolist()),
                    math.fsum((selected * hz[use]).tolist()),
                    math.fsum((selected * earth[use]).tolist()),
                )
    result: list[dict[str, float]] = []
    for threshold in AGE_THRESHOLDS:
        for radius in RADII:
            thin = aggregate[(threshold, radius, "thin")]
            thick = aggregate[(threshold, radius, "thick")]
            factor = 2.0 * math.pi * radius * 1.0e6
            result.append(
                {
                    "age_threshold_Gyr": threshold,
                    "R_kpc": radius,
                    "Sigma_G_thin_pc-2": thin[0],
                    "Sigma_G_thick_pc-2": thick[0],
                    "Sigma_G_total_pc-2": thin[0] + thick[0],
                    "dN_dR_stars_kpc-1": factor * (thin[0] + thick[0]),
                    "dLambda_HZ_dR_kpc-1": factor * (thin[1] + thick[1]),
                    "dLambda_Earth10_dR_kpc-1": factor * (thin[2] + thick[2]),
                }
            )
    require_monotonic(result)
    return result


def require_monotonic(rows: list[dict[str, float]]) -> None:
    fields = RADIAL_COLUMNS[2:]
    by_key = {(row["age_threshold_Gyr"], row["R_kpc"]): row for row in rows}
    if len(by_key) != len(AGE_THRESHOLDS) * len(RADII):
        fail("radial age-cut keys are not unique and complete")
    for radius in RADII:
        for field in fields:
            values = [by_key[(threshold, radius)][field] for threshold in AGE_THRESHOLDS]
            if any(later > earlier for earlier, later in zip(values, values[1:])):
                fail(f"exact radial monotonicity failed at R={radius:g} for {field}")


def integrate(
    rows: list[dict[str, float]], threshold: float, field: str, lo: float, hi: float
) -> float:
    selected = [
        row
        for row in rows
        if row["age_threshold_Gyr"] == threshold and lo <= row["R_kpc"] <= hi
    ]
    expected_radii = [radius for radius in RADII if lo <= radius <= hi]
    if [row["R_kpc"] for row in selected] != expected_radii:
        fail(f"integration grid incomplete for {threshold=} {field=} {lo=} {hi=}")
    return math.fsum(
        0.5
        * (left[field] + right[field])
        * (right["R_kpc"] - left["R_kpc"])
        for left, right in zip(selected, selected[1:])
    )


def csv_rows(source: FileSnapshot, header: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(source.data.decode("utf-8"), newline=""))
        if tuple(reader.fieldnames or ()) != header:
            fail(f"CSV header changed in {source.path.name}: {reader.fieldnames!r}")
        rows = list(reader)
    except (UnicodeError, csv.Error) as exc:
        fail(f"cannot parse CSV {source.path.name}: {exc}")
    if any(set(row) != set(header) or any(value is None for value in row.values()) for row in rows):
        fail(f"malformed CSV row in {source.path.name}")
    return rows


def canonical_snapshot(
    root_path: Path, expected_commit: str
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]], list[dict[str, str]], Any]:
    root = require_directory(root_path, "canonical host root")
    manifest = read_snapshot(
        root / CANONICAL_MANIFEST_NAME,
        "canonical host manifest",
        maximum_bytes=MAX_MANIFEST_BYTES,
    )
    listed = parse_manifest_bytes(
        manifest.data, CANONICAL_MANIFEST_MEMBERS, "canonical host manifest"
    )
    members: dict[str, FileSnapshot] = {}
    for name in CANONICAL_MANIFEST_MEMBERS:
        member = read_snapshot(root / name, f"canonical host file {name}")
        if member.sha256 != listed[name]:
            fail(f"canonical host manifest hash mismatch for {name}")
        members[name] = member
    tams_radial = read_snapshot(root / TAMS_AB_RADIAL_NAME, "TAMS A/B radial table")
    tams_results = read_snapshot(
        root / TAMS_AB_RESULTS_NAME, "TAMS A/B results", maximum_bytes=MAX_REPORT_BYTES
    )
    canonical_rows = csv_rows(
        members[CANONICAL_RADIAL_NAME],
        (
            "R_kpc",
            "Sigma_G_thin_pc-2",
            "Sigma_G_thick_pc-2",
            "Sigma_G_total_pc-2",
            "dN_dR_stars_kpc-1",
        ),
    )
    tams_rows = csv_rows(
        tams_radial,
        ("R_kpc", "A_N", "B_N", "A_L1", "B_L1", "A_L2", "B_L2"),
    )
    summary = load_strict_json(members[CANONICAL_SUMMARY_NAME].data, "canonical summary")
    result = load_strict_json(tams_results.data, "TAMS A/B results")
    if not isinstance(summary, dict) or not isinstance(result, dict):
        fail("canonical summary and TAMS A/B results must be objects")
    if summary.get("jj_commit") != expected_commit:
        fail("canonical host summary JJ commit differs from the audited checkout")
    if summary.get("isochrone_family") != "Padova/PARSEC":
        fail("canonical host summary is not Padova/PARSEC")
    estimand = summary.get("host_estimand")
    if not isinstance(estimand, dict) or finite_number(
        estimand.get("age_Gyr_min"), "canonical age minimum"
    ) != 4.57:
        fail("canonical host summary is not age>=4.57")
    snapshots = {
        CANONICAL_MANIFEST_NAME: manifest,
        **members,
        TAMS_AB_RADIAL_NAME: tams_radial,
        TAMS_AB_RESULTS_NAME: tams_results,
    }
    names = (
        CANONICAL_MANIFEST_NAME,
        CANONICAL_RADIAL_NAME,
        CANONICAL_SUMMARY_NAME,
        TAMS_AB_RADIAL_NAME,
        TAMS_AB_RESULTS_NAME,
    )
    evidence = {
        name: {
            "filename": name,
            "sha256": snapshots[name].sha256,
            "size_bytes": snapshots[name].size_bytes,
        }
        for name in names
    }
    return evidence, canonical_rows, tams_rows, result


def compare_close(observed: float, expected: float, description: str) -> tuple[float, float]:
    if not math.isfinite(observed) or not math.isfinite(expected):
        fail(f"non-finite comparison for {description}")
    absolute = abs(observed - expected)
    relative = absolute / max(abs(expected), 1.0)
    if absolute > 1.0e-5 and relative > 5.0e-12:
        fail(f"{description} mismatch: {observed!r} != {expected!r}")
    return absolute, relative


def canonical_cross_check(
    rows: list[dict[str, float]],
    canonical_rows: list[dict[str, str]],
    tams_rows: list[dict[str, str]],
    tams_results: Any,
) -> dict[str, Any]:
    selected = [row for row in rows if row["age_threshold_Gyr"] == 4.57]
    if len(selected) != 21 or len(canonical_rows) != 21 or len(tams_rows) != 21:
        fail("canonical 4.57-Gyr radial cross-check must contain 21 nodes")
    max_abs = 0.0
    max_rel = 0.0
    for radius, current, canonical, tams in zip(RADII, selected, canonical_rows, tams_rows):
        if finite_csv(canonical["R_kpc"], "canonical R_kpc") != radius:
            fail("canonical radial order differs")
        if finite_csv(tams["R_kpc"], "TAMS R_kpc") != radius:
            fail("TAMS radial order differs")
        comparisons = (
            (current["Sigma_G_thin_pc-2"], finite_csv(canonical["Sigma_G_thin_pc-2"], "canonical thin sigma"), "canonical thin sigma"),
            (current["Sigma_G_thick_pc-2"], finite_csv(canonical["Sigma_G_thick_pc-2"], "canonical thick sigma"), "canonical thick sigma"),
            (current["Sigma_G_total_pc-2"], finite_csv(canonical["Sigma_G_total_pc-2"], "canonical total sigma"), "canonical total sigma"),
            (current["dN_dR_stars_kpc-1"], finite_csv(canonical["dN_dR_stars_kpc-1"], "canonical dN/dR"), "canonical dN/dR"),
            (current["dN_dR_stars_kpc-1"], finite_csv(tams["B_N"], "TAMS B_N"), "TAMS B_N"),
            (current["dLambda_HZ_dR_kpc-1"], finite_csv(tams["B_L1"], "TAMS B_L1"), "TAMS B_L1"),
            (current["dLambda_Earth10_dR_kpc-1"], finite_csv(tams["B_L2"], "TAMS B_L2"), "TAMS B_L2"),
        )
        for observed, expected, name in comparisons:
            absolute, relative = compare_close(observed, expected, f"R={radius:g} {name}")
            max_abs = max(max_abs, absolute)
            max_rel = max(max_rel, relative)
    if not isinstance(tams_results, dict) or not isinstance(tams_results.get("domains"), dict):
        fail("TAMS A/B results domains are missing")
    domain_values: dict[str, Any] = {}
    for name, lo, hi in (("lineweaver_7_9", 7.0, 9.0), ("full_JJ_4_14", 4.0, 14.0)):
        raw_domain = tams_results["domains"].get(name)
        branch = raw_domain.get("B") if isinstance(raw_domain, dict) else None
        if not isinstance(branch, dict):
            fail(f"TAMS A/B domain B is missing for {name}")
        derived = {
            "N_G": integrate(rows, 4.57, "dN_dR_stars_kpc-1", lo, hi),
            "Lambda_ESHZ": integrate(rows, 4.57, "dLambda_HZ_dR_kpc-1", lo, hi),
            "Lambda_earth10": integrate(
                rows, 4.57, "dLambda_Earth10_dR_kpc-1", lo, hi
            ),
        }
        for field, value in derived.items():
            reported = finite_number(branch.get(field), f"TAMS {name} B {field}")
            absolute, relative = compare_close(value, reported, f"TAMS {name} B {field}")
            max_abs = max(max_abs, absolute)
            max_rel = max(max_rel, relative)
        domain_values[name] = derived
    return {
        "status": "PASS",
        "age_threshold_Gyr": 4.57,
        "radial_node_count": 21,
        "maximum_absolute_difference": max_abs,
        "maximum_relative_difference": max_rel,
        "domains": domain_values,
    }


def integrated_domains(rows: list[dict[str, float]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, lo, hi in (("lineweaver_7_9", 7.0, 9.0), ("full_JJ_4_14", 4.0, 14.0)):
        values = [
            {
                "age_threshold_Gyr": threshold,
                "N_G": integrate(rows, threshold, "dN_dR_stars_kpc-1", lo, hi),
                "Lambda_HZ": integrate(rows, threshold, "dLambda_HZ_dR_kpc-1", lo, hi),
                "Lambda_Earth10": integrate(
                    rows, threshold, "dLambda_Earth10_dR_kpc-1", lo, hi
                ),
            }
            for threshold in AGE_THRESHOLDS
        ]
        for field in ("N_G", "Lambda_HZ", "Lambda_Earth10"):
            sequence = [row[field] for row in values]
            if any(later > earlier for earlier, later in zip(sequence, sequence[1:])):
                fail(f"exact integrated monotonicity failed for {name}/{field}")
        result[name] = {"R_kpc": [lo, hi], "by_threshold": values}
    return result


def parse_artifact_radial(source: FileSnapshot) -> list[dict[str, float]]:
    raw = csv_rows(source, RADIAL_COLUMNS)
    if len(raw) != 105:
        fail(f"age-cut radial table must contain 105 rows, found {len(raw)}")
    result: list[dict[str, float]] = []
    for index, row in enumerate(raw):
        parsed = {key: finite_csv(row[key], f"age-cut radial row {index + 2} {key}") for key in RADIAL_COLUMNS}
        result.append(parsed)
    expected_keys = [(threshold, radius) for threshold in AGE_THRESHOLDS for radius in RADII]
    observed_keys = [(row["age_threshold_Gyr"], row["R_kpc"]) for row in result]
    if observed_keys != expected_keys or len(set(observed_keys)) != 105:
        fail("age-cut radial row identity/order is incomplete, duplicated, or changed")
    require_monotonic(result)
    return result


def compare_radial(
    observed: list[dict[str, float]], expected: list[dict[str, float]]
) -> None:
    if len(observed) != len(expected):
        fail("age-cut radial table row count differs from independent recomputation")
    for index, (left, right) in enumerate(zip(observed, expected), 2):
        if (left["age_threshold_Gyr"], left["R_kpc"]) != (
            right["age_threshold_Gyr"],
            right["R_kpc"],
        ):
            fail(f"age-cut radial key mismatch at row {index}")
        for field in RADIAL_COLUMNS[2:]:
            compare_close(left[field], right[field], f"age-cut radial row {index} {field}")


def evidence(source: FileSnapshot) -> dict[str, Any]:
    return {
        "filename": source.path.name,
        "sha256": source.sha256,
        "size_bytes": source.size_bytes,
    }


def compare_document(observed: Any, expected: Any, description: str = "report") -> None:
    """Strict structural comparison with a tight numeric portability tolerance."""

    if isinstance(expected, bool):
        if type(observed) is not bool or observed is not expected:
            fail(f"{description} boolean differs")
        return
    if isinstance(expected, int):
        if type(observed) is not int or observed != expected:
            fail(f"{description} integer differs or was coerced")
        return
    if isinstance(expected, float):
        if type(observed) is not float:
            fail(f"{description} float differs in type or was coerced")
        compare_close(observed, expected, description)
        return
    if isinstance(expected, str) or expected is None:
        if type(observed) is not type(expected) or observed != expected:
            fail(f"{description} value differs")
        return
    if isinstance(expected, list):
        if not isinstance(observed, list) or len(observed) != len(expected):
            fail(f"{description} list length/type differs")
        for index, (left, right) in enumerate(zip(observed, expected)):
            compare_document(left, right, f"{description}[{index}]")
        return
    if isinstance(expected, dict):
        exact_keys(observed, set(expected), description)
        for key in expected:
            compare_document(observed[key], expected[key], f"{description}.{key}")
        return
    fail(f"unsupported expected type while comparing {description}")


def _verify_age_cut_artifact(
    artifact_root: Path,
    *,
    jj_root: Path,
    run_dir: Path,
    canonical_host_root: Path,
    age_ssp_contract: Path,
    ssp_qualification_report: Path,
    host_artifact_contract: Path,
    expected_jj_commit: str,
    require_repository_contract_paths: bool = True,
    ssp_contract_check: Any = ssp_contract_verifier.verify_accepted_repetition,
    host_contract_check: Any = host_contract_verifier.verify_artifact,
) -> dict[str, Any]:
    if require_repository_contract_paths:
        if Path(age_ssp_contract).resolve() != CANONICAL_SSP_CONTRACT_PATH.resolve():
            fail("age-cut verifier requires the repository-canonical SSP contract path")
        if Path(host_artifact_contract).resolve() != CANONICAL_HOST_CONTRACT_PATH.resolve():
            fail("age-cut verifier requires the repository-canonical host contract path")
    try:
        qualified_ssp = ssp_contract_check(
            Path(age_ssp_contract), Path(ssp_qualification_report), Path(run_dir)
        )
    except ssp_contract_verifier.SSPContractError as exc:
        fail(f"age-cut SSP qualification gate failed: {exc}")
    try:
        qualified_host = host_contract_check(
            Path(host_artifact_contract), Path(canonical_host_root)
        )
    except host_contract_verifier.ContractError as exc:
        fail(f"canonical host contract gate failed: {exc}")
    if not isinstance(qualified_ssp, dict) or qualified_ssp.get(
        "artifact_set_id"
    ) is None:
        fail("age-cut SSP contract verifier returned invalid evidence")
    if (
        not isinstance(qualified_host, dict)
        or not isinstance(qualified_host.get("artifact_set"), dict)
        or qualified_host["artifact_set"].get("production_accepted") is not True
    ):
        fail("canonical host contract verifier returned invalid evidence")
    root = require_directory(artifact_root, "age-cut artifact root")
    entries = {path.name for path in root.iterdir()}
    if entries != OUTPUT_FILES:
        fail(
            "age-cut artifact root does not contain the exact four-file set: "
            f"expected={sorted(OUTPUT_FILES)!r}, found={sorted(entries)!r}"
        )
    snapshots = {
        REPORT_NAME: read_snapshot(root / REPORT_NAME, "age-cut report", maximum_bytes=MAX_REPORT_BYTES),
        RADIAL_NAME: read_snapshot(root / RADIAL_NAME, "age-cut radial table", maximum_bytes=MAX_RADIAL_BYTES),
        SSP_MANIFEST_NAME: read_snapshot(root / SSP_MANIFEST_NAME, "JJ SSP manifest", maximum_bytes=MAX_MANIFEST_BYTES),
        OUTPUT_MANIFEST_NAME: read_snapshot(root / OUTPUT_MANIFEST_NAME, "age-cut output manifest", maximum_bytes=MAX_MANIFEST_BYTES),
    }
    if {path.name for path in root.iterdir()} != OUTPUT_FILES:
        fail("age-cut artifact root changed during snapshot")
    output_manifest = parse_manifest_bytes(
        snapshots[OUTPUT_MANIFEST_NAME].data,
        OUTPUT_MANIFEST_MEMBERS,
        "age-cut output manifest",
    )
    for name in OUTPUT_MANIFEST_MEMBERS:
        if snapshots[name].sha256 != output_manifest[name]:
            fail(f"age-cut output manifest hash mismatch for {name}")

    commit, official_parameters, official_sfr = verify_jj_checkout(
        Path(jj_root), expected_jj_commit
    )
    runtime, parameters, sfr = run_configuration(
        Path(run_dir), official_parameters, official_sfr
    )
    ssp = snapshot_ssp_set(Path(run_dir), allow_qualified_flat_root=True)
    if {name: ssp[name].sha256 for name in ssp_names()} != qualified_ssp.get(
        "ssp_member_sha256"
    ):
        fail("independent SSP snapshots differ from the accepted qualification tuple")
    if parameters.sha256 != qualified_ssp.get("runtime_parameters_sha256"):
        fail("runtime parameters differ from the accepted SSP qualification")
    if sfr.sha256 != qualified_ssp.get("sfr_peaks_parameters_sha256"):
        fail("SFR-peak parameters differ from the accepted SSP qualification")
    ssp_manifest = parse_manifest_bytes(
        snapshots[SSP_MANIFEST_NAME].data, ssp_names(), "JJ SSP input manifest"
    )
    for name in ssp_names():
        if ssp[name].sha256 != ssp_manifest[name]:
            fail(f"JJ SSP bytes differ from the bound input manifest: {name}")

    recomputed = recompute_radial(ssp)
    reported_radial = parse_artifact_radial(snapshots[RADIAL_NAME])
    compare_radial(reported_radial, recomputed)
    canonical_evidence, canonical_rows, tams_rows, tams_results = canonical_snapshot(
        Path(canonical_host_root), expected_jj_commit
    )
    cross_check = canonical_cross_check(
        recomputed, canonical_rows, tams_rows, tams_results
    )
    domains = integrated_domains(recomputed)
    expected_report = {
        "schema_version": 1,
        "status": "PASS",
        "experiment": "age_threshold_sensitivity_canonical_parsec_tams",
        "jj": {
            "repository": "askenja/jjmodel",
            "commit": commit,
            "version_expected": "1.0.1",
            "isochrone_label": "Padova",
            "isochrone_family": "Padova/PARSEC",
            "runtime_parameters": evidence(parameters),
            "sfr_peaks_parameters": evidence(sfr),
            "runtime_configuration": runtime,
            "ssp_manifest": evidence(snapshots[SSP_MANIFEST_NAME]),
            "ssp_file_count": 42,
        },
        "host_estimand": {
            "Teff_K": [5300.0, 6000.0],
            "temperature_interval": "closed",
            "age_thresholds_Gyr": list(AGE_THRESHOLDS),
            "age_interval": "age_Gyr >= threshold",
            "components": ["thin", "thick"],
            "main_sequence_selector": (
                "Rstar_g <= PARSEC TAMS radius at Teff, plus logg < 7 "
                "compact-remnant veto"
            ),
            "radius_reconstruction": "Rstar/Rsun = sqrt(Mf * 10^(4.438-logg))",
            "tams_reference_sha256": TAMS_SHA256,
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
                "node_count": 21,
            },
        },
        "canonical_inputs": canonical_evidence,
        "canonical_age_4p57_cross_check": cross_check,
        "domains": domains,
        "monotonicity": {
            "status": "PASS",
            "direction": "nonincreasing with increasing minimum age",
            "radial_checks": 21 * 6 * (len(AGE_THRESHOLDS) - 1),
            "integrated_checks": 2 * 3 * (len(AGE_THRESHOLDS) - 1),
            "exact_comparison": True,
        },
        "row_level_host_output_emitted": False,
    }
    report = load_strict_json(snapshots[REPORT_NAME].data, "age-cut report")
    compare_document(report, expected_report)
    if {path.name for path in root.iterdir()} != OUTPUT_FILES:
        fail("age-cut artifact root changed during verification")
    return report


def verify_age_cut_artifact(
    artifact_root: Path,
    *,
    jj_root: Path,
    run_dir: Path,
    canonical_host_root: Path,
    age_ssp_contract: Path,
    ssp_qualification_report: Path,
    host_artifact_contract: Path,
) -> dict[str, Any]:
    """Public fail-closed verifier locked to the production JJ commit."""

    return _verify_age_cut_artifact(
        artifact_root,
        jj_root=jj_root,
        run_dir=run_dir,
        canonical_host_root=canonical_host_root,
        age_ssp_contract=age_ssp_contract,
        ssp_qualification_report=ssp_qualification_report,
        host_artifact_contract=host_artifact_contract,
        expected_jj_commit=JJ_SHA,
    )


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--artifact-root", required=True, type=Path)
    argument_parser.add_argument("--jj-root", required=True, type=Path)
    argument_parser.add_argument("--run-dir", required=True, type=Path)
    argument_parser.add_argument("--canonical-host-root", required=True, type=Path)
    argument_parser.add_argument("--age-ssp-contract", required=True, type=Path)
    argument_parser.add_argument(
        "--ssp-qualification-report", required=True, type=Path
    )
    argument_parser.add_argument("--host-artifact-contract", required=True, type=Path)
    return argument_parser


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        report = verify_age_cut_artifact(
            args.artifact_root,
            jj_root=args.jj_root,
            run_dir=args.run_dir,
            canonical_host_root=args.canonical_host_root,
            age_ssp_contract=args.age_ssp_contract,
            ssp_qualification_report=args.ssp_qualification_report,
            host_artifact_contract=args.host_artifact_contract,
        )
    except VerificationError as exc:
        raise SystemExit(f"AGE CUT SENSITIVITY FAIL: {exc}") from exc
    print(
        "PASS age-cut sensitivity "
        f"({len(report['host_estimand']['age_thresholds_Gyr'])} thresholds; "
        "42 SSP inputs independently rederived)"
    )


if __name__ == "__main__":
    main()
