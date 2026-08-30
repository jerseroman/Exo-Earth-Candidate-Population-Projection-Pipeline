#!/usr/bin/env python3
"""Fail closed unless a metallicity-TAMS artifact is a negative validation.

The accepted artifact does not contain or authorize a metallicity-dependent
host correction.  It records that the checksum-locked public PARSEC tracks do
not provide full low-mass TAMS coverage over the required temperature domain,
plus a validation-only solar-metallicity node table used by the separate host
selector audit.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_LOCKS = ROOT / "provenance" / "DATA_LOCKS.json"
SOURCE_PROVENANCE = (
    ROOT / "research" / "jj-host-export" / "PROVENANCE_METALLICITY_DIFFERENTIAL.md"
)

REPORT_NAME = "metallicity_tams_differential_sensitivity.json"
SOLAR_POINTS_NAME = "native_solar_tams_nodes.csv"
RUNTIME_NAME = "NUMERICAL_RUNTIME_POLICY.json"
PROVENANCE_NAME = "PROVENANCE_METALLICITY_DIFFERENTIAL.md"
MANIFEST_NAME = "SHA256SUMS_all.txt"

MANIFEST_TARGETS = {
    REPORT_NAME,
    SOLAR_POINTS_NAME,
    RUNTIME_NAME,
    PROVENANCE_NAME,
}
EXPECTED_FILES = {*MANIFEST_TARGETS, MANIFEST_NAME}
FORBIDDEN_CORRECTION_FILES = {
    "metallicity_tams_differential_radial.csv",
    "metallicity_tams_solar_validation.csv",
    "metallicity_tams_anchor_points.csv",
}

EXPECTED_STATUS = "FAIL_NOT_PUBLISHABLE"
EXPECTED_DECISION = (
    "No metallicity-dependent TAMS correction is computed or used in "
    "manuscript v4."
)
EXPECTED_REASON = (
    "The public archive does not provide a validated low-mass phase-7 TAMS "
    "surface over 5300--6000 K at every required metallicity."
)
EXPECTED_CORRECTION_POLICY = {
    "applied": False,
    "publishable": False,
    "emitted_files": [],
}
EXPECTED_LOW_MASS_FILTER = {
    "maximum_mass_Msun": 2.0,
    "maximum_radius_Rsun_exclusive": 10.0,
    "track_age_horizon_Gyr": 30.0,
    "required_temperature_range_K": [5300.0, 6000.0],
}
PARSEC_LOCK_METALLICITIES = {
    "parsec_tracks_z00005": 0.0005,
    "parsec_tracks_z0001": 0.001,
    "parsec_tracks_z0002": 0.002,
    "parsec_tracks_z0004": 0.004,
    "parsec_tracks_z0006": 0.006,
    "parsec_tracks_z0008": 0.008,
    "parsec_tracks_z001": 0.010,
    "parsec_tracks_z0014": 0.014,
    "parsec_tracks_z0017": 0.017,
    "parsec_tracks_z002": 0.020,
    "parsec_tracks_z003": 0.030,
    "parsec_tracks_z004": 0.040,
}
PARSEC_LOCK_ORDER = tuple(PARSEC_LOCK_METALLICITIES)
EXPECTED_PARENT_FILENAME = "jj_g_hosts_parent_prelogg_padova.csv"

EXPECTED_NUMERICAL_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,"
        "AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
EXPECTED_RUNTIME_KEYS = {
    "schema_version",
    "status",
    "python",
    "python_executable",
    "platform",
    "machine",
    "numpy_version",
    "numpy_cpu_baseline",
    "numpy_cpu_dispatch_build",
    "selected_cpu_features",
    "environment",
}
EXPECTED_SELECTED_CPU_FEATURE_KEYS = {
    "AVX2",
    "AVX512CD",
    "AVX512F",
    "AVX512_KNL",
    "AVX512_KNM",
    "AVX512_CLX",
    "AVX512_CNL",
    "AVX512_ICL",
    "AVX512_SKX",
    "FMA3",
}
EXPECTED_REQUIRED_CPU_FEATURE_STATES = {
    "AVX2": True,
    "FMA3": True,
    "AVX512F": False,
    "AVX512CD": False,
    "AVX512_KNL": False,
    "AVX512_KNM": False,
    "AVX512_CLX": False,
    "AVX512_CNL": False,
    "AVX512_ICL": False,
    "AVX512_SKX": False,
}

EXPECTED_REPORT_KEYS = {
    "schema_version",
    "experiment",
    "status",
    "decision",
    "reason",
    "parent_input",
    "low_mass_filter",
    "coverage_failures",
    "coverage_evidence",
    "correction_policy",
    "native_solar_reference",
}
EXPECTED_PARENT_INPUT_KEYS = {
    "filename",
    "sha256",
    "size_bytes",
    "row_count",
    "feh_min",
    "feh_max",
}
EXPECTED_COVERAGE_EVIDENCE_KEYS = {
    "required_lock_ids",
    "successful_lock_ids",
    "failed_lock_ids",
}
EXPECTED_FAILURE_KEYS = {
    "Z",
    "archive",
    "archive_lock_id",
    "archive_size_bytes",
    "archive_sha256",
    "error",
}
EXPECTED_SOLAR_REFERENCE_KEYS = {
    "status",
    "role",
    "metallicity_Z",
    "points_file",
    "points_sha256",
    "node_count",
    "reference_validation_node_count",
    "max_abs_temperature_difference_K",
    "max_relative_radius_difference",
    "archive_lock_id",
    "archive_filename",
    "archive_size_bytes",
    "archive_sha256",
}
EXPECTED_SOLAR_COLUMNS = [
    "Z",
    "Y",
    "MH",
    "Teff_K",
    "R_Rsun",
    "mass",
    "file",
    "age_Gyr",
]

REFERENCE_TEFF = (
    5390.13944,
    5517.85139,
    5633.13293,
    5738.25706,
    5844.13178,
    5951.82290,
    6060.24246,
)
REFERENCE_RADIUS = (
    1.22926,
    1.28542,
    1.35053,
    1.42375,
    1.49188,
    1.55332,
    1.61155,
)
# Regenerated phase-7 rows from DATA_LOCKS.json lock parsec_tracks_z0017,
# SHA-256 22d0dd4783d6c4bff882c9c319f748aa5e8d3937bb57b5dbc54f5071d51268c2.
EXPECTED_SOLAR_NODES = (
    (0.017, 0.279, 0.06675788707313442, 5151.337446989074, 1.011706953863964, 0.75, "Z0.017Y0.279OUTA1.74_F7_M000.750.DAT", 27.202020114),
    (0.017, 0.279, 0.06675788707313442, 5304.812032718946, 1.0337124217916671, 0.80, "Z0.017Y0.279OUTA1.74_F7_M000.800.DAT", 21.0708279315),
    (0.017, 0.279, 0.06675788707313442, 5390.139436325507, 1.2292627883933631, 0.85, "Z0.017Y0.279OUTA1.74_F7_M000.850.DAT", 18.3962474249),
    (0.017, 0.279, 0.06675788707313442, 5517.851394729554, 1.2854190594305617, 0.90, "Z0.017Y0.279OUTA1.74_F7_M000.900.DAT", 14.8576832197),
    (0.017, 0.279, 0.06675788707313442, 5633.132932779186, 1.3505315525272714, 0.95, "Z0.017Y0.279OUTA1.74_F7_M000.950.DAT", 12.1056313313),
    (0.017, 0.279, 0.06675788707313442, 5738.257064157849, 1.4237532717384762, 1.00, "Z0.017Y0.279OUTA1.74_F7_M001.000.DAT", 9.949438865),
    (0.017, 0.279, 0.06675788707313442, 5844.131775573857, 1.4918828965541018, 1.05, "Z0.017Y0.279OUTA1.74_F7_M001.050.DAT", 8.19537291074),
    (0.017, 0.279, 0.06675788707313442, 5951.822899428788, 1.553315711522533, 1.10, "Z0.017Y0.279OUTA1.74_F7_M001.100.DAT", 6.7592173605),
    (0.017, 0.279, 0.06675788707313442, 6060.242461424597, 1.611553527393026, 1.15, "Z0.017Y0.279OUTA1.74_F7_M001.150.DAT", 5.58853443962),
)
SOLAR_NODE_ABS_TOLERANCES = {
    "Z": 1.0e-12,
    "Y": 1.0e-12,
    "MH": 1.0e-12,
    "Teff_K": 1.0e-5,
    "R_Rsun": 1.0e-10,
    "mass": 1.0e-12,
    "age_Gyr": 1.0e-10,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditError(RuntimeError):
    """Raised when an artifact does not satisfy the negative-audit contract."""


def fail(message: str) -> None:
    raise AuditError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def is_portable_safe_leaf(value: Any) -> bool:
    """Return true only for one path leaf under both POSIX and Windows rules."""

    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "\x00" not in value
        and "/" not in value
        and "\\" not in value
        and ":" not in value
        and PurePosixPath(value).name == value
        and PureWindowsPath(value).name == value
    )


def read_regular_bytes(path: Path, description: str) -> bytes:
    """Read one immutable snapshot while rejecting symlinks and path swaps."""

    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            fail(f"{description} is missing or is not a safe regular file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after_open = path.lstat()
            if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after_open.st_mode):
                fail(f"{description} changed to an unsafe file type: {path}")
            identities = {
                (before.st_dev, before.st_ino),
                (opened.st_dev, opened.st_ino),
                (after_open.st_dev, after_open.st_ino),
            }
            if len(identities) != 1:
                fail(f"{description} path changed while opening: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read()
            finished = os.fstat(descriptor)
            opened_state = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            finished_state = (
                finished.st_dev,
                finished.st_ino,
                finished.st_size,
                finished.st_mtime_ns,
            )
            if opened_state != finished_state or len(payload) != opened.st_size:
                fail(f"{description} changed while reading: {path}")
            return payload
        finally:
            os.close(descriptor)
    except AuditError:
        raise
    except (OSError, ValueError) as exc:
        fail(f"cannot safely read {description}: {exc}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(read_regular_bytes(path, f"SHA-256 input {path.name}")).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    fail(f"non-finite JSON number is forbidden: {value}")


def load_json_bytes(payload: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite_json,
        )
    except AuditError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {description}: {exc}")
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object")
    return value


def load_json(path: Path, description: str) -> dict[str, Any]:
    return load_json_bytes(read_regular_bytes(path, description), description)


def require_exact_keys(
    value: Any, expected: set[str], description: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    if set(value) != expected:
        fail(
            f"{description} key set changed: expected={sorted(expected)!r}, "
            f"found={sorted(value)!r}"
        )
    return value


def require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} is missing or is not a safe regular file: {path}")


def require_finite_number(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} must be a JSON number")
    numeric = float(value)
    if not math.isfinite(numeric):
        fail(f"{description} must be finite")
    return numeric


def mh_from_z(metallicity: float) -> float:
    helium = 0.2485 + 1.78 * metallicity
    hydrogen = 1.0 - helium - metallicity
    return math.log10((metallicity / hydrogen) / 0.0207)


def required_lock_ids_for_parent(feh_min: float, feh_max: float) -> list[str]:
    anchor_mh = [mh_from_z(PARSEC_LOCK_METALLICITIES[item]) for item in PARSEC_LOCK_ORDER]
    lower = max(0, bisect.bisect_right(anchor_mh, feh_min) - 1)
    upper = min(len(PARSEC_LOCK_ORDER) - 1, bisect.bisect_left(anchor_mh, feh_max))
    selected = set(PARSEC_LOCK_ORDER[lower : upper + 1])
    selected.add("parsec_tracks_z0017")
    return [lock_id for lock_id in PARSEC_LOCK_ORDER if lock_id in selected]


def validate_parent_input(raw: Any) -> tuple[dict[str, Any], list[str]]:
    parent = require_exact_keys(raw, EXPECTED_PARENT_INPUT_KEYS, "parent input evidence")
    filename = parent["filename"]
    if (
        filename != EXPECTED_PARENT_FILENAME
        or not is_portable_safe_leaf(filename)
    ):
        fail("parent input filename changed or is unsafe")
    digest = parent["sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        fail("parent input SHA-256 is invalid")
    for key in ("size_bytes", "row_count"):
        value = parent[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            fail(f"parent input {key} must be a positive integer")
    feh_min = require_finite_number(parent["feh_min"], "parent input feh_min")
    feh_max = require_finite_number(parent["feh_max"], "parent input feh_max")
    if feh_min > feh_max:
        fail("parent input FeH domain is reversed")
    return parent, required_lock_ids_for_parent(feh_min, feh_max)


FLOAT_TOKEN = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
COVERAGE_ERROR_RE = re.compile(
    rf"low-mass TAMS coverage ({FLOAT_TOKEN})\.\.({FLOAT_TOKEN}) K "
    r"does not span 5300\.0\.\.6000\.0 K"
)
INSUFFICIENT_ERROR_RE = re.compile(r"insufficient low-mass TAMS points \(([0-9]+)\)")


def validate_failure_error(error: Any, metallicity: float, index: int) -> None:
    if not isinstance(error, str) or not error.strip():
        fail(f"coverage failure {index} lacks an error description")
    prefix = f"Z={metallicity}: "
    if not error.startswith(prefix):
        fail(f"coverage failure {index} error does not identify its metallicity")
    detail = error[len(prefix) :]
    insufficient = INSUFFICIENT_ERROR_RE.fullmatch(detail)
    if insufficient is not None:
        if int(insufficient.group(1)) >= 4:
            fail(f"coverage failure {index} has a non-failing point count")
        return
    coverage = COVERAGE_ERROR_RE.fullmatch(detail)
    if coverage is None:
        fail(f"coverage failure {index} has an unrecognized failure condition")
    lower, upper = map(float, coverage.groups())
    if not all(math.isfinite(value) for value in (lower, upper)) or lower > upper:
        fail(f"coverage failure {index} has an invalid temperature domain")
    if lower <= 5300.0 and upper >= 6000.0:
        fail(f"coverage failure {index} error describes successful coverage")


def load_data_locks(path: Path) -> dict[str, dict[str, Any]]:
    require_regular_file(path, "data-lock registry")
    registry = load_json(path, "data-lock registry")
    locks = registry.get("locks")
    if not isinstance(locks, dict):
        fail("data-lock registry lacks a locks object")
    result: dict[str, dict[str, Any]] = {}
    for lock_id, record in locks.items():
        if isinstance(lock_id, str) and isinstance(record, dict):
            result[lock_id] = record
    return result


def validate_manifest(
    root: Path, snapshots: dict[str, bytes] | None = None
) -> dict[str, str]:
    manifest = root / MANIFEST_NAME
    entries: dict[str, str] = {}
    try:
        payload = (
            snapshots[MANIFEST_NAME]
            if snapshots is not None
            else read_regular_bytes(manifest, "metallicity-audit manifest")
        )
        lines = payload.decode("utf-8").splitlines()
    except (KeyError, UnicodeError) as exc:
        fail(f"cannot read metallicity-audit manifest: {exc}")
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", line)
        if match is None:
            fail(f"invalid manifest line {line_number}: {line!r}")
        digest, name = match.groups()
        if not is_portable_safe_leaf(name):
            fail(f"unsafe manifest filename at line {line_number}: {name!r}")
        if name in entries:
            fail(f"duplicate manifest entry: {name!r}")
        entries[name] = digest
    if set(entries) != MANIFEST_TARGETS:
        fail(
            "manifest does not contain the exact four payload files: "
            f"expected={sorted(MANIFEST_TARGETS)!r}, found={sorted(entries)!r}"
        )
    for name, expected in entries.items():
        path = root / name
        payload = (
            snapshots[name]
            if snapshots is not None
            else read_regular_bytes(path, f"manifest payload {name}")
        )
        observed = hashlib.sha256(payload).hexdigest()
        if observed != expected:
            fail(f"manifest SHA-256 mismatch for {name}: {observed} != {expected}")
    return entries


def validate_runtime_policy(path: Path, payload: bytes | None = None) -> dict[str, Any]:
    runtime = require_exact_keys(
        load_json_bytes(
            payload
            if payload is not None
            else read_regular_bytes(path, "numerical-runtime policy"),
            "numerical-runtime policy",
        ),
        EXPECTED_RUNTIME_KEYS,
        "numerical-runtime policy",
    )
    if (
        isinstance(runtime["schema_version"], bool)
        or runtime["schema_version"] != 1
        or runtime["status"] != "PASS"
    ):
        fail("numerical-runtime policy is not schema-1 PASS")
    if runtime["numpy_version"] != "1.23.5":
        fail("numerical-runtime policy does not pin NumPy 1.23.5")
    if runtime["environment"] != EXPECTED_NUMERICAL_ENV:
        fail("numerical-runtime environment differs from the release policy")
    selected_features = require_exact_keys(
        runtime["selected_cpu_features"],
        EXPECTED_SELECTED_CPU_FEATURE_KEYS,
        "numerical-runtime selected CPU features",
    )
    if any(type(value) is not bool for value in selected_features.values()):
        fail("numerical-runtime CPU feature states must be JSON booleans")
    for name, expected in EXPECTED_REQUIRED_CPU_FEATURE_STATES.items():
        if selected_features[name] is not expected:
            fail("numerical-runtime CPU feature state differs from the release policy")
    for key in ("python", "python_executable", "platform", "machine"):
        if not isinstance(runtime[key], str) or not runtime[key]:
            fail(f"numerical-runtime field {key!r} is empty or invalid")
    for key in ("numpy_cpu_baseline", "numpy_cpu_dispatch_build"):
        if not isinstance(runtime[key], list) or not all(
            isinstance(item, str) and item for item in runtime[key]
        ):
            fail(f"numerical-runtime field {key!r} is invalid")
    return runtime


def validate_solar_csv(
    path: Path, payload: bytes | None = None
) -> dict[str, float | int]:
    try:
        content = (
            payload
            if payload is not None
            else read_regular_bytes(path, "native solar TAMS node table")
        ).decode("utf-8")
        reader = csv.DictReader(io.StringIO(content, newline=""))
        if reader.fieldnames != EXPECTED_SOLAR_COLUMNS:
            fail(
                "native solar TAMS header changed: "
                f"{reader.fieldnames!r} != {EXPECTED_SOLAR_COLUMNS!r}"
            )
        rows = list(reader)
    except (UnicodeError, csv.Error) as exc:
        fail(f"cannot read native solar TAMS node table: {exc}")
    if len(rows) != 9:
        fail(f"native solar TAMS table must contain exactly 9 rows, found {len(rows)}")

    parsed: list[dict[str, Any]] = []
    filenames: set[str] = set()
    for row_number, row in enumerate(rows, 2):
        if set(row) != set(EXPECTED_SOLAR_COLUMNS) or any(
            value is None or value == "" for value in row.values()
        ):
            fail(f"invalid native solar TAMS row {row_number}")
        numeric: dict[str, float] = {}
        for key in ("Z", "Y", "MH", "Teff_K", "R_Rsun", "mass", "age_Gyr"):
            try:
                value = float(row[key])
            except (TypeError, ValueError) as exc:
                fail(f"invalid {key} at native solar TAMS row {row_number}: {exc}")
            if not math.isfinite(value):
                fail(f"non-finite {key} at native solar TAMS row {row_number}")
            numeric[key] = value
        if not math.isclose(numeric["Z"], 0.017, rel_tol=0.0, abs_tol=1.0e-12):
            fail(f"native solar TAMS row {row_number} is not Z=0.017")
        if not math.isclose(numeric["Y"], 0.279, rel_tol=0.0, abs_tol=1.0e-12):
            fail(f"native solar TAMS row {row_number} is not Y=0.279")
        if not (5150.0 <= numeric["Teff_K"] <= 6060.3):
            fail(f"native solar TAMS row {row_number} is outside the validation Teff range")
        if not (0.0 < numeric["R_Rsun"] < 10.0):
            fail(f"native solar TAMS row {row_number} has an invalid radius")
        if not (0.0 < numeric["mass"] <= 2.0):
            fail(f"native solar TAMS row {row_number} has an invalid mass")
        if not (0.0 < numeric["age_Gyr"] < 30.0):
            fail(f"native solar TAMS row {row_number} has an invalid age")
        filename = row["file"]
        if (
            not is_portable_safe_leaf(filename)
            or not filename.upper().endswith(".DAT")
        ):
            fail(f"unsafe native solar TAMS source filename at row {row_number}")
        if filename in filenames:
            fail(f"duplicate native solar TAMS source filename: {filename}")
        filenames.add(filename)
        parsed.append({**numeric, "file": filename})

    temperatures = [row["Teff_K"] for row in parsed]
    radii = [row["R_Rsun"] for row in parsed]
    if any(right <= left for left, right in zip(temperatures, temperatures[1:])):
        fail("native solar TAMS temperatures are not strictly increasing")
    if any(right <= left for left, right in zip(radii, radii[1:])):
        fail("native solar TAMS radii are not strictly increasing")
    if temperatures[0] > 5300.0 or not any(
        5300.0 <= value < REFERENCE_TEFF[0] for value in temperatures
    ):
        fail("native solar TAMS nodes do not bracket the 5300 K lower boundary")

    for row_number, (observed, expected) in enumerate(
        zip(parsed, EXPECTED_SOLAR_NODES), 2
    ):
        expected_values = dict(zip(EXPECTED_SOLAR_COLUMNS, expected))
        if observed["file"] != expected_values["file"]:
            fail(f"native solar TAMS locked source filename mismatch at row {row_number}")
        for key, tolerance in SOLAR_NODE_ABS_TOLERANCES.items():
            if not math.isclose(
                observed[key],
                float(expected_values[key]),
                rel_tol=0.0,
                abs_tol=tolerance,
            ):
                fail(f"native solar TAMS locked {key} mismatch at row {row_number}")

    reference_rows = [
        row
        for row in parsed
        if row["age_Gyr"] < 20.0 and row["Teff_K"] >= REFERENCE_TEFF[0] - 0.01
    ]
    if len(reference_rows) != 7:
        fail(
            "native solar TAMS table must contain exactly seven age<20 Gyr "
            f"reference nodes, found {len(reference_rows)}"
        )
    maximum_temperature_difference = max(
        abs(row["Teff_K"] - expected)
        for row, expected in zip(reference_rows, REFERENCE_TEFF)
    )
    maximum_relative_radius_difference = max(
        abs(row["R_Rsun"] - expected) / expected
        for row, expected in zip(reference_rows, REFERENCE_RADIUS)
    )
    if maximum_temperature_difference > 0.01:
        fail("native solar TAMS temperatures do not reproduce the reference")
    if maximum_relative_radius_difference > 1.0e-4:
        fail("native solar TAMS radii do not reproduce the reference")
    return {
        "node_count": len(parsed),
        "reference_validation_node_count": len(reference_rows),
        "max_abs_temperature_difference_K": maximum_temperature_difference,
        "max_relative_radius_difference": maximum_relative_radius_difference,
    }


def validate_report(
    path: Path,
    solar_path: Path,
    solar_metrics: dict[str, float | int],
    locks: dict[str, dict[str, Any]],
    report_payload: bytes | None = None,
    solar_payload: bytes | None = None,
) -> dict[str, Any]:
    report = require_exact_keys(
        load_json_bytes(
            report_payload
            if report_payload is not None
            else read_regular_bytes(path, "metallicity-TAMS audit report"),
            "metallicity-TAMS audit report",
        ),
        EXPECTED_REPORT_KEYS,
        "metallicity-TAMS audit report",
    )
    if isinstance(report["schema_version"], bool) or report["schema_version"] != 3:
        fail("metallicity-TAMS audit report is not schema version 3")
    if report["experiment"] != "differential_metallicity_PARSEC_TAMS_coverage_audit":
        fail("metallicity-TAMS experiment identifier changed")
    if report["status"] != EXPECTED_STATUS:
        fail(f"metallicity-TAMS status is not {EXPECTED_STATUS}")
    if report["decision"] != EXPECTED_DECISION or report["reason"] != EXPECTED_REASON:
        fail("metallicity-TAMS negative decision or reason changed")
    _, expected_required_lock_ids = validate_parent_input(report["parent_input"])
    if report["low_mass_filter"] != EXPECTED_LOW_MASS_FILTER:
        fail("metallicity-TAMS low-mass filter changed")
    correction_policy = require_exact_keys(
        report["correction_policy"],
        set(EXPECTED_CORRECTION_POLICY),
        "metallicity-TAMS correction policy",
    )
    if (
        correction_policy["applied"] is not False
        or correction_policy["publishable"] is not False
        or correction_policy["emitted_files"] != []
    ):
        fail("metallicity-TAMS correction policy is not exactly false/false/empty")

    failures = report["coverage_failures"]
    if not isinstance(failures, list) or not failures:
        fail("metallicity-TAMS coverage failures must be a non-empty list")
    seen_locks: set[str] = set()
    seen_metallicities: set[float] = set()
    for index, raw in enumerate(failures):
        failure = require_exact_keys(
            raw, EXPECTED_FAILURE_KEYS, f"coverage failure {index}"
        )
        lock_id = failure["archive_lock_id"]
        if not isinstance(lock_id, str) or lock_id not in PARSEC_LOCK_METALLICITIES:
            fail(f"coverage failure {index} does not reference a recognized PARSEC track lock")
        if lock_id not in locks:
            fail(f"coverage failure {index} references a missing PARSEC data lock")
        if lock_id in seen_locks:
            fail(f"duplicate coverage-failure lock: {lock_id}")
        seen_locks.add(lock_id)
        record = locks[lock_id]
        if record.get("distribution_role") != "fetch-only":
            fail(f"coverage failure {index} does not reference a fetch-only lock")
        archive = failure["archive"]
        if (
            not is_portable_safe_leaf(archive)
            or archive != record.get("filename")
        ):
            fail(f"coverage failure {index} archive does not match its data lock")
        size = failure["archive_size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int):
            fail(f"coverage failure {index} archive size is not an integer")
        if size != record.get("expected_size_bytes"):
            fail(f"coverage failure {index} archive size differs from its data lock")
        digest = failure["archive_sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"coverage failure {index} has an invalid archive SHA-256")
        if digest != record.get("expected_sha256"):
            fail(f"coverage failure {index} archive SHA-256 differs from its data lock")
        metallicity = require_finite_number(failure["Z"], f"coverage failure {index} Z")
        if metallicity <= 0.0 or metallicity in seen_metallicities:
            fail(f"coverage failure {index} has invalid or duplicate metallicity")
        if not math.isclose(
            metallicity,
            PARSEC_LOCK_METALLICITIES[lock_id],
            rel_tol=0.0,
            abs_tol=1.0e-12,
        ):
            fail(f"coverage failure {index} metallicity does not match its PARSEC lock")
        seen_metallicities.add(metallicity)
        validate_failure_error(failure["error"], metallicity, index)

    evidence = require_exact_keys(
        report["coverage_evidence"],
        EXPECTED_COVERAGE_EVIDENCE_KEYS,
        "coverage evidence",
    )
    evidence_lists: dict[str, list[str]] = {}
    for key in EXPECTED_COVERAGE_EVIDENCE_KEYS:
        value = evidence[key]
        if (
            not isinstance(value, list)
            or not all(isinstance(item, str) for item in value)
            or len(value) != len(set(value))
        ):
            fail(f"coverage evidence {key} must be a unique string list")
        if any(item not in PARSEC_LOCK_METALLICITIES for item in value):
            fail(f"coverage evidence {key} contains an unknown PARSEC lock")
        evidence_lists[key] = value
    required_ids = evidence_lists["required_lock_ids"]
    successful_ids = evidence_lists["successful_lock_ids"]
    failed_ids = evidence_lists["failed_lock_ids"]
    if required_ids != expected_required_lock_ids:
        fail("coverage required locks do not match the bound parent FeH domain")
    if set(successful_ids).intersection(failed_ids):
        fail("coverage successful and failed lock sets overlap")
    if set(successful_ids).union(failed_ids) != set(required_ids):
        fail("coverage evidence is not an exhaustive required-lock partition")
    if successful_ids != [item for item in required_ids if item not in set(failed_ids)]:
        fail("coverage successful locks are not in canonical required-lock order")
    failure_ids = [item["archive_lock_id"] for item in failures]
    if failed_ids != failure_ids or failed_ids != [item for item in required_ids if item in set(failure_ids)]:
        fail("coverage failed locks do not exactly match ordered failure records")
    if "parsec_tracks_z0017" not in successful_ids:
        fail("solar PARSEC lock must be successful coverage evidence")
    for lock_id in required_ids:
        record = locks.get(lock_id)
        if not isinstance(record, dict) or record.get("distribution_role") != "fetch-only":
            fail(f"required coverage lock is missing or is not fetch-only: {lock_id}")

    solar = require_exact_keys(
        report["native_solar_reference"],
        EXPECTED_SOLAR_REFERENCE_KEYS,
        "native solar reference",
    )
    if solar["status"] != "PASS":
        fail("native solar reference did not pass")
    if solar["role"] != "validation_only_not_a_metallicity_correction":
        fail("native solar reference role changed")
    metallicity = require_finite_number(solar["metallicity_Z"], "native solar Z")
    if not math.isclose(metallicity, 0.017, rel_tol=0.0, abs_tol=1.0e-12):
        fail("native solar reference is not Z=0.017")
    if solar["points_file"] != SOLAR_POINTS_NAME:
        fail("native solar reference points filename changed")
    observed_points_hash = hashlib.sha256(
        solar_payload
        if solar_payload is not None
        else read_regular_bytes(solar_path, "native solar TAMS node table")
    ).hexdigest()
    if (
        not isinstance(solar["points_sha256"], str)
        or not SHA256_RE.fullmatch(solar["points_sha256"])
        or solar["points_sha256"] != observed_points_hash
    ):
        fail("native solar reference points SHA-256 mismatch")
    for key in ("node_count", "reference_validation_node_count"):
        value = solar[key]
        if isinstance(value, bool) or not isinstance(value, int):
            fail(f"native solar reference {key} is not an integer")
        if value != solar_metrics[key]:
            fail(f"native solar reference {key} mismatch")
    for key in (
        "max_abs_temperature_difference_K",
        "max_relative_radius_difference",
    ):
        observed = require_finite_number(solar[key], f"native solar reference {key}")
        expected = float(solar_metrics[key])
        if not math.isclose(observed, expected, rel_tol=0.0, abs_tol=1.0e-12):
            fail(f"native solar reference {key} mismatch")

    solar_lock_id = solar["archive_lock_id"]
    if solar_lock_id != "parsec_tracks_z0017" or solar_lock_id not in locks:
        fail("native solar reference does not use the locked Z=0.017 archive")
    solar_lock = locks[solar_lock_id]
    if solar_lock.get("distribution_role") != "fetch-only":
        fail("native solar reference does not use a fetch-only archive lock")
    if not is_portable_safe_leaf(solar["archive_filename"]):
        fail("native solar reference archive filename is unsafe")
    if not is_portable_safe_leaf(solar_lock.get("filename")):
        fail("native solar reference data-lock filename is unsafe")
    expected_lock_values = {
        "archive_filename": solar_lock.get("filename"),
        "archive_size_bytes": solar_lock.get("expected_size_bytes"),
        "archive_sha256": solar_lock.get("expected_sha256"),
    }
    for key, expected in expected_lock_values.items():
        if solar[key] != expected:
            fail(f"native solar reference {key} differs from its data lock")
    if (
        isinstance(solar["archive_size_bytes"], bool)
        or not isinstance(solar["archive_size_bytes"], int)
    ):
        fail("native solar reference archive size is not an integer")
    if (
        not isinstance(solar["archive_sha256"], str)
        or not SHA256_RE.fullmatch(solar["archive_sha256"])
    ):
        fail("native solar reference archive SHA-256 is invalid")
    return report


def verify_artifact(
    artifact_root: Path,
    data_locks_path: Path = DEFAULT_DATA_LOCKS,
) -> dict[str, Any]:
    root = artifact_root.resolve()
    if artifact_root.is_symlink() or not root.is_dir():
        fail(f"artifact root is missing or unsafe: {artifact_root}")

    for name in FORBIDDEN_CORRECTION_FILES:
        path = root / name
        if path.is_symlink() or path.exists():
            fail(f"forbidden correction artifact is present: {name}")

    actual_entries = {path.name for path in root.iterdir()}
    if actual_entries != EXPECTED_FILES:
        fail(
            "metallicity-audit artifact does not have the exact five-file set: "
            f"expected={sorted(EXPECTED_FILES)!r}, found={sorted(actual_entries)!r}"
        )
    for name in EXPECTED_FILES:
        require_regular_file(root / name, f"metallicity-audit file {name}")

    snapshots = {
        name: read_regular_bytes(root / name, f"metallicity-audit file {name}")
        for name in EXPECTED_FILES
    }
    if {path.name for path in root.iterdir()} != EXPECTED_FILES:
        fail("metallicity-audit root changed while taking the verification snapshot")

    validate_manifest(root, snapshots)
    validate_runtime_policy(root / RUNTIME_NAME, snapshots[RUNTIME_NAME])
    try:
        provenance = snapshots[PROVENANCE_NAME].decode("utf-8")
    except UnicodeError as exc:
        fail(f"cannot read metallicity-audit provenance: {exc}")
    source_provenance = read_regular_bytes(
        SOURCE_PROVENANCE, "reviewable metallicity-audit provenance source"
    )
    if snapshots[PROVENANCE_NAME] != source_provenance:
        fail("metallicity-audit provenance differs from its reviewable source")
    for required_text in (
        EXPECTED_STATUS,
        "No metallicity-dependent TAMS correction",
        "validation-only solar",
        "binds the exact JJ parent CSV",
        "disjoint exhaustive partition",
        "All nine validation-only solar nodes",
    ):
        if required_text not in provenance:
            fail(f"metallicity-audit provenance lacks required text: {required_text!r}")

    solar_metrics = validate_solar_csv(
        root / SOLAR_POINTS_NAME, snapshots[SOLAR_POINTS_NAME]
    )
    locks = load_data_locks(data_locks_path)
    report = validate_report(
        root / REPORT_NAME,
        root / SOLAR_POINTS_NAME,
        solar_metrics,
        locks,
        snapshots[REPORT_NAME],
        snapshots[SOLAR_POINTS_NAME],
    )
    for name, snapshot in snapshots.items():
        current = read_regular_bytes(
            root / name, f"post-verification metallicity-audit file {name}"
        )
        if current != snapshot:
            fail(f"metallicity-audit file changed during verification: {name}")
    if {path.name for path in root.iterdir()} != EXPECTED_FILES:
        fail("metallicity-audit root changed during verification")
    return report


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--artifact-root", required=True, type=Path)
    argument_parser.add_argument(
        "--data-locks", type=Path, default=DEFAULT_DATA_LOCKS
    )
    return argument_parser


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        report = verify_artifact(args.artifact_root, args.data_locks)
    except AuditError as exc:
        raise SystemExit(f"METALLICITY TAMS AUDIT FAIL: {exc}") from exc
    print(
        "PASS metallicity-TAMS negative validation "
        f"({report['status']}; correction applied=false)"
    )


if __name__ == "__main__":
    main()
