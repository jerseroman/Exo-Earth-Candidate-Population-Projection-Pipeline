#!/usr/bin/env python3
"""Weighted host-selector and native-PARSEC TAMS audit for manuscript v4."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import math
import os
import re
import stat
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd


LOW_T_NATIVE_K = 5390.13944
CANONICAL_N_STAR = 263061992.36674237
LEGACY_N_STAR = 196679892.57673854
EXPECTED_RADIAL_NODES = np.array([7.0, 7.5, 8.0, 8.5, 9.0])
EXPECTED_HOST_STATUS = "PASS_WITH_METALLICITY_CORRECTION_NOT_PUBLISHABLE"
RETRACTED_METALLICITY_ANCHOR_NAME = "metallicity_tams_anchor_points.csv"
EXPECTED_POSTERIOR_ROW_COUNT = 204_800
EXPECTED_OUTER_REALIZATIONS = 400
EXPECTED_SAMPLES_PER_REALIZATION = 512
EXPECTED_SELECTOR_LABELS = {
    "canonical": "canonical PARSEC-TAMS selector",
    "legacy": "legacy 4.3 < logg < 7 selector",
}
EXPECTED_SELECTOR_HOST_COUNTS = {
    "canonical": CANONICAL_N_STAR,
    "legacy": LEGACY_N_STAR,
}
EXPECTED_SELECTOR_TEMPERATURE_COUNTS = {"canonical": 539, "legacy": 536}
GALACTIC_QUANTITIES = (
    "mean_f_HZ",
    "mean_f_EE",
    "Lambda_HZ",
    "Lambda_EE",
    "Lambda_EE_over_Lambda_HZ",
)
QUANTILES = ("q2.5", "q16", "q50", "q84", "q97.5")
METALLICITY_REPORT_NAME = "metallicity_tams_differential_sensitivity.json"
NATIVE_SOLAR_POINTS_NAME = "native_solar_tams_nodes.csv"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PARENT_COLUMNS = (
    "R_kpc",
    "component",
    "age_Gyr",
    "FeH",
    "Mini",
    "Mf",
    "logL",
    "logT",
    "Teff_K",
    "logg",
    "N_surface_pc-2",
    "Rstar_g_Rsun",
    "Rstar_L_Rsun",
    "R_TAMS_Rsun",
    "A_logg",
    "B_TAMS_MS",
    "f_HZ",
    "f_earth10",
)
HOST_COLUMNS = (
    "R_kpc",
    "component",
    "Teff_K",
    "age_Gyr",
    "logg",
    "N_surface_pc-2",
)
COLLAPSED_COLUMNS = ("Teff_K", "integrated_host_weight")
POSTERIOR_COLUMNS = ("branch", "global_trial", "F0", "alpha", "beta", "gamma")
PROPAGATED_DRAW_COLUMNS = (
    *POSTERIOR_COLUMNS,
    "N_star",
    *GALACTIC_QUANTITIES,
)
EXPECTED_PARENT_RADIAL_NODES = np.arange(4.0, 14.0 + 0.25, 0.5)
GALACTIC_ARTIFACT_STEMS = {
    "collapsed": "collapsed_host_temperature_measure.csv",
    "draws": "galactic_posterior_draws_{branch}.csv.gz",
    "summary": "galactic_posterior_summary_{branch}.json",
    "manifest": "SHA256SUMS_galactic_{branch}.txt",
}
OCCURRENCE_ANCHOR_TEMPERATURES_K = np.array([5300.0, 5780.0, 6000.0])
OCCURRENCE_F_HZ_ANCHORS = np.array(
    [0.36179926070124835, 0.41752709358639872, 0.4449005443811479]
)
OCCURRENCE_F_EARTH10_ANCHORS = np.array(
    [0.00922758851250703, 0.014339858806826793, 0.015348122667146951]
)
TAMS_CONVERGENCE_MANIFEST_NAME = "SHA256SUMS_tams_radial_convergence.txt"
TAMS_CONVERGENCE_REPORT_NAME = "tams_radial_convergence_results.json"
TAMS_CONVERGENCE_TABLE_NAME = "tams_radial_convergence_table.csv"
TAMS_CONVERGENCE_DRS = (1.0, 0.5, 0.25)
TAMS_TUTORIAL_SFR_SHA256 = (
    "56d25b9ea61f454630a222ce6a6414bd1eaeb13bd165c25e9559ebe5c6b5039b"
)
HOST_CONTRACT_NAME = "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
RADIAL_SSP_CONTRACT_NAME = "RADIAL_SSP_CONTRACT_v4_0_4.json"
LOCAL_RUN_CONTRACT_NAME = "LOCAL_RUN_ATTESTATION_CONTRACT_v4_0_4.json"
HOST_CONTRACT_MANIFEST_NAME = "SHA256SUMS_padova.txt"
HOST_CONTRACT_FILES = (
    "jj_g_hosts_radial_padova.csv",
    "jj_g_hosts_R_T_padova.csv",
    "jj_g_hosts_R_T_age_padova.csv",
    "jj_g_hosts_raw_eligible_padova.csv",
    "jj_g_hosts_summary_padova.json",
)


def _tams_dr_tag(dr: float) -> str:
    return str(dr).replace(".", "p")


def tams_convergence_target_names() -> tuple[str, ...]:
    names = [
        "tams_radial_convergence.py",
        "compare_convergence.py",
        "NUMERICAL_RUNTIME_POLICY.json",
    ]
    for dr in TAMS_CONVERGENCE_DRS:
        tag = _tams_dr_tag(dr)
        names.extend(
            [
                f"parameters_original_dr{tag}.txt",
                f"parameters_runtime_dr{tag}.txt",
                f"sfrd_peaks_parameters_dr{tag}.txt",
                f"tams_radial_dr{tag}.csv",
                f"tams_result_dr{tag}.json",
            ]
        )
    names.extend((TAMS_CONVERGENCE_TABLE_NAME, TAMS_CONVERGENCE_REPORT_NAME))
    return tuple(names)


def _load_python_module_from_snapshot(
    path: Path, *, module_name: str, label: str
) -> tuple[Any, FileSnapshot]:
    """Execute one exact, pre-read local source file without import-cache trust."""

    snapshot = read_file_snapshot(path, label)
    module = types.ModuleType(module_name)
    module.__file__ = str(snapshot.path)
    module.__package__ = ""
    missing = object()
    previous = sys.modules.get(module_name, missing)
    sys.modules[module_name] = module
    try:
        try:
            code = compile(snapshot.data, str(snapshot.path), "exec")
            exec(code, module.__dict__)
        except Exception as error:
            raise RuntimeError(
                f"{label} could not be loaded from its captured bytes"
            ) from error
        if Path(str(module.__file__)).resolve() != snapshot.path.resolve():
            raise RuntimeError(f"{label} changed its source identity while loading")
        return module, snapshot
    finally:
        if previous is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


def independent_occurrence_fractions(
    teff: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Independently reconstruct the fixed Bryson/Kopparapu plug-in fractions."""

    temperature = np.asarray(teff, dtype=float)
    if temperature.ndim != 1 or not np.isfinite(temperature).all():
        raise RuntimeError("Occurrence temperatures must be a finite vector")

    f0 = 1.107
    alpha = -1.082
    beta = -0.839
    gamma = -2.671

    def power_integral(lower: float, upper: float, exponent: float) -> float:
        return (upper ** (exponent + 1.0) - lower ** (exponent + 1.0)) / (
            exponent + 1.0
        )

    radius_fit = power_integral(0.5, 2.5, alpha)
    instellation_fit = power_integral(0.2, 2.2, beta)
    q1 = gamma + 3.16
    q2 = gamma + 4.49
    geometric_mean = (
        10.0 ** (-11.839) * power_integral(3900.0, 5117.0, q1)
        + 10.0 ** (-16.769) * power_integral(5117.0, 6300.0, q2)
    ) / (6300.0 - 3900.0)
    normalization = 1.0 / (radius_fit * instellation_fit * geometric_mean)
    prefactor = (
        f0
        * normalization
        * temperature**gamma
        * np.where(
            temperature <= 5117.0,
            10.0 ** (-11.839) * temperature**3.16,
            10.0 ** (-16.769) * temperature**4.49,
        )
    )
    offset = temperature - 5780.0
    runaway = sum(
        coefficient * offset**power
        for power, coefficient in enumerate(
            (1.107, 1.332e-4, 1.58e-8, -8.308e-12, -1.931e-15)
        )
    )
    maximum = sum(
        coefficient * offset**power
        for power, coefficient in enumerate(
            (0.356, 6.171e-5, 1.698e-9, -3.198e-12, -5.575e-16)
        )
    )
    hz_instellation = (runaway ** (beta + 1.0) - maximum ** (beta + 1.0)) / (
        beta + 1.0
    )
    earth_lower = np.maximum(0.9, maximum)
    earth_upper = np.minimum(1.1, runaway)
    earth_instellation = np.where(
        earth_upper > earth_lower,
        (
            earth_upper ** (beta + 1.0)
            - earth_lower ** (beta + 1.0)
        )
        / (beta + 1.0),
        0.0,
    )
    return (
        prefactor * power_integral(0.5, 1.5, alpha) * hz_instellation,
        prefactor * power_integral(0.9, 1.1, alpha) * earth_instellation,
    )


@dataclass(frozen=True)
class FileSnapshot:
    """Bytes and identity captured by one stable read of a regular file."""

    path: Path
    data: bytes
    sha256: str
    size_bytes: int


def read_file_snapshot(path: Path, label: str) -> FileSnapshot:
    """Read once, reject links, and fail if file identity changes while read."""

    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"{label} cannot be inspected: {candidate}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_file_attributes", 0) & 0x400)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise RuntimeError(f"{label} is not a regular non-symlink file: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise RuntimeError(f"{label} cannot be opened safely: {candidate}") from error
    with os.fdopen(descriptor, "rb") as stream:
        opened_before = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened_before.st_mode):
            raise RuntimeError(f"{label} opened object is not a regular file: {candidate}")
        data = stream.read()
        opened_after = os.fstat(stream.fileno())
    try:
        after = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"{label} disappeared while it was being read: {candidate}") from error
    identity_before = (
        opened_before.st_dev,
        opened_before.st_ino,
        opened_before.st_size,
        opened_before.st_mtime_ns,
    )
    identity_after = (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    )
    path_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    path_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity_before != identity_after
        or identity_after != path_after
        or path_before != path_after
        or stat.S_ISLNK(after.st_mode)
        or bool(getattr(after, "st_file_attributes", 0) & 0x400)
        or not stat.S_ISREG(after.st_mode)
    ):
        raise RuntimeError(f"{label} changed while it was being read: {candidate}")
    if len(data) != opened_after.st_size:
        raise RuntimeError(f"{label} size changed while it was being read: {candidate}")
    return FileSnapshot(
        path=candidate.resolve(),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def recheck_file_snapshot(snapshot: FileSnapshot, label: str) -> None:
    """Fail if a previously captured file was replaced after validation."""

    current = read_file_snapshot(snapshot.path, label)
    if (
        current.data != snapshot.data
        or current.sha256 != snapshot.sha256
        or current.size_bytes != snapshot.size_bytes
    ):
        raise RuntimeError(f"{label} changed after its validated snapshot")


def sha256(path: Path) -> str:
    return read_file_snapshot(path, "SHA-256 input").sha256


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise RuntimeError(f"Non-finite JSON number is forbidden: {value}")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise RuntimeError(f"Non-finite JSON number is forbidden: {value}")
    return number


def load_json_value_bytes(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} is not valid UTF-8") from error
    return json.loads(
        text,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_nonfinite_json,
        parse_float=_finite_json_float,
    )


def load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    value = load_json_value_bytes(data, label)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def load_json_snapshot(path: Path, label: str) -> tuple[dict[str, Any], FileSnapshot]:
    snapshot = read_file_snapshot(path, label)
    return load_json_bytes(snapshot.data, label), snapshot


def load_json(path: Path) -> dict[str, Any]:
    value, _ = load_json_snapshot(path, f"JSON input {path}")
    return value


def read_csv_bytes(
    data: bytes, label: str, *, compressed: bool = False, **kwargs: Any
) -> pd.DataFrame:
    try:
        kwargs.setdefault("float_precision", "round_trip")
        return pd.read_csv(
            io.BytesIO(data), compression="gzip" if compressed else None, **kwargs
        )
    except Exception as error:
        raise RuntimeError(f"Cannot parse {label} as CSV: {error}") from error


def read_csv_snapshot(path: Path, label: str, **kwargs: Any) -> tuple[pd.DataFrame, FileSnapshot]:
    snapshot = read_file_snapshot(path, label)
    frame = read_csv_bytes(
        snapshot.data,
        label,
        compressed=snapshot.path.name.endswith(".gz"),
        **kwargs,
    )
    return frame, snapshot


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _portable_basename(value: Any, label: str) -> str:
    """Return a filename using both POSIX and Windows separator rules."""

    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or value.endswith(("/", "\\"))
    ):
        raise RuntimeError(f"{label} is not a safe file path")
    basename = re.split(r"[\\/]", value)[-1]
    if basename in {"", ".", ".."} or ":" in basename:
        raise RuntimeError(f"{label} is not a safe file path")
    return basename


def _portable_leaf_name(value: Any, label: str) -> str:
    basename = _portable_basename(value, label)
    if basename != value:
        raise RuntimeError(f"{label} must be a portable leaf filename")
    return basename


def release_safe_evidence(value: Any) -> Any:
    """Remove machine-local locations while retaining filenames and digests."""

    if isinstance(value, list):
        return [release_safe_evidence(item) for item in value]
    if not isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"artifact_root", "checkout"}:
            continue
        if key == "path" or (key.endswith("_path") and key != "workflow_path"):
            replacement = "filename" if key == "path" else f"{key[:-5]}_filename"
            # Evidence may have been produced on a different operating system.
            # ``Path`` only recognizes the separators of the verifier host, so
            # a Windows absolute path would otherwise survive unchanged on
            # Linux and disclose a private directory in the public artifact.
            try:
                basename = _portable_basename(item, f"Release evidence {key}")
            except RuntimeError as error:
                raise RuntimeError(
                    f"Release evidence contains malformed {key}"
                ) from error
            if replacement in result and result[replacement] != basename:
                raise RuntimeError(f"Release evidence has conflicting {replacement}")
            result[replacement] = basename
            continue
        result[key] = release_safe_evidence(item)
    return result


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise RuntimeError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _require_finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} must be a JSON number")
    number = float(value)
    if not math.isfinite(number):
        raise RuntimeError(f"{label} must be finite")
    return number


def _require_finite_nonnegative(value: Any, label: str) -> float:
    number = _require_finite_number(value, label)
    if number < 0.0:
        raise RuntimeError(f"{label} must be non-negative")
    return number


def _require_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"{label} must be a JSON integer")
    return value


def _require_positive_integer(value: Any, label: str) -> int:
    number = _require_integer(value, label)
    if number <= 0:
        raise RuntimeError(f"{label} must be positive")
    return number


def _require_exact_bool(value: Any, expected: bool, label: str) -> bool:
    if value is not expected:
        raise RuntimeError(f"{label} must be exactly {expected}")
    return expected


def _require_close(
    value: Any,
    expected: float,
    label: str,
    *,
    rel_tol: float = 1.0e-12,
    abs_tol: float = 1.0e-12,
) -> float:
    number = _require_finite_number(value, label)
    if not math.isclose(number, expected, rel_tol=rel_tol, abs_tol=abs_tol):
        raise RuntimeError(f"{label} mismatch: {number} versus {expected}")
    return number


def _validate_ordered_quantiles(
    summary: dict[str, Any], label: str
) -> dict[str, float]:
    if set(summary) != set(QUANTILES):
        raise RuntimeError(f"{label} does not contain the exact quantile set")
    for name in QUANTILES:
        if isinstance(summary[name], bool) or not isinstance(summary[name], (int, float)):
            raise RuntimeError(f"{label}:{name} must be a JSON number")
    values = np.asarray([summary[name] for name in QUANTILES], dtype=float)
    if not np.isfinite(values).all() or np.any(np.diff(values) < 0.0):
        raise RuntimeError(f"{label} quantiles are non-finite or unordered")
    return {name: float(summary[name]) for name in QUANTILES}


def _q50_mcse_fraction(
    quantiles: dict[str, float], mcse: dict[str, Any], *, outer: bool
) -> float:
    width = float(quantiles["q84"] - quantiles["q16"])
    if not math.isfinite(width) or width <= 0.0:
        raise RuntimeError("Propagation q16--q84 width must be positive and finite")
    if outer:
        q50 = _require_mapping(mcse.get("q50"), "outer q50 MCSE")
        error = _require_finite_nonnegative(
            q50.get("standard_error"), "outer q50 standard error"
        )
    else:
        error = _require_finite_nonnegative(mcse.get("q50"), "inner q50 MCSE")
    return error / width


def _snapshot_exact_manifest_root(
    artifact_root: Path,
    *,
    manifest_name: str,
    target_names: tuple[str, ...],
    label: str,
) -> tuple[dict[str, FileSnapshot], FileSnapshot]:
    root_arg = Path(artifact_root)
    if root_arg.is_symlink():
        raise RuntimeError(f"{label} root must not be a symlink")
    root = root_arg.resolve()
    if not root.is_dir():
        raise RuntimeError(f"{label} root is not a directory: {root}")
    expected_names = {*target_names, manifest_name}
    before_names = {path.name for path in root.iterdir()}
    if before_names != expected_names:
        raise RuntimeError(
            f"{label} root entry set mismatch: {sorted(before_names)} versus "
            f"{sorted(expected_names)}"
        )
    manifest = read_file_snapshot(root / manifest_name, f"{label} manifest")
    try:
        lines = manifest.data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} manifest is not valid UTF-8") from error
    if len(lines) != len(target_names):
        raise RuntimeError(f"{label} manifest does not have the exact entry count")
    declared: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        fields = line.split()
        if len(fields) != 2 or not SHA256_PATTERN.fullmatch(fields[0]):
            raise RuntimeError(f"Malformed {label} manifest line {line_number}: {line!r}")
        name = fields[1]
        try:
            name = _portable_leaf_name(name, f"{label} manifest entry")
        except RuntimeError as error:
            raise RuntimeError(
                f"Unsafe or duplicate {label} manifest entry: {name!r}"
            ) from error
        if name in seen:
            raise RuntimeError(f"Unsafe or duplicate {label} manifest entry: {name!r}")
        seen.add(name)
        declared.append((name, fields[0]))
    if tuple(name for name, _ in declared) != target_names:
        raise RuntimeError(f"{label} manifest order or exact target set changed")
    snapshots: dict[str, FileSnapshot] = {}
    for name, expected_sha in declared:
        snapshot = read_file_snapshot(root / name, f"{label} target {name}")
        if snapshot.sha256 != expected_sha:
            raise RuntimeError(f"{label} checksum mismatch for {name}")
        snapshots[name] = snapshot
    after_names = {path.name for path in root.iterdir()}
    if after_names != before_names:
        raise RuntimeError(f"{label} root changed while it was being verified")
    return snapshots, manifest


def _validate_realization_layout(
    frame: pd.DataFrame,
    *,
    branch: str,
    label: str,
    required_numeric: set[str],
    expected_columns: tuple[str, ...],
) -> None:
    if tuple(frame.columns) != expected_columns:
        raise RuntimeError(
            f"{label} columns changed: {tuple(frame.columns)!r} versus "
            f"{expected_columns!r}"
        )
    try:
        numeric = frame.loc[:, ["global_trial", *sorted(required_numeric)]].apply(
            pd.to_numeric, errors="raise"
        )
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{label} contains a non-numeric required value") from error
    values = numeric.to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise RuntimeError(f"{label} contains non-finite numerical values")
    trials = numeric["global_trial"].to_numpy(dtype=float)
    if not np.array_equal(trials, trials.astype(np.int64).astype(float)):
        raise RuntimeError(f"{label} global_trial is not exactly integral")
    if set(frame["branch"].astype(str)) != {branch}:
        raise RuntimeError(f"{label} branch column does not equal {branch!r}")
    counts = frame.assign(global_trial=trials.astype(np.int64)).groupby(
        "global_trial", sort=True
    ).size()
    if not np.array_equal(
        counts.index.to_numpy(dtype=np.int64),
        np.arange(EXPECTED_OUTER_REALIZATIONS, dtype=np.int64),
    ):
        raise RuntimeError(f"{label} does not contain exact global_trial 0..399")
    if not np.all(counts.to_numpy(dtype=np.int64) == EXPECTED_SAMPLES_PER_REALIZATION):
        raise RuntimeError(f"{label} does not contain exactly 512 rows per realization")
    if len(frame) != EXPECTED_POSTERIOR_ROW_COUNT:
        raise RuntimeError(f"{label} row count is not exactly 204800")


def validate_posterior_artifact(
    path: Path | FileSnapshot, *, branch: str
) -> tuple[pd.DataFrame, FileSnapshot, dict[str, Any]]:
    if isinstance(path, FileSnapshot):
        snapshot = path
        frame = read_csv_bytes(
            snapshot.data,
            f"{branch} posterior samples",
            compressed=snapshot.path.name.endswith(".gz"),
        )
    else:
        frame, snapshot = read_csv_snapshot(path, f"{branch} posterior samples")
    _validate_realization_layout(
        frame,
        branch=branch,
        label=f"{branch} posterior samples",
        required_numeric={"F0", "alpha", "beta", "gamma"},
        expected_columns=POSTERIOR_COLUMNS,
    )
    return frame, snapshot, {
        "path": str(snapshot.path),
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "row_count": len(frame),
        "outer_realizations": EXPECTED_OUTER_REALIZATIONS,
        "equal_samples_per_outer_realization": EXPECTED_SAMPLES_PER_REALIZATION,
    }


def _validate_host_frame(frame: pd.DataFrame, *, selector: str, label: str) -> pd.DataFrame:
    if tuple(frame.columns) != HOST_COLUMNS:
        raise RuntimeError(
            f"{label} columns changed: {tuple(frame.columns)!r} versus {HOST_COLUMNS!r}"
        )
    working = frame.copy()
    numeric_columns = [name for name in HOST_COLUMNS if name != "component"]
    for column in numeric_columns:
        working[column] = pd.to_numeric(working[column], errors="raise")
    if not np.isfinite(working[numeric_columns].to_numpy(dtype=float)).all():
        raise RuntimeError(f"{label} contains non-finite values")
    if (working["N_surface_pc-2"] < 0.0).any():
        raise RuntimeError(f"{label} contains a negative host weight")
    if set(working.component.astype(str)) != {"thin", "thick"}:
        raise RuntimeError(f"{label} disk-component set changed")
    if not working.Teff_K.between(5300.0, 6000.0).all():
        raise RuntimeError(f"{label} contains temperatures outside 5300--6000 K")
    if not (working.age_Gyr >= 4.57).all():
        raise RuntimeError(f"{label} contains ages below 4.57 Gyr")
    renamed = working.rename(columns={"N_surface_pc-2": "N_surface_pc_2"})
    weighted = attach_radial_weights(renamed)
    collapsed = collapsed_host_measure_frame(weighted, np.ones(len(weighted), dtype=bool))
    if len(collapsed) != EXPECTED_SELECTOR_TEMPERATURE_COUNTS[selector]:
        raise RuntimeError(f"{label} has the wrong exact temperature count")
    total = _require_close(
        collapsed.integrated_host_weight.sum(),
        EXPECTED_SELECTOR_HOST_COUNTS[selector],
        f"{label} integrated host count",
        rel_tol=0.0,
        abs_tol=0.1,
    )
    if total <= 0.0:
        raise RuntimeError(f"{label} host count must be positive")
    return collapsed


def validate_host_artifact(
    path: Path, *, selector: str
) -> tuple[pd.DataFrame, pd.DataFrame, FileSnapshot, dict[str, Any]]:
    frame, snapshot = read_csv_snapshot(path, f"{selector} host rows")
    collapsed = _validate_host_frame(
        frame, selector=selector, label=f"{selector} host rows"
    )
    return frame, collapsed, snapshot, {
        "path": str(snapshot.path),
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "row_count": len(frame),
    }


def validate_fresh_propagation_summary(
    artifact_root: Path,
    *,
    branch: str,
    selector: str,
    posterior_snapshot: FileSnapshot,
    posterior_frame: pd.DataFrame,
    host_snapshot: FileSnapshot,
    host_frame: pd.DataFrame,
    host_collapsed: pd.DataFrame,
    parent_collapsed: pd.DataFrame | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate one exact propagation artifact root against its actual inputs."""

    if branch not in {"constant", "zero"}:
        raise RuntimeError(f"Unsupported propagation branch: {branch}")
    if selector not in EXPECTED_SELECTOR_LABELS:
        raise RuntimeError(f"Unsupported host selector: {selector}")
    collapsed_name = GALACTIC_ARTIFACT_STEMS["collapsed"]
    draws_name = GALACTIC_ARTIFACT_STEMS["draws"].format(branch=branch)
    summary_name = GALACTIC_ARTIFACT_STEMS["summary"].format(branch=branch)
    manifest_name = GALACTIC_ARTIFACT_STEMS["manifest"].format(branch=branch)
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        artifact_root,
        manifest_name=manifest_name,
        target_names=(collapsed_name, draws_name, summary_name),
        label=f"{selector}:{branch} propagation",
    )
    summary_snapshot = snapshots[summary_name]
    data = load_json_bytes(
        summary_snapshot.data, f"{selector}:{branch} propagation summary"
    )
    expected_top_level = {
        "status",
        "branch",
        "source_posterior_samples",
        "host_rows",
        "plugin_validation",
        "posterior_quantiles",
        "posterior_quantile_monte_carlo_error",
        "runtime_seconds",
        "software",
        "included_uncertainty",
        "excluded_systematics",
    }
    if set(data) != expected_top_level:
        raise RuntimeError(f"Unexpected propagation summary schema for {selector}:{branch}")
    label = EXPECTED_SELECTOR_LABELS[selector]
    expected_status = (
        "occurrence-posterior propagation conditional on the declared host "
        f"selector ({label}) and 1-Mearth conservative-HZ model"
    )
    if data.get("status") != expected_status:
        raise RuntimeError(f"Unexpected propagation status for {selector}:{branch}")
    if data.get("branch") != branch:
        raise RuntimeError(f"Propagation branch mismatch for {selector}:{branch}")
    _require_finite_nonnegative(
        data.get("runtime_seconds"), f"{selector}:{branch} runtime_seconds"
    )
    software = _require_mapping(data.get("software"), f"{selector}:{branch} software")
    if set(software) != {"python", "platform", "numpy", "pandas"} or any(
        not isinstance(software[key], str) or not software[key]
        for key in software
    ):
        raise RuntimeError(f"Propagation software provenance changed for {selector}:{branch}")
    if not isinstance(data.get("included_uncertainty"), str) or not data[
        "included_uncertainty"
    ]:
        raise RuntimeError(f"Propagation uncertainty declaration is missing for {selector}:{branch}")
    excluded = data.get("excluded_systematics")
    if (
        not isinstance(excluded, list)
        or not excluded
        or any(not isinstance(item, str) or not item for item in excluded)
    ):
        raise RuntimeError(f"Propagation excluded-systematics list is invalid for {selector}:{branch}")

    source = _require_mapping(
        data.get("source_posterior_samples"),
        f"{selector}:{branch} source_posterior_samples",
    )
    if set(source) != {
        "path",
        "sha256",
        "row_count",
        "outer_realizations",
        "equal_samples_per_outer_realization",
    }:
        raise RuntimeError(f"Unexpected posterior-source schema for {selector}:{branch}")
    if not isinstance(source.get("path"), str) or not source["path"]:
        raise RuntimeError(f"Posterior-source path is missing for {selector}:{branch}")
    source_sha = _require_sha256(
        source.get("sha256"), f"{selector}:{branch} posterior sample hash"
    )
    if source_sha != posterior_snapshot.sha256:
        raise RuntimeError(
            f"{selector}:{branch} summary is not bound to the supplied posterior samples"
        )
    expected_source_shape = (
        _require_integer(source.get("row_count"), "posterior row_count"),
        _require_integer(source.get("outer_realizations"), "posterior outer_realizations"),
        _require_integer(
            source.get("equal_samples_per_outer_realization"),
            "posterior equal_samples_per_outer_realization",
        ),
    )
    if expected_source_shape != (
        EXPECTED_POSTERIOR_ROW_COUNT,
        EXPECTED_OUTER_REALIZATIONS,
        EXPECTED_SAMPLES_PER_REALIZATION,
    ):
        raise RuntimeError(
            f"Unexpected posterior shape for {selector}:{branch}: "
            f"{expected_source_shape}"
        )
    _validate_realization_layout(
        posterior_frame,
        branch=branch,
        label=f"{selector}:{branch} posterior samples",
        required_numeric={"F0", "alpha", "beta", "gamma"},
        expected_columns=POSTERIOR_COLUMNS,
    )

    host_rows = _require_mapping(data.get("host_rows"), f"{selector}:{branch} host_rows")
    if set(host_rows) != {
        "path",
        "sha256",
        "N_star_7_9_kpc",
        "exact_distinct_Teff_values",
        "host_selection_label",
        "collapsed_measure_file",
        "collapsed_measure_sha256",
    }:
        raise RuntimeError(f"Unexpected host-row schema for {selector}:{branch}")
    if not isinstance(host_rows.get("path"), str) or not host_rows["path"]:
        raise RuntimeError(f"Host-row path is missing for {selector}:{branch}")
    if host_rows.get("collapsed_measure_file") != collapsed_name:
        raise RuntimeError(f"Unexpected collapsed host filename for {selector}:{branch}")
    if host_rows.get("host_selection_label") != label:
        raise RuntimeError(f"Host-selector label mismatch for {selector}:{branch}")
    host_sha = _require_sha256(
        host_rows.get("sha256"), f"{selector}:{branch} host hash"
    )
    if host_sha != host_snapshot.sha256:
        raise RuntimeError(
            f"{selector}:{branch} summary is not bound to the supplied host rows"
        )
    collapsed_sha = _require_sha256(
        host_rows.get("collapsed_measure_sha256"),
        f"{selector}:{branch} collapsed host hash",
    )
    host_count = _require_finite_nonnegative(
        host_rows.get("N_star_7_9_kpc"), f"{selector}:{branch} host count"
    )
    if abs(host_count - EXPECTED_SELECTOR_HOST_COUNTS[selector]) > 0.1:
        raise RuntimeError(f"Host count mismatch for {selector}:{branch}: {host_count}")
    distinct_temperatures = _require_integer(
        host_rows.get("exact_distinct_Teff_values"),
        f"{selector}:{branch} exact_distinct_Teff_values",
    )
    if distinct_temperatures != EXPECTED_SELECTOR_TEMPERATURE_COUNTS[selector]:
        raise RuntimeError(
            f"Host-temperature count mismatch for {selector}:{branch}: "
            f"{distinct_temperatures}"
        )

    collapsed_snapshot = snapshots[collapsed_name]
    if collapsed_sha != collapsed_snapshot.sha256:
        raise RuntimeError(
            f"{selector}:{branch} summary is not bound to its collapsed host measure"
        )
    collapsed = read_csv_bytes(
        collapsed_snapshot.data,
        f"{selector}:{branch} collapsed host measure",
    )
    if tuple(collapsed.columns) != COLLAPSED_COLUMNS:
        raise RuntimeError(f"{selector}:{branch} collapsed host schema changed")
    for column in COLLAPSED_COLUMNS:
        collapsed[column] = pd.to_numeric(collapsed[column], errors="raise")
    if not np.isfinite(collapsed.to_numpy(dtype=float)).all():
        raise RuntimeError(f"{selector}:{branch} collapsed host measure is non-finite")
    expected_collapsed_bytes = collapsed_frame_bytes(host_collapsed)
    if collapsed_snapshot.data != expected_collapsed_bytes:
        raise RuntimeError(
            f"{selector}:{branch} collapsed measure is not exactly derived from its host rows"
        )
    if parent_collapsed is not None and collapsed_snapshot.data != collapsed_frame_bytes(
        parent_collapsed
    ):
        raise RuntimeError(
            f"{selector}:{branch} collapsed measure is not exactly derived from the audited parent"
        )

    plugin = _require_mapping(
        data.get("plugin_validation"), f"{selector}:{branch} plugin_validation"
    )
    if selector == "canonical":
        if set(plugin) != {"Lambda_HZ", "Lambda_EE"}:
            raise RuntimeError(f"Canonical plug-in quantity set changed for {branch}")
        for quantity in ("Lambda_HZ", "Lambda_EE"):
            comparison = _require_mapping(
                plugin.get(quantity), f"{selector}:{branch}:{quantity} plug-in"
            )
            if set(comparison) != {"calculated", "reference", "relative_difference"}:
                raise RuntimeError(
                    f"Canonical plug-in schema changed for {branch}:{quantity}"
                )
            relative = _require_finite_number(
                comparison.get("relative_difference"),
                f"{selector}:{branch}:{quantity} plug-in difference",
            )
            calculated = _require_finite_number(
                comparison.get("calculated"),
                f"{selector}:{branch}:{quantity} plug-in calculated value",
            )
            reference = _require_finite_number(
                comparison.get("reference"),
                f"{selector}:{branch}:{quantity} plug-in reference value",
            )
            if reference == 0.0 or not math.isclose(
                relative,
                (calculated - reference) / reference,
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            ):
                raise RuntimeError(
                    f"Canonical plug-in fields are inconsistent for {branch}:{quantity}"
                )
            if not math.isfinite(relative) or abs(relative) > 1.0e-10:
                raise RuntimeError(
                    f"Canonical plug-in validation failed for {branch}:{quantity}"
                )
    elif plugin != {
        "status": "not_applicable_to_alternative_host_selector",
        "host_selection_label": label,
    }:
        raise RuntimeError(f"Legacy plug-in policy mismatch for {branch}")

    quantile_root = _require_mapping(
        data.get("posterior_quantiles"), f"{selector}:{branch} posterior_quantiles"
    )
    if set(quantile_root) != set(GALACTIC_QUANTITIES):
        raise RuntimeError(f"Unexpected propagated quantity set for {selector}:{branch}")
    mcse = _require_mapping(
        data.get("posterior_quantile_monte_carlo_error"),
        f"{selector}:{branch} propagation MCSE",
    )
    if set(mcse) != {
        "outer_realization_cluster_bootstrap",
        "outer_realization_cluster_bootstrap_replicates",
        "outer_realization_cluster_bootstrap_seed",
        "inner_chain_contiguous_batch_mcse",
        "inner_chain_batches",
        "interpretation",
    }:
        raise RuntimeError(f"Propagation MCSE schema changed for {selector}:{branch}")
    if _require_integer(
        mcse.get("outer_realization_cluster_bootstrap_replicates"),
        "outer bootstrap replicate count",
    ) != 1000:
        raise RuntimeError(f"Propagation bootstrap count changed for {selector}:{branch}")
    if _require_integer(
        mcse.get("outer_realization_cluster_bootstrap_seed"),
        "outer bootstrap seed",
    ) != 2026082102:
        raise RuntimeError(f"Propagation bootstrap seed changed for {selector}:{branch}")
    if _require_integer(mcse.get("inner_chain_batches"), "inner-chain batch count") != 8:
        raise RuntimeError(f"Propagation inner-chain batch count changed for {selector}:{branch}")
    if not isinstance(mcse.get("interpretation"), str) or not mcse["interpretation"]:
        raise RuntimeError(f"Propagation MCSE interpretation is missing for {selector}:{branch}")
    outer = _require_mapping(
        mcse.get("outer_realization_cluster_bootstrap"),
        f"{selector}:{branch} outer propagation MCSE",
    )
    inner = _require_mapping(
        mcse.get("inner_chain_contiguous_batch_mcse"),
        f"{selector}:{branch} inner propagation MCSE",
    )
    if set(outer) != set(GALACTIC_QUANTITIES) or set(inner) != set(GALACTIC_QUANTITIES):
        raise RuntimeError(f"Propagation MCSE quantity set changed for {selector}:{branch}")
    checks: dict[str, Any] = {}
    draws = read_csv_bytes(
        snapshots[draws_name].data,
        f"{selector}:{branch} propagated draws",
        compressed=True,
    )
    _validate_realization_layout(
        draws,
        branch=branch,
        label=f"{selector}:{branch} propagated draws",
        required_numeric={
            "F0",
            "alpha",
            "beta",
            "gamma",
            "N_star",
            *GALACTIC_QUANTITIES,
        },
        expected_columns=PROPAGATED_DRAW_COLUMNS,
    )
    if not np.array_equal(
        draws["branch"].astype(str).to_numpy(),
        posterior_frame["branch"].astype(str).to_numpy(),
    ) or not np.array_equal(
        draws.loc[:, POSTERIOR_COLUMNS[1:]].to_numpy(dtype=float),
        posterior_frame.loc[:, POSTERIOR_COLUMNS[1:]].to_numpy(dtype=float),
    ):
        raise RuntimeError(
            f"{selector}:{branch} propagated draws are not row-for-row bound "
            "to the supplied posterior samples"
        )
    for quantity in GALACTIC_QUANTITIES:
        actual = np.quantile(
            draws[quantity].to_numpy(dtype=float),
            [0.025, 0.16, 0.50, 0.84, 0.975],
        )
        declared = np.asarray(
            [quantile_root[quantity][name] for name in QUANTILES], dtype=float
        )
        if not np.allclose(actual, declared, rtol=1.0e-12, atol=1.0e-12):
            raise RuntimeError(
                f"{selector}:{branch}:{quantity} quantiles do not match actual draws"
            )
    n_values = draws.N_star.to_numpy(dtype=float)
    if not np.allclose(
        n_values,
        EXPECTED_SELECTOR_HOST_COUNTS[selector],
        rtol=0.0,
        atol=0.1,
    ):
        raise RuntimeError(f"{selector}:{branch} draws contain the wrong N_star")
    lambda_hz = draws.Lambda_HZ.to_numpy(dtype=float)
    lambda_ee = draws.Lambda_EE.to_numpy(dtype=float)
    mean_hz = draws.mean_f_HZ.to_numpy(dtype=float)
    mean_ee = draws.mean_f_EE.to_numpy(dtype=float)
    ratio = draws.Lambda_EE_over_Lambda_HZ.to_numpy(dtype=float)
    if np.any(
        np.column_stack([mean_hz, mean_ee, lambda_hz, lambda_ee, ratio]) < 0.0
    ):
        raise RuntimeError(f"{selector}:{branch} propagated quantities must be non-negative")
    bryson_dir = Path(__file__).resolve().parents[1] / "bryson-joint-posterior"
    if str(bryson_dir) not in sys.path:
        sys.path.insert(0, str(bryson_dir))
    propagation_module = importlib.import_module("propagate_hab2_joint_posterior")
    teff = host_collapsed.Teff_K.to_numpy(dtype=float)
    host_weight = host_collapsed.integrated_host_weight.to_numpy(dtype=float)
    recomputed_hz = np.empty(len(posterior_frame), dtype=float)
    recomputed_ee = np.empty(len(posterior_frame), dtype=float)
    validation_chunk_size = 2048
    for start in range(0, len(posterior_frame), validation_chunk_size):
        stop = min(start + validation_chunk_size, len(posterior_frame))
        expected_hz, expected_ee = propagation_module.propagate_chunk(
            posterior_frame.iloc[start:stop], teff, host_weight
        )
        recomputed_hz[start:stop] = expected_hz
        recomputed_ee[start:stop] = expected_ee
    if not np.allclose(
        lambda_hz, recomputed_hz, rtol=2.0e-12, atol=1.0e-8
    ) or not np.allclose(
        lambda_ee, recomputed_ee, rtol=2.0e-12, atol=1.0e-8
    ):
        raise RuntimeError(
            f"{selector}:{branch} propagated populations are not reproduced "
            "from the supplied posterior and host measure"
        )
    if not np.allclose(
        lambda_hz,
        mean_hz * n_values,
        rtol=1.0e-12,
        atol=1.0e-12,
    ) or not np.allclose(
        lambda_ee,
        mean_ee * n_values,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError(f"{selector}:{branch} mean/count propagation identity failed")
    if np.any(lambda_hz == 0.0) or not np.allclose(
        ratio,
        lambda_ee / lambda_hz,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError(f"{selector}:{branch} propagated ratio identity failed")

    # Do not trust the summary's own uncertainty diagnostics.  Recompute both
    # estimators from populations independently reconstructed from the supplied
    # posterior and host measure.  This also avoids treating CSV round-trip
    # noise as part of the mathematical MCSE definition.
    diagnostics_module = importlib.import_module("clustered_monte_carlo")
    diagnostic_draws = posterior_frame.loc[:, POSTERIOR_COLUMNS].copy()
    diagnostic_n_star = float(host_weight.sum())
    diagnostic_draws["mean_f_HZ"] = recomputed_hz / diagnostic_n_star
    diagnostic_draws["mean_f_EE"] = recomputed_ee / diagnostic_n_star
    diagnostic_draws["Lambda_HZ"] = recomputed_hz
    diagnostic_draws["Lambda_EE"] = recomputed_ee
    diagnostic_draws["Lambda_EE_over_Lambda_HZ"] = recomputed_ee / recomputed_hz
    recomputed_outer = diagnostics_module.cluster_bootstrap_quantile_mcse(
        diagnostic_draws,
        GALACTIC_QUANTITIES,
        "global_trial",
        1000,
        2026082102,
    )
    recomputed_inner = diagnostics_module.contiguous_batch_quantile_mcse(
        diagnostic_draws,
        GALACTIC_QUANTITIES,
        "global_trial",
        8,
    )
    for quantity in GALACTIC_QUANTITIES:
        outer_quantity = _require_mapping(
            outer.get(quantity), f"{quantity} outer MCSE"
        )
        inner_quantity = _require_mapping(
            inner.get(quantity), f"{quantity} inner MCSE"
        )
        if set(outer_quantity) != set(QUANTILES) or set(inner_quantity) != set(
            QUANTILES
        ):
            raise RuntimeError(
                f"Propagation MCSE quantile set changed for {selector}:{branch}:{quantity}"
            )
        for quantile in QUANTILES:
            interval = _require_mapping(
                outer_quantity.get(quantile),
                f"{selector}:{branch}:{quantity}:{quantile} outer MCSE",
            )
            if set(interval) != {
                "standard_error",
                "bootstrap_q2.5",
                "bootstrap_q97.5",
            }:
                raise RuntimeError(
                    f"Outer MCSE schema changed for {selector}:{branch}:{quantity}:{quantile}"
                )
            standard_error = _require_finite_nonnegative(
                interval.get("standard_error"), "outer MCSE standard error"
            )
            lower = _require_finite_number(
                interval.get("bootstrap_q2.5"), "outer MCSE lower endpoint"
            )
            upper = _require_finite_number(
                interval.get("bootstrap_q97.5"), "outer MCSE upper endpoint"
            )
            if lower > upper or standard_error < 0.0:
                raise RuntimeError("Outer MCSE interval is invalid")
            inner_value = _require_finite_nonnegative(
                inner_quantity.get(quantile), "inner-chain quantile MCSE"
            )
            expected_interval = recomputed_outer[quantity][quantile]
            for field, observed in (
                ("standard_error", standard_error),
                ("bootstrap_q2.5", lower),
                ("bootstrap_q97.5", upper),
            ):
                if not math.isclose(
                    observed,
                    expected_interval[field],
                    rel_tol=1.0e-12,
                    abs_tol=1.0e-12,
                ):
                    raise RuntimeError(
                        f"{selector}:{branch}:{quantity}:{quantile} outer MCSE "
                        "does not match the manifest-bound draws"
                    )
            if not math.isclose(
                inner_value,
                recomputed_inner[quantity][quantile],
                rel_tol=1.0e-12,
                abs_tol=1.0e-12,
            ):
                raise RuntimeError(
                    f"{selector}:{branch}:{quantity}:{quantile} inner MCSE "
                    "does not match the manifest-bound draws"
                )
        quantiles = _validate_ordered_quantiles(
            _require_mapping(quantile_root.get(quantity), quantity),
            f"{selector}:{branch}:{quantity}",
        )
        outer_fraction = _q50_mcse_fraction(
            quantiles,
            outer_quantity,
            outer=True,
        )
        inner_fraction = _q50_mcse_fraction(
            quantiles,
            inner_quantity,
            outer=False,
        )
        if outer_fraction > 0.10 or inner_fraction > 0.05:
            raise RuntimeError(
                f"Propagation MCSE gate failed for {selector}:{branch}:{quantity}: "
                f"outer={outer_fraction}, inner={inner_fraction}"
            )
        checks[quantity] = {
            "outer_q50_mcse_fraction_of_q16_q84_width": outer_fraction,
            "inner_q50_mcse_fraction_of_q16_q84_width": inner_fraction,
        }
    return data, {
        "artifact_root": str(Path(artifact_root).resolve()),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {
            name: snapshot.sha256 for name, snapshot in snapshots.items()
        },
        "summary_sha256": summary_snapshot.sha256,
        "draws_sha256": snapshots[draws_name].sha256,
        "posterior_sample_sha256": source_sha,
        "posterior_row_count": EXPECTED_POSTERIOR_ROW_COUNT,
        "host_sha256": host_sha,
        "collapsed_host_sha256": collapsed_sha,
        "host_count": host_count,
        "distinct_host_temperatures": distinct_temperatures,
        "mcse": checks,
    }


def validate_fresh_propagation_set(
    roots: dict[tuple[str, str], Path],
    *,
    posterior_paths: dict[str, Path | FileSnapshot],
    host_paths: dict[str, Path],
    parent_collapsed: dict[str, pd.DataFrame] | None = None,
    parent_host_frames: dict[str, pd.DataFrame] | None = None,
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, Any]]:
    expected = {
        (selector, branch)
        for selector in ("canonical", "legacy")
        for branch in ("constant", "zero")
    }
    if set(roots) != expected:
        raise RuntimeError("Fresh propagation set must contain canonical/legacy x constant/zero")
    if set(posterior_paths) != {"constant", "zero"}:
        raise RuntimeError("Fresh propagation set requires exact constant/zero posterior paths")
    if set(host_paths) != {"canonical", "legacy"}:
        raise RuntimeError("Fresh propagation set requires exact canonical/legacy host paths")
    if parent_collapsed is not None and set(parent_collapsed) != {"canonical", "legacy"}:
        raise RuntimeError("Parent collapsed measures require canonical and legacy entries")
    if parent_host_frames is not None and set(parent_host_frames) != {"canonical", "legacy"}:
        raise RuntimeError("Parent host rows require canonical and legacy entries")

    posterior_inputs: dict[str, tuple[pd.DataFrame, FileSnapshot, dict[str, Any]]] = {}
    for branch in ("constant", "zero"):
        posterior_inputs[branch] = validate_posterior_artifact(
            posterior_paths[branch], branch=branch
        )
    host_inputs: dict[
        str, tuple[pd.DataFrame, pd.DataFrame, FileSnapshot, dict[str, Any]]
    ] = {}
    for selector in ("canonical", "legacy"):
        host_inputs[selector] = validate_host_artifact(
            host_paths[selector], selector=selector
        )
        if parent_host_frames is not None:
            require_host_rows_equal_parent(
                host_inputs[selector][0],
                parent_host_frames[selector],
                selector=selector,
            )

    summaries: dict[tuple[str, str], dict[str, Any]] = {}
    evidence: dict[str, dict[str, Any]] = {"canonical": {}, "legacy": {}}
    for selector, branch in sorted(expected):
        posterior_frame, posterior_snapshot, posterior_evidence = posterior_inputs[branch]
        host_frame, host_collapsed, host_snapshot, host_evidence = host_inputs[selector]
        summary, check = validate_fresh_propagation_summary(
            roots[(selector, branch)],
            branch=branch,
            selector=selector,
            posterior_snapshot=posterior_snapshot,
            posterior_frame=posterior_frame,
            host_snapshot=host_snapshot,
            host_frame=host_frame,
            host_collapsed=host_collapsed,
            parent_collapsed=(
                None if parent_collapsed is None else parent_collapsed[selector]
            ),
        )
        check["posterior_artifact"] = posterior_evidence
        check["host_artifact"] = host_evidence
        summaries[(selector, branch)] = summary
        evidence[selector][branch] = check

    for branch in ("constant", "zero"):
        canonical = evidence["canonical"][branch]
        legacy = evidence["legacy"][branch]
        if canonical["posterior_sample_sha256"] != legacy["posterior_sample_sha256"]:
            raise RuntimeError(
                f"Canonical and legacy {branch} propagations do not use identical posterior samples"
            )
    if (
        evidence["canonical"]["constant"]["posterior_sample_sha256"]
        == evidence["canonical"]["zero"]["posterior_sample_sha256"]
    ):
        raise RuntimeError("Constant and zero branches unexpectedly use the same posterior sample")

    for selector in ("canonical", "legacy"):
        constant = evidence[selector]["constant"]
        zero = evidence[selector]["zero"]
        for key in ("host_sha256", "collapsed_host_sha256", "host_count", "distinct_host_temperatures"):
            if constant[key] != zero[key]:
                raise RuntimeError(f"{selector} host evidence differs across branches: {key}")
    canonical_count = float(evidence["canonical"]["constant"]["host_count"])
    if abs(canonical_count - CANONICAL_N_STAR) > 0.1:
        raise RuntimeError(f"Canonical propagation host count mismatch: {canonical_count}")
    if (
        evidence["canonical"]["constant"]["host_sha256"]
        == evidence["legacy"]["constant"]["host_sha256"]
    ):
        raise RuntimeError("Canonical and legacy propagations use the same host artifact")
    return summaries, evidence


def verify_metallicity_audit_root(
    artifact_root: Path,
    native_solar_points: Path | None = None,
    parent_evidence: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the independent metallicity audit verifier and cross-check its solar CSV."""

    root = artifact_root.resolve()
    if artifact_root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"Metallicity audit root is not a directory: {root}")
    scripts = Path(__file__).resolve().parents[2] / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    try:
        verifier = importlib.import_module("verify_metallicity_tams_audit")
        report = verifier.verify_artifact(root)
    except Exception as error:
        raise RuntimeError(f"Metallicity-TAMS artifact verification failed: {error}") from error

    report_path = root / METALLICITY_REPORT_NAME
    disk_report, report_snapshot = load_json_snapshot(
        report_path, "verified metallicity report"
    )
    if disk_report != report:
        raise RuntimeError("Verified metallicity report does not match the report on disk")
    if report.get("status") != "FAIL_NOT_PUBLISHABLE":
        raise RuntimeError("Metallicity correction is not in the required non-publishable state")
    correction_policy = report.get("correction_policy")
    if correction_policy != {"applied": False, "publishable": False, "emitted_files": []}:
        raise RuntimeError("Metallicity correction policy is not fail-closed")

    parent_binding = _require_mapping(
        report.get("parent_input"), "metallicity parent_input"
    )
    expected_parent_keys = {
        "filename",
        "sha256",
        "size_bytes",
        "row_count",
        "feh_min",
        "feh_max",
    }
    if set(parent_binding) != expected_parent_keys:
        raise RuntimeError("Metallicity parent_input schema changed")
    _require_sha256(parent_binding.get("sha256"), "metallicity parent SHA-256")
    _require_positive_integer(parent_binding.get("size_bytes"), "metallicity parent size")
    _require_positive_integer(parent_binding.get("row_count"), "metallicity parent row count")
    _require_finite_number(parent_binding.get("feh_min"), "metallicity parent FeH minimum")
    _require_finite_number(parent_binding.get("feh_max"), "metallicity parent FeH maximum")
    if parent_evidence is not None:
        if parent_binding.get("filename") != parent_evidence.get("filename"):
            raise RuntimeError("Metallicity audit used a different parent filename")
        for key in ("sha256", "size_bytes", "row_count"):
            if parent_binding.get(key) != parent_evidence.get(key):
                raise RuntimeError(f"Metallicity audit used a different parent: {key}")
        for key in ("feh_min", "feh_max"):
            if not math.isclose(
                _require_finite_number(parent_binding.get(key), f"metallicity {key}"),
                _require_finite_number(parent_evidence.get(key), f"host parent {key}"),
                rel_tol=0.0,
                abs_tol=1.0e-12,
            ):
                raise RuntimeError(f"Metallicity audit parent FeH range mismatch: {key}")

    native = _require_mapping(
        report.get("native_solar_reference"), "metallicity native_solar_reference"
    )
    if native.get("points_file") != NATIVE_SOLAR_POINTS_NAME:
        raise RuntimeError("Unexpected native solar TAMS filename")
    points_path = (root / NATIVE_SOLAR_POINTS_NAME).resolve()
    if points_path.parent != root or not points_path.is_file():
        raise RuntimeError("Native solar TAMS points are not a direct artifact-root file")
    points_snapshot = read_file_snapshot(points_path, "native solar TAMS points")
    points_sha = points_snapshot.sha256
    if _require_sha256(native.get("points_sha256"), "native solar points hash") != points_sha:
        raise RuntimeError("Native solar TAMS points hash disagrees with metallicity report")
    if native_solar_points is not None and native_solar_points.resolve() != points_path:
        raise RuntimeError(
            "--native-solar-tams-points must identify the verified artifact-root CSV"
        )
    return report, {
        "artifact_root": str(root),
        "report_path": str(report_path),
        "report_sha256": report_snapshot.sha256,
        "native_solar_tams_points_filename": points_path.name,
        "native_solar_tams_points_sha256": points_sha,
        "parent_input": dict(parent_binding),
    }


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


def collapsed_host_measure_frame(
    frame: pd.DataFrame,
    mask: np.ndarray,
) -> pd.DataFrame:
    active = np.asarray(mask, dtype=bool)
    if active.shape != (len(frame),):
        raise RuntimeError("Host selector mask has the wrong shape")
    collapsed = (
        frame.loc[active, ["Teff_K", "integrated_weight"]]
        .groupby("Teff_K", as_index=False, sort=True)
        .integrated_weight.sum()
        .rename(columns={"integrated_weight": "integrated_host_weight"})
        .sort_values("Teff_K")
        .reset_index(drop=True)
    )
    if collapsed.empty or not np.isfinite(collapsed.to_numpy(dtype=float)).all():
        raise RuntimeError("Derived collapsed host measure is empty or non-finite")
    if (collapsed.integrated_host_weight < 0.0).any():
        raise RuntimeError("Derived collapsed host measure contains negative weight")
    if not np.all(np.diff(collapsed.Teff_K.to_numpy(dtype=float)) > 0.0):
        raise RuntimeError("Derived collapsed host temperatures are not strictly increasing")
    return collapsed


def collapsed_frame_bytes(collapsed: pd.DataFrame) -> bytes:
    if tuple(collapsed.columns) != COLLAPSED_COLUMNS:
        raise RuntimeError("Collapsed host measure has an unexpected schema")
    return collapsed.to_csv(index=False, lineterminator="\n").encode("utf-8")


def derived_collapsed_host_measure(
    frame: pd.DataFrame,
    mask: np.ndarray,
) -> dict[str, Any]:
    collapsed = collapsed_host_measure_frame(frame, mask)
    encoded = collapsed_frame_bytes(collapsed)
    return {
        "row_count": int(len(collapsed)),
        "N_star": float(collapsed.integrated_host_weight.sum()),
        "csv_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def weighted_quantile(
    values: np.ndarray, weights: np.ndarray, probabilities: tuple[float, ...]
) -> list[float]:
    numeric_values = np.asarray(values, dtype=float)
    numeric_weights = np.asarray(weights, dtype=float)
    numeric_probabilities = np.asarray(probabilities, dtype=float)
    if (
        numeric_values.ndim != 1
        or numeric_weights.shape != numeric_values.shape
        or not len(numeric_values)
        or not np.isfinite(numeric_values).all()
        or not np.isfinite(numeric_weights).all()
        or np.any(numeric_weights < 0.0)
        or not math.isfinite(float(numeric_weights.sum()))
        or float(numeric_weights.sum()) <= 0.0
    ):
        raise RuntimeError("Weighted-quantile values or weights are invalid")
    if (
        numeric_probabilities.ndim != 1
        or not np.isfinite(numeric_probabilities).all()
        or np.any((numeric_probabilities < 0.0) | (numeric_probabilities > 1.0))
        or np.any(np.diff(numeric_probabilities) < 0.0)
    ):
        raise RuntimeError("Weighted-quantile probabilities are invalid")
    order = np.argsort(numeric_values)
    sorted_values = numeric_values[order]
    sorted_weights = numeric_weights[order]
    cumulative = np.cumsum(sorted_weights)
    cumulative /= cumulative[-1]
    return [
        float(np.interp(probability, cumulative, sorted_values))
        for probability in numeric_probabilities
    ]


def selection_summary(frame: pd.DataFrame, mask: np.ndarray) -> dict[str, float]:
    weights = frame.integrated_weight.to_numpy(dtype=float)
    active = np.asarray(mask, dtype=bool)
    if active.shape != (len(frame),):
        raise RuntimeError("Selection-summary mask has the wrong shape")
    f_hz = frame.f_HZ.to_numpy(dtype=float)
    f_earth10 = frame.f_earth10.to_numpy(dtype=float)
    if (
        not np.isfinite(weights).all()
        or not np.isfinite(f_hz).all()
        or not np.isfinite(f_earth10).all()
        or np.any(weights < 0.0)
        or np.any(f_hz < 0.0)
        or np.any(f_earth10 < 0.0)
        or np.any(f_earth10 > f_hz)
    ):
        raise RuntimeError("Selection-summary inputs violate finite/nonnegative invariants")
    n_star = float(np.sum(weights[active]))
    if not math.isfinite(n_star) or n_star <= 0.0:
        raise RuntimeError("Selection-summary host count must be positive and finite")
    lambda_hz = float(np.sum(weights[active] * f_hz[active]))
    lambda_ee = float(np.sum(weights[active] * f_earth10[active]))
    result = {
        "N_star": n_star,
        "mean_f_HZ_plugin": lambda_hz / n_star,
        "mean_f_EE_plugin": lambda_ee / n_star,
        "Lambda_HZ_plugin": lambda_hz,
        "Lambda_EE_plugin": lambda_ee,
    }
    if not all(math.isfinite(value) and value >= 0.0 for value in result.values()):
        raise RuntimeError("Selection summary is non-finite or negative")
    if result["Lambda_EE_plugin"] > result["Lambda_HZ_plugin"]:
        raise RuntimeError("Selection-summary population ordering failed")
    return result


def fractional_change(value: float, reference: float) -> float:
    numeric_value = float(value)
    numeric_reference = float(reference)
    if (
        not math.isfinite(numeric_value)
        or not math.isfinite(numeric_reference)
        or numeric_reference == 0.0
    ):
        raise RuntimeError("Fractional-change inputs must be finite with nonzero reference")
    result = (numeric_value - numeric_reference) / numeric_reference
    if not math.isfinite(result):
        raise RuntimeError("Fractional change is non-finite")
    return result


def validate_native_solar_points(
    source: Path | FileSnapshot,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    snapshot = (
        source
        if isinstance(source, FileSnapshot)
        else read_file_snapshot(source, "native solar TAMS points")
    )
    points = read_csv_bytes(snapshot.data, "native solar TAMS points")
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


def verify_host_artifact_contract_binding(
    contract_path: Path,
    artifact_root: Path,
    canonical_hosts: pd.DataFrame,
    *,
    expected_contract_sha256: str,
    expected_contract_size_bytes: int,
    expected_qualification_report_sha256: str,
    expected_qualification_report_size_bytes: int,
    expected_source_lock: Mapping[str, Any],
    qualification_report_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], FileSnapshot]:
    """Verify an accepted host tuple and bind its raw rows to the parent table."""

    repository_root = Path(__file__).resolve().parents[2]
    contract_snapshot = read_file_snapshot(contract_path, "host artifact contract")
    if (
        contract_snapshot.sha256 != expected_contract_sha256
        or contract_snapshot.size_bytes != expected_contract_size_bytes
    ):
        raise RuntimeError("External host artifact contract differs from its exact lock")
    root = Path(artifact_root)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Host artifact root must be a non-symlink directory")
    manifest_snapshot = read_file_snapshot(
        root / HOST_CONTRACT_MANIFEST_NAME, "host artifact manifest"
    )
    artifact_snapshots = {
        name: read_file_snapshot(root / name, f"host contract target {name}")
        for name in HOST_CONTRACT_FILES
    }
    verifier, verifier_snapshot = _load_python_module_from_snapshot(
        repository_root / "scripts" / "verify_host_artifact_contract.py",
        module_name="_host_audit_verify_host_artifact_contract",
        label="host artifact contract verifier",
    )
    contract_document = verifier.load_json_bytes(
        contract_snapshot.data, "host artifact contract"
    )
    contract_document = verifier.validate_contract(contract_document)
    qualification_snapshots: dict[str, FileSnapshot] = {}
    if isinstance(contract_document, dict):
        for artifact_set in contract_document.get("artifact_sets", []):
            if not isinstance(artifact_set, dict):
                continue
            reference = artifact_set.get("qualification_report")
            if reference is None:
                continue
            if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
                raise RuntimeError("Host qualification-report reference is malformed")
            try:
                name = _portable_leaf_name(
                    reference.get("path"), "Host qualification-report reference"
                )
            except RuntimeError as error:
                raise RuntimeError(
                    "Host qualification-report reference is malformed"
                ) from error
            authoritative_path = Path(contract_path).parent / name
            if qualification_report_path is not None and Path(
                qualification_report_path
            ).resolve() != authoritative_path.resolve():
                raise RuntimeError(
                    "Supplied host qualification-report path differs from contract B"
                )
            snapshot = read_file_snapshot(
                authoritative_path,
                f"host qualification report {name}",
            )
            if snapshot.sha256 != reference.get("sha256"):
                raise RuntimeError("Host qualification-report hash mismatch")
            qualification_snapshots[name] = snapshot
    if len(qualification_snapshots) != 1:
        raise RuntimeError("Accepted host contract must reference exactly one report")
    qualification_snapshot = next(iter(qualification_snapshots.values()))
    if (
        qualification_snapshot.sha256 != expected_qualification_report_sha256
        or qualification_snapshot.size_bytes
        != expected_qualification_report_size_bytes
    ):
        raise RuntimeError("Host qualification report differs from its exact lock")
    with tempfile.TemporaryDirectory(prefix="host-contract-binding-") as temporary:
        stable = Path(temporary)
        stable_contract = stable / HOST_CONTRACT_NAME
        stable_contract.write_bytes(contract_snapshot.data)
        for name, snapshot in qualification_snapshots.items():
            (stable / name).write_bytes(snapshot.data)
        stable_root = stable / "artifact"
        stable_root.mkdir()
        (stable_root / HOST_CONTRACT_MANIFEST_NAME).write_bytes(manifest_snapshot.data)
        for name, snapshot in artifact_snapshots.items():
            (stable_root / name).write_bytes(snapshot.data)
        verified = verifier.verify_artifact(stable_contract, stable_root)
        accepted_sets = [
            item
            for item in contract_document["artifact_sets"]
            if item["production_accepted"] is True
        ]
        if len(accepted_sets) != 1:
            raise RuntimeError("External host contract lacks one accepted candidate")
        qualification = verifier._validate_qualification_report(
            stable_contract,
            contract_document,
            accepted_sets[0],
            include_source_state=True,
        )
    artifact_set = _require_mapping(
        verified.get("artifact_set"), "verified host artifact set"
    )
    if artifact_set.get("production_accepted") is not True:
        raise RuntimeError("Host artifact set is not production accepted")

    raw_name = "jj_g_hosts_raw_eligible_padova.csv"
    raw = read_csv_bytes(
        artifact_snapshots[raw_name].data,
        "contract-bound raw eligible hosts",
        float_precision="round_trip",
    )
    parent_projection_columns = (
        "R_kpc",
        "component",
        "Teff_K",
        "age_Gyr",
        "logg",
        "N_surface_pc-2",
    )
    if tuple(raw.columns) != parent_projection_columns or len(raw) != len(canonical_hosts):
        raise RuntimeError("Contract raw host table does not match canonical parent-selected rows")
    if not np.array_equal(
        raw.component.astype(str).to_numpy(),
        canonical_hosts.component.astype(str).to_numpy(),
    ):
        raise RuntimeError("Contract raw host components differ from the parent table")
    numeric = [column for column in parent_projection_columns if column != "component"]
    for column in numeric:
        raw[column] = pd.to_numeric(raw[column], errors="raise")
    if not np.isfinite(raw[numeric].to_numpy(dtype=float)).all() or not np.array_equal(
        raw[numeric].to_numpy(dtype=float),
        canonical_hosts[numeric].to_numpy(dtype=float),
    ):
        raise RuntimeError("Contract raw numerical rows differ from the parent table")
    summary_snapshot = artifact_snapshots["jj_g_hosts_summary_padova.json"]
    source_state = qualification["source_state"]

    def compact_source(record: Mapping[str, Any]) -> dict[str, Any]:
        archive = record["source_archive"]
        return {
            "repository": record["repository"],
            "commit_sha": record["commit_sha"],
            "git_tree_sha": record["git_tree_sha"],
            "source_archive_sha256": archive["sha256"],
            "source_archive_size_bytes": archive["size_bytes"],
        }

    source_lock = {
        "public_source": compact_source(source_state["public_source"]),
        "private_source": compact_source(source_state["private_source"]),
    }
    if source_lock != dict(expected_source_lock):
        raise RuntimeError("Host qualification source lock differs from computational A")
    public = source_lock["public_source"]
    private = source_lock["private_source"]
    for field in (
        "commit_sha",
        "git_tree_sha",
        "source_archive_sha256",
        "source_archive_size_bytes",
    ):
        if public[field] != private[field]:
            raise RuntimeError("Host public/private computational source A differs")
    computational_source = {
        "commit": public["commit_sha"],
        "tree": public["git_tree_sha"],
        "archive_sha256": public["source_archive_sha256"],
        "archive_size_bytes": public["source_archive_size_bytes"],
    }
    return verified, {
        "contract_sha256": contract_snapshot.sha256,
        "contract_size_bytes": contract_snapshot.size_bytes,
        "contract_verifier_sha256": verifier_snapshot.sha256,
        "artifact_root": str(root.resolve()),
        "manifest_sha256": manifest_snapshot.sha256,
        "artifact_set_id": artifact_set.get("id"),
        "representation_match": verified.get("representation_match"),
        "production_accepted": True,
        "qualification_report_sha256": qualification_snapshot.sha256,
        "qualification_report_size_bytes": qualification_snapshot.size_bytes,
        "qualification_id": qualification["report"]["qualification_id"],
        "source_lock": source_lock,
        "computational_source": computational_source,
        "raw_parent_projection_sha256": artifact_snapshots[raw_name].sha256,
        "qualification_reports": {
            name: {
                "sha256": snapshot.sha256,
                "size_bytes": snapshot.size_bytes,
            }
            for name, snapshot in qualification_snapshots.items()
        },
    }, summary_snapshot


def validate_parent_artifact(
    path: Path,
) -> tuple[
    pd.DataFrame,
    dict[str, np.ndarray],
    dict[str, pd.DataFrame],
    dict[str, pd.DataFrame],
    FileSnapshot,
    dict[str, Any],
]:
    """Reconstruct every parent-derived selector quantity from primitive columns."""

    parent, snapshot = read_csv_snapshot(path, "JJ parent host table")
    if tuple(parent.columns) != PARENT_COLUMNS:
        raise RuntimeError(
            f"Parent host table columns changed: {tuple(parent.columns)!r}"
        )
    numeric_columns = [column for column in PARENT_COLUMNS if column != "component"]
    for column in numeric_columns:
        parent[column] = pd.to_numeric(parent[column], errors="raise")
    numeric_values = parent[numeric_columns].to_numpy(dtype=float)
    if not np.isfinite(numeric_values).all():
        raise RuntimeError("Parent host table contains non-finite numerical values")
    if not len(parent):
        raise RuntimeError("Parent host table is empty")
    if set(parent.component.astype(str)) != {"thin", "thick"}:
        raise RuntimeError("Parent host table must contain exactly thin and thick components")
    if not parent.Teff_K.between(5300.0, 6000.0).all():
        raise RuntimeError("Parent host table contains temperatures outside 5300--6000 K")
    if not (parent.age_Gyr >= 4.57).all():
        raise RuntimeError("Parent host table contains ages below 4.57 Gyr")
    if (parent["N_surface_pc-2"] < 0.0).any() or (parent.Mf <= 0.0).any():
        raise RuntimeError("Parent host table contains invalid weight or final mass")
    if (parent.Rstar_g_Rsun <= 0.0).any() or (parent.R_TAMS_Rsun <= 0.0).any():
        raise RuntimeError("Parent host table contains a non-positive stellar/TAMS radius")
    nodes = np.sort(parent.R_kpc.unique())
    if not np.array_equal(nodes, EXPECTED_PARENT_RADIAL_NODES):
        raise RuntimeError(f"Parent host table radial nodes changed: {nodes}")
    component_grid = parent.groupby(["R_kpc", "component"], sort=True).size()
    expected_pairs = {
        (float(radius), component)
        for radius in EXPECTED_PARENT_RADIAL_NODES
        for component in ("thin", "thick")
    }
    if set(component_grid.index) != expected_pairs:
        raise RuntimeError("Parent host table lacks a radial-node/disk-component cell")

    teff = parent.Teff_K.to_numpy(dtype=float)
    expected_teff = np.power(10.0, parent.logT.to_numpy(dtype=float))
    if not np.allclose(teff, expected_teff, rtol=1.0e-12, atol=1.0e-9):
        raise RuntimeError("Parent Teff_K is not reconstructed from logT")
    expected_radius_g = np.sqrt(
        parent.Mf.to_numpy(dtype=float)
        * np.power(10.0, 4.438 - parent.logg.to_numpy(dtype=float))
    )
    if not np.allclose(
        parent.Rstar_g_Rsun.to_numpy(dtype=float),
        expected_radius_g,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError("Parent gravity-derived stellar radius identity failed")
    expected_radius_l = np.power(10.0, parent.logL.to_numpy(dtype=float) / 2.0) * np.power(
        5772.0 / teff, 2.0
    )
    if not np.allclose(
        parent.Rstar_L_Rsun.to_numpy(dtype=float),
        expected_radius_l,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError("Parent luminosity-derived stellar radius identity failed")

    jj_host_dir = Path(__file__).resolve().parents[1] / "jj-host-export"
    tams_reference, tams_source_snapshot = _load_python_module_from_snapshot(
        jj_host_dir / "tams_reference.py",
        module_name="_host_audit_tams_reference",
        label="TAMS reference implementation",
    )
    occurrence_reference, occurrence_source_snapshot = (
        _load_python_module_from_snapshot(
            jj_host_dir / "occurrence_reference.py",
            module_name="_host_audit_occurrence_reference",
            label="occurrence reference implementation",
        )
    )
    validate_occurrence_reference_anchors(occurrence_reference)
    expected_tams = np.asarray(tams_reference.tams_radius_rsun(teff), dtype=float)
    if not np.allclose(
        parent.R_TAMS_Rsun.to_numpy(dtype=float),
        expected_tams,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError("Parent TAMS radius is not derived from the locked reference")
    helper_f_hz = np.asarray(occurrence_reference.f_hz(teff), dtype=float)
    helper_f_earth10 = np.asarray(
        occurrence_reference.f_earth10(teff), dtype=float
    )
    expected_f_hz, expected_f_earth10 = independent_occurrence_fractions(teff)
    if not np.allclose(
        helper_f_hz, expected_f_hz, rtol=1.0e-14, atol=1.0e-15
    ) or not np.allclose(
        helper_f_earth10, expected_f_earth10, rtol=1.0e-14, atol=1.0e-15
    ):
        raise RuntimeError(
            "Shared occurrence helper differs from the independent formula reconstruction"
        )
    if (
        not np.isfinite(expected_f_hz).all()
        or not np.isfinite(expected_f_earth10).all()
        or np.any(expected_f_hz <= 0.0)
        or np.any(expected_f_earth10 < 0.0)
        or np.any(expected_f_earth10 > expected_f_hz)
    ):
        raise RuntimeError("Reconstructed occurrence fractions violate physical invariants")
    if not np.allclose(
        parent.f_HZ.to_numpy(dtype=float),
        expected_f_hz,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError("Parent f_HZ is not derived from the reviewable occurrence model")
    if not np.allclose(
        parent.f_earth10.to_numpy(dtype=float),
        expected_f_earth10,
        rtol=1.0e-12,
        atol=1.0e-12,
    ):
        raise RuntimeError(
            "Parent f_earth10 is not derived from the reviewable occurrence model"
        )
    for column in ("A_logg", "B_TAMS_MS"):
        values = parent[column].to_numpy(dtype=float)
        if not np.array_equal(values, values.astype(np.int64).astype(float)) or not set(
            values
        ).issubset({0.0, 1.0}):
            raise RuntimeError(f"Parent selector {column} is not exactly binary")
    reconstructed_legacy = (
        (parent.logg.to_numpy(dtype=float) > 4.3)
        & (parent.logg.to_numpy(dtype=float) < 7.0)
    )
    reconstructed_canonical = (
        parent.Rstar_g_Rsun.to_numpy(dtype=float) <= expected_tams
    ) & (parent.logg.to_numpy(dtype=float) < 7.0)
    if not np.array_equal(
        parent.A_logg.to_numpy(dtype=np.int64), reconstructed_legacy.astype(np.int64)
    ):
        raise RuntimeError("Stored legacy selector differs from its exact definition")
    if not np.array_equal(
        parent.B_TAMS_MS.to_numpy(dtype=np.int64),
        reconstructed_canonical.astype(np.int64),
    ):
        raise RuntimeError("Stored canonical selector differs from its exact definition")

    selected_host_frames = {
        "canonical": parent.loc[reconstructed_canonical, list(HOST_COLUMNS)].reset_index(
            drop=True
        ),
        "legacy": parent.loc[reconstructed_legacy, list(HOST_COLUMNS)].reset_index(drop=True),
    }
    weighted = attach_radial_weights(
        parent.rename(columns={"N_surface_pc-2": "N_surface_pc_2"})
    )
    masks = {
        "canonical": (
            weighted.Rstar_g_Rsun.to_numpy(dtype=float)
            <= weighted.R_TAMS_Rsun.to_numpy(dtype=float)
        )
        & (weighted.logg.to_numpy(dtype=float) < 7.0),
        "legacy": (
            (weighted.logg.to_numpy(dtype=float) > 4.3)
            & (weighted.logg.to_numpy(dtype=float) < 7.0)
        ),
    }
    collapsed = {
        selector: collapsed_host_measure_frame(weighted, mask)
        for selector, mask in masks.items()
    }
    for selector in ("canonical", "legacy"):
        if len(collapsed[selector]) != EXPECTED_SELECTOR_TEMPERATURE_COUNTS[selector]:
            raise RuntimeError(f"Derived {selector} host temperature count changed")
        _require_close(
            collapsed[selector].integrated_host_weight.sum(),
            EXPECTED_SELECTOR_HOST_COUNTS[selector],
            f"Derived {selector} host count",
            rel_tol=0.0,
            abs_tol=0.1,
        )
    weights = weighted.integrated_weight.to_numpy(dtype=float)
    below_tams = (
        weighted.Rstar_g_Rsun.to_numpy(dtype=float)
        <= weighted.R_TAMS_Rsun.to_numpy(dtype=float)
    )
    compact_veto = below_tams & (weighted.logg.to_numpy(dtype=float) >= 7.0)
    radius_rejected = ~below_tams
    closure = (
        np.sum(weights[radius_rejected])
        + np.sum(weights[compact_veto])
        + np.sum(weights[masks["canonical"]])
        - np.sum(weights)
    )
    closure_scale = max(float(np.sum(weights)), 1.0)
    if not math.isfinite(float(closure)) or abs(float(closure)) > 1.0e-13 * closure_scale:
        raise RuntimeError(f"Canonical selector decomposition does not close: {closure}")
    evidence = {
        "path": str(snapshot.path),
        "filename": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "row_count": int(len(parent)),
        "feh_min": float(parent.FeH.min()),
        "feh_max": float(parent.FeH.max()),
        "tams_reference_sha256": str(tams_reference.EXPECTED_SHA256),
        "tams_reference_implementation_sha256": tams_source_snapshot.sha256,
        "occurrence_reference_sha256": occurrence_source_snapshot.sha256,
        "decomposition_relative_closure_error": float(closure / closure_scale),
    }
    return weighted, masks, collapsed, selected_host_frames, snapshot, evidence


def require_host_rows_equal_parent(
    actual: pd.DataFrame, expected: pd.DataFrame, *, selector: str
) -> None:
    if tuple(actual.columns) != tuple(expected.columns) or len(actual) != len(expected):
        raise RuntimeError(f"{selector} host rows do not match the parent-selected schema/size")
    if not np.array_equal(
        actual.component.astype(str).to_numpy(), expected.component.astype(str).to_numpy()
    ):
        raise RuntimeError(f"{selector} host component rows differ from the parent selector")
    numeric = [column for column in HOST_COLUMNS if column != "component"]
    if not np.array_equal(
        actual[numeric].to_numpy(dtype=float), expected[numeric].to_numpy(dtype=float)
    ):
        raise RuntimeError(f"{selector} host numerical rows differ from the parent selector")


def validate_occurrence_reference_anchors(occurrence_reference: Any) -> None:
    """Pin the shared implementation to independently recorded formula anchors."""

    measured_hz = np.asarray(
        occurrence_reference.f_hz(OCCURRENCE_ANCHOR_TEMPERATURES_K), dtype=float
    )
    measured_earth10 = np.asarray(
        occurrence_reference.f_earth10(OCCURRENCE_ANCHOR_TEMPERATURES_K), dtype=float
    )
    if not np.allclose(
        measured_hz,
        OCCURRENCE_F_HZ_ANCHORS,
        rtol=1.0e-14,
        atol=1.0e-15,
    ) or not np.allclose(
        measured_earth10,
        OCCURRENCE_F_EARTH10_ANCHORS,
        rtol=1.0e-14,
        atol=1.0e-15,
    ):
        raise RuntimeError("Occurrence reference does not match the immutable anchors")


def _validate_snapshot_record(
    raw: Any, snapshot: FileSnapshot, expected_name: str, label: str
) -> None:
    record = _require_mapping(raw, label)
    if set(record) != {"filename", "sha256", "size_bytes"}:
        raise RuntimeError(f"{label} artifact-record schema changed")
    if (
        record.get("filename") != expected_name
        or record.get("sha256") != snapshot.sha256
        or _require_integer(record.get("size_bytes"), f"{label} size")
        != snapshot.size_bytes
    ):
        raise RuntimeError(f"{label} does not bind its captured bytes")


def _parse_jj_parameter_bytes(data: bytes, label: str) -> dict[str, tuple[str, ...]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} is not valid UTF-8") from error
    result: dict[str, tuple[str, ...]] = {}
    for line_number, line in enumerate(lines, 1):
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        fields = tuple(body.split())
        if len(fields) < 2:
            raise RuntimeError(f"{label} line {line_number} is malformed")
        if fields[0] in result:
            raise RuntimeError(f"{label} repeats parameter {fields[0]!r}")
        result[fields[0]] = fields[1:]
    if not result:
        raise RuntimeError(f"{label} contains no parameters")
    return result


def validate_tams_radial_convergence_root(
    artifact_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshots, manifest_snapshot = _snapshot_exact_manifest_root(
        Path(artifact_root),
        manifest_name=TAMS_CONVERGENCE_MANIFEST_NAME,
        target_names=tams_convergence_target_names(),
        label="TAMS radial-convergence contract",
    )
    report = load_json_bytes(
        snapshots[TAMS_CONVERGENCE_REPORT_NAME].data,
        "TAMS radial-convergence report",
    )
    gate = validate_tams_radial_convergence(report, snapshots=snapshots)
    return report, {
        "artifact_root": str(Path(artifact_root).resolve()),
        "manifest_sha256": manifest_snapshot.sha256,
        "validated_files": {name: snapshot.sha256 for name, snapshot in snapshots.items()},
        "gate": gate,
    }


def verify_radial_ssp_contract_binding(
    contract_path: Path,
    qualification_report_path: Path,
    convergence_root: Path,
    *,
    expected_contract_sha256: str,
    expected_contract_size_bytes: int,
    expected_qualification_report_sha256: str,
    expected_qualification_report_size_bytes: int,
    expected_computational_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind accepted signed private SSP rederivations to public convergence files."""

    repository_root = Path(__file__).resolve().parents[2]
    contract_snapshot = read_file_snapshot(contract_path, "radial SSP contract")
    if (
        contract_snapshot.sha256 != expected_contract_sha256
        or contract_snapshot.size_bytes != expected_contract_size_bytes
    ):
        raise RuntimeError("External radial SSP contract differs from its exact lock")
    report_snapshot = read_file_snapshot(
        qualification_report_path, "radial SSP qualification report"
    )
    if (
        report_snapshot.sha256 != expected_qualification_report_sha256
        or report_snapshot.size_bytes != expected_qualification_report_size_bytes
    ):
        raise RuntimeError("Radial SSP qualification report differs from its exact lock")
    report_document = load_json_bytes(
        report_snapshot.data, "radial SSP qualification report"
    )
    report_name = _portable_leaf_name(
        report_snapshot.path.name, "Radial SSP qualification-report name"
    )
    source_root = Path(convergence_root)
    if source_root.is_symlink() or not source_root.is_dir():
        raise RuntimeError("Radial convergence root must be a non-symlink directory")
    if (source_root / "freeze-contract").is_dir() and not (
        source_root / "freeze-contract"
    ).is_symlink():
        source_root = source_root / "freeze-contract"
    manifest_snapshot = read_file_snapshot(
        source_root / TAMS_CONVERGENCE_MANIFEST_NAME,
        "radial convergence manifest for SSP binding",
    )
    target_snapshots = {
        name: read_file_snapshot(
            source_root / name, f"radial convergence target for SSP binding {name}"
        )
        for name in tams_convergence_target_names()
    }
    verifier, verifier_snapshot = _load_python_module_from_snapshot(
        repository_root / "scripts" / "verify_radial_ssp_contract.py",
        module_name="_host_audit_verify_radial_ssp_contract",
        label="radial SSP contract verifier",
    )
    with tempfile.TemporaryDirectory(prefix="radial-ssp-contract-binding-") as temporary:
        stable = Path(temporary)
        stable_contract = stable / RADIAL_SSP_CONTRACT_NAME
        stable_contract.write_bytes(contract_snapshot.data)
        stable_report = stable / report_name
        stable_report.write_bytes(report_snapshot.data)
        stable_root = stable / "convergence"
        stable_root.mkdir()
        (stable_root / TAMS_CONVERGENCE_MANIFEST_NAME).write_bytes(
            manifest_snapshot.data
        )
        for name, snapshot in target_snapshots.items():
            (stable_root / name).write_bytes(snapshot.data)
        try:
            bound = verifier.bind_public_convergence(
                stable_contract, stable_report, stable_root
            )
        except Exception as error:
            raise RuntimeError("Signed radial SSP qualification binding failed") from error
    if bound.get("status") != "PASS":
        raise RuntimeError("Signed radial SSP qualification did not pass")
    triplets = report_document.get("triplets")
    if not isinstance(triplets, list) or len(triplets) != 2:
        raise RuntimeError("Radial SSP qualification lacks two signed triplets")
    source_states = []
    for index, triplet in enumerate(triplets):
        if not isinstance(triplet, dict):
            raise RuntimeError(f"Radial SSP triplet {index} is malformed")
        state = triplet.get("source_provenance")
        if not isinstance(state, dict):
            raise RuntimeError(f"Radial SSP triplet {index} lacks source provenance")
        source_states.append(state)
    if source_states[0] != source_states[1]:
        raise RuntimeError("Radial SSP qualification triplet source locks differ")
    source_state = source_states[0]

    def compact_source(record: Any, label: str) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise RuntimeError(f"Radial SSP {label} source record is malformed")
        archive = record.get("source_archive")
        if not isinstance(archive, dict):
            raise RuntimeError(f"Radial SSP {label} source archive is malformed")
        return {
            "commit": record.get("commit_sha"),
            "tree": record.get("git_tree_sha"),
            "archive_sha256": archive.get("sha256"),
            "archive_size_bytes": archive.get("size_bytes"),
        }

    public_source = compact_source(source_state.get("public_source"), "public")
    private_source = compact_source(source_state.get("private_source"), "private")
    if public_source != private_source:
        raise RuntimeError("Radial SSP public/private computational sources differ")
    if public_source != dict(expected_computational_source):
        raise RuntimeError("Radial SSP qualification is not bound to computational source A")
    for snapshot in (
        contract_snapshot,
        report_snapshot,
        manifest_snapshot,
        *target_snapshots.values(),
    ):
        recheck_file_snapshot(snapshot, "radial SSP binding input")
    return {
        "status": "PASS",
        "artifact_set_id": bound.get("artifact_set_id"),
        "contract_sha256": contract_snapshot.sha256,
        "contract_size_bytes": contract_snapshot.size_bytes,
        "qualification_report_sha256": report_snapshot.sha256,
        "qualification_report_size_bytes": report_snapshot.size_bytes,
        "qualification_id": report_document.get("qualification_id"),
        "computational_source": public_source,
        "qualified_public_evidence_sha256": bound.get(
            "qualified_public_evidence_sha256"
        ),
        "contract_verifier_sha256": verifier_snapshot.sha256,
        "convergence_manifest_sha256": manifest_snapshot.sha256,
        "bound_run_files": {
            dr: {
                role: evidence.get("sha256")
                for role, evidence in run.items()
                if role in {"generated_radial", "generated_result"}
            }
            for dr, run in bound.get("runs", {}).items()
        },
    }


def verify_local_run_attestation_binding(
    contract_path: Path,
    *,
    candidate_id: str,
    public_report_path: Path,
    expected_contract_sha256: str,
    expected_contract_size_bytes: int,
    expected_public_report_sha256: str,
    expected_public_report_size_bytes: int,
    expected_computational_source: Mapping[str, Any],
    public_source_repo: Path,
    private_source_repo: Path,
    plan_path: Path,
    runtime_manifest_path: Path,
    output_root: Path,
    evidence_dir: Path,
    execution_root: Path,
    execution_environment: str,
    git_executable: Path,
    ssh_keygen_executable: Path,
) -> dict[str, Any]:
    """Reverify the accepted two-signer local run without exposing private paths."""

    repository_root = Path(__file__).resolve().parents[2]
    contract_snapshot = read_file_snapshot(contract_path, "local-run attestation contract")
    if (
        contract_snapshot.sha256 != expected_contract_sha256
        or contract_snapshot.size_bytes != expected_contract_size_bytes
    ):
        raise RuntimeError("External local-run contract differs from its exact lock")
    report_snapshot = read_file_snapshot(
        public_report_path, "accepted public local-run report"
    )
    if (
        report_snapshot.sha256 != expected_public_report_sha256
        or report_snapshot.size_bytes != expected_public_report_size_bytes
    ):
        raise RuntimeError("Accepted public local-run report differs from its exact lock")
    verifier, verifier_snapshot = _load_python_module_from_snapshot(
        repository_root / "scripts" / "verify_local_run_attestation.py",
        module_name="_freeze_verify_local_run_attestation",
        label="local-run attestation verifier",
    )
    try:
        _contract, candidate, _contract_check_snapshot = verifier.select_contract(
            contract_path, candidate_id
        )
        runtime_value, runtime_snapshot = verifier.load_json_snapshot(
            runtime_manifest_path, "bound numerical runtime manifest"
        )
        runtime = verifier.validate_numerical_runtime(runtime_value)
        plan_value, plan_snapshot = verifier.load_json_snapshot(
            plan_path, "bound local production command plan"
        )
        plan = verifier.validate_plan(plan_value, runtime)
        output_manifest_value, output_manifest_snapshot = verifier.load_json_snapshot(
            Path(evidence_dir) / verifier.OUTPUT_MANIFEST_NAME,
            "bound strict local-run output manifest",
        )
        output_entries = verifier.validate_output_manifest(
            output_manifest_value, plan["expected_output_files"]
        )
        report = verifier.verify_run(
            contract_path=contract_path,
            candidate_id=candidate_id,
            public_source_repo=public_source_repo,
            source_repo=private_source_repo,
            plan_path=plan_path,
            runtime_path=runtime_manifest_path,
            output_root=output_root,
            evidence_dir=evidence_dir,
            execution_root=execution_root,
            execution_environment=execution_environment,
            git_executable=git_executable,
            ssh_keygen_executable=ssh_keygen_executable,
            report_path=None,
            qualification_mode=False,
        )
        verifier.validate_report_disclosure(report)
        regenerated = verifier.canonical_json_bytes(report)
    except Exception as error:
        raise RuntimeError("Accepted signed local production run verification failed") from error
    if regenerated != report_snapshot.data:
        raise RuntimeError("Accepted local-run report differs from independently regenerated bytes")
    if report.get("command_plan_sha256") != plan_snapshot.sha256:
        raise RuntimeError("Accepted local-run report is not bound to the supplied plan")
    if report.get("numerical_runtime_manifest_sha256") != runtime_snapshot.sha256:
        raise RuntimeError("Accepted local-run report is not bound to the supplied runtime")
    if report.get("output_manifest_sha256") != output_manifest_snapshot.sha256:
        raise RuntimeError("Accepted local-run report is not bound to the supplied output manifest")
    for snapshot, label in (
        (runtime_snapshot, "bound numerical runtime manifest"),
        (plan_snapshot, "bound local production command plan"),
        (output_manifest_snapshot, "bound strict local-run output manifest"),
    ):
        verifier.recheck_snapshot(snapshot, label)
    for snapshot in (contract_snapshot, report_snapshot):
        recheck_file_snapshot(snapshot, "local-run attestation binding input")
    if candidate.get("production_accepted") is not True:
        raise RuntimeError("Local-run report is not production accepted")
    computational_source = {
        "commit": report.get("source_commit"),
        "tree": report.get("source_tree"),
        "archive_sha256": report.get("source_archive_sha256"),
        "archive_size_bytes": report.get("source_archive_size_bytes"),
    }
    candidate_source = candidate.get("source_lock")
    if not isinstance(candidate_source, dict):
        raise RuntimeError("Accepted local-run candidate lacks a source lock")
    locked_source = {
        "commit": candidate_source.get("commit"),
        "tree": candidate_source.get("tree"),
        "archive_sha256": candidate_source.get("archive_sha256"),
        "archive_size_bytes": candidate_source.get("archive_size_bytes"),
    }
    if computational_source != locked_source:
        raise RuntimeError("Accepted local-run report differs from its contract source lock")
    if computational_source != dict(expected_computational_source):
        raise RuntimeError("Accepted local run is not bound to computational source A")
    return {
        "status": "PASS",
        "report_id": report.get("report_id"),
        "contract_sha256": contract_snapshot.sha256,
        "contract_size_bytes": contract_snapshot.size_bytes,
        "public_report_sha256": report_snapshot.sha256,
        "public_report_size_bytes": report_snapshot.size_bytes,
        "contract_verifier_sha256": verifier_snapshot.sha256,
        "candidate_id": report.get("candidate_id"),
        "source_archive_sha256": report.get("source_archive_sha256"),
        "source_archive_size_bytes": report.get("source_archive_size_bytes"),
        "computational_source": computational_source,
        "command_plan_sha256": report.get("command_plan_sha256"),
        "numerical_runtime_manifest_sha256": report.get(
            "numerical_runtime_manifest_sha256"
        ),
        "output_manifest_sha256": report.get("output_manifest_sha256"),
        "output_file_set_sha256": report.get("output_file_set_sha256"),
        "output_file_count": report.get("output_file_count"),
        "output_total_size_bytes": report.get("output_total_size_bytes"),
        # Private implementation detail for a second, post-consumption byte
        # check.  Callers must remove this map before serializing public output.
        "_signed_output_files": {
            entry["path"]: {
                "sha256": entry["sha256"],
                "size_bytes": entry["size_bytes"],
            }
            for entry in output_entries
        },
    }


def _plain_directory_entries(root: Path, label: str) -> tuple[set[str], set[str]]:
    """Enumerate one tree without following links or Windows reparse points."""

    files: set[str] = set()
    directories: set[str] = {""}
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise RuntimeError(f"{label} cannot be enumerated safely") from error
        for entry in entries:
            relative = (
                f"{relative_directory}/{entry.name}"
                if relative_directory
                else entry.name
            )
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise RuntimeError(f"{label} member cannot be inspected: {relative}") from error
            if (
                stat.S_ISLNK(metadata.st_mode)
                or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
            ):
                raise RuntimeError(f"{label} contains a link or reparse point: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
            else:
                raise RuntimeError(f"{label} contains a non-regular member: {relative}")
    return files, directories


def verify_attested_output_roots(
    output_root: Path,
    artifact_roots: dict[str, Path],
    signed_output_files: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Recheck every consumed result byte against the signed output manifest.

    This gate is intentionally run *after* scientific validation.  It ensures
    that the files actually consumed by a freeze still equal the files signed
    by the local production controller and that no unsigned file is present in
    any consumed artifact root.
    """

    root = Path(output_root)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise RuntimeError("Signed local-run output root cannot be inspected") from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or bool(getattr(root_metadata, "st_file_attributes", 0) & 0x400)
        or not stat.S_ISDIR(root_metadata.st_mode)
    ):
        raise RuntimeError("Signed local-run output root must be a plain directory")
    root = root.resolve(strict=True)
    if not isinstance(artifact_roots, dict) or not artifact_roots:
        raise RuntimeError("At least one consumed production artifact root is required")
    if not isinstance(signed_output_files, dict) or not signed_output_files:
        raise RuntimeError("Signed local-run output file map is missing")

    signed: dict[str, tuple[str, int]] = {}
    for relative, evidence in signed_output_files.items():
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or not isinstance(evidence, dict)
        ):
            raise RuntimeError("Signed local-run output file map is malformed")
        digest = evidence.get("sha256")
        size = evidence.get("size_bytes")
        if (
            not isinstance(digest, str)
            or not SHA256_PATTERN.fullmatch(digest)
            or type(size) is not int
            or size < 0
        ):
            raise RuntimeError("Signed local-run output evidence is malformed")
        signed[relative] = (digest, size)

    initial_output_files, initial_output_directories = _plain_directory_entries(
        root, "signed local-run output tree"
    )
    if initial_output_files != set(signed):
        raise RuntimeError("Signed local-run output tree differs from its manifest")

    validated_roots: dict[str, dict[str, Any]] = {}
    seen_prefixes: list[str] = []
    all_snapshots: list[FileSnapshot] = []
    combined_records: list[str] = []
    for label, raw_artifact_root in sorted(artifact_roots.items()):
        if not isinstance(label, str) or not label:
            raise RuntimeError("Consumed production artifact label is malformed")
        candidate = Path(raw_artifact_root)
        try:
            candidate_metadata = candidate.lstat()
        except OSError as error:
            raise RuntimeError(f"Consumed production artifact cannot be inspected: {label}") from error
        if (
            stat.S_ISLNK(candidate_metadata.st_mode)
            or bool(getattr(candidate_metadata, "st_file_attributes", 0) & 0x400)
            or not stat.S_ISDIR(candidate_metadata.st_mode)
        ):
            raise RuntimeError(f"Consumed production artifact is not a plain directory: {label}")
        candidate = candidate.resolve(strict=True)
        try:
            relative_root = candidate.relative_to(root).as_posix()
        except ValueError as error:
            raise RuntimeError(
                f"Consumed production artifact is outside the signed output root: {label}"
            ) from error
        if relative_root in {"", "."}:
            raise RuntimeError("The whole signed output root cannot be used as one artifact")
        for prefix in seen_prefixes:
            if (
                relative_root == prefix
                or relative_root.startswith(f"{prefix}/")
                or prefix.startswith(f"{relative_root}/")
            ):
                raise RuntimeError("Consumed production artifact roots overlap")
        seen_prefixes.append(relative_root)

        first_files, first_directories = _plain_directory_entries(
            candidate, f"consumed production artifact {label}"
        )
        actual_relative = {
            f"{relative_root}/{member}" for member in first_files
        }
        expected_relative = {
            name for name in signed if name.startswith(f"{relative_root}/")
        }
        if not expected_relative:
            raise RuntimeError(
                f"Consumed production artifact has no signed files: {label}"
            )
        if actual_relative != expected_relative:
            raise RuntimeError(
                f"Consumed production artifact file set differs from the signed manifest: {label}"
            )
        root_records: list[str] = []
        root_snapshots: list[FileSnapshot] = []
        for relative in sorted(actual_relative):
            member = root / Path(*relative.split("/"))
            snapshot = read_file_snapshot(
                member, f"signed consumed production file {relative}"
            )
            expected_digest, expected_size = signed[relative]
            if snapshot.sha256 != expected_digest or snapshot.size_bytes != expected_size:
                raise RuntimeError(
                    f"Consumed production file differs from the signed manifest: {relative}"
                )
            record = f"{relative}\0{snapshot.sha256}\0{snapshot.size_bytes}"
            root_records.append(record)
            combined_records.append(record)
            root_snapshots.append(snapshot)
            all_snapshots.append(snapshot)
        for snapshot in root_snapshots:
            recheck_file_snapshot(snapshot, f"post-consumption file in {label}")
        final_files, final_directories = _plain_directory_entries(
            candidate, f"consumed production artifact {label}"
        )
        if final_files != first_files or final_directories != first_directories:
            raise RuntimeError(
                f"Consumed production artifact changed during final recheck: {label}"
            )
        for snapshot in root_snapshots:
            recheck_file_snapshot(snapshot, f"final post-consumption file in {label}")
        validated_roots[label] = {
            "relative_root": relative_root,
            "file_count": len(root_snapshots),
            "file_set_sha256": hashlib.sha256(
                "\n".join(root_records).encode("utf-8")
            ).hexdigest(),
        }

    final_output_files, final_output_directories = _plain_directory_entries(
        root, "signed local-run output tree"
    )
    if (
        final_output_files != initial_output_files
        or final_output_directories != initial_output_directories
    ):
        raise RuntimeError("Signed local-run output tree changed during final recheck")

    return {
        "status": "PASS",
        "root_count": len(validated_roots),
        "file_count": len(all_snapshots),
        "consumed_file_set_sha256": hashlib.sha256(
            "\n".join(sorted(combined_records)).encode("utf-8")
        ).hexdigest(),
        "roots": validated_roots,
    }


def validate_tams_numerical_runtime_policy(runtime: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact environment emitted by the shared runtime producer."""

    if runtime.get("schema_version") != 1 or runtime.get("status") != "PASS":
        raise RuntimeError("TAMS numerical runtime policy did not pass")
    if runtime.get("numpy_version") != "1.23.5":
        raise RuntimeError("TAMS numerical runtime NumPy version changed")
    environment = _require_mapping(
        runtime.get("environment"), "TAMS numerical runtime environment"
    )
    expected_environment = {
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
    if environment != expected_environment:
        raise RuntimeError("TAMS numerical runtime environment changed")
    features = _require_mapping(
        runtime.get("selected_cpu_features"), "TAMS numerical CPU features"
    )
    required_enabled = {"AVX2", "FMA3"}
    required_disabled = {
        "AVX512F",
        "AVX512CD",
        "AVX512_KNL",
        "AVX512_KNM",
        "AVX512_SKX",
        "AVX512_CLX",
        "AVX512_CNL",
        "AVX512_ICL",
    }
    if set(features) != required_enabled | required_disabled:
        raise RuntimeError("TAMS numerical CPU-feature record changed")
    for name in required_enabled:
        _require_exact_bool(features.get(name), True, f"TAMS CPU feature {name}")
    for name in required_disabled:
        _require_exact_bool(features.get(name), False, f"TAMS CPU feature {name}")
    return {"environment": dict(environment), "selected_cpu_features": dict(features)}


def validate_tams_radial_convergence(
    data: dict[str, Any], *, snapshots: dict[str, FileSnapshot] | None = None
) -> dict[str, Any]:
    """Validate the declared fine-denominator radial-convergence calculation."""

    if set(data) != {
        "schema_version",
        "experiment",
        "definition",
        "pass_threshold_abs_fraction",
        "producer_contract",
        "numerical_runtime_policy",
        "run_artifacts",
        "runs",
        "comparisons",
        "pass",
    }:
        raise RuntimeError("TAMS radial-convergence schema changed")
    if _require_integer(data.get("schema_version"), "TAMS convergence schema") != 2:
        raise RuntimeError("TAMS radial-convergence schema version changed")
    if snapshots is None or set(snapshots) != set(tams_convergence_target_names()):
        raise RuntimeError("TAMS radial convergence requires its exact artifact snapshots")
    if data.get("experiment") != "final_TAMS_radial_convergence":
        raise RuntimeError("TAMS radial-convergence experiment changed")
    if data.get("definition") != "delta_(coarse_to_fine)=(X_fine-X_coarse)/X_fine":
        raise RuntimeError("TAMS radial-convergence definition changed")
    _require_close(
        data.get("pass_threshold_abs_fraction"),
        0.01,
        "TAMS radial-convergence threshold",
        rel_tol=0.0,
        abs_tol=0.0,
    )
    _require_exact_bool(data.get("pass"), True, "TAMS radial convergence")
    producer = _require_mapping(
        data.get("producer_contract"), "TAMS radial producer contract"
    )
    if set(producer) != {"run_generator", "comparator"}:
        raise RuntimeError("TAMS radial producer-contract role set changed")
    for role, filename in (
        ("run_generator", "tams_radial_convergence.py"),
        ("comparator", "compare_convergence.py"),
    ):
        _validate_snapshot_record(
            producer[role], snapshots[filename], filename, f"TAMS {role}"
        )
        current_source = (
            Path(__file__).resolve().parents[1] / "jj-tams-convergence" / filename
        )
        if read_file_snapshot(current_source, f"current TAMS {role}").sha256 != snapshots[
            filename
        ].sha256:
            raise RuntimeError(f"TAMS {role} differs from the reviewable release source")
    runtime_name = "NUMERICAL_RUNTIME_POLICY.json"
    _validate_snapshot_record(
        data.get("numerical_runtime_policy"),
        snapshots[runtime_name],
        runtime_name,
        "TAMS numerical runtime policy",
    )
    runtime = load_json_bytes(snapshots[runtime_name].data, "TAMS numerical runtime policy")
    validate_tams_numerical_runtime_policy(runtime)
    runs = _require_mapping(data.get("runs"), "TAMS radial-convergence runs")
    if set(runs) != {"1.0", "0.5", "0.25"}:
        raise RuntimeError("TAMS radial-convergence run set changed")
    run_artifacts = _require_mapping(
        data.get("run_artifacts"), "TAMS radial-convergence run artifacts"
    )
    if set(run_artifacts) != set(runs):
        raise RuntimeError("TAMS radial-convergence artifact run set changed")

    expected_run_keys = {
        "experiment",
        "jj_commit",
        "isochrone_family",
        "dR_kpc",
        "radial_nodes",
        "host_selector",
        "occurrence_branch",
        "selected_stellar_assembly_rows",
        "compact_remnant_rows_rejected",
        "compact_remnant_surface_weight_rejected_sum_pc-2",
        "C1",
        "domains",
    }
    expected_domain_keys = {
        "R_kpc",
        "N_G",
        "Lambda_ESHZ",
        "Lambda_earth10",
        "mean_f_HZ",
        "mean_f_earth10",
        "L2_over_L1",
    }
    expected_host_selector = (
        "5300<=Teff<=6000 K; age>=4.57 Gyr; thin+thick; "
        "Rstar<=PARSEC-TAMS(Teff); logg<7 remnant veto"
    )
    expected_occurrence = (
        "Bryson Model 1 hab2 constant-completeness + Kopparapu conservative HZ"
    )
    alpha, beta, gamma = -1.082, -0.839, -2.671
    power_integral = lambda lo, hi, exponent: (
        hi ** (exponent + 1.0) - lo ** (exponent + 1.0)
    ) / (exponent + 1.0)
    gbar = (
        10.0 ** (-11.839) * power_integral(3900.0, 5117.0, gamma + 3.16)
        + 10.0 ** (-16.769) * power_integral(5117.0, 6300.0, gamma + 4.49)
    ) / 2400.0
    expected_c1 = 1.0 / (
        power_integral(0.5, 2.5, alpha)
        * power_integral(0.2, 2.2, beta)
        * gbar
    )
    radial_frames: dict[str, pd.DataFrame] = {}
    for dr in TAMS_CONVERGENCE_DRS:
        key = str(dr)
        tag = _tams_dr_tag(dr)
        artifact_set = _require_mapping(
            run_artifacts[key], f"TAMS radial artifacts dR={dr}"
        )
        if set(artifact_set) != {
            "parameters_original",
            "parameters_runtime",
            "sfr_peaks_parameters",
            "radial_table",
            "result",
        }:
            raise RuntimeError(f"TAMS radial artifact roles changed for dR={dr}")
        names = {
            "parameters_original": f"parameters_original_dr{tag}.txt",
            "parameters_runtime": f"parameters_runtime_dr{tag}.txt",
            "sfr_peaks_parameters": f"sfrd_peaks_parameters_dr{tag}.txt",
            "radial_table": f"tams_radial_dr{tag}.csv",
            "result": f"tams_result_dr{tag}.json",
        }
        for role, filename in names.items():
            _validate_snapshot_record(
                artifact_set[role],
                snapshots[filename],
                filename,
                f"TAMS dR={dr} {role}",
            )
        if snapshots[names["sfr_peaks_parameters"]].sha256 != TAMS_TUTORIAL_SFR_SHA256:
            raise RuntimeError(
                f"TAMS sfrd_peaks_parameters differs from the pinned JJ tutorial2 file for dR={dr}"
            )
        captured_run = load_json_bytes(
            snapshots[names["result"]].data, f"TAMS dR={dr} result"
        )
        if captured_run != runs[key]:
            raise RuntimeError(f"TAMS embedded run differs from result bytes for dR={dr}")
        run = _require_mapping(runs[key], f"TAMS radial run dR={dr}")
        if set(run) != expected_run_keys:
            raise RuntimeError(f"TAMS radial run schema changed for dR={dr}")
        if (
            run.get("experiment") != "final_TAMS_radial_convergence"
            or run.get("jj_commit") != "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
            or run.get("isochrone_family") != "Padova"
            or run.get("host_selector") != expected_host_selector
            or run.get("occurrence_branch") != expected_occurrence
        ):
            raise RuntimeError(f"TAMS radial run definition changed for dR={dr}")
        _require_close(run.get("dR_kpc"), dr, f"TAMS dR={dr}", rel_tol=0.0, abs_tol=1e-15)
        expected_nodes = int(round((14.0 - 4.0) / dr)) + 1
        if _require_integer(run.get("radial_nodes"), f"TAMS nodes dR={dr}") != expected_nodes:
            raise RuntimeError(f"TAMS radial-node count changed for dR={dr}")
        _require_positive_integer(
            run.get("selected_stellar_assembly_rows"), f"TAMS selected rows dR={dr}"
        )
        compact_rows = _require_integer(
            run.get("compact_remnant_rows_rejected"), f"TAMS compact rows dR={dr}"
        )
        if compact_rows < 0:
            raise RuntimeError("TAMS compact-remnant row count is negative")
        _require_finite_nonnegative(
            run.get("compact_remnant_surface_weight_rejected_sum_pc-2"),
            f"TAMS compact-remnant weight dR={dr}",
        )
        _require_close(run.get("C1"), expected_c1, f"TAMS C1 dR={dr}", rel_tol=1e-14, abs_tol=1e-14)

        original_parameters = _parse_jj_parameter_bytes(
            snapshots[names["parameters_original"]].data,
            f"TAMS original parameters dR={dr}",
        )
        runtime_parameters = _parse_jj_parameter_bytes(
            snapshots[names["parameters_runtime"]].data,
            f"TAMS runtime parameters dR={dr}",
        )
        if set(original_parameters) != set(runtime_parameters):
            raise RuntimeError(f"TAMS parameter key set changed for dR={dr}")
        mutable = {"Rmin", "Rmax", "dR", "nprocess"}
        for name in set(original_parameters) - mutable:
            if original_parameters[name] != runtime_parameters[name]:
                raise RuntimeError(f"TAMS science parameter {name} changed for dR={dr}")
        for name in mutable:
            if name not in original_parameters or name not in runtime_parameters:
                raise RuntimeError(f"TAMS required parameter {name} is missing")
            if original_parameters[name][1:] != runtime_parameters[name][1:]:
                raise RuntimeError(f"TAMS parameter metadata changed for {name}, dR={dr}")
        target_values = {"Rmin": 4.0, "Rmax": 14.0, "dR": dr, "nprocess": 2.0}
        for name, expected_value in target_values.items():
            try:
                observed_value = float(runtime_parameters[name][0])
            except ValueError as error:
                raise RuntimeError(f"TAMS runtime parameter {name} is not numeric") from error
            if observed_value != expected_value:
                raise RuntimeError(f"TAMS runtime parameter {name} changed for dR={dr}")

        radial = read_csv_bytes(
            snapshots[names["radial_table"]].data,
            f"TAMS radial table dR={dr}",
            float_precision="round_trip",
        )
        radial_columns = (
            "R_kpc",
            "dN_dR",
            "dL1_dR",
            "dL2_dR",
            "Sigma_TAMS_pc-2",
            "Sigma_thick_TAMS_pc-2",
        )
        if tuple(radial.columns) != radial_columns or len(radial) != expected_nodes:
            raise RuntimeError(f"TAMS radial-table schema/size changed for dR={dr}")
        for column in radial_columns:
            radial[column] = pd.to_numeric(radial[column], errors="raise")
        if not np.isfinite(radial.to_numpy(dtype=float)).all():
            raise RuntimeError(f"TAMS radial table contains non-finite values for dR={dr}")
        expected_radius = np.linspace(4.0, 14.0, expected_nodes)
        if not np.allclose(
            radial.R_kpc.to_numpy(dtype=float),
            expected_radius,
            rtol=0.0,
            atol=1.0e-12,
        ):
            raise RuntimeError(f"TAMS radial grid changed for dR={dr}")
        nonnegative_columns = radial_columns[1:]
        if (radial.loc[:, nonnegative_columns] < 0.0).any().any():
            raise RuntimeError(f"TAMS radial table contains negative measures for dR={dr}")
        if np.any(radial.dL2_dR > radial.dL1_dR) or np.any(
            radial["Sigma_thick_TAMS_pc-2"] > radial["Sigma_TAMS_pc-2"]
        ):
            raise RuntimeError(f"TAMS radial physical ordering failed for dR={dr}")
        expected_dN = (
            2.0
            * math.pi
            * radial.R_kpc.to_numpy(dtype=float)
            * 1.0e6
            * radial["Sigma_TAMS_pc-2"].to_numpy(dtype=float)
        )
        if not np.allclose(
            radial.dN_dR.to_numpy(dtype=float), expected_dN, rtol=1e-12, atol=1e-6
        ):
            raise RuntimeError(f"TAMS radial dN/dR identity failed for dR={dr}")
        radial_frames[key] = radial

        domains = _require_mapping(run.get("domains"), f"TAMS domains dR={dr}")
        if set(domains) != {"lineweaver_7_9", "full_JJ_4_14"}:
            raise RuntimeError(f"TAMS domain set changed for dR={dr}")
        for domain, limits in (
            ("lineweaver_7_9", (7.0, 9.0)),
            ("full_JJ_4_14", (4.0, 14.0)),
        ):
            record = _require_mapping(domains[domain], f"TAMS {domain} dR={dr}")
            if set(record) != expected_domain_keys or record.get("R_kpc") != list(limits):
                raise RuntimeError(f"TAMS domain schema/range changed for {domain}, dR={dr}")
            selected = radial.loc[radial.R_kpc.between(*limits)]
            expected_integrals = {
                "N_G": float(np.trapz(selected.dN_dR, selected.R_kpc)),
                "Lambda_ESHZ": float(np.trapz(selected.dL1_dR, selected.R_kpc)),
                "Lambda_earth10": float(np.trapz(selected.dL2_dR, selected.R_kpc)),
            }
            for name, expected_value in expected_integrals.items():
                _require_close(
                    record.get(name),
                    expected_value,
                    f"TAMS {domain}:{name} dR={dr}",
                    rel_tol=1e-12,
                    abs_tol=1e-6,
                )
            n_value = _require_finite_number(record.get("N_G"), "TAMS N_G")
            l1_value = _require_finite_number(record.get("Lambda_ESHZ"), "TAMS L1")
            l2_value = _require_finite_number(record.get("Lambda_earth10"), "TAMS L2")
            if not (n_value > 0.0 and l1_value > 0.0 and 0.0 <= l2_value <= l1_value):
                raise RuntimeError(f"TAMS integrated ordering failed for {domain}, dR={dr}")
            for name, expected_value in (
                ("mean_f_HZ", l1_value / n_value),
                ("mean_f_earth10", l2_value / n_value),
                ("L2_over_L1", l2_value / l1_value),
            ):
                _require_close(
                    record.get(name),
                    expected_value,
                    f"TAMS {domain}:{name} dR={dr}",
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                )

    originals = [
        snapshots[f"parameters_original_dr{_tams_dr_tag(dr)}.txt"].data
        for dr in TAMS_CONVERGENCE_DRS
    ]
    if any(data_bytes != originals[0] for data_bytes in originals[1:]):
        raise RuntimeError("TAMS experiments did not start from one exact parameter file")
    sfr_inputs = [
        snapshots[f"sfrd_peaks_parameters_dr{_tams_dr_tag(dr)}.txt"].data
        for dr in TAMS_CONVERGENCE_DRS
    ]
    if any(data_bytes != sfr_inputs[0] for data_bytes in sfr_inputs[1:]):
        raise RuntimeError("TAMS experiments did not start from one exact SFR file")
    anchor = runs["0.5"]["domains"]["lineweaver_7_9"]
    for name, expected_value in (
        ("N_G", 263061992.36674243),
        ("Lambda_ESHZ", 105716685.0799756),
        ("Lambda_earth10", 3376462.6740267016),
    ):
        _require_close(
            anchor.get(name),
            expected_value,
            f"TAMS canonical 0.5-kpc anchor {name}",
            rel_tol=0.0,
            abs_tol=0.01,
        )
    comparisons = _require_mapping(
        data.get("comparisons"), "TAMS radial-convergence comparisons"
    )
    expected_domains = {"lineweaver_7_9", "full_JJ_4_14"}
    expected_steps = {"1.0_to_0.5", "0.5_to_0.25"}
    expected_quantities = {"N_G", "Lambda_ESHZ", "Lambda_earth10"}
    step_runs = {"1.0_to_0.5": ("1.0", "0.5"), "0.5_to_0.25": ("0.5", "0.25")}
    if set(comparisons) != expected_domains:
        raise RuntimeError("TAMS radial-convergence domain set changed")
    for domain in expected_domains:
        steps = _require_mapping(comparisons[domain], f"TAMS convergence {domain}")
        if set(steps) != expected_steps:
            raise RuntimeError(f"TAMS radial-convergence step set changed for {domain}")
        for step in expected_steps:
            quantities = _require_mapping(steps[step], f"TAMS convergence {domain}:{step}")
            if set(quantities) != expected_quantities:
                raise RuntimeError(
                    f"TAMS radial-convergence quantity set changed for {domain}:{step}"
                )
            for quantity, raw_record in quantities.items():
                record = _require_mapping(
                    raw_record, f"TAMS convergence {domain}:{step}:{quantity}"
                )
                if set(record) != {
                    "coarse",
                    "fine",
                    "delta_fraction",
                    "delta_percent",
                }:
                    raise RuntimeError(
                        f"TAMS convergence fields changed for {domain}:{step}:{quantity}"
                    )
                coarse = _require_finite_nonnegative(
                    record.get("coarse"), f"TAMS coarse {domain}:{step}:{quantity}"
                )
                fine = _require_finite_number(
                    record.get("fine"), f"TAMS fine {domain}:{step}:{quantity}"
                )
                if fine <= 0.0:
                    raise RuntimeError(f"TAMS fine value must be positive for {quantity}")
                delta = _require_finite_number(
                    record.get("delta_fraction"),
                    f"TAMS delta {domain}:{step}:{quantity}",
                )
                percent = _require_finite_number(
                    record.get("delta_percent"),
                    f"TAMS percent {domain}:{step}:{quantity}",
                )
                expected_delta = (fine - coarse) / fine
                coarse_run, fine_run = step_runs[step]
                expected_coarse = _require_finite_number(
                    runs[coarse_run]["domains"][domain][quantity],
                    f"TAMS source coarse {domain}:{step}:{quantity}",
                )
                expected_fine = _require_finite_number(
                    runs[fine_run]["domains"][domain][quantity],
                    f"TAMS source fine {domain}:{step}:{quantity}",
                )
                if not math.isclose(
                    delta, expected_delta, rel_tol=1.0e-12, abs_tol=1.0e-12
                ) or not math.isclose(
                    percent, 100.0 * delta, rel_tol=1.0e-12, abs_tol=1.0e-12
                ) or not math.isclose(
                    coarse, expected_coarse, rel_tol=1.0e-12, abs_tol=1.0e-6
                ) or not math.isclose(
                    fine, expected_fine, rel_tol=1.0e-12, abs_tol=1.0e-6
                ):
                    raise RuntimeError(
                        f"TAMS radial-convergence identity failed for {domain}:{step}:{quantity}"
                    )
                if domain == "lineweaver_7_9" and step == "0.5_to_0.25" and abs(delta) >= 0.01:
                    raise RuntimeError(f"TAMS radial-convergence gate failed for {quantity}")
    table = read_csv_bytes(
        snapshots[TAMS_CONVERGENCE_TABLE_NAME].data,
        "TAMS radial-convergence comparison table",
        float_precision="round_trip",
    )
    table_columns = (
        "domain",
        "coarse_dR_kpc",
        "fine_dR_kpc",
        "quantity",
        "coarse_value",
        "fine_value",
        "delta_fraction",
        "delta_percent",
    )
    if tuple(table.columns) != table_columns or len(table) != 12:
        raise RuntimeError("TAMS radial-convergence table schema/size changed")
    expected_rows: list[dict[str, Any]] = []
    for domain in ("lineweaver_7_9", "full_JJ_4_14"):
        for step, (coarse_run, fine_run) in step_runs.items():
            coarse_dr, fine_dr = map(float, (coarse_run, fine_run))
            for quantity in ("N_G", "Lambda_ESHZ", "Lambda_earth10"):
                record = comparisons[domain][step][quantity]
                expected_rows.append(
                    {
                        "domain": domain,
                        "coarse_dR_kpc": coarse_dr,
                        "fine_dR_kpc": fine_dr,
                        "quantity": quantity,
                        "coarse_value": record["coarse"],
                        "fine_value": record["fine"],
                        "delta_fraction": record["delta_fraction"],
                        "delta_percent": record["delta_percent"],
                    }
                )
    if table.domain.astype(str).tolist() != [row["domain"] for row in expected_rows] or table.quantity.astype(
        str
    ).tolist() != [row["quantity"] for row in expected_rows]:
        raise RuntimeError("TAMS radial-convergence table row identities changed")
    for column in table_columns[1:3] + table_columns[4:]:
        observed = pd.to_numeric(table[column], errors="raise").to_numpy(dtype=float)
        expected = np.asarray([row[column] for row in expected_rows], dtype=float)
        if not np.isfinite(observed).all() or not np.allclose(
            observed, expected, rtol=1.0e-12, atol=1.0e-12
        ):
            raise RuntimeError(f"TAMS radial-convergence table differs for {column}")
    return comparisons["lineweaver_7_9"]["0.5_to_0.25"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--host-artifact-contract", required=True, type=Path)
    parser.add_argument("--expected-host-artifact-contract-sha256", required=True)
    parser.add_argument("--expected-host-artifact-contract-size-bytes", required=True, type=int)
    parser.add_argument("--expected-host-qualification-report-sha256", required=True)
    parser.add_argument("--expected-host-qualification-report-size-bytes", required=True, type=int)
    parser.add_argument("--expected-computational-source-commit", required=True)
    parser.add_argument("--expected-computational-source-tree", required=True)
    parser.add_argument("--expected-computational-source-archive-sha256", required=True)
    parser.add_argument("--expected-computational-source-archive-size-bytes", required=True, type=int)
    parser.add_argument("--host-artifact-root", required=True, type=Path)
    parser.add_argument("--native-solar-tams-points", required=True, type=Path)
    parser.add_argument("--metallicity-audit-root", required=True, type=Path)
    parser.add_argument("--kepler-stars", required=True, type=Path)
    for selector in ("canonical", "legacy"):
        parser.add_argument(f"--{selector}-hosts", required=True, type=Path)
        for branch in ("constant", "zero"):
            parser.add_argument(
                f"--{selector}-{branch}-artifact-root", required=True, type=Path
            )
    parser.add_argument("--constant-posterior-samples", required=True, type=Path)
    parser.add_argument("--zero-posterior-samples", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    output = args.out.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise RuntimeError("Host/TAMS output directory must be absent or empty")
    (
        parent,
        parent_masks,
        parent_collapsed,
        parent_host_frames,
        parent_snapshot,
        parent_evidence,
    ) = validate_parent_artifact(args.parent)
    (
        _host_contract_result,
        host_contract_evidence,
        contract_summary_snapshot,
    ) = verify_host_artifact_contract_binding(
        args.host_artifact_contract,
        args.host_artifact_root,
        parent_host_frames["canonical"],
        expected_contract_sha256=args.expected_host_artifact_contract_sha256,
        expected_contract_size_bytes=args.expected_host_artifact_contract_size_bytes,
        expected_qualification_report_sha256=(
            args.expected_host_qualification_report_sha256
        ),
        expected_qualification_report_size_bytes=(
            args.expected_host_qualification_report_size_bytes
        ),
        expected_source_lock={
            "public_source": {
                "repository": "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline",
                "commit_sha": args.expected_computational_source_commit,
                "git_tree_sha": args.expected_computational_source_tree,
                "source_archive_sha256": args.expected_computational_source_archive_sha256,
                "source_archive_size_bytes": args.expected_computational_source_archive_size_bytes,
            },
            "private_source": {
                "repository": "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline-private-production",
                "commit_sha": args.expected_computational_source_commit,
                "git_tree_sha": args.expected_computational_source_tree,
                "source_archive_sha256": args.expected_computational_source_archive_sha256,
                "source_archive_size_bytes": args.expected_computational_source_archive_size_bytes,
            },
        },
    )
    contract_summary = load_json_bytes(
        contract_summary_snapshot.data, "contract-bound JJ host summary"
    )
    _require_close(
        contract_summary.get("N_G_hosts_age_ge_4p57_R7_9"),
        CANONICAL_N_STAR,
        "Contract-bound canonical host count",
        rel_tol=0.0,
        abs_tol=0.1,
    )
    metallicity_report, metallicity_evidence = verify_metallicity_audit_root(
        args.metallicity_audit_root,
        args.native_solar_tams_points,
        parent_evidence,
    )
    canonical = parent_masks["canonical"]
    legacy = parent_masks["legacy"]
    below_tams = parent.Rstar_g_Rsun.to_numpy() <= parent.R_TAMS_Rsun.to_numpy()
    compact_veto = below_tams & (parent.logg.to_numpy() >= 7.0)
    tams_radius_rejected = ~below_tams
    weights = parent.integrated_weight.to_numpy(dtype=float)
    parent_weight = float(np.sum(weights))
    canonical_summary = selection_summary(parent, canonical)
    _require_close(
        canonical_summary["N_star"],
        CANONICAL_N_STAR,
        "Canonical host count",
        rel_tol=0.0,
        abs_tol=0.1,
    )

    native_snapshot = read_file_snapshot(
        args.native_solar_tams_points, "native solar TAMS points used by host audit"
    )
    if native_snapshot.sha256 != metallicity_evidence["native_solar_tams_points_sha256"]:
        raise RuntimeError("Native solar TAMS points changed after metallicity verification")
    native, native_validation = validate_native_solar_points(native_snapshot)
    native_reference = _require_mapping(
        metallicity_report.get("native_solar_reference"),
        "metallicity native_solar_reference",
    )
    expected_native_reference = {
        "status": "PASS",
        "role": "validation_only_not_a_metallicity_correction",
        "metallicity_Z": 0.017,
        "points_file": NATIVE_SOLAR_POINTS_NAME,
        "points_sha256": metallicity_evidence[
            "native_solar_tams_points_sha256"
        ],
        "node_count": 9,
        "reference_validation_node_count": 7,
        "max_abs_temperature_difference_K": native_reference.get(
            "max_abs_temperature_difference_K"
        ),
        "max_relative_radius_difference": native_reference.get(
            "max_relative_radius_difference"
        ),
        "archive_lock_id": "parsec_tracks_z0017",
        "archive_filename": native_reference.get("archive_filename"),
        "archive_size_bytes": native_reference.get("archive_size_bytes"),
        "archive_sha256": native_reference.get("archive_sha256"),
    }
    if native_reference != expected_native_reference:
        raise RuntimeError("Unexpected native-solar reference schema or policy")
    for key, measured_key in (
        ("max_abs_temperature_difference_K", "max_abs_temperature_difference_K"),
        ("max_relative_radius_difference", "max_relative_radius_difference"),
    ):
        reported = float(native_reference[key])
        measured = float(native_validation[measured_key])
        if not math.isfinite(reported) or not math.isclose(
            reported, measured, rel_tol=1.0e-12, abs_tol=1.0e-12
        ):
            raise RuntimeError(f"Native-solar validation metric mismatch: {key}")
    if (
        not isinstance(native_reference["archive_filename"], str)
        or not native_reference["archive_filename"]
        or int(native_reference["archive_size_bytes"]) <= 0
    ):
        raise RuntimeError("Native-solar archive provenance is incomplete")
    _require_sha256(native_reference["archive_sha256"], "native-solar archive hash")
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
    if abs(legacy_plugin_summary["N_star"] - LEGACY_N_STAR) > 0.1:
        raise RuntimeError(
            f"Legacy host count mismatch: {legacy_plugin_summary['N_star']}"
        )
    derived_host_measures = {
        "canonical": derived_collapsed_host_measure(parent, canonical),
        "legacy": derived_collapsed_host_measure(parent, legacy),
    }

    jj_radius = parent.loc[canonical, "Rstar_g_Rsun"].to_numpy(dtype=float)
    jj_weight = weights[canonical]
    jj_q16, jj_median, jj_q84 = weighted_quantile(
        jj_radius, jj_weight, (0.16, 0.5, 0.84)
    )
    jj_mean = float(np.average(jj_radius, weights=jj_weight))
    jj_above_135 = float(np.sum(jj_weight[jj_radius > 1.35]) / np.sum(jj_weight))

    kepler, kepler_snapshot = read_csv_snapshot(
        args.kepler_stars,
        "Kepler stellar-radius diagnostic input",
        usecols=["teff", "radius"],
    )
    kepler = kepler.loc[
        pd.to_numeric(kepler.teff, errors="coerce").between(5300.0, 6000.0)
    ].copy()
    kepler.radius = pd.to_numeric(kepler.radius, errors="coerce")
    kepler = kepler.loc[np.isfinite(kepler.radius) & (kepler.radius > 0.0)].copy()
    if kepler.empty:
        raise RuntimeError("Kepler stellar-radius diagnostic sample is empty")
    kepler_mean = float(kepler.radius.mean())
    kepler_median = float(kepler.radius.median())
    kepler_above_135 = float(np.mean(kepler.radius.to_numpy() > 1.35))

    propagation_roots = {
        (selector, branch): getattr(
            args, f"{selector}_{branch}_artifact_root"
        )
        for selector in ("canonical", "legacy")
        for branch in ("constant", "zero")
    }
    posterior_paths = {
        "constant": args.constant_posterior_samples,
        "zero": args.zero_posterior_samples,
    }
    host_paths = {
        "canonical": args.canonical_hosts,
        "legacy": args.legacy_hosts,
    }
    propagation_summaries, propagation_evidence = validate_fresh_propagation_set(
        propagation_roots,
        posterior_paths=posterior_paths,
        host_paths=host_paths,
        parent_collapsed=parent_collapsed,
        parent_host_frames=parent_host_frames,
    )
    for selector, derived in derived_host_measures.items():
        reported = propagation_evidence[selector]["constant"]
        if (
            reported["distinct_host_temperatures"] != derived["row_count"]
            or abs(float(reported["host_count"]) - float(derived["N_star"])) > 0.1
            or reported["collapsed_host_sha256"]
            != derived["csv_sha256"]
        ):
            raise RuntimeError(
                f"Fresh {selector} propagation is not derived from the audited parent selector"
            )
    canonical_constant = propagation_summaries[("canonical", "constant")]
    canonical_zero = propagation_summaries[("canonical", "zero")]
    legacy_constant = propagation_summaries[("legacy", "constant")]
    legacy_zero = propagation_summaries[("legacy", "zero")]

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
            EXPECTED_HOST_STATUS if anchor_gate == "PASS" else anchor_gate
        ),
        "scope": "JJ 7--9 kpc host-selector validation; plug-in occurrence is diagnostic only.",
        "inputs": {
            "parent": parent_evidence,
            "host_artifact_contract": host_contract_evidence,
            "native_solar_tams_points": {
                "path": str(native_snapshot.path),
                "sha256": native_snapshot.sha256,
                "size_bytes": native_snapshot.size_bytes,
            },
            "kepler_stars": {
                "path": str(kepler_snapshot.path),
                "sha256": kepler_snapshot.sha256,
                "size_bytes": kepler_snapshot.size_bytes,
            },
            "constant_posterior_samples": propagation_evidence["canonical"][
                "constant"
            ]["posterior_artifact"],
            "zero_posterior_samples": propagation_evidence["canonical"]["zero"][
                "posterior_artifact"
            ],
            "canonical_hosts": propagation_evidence["canonical"]["constant"][
                "host_artifact"
            ],
            "legacy_hosts": propagation_evidence["legacy"]["constant"][
                "host_artifact"
            ],
            **{
                f"{selector}_{branch}": {
                    "artifact_root": propagation_evidence[selector][branch][
                        "artifact_root"
                    ],
                    "sha256": propagation_evidence[selector][branch][
                        "summary_sha256"
                    ],
                    "manifest_sha256": propagation_evidence[selector][branch][
                        "manifest_sha256"
                    ],
                }
                for selector in ("canonical", "legacy")
                for branch in ("constant", "zero")
            },
        },
        "verified_metallicity_artifact": metallicity_evidence,
        "fresh_propagation_validation": propagation_evidence,
        "derived_collapsed_host_measures": derived_host_measures,
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
        "metallicity_dependent_TAMS_audit": metallicity_report,
        "metallicity_correction_policy": {
            "applied": False,
            "publishable": False,
            "role": "EXCLUDED_OPEN_SYSTEMATIC",
            "interpretation": (
                "The independently verified differential correction is not "
                "publishable, is not applied to the host selector, and remains "
                "an explicit host-model systematic."
            ),
        },
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

    output.mkdir(parents=True, exist_ok=True)
    result = release_safe_evidence(result)
    result_path = output / "host_tams_audit.json"
    with result_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
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
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
