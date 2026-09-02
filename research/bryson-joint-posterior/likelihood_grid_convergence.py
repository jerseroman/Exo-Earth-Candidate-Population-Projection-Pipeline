#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
# This derivative is documented in MODIFICATIONS_BRYSON.md and remains under
# GPL-2.0-only. Modified by Roman Jerše on 2026-08-30; see that record.
"""Audit 31/61/121-cell convergence of the Bryson likelihood integral.

The point-process log likelihood is

    log L(theta) = sum_i log lambda(x_i | theta) - N_exp(theta).

The grid enters only the numerical approximation to ``N_exp``.  This audit
therefore evaluates the expected-count integral at three fixed grid sizes for
actual joint posterior rows, never for synthetic combinations of marginal
quantiles.  Every large scientific input is copied once into a private,
read-only snapshot while its locked SHA-256 is computed.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import stat
import tempfile
from typing import Any

import numpy as np
import pandas as pd
from astropy.io import fits
from scipy import __version__ as scipy_version
from scipy.interpolate import interp2d


ROOT = Path(__file__).resolve().parents[2]
DATA_LOCKS_PATH = ROOT / "provenance" / "DATA_LOCKS.json"
REPORT_NAME = "LIKELIHOOD_GRID_CONVERGENCE.json"
SELECTED_NAME = "selected_joint_parameter_points.csv"
MANIFEST_NAME = "SHA256SUMS_likelihood_grid_convergence.txt"
GRID_SIZES = (31, 61, 121)
PARAMETERS = ("F0", "alpha", "beta", "gamma")
IDENTIFIERS = ("global_trial", "production_step", "walker")
TAIL_QUANTILES = (0.025, 0.16, 0.84, 0.975)
RUNTIME_ENVIRONMENT_NAMES = (
    "NPY_DISABLE_CPU_FEATURES",
    "OPENBLAS_NUM_THREADS",
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "PYTHONHASHSEED",
)
EXPECTED_RUNTIME_ENVIRONMENT = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
EXPECTED_LIBRARY_VERSIONS = {
    "numpy": "1.23.5",
    "pandas": "1.5.3",
    "scipy": "1.10.1",
    "astropy": "5.3.4",
}
MAX_RELATIVE_NORM_DELTA = 5.0e-4
MAX_ABSOLUTE_LOGL_DELTA = 0.25
MAX_Q95_ABSOLUTE_LOGL_DELTA = 0.10
MAX_CENTRAL_RELATIVE_NORM_DELTA = 1.0e-4
MAX_CENTRAL_ABSOLUTE_LOGL_DELTA = 0.02
MAX_ABSOLUTE_DIAGONAL_RULE_DELTA = 0.05
MAX_RELATIVE_DIAGONAL_RULE_DELTA = 1.0e-4
MAX_CENTRAL_ABSOLUTE_DIAGONAL_RULE_DELTA = 0.01
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 2_000_000
CSV_COLUMNS = (
    "branch",
    "selection_labels",
    "posterior_row_number",
    "global_trial",
    "production_step",
    "walker",
    "F0",
    "alpha",
    "beta",
    "gamma",
    "norm_31",
    "norm_61",
    "norm_121",
    "norm_121_four_corner",
    "abs_delta_log_likelihood_61_121",
    "relative_norm_delta_61_121",
    "abs_delta_diagonal_vs_four_corner_121",
    "relative_delta_diagonal_vs_four_corner_121",
    "abs_delta_norm_31_61",
    "refinement_ratio_61_121_over_31_61",
    "is_central",
    "point_rate_grid_invariant",
)


class GridAuditError(RuntimeError):
    """Raised when a likelihood-grid artifact fails closed."""


def fail(message: str) -> None:
    raise GridAuditError(message)


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


@dataclass(frozen=True)
class Snapshot:
    path: Path
    sha256: str
    size_bytes: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_regular(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} must be a regular, non-symlink file: {path}")


def _require_directory(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_dir():
        fail(f"{description} must be a directory, not a symlink: {path}")


def snapshot_file(
    source: Path,
    destination: Path,
    description: str,
    *,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
) -> Snapshot:
    """Create one stable private copy and detect replacement during the read."""

    _require_regular(source, description)
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        fail(f"{description} must be a regular, non-symlink file: {source}")
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    # O_NOFOLLOW closes the final-component symlink race on POSIX.  The
    # lstat/fstat identity checks below retain fail-closed replacement
    # detection on platforms where that flag is unavailable.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as reader, destination.open("xb") as writer:
            opened_before = os.fstat(reader.fileno())
            if not stat.S_ISREG(opened_before.st_mode):
                fail(f"{description} changed to a non-regular file before reading")
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
            opened_after = os.fstat(reader.fileno())
    except OSError as exc:
        fail(f"cannot snapshot {description}: {exc}")
    after = source.lstat()
    if not stat.S_ISREG(after.st_mode):
        fail(f"{description} changed to a non-regular file while being snapshotted")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1 or size != opened_after.st_size:
        fail(f"{description} changed while it was being snapshotted")
    observed_sha256 = digest.hexdigest()
    if expected_sha256 is not None and observed_sha256 != expected_sha256:
        fail(
            f"locked SHA-256 mismatch for {description}: "
            f"{observed_sha256} != {expected_sha256}"
        )
    if expected_size_bytes is not None and size != expected_size_bytes:
        fail(
            f"locked size mismatch for {description}: "
            f"{size} != {expected_size_bytes}"
        )
    # Windows treats the read-only bit as an unlink barrier, which prevents
    # TemporaryDirectory cleanup. POSIX can retain the extra hardening without
    # making the verifier's private snapshot directory undeletable.
    if os.name != "nt":
        destination.chmod(stat.S_IRUSR)
    return Snapshot(destination.resolve(), observed_sha256, size)


def _reject_constant(token: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {token}")


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def strict_json_bytes(data: bytes, description: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse strict UTF-8 JSON {description}: {exc}")


def strict_json_file(path: Path) -> Any:
    _require_regular(path, "JSON input")
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        fail(f"JSON input exceeds {MAX_JSON_BYTES} bytes: {path}")
    return strict_json_bytes(data, str(path))


def _exact_keys(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    observed = set(value)
    if observed != keys:
        fail(
            f"{description} keys differ: missing={sorted(keys - observed)}, "
            f"extra={sorted(observed - keys)}"
        )
    return value


def _finite(value: Any, description: str, *, nonnegative: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (nonnegative and result < 0.0):
        fail(f"{description} must be finite" + (" and non-negative" if nonnegative else ""))
    return result


def load_data_locks(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = DATA_LOCKS_PATH
    document = strict_json_file(path)
    if not isinstance(document, dict) or not isinstance(document.get("locks"), dict):
        fail("DATA_LOCKS.json lacks the locks object")
    return document["locks"]


def locked_input(lock: dict[str, Any], lock_id: str) -> tuple[str, int, str]:
    try:
        item = lock[lock_id]
        digest = item["expected_sha256"]
        size = item["expected_size_bytes"]
        filename = item["filename"]
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid data lock {lock_id!r}: {exc}")
    if (
        not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or not is_portable_safe_leaf(filename)
    ):
        fail(f"unsafe data lock {lock_id!r}")
    return digest, size, filename


def parse_manifest_bytes(data: bytes, description: str) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        fail(f"cannot decode {description}: {exc}")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if match is None:
            fail(f"invalid {description} line {line_number}: {line!r}")
        digest, name = match.groups()
        if not is_portable_safe_leaf(name):
            fail(f"unsafe {description} filename at line {line_number}: {name!r}")
        if name in entries:
            fail(f"duplicate {description} entry: {name}")
        entries[name] = digest
    if not entries:
        fail(f"{description} is empty")
    return entries


def parse_manifest(path: Path, description: str) -> dict[str, str]:
    _require_regular(path, description)
    return parse_manifest_bytes(path.read_bytes(), description)


def _integer_series(frame: pd.DataFrame, name: str) -> np.ndarray:
    values = pd.to_numeric(frame[name], errors="coerce").to_numpy(dtype=float)
    if not np.all(np.isfinite(values)) or not np.all(values == np.floor(values)):
        fail(f"posterior identifier {name} is not exactly integral")
    return values.astype(np.int64)


def validate_posterior(frame: pd.DataFrame, branch: str) -> pd.DataFrame:
    required = {"branch", *IDENTIFIERS, *PARAMETERS}
    missing = required - set(frame.columns)
    if missing:
        fail(f"posterior is missing columns: {sorted(missing)}")
    if len(frame) < 100:
        fail("posterior has fewer than 100 rows")
    branches = set(frame["branch"].astype(str))
    if branches != {branch}:
        fail(f"posterior branch mismatch: {sorted(branches)}")
    clean = frame.copy()
    for name in IDENTIFIERS:
        clean[name] = _integer_series(clean, name)
        if (clean[name] < 0).any():
            fail(f"posterior identifier {name} is negative")
    if clean.loc[:, list(IDENTIFIERS)].duplicated().any():
        fail("posterior chain coordinates are duplicated")
    values = clean.loc[:, list(PARAMETERS)].apply(
        pd.to_numeric, errors="coerce"
    ).to_numpy(dtype=float)
    if not np.all(np.isfinite(values)):
        fail("posterior contains non-finite parameters")
    clean.loc[:, list(PARAMETERS)] = values
    clean.insert(0, "posterior_row_number", np.arange(2, len(clean) + 2))
    clean.sort_values(list(IDENTIFIERS), kind="mergesort", inplace=True)
    clean.reset_index(drop=True, inplace=True)
    return clean


def select_joint_parameter_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Select one multivariate centre and sixteen actual marginal-tail rows."""

    values = frame.loc[:, list(PARAMETERS)].to_numpy(dtype=float)
    medians = np.quantile(values, 0.50, axis=0)
    q16 = np.quantile(values, 0.16, axis=0)
    q84 = np.quantile(values, 0.84, axis=0)
    scales = q84 - q16
    if not np.all(np.isfinite(scales)) or np.any(scales <= 0.0):
        fail("posterior has a degenerate marginal q16-q84 width")
    distance = np.sum(((values - medians) / scales) ** 2, axis=1)
    if not np.all(np.isfinite(distance)):
        fail("non-finite robust distance in posterior selection")

    labels_by_index: dict[int, list[str]] = {}
    central_index = int(np.argmin(distance))
    labels_by_index.setdefault(central_index, []).append("central")
    for parameter_index, parameter in enumerate(PARAMETERS):
        column = values[:, parameter_index]
        for quantile in TAIL_QUANTILES:
            target = float(np.quantile(column, quantile))
            row_index = int(np.argmin(np.abs(column - target)))
            labels_by_index.setdefault(row_index, []).append(
                f"{parameter}:q{quantile:g}"
            )

    selected = frame.iloc[sorted(labels_by_index)].copy()
    selected.insert(
        1,
        "selection_labels",
        [";".join(sorted(labels_by_index[index])) for index in sorted(labels_by_index)],
    )
    selected.insert(
        2,
        "is_central",
        ["central" in labels_by_index[index] for index in sorted(labels_by_index)],
    )
    if len(selected) < 5 or len(selected) > 17 or int(selected["is_central"].sum()) != 1:
        fail("joint-posterior selection cardinality is invalid")
    return selected


def load_rate_model_module(source_path: Path):
    spec = importlib.util.spec_from_file_location(
        "locked_rateModels3D_grid_audit", source_path
    )
    if spec is None or spec.loader is None:
        fail("cannot create an import specification for rateModels3D.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if Path(module.__file__).resolve() != source_path.resolve():
        fail("loaded rate-model source path differs from the snapshot")
    if sha256_file(source_path) != sha256_file(Path(module.__file__)):
        fail("loaded rate-model source bytes differ from the snapshot")
    return module


def load_completeness_arrays(path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    try:
        with fits.open(path, memmap=False) as hdulist:
            if (
                len(hdulist) != 2
                or getattr(hdulist[1].data, "shape", None) != (68885,)
            ):
                fail("completeness FITS HDU structure differs from the locked inputs")
            cumulative = np.asarray(hdulist[0].data)
            header = hdulist[0].header.copy()
    except (OSError, ValueError) as exc:
        fail(f"cannot load completeness FITS: {exc}")
    if cumulative.ndim != 3 or cumulative.shape[0] != 13:
        fail(f"unexpected completeness array shape: {cumulative.shape!r}")
    if not np.all(np.isfinite(cumulative)):
        fail("completeness FITS contains non-finite values")
    try:
        n_period = int(header["NPER"])
        n_radius = int(header["NRP"])
        n_teff = int(header["NTEFF"])
        flux_grid = np.linspace(
            float(header["MAXFLX"]), float(header["MINFLX"]), n_period
        )
        radius_grid = np.linspace(
            float(header["MINRP"]), float(header["MAXRP"]), n_radius
        )
        mean_teff = np.asarray(
            [float(header[f"MEANT{index}"]) for index in range(n_teff)],
            dtype=float,
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid completeness FITS header: {exc}")
    if cumulative.shape[1:] != (n_radius, n_period) or n_teff != 10:
        fail("completeness FITS header/array dimensions differ")
    if not all(np.all(np.isfinite(item)) for item in (flux_grid, radius_grid, mean_teff)):
        fail("completeness coordinate arrays are non-finite")
    return cumulative[3:, :, :], flux_grid, radius_grid, mean_teff


def build_completeness_on_grid(
    probability: np.ndarray,
    source_flux: np.ndarray,
    source_radius: np.ndarray,
    comp_space: Any,
) -> np.ndarray:
    result = np.zeros(
        (comp_space.nPeriod, comp_space.nRp, probability.shape[0]), dtype=float
    )
    for index in range(probability.shape[0]):
        interpolator = interp2d(
            source_flux, source_radius, probability[index, :, :]
        )
        result[:, :, index] = np.transpose(
            interpolator(comp_space.period1D, comp_space.rp1D)
        )
    if not np.all(np.isfinite(result)) or np.any(result < 0.0):
        fail("interpolated completeness is non-finite or negative")
    return result


def expected_count(
    theta_source_order: np.ndarray,
    comp_space: Any,
    model: Any,
    summed_completeness: np.ndarray,
    mean_teff: np.ndarray,
    *,
    cell_rule: str = "source_diagonal",
) -> float:
    result = 0.0
    with np.errstate(all="ignore"):
        for index in range(comp_space.nTemp):
            rate = model.rateModel(
                comp_space.period2D,
                comp_space.rp2D,
                np.asarray(mean_teff[index]),
                comp_space.periodRange,
                comp_space.rpRange,
                comp_space.tempRange,
                theta_source_order,
            )
            population = rate * summed_completeness[:, :, index]
            if cell_rule == "source_diagonal":
                population = 0.5 * (
                    population[:-1, :-1] + population[1:, 1:]
                )
            elif cell_rule == "four_corner_trapezoid":
                population = 0.25 * (
                    population[:-1, :-1]
                    + population[:-1, 1:]
                    + population[1:, :-1]
                    + population[1:, 1:]
                )
            else:
                fail(f"unknown expected-count cell rule: {cell_rule!r}")
            result += float(np.sum(population * comp_space.vol2D))
    if not math.isfinite(result) or result < 0.0:
        fail("expected-count integral is non-finite or negative")
    return result


def evaluate_grids(
    selected: pd.DataFrame,
    rate_model_module: Any,
    completeness: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray],
) -> tuple[dict[int, list[float]], list[float], bool]:
    probability, source_flux, source_radius, mean_teff = completeness
    theta = selected.loc[:, ["F0", "beta", "alpha", "gamma"]].to_numpy(
        dtype=float
    )
    norms: dict[int, list[float]] = {}
    four_corner_121: list[float] | None = None
    point_rates: dict[int, np.ndarray] = {}
    probe_flux = np.asarray([0.21, 0.73, 2.19], dtype=float)
    probe_radius = np.asarray([0.51, 1.0, 2.49], dtype=float)
    probe_teff = np.asarray([3901.0, 5117.0, 6299.0], dtype=float)
    for size in GRID_SIZES:
        comp_space = rate_model_module.compSpace(
            periodName="Instellation",
            periodUnits="Iearth",
            periodRange=(0.2, 2.2),
            nPeriod=size,
            radiusName="Radius",
            radiusUnits="Rearth",
            rpRange=(0.5, 2.5),
            nRp=size,
            tempName="Teff",
            tempUnits="K",
            tempRange=(3900, 6300),
            nTemp=10,
        )
        model = rate_model_module.triplePowerLawTeffAvg(comp_space)
        summed = build_completeness_on_grid(
            probability, source_flux, source_radius, comp_space
        )
        norms[size] = [
            expected_count(row, comp_space, model, summed, mean_teff)
            for row in theta
        ]
        if size == 121:
            four_corner_121 = [
                expected_count(
                    row,
                    comp_space,
                    model,
                    summed,
                    mean_teff,
                    cell_rule="four_corner_trapezoid",
                )
                for row in theta
            ]
        point_rates[size] = np.vstack(
            [
                model.rateModel(
                    probe_flux,
                    probe_radius,
                    probe_teff,
                    comp_space.periodRange,
                    comp_space.rpRange,
                    comp_space.tempRange,
                    row,
                )
                for row in theta
            ]
        )
    invariant = all(
        np.array_equal(point_rates[GRID_SIZES[0]], point_rates[size])
        for size in GRID_SIZES[1:]
    )
    if not invariant:
        fail("point-rate term unexpectedly changes with quadrature grid size")
    if four_corner_121 is None:
        fail("four-corner 121-grid comparison was not evaluated")
    return norms, four_corner_121, invariant


def attach_results(
    selected: pd.DataFrame,
    branch: str,
    norms: dict[int, list[float]],
    four_corner_121: list[float],
    invariant: bool,
) -> pd.DataFrame:
    output = selected.loc[
        :, ["selection_labels", "is_central", "posterior_row_number", *IDENTIFIERS, *PARAMETERS]
    ].copy()
    output.insert(0, "branch", branch)
    for size in GRID_SIZES:
        output[f"norm_{size}"] = np.asarray(norms[size], dtype=float)
    output["norm_121_four_corner"] = np.asarray(
        four_corner_121, dtype=float
    )
    fine_delta = np.abs(output["norm_121"] - output["norm_61"])
    coarse_delta = np.abs(output["norm_61"] - output["norm_31"])
    rule_delta = np.abs(
        output["norm_121"] - output["norm_121_four_corner"]
    )
    output["abs_delta_log_likelihood_61_121"] = fine_delta
    output["relative_norm_delta_61_121"] = fine_delta / np.maximum(
        np.abs(output["norm_121"]), np.finfo(float).tiny
    )
    output["abs_delta_diagonal_vs_four_corner_121"] = rule_delta
    output["relative_delta_diagonal_vs_four_corner_121"] = (
        rule_delta
        / np.maximum(
            np.abs(output["norm_121_four_corner"]), np.finfo(float).tiny
        )
    )
    output["abs_delta_norm_31_61"] = coarse_delta
    output["refinement_ratio_61_121_over_31_61"] = fine_delta / np.maximum(
        coarse_delta, np.finfo(float).tiny
    )
    output["point_rate_grid_invariant"] = invariant
    output = output.loc[:, list(CSV_COLUMNS)]
    return output


def summarize_results(frame: pd.DataFrame) -> dict[str, Any]:
    fine = frame["abs_delta_log_likelihood_61_121"].to_numpy(dtype=float)
    relative = frame["relative_norm_delta_61_121"].to_numpy(dtype=float)
    rule_absolute = frame[
        "abs_delta_diagonal_vs_four_corner_121"
    ].to_numpy(dtype=float)
    rule_relative = frame[
        "relative_delta_diagonal_vs_four_corner_121"
    ].to_numpy(dtype=float)
    central = frame.loc[frame["is_central"]]
    if len(central) != 1:
        fail("result table must contain exactly one central point")
    central_abs = float(central.iloc[0]["abs_delta_log_likelihood_61_121"])
    central_relative = float(central.iloc[0]["relative_norm_delta_61_121"])
    central_rule_absolute = float(
        central.iloc[0]["abs_delta_diagonal_vs_four_corner_121"]
    )
    q95 = float(np.quantile(fine, 0.95))
    accepted = bool(
        np.max(fine) <= MAX_ABSOLUTE_LOGL_DELTA
        and np.max(relative) <= MAX_RELATIVE_NORM_DELTA
        and q95 <= MAX_Q95_ABSOLUTE_LOGL_DELTA
        and central_abs <= MAX_CENTRAL_ABSOLUTE_LOGL_DELTA
        and central_relative <= MAX_CENTRAL_RELATIVE_NORM_DELTA
        and np.max(rule_absolute) <= MAX_ABSOLUTE_DIAGONAL_RULE_DELTA
        and np.max(rule_relative) <= MAX_RELATIVE_DIAGONAL_RULE_DELTA
        and central_rule_absolute
        <= MAX_CENTRAL_ABSOLUTE_DIAGONAL_RULE_DELTA
        and frame["point_rate_grid_invariant"].eq(True).all()
    )
    return {
        "selected_point_count": int(len(frame)),
        "maximum_absolute_log_likelihood_delta_61_121": float(np.max(fine)),
        "maximum_relative_norm_delta_61_121": float(np.max(relative)),
        "q95_absolute_log_likelihood_delta_61_121": q95,
        "central_absolute_log_likelihood_delta_61_121": central_abs,
        "central_relative_norm_delta_61_121": central_relative,
        "maximum_absolute_diagonal_vs_four_corner_delta_121": float(
            np.max(rule_absolute)
        ),
        "maximum_relative_diagonal_vs_four_corner_delta_121": float(
            np.max(rule_relative)
        ),
        "central_absolute_diagonal_vs_four_corner_delta_121": (
            central_rule_absolute
        ),
        "maximum_absolute_norm_delta_31_61": float(
            np.max(frame["abs_delta_norm_31_61"].to_numpy(dtype=float))
        ),
        "maximum_refinement_ratio": float(
            np.max(
                frame[
                    "refinement_ratio_61_121_over_31_61"
                ].to_numpy(dtype=float)
            )
        ),
        "point_rate_grid_invariant": True,
        "accepted": accepted,
    }


def _thresholds() -> dict[str, float]:
    return {
        "maximum_absolute_log_likelihood_delta_61_121": MAX_ABSOLUTE_LOGL_DELTA,
        "maximum_relative_norm_delta_61_121": MAX_RELATIVE_NORM_DELTA,
        "maximum_q95_absolute_log_likelihood_delta_61_121": MAX_Q95_ABSOLUTE_LOGL_DELTA,
        "maximum_central_absolute_log_likelihood_delta_61_121": MAX_CENTRAL_ABSOLUTE_LOGL_DELTA,
        "maximum_central_relative_norm_delta_61_121": MAX_CENTRAL_RELATIVE_NORM_DELTA,
        "maximum_absolute_diagonal_vs_four_corner_delta_121": (
            MAX_ABSOLUTE_DIAGONAL_RULE_DELTA
        ),
        "maximum_relative_diagonal_vs_four_corner_delta_121": (
            MAX_RELATIVE_DIAGONAL_RULE_DELTA
        ),
        "maximum_central_absolute_diagonal_vs_four_corner_delta_121": (
            MAX_CENTRAL_ABSOLUTE_DIAGONAL_RULE_DELTA
        ),
    }


def _method() -> dict[str, Any]:
    return {
        "likelihood_identity": "sum(log(point_rate)) - expected_count",
        "grid_dependent_term": "expected_count only",
        "expected_count_cell_rule": "0.5*(lower-left+upper-right)*cell_area",
        "comparison_cell_rule": (
            "0.25*(lower-left+lower-right+upper-left+upper-right)*cell_area"
        ),
        "grid_sizes": list(GRID_SIZES),
        "selection": (
            "one actual joint row nearest the four marginal medians in "
            "q16-q84-scaled Euclidean distance, plus one actual row nearest "
            "each q={0.025,0.16,0.84,0.975} for each parameter; deterministic "
            "tie-break after sorting by global_trial, production_step, walker"
        ),
        "refinement_ratio_role": "diagnostic_only_nonmonotonic_convergence_allowed",
    }


def _runtime() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scipy": scipy_version,
        "astropy": __import__("astropy").__version__,
        "environment": {
            name: os.environ.get(name)
            for name in RUNTIME_ENVIRONMENT_NAMES
        },
    }


def validate_runtime() -> dict[str, Any]:
    runtime = _runtime()
    if not str(runtime["python"]).startswith("3.10."):
        fail(f"Python 3.10.x is required, found {runtime['python']}")
    observed_versions = {
        name: runtime[name] for name in EXPECTED_LIBRARY_VERSIONS
    }
    if observed_versions != EXPECTED_LIBRARY_VERSIONS:
        fail(
            "likelihood-grid library versions differ: "
            f"{observed_versions!r} != {EXPECTED_LIBRARY_VERSIONS!r}"
        )
    if runtime["environment"] != EXPECTED_RUNTIME_ENVIRONMENT:
        fail(
            "likelihood-grid numerical environment differs: "
            f"{runtime['environment']!r} != {EXPECTED_RUNTIME_ENVIRONMENT!r}"
        )
    return runtime


def write_manifest(root: Path) -> None:
    targets = (SELECTED_NAME, REPORT_NAME)
    (root / MANIFEST_NAME).write_text(
        "".join(f"{sha256_file(root / name)}  {name}\n" for name in targets),
        encoding="utf-8",
        newline="\n",
    )


def run_audit(args: argparse.Namespace) -> dict[str, Any]:
    runtime = validate_runtime()
    locks = load_data_locks()
    source_lock = locked_input(locks, "bryson_rate_models_3d")
    completeness_lock_id = (
        "completeness_constant" if args.branch == "constant" else "completeness_zero"
    )
    completeness_lock = locked_input(locks, completeness_lock_id)
    expected_posterior_name = f"joint_posterior_{args.branch}_full.csv.gz"
    if (
        not is_portable_safe_leaf(args.posterior.name)
        or args.posterior.name != expected_posterior_name
    ):
        fail(f"posterior filename must be {expected_posterior_name}")
    aggregate_manifest_name = args.aggregate_manifest.name
    if not is_portable_safe_leaf(aggregate_manifest_name):
        fail("aggregate manifest path must end in one portable safe filename")

    output = args.out.resolve()
    if output.exists():
        _require_directory(output, "output root")
        if any(output.iterdir()):
            fail("output root must be empty")
    else:
        output.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="likelihood-grid-audit-") as temporary:
        temporary_root = Path(temporary)
        source = snapshot_file(
            args.rate_model_source,
            temporary_root / "rateModels3D.py",
            "Bryson rate-model source",
            expected_sha256=source_lock[0],
            expected_size_bytes=source_lock[1],
        )
        completeness = snapshot_file(
            args.completeness,
            temporary_root / completeness_lock[2],
            "completeness FITS",
            expected_sha256=completeness_lock[0],
            expected_size_bytes=completeness_lock[1],
        )
        posterior = snapshot_file(
            args.posterior,
            temporary_root / expected_posterior_name,
            "joint posterior",
        )
        aggregate_manifest = snapshot_file(
            args.aggregate_manifest,
            temporary_root / aggregate_manifest_name,
            "aggregate manifest",
        )
        aggregate_entries = parse_manifest(
            aggregate_manifest.path, "aggregate manifest"
        )
        if aggregate_entries.get(expected_posterior_name) != posterior.sha256:
            fail("aggregate manifest does not bind the supplied full posterior")

        frame = pd.read_csv(
            posterior.path, compression="gzip", float_precision="round_trip"
        )
        frame = validate_posterior(frame, args.branch)
        selected = select_joint_parameter_rows(frame)
        module = load_rate_model_module(source.path)
        arrays = load_completeness_arrays(completeness.path)
        norms, four_corner_121, invariant = evaluate_grids(
            selected, module, arrays
        )
        result_frame = attach_results(
            selected,
            args.branch,
            norms,
            four_corner_121,
            invariant,
        )

    result_frame.to_csv(
        output / SELECTED_NAME,
        index=False,
        lineterminator="\n",
        float_format="%.17g",
    )
    results = summarize_results(result_frame)
    selected_sha = sha256_file(output / SELECTED_NAME)
    report = {
        "schema_version": 1,
        "status": "PASS" if results["accepted"] else "FAIL",
        "branch": args.branch,
        "method": _method(),
        "thresholds": _thresholds(),
        "inputs": {
            "rate_model_source": {
                "filename": source_lock[2],
                "sha256": source.sha256,
                "size_bytes": source.size_bytes,
                "lock_id": "bryson_rate_models_3d",
            },
            "completeness": {
                "filename": completeness_lock[2],
                "sha256": completeness.sha256,
                "size_bytes": completeness.size_bytes,
                "lock_id": completeness_lock_id,
            },
            "posterior": {
                "filename": expected_posterior_name,
                "sha256": posterior.sha256,
                "size_bytes": posterior.size_bytes,
                "row_count": int(len(frame)),
            },
            "aggregate_manifest": {
                "filename": aggregate_manifest_name,
                "sha256": aggregate_manifest.sha256,
                "size_bytes": aggregate_manifest.size_bytes,
            },
        },
        "selected_points": {
            "filename": SELECTED_NAME,
            "sha256": selected_sha,
            "size_bytes": (output / SELECTED_NAME).stat().st_size,
            "row_count": int(len(result_frame)),
            "columns": list(CSV_COLUMNS),
        },
        "results": results,
        "runtime": runtime,
    }
    (output / REPORT_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_manifest(output)
    if report["status"] != "PASS":
        fail("likelihood grid convergence thresholds failed")
    return report


def _read_result_csv(path: Path, branch: str) -> pd.DataFrame:
    _require_regular(path, "selected-point table")
    try:
        frame = pd.read_csv(
            path,
            dtype={"selection_labels": str, "branch": str},
            float_precision="round_trip",
        )
    except (OSError, pd.errors.ParserError) as exc:
        fail(f"cannot read selected-point table: {exc}")
    if tuple(frame.columns) != CSV_COLUMNS:
        fail(f"selected-point columns differ: {list(frame.columns)!r}")
    if set(frame["branch"]) != {branch}:
        fail("selected-point branch differs")
    if len(frame) < 5 or len(frame) > 17:
        fail("selected-point row count is outside 5..17")
    for column in (
        "posterior_row_number",
        *IDENTIFIERS,
        *PARAMETERS,
        "norm_31",
        "norm_61",
        "norm_121",
        "norm_121_four_corner",
        "abs_delta_log_likelihood_61_121",
        "relative_norm_delta_61_121",
        "abs_delta_diagonal_vs_four_corner_121",
        "relative_delta_diagonal_vs_four_corner_121",
        "abs_delta_norm_31_61",
        "refinement_ratio_61_121_over_31_61",
    ):
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float)
        if not np.all(np.isfinite(values)):
            fail(f"selected-point column {column} contains non-finite values")
        frame[column] = values
    for column in ("is_central", "point_rate_grid_invariant"):
        text_values = frame[column].astype(str).str.lower()
        if not text_values.isin(("true", "false")).all():
            fail(f"selected-point column {column} is not strict Boolean text")
        frame[column] = text_values.eq("true")
    fine = np.abs(frame["norm_121"] - frame["norm_61"])
    relative = fine / np.maximum(np.abs(frame["norm_121"]), np.finfo(float).tiny)
    rule = np.abs(frame["norm_121"] - frame["norm_121_four_corner"])
    rule_relative = rule / np.maximum(
        np.abs(frame["norm_121_four_corner"]), np.finfo(float).tiny
    )
    coarse = np.abs(frame["norm_61"] - frame["norm_31"])
    ratio = fine / np.maximum(coarse, np.finfo(float).tiny)
    for observed, declared, description in (
        (fine, frame["abs_delta_log_likelihood_61_121"], "fine absolute delta"),
        (relative, frame["relative_norm_delta_61_121"], "fine relative delta"),
        (
            rule,
            frame["abs_delta_diagonal_vs_four_corner_121"],
            "diagonal-rule absolute delta",
        ),
        (
            rule_relative,
            frame["relative_delta_diagonal_vs_four_corner_121"],
            "diagonal-rule relative delta",
        ),
        (coarse, frame["abs_delta_norm_31_61"], "coarse absolute delta"),
        (ratio, frame["refinement_ratio_61_121_over_31_61"], "refinement ratio"),
    ):
        if not np.allclose(observed, declared, rtol=2.0e-15, atol=2.0e-15):
            fail(f"selected-point {description} is not reproducible")
    return frame


def _verify_likelihood_grid_artifact_in_snapshot_root(
    root: Path,
    *,
    branch: str,
    posterior_path: Path,
    aggregate_manifest_path: Path,
    rate_model_source_path: Path,
    completeness_path: Path,
    temporary_root: Path,
) -> dict[str, Any]:
    """Implementation operating inside an already managed private directory."""

    _require_directory(root, "likelihood-grid artifact root")
    expected_files = {REPORT_NAME, SELECTED_NAME, MANIFEST_NAME}
    children = list(root.iterdir())
    actual_files = {path.name for path in children}
    if actual_files != expected_files or any(
        path.is_symlink() or not path.is_file() for path in children
    ):
        fail("likelihood-grid artifact root file set differs")

    posterior_original_name = posterior_path.name
    aggregate_original_name = aggregate_manifest_path.name
    expected_posterior_name = f"joint_posterior_{branch}_full.csv.gz"
    if (
        not is_portable_safe_leaf(posterior_original_name)
        or posterior_original_name != expected_posterior_name
    ):
        fail(f"posterior filename must be {expected_posterior_name}")
    if not is_portable_safe_leaf(aggregate_original_name):
        fail("aggregate manifest path must end in one portable safe filename")
    locks = load_data_locks()
    source_lock = locked_input(locks, "bryson_rate_models_3d")
    completeness_lock_id = (
        "completeness_constant" if branch == "constant" else "completeness_zero"
    )
    completeness_lock = locked_input(locks, completeness_lock_id)
    manifest_snapshot = snapshot_file(
        root / MANIFEST_NAME,
        temporary_root / "artifact-manifest.txt",
        "likelihood-grid manifest",
    )
    selected_snapshot = snapshot_file(
        root / SELECTED_NAME,
        temporary_root / "selected-points.csv",
        "selected-point table",
    )
    report_snapshot = snapshot_file(
        root / REPORT_NAME,
        temporary_root / "report.json",
        "likelihood-grid report",
    )
    posterior_snapshot = snapshot_file(
        posterior_path,
        temporary_root / "posterior.csv.gz",
        "full posterior",
    )
    aggregate_snapshot = snapshot_file(
        aggregate_manifest_path,
        temporary_root / "aggregate-manifest.txt",
        "aggregate manifest",
    )
    source_snapshot = snapshot_file(
        rate_model_source_path,
        temporary_root / "rateModels3D.py",
        "Bryson rate-model source",
        expected_sha256=source_lock[0],
        expected_size_bytes=source_lock[1],
    )
    completeness_snapshot = snapshot_file(
        completeness_path,
        temporary_root / completeness_lock[2],
        "completeness FITS",
        expected_sha256=completeness_lock[0],
        expected_size_bytes=completeness_lock[1],
    )
    manifest = parse_manifest(
        manifest_snapshot.path, "likelihood-grid manifest"
    )
    if list(manifest) != [SELECTED_NAME, REPORT_NAME]:
        fail("likelihood-grid manifest order or target set differs")
    artifact_snapshots = {
        SELECTED_NAME: selected_snapshot,
        REPORT_NAME: report_snapshot,
    }
    for name, expected in manifest.items():
        if artifact_snapshots[name].sha256 != expected:
            fail(f"likelihood-grid manifest hash mismatch for {name}")

    report = _exact_keys(
        strict_json_file(report_snapshot.path),
        {
            "schema_version",
            "status",
            "branch",
            "method",
            "thresholds",
            "inputs",
            "selected_points",
            "results",
            "runtime",
        },
        "likelihood-grid report",
    )
    if report["schema_version"] != 1 or report["status"] != "PASS" or report["branch"] != branch:
        fail("likelihood-grid report identity or status differs")
    if report["method"] != _method():
        fail("likelihood-grid method differs from the locked method")
    if report["thresholds"] != _thresholds():
        fail("likelihood-grid thresholds differ from the locked policy")
    runtime = _exact_keys(
        report["runtime"],
        {"python", "platform", "numpy", "pandas", "scipy", "astropy", "environment"},
        "likelihood-grid runtime",
    )
    if not isinstance(runtime["platform"], str) or not runtime["platform"]:
        fail("likelihood-grid runtime platform is empty")
    if not str(runtime["python"]).startswith("3.10."):
        fail("likelihood-grid runtime Python is not 3.10.x")
    if {name: runtime[name] for name in EXPECTED_LIBRARY_VERSIONS} != EXPECTED_LIBRARY_VERSIONS:
        fail("likelihood-grid runtime library versions differ")
    if runtime["environment"] != EXPECTED_RUNTIME_ENVIRONMENT:
        fail("likelihood-grid runtime environment differs")
    inputs = report["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "rate_model_source", "completeness", "posterior", "aggregate_manifest"
    }:
        fail("likelihood-grid input records differ")
    expected_input_records = {
        "rate_model_source": {
            "filename": source_lock[2],
            "sha256": source_lock[0],
            "size_bytes": source_lock[1],
            "lock_id": "bryson_rate_models_3d",
        },
        "completeness": {
            "filename": completeness_lock[2],
            "sha256": completeness_lock[0],
            "size_bytes": completeness_lock[1],
            "lock_id": completeness_lock_id,
        },
    }
    for key, expected_record in expected_input_records.items():
        if inputs[key] != expected_record:
            fail(f"likelihood-grid locked input record differs for {key}")
    posterior_sha = posterior_snapshot.sha256
    aggregate_sha = aggregate_snapshot.sha256
    posterior_record = _exact_keys(
        inputs["posterior"],
        {"filename", "sha256", "size_bytes", "row_count"},
        "likelihood-grid posterior record",
    )
    if (
        posterior_record["filename"] != posterior_original_name
        or posterior_record["sha256"] != posterior_sha
        or posterior_record["size_bytes"] != posterior_snapshot.size_bytes
    ):
        fail("likelihood-grid posterior SHA-256 differs from the supplied aggregate")
    aggregate_record = _exact_keys(
        inputs["aggregate_manifest"],
        {"filename", "sha256", "size_bytes"},
        "likelihood-grid aggregate-manifest record",
    )
    if (
        aggregate_record["filename"] != aggregate_original_name
        or aggregate_record["sha256"] != aggregate_sha
        or aggregate_record["size_bytes"] != aggregate_snapshot.size_bytes
    ):
        fail("likelihood-grid aggregate-manifest SHA-256 differs")
    aggregate_entries = parse_manifest(
        aggregate_snapshot.path, "aggregate manifest"
    )
    if aggregate_entries.get(posterior_original_name) != posterior_sha:
        fail("aggregate manifest does not bind the likelihood-grid posterior")

    selected_record = _exact_keys(
        report["selected_points"],
        {"filename", "sha256", "size_bytes", "row_count", "columns"},
        "likelihood-grid selected-point record",
    )
    if selected_record["filename"] != SELECTED_NAME:
        fail("likelihood-grid selected-point record differs")
    if selected_record.get("sha256") != manifest[SELECTED_NAME]:
        fail("likelihood-grid selected-point SHA-256 differs")
    result_frame = _read_result_csv(selected_snapshot.path, branch)
    if (
        selected_record.get("row_count") != len(result_frame)
        or selected_record.get("columns") != list(CSV_COLUMNS)
    ):
        fail("likelihood-grid selected-point schema/count differs")
    if selected_record["size_bytes"] != selected_snapshot.size_bytes:
        fail("likelihood-grid selected-point size differs")

    posterior_frame = validate_posterior(
        pd.read_csv(
            posterior_snapshot.path,
            compression="gzip",
            float_precision="round_trip",
        ),
        branch,
    )
    if posterior_record["row_count"] != len(posterior_frame):
        fail("likelihood-grid posterior row count differs")
    expected_selection = select_joint_parameter_rows(posterior_frame)
    expected = expected_selection.loc[
        :, ["selection_labels", "is_central", "posterior_row_number", *IDENTIFIERS, *PARAMETERS]
    ].reset_index(drop=True)
    observed = result_frame.loc[:, expected.columns].reset_index(drop=True)
    for column in ("selection_labels",):
        if not observed[column].equals(expected[column]):
            fail("likelihood-grid selection labels differ from the posterior")
    for column in ("is_central", "posterior_row_number", *IDENTIFIERS):
        if not np.array_equal(observed[column].to_numpy(), expected[column].to_numpy()):
            fail(f"likelihood-grid selected coordinate differs for {column}")
    if not np.array_equal(
        observed.loc[:, list(PARAMETERS)].to_numpy(dtype=float),
        expected.loc[:, list(PARAMETERS)].to_numpy(dtype=float),
    ):
        fail("likelihood-grid selected parameters differ from the posterior")

    module = load_rate_model_module(source_snapshot.path)
    completeness_arrays = load_completeness_arrays(
        completeness_snapshot.path
    )
    recomputed_norms, recomputed_four_corner, recomputed_invariant = (
        evaluate_grids(expected_selection, module, completeness_arrays)
    )
    recomputed_frame = attach_results(
        expected_selection,
        branch,
        recomputed_norms,
        recomputed_four_corner,
        recomputed_invariant,
    )
    numeric_result_columns = (
        "norm_31",
        "norm_61",
        "norm_121",
        "norm_121_four_corner",
        "abs_delta_log_likelihood_61_121",
        "relative_norm_delta_61_121",
        "abs_delta_diagonal_vs_four_corner_121",
        "relative_delta_diagonal_vs_four_corner_121",
        "abs_delta_norm_31_61",
        "refinement_ratio_61_121_over_31_61",
    )
    if not np.allclose(
        result_frame.loc[:, list(numeric_result_columns)].to_numpy(dtype=float),
        recomputed_frame.loc[:, list(numeric_result_columns)].to_numpy(dtype=float),
        rtol=2.0e-15,
        atol=2.0e-15,
    ):
        fail(
            "likelihood-grid numerical integrals differ from independent "
            "recomputation using the locked source and completeness bytes"
        )
    if not np.array_equal(
        result_frame["point_rate_grid_invariant"].to_numpy(dtype=bool),
        recomputed_frame["point_rate_grid_invariant"].to_numpy(dtype=bool),
    ):
        fail("likelihood-grid point-rate invariant differs on recomputation")

    recomputed = summarize_results(result_frame)
    results = report["results"]
    if not isinstance(results, dict) or set(results) != set(recomputed):
        fail("likelihood-grid result keys differ")
    for key, value in recomputed.items():
        declared = results[key]
        if isinstance(value, bool):
            if declared is not value:
                fail(f"likelihood-grid result differs for {key}")
        elif isinstance(value, int):
            if (
                isinstance(declared, bool)
                or not isinstance(declared, int)
                or declared != value
            ):
                fail(f"likelihood-grid result differs for {key}")
        else:
            declared_value = _finite(
                declared, f"likelihood-grid result {key}", nonnegative=True
            )
            if not math.isclose(
                declared_value, value, rel_tol=2.0e-15, abs_tol=2.0e-15
            ):
                fail(f"likelihood-grid result differs for {key}")
    if recomputed["accepted"] is not True:
        fail("likelihood-grid convergence gate is not accepted")
    final_children = list(root.iterdir())
    if {path.name for path in final_children} != expected_files or any(
        path.is_symlink() or not path.is_file() for path in final_children
    ):
        fail("likelihood-grid artifact root changed during verification")
    return report


def verify_likelihood_grid_artifact(
    root: Path,
    *,
    branch: str,
    posterior_path: Path,
    aggregate_manifest_path: Path,
    rate_model_source_path: Path,
    completeness_path: Path,
) -> dict[str, Any]:
    """Verify the exact audit root and rederive its posterior-row selection."""

    validate_runtime()
    with tempfile.TemporaryDirectory(
        prefix="likelihood-grid-verify-"
    ) as temporary:
        return _verify_likelihood_grid_artifact_in_snapshot_root(
            root,
            branch=branch,
            posterior_path=posterior_path,
            aggregate_manifest_path=aggregate_manifest_path,
            rate_model_source_path=rate_model_source_path,
            completeness_path=completeness_path,
            temporary_root=Path(temporary),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--rate-model-source", required=True, type=Path)
    parser.add_argument("--completeness", required=True, type=Path)
    parser.add_argument("--posterior", required=True, type=Path)
    parser.add_argument("--aggregate-manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run_audit(args)
    except (GridAuditError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
