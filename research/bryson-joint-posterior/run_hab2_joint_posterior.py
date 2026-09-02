#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from the Bryson DR25 occurrence implementation identified in
# MODIFICATIONS_BRYSON.md. Roman Jerše's modifications remain under GPL-2.0-only.
# Modified by Roman Jerše on 2026-08-30; see MODIFICATIONS_BRYSON.md.
"""Re-run the Bryson et al. Model-1 hab2 joint posterior.

This is a clean, seeded implementation of the public notebook
``insolation/computeOccurrencefixedTeff_uncertainty.ipynb`` from
``stevepur/DR25-occurrence-public``.  The exact source commit or source-file
SHA-256 is verified at runtime and recorded in every summary.

The source notebook pools MCMC samples over reliability/measurement-error
realisations.  This runner can either preserve the notebook's measurement-error
construction exactly or use the v4 quantile-matched two-sided correction.  It
records the selected mode, random seed, trial-level diagnostics, a complete
post-perturbation domain audit, input checksums, and source-versus-manuscript
parameter ordering.

Important parameter-order convention
------------------------------------
The Bryson implementation stores theta as::

    [F0, beta_inst, alpha_radius, gamma]

although internal local variable names in ``rateModels3D.py`` are reversed for
its two spatial exponents.  Output tables additionally provide manuscript
order::

    [F0, alpha_radius, beta_inst, gamma]

This runner does not treat independently sampled marginal summaries as a joint
posterior and does not combine the constant- and zero-completeness branches.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import os
import platform
import re
import stat
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any, NamedTuple

import emcee
import numpy as np
import pandas as pd
from astropy.io import fits
from scipy.interpolate import interp2d
from scipy.optimize import minimize

from measurement_error import (
    LEGACY_SOURCE_MIXTURE,
    MEASUREMENT_ERROR_MODES,
    measurement_error_metadata,
    perturb_planets,
)
from mcmc_convergence import run_production_chain
from raw_chain_evidence import (
    RawChainEvidenceError,
    finalize_raw_chain_bundle,
    initialize_private_raw_chain_directory,
    write_raw_chain,
)

BRYSON_REPOSITORY = "stevepur/DR25-occurrence-public"
BRYSON_SOURCE_RELATIVE_PATH = Path("insolation") / "rateModels3D.py"
DATA_LOCKS_PATH = Path(__file__).resolve().parents[2] / "provenance" / "DATA_LOCKS.json"
RUN_STATUSES = ("pilot_only", "production_candidate")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PUBLISHED = {
    "constant": {
        "F0": 1.107,
        "alpha": -1.082,
        "beta": -0.839,
        "gamma": -2.671,
    },
    "zero": {
        "F0": 1.590,
        "alpha": -1.175,
        "beta": -1.195,
        "gamma": -1.376,
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class StableInputSnapshot(NamedTuple):
    """One regular input captured through one non-following descriptor."""

    path: Path
    data: bytes
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int, int]


def _has_reparse_point(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def stable_input_snapshot(path: Path, label: str) -> StableInputSnapshot:
    """Capture exact bytes once and reject links, swaps, and special files."""

    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"Cannot inspect {label}: {candidate}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or _has_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise RuntimeError(f"Unsafe or missing {label}: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            digest.update(block)
            size += len(block)
        opened_after = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeError(f"Cannot read {label}: {candidate}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = candidate.lstat()
    except OSError as error:
        raise RuntimeError(f"Cannot re-inspect {label}: {candidate}") from error
    observed = _file_identity(opened_before)
    if (
        observed != _file_identity(opened_after)
        or observed != _file_identity(before)
        or observed != _file_identity(after)
        or stat.S_ISLNK(after.st_mode)
        or _has_reparse_point(after)
        or not stat.S_ISREG(after.st_mode)
        or size != opened_before.st_size
    ):
        raise RuntimeError(f"{label} changed during its stable snapshot")
    return StableInputSnapshot(
        path=candidate.resolve(),
        data=b"".join(chunks),
        sha256=digest.hexdigest(),
        size_bytes=size,
        identity=observed,
    )


def recheck_input_snapshot(snapshot: StableInputSnapshot, label: str) -> None:
    """Require a captured input path to retain the exact captured bytes."""

    current = stable_input_snapshot(snapshot.path, label)
    if (
        current.identity != snapshot.identity
        or current.sha256 != snapshot.sha256
        or current.size_bytes != snapshot.size_bytes
        or current.data != snapshot.data
    ):
        raise RuntimeError(f"{label} changed after its validated snapshot")


def locked_bryson_source_sha256() -> str:
    """Return the independently audited Bryson source hash from DATA_LOCKS."""

    try:
        registry = json.loads(DATA_LOCKS_PATH.read_text(encoding="utf-8"))
        expected = str(
            registry["locks"]["bryson_rate_models_3d"]["expected_sha256"]
        ).strip().lower()
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot load the Bryson source data lock: {error}") from error
    if not SHA256_RE.fullmatch(expected):
        raise RuntimeError("The Bryson source data lock has an invalid SHA-256")
    return expected


def locked_runner_input_sha256(branch: str) -> dict[str, str]:
    """Return the exact branch-specific scientific-input hashes."""

    lock_ids = {
        "stellar_catalog": "bryson_stellar_catalog_extracted",
        "pc_catalog": "bryson_pc_catalog",
        "completeness": (
            "completeness_constant" if branch == "constant" else "completeness_zero"
        ),
    }
    try:
        registry = json.loads(DATA_LOCKS_PATH.read_text(encoding="utf-8"))
        locks = registry["locks"]
        expected = {
            key: str(locks[lock_id]["expected_sha256"]).strip().lower()
            for key, lock_id in lock_ids.items()
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot load runner scientific-input locks: {error}") from error
    if any(not SHA256_RE.fullmatch(value) for value in expected.values()):
        raise RuntimeError("A runner scientific-input lock has an invalid SHA-256")
    return expected


def verify_runner_inputs(
    branch: str,
    stellar_catalog: Path,
    pc_catalog: Path,
    completeness: Path,
) -> dict[str, dict[str, Any]]:
    """Hash and lock every scientific input before any of its bytes are loaded."""

    paths = {
        "stellar_catalog": stellar_catalog,
        "pc_catalog": pc_catalog,
        "completeness": completeness,
    }
    expected = locked_runner_input_sha256(branch)
    records: dict[str, dict[str, Any]] = {}
    for key, path in paths.items():
        snapshot = stable_input_snapshot(path, f"runner input for {key}")
        actual = snapshot.sha256
        if actual != expected[key]:
            raise RuntimeError(
                f"Locked runner input SHA-256 mismatch for {key}: "
                f"{actual} != {expected[key]}"
            )
        records[key] = {
            "path": str(snapshot.path),
            "sha256": actual,
            "size_bytes": snapshot.size_bytes,
            "_snapshot": snapshot,
        }
    return records


def reverify_runner_inputs(records: dict[str, dict[str, Any]]) -> None:
    """Reject input replacement between pre-flight hashing and summary writing."""

    for key, record in records.items():
        snapshot = record.get("_snapshot")
        if not isinstance(snapshot, StableInputSnapshot):
            raise RuntimeError(f"Runner input snapshot is missing for {key}")
        try:
            recheck_input_snapshot(snapshot, f"runner input for {key}")
        except RuntimeError as error:
            raise RuntimeError(f"Runner input changed after use for {key}") from error


def public_runner_input_provenance(
    records: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Project internal byte snapshots onto JSON-safe public provenance."""

    public: dict[str, dict[str, Any]] = {}
    for key, record in records.items():
        public[key] = {
            "path": str(record["path"]),
            "sha256": str(record["sha256"]),
            "size_bytes": int(record["size_bytes"]),
        }
    return public


def public_bryson_source_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    """Remove the in-memory source snapshot from serialized provenance."""

    return {
        key: value
        for key, value in provenance.items()
        if key != "_source_snapshot"
    }


def resolve_run_status(requested_status: str | None) -> tuple[str, str]:
    """Return a conservative run status that never depends on ``run_label``."""

    if requested_status is None:
        return "pilot_only", "safe_default"
    if requested_status not in RUN_STATUSES:
        raise ValueError(f"Unknown run status: {requested_status!r}")
    return requested_status, "explicit_cli"


def add_run_metadata_arguments(parser: argparse.ArgumentParser) -> None:
    """Add non-scientific run-label, status, and provenance controls."""

    parser.add_argument("--run-label", default="pilot")
    parser.add_argument(
        "--run-status",
        choices=RUN_STATUSES,
        default=None,
        help=(
            "Explicit preliminary output classification. Omission fails safe "
            "to pilot_only; production_candidate still requires the aggregate "
            "acceptance gate, and run-label text never determines status."
        ),
    )
    parser.add_argument(
        "--verified-bryson-source-sha256",
        default=None,
        metavar="SHA256",
        help=(
            "Independently verified SHA-256 of "
            "BRYSON_ROOT/insolation/rateModels3D.py. Required only when the "
            "source is neither a clean Git checkout nor covered by "
            "BRYSON_ROOT/SHA256SUMS.txt."
        ),
    )


def _normalise_sha256(value: str, description: str) -> str:
    normalised = value.strip().lower()
    if not SHA256_RE.fullmatch(normalised):
        raise ValueError(f"{description} must be exactly 64 hexadecimal characters")
    return normalised


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(
        str(right.resolve())
    )


def _git_command(root: Path, *arguments: str, text: bool = True):
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=text,
    )


def _git_source_verification(
    root: Path, source_path: Path, actual_sha256: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Verify that the executed source bytes equal the exact Git HEAD blob."""

    try:
        top_level = _git_command(root, "rev-parse", "--show-toplevel")
    except OSError as exc:
        return None, f"Git unavailable: {exc}"
    if top_level.returncode != 0:
        return None, "Bryson root is not a Git checkout"

    reported_root = Path(top_level.stdout.strip())
    if not _same_path(reported_root, root):
        return None, "Bryson root is nested inside a different Git checkout"

    origin = _git_command(root, "remote", "get-url", "origin")
    if origin.returncode != 0:
        return None, "Bryson Git checkout has no origin remote"
    remote_url = origin.stdout.strip()
    normalized_remote = remote_url.lower().rstrip("/")
    if normalized_remote.endswith(".git"):
        normalized_remote = normalized_remote[:-4]
    if normalized_remote != "https://github.com/stevepur/dr25-occurrence-public":
        return None, f"Unexpected Bryson Git origin URL: {remote_url!r}"

    head = _git_command(root, "rev-parse", "HEAD")
    commit = head.stdout.strip().lower()
    if head.returncode != 0 or not GIT_COMMIT_RE.fullmatch(commit):
        return None, "Git HEAD could not be resolved to a full commit identifier"

    relative = BRYSON_SOURCE_RELATIVE_PATH.as_posix()
    head_source = _git_command(root, "show", f"{commit}:{relative}", text=False)
    if head_source.returncode != 0:
        return None, f"{relative} is not available from Git HEAD"
    head_sha256 = hashlib.sha256(head_source.stdout).hexdigest()
    if head_sha256 != actual_sha256:
        return None, (
            f"working source SHA-256 {actual_sha256} differs from Git HEAD "
            f"source SHA-256 {head_sha256}"
        )

    return (
        {
            "verified": True,
            "verification_method": "git_head_source_bytes",
            "source_repository": BRYSON_REPOSITORY,
            "source_remote_url": remote_url,
            "source_commit": commit,
            "source_root": str(root),
            "source_file": {
                "path": str(source_path),
                "relative_path": relative,
                "sha256": actual_sha256,
            },
        },
        None,
    )


def _manifest_sha256(manifest_path: Path, relative_path: Path) -> str | None:
    """Return the unique SHA-256 entry for ``relative_path`` from sha256sum output."""

    target = relative_path.as_posix()
    matches: list[str] = []
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"Cannot read Bryson SHA-256 manifest: {exc}") from exc
    for line in lines:
        match = re.fullmatch(r"([0-9A-Fa-f]{64}) [ *](.+)", line)
        if match is None:
            continue
        manifest_name = match.group(2).replace("\\", "/")
        while manifest_name.startswith("./"):
            manifest_name = manifest_name[2:]
        if manifest_name == target:
            matches.append(match.group(1).lower())
    if not matches:
        return None
    if len(set(matches)) != 1:
        raise RuntimeError(
            f"Conflicting SHA-256 entries for {target} in {manifest_path}"
        )
    return matches[0]


def verify_bryson_source(
    bryson_root: Path, explicitly_verified_sha256: str | None = None
) -> dict[str, Any]:
    """Fail closed unless the executed Bryson source has verifiable provenance."""

    root = bryson_root.resolve()
    if not root.is_dir():
        raise RuntimeError(f"Bryson root is not a directory: {root}")

    source_path = root / BRYSON_SOURCE_RELATIVE_PATH
    source_snapshot = stable_input_snapshot(source_path, "Bryson rate-model source")
    if not _same_path(source_snapshot.path.parent.parent, root):
        raise RuntimeError(f"Bryson source escapes the declared root: {source_path}")

    actual_sha256 = source_snapshot.sha256
    locked_sha256 = locked_bryson_source_sha256()
    if actual_sha256 != locked_sha256:
        raise RuntimeError(
            "Bryson source does not match the repository data lock: expected "
            f"{locked_sha256}, got {actual_sha256}"
        )
    relative = BRYSON_SOURCE_RELATIVE_PATH.as_posix()

    if explicitly_verified_sha256 is not None:
        expected_sha256 = _normalise_sha256(
            explicitly_verified_sha256, "--verified-bryson-source-sha256"
        )
        if expected_sha256 != locked_sha256:
            raise RuntimeError(
                "--verified-bryson-source-sha256 does not match the repository "
                f"data lock {locked_sha256}"
            )
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                "Bryson source SHA-256 mismatch: expected "
                f"{expected_sha256}, got {actual_sha256}"
            )
        return {
            "verified": True,
            "verification_method": "explicit_cli_sha256",
            "source_repository": BRYSON_REPOSITORY,
            "source_commit": None,
            "source_root": str(root),
            "source_file": {
                "path": str(source_path),
                "relative_path": relative,
                "sha256": actual_sha256,
            },
            "_source_snapshot": source_snapshot,
        }

    git_provenance, git_failure = _git_source_verification(
        root, source_snapshot.path, actual_sha256
    )
    if git_provenance is not None:
        git_provenance["_source_snapshot"] = source_snapshot
        return git_provenance

    manifest_path = root / "SHA256SUMS.txt"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        expected_sha256 = _manifest_sha256(
            manifest_path, BRYSON_SOURCE_RELATIVE_PATH
        )
        if expected_sha256 is None:
            raise RuntimeError(
                f"Bryson SHA-256 manifest has no entry for {relative}: "
                f"{manifest_path}"
            )
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                "Bryson source SHA-256 mismatch against manifest: expected "
                f"{expected_sha256}, got {actual_sha256}"
            )
        return {
            "verified": True,
            "verification_method": "artifact_sha256_manifest",
            "verification_manifest": str(manifest_path),
            "source_repository": BRYSON_REPOSITORY,
            "source_commit": None,
            "source_root": str(root),
            "source_file": {
                "path": str(source_path),
                "relative_path": relative,
                "sha256": actual_sha256,
            },
            "_source_snapshot": source_snapshot,
        }

    reason = git_failure or "no Git provenance was available"
    raise RuntimeError(
        "Bryson source provenance could not be verified fail-closed: "
        f"{reason}; provide a clean exact Git checkout, a matching "
        "BRYSON_ROOT/SHA256SUMS.txt entry, or "
        "--verified-bryson-source-sha256"
    )


def verify_loaded_bryson_module(module: Any, provenance: dict[str, Any]) -> None:
    """Ensure Python imported the same source file whose bytes were verified."""

    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise RuntimeError("Imported rateModels3D module does not expose __file__")
    expected_path = Path(provenance["source_file"]["path"])
    if not _same_path(Path(module_file), expected_path):
        raise RuntimeError(
            "Imported rateModels3D module does not match verified source: "
            f"loaded {Path(module_file).resolve()}, expected {expected_path.resolve()}"
        )
    expected_sha256 = str(provenance["source_file"]["sha256"])
    if getattr(module, "__verified_source_sha256__", None) != expected_sha256:
        raise RuntimeError("Loaded rateModels3D module lacks its verified byte binding")
    snapshot = provenance.get("_source_snapshot")
    if not isinstance(snapshot, StableInputSnapshot):
        raise RuntimeError("Verified Bryson source snapshot is missing")
    try:
        recheck_input_snapshot(snapshot, "Bryson rate-model source")
    except RuntimeError as error:
        raise RuntimeError(
            "Imported rateModels3D source bytes changed after provenance verification"
        ) from error


def load_verified_bryson_module(provenance: dict[str, Any]) -> Any:
    """Execute only the stable source bytes captured by provenance verification."""

    snapshot = provenance.get("_source_snapshot")
    if not isinstance(snapshot, StableInputSnapshot):
        raise RuntimeError("Verified Bryson source snapshot is missing")
    module = types.ModuleType("rateModels3D")
    module.__file__ = str(snapshot.path)
    module.__package__ = ""
    try:
        code = compile(snapshot.data, str(snapshot.path), "exec")
        sys.modules["rateModels3D"] = module
        exec(code, module.__dict__)
    except Exception as error:
        raise RuntimeError("Verified Bryson rate-model bytes could not be loaded") from error
    module.__verified_source_sha256__ = snapshot.sha256
    verify_loaded_bryson_module(module, provenance)
    return module


def jsonable(value: Any) -> Any:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.floating, np.integer)):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def lnlike(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    """Poisson log-likelihood copied from the public notebook."""
    theta = np.asarray(theta, dtype=float)
    norm = 0.0
    with np.errstate(all="ignore"):
        for index in range(cs.nTemp):
            rate = model.rateModel(
                cs.period2D,
                cs.rp2D,
                np.asarray(teff_means[index]),
                cs.periodRange,
                cs.rpRange,
                cs.tempRange,
                theta,
            )
            population = rate * sum_comp[:, :, index]
            population = 0.5 * (population[:-1, :-1] + population[1:, 1:])
            norm += float(np.sum(population * cs.vol2D))

        point_rate = model.rateModel(
            np.asarray(koi_flux),
            np.asarray(koi_radius),
            np.asarray(koi_teff),
            cs.periodRange,
            cs.rpRange,
            cs.tempRange,
            theta,
        )
        result = float(np.sum(np.log(point_rate)) - norm)
    return result if np.isfinite(result) else -np.inf


def lnprior(theta, model):
    bounds = model.getBounds()
    for value, (lower, upper) in zip(theta, bounds):
        if lower > value or value >= upper:
            return -np.inf
    # The public notebook returns 1.0 rather than 0.0; retain it because the
    # additive constant does not alter the posterior.
    return 1.0


def lnprob(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    prior = lnprior(theta, model)
    if not np.isfinite(prior):
        return -np.inf
    return prior + lnlike(
        theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model
    )


def nll(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model):
    value = lnlike(theta, cs, koi_flux, koi_radius, koi_teff, sum_comp, teff_means, model)
    return -value if np.isfinite(value) else 1.0e15


def _load_completeness_stream(stream, cs):
    """Parse one already opened FITS byte stream."""

    with fits.open(stream, memmap=False) as hdulist:
        cumulative = np.asarray(hdulist[0].data)
        header = hdulist[0].header
        prob_teff = cumulative[3:, :, :]

        n_period = int(header["NPER"])
        n_radius = int(header["NRP"])
        max_flux = float(header["MAXFLX"])
        min_flux = float(header["MINFLX"])
        min_radius = float(header["MINRP"])
        max_radius = float(header["MAXRP"])
        n_teff = int(header["NTEFF"])
        mean_teff = np.array(
            [float(header[f"MEANT{index}"]) for index in range(n_teff)],
            dtype=float,
        )

    flux_grid = np.linspace(max_flux, min_flux, n_period)
    radius_grid = np.linspace(min_radius, max_radius, n_radius)
    summed_teff = np.zeros((cs.nPeriod, cs.nRp, n_teff), dtype=float)
    for index in range(n_teff):
        # scipy.interp2d is intentionally retained under a pinned SciPy version
        # to match the source notebook's interpolation convention.
        interpolator = interp2d(flux_grid, radius_grid, prob_teff[index, :, :])
        summed_teff[:, :, index] = np.transpose(
            interpolator(cs.period1D, cs.rp1D)
        )
    return summed_teff, mean_teff


def load_completeness(data: bytes, cs):
    """Load FITS data from the preflight-captured immutable input bytes."""

    with io.BytesIO(data) as captured:
        if data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=captured, mode="rb") as decoded:
                return _load_completeness_stream(decoded, cs)
        return _load_completeness_stream(captured, cs)


def safe_initial_positions(center: np.ndarray, bounds, n_walkers: int) -> np.ndarray:
    positions = center[None, :] + 1.0e-5 * np.random.randn(n_walkers, len(center))
    for index, (lower, upper) in enumerate(bounds):
        epsilon = max(1.0e-10, 1.0e-10 * max(1.0, abs(upper - lower)))
        positions[:, index] = np.clip(
            positions[:, index], lower + epsilon, upper - epsilon
        )
    return positions


def quantile_summary(samples: np.ndarray) -> dict[str, dict[str, float]]:
    # Source theta order: F0, beta_inst, alpha_radius, gamma.
    manuscript = {
        "F0": samples[:, 0],
        "alpha": samples[:, 2],
        "beta": samples[:, 1],
        "gamma": samples[:, 3],
    }
    summary: dict[str, dict[str, float]] = {}
    for name, values in manuscript.items():
        q025, q16, q50, q84, q975 = np.quantile(
            values, [0.025, 0.16, 0.5, 0.84, 0.975]
        )
        summary[name] = {
            "q2.5": float(q025),
            "q16": float(q16),
            "q50": float(q50),
            "q84": float(q84),
            "q97.5": float(q975),
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bryson-root", required=True, type=Path)
    parser.add_argument("--stellar-catalog", required=True, type=Path)
    parser.add_argument("--pc-catalog", required=True, type=Path)
    parser.add_argument("--completeness", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument(
        "--mcmc-seed-offset",
        type=int,
        default=0,
        help=(
            "Optional offset that separates the MCMC random stream from the "
            "outer reliability/measurement realization. Zero preserves the "
            "legacy single-stream behavior."
        ),
    )
    parser.add_argument("--trials", type=int, default=4)
    parser.add_argument("--burnin", type=int, default=60)
    parser.add_argument("--steps", type=int, default=200)
    parser.add_argument("--thin", type=int, default=2)
    parser.add_argument("--walkers", type=int, default=8)
    parser.add_argument(
        "--private-raw-chain-dir",
        type=Path,
        default=None,
        help=(
            "Separate private directory for deterministic unthinned production "
            "chains. Required for production_candidate and forbidden inside --out."
        ),
    )
    parser.add_argument(
        "--adaptive-production",
        action="store_true",
        help=(
            "Extend production in check-interval chunks until the requested "
            "chain-length/tau and successive-tau stability gates pass."
        ),
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Maximum adaptive production steps per realization.",
    )
    parser.add_argument("--check-interval", type=int, default=1000)
    parser.add_argument("--tau-multiple", type=float, default=100.0)
    parser.add_argument("--tau-relative-tolerance", type=float, default=0.05)
    parser.add_argument("--tau-stability-checks", type=int, default=2)
    parser.add_argument(
        "--period-max-days",
        type=float,
        default=None,
        help="Optional source-period cutoff. Omit to reproduce the no-suffix archived run.",
    )
    add_run_metadata_arguments(parser)
    parser.add_argument(
        "--measurement-error-mode",
        choices=MEASUREMENT_ERROR_MODES,
        default=LEGACY_SOURCE_MIXTURE,
        help=(
            "Measurement-error construction. The default preserves the public "
            "notebook exactly; v4 corrected runs must explicitly select "
            "quantile_matched_two_sided."
        ),
    )
    args = parser.parse_args()

    if args.trials <= 0 or args.burnin <= 0 or args.steps <= 0 or args.thin <= 0:
        parser.error("trials, burnin, steps, and thin must all be positive")
    if args.walkers < 8 or args.walkers % 2:
        parser.error("walkers must be an even integer of at least 8")
    if args.check_interval <= 0:
        parser.error("check-interval must be positive")
    if args.tau_multiple <= 0.0:
        parser.error("tau-multiple must be positive")
    if not 0.0 < args.tau_relative_tolerance < 1.0:
        parser.error("tau-relative-tolerance must be between zero and one")
    if args.tau_stability_checks <= 0:
        parser.error("tau-stability-checks must be positive")
    if args.adaptive_production:
        if args.max_steps is None:
            parser.error("--max-steps is required with --adaptive-production")
        if args.max_steps < args.steps:
            parser.error("max-steps must be at least steps")
    maximum_steps = args.max_steps if args.max_steps is not None else args.steps
    run_status, run_status_source = resolve_run_status(args.run_status)
    if run_status == "production_candidate" and args.private_raw_chain_dir is None:
        parser.error(
            "production_candidate requires --private-raw-chain-dir for auditable "
            "unthinned-chain evidence"
        )

    started = time.time()
    root = args.bryson_root.resolve()
    try:
        input_file_provenance = verify_runner_inputs(
            args.branch,
            args.stellar_catalog,
            args.pc_catalog,
            args.completeness,
        )
        bryson_source_provenance = verify_bryson_source(
            root, args.verified_bryson_source_sha256
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    out = args.out.resolve()
    private_raw_chain_dir: Path | None = None
    if args.private_raw_chain_dir is not None:
        try:
            private_raw_chain_dir = initialize_private_raw_chain_directory(
                args.private_raw_chain_dir, out
            )
        except RawChainEvidenceError as error:
            parser.error(str(error))

    sys.path.insert(0, str(root / "completenessContours"))
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "insolation"))
    rm3d = load_verified_bryson_module(bryson_source_provenance)
    out.mkdir(parents=True, exist_ok=True)

    cs = rm3d.compSpace(
        periodName="Instellation",
        periodUnits="Iearth",
        periodRange=(0.2, 2.2),
        nPeriod=61,
        radiusName="Radius",
        radiusUnits="Rearth",
        rpRange=(0.5, 2.5),
        nRp=61,
        tempName="Teff",
        tempUnits="K",
        tempRange=(3900, 6300),
        nTemp=10,
    )
    model = rm3d.triplePowerLawTeffAvg(cs)

    reverify_runner_inputs(input_file_provenance)
    verify_loaded_bryson_module(rm3d, bryson_source_provenance)
    public_input_file_provenance = public_runner_input_provenance(
        input_file_provenance
    )
    public_source_provenance = public_bryson_source_provenance(
        bryson_source_provenance
    )
    stellar_snapshot = input_file_provenance["stellar_catalog"].get("_snapshot")
    pc_snapshot = input_file_provenance["pc_catalog"].get("_snapshot")
    completeness_snapshot = input_file_provenance["completeness"].get("_snapshot")
    if not all(
        isinstance(snapshot, StableInputSnapshot)
        for snapshot in (stellar_snapshot, pc_snapshot, completeness_snapshot)
    ):
        raise RuntimeError("A stable scientific-input snapshot is missing")
    stellar = pd.read_csv(io.BytesIO(stellar_snapshot.data))
    base_kois = pd.read_csv(io.BytesIO(pc_snapshot.data))
    base_kois = pd.merge(
        base_kois,
        stellar[["kepid", "logg"]],
        left_on="kepid_x",
        right_on="kepid",
        how="inner",
    ).reset_index(drop=True)
    base_kois["source_row"] = np.arange(len(base_kois), dtype=int)

    summed_teff, mean_teff = load_completeness(completeness_snapshot.data, cs)

    chain_rows: list[list[Any]] = []
    planet_rows: list[list[Any]] = []
    audit_frames: list[pd.DataFrame] = []
    diagnostics: list[dict[str, Any]] = []
    raw_chain_records: list[dict[str, Any]] = []
    pooled: list[np.ndarray] = []

    for trial in range(args.trials):
        trial_seed = int(args.seed + 1_000_003 * trial)
        np.random.seed(trial_seed)
        trial_start = time.time()
        perturbation = perturb_planets(
            base_kois,
            rng=np.random,
            instellation_range=cs.periodRange,
            radius_range=cs.rpRange,
            teff_range=cs.tempRange,
            period_max_days=args.period_max_days,
            mode=args.measurement_error_mode,
        )
        selected = perturbation.retained
        if len(selected) < 4:
            raise RuntimeError(
                f"Trial {trial} retained only {len(selected)} candidates; cannot fit four parameters."
            )

        trial_audit = perturbation.audit.copy()
        trial_audit.insert(0, "trial_seed", trial_seed)
        trial_audit.insert(0, "trial", trial)
        trial_audit.insert(0, "measurement_error_mode", args.measurement_error_mode)
        trial_audit.insert(0, "run_label", args.run_label)
        trial_audit.insert(0, "branch", args.branch)
        audit_frames.append(trial_audit)

        koi_flux = np.asarray(selected.perturbed_flux, dtype=float)
        koi_radius = np.asarray(selected.perturbed_radius, dtype=float)
        koi_teff = np.asarray(selected.perturbed_teff, dtype=float)

        initial = np.asarray(model.initRateModel(), dtype=float)
        likelihood_args = (
            cs,
            koi_flux,
            koi_radius,
            koi_teff,
            summed_teff,
            mean_teff,
            model,
        )
        optimum = minimize(
            nll,
            initial,
            method="L-BFGS-B",
            bounds=model.getBounds(),
            args=likelihood_args,
        )
        if not np.all(np.isfinite(optimum.x)):
            raise RuntimeError(f"Trial {trial} produced a non-finite optimizer state")

        ndim = len(optimum.x)
        n_walkers = args.walkers
        if n_walkers < 2 * ndim:
            raise RuntimeError(
                f"Need at least {2 * ndim} walkers for {ndim} dimensions"
            )
        mcmc_seed = int(trial_seed + args.mcmc_seed_offset)
        if args.mcmc_seed_offset:
            np.random.seed(mcmc_seed)
        positions = safe_initial_positions(
            np.asarray(optimum.x, dtype=float), model.getBounds(), n_walkers
        )
        sampler = emcee.EnsembleSampler(
            n_walkers,
            ndim,
            lnprob,
            args=likelihood_args,
        )
        state = sampler.run_mcmc(positions, args.burnin, progress=False)
        sampler.reset()
        _, tau, converged, convergence_checks = run_production_chain(
            sampler,
            state,
            minimum_steps=args.steps,
            adaptive=args.adaptive_production,
            maximum_steps=maximum_steps,
            check_interval=args.check_interval,
            tau_multiple=args.tau_multiple,
            relative_tolerance=args.tau_relative_tolerance,
            required_stable_checks=args.tau_stability_checks,
        )
        production_steps_completed = int(sampler.iteration)

        chain = sampler.get_chain(thin=args.thin)
        log_probability = sampler.get_log_prob(thin=args.thin)
        raw_chain_record: dict[str, Any] | None = None
        if private_raw_chain_dir is not None:
            raw_chain_record = write_raw_chain(
                private_raw_chain_dir,
                branch=args.branch,
                run_label=args.run_label,
                trial=trial,
                trial_seed=trial_seed,
                mcmc_seed=mcmc_seed,
                chain_source_order=sampler.get_chain(thin=1),
                log_probability=sampler.get_log_prob(thin=1),
            )
            raw_chain_records.append(raw_chain_record)
        flat = chain.reshape((-1, ndim))
        pooled.append(flat)

        ess = None
        if tau is not None:
            tau_array = np.asarray(tau, dtype=float)
            if np.all(np.isfinite(tau_array)) and np.all(tau_array > 0.0):
                ess = [
                    float(n_walkers * production_steps_completed / value)
                    for value in tau_array
                ]

        for step_index in range(chain.shape[0]):
            for walker in range(chain.shape[1]):
                theta = chain[step_index, walker, :]
                # Source order is F0, beta_inst, alpha_radius, gamma.
                chain_rows.append(
                    [
                        args.branch,
                        args.run_label,
                        trial,
                        trial_seed,
                        mcmc_seed,
                        step_index * args.thin,
                        walker,
                        float(log_probability[step_index, walker]),
                        float(theta[0]),
                        float(theta[2]),
                        float(theta[1]),
                        float(theta[3]),
                        float(theta[1]),
                        float(theta[2]),
                    ]
                )

        for _, row in selected.iterrows():
            planet_rows.append(
                [
                    args.branch,
                    args.run_label,
                    trial,
                    trial_seed,
                    int(row.source_row),
                    str(row.get("kepoi_name", "")),
                    float(row.totalReliability),
                    float(row.koi_period),
                    float(row.perturbed_flux),
                    float(row.perturbed_radius),
                    float(row.perturbed_teff),
                ]
            )

        diagnostic = {
                "trial": trial,
                "seed": trial_seed,
                "perturbation_seed": trial_seed,
                "mcmc_seed": mcmc_seed,
                "measurement_error_mode": args.measurement_error_mode,
                "selected_after_domain": int(len(selected)),
                "perturbation_counts": perturbation.counts,
                "optimizer_success": bool(optimum.success),
                "optimizer_status": int(optimum.status),
                "optimizer_message": str(optimum.message),
                "optimizer_fun": float(optimum.fun),
                "optimizer_theta_source_order": [float(value) for value in optimum.x],
                "mean_acceptance_fraction": float(np.mean(sampler.acceptance_fraction)),
                "acceptance_fraction_by_walker": [
                    float(value) for value in sampler.acceptance_fraction
                ],
                "autocorrelation_time": tau,
                "effective_sample_size_source_order": ess,
                "production_steps_completed": production_steps_completed,
                "adaptive_production": bool(args.adaptive_production),
                "converged": bool(converged) if args.adaptive_production else None,
                "convergence_checks": convergence_checks,
                "runtime_seconds": float(time.time() - trial_start),
            }
        if raw_chain_record is not None:
            diagnostic["private_raw_chain"] = raw_chain_record
        diagnostics.append(diagnostic)
        print(
            json.dumps(
                {
                    "branch": args.branch,
                    "trial": trial,
                    "measurement_error_mode": args.measurement_error_mode,
                    "selected": len(selected),
                    "optimizer_success": bool(optimum.success),
                    "acceptance": float(np.mean(sampler.acceptance_fraction)),
                    "production_steps": production_steps_completed,
                    "converged": (
                        bool(converged) if args.adaptive_production else None
                    ),
                }
            ),
            flush=True,
        )

    raw_chain_bundle = None
    if private_raw_chain_dir is not None:
        raw_chain_bundle = finalize_raw_chain_bundle(
            private_raw_chain_dir,
            branch=args.branch,
            run_label=args.run_label,
            records=raw_chain_records,
        )

    pooled_samples = np.concatenate(pooled, axis=0)
    posterior = quantile_summary(pooled_samples)
    published = PUBLISHED[args.branch]
    comparison = {
        name: {
            "published_marginal_median": float(published[name]),
            "rerun_q50": float(posterior[name]["q50"]),
            "difference": float(posterior[name]["q50"] - published[name]),
        }
        for name in ("F0", "alpha", "beta", "gamma")
    }

    chain_path = out / f"joint_posterior_{args.branch}_{args.run_label}.csv"
    with chain_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "branch",
                "run_label",
                "trial",
                "trial_seed",
                "mcmc_seed",
                "production_step",
                "walker",
                "log_probability",
                "F0",
                "alpha",
                "beta",
                "gamma",
                "source_theta1_beta_inst",
                "source_theta2_alpha_radius",
            ]
        )
        writer.writerows(chain_rows)

    planets_path = out / f"perturbed_planets_{args.branch}_{args.run_label}.csv"
    with planets_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "branch",
                "run_label",
                "trial",
                "trial_seed",
                "source_row",
                "kepoi_name",
                "total_reliability",
                "koi_period_days",
                "perturbed_flux",
                "perturbed_radius_rearth",
                "perturbed_teff_K",
            ]
        )
        writer.writerows(planet_rows)

    audit_path = out / f"perturbation_audit_{args.branch}_{args.run_label}.csv"
    pd.concat(audit_frames, ignore_index=True).to_csv(audit_path, index=False)

    diagnostics_path = out / f"trial_diagnostics_{args.branch}_{args.run_label}.json"
    diagnostics_path.write_text(
        json.dumps(diagnostics, indent=2, default=jsonable), encoding="utf-8"
    )

    reverify_runner_inputs(input_file_provenance)

    summary = {
        "status": run_status,
        "status_assignment": {
            "method": run_status_source,
            "run_label_used_for_status": False,
        },
        "scientific_interpretation": (
            "A source-faithful newly seeded rerun of the public Bryson likelihood; "
            "not the missing historical chain or a bitwise reproduction of the "
            "published stochastic run."
            if args.measurement_error_mode == LEGACY_SOURCE_MIXTURE
            else
            "A newly seeded corrected variant of the public Bryson likelihood, "
            "using quantile-matched two-sided measurement perturbations and all "
            "three post-perturbation source-domain filters; not the missing "
            "historical chain."
        ),
        "source_repository": BRYSON_REPOSITORY,
        "source_commit": bryson_source_provenance["source_commit"],
        "source_provenance": public_source_provenance,
        "branch": args.branch,
        "run_label": args.run_label,
        "parameter_order_source": ["F0", "beta_inst", "alpha_radius", "gamma"],
        "parameter_order_manuscript": ["F0", "alpha_radius", "beta_inst", "gamma"],
        "period_cutoff_days": args.period_max_days,
        "measurement_error": measurement_error_metadata(args.measurement_error_mode),
        "base_seed": args.seed,
        "mcmc_seed_offset": args.mcmc_seed_offset,
        "trials": args.trials,
        "walkers": args.walkers,
        "burnin_steps": args.burnin,
        "production_steps": (
            args.steps if not args.adaptive_production else None
        ),
        "production_steps_requested_minimum": args.steps,
        "production_steps_requested_maximum": maximum_steps,
        "production_steps_completed": [
            int(entry["production_steps_completed"]) for entry in diagnostics
        ],
        "adaptive_production": {
            "enabled": bool(args.adaptive_production),
            "check_interval": args.check_interval,
            "tau_multiple": args.tau_multiple,
            "tau_relative_tolerance": args.tau_relative_tolerance,
            "required_consecutive_stable_checks": args.tau_stability_checks,
            "converged_realizations": int(
                sum(bool(entry.get("converged")) for entry in diagnostics)
            ),
        },
        "thin": args.thin,
        "pooled_sample_count": int(len(pooled_samples)),
        "posterior_quantiles": posterior,
        "comparison_with_archived_published_marginal_medians": comparison,
        "trial_diagnostics_file": diagnostics_path.name,
        "perturbation_audit_file": audit_path.name,
        "private_raw_chain_bundle": raw_chain_bundle,
        "input_files": public_input_file_provenance,
        "runtime_seconds": float(time.time() - started),
        "software": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "emcee": emcee.__version__,
        },
        "limitations": [
            *(
                [
                    "The run is classified pilot_only; run-label text and "
                    "numerical settings do not promote it to production."
                ]
                if run_status == "pilot_only"
                else []
            ),
            "The public snapshot contains no serialized historical posterior chain.",
            *(
                ["Fixed-length MCMC convergence must be assessed after aggregation."]
                if not args.adaptive_production
                else []
            ),
            "The two completeness branches remain separate model scenarios.",
        ],
    }
    summary_path = out / f"posterior_summary_{args.branch}_{args.run_label}.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=jsonable), encoding="utf-8"
    )

    manifest_targets = [
        chain_path,
        planets_path,
        audit_path,
        diagnostics_path,
        summary_path,
    ]
    manifest_path = out / f"SHA256SUMS_{args.branch}_{args.run_label}.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_targets),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
