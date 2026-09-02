#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
# This derivative is documented in MODIFICATIONS_BRYSON.md and remains under
# GPL-2.0-only. Modified by Roman Jerše on 2026-08-30; see that record.
"""Independently replay every DR25 reliability/measurement realization.

This verifier starts from the locked planet-candidate and stellar-catalog
bytes.  It reconstructs the merge, reliability draw, asymmetric measurement
draws, and source-domain masks without importing the production measurement
module.  The resulting rows and counts must match the complete aggregate
perturbation audit exactly.  Row-level catalog data remain private; the output
contains only hashes, sizes, counts, and a self-identifying PASS record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterable

import numpy as np
import pandas as pd


CORRECTED_MODE = "quantile_matched_two_sided"
LEGACY_MODE = "legacy_source_mixture"
MODES = (CORRECTED_MODE, LEGACY_MODE)
# Backward-compatible name used by the direct tests and older callers.
MODE = CORRECTED_MODE
BRANCHES = ("constant", "zero")
PC_LOCK_ID = "bryson_pc_catalog"
STELLAR_LOCK_ID = "bryson_stellar_catalog_extracted"
PC_FILENAME = "PCs_dr25_hab2.csv"
PC_SHA256 = "c8ae78fcfe4ed27bbe972b1041a3e370031a4f94afea4ad35dd7bd47834c140b"
PC_SIZE_BYTES = 1_431_857
STELLAR_FILENAME = "dr25_stellar_berger2020_clean_hab2.txt"
STELLAR_SHA256 = "79744e4daf1f46414dacada9f91be017b2dcfed68028ef18544e3764fe5a4fa3"
STELLAR_SIZE_BYTES = 100_194_836
TRIALS_PER_SHARD = 25
MAX_JSON_BYTES = 8_000_000
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COUNT_KEYS = (
    "n_catalog_rows",
    "n_reliability_selected_before_domain",
    "n_outside_instellation_source_domain",
    "n_outside_radius_source_domain",
    "n_outside_teff_source_domain",
    "n_outside_any_of_three_source_domains",
    "n_failing_optional_period_cutoff",
    "n_retained_by_active_policy",
    "n_retained_with_teff_outside_source_domain",
)
AUDIT_COLUMNS = (
    "branch",
    "run_label",
    "measurement_error_mode",
    "shard",
    "trial",
    "global_trial",
    "trial_seed",
    "source_row",
    "kepoi_name",
    "kepid_x",
    "totalReliability",
    "koi_period",
    "gaia_iso_insol",
    "gaia_iso_insol_errm",
    "gaia_iso_insol_errp",
    "gaia_iso_prad",
    "gaia_iso_prad_errm",
    "gaia_iso_prad_errp",
    "teff",
    "teff_err2",
    "teff_err1",
    "perturbed_flux",
    "perturbed_radius",
    "perturbed_teff",
    "instellation_in_source_domain",
    "radius_in_source_domain",
    "teff_in_source_domain",
    "period_passes_optional_cutoff",
    "teff_filter_active",
    "retained_by_active_policy",
    "audit_status",
)
NUMERIC_COLUMNS = (
    "shard",
    "trial",
    "global_trial",
    "trial_seed",
    "source_row",
    "kepid_x",
    "totalReliability",
    "koi_period",
    "gaia_iso_insol",
    "gaia_iso_insol_errm",
    "gaia_iso_insol_errp",
    "gaia_iso_prad",
    "gaia_iso_prad_errm",
    "gaia_iso_prad_errp",
    "teff",
    "teff_err2",
    "teff_err1",
    "perturbed_flux",
    "perturbed_radius",
    "perturbed_teff",
)
BOOLEAN_COLUMNS = (
    "instellation_in_source_domain",
    "radius_in_source_domain",
    "teff_in_source_domain",
    "period_passes_optional_cutoff",
    "teff_filter_active",
    "retained_by_active_policy",
)
STRING_COLUMNS = (
    "branch",
    "run_label",
    "measurement_error_mode",
    "kepoi_name",
    "audit_status",
)


class CatalogAuditError(RuntimeError):
    """Raised whenever catalog-to-aggregate reconstruction fails closed."""


def fail(message: str) -> None:
    raise CatalogAuditError(message)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_constant(token: str) -> None:
    fail(f"non-finite JSON constant is forbidden: {token}")


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def strict_json_bytes(data: bytes, description: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse strict UTF-8 JSON {description}: {exc}")


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def snapshot_file(
    source: Path,
    destination: Path,
    description: str,
    *,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    maximum_bytes: int | None = None,
) -> dict[str, Any]:
    """Copy one stable regular file while hashing its exact source bytes."""

    candidate = Path(source)
    try:
        before = candidate.lstat()
    except OSError as exc:
        fail(f"cannot inspect {description}: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{description} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as reader, destination.open("xb") as writer:
            opened_before = os.fstat(reader.fileno())
            if not stat.S_ISREG(opened_before.st_mode):
                fail(f"{description} opened object is not a regular file")
            while True:
                block = reader.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                if maximum_bytes is not None and size > maximum_bytes:
                    fail(f"{description} exceeds {maximum_bytes} bytes")
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
            opened_after = os.fstat(reader.fileno())
    except OSError as exc:
        fail(f"cannot snapshot {description}: {exc}")
    try:
        after = candidate.lstat()
    except OSError as exc:
        fail(f"cannot re-inspect {description}: {exc}")
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or len({_identity(item) for item in (before, opened_before, opened_after, after)})
        != 1
        or size != opened_after.st_size
    ):
        fail(f"{description} changed while being snapshotted")
    observed = digest.hexdigest()
    if expected_sha256 is not None and observed != expected_sha256:
        fail(f"{description} SHA-256 mismatch: {observed} != {expected_sha256}")
    if expected_size_bytes is not None and size != expected_size_bytes:
        fail(f"{description} size mismatch: {size} != {expected_size_bytes}")
    return {
        "filename": candidate.name,
        "sha256": observed,
        "size_bytes": size,
        "snapshot": destination,
    }


def load_locks(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="catalog-lock-") as temporary:
        snapshot = snapshot_file(
            path,
            Path(temporary) / "DATA_LOCKS.json",
            "DATA_LOCKS.json",
            maximum_bytes=MAX_JSON_BYTES,
        )
        document = strict_json_bytes(
            Path(snapshot["snapshot"]).read_bytes(), "DATA_LOCKS.json"
        )
    if not isinstance(document, dict) or not isinstance(document.get("locks"), dict):
        fail("DATA_LOCKS.json has no locks object")
    return document["locks"], {
        key: snapshot[key] for key in ("filename", "sha256", "size_bytes")
    }


def locked_input(
    locks: dict[str, dict[str, Any]], lock_id: str, path: Path
) -> tuple[str, int]:
    record = locks.get(lock_id)
    if not isinstance(record, dict):
        fail(f"missing data lock: {lock_id}")
    immutable = {
        PC_LOCK_ID: (PC_FILENAME, PC_SHA256, PC_SIZE_BYTES),
        STELLAR_LOCK_ID: (
            STELLAR_FILENAME,
            STELLAR_SHA256,
            STELLAR_SIZE_BYTES,
        ),
    }
    locked_name, locked_hash, locked_size = immutable[lock_id]
    expected_hash = record.get("expected_sha256")
    expected_size = record.get("expected_size_bytes")
    if not isinstance(expected_hash, str) or HEX64.fullmatch(expected_hash) is None:
        fail(f"invalid expected SHA-256 for {lock_id}")
    if type(expected_size) is not int or expected_size <= 0:
        fail(f"invalid expected size for {lock_id}")
    if (record.get("filename"), expected_hash, expected_size) != (
        locked_name,
        locked_hash,
        locked_size,
    ):
        fail(f"canonical lock tuple changed for {lock_id}")
    if record.get("filename") != Path(path).name:
        fail(f"locked filename mismatch for {lock_id}")
    return expected_hash, expected_size


def draw_two_sided(
    nominal: np.ndarray,
    sigma_minus: np.ndarray,
    sigma_plus: np.ndarray,
    rng: np.random.RandomState,
    mode: str,
) -> np.ndarray:
    """Independent transcription of both source and corrected draw orders."""

    if mode not in MODES:
        fail(f"unsupported measurement-error mode: {mode!r}")
    center = np.asarray(nominal, dtype=float)
    lower = np.asarray(sigma_minus, dtype=float)
    upper = np.asarray(sigma_plus, dtype=float)
    if mode == CORRECTED_MODE and (
        np.any(np.isfinite(lower) & (lower < 0.0))
        or np.any(np.isfinite(upper) & (upper < 0.0))
    ):
        fail("catalog contains a negative finite measurement uncertainty")
    plus = rng.rand(len(center)) > 0.5
    minus = ~plus
    plus_noise = rng.randn(int(np.sum(plus)))
    minus_noise = rng.randn(int(np.sum(minus)))
    if mode == CORRECTED_MODE:
        plus_noise = np.abs(plus_noise)
        minus_noise = np.abs(minus_noise)
    result = np.zeros(len(center), dtype=float)
    result[plus] = center[plus] + upper[plus] * plus_noise
    result[minus] = center[minus] - lower[minus] * minus_noise
    return result


def replay_trial(
    catalog: pd.DataFrame,
    *,
    branch: str,
    shard: int,
    trial: int,
    global_trial: int,
    trial_seed: int,
    measurement_error_mode: str = CORRECTED_MODE,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Reconstruct one audit table directly from the merged source catalog."""

    rng = np.random.RandomState(trial_seed)
    reliability = catalog.totalReliability.to_numpy(dtype=float)
    selected = catalog.loc[rng.rand(len(catalog)) < reliability].copy()
    flux = draw_two_sided(
        selected.gaia_iso_insol.to_numpy(dtype=float),
        selected.gaia_iso_insol_errm.to_numpy(dtype=float),
        selected.gaia_iso_insol_errp.to_numpy(dtype=float),
        rng,
        measurement_error_mode,
    )
    radius = draw_two_sided(
        selected.gaia_iso_prad.to_numpy(dtype=float),
        selected.gaia_iso_prad_errm.to_numpy(dtype=float),
        selected.gaia_iso_prad_errp.to_numpy(dtype=float),
        rng,
        measurement_error_mode,
    )
    teff = draw_two_sided(
        selected.teff.to_numpy(dtype=float),
        selected.teff_err2.to_numpy(dtype=float),
        selected.teff_err1.to_numpy(dtype=float),
        rng,
        measurement_error_mode,
    )
    instellation_ok = np.isfinite(flux) & (0.2 <= flux) & (flux <= 2.2)
    radius_ok = np.isfinite(radius) & (0.5 <= radius) & (radius <= 2.5)
    teff_ok = np.isfinite(teff) & (3900.0 <= teff) & (teff <= 6300.0)
    period_ok = np.ones(len(selected), dtype=bool)
    retained = instellation_ok & radius_ok & period_ok
    if measurement_error_mode == CORRECTED_MODE:
        retained &= teff_ok
    selected["perturbed_flux"] = flux
    selected["perturbed_radius"] = radius
    selected["perturbed_teff"] = teff
    preferred = (
        "source_row",
        "kepoi_name",
        "kepid_x",
        "totalReliability",
        "koi_period",
        "gaia_iso_insol",
        "gaia_iso_insol_errm",
        "gaia_iso_insol_errp",
        "gaia_iso_prad",
        "gaia_iso_prad_errm",
        "gaia_iso_prad_errp",
        "teff",
        "teff_err2",
        "teff_err1",
        "perturbed_flux",
        "perturbed_radius",
        "perturbed_teff",
    )
    missing = [name for name in preferred if name not in selected]
    if missing:
        fail(f"merged catalog lacks required columns: {missing!r}")
    audit = selected.loc[:, list(preferred)].copy()
    audit["instellation_in_source_domain"] = instellation_ok
    audit["radius_in_source_domain"] = radius_ok
    audit["teff_in_source_domain"] = teff_ok
    audit["period_passes_optional_cutoff"] = period_ok
    audit["teff_filter_active"] = measurement_error_mode == CORRECTED_MODE
    audit["retained_by_active_policy"] = retained
    reasons: list[str] = []
    for flux_ok, prad_ok, temperature_ok, kept in zip(
        instellation_ok, radius_ok, teff_ok, retained
    ):
        row_reasons: list[str] = []
        if not flux_ok:
            row_reasons.append("instellation_outside_source_domain")
        if not prad_ok:
            row_reasons.append("radius_outside_source_domain")
        if not temperature_ok:
            row_reasons.append(
                "teff_outside_source_domain"
                if measurement_error_mode == CORRECTED_MODE
                else "teff_outside_source_domain_not_filtered_in_legacy"
            )
        if kept and not row_reasons:
            row_reasons.append("retained")
        reasons.append(";".join(row_reasons))
    audit["audit_status"] = reasons
    audit.insert(0, "trial_seed", trial_seed)
    audit.insert(0, "global_trial", global_trial)
    audit.insert(0, "trial", trial)
    audit.insert(0, "shard", shard)
    audit.insert(0, "measurement_error_mode", measurement_error_mode)
    audit.insert(0, "run_label", f"production-shard-{shard}")
    audit.insert(0, "branch", branch)
    audit = audit.loc[:, list(AUDIT_COLUMNS)]
    all_three = instellation_ok & radius_ok & teff_ok
    counts = {
        "n_catalog_rows": int(len(catalog)),
        "n_reliability_selected_before_domain": int(len(selected)),
        "n_outside_instellation_source_domain": int(np.sum(~instellation_ok)),
        "n_outside_radius_source_domain": int(np.sum(~radius_ok)),
        "n_outside_teff_source_domain": int(np.sum(~teff_ok)),
        "n_outside_any_of_three_source_domains": int(np.sum(~all_three)),
        "n_failing_optional_period_cutoff": 0,
        "n_retained_by_active_policy": int(np.sum(retained)),
        "n_retained_with_teff_outside_source_domain": int(
            np.sum(retained & ~teff_ok)
        ),
    }
    return audit, counts


def load_diagnostics(
    path: Path,
    expected_trials: int,
    branch: str,
    measurement_error_mode: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_bytes().splitlines(), 1):
        if not line.strip():
            fail(f"blank diagnostics line {number}")
        record = strict_json_bytes(line, f"diagnostics line {number}")
        if not isinstance(record, dict):
            fail(f"diagnostics line {number} is not an object")
        records.append(record)
    if len(records) != expected_trials:
        fail(f"diagnostic count differs: {len(records)} != {expected_trials}")
    records.sort(key=lambda item: item.get("global_trial", -1))
    if [item.get("global_trial") for item in records] != list(range(expected_trials)):
        fail("diagnostic global_trial set/order is incomplete")
    seen_seeds: set[int] = set()
    for expected_global, record in enumerate(records):
        for key in ("shard", "trial", "global_trial", "perturbation_seed"):
            if type(record.get(key)) is not int or record[key] < 0:
                fail(f"invalid diagnostic integer {key} at global trial {expected_global}")
        if record.get("measurement_error_mode") != measurement_error_mode:
            fail("diagnostic measurement mode differs from the requested audit mode")
        seed = record["perturbation_seed"]
        if record.get("seed") != seed or seed in seen_seeds:
            fail("diagnostic perturbation seeds are inconsistent or duplicated")
        seen_seeds.add(seed)
        if record["global_trial"] != expected_global:
            fail("diagnostic global trial changed during validation")
        expected_shard, expected_trial = divmod(expected_global, TRIALS_PER_SHARD)
        if (record["shard"], record["trial"]) != (
            expected_shard,
            expected_trial,
        ):
            fail("diagnostic shard/trial/global mapping changed")
        expected_seed = (
            2_026_082_200
            + (100_000 if branch == "zero" else 0)
            + expected_shard * 1_000
            + 1_000_003 * expected_trial
        )
        if seed != expected_seed:
            fail(
                "v4.0.4 perturbation-seed schedule mismatch at global trial "
                f"{expected_global}: {seed} != {expected_seed}"
            )
        if not isinstance(record.get("perturbation_counts"), dict):
            fail("diagnostic perturbation_counts is missing")
        if set(record["perturbation_counts"]) != set(COUNT_KEYS):
            fail("diagnostic perturbation-count schema changed")
    return records


def compare_frames(expected: pd.DataFrame, observed: pd.DataFrame) -> None:
    if tuple(observed.columns) != AUDIT_COLUMNS:
        fail("aggregate perturbation-audit column order/schema changed")
    if len(expected) != len(observed):
        fail(f"aggregate perturbation-audit row count differs: {len(observed)} != {len(expected)}")
    expected = expected.sort_values(["global_trial", "source_row"]).reset_index(drop=True)
    observed = observed.sort_values(["global_trial", "source_row"]).reset_index(drop=True)
    for column in NUMERIC_COLUMNS:
        try:
            left = pd.to_numeric(expected[column], errors="raise").to_numpy(dtype=float)
            right = pd.to_numeric(observed[column], errors="raise").to_numpy(dtype=float)
        except (TypeError, ValueError) as exc:
            fail(f"non-numeric audit column {column}: {exc}")
        if not np.array_equal(left, right, equal_nan=True):
            mismatches = np.flatnonzero(~((left == right) | (np.isnan(left) & np.isnan(right))))
            first = int(mismatches[0]) if len(mismatches) else -1
            fail(f"aggregate perturbation audit differs at {column}, row {first}")
    for column in BOOLEAN_COLUMNS:
        left = expected[column].to_numpy(dtype=bool)
        if observed[column].dtype != bool:
            fail(f"aggregate perturbation boolean column changed type: {column}")
        right = observed[column].to_numpy(dtype=bool)
        if not np.array_equal(left, right):
            fail(f"aggregate perturbation audit differs at Boolean column {column}")
    for column in STRING_COLUMNS:
        left = expected[column].fillna("").astype(str).to_numpy()
        right = observed[column].fillna("").astype(str).to_numpy()
        if not np.array_equal(left, right):
            fail(f"aggregate perturbation audit differs at text column {column}")


def verify_catalog_perturbations(
    *,
    branch: str,
    aggregate_root: Path,
    pc_catalog: Path,
    stellar_catalog: Path,
    data_locks_path: Path,
    expected_trials: int = 400,
    measurement_error_mode: str = CORRECTED_MODE,
) -> dict[str, Any]:
    if branch not in BRANCHES:
        fail(f"unsupported branch: {branch!r}")
    if type(expected_trials) is not int or expected_trials <= 0:
        fail("expected_trials must be a positive integer")
    if measurement_error_mode not in MODES:
        fail(f"unsupported measurement-error mode: {measurement_error_mode!r}")
    if measurement_error_mode == LEGACY_MODE and branch != "constant":
        fail("legacy measurement sensitivity is defined only for the constant branch")
    root = Path(aggregate_root)
    if root.is_symlink() or not root.is_dir():
        fail("aggregate root must be an existing non-symlink directory")
    locks, locks_evidence = load_locks(data_locks_path)
    pc_hash, pc_size = locked_input(locks, PC_LOCK_ID, pc_catalog)
    stellar_hash, stellar_size = locked_input(locks, STELLAR_LOCK_ID, stellar_catalog)
    audit_source = root / f"perturbation_audit_{branch}_full.csv.gz"
    diagnostics_source = root / f"trial_diagnostics_{branch}_full.jsonl"
    with tempfile.TemporaryDirectory(prefix="catalog-perturbation-audit-") as temporary:
        private = Path(temporary)
        pc = snapshot_file(
            pc_catalog,
            private / Path(pc_catalog).name,
            "locked planet-candidate catalog",
            expected_sha256=pc_hash,
            expected_size_bytes=pc_size,
        )
        stellar = snapshot_file(
            stellar_catalog,
            private / Path(stellar_catalog).name,
            "locked stellar catalog",
            expected_sha256=stellar_hash,
            expected_size_bytes=stellar_size,
        )
        audit = snapshot_file(
            audit_source,
            private / audit_source.name,
            "aggregate perturbation audit",
        )
        diagnostics = snapshot_file(
            diagnostics_source,
            private / diagnostics_source.name,
            "aggregate trial diagnostics",
            maximum_bytes=MAX_JSON_BYTES,
        )
        verifier = snapshot_file(
            Path(__file__).resolve(),
            private / "catalog_perturbation_audit_source.py",
            "catalog perturbation verifier source",
        )
        try:
            stellar_frame = pd.read_csv(stellar["snapshot"])
            pc_frame = pd.read_csv(pc["snapshot"])
            # The production audit is decimal CSV.  Pandas' round-trip parser
            # reconstructs the exact binary64 values emitted by to_csv; the
            # default fast parser can differ by one ULP and would weaken an
            # otherwise exact comparison.
            observed = pd.read_csv(audit["snapshot"], float_precision="round_trip")
        except Exception as exc:
            fail(f"cannot parse locked/audit CSV input: {exc}")
        if "kepid" not in stellar_frame or "logg" not in stellar_frame:
            fail("stellar catalog lacks kepid/logg")
        if "kepid_x" not in pc_frame:
            fail("planet-candidate catalog lacks kepid_x")
        merged = pd.merge(
            pc_frame,
            stellar_frame[["kepid", "logg"]],
            left_on="kepid_x",
            right_on="kepid",
            how="inner",
        ).reset_index(drop=True)
        merged["source_row"] = np.arange(len(merged), dtype=int)
        records = load_diagnostics(
            Path(diagnostics["snapshot"]),
            expected_trials,
            branch,
            measurement_error_mode,
        )
        frames: list[pd.DataFrame] = []
        count_projection: list[dict[str, Any]] = []
        for record in records:
            frame, counts = replay_trial(
                merged,
                branch=branch,
                shard=record["shard"],
                trial=record["trial"],
                global_trial=record["global_trial"],
                trial_seed=record["perturbation_seed"],
                measurement_error_mode=measurement_error_mode,
            )
            declared = record["perturbation_counts"]
            if declared != counts:
                fail(
                    "catalog replay count mismatch at global trial "
                    f"{record['global_trial']}"
                )
            if record.get("selected_after_domain") != counts[
                "n_retained_by_active_policy"
            ]:
                fail("diagnostic selected_after_domain differs from catalog replay")
            frames.append(frame)
            count_projection.append(
                {"global_trial": record["global_trial"], **counts}
            )
        expected = pd.concat(frames, ignore_index=True)
        compare_frames(expected, observed)
        seed_projection = [
            {
                "global_trial": item["global_trial"],
                "shard": item["shard"],
                "trial": item["trial"],
                "perturbation_seed": item["perturbation_seed"],
            }
            for item in records
        ]
        body = {
            "schema_version": 1,
            "status": "PASS",
            "branch": branch,
            "measurement_error_mode": measurement_error_mode,
            "trials_verified": expected_trials,
            "merged_catalog_rows": int(len(merged)),
            "audit_rows_verified": int(len(expected)),
            "locked_inputs": {
                PC_LOCK_ID: {key: pc[key] for key in ("filename", "sha256", "size_bytes")},
                STELLAR_LOCK_ID: {
                    key: stellar[key] for key in ("filename", "sha256", "size_bytes")
                },
            },
            "data_locks": locks_evidence,
            "verifier_source": {
                key: verifier[key] for key in ("sha256", "size_bytes")
            },
            "aggregate_inputs": {
                "perturbation_audit": {
                    key: audit[key] for key in ("filename", "sha256", "size_bytes")
                },
                "trial_diagnostics": {
                    key: diagnostics[key]
                    for key in ("filename", "sha256", "size_bytes")
                },
            },
            "seed_schedule_sha256": hashlib.sha256(
                canonical_json_bytes(seed_projection)
            ).hexdigest(),
            "count_projection_sha256": hashlib.sha256(
                canonical_json_bytes(count_projection)
            ).hexdigest(),
            "verification_scope": (
                "exact source merge, reliability selection, asymmetric draws, "
                "domain masks, row identities, source fields, perturbed values, "
                "audit statuses, and per-realization counts"
            ),
        }
    return {
        "audit_id": "sha256:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
        **body,
    }


def write_report(report: dict[str, Any], output_root: Path) -> tuple[Path, Path]:
    root = Path(output_root)
    if root.exists() or root.is_symlink():
        fail("catalog-audit output root must not already exist")
    root.mkdir(parents=True)
    report_path = root / "CATALOG_PERTURBATION_AUDIT.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    manifest_path = root / "SHA256SUMS_catalog_perturbation_audit.txt"
    manifest_path.write_text(
        f"{digest}  {report_path.name}\n", encoding="utf-8", newline="\n"
    )
    return report_path, manifest_path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--branch", required=True, choices=BRANCHES)
    value.add_argument("--aggregate-root", required=True, type=Path)
    value.add_argument("--pc-catalog", required=True, type=Path)
    value.add_argument("--stellar-catalog", required=True, type=Path)
    value.add_argument("--data-locks", required=True, type=Path)
    value.add_argument(
        "--measurement-error-mode", required=True, choices=MODES
    )
    value.add_argument("--out", required=True, type=Path)
    return value


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        report = verify_catalog_perturbations(
            branch=args.branch,
            aggregate_root=args.aggregate_root,
            pc_catalog=args.pc_catalog,
            stellar_catalog=args.stellar_catalog,
            data_locks_path=args.data_locks,
            measurement_error_mode=args.measurement_error_mode,
        )
        write_report(report, args.out)
    except CatalogAuditError as exc:
        raise SystemExit(f"CATALOG PERTURBATION AUDIT FAIL: {exc}") from exc
    print(
        "PASS catalog perturbation audit "
        f"({report['branch']}; {report['trials_verified']} realizations; "
        f"{report['audit_rows_verified']} selected rows)"
    )


if __name__ == "__main__":
    main()
