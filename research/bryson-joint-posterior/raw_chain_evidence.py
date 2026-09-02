#!/usr/bin/env python3
"""Deterministic private raw-chain storage and independent MCMC audit.

The binary format deliberately avoids pickle, ZIP metadata, platform-native
endianness, and absolute paths.  Public artifacts may retain hashes and audit
results, but never the raw payloads handled by this module.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import struct
from typing import Any

import numpy as np


RAW_CHAIN_MAGIC = b"EXOERAW1"
RAW_CHAIN_SCHEMA_VERSION = 1
RAW_CHAIN_FORMAT = "exoearth_raw_chain_le_f64_v1"
RAW_CHAIN_PARAMETER_ORDER = ("F0", "beta_inst", "alpha_radius", "gamma")
RAW_CHAIN_FIELD_ORDER = (*RAW_CHAIN_PARAMETER_ORDER, "log_probability")
RAW_CHAIN_STORAGE_POLICY = "PRIVATE_NOT_FOR_PUBLIC_RELEASE"
RAW_CHAIN_HEADER = struct.Struct("<8sIIIIIqq32s")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RAW_RECORD_KEYS = {
    "trial",
    "trial_seed",
    "mcmc_seed",
    "file",
    "sha256",
    "size_bytes",
    "production_steps",
    "walkers",
    "parameter_count",
    "identity_sha256",
}
RAW_BUNDLE_KEYS = {
    "schema_version",
    "storage_policy",
    "index_file",
    "index_sha256",
    "manifest_file",
    "manifest_sha256",
    "trial_count",
}


class RawChainEvidenceError(RuntimeError):
    """Raised when private raw-chain evidence is unsafe or inconsistent."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def read_stable_file_bytes(path: Path, description: str) -> tuple[bytes, str]:
    """Read and hash one immutable regular-file snapshot through a single FD."""

    path = Path(path)
    try:
        path_before = os.lstat(path)
    except OSError as error:
        raise RawChainEvidenceError(f"Cannot stat {description}: {error}") from error
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise RawChainEvidenceError(f"Unsafe {description}: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RawChainEvidenceError(f"Cannot open {description}: {error}") from error
    try:
        descriptor_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or _stat_identity(descriptor_before) != _stat_identity(path_before)
        ):
            raise RawChainEvidenceError(f"{description} changed before its stable read")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        data = b"".join(chunks)
        digest = _digest_bytes(data)
        os.lseek(descriptor, 0, os.SEEK_SET)
        confirmation_chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            confirmation_chunks.append(block)
        if b"".join(confirmation_chunks) != data:
            raise RawChainEvidenceError(f"{description} changed during its stable read")
        descriptor_after = os.fstat(descriptor)
        try:
            path_after = os.lstat(path)
        except OSError as error:
            raise RawChainEvidenceError(
                f"{description} disappeared after its stable read: {error}"
            ) from error
        if (
            _stat_identity(descriptor_before) != _stat_identity(descriptor_after)
            or _stat_identity(path_before) != _stat_identity(path_after)
            or len(data) != descriptor_before.st_size
        ):
            raise RawChainEvidenceError(f"{description} changed during its stable read")
        return data, digest
    finally:
        os.close(descriptor)


def _portable_component(value: str, description: str) -> str:
    if (
        not isinstance(value, str)
        or not SAFE_COMPONENT_RE.fullmatch(value)
        or PurePosixPath(value).name != value
        or PureWindowsPath(value).name != value
        or value in {".", ".."}
        or value.endswith((".", " "))
    ):
        raise RawChainEvidenceError(f"Unsafe {description}: {value!r}")
    return value


def _exact_integer(value: Any, description: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RawChainEvidenceError(f"Invalid {description}: {value!r}")
    return value


def _finite_float(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RawChainEvidenceError(f"Invalid {description}: {value!r}")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise RawChainEvidenceError(f"Non-finite {description}: {value!r}")
    return numeric


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RawChainEvidenceError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(token: str) -> Any:
    raise RawChainEvidenceError(f"Non-standard JSON constant: {token!r}")


def _finite_json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise RawChainEvidenceError(f"Overflowing JSON number: {token!r}")
    return value


def load_strict_json(path: Path) -> Any:
    try:
        data, _digest = read_stable_file_bytes(path, f"JSON file {path}")
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RawChainEvidenceError(f"Invalid UTF-8 JSON {path}: {error}") from error


def _identity_sha256(
    branch: str,
    run_label: str,
    trial: int,
    trial_seed: int,
    mcmc_seed: int,
) -> str:
    identity = {
        "branch": branch,
        "mcmc_seed": mcmc_seed,
        "run_label": run_label,
        "trial": trial,
        "trial_seed": trial_seed,
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def raw_chain_filename(branch: str, run_label: str, trial: int) -> str:
    branch = _portable_component(branch, "branch")
    run_label = _portable_component(run_label, "run label")
    trial = _exact_integer(trial, "trial")
    if trial > 999:
        raise RawChainEvidenceError("Raw-chain trial exceeds the three-digit schema")
    return f"raw_production_chain_{branch}_{run_label}_trial-{trial:03d}.bin"


def raw_chain_index_filename(branch: str, run_label: str) -> str:
    return (
        f"raw_chain_index_{_portable_component(branch, 'branch')}_"
        f"{_portable_component(run_label, 'run label')}.json"
    )


def raw_chain_manifest_filename(branch: str, run_label: str) -> str:
    return (
        f"SHA256SUMS_raw_chain_{_portable_component(branch, 'branch')}_"
        f"{_portable_component(run_label, 'run label')}.txt"
    )


def initialize_private_raw_chain_directory(path: Path, public_out: Path) -> Path:
    """Create an empty resolved private directory outside the public output."""

    supplied = Path(path)
    if supplied.exists():
        if supplied.is_symlink() or not supplied.is_dir() or any(supplied.iterdir()):
            raise RawChainEvidenceError(
                "Private raw-chain directory must be absent or an empty real directory"
            )
    else:
        supplied.mkdir(parents=True)
    private = supplied.resolve()
    public = Path(public_out).resolve()
    if private == public or public in private.parents or private in public.parents:
        raise RawChainEvidenceError(
            "Private raw-chain directory must be outside the public output tree"
        )
    return private


def write_raw_chain(
    directory: Path,
    *,
    branch: str,
    run_label: str,
    trial: int,
    trial_seed: int,
    mcmc_seed: int,
    chain_source_order: np.ndarray,
    log_probability: np.ndarray,
) -> dict[str, Any]:
    """Write one raw unthinned chain and return its immutable index record."""

    trial = _exact_integer(trial, "trial")
    trial_seed = _exact_integer(trial_seed, "trial seed")
    mcmc_seed = _exact_integer(mcmc_seed, "MCMC seed")
    chain = np.asarray(chain_source_order, dtype=np.dtype("<f8"))
    log_prob = np.asarray(log_probability, dtype=np.dtype("<f8"))
    if chain.ndim != 3 or chain.shape[2] != len(RAW_CHAIN_PARAMETER_ORDER):
        raise RawChainEvidenceError(f"Invalid raw-chain shape: {chain.shape}")
    if log_prob.shape != chain.shape[:2]:
        raise RawChainEvidenceError(
            f"Raw log-probability shape mismatch: {log_prob.shape} != {chain.shape[:2]}"
        )
    if chain.shape[0] <= 0 or chain.shape[1] <= 0:
        raise RawChainEvidenceError("Raw chain must contain steps and walkers")
    if not np.all(np.isfinite(chain)) or not np.all(np.isfinite(log_prob)):
        raise RawChainEvidenceError("Raw chain contains non-finite values")
    payload = np.empty((*chain.shape[:2], len(RAW_CHAIN_FIELD_ORDER)), dtype="<f8")
    payload[..., : len(RAW_CHAIN_PARAMETER_ORDER)] = chain
    payload[..., -1] = log_prob
    payload = np.ascontiguousarray(payload)
    identity = _identity_sha256(branch, run_label, trial, trial_seed, mcmc_seed)
    header = RAW_CHAIN_HEADER.pack(
        RAW_CHAIN_MAGIC,
        RAW_CHAIN_SCHEMA_VERSION,
        trial,
        int(chain.shape[0]),
        int(chain.shape[1]),
        len(RAW_CHAIN_PARAMETER_ORDER),
        trial_seed,
        mcmc_seed,
        bytes.fromhex(identity),
    )
    filename = raw_chain_filename(branch, run_label, trial)
    path = Path(directory) / filename
    try:
        with path.open("xb") as handle:
            handle.write(header)
            handle.write(payload.tobytes(order="C"))
    except OSError as error:
        raise RawChainEvidenceError(f"Cannot write private raw chain {path}: {error}") from error
    return {
        "trial": trial,
        "trial_seed": trial_seed,
        "mcmc_seed": mcmc_seed,
        "file": filename,
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
        "production_steps": int(chain.shape[0]),
        "walkers": int(chain.shape[1]),
        "parameter_count": len(RAW_CHAIN_PARAMETER_ORDER),
        "identity_sha256": identity,
    }


def finalize_raw_chain_bundle(
    directory: Path,
    *,
    branch: str,
    run_label: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Write a deterministic index and exact private bundle manifest."""

    if not records:
        raise RawChainEvidenceError("Cannot finalize an empty raw-chain bundle")
    ordered = sorted((dict(record) for record in records), key=lambda item: item["trial"])
    if [record["trial"] for record in ordered] != list(range(len(ordered))):
        raise RawChainEvidenceError("Raw-chain records do not have exact trial IDs")
    index = {
        "schema_version": RAW_CHAIN_SCHEMA_VERSION,
        "format": RAW_CHAIN_FORMAT,
        "storage_policy": RAW_CHAIN_STORAGE_POLICY,
        "branch": branch,
        "run_label": run_label,
        "parameter_order_source": list(RAW_CHAIN_PARAMETER_ORDER),
        "payload_field_order": list(RAW_CHAIN_FIELD_ORDER),
        "trials": ordered,
    }
    index_name = raw_chain_index_filename(branch, run_label)
    index_path = Path(directory) / index_name
    try:
        with index_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps(index, indent=2, sort_keys=True, allow_nan=False) + "\n"
            )
    except OSError as error:
        raise RawChainEvidenceError(f"Cannot write raw-chain index: {error}") from error
    manifest_name = raw_chain_manifest_filename(branch, run_label)
    manifest_path = Path(directory) / manifest_name
    hashes = {record["file"]: record["sha256"] for record in ordered}
    hashes[index_name] = sha256(index_path)
    try:
        with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes))
            )
    except OSError as error:
        raise RawChainEvidenceError(f"Cannot write raw-chain manifest: {error}") from error
    return {
        "schema_version": RAW_CHAIN_SCHEMA_VERSION,
        "storage_policy": RAW_CHAIN_STORAGE_POLICY,
        "index_file": index_name,
        "index_sha256": hashes[index_name],
        "manifest_file": manifest_name,
        "manifest_sha256": sha256(manifest_path),
        "trial_count": len(ordered),
    }


def _parse_manifest_bytes(data: bytes) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RawChainEvidenceError(f"Cannot read raw-chain manifest: {error}") from error
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            raise RawChainEvidenceError(
                f"Invalid raw-chain manifest line {line_number}: {line!r}"
            )
        name = _portable_component(match.group(2), "raw-chain manifest filename")
        if name in entries:
            raise RawChainEvidenceError(f"Duplicate raw-chain manifest path: {name}")
        entries[name] = match.group(1)
    return entries


def _parse_manifest(path: Path) -> dict[str, str]:
    data, _digest = read_stable_file_bytes(path, "raw-chain manifest")
    return _parse_manifest_bytes(data)


def verify_raw_chain_bundle(
    directory: Path,
    *,
    branch: str,
    run_label: str,
    expected_trials: dict[int, tuple[int, int]],
    binding: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    """Verify one exact private bundle and return records keyed by trial."""

    if not isinstance(binding, dict) or set(binding) != RAW_BUNDLE_KEYS:
        raise RawChainEvidenceError("Invalid private raw-chain bundle binding")
    if binding.get("schema_version") != RAW_CHAIN_SCHEMA_VERSION:
        raise RawChainEvidenceError("Raw-chain bundle schema mismatch")
    if binding.get("storage_policy") != RAW_CHAIN_STORAGE_POLICY:
        raise RawChainEvidenceError("Raw-chain storage policy mismatch")
    if binding.get("trial_count") != len(expected_trials):
        raise RawChainEvidenceError("Raw-chain bundle trial count mismatch")
    index_name = raw_chain_index_filename(branch, run_label)
    manifest_name = raw_chain_manifest_filename(branch, run_label)
    if binding.get("index_file") != index_name or binding.get("manifest_file") != manifest_name:
        raise RawChainEvidenceError("Raw-chain bundle filename binding mismatch")
    directory = Path(directory)
    index_path = directory / index_name
    manifest_path = directory / manifest_name
    index_bytes, index_hash = read_stable_file_bytes(index_path, "raw-chain index")
    manifest_bytes, manifest_hash = read_stable_file_bytes(
        manifest_path, "raw-chain manifest"
    )
    if index_hash != binding.get("index_sha256"):
        raise RawChainEvidenceError("Raw-chain index SHA-256 binding mismatch")
    if manifest_hash != binding.get("manifest_sha256"):
        raise RawChainEvidenceError("Raw-chain manifest SHA-256 binding mismatch")
    try:
        entries = _parse_manifest_bytes(manifest_bytes)
        index = json.loads(
            index_bytes.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RawChainEvidenceError(f"Invalid raw-chain bundle metadata: {error}") from error
    expected_index_keys = {
        "schema_version",
        "format",
        "storage_policy",
        "branch",
        "run_label",
        "parameter_order_source",
        "payload_field_order",
        "trials",
    }
    if not isinstance(index, dict) or set(index) != expected_index_keys:
        raise RawChainEvidenceError("Raw-chain index schema mismatch")
    expected_header = {
        "schema_version": RAW_CHAIN_SCHEMA_VERSION,
        "format": RAW_CHAIN_FORMAT,
        "storage_policy": RAW_CHAIN_STORAGE_POLICY,
        "branch": branch,
        "run_label": run_label,
        "parameter_order_source": list(RAW_CHAIN_PARAMETER_ORDER),
        "payload_field_order": list(RAW_CHAIN_FIELD_ORDER),
    }
    if any(index.get(key) != value for key, value in expected_header.items()):
        raise RawChainEvidenceError("Raw-chain index identity or format mismatch")
    raw_records = index.get("trials")
    if not isinstance(raw_records, list) or len(raw_records) != len(expected_trials):
        raise RawChainEvidenceError("Raw-chain index trial list mismatch")
    records: dict[int, dict[str, Any]] = {}
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or set(raw_record) != RAW_RECORD_KEYS:
            raise RawChainEvidenceError("Raw-chain trial record schema mismatch")
        trial = _exact_integer(raw_record.get("trial"), "raw-chain trial")
        if trial in records or trial not in expected_trials:
            raise RawChainEvidenceError(f"Unexpected or duplicate raw-chain trial {trial}")
        trial_seed, mcmc_seed = expected_trials[trial]
        expected_identity = _identity_sha256(
            branch, run_label, trial, trial_seed, mcmc_seed
        )
        filename = raw_chain_filename(branch, run_label, trial)
        expected_values = {
            "trial_seed": trial_seed,
            "mcmc_seed": mcmc_seed,
            "file": filename,
            "parameter_count": len(RAW_CHAIN_PARAMETER_ORDER),
            "identity_sha256": expected_identity,
        }
        if any(raw_record.get(key) != value for key, value in expected_values.items()):
            raise RawChainEvidenceError(f"Raw-chain identity mismatch for trial {trial}")
        for key in ("size_bytes", "production_steps", "walkers"):
            _exact_integer(raw_record.get(key), f"raw-chain {key}", minimum=1)
        raw_hash = raw_record.get("sha256")
        if not isinstance(raw_hash, str) or not SHA256_RE.fullmatch(raw_hash):
            raise RawChainEvidenceError(f"Invalid raw-chain SHA-256 for trial {trial}")
        records[trial] = dict(raw_record)
    if set(records) != set(expected_trials):
        raise RawChainEvidenceError("Raw-chain trial identity set is incomplete")
    expected_files = {record["file"] for record in records.values()} | {index_name}
    if set(entries) != expected_files:
        raise RawChainEvidenceError("Raw-chain manifest has a non-exact file set")
    actual_files = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and not path.is_symlink() and path.name != manifest_name
    }
    if actual_files != expected_files:
        raise RawChainEvidenceError("Private raw-chain directory has extra or missing files")
    if entries[index_name] != index_hash:
        raise RawChainEvidenceError("Raw-chain index manifest hash mismatch")
    for record in records.values():
        path = directory / record["file"]
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise RawChainEvidenceError(f"Missing raw-chain file: {path}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RawChainEvidenceError(f"Unsafe raw-chain file: {path}")
    for record in records.values():
        if entries[record["file"]] != record["sha256"]:
            raise RawChainEvidenceError("Raw-chain record/manifest hash mismatch")
    if entries[index_name] != binding["index_sha256"]:
        raise RawChainEvidenceError("Raw-chain index/manifest hash mismatch")
    return records


def read_raw_chain(
    path: Path,
    *,
    branch: str,
    run_label: str,
    record: dict[str, Any],
) -> tuple[np.ndarray, np.ndarray]:
    """Read and validate one private binary raw chain without pickle."""

    if not isinstance(record, dict) or set(record) != RAW_RECORD_KEYS:
        raise RawChainEvidenceError("Invalid raw-chain record")
    path = Path(path)
    if path.name != record.get("file"):
        raise RawChainEvidenceError(f"Unsafe raw-chain path: {path}")
    data, observed_hash = read_stable_file_bytes(path, f"raw chain {path.name}")
    if len(data) != record.get("size_bytes") or observed_hash != record.get("sha256"):
        raise RawChainEvidenceError(f"Raw-chain byte binding mismatch: {path.name}")
    header = data[: RAW_CHAIN_HEADER.size]
    if len(header) != RAW_CHAIN_HEADER.size:
        raise RawChainEvidenceError("Truncated raw-chain header")
    (
        magic,
        schema,
        trial,
        steps,
        walkers,
        parameter_count,
        trial_seed,
        mcmc_seed,
        identity_bytes,
    ) = RAW_CHAIN_HEADER.unpack(header)
    payload = data[RAW_CHAIN_HEADER.size :]
    expected_header = (
        RAW_CHAIN_MAGIC,
        RAW_CHAIN_SCHEMA_VERSION,
        record["trial"],
        record["production_steps"],
        record["walkers"],
        len(RAW_CHAIN_PARAMETER_ORDER),
        record["trial_seed"],
        record["mcmc_seed"],
        bytes.fromhex(record["identity_sha256"]),
    )
    observed_header = (
        magic,
        schema,
        trial,
        steps,
        walkers,
        parameter_count,
        trial_seed,
        mcmc_seed,
        identity_bytes,
    )
    if observed_header != expected_header:
        raise RawChainEvidenceError(f"Raw-chain header mismatch: {path.name}")
    expected_identity = _identity_sha256(
        branch, run_label, trial, trial_seed, mcmc_seed
    )
    if expected_identity != record["identity_sha256"]:
        raise RawChainEvidenceError(f"Raw-chain identity digest mismatch: {path.name}")
    expected_payload_bytes = steps * walkers * len(RAW_CHAIN_FIELD_ORDER) * 8
    if len(payload) != expected_payload_bytes:
        raise RawChainEvidenceError(f"Raw-chain payload size mismatch: {path.name}")
    values = np.frombuffer(payload, dtype="<f8").reshape(
        steps, walkers, len(RAW_CHAIN_FIELD_ORDER)
    )
    if not np.all(np.isfinite(values)):
        raise RawChainEvidenceError(f"Raw-chain payload is non-finite: {path.name}")
    return values[..., : len(RAW_CHAIN_PARAMETER_ORDER)].copy(), values[..., -1].copy()


def _next_power_of_two(value: int) -> int:
    result = 1
    while result < value:
        result <<= 1
    return result


def _autocorrelation_function_1d(values: np.ndarray) -> np.ndarray:
    series = np.atleast_1d(values)
    if series.ndim != 1 or len(series) == 0:
        raise RawChainEvidenceError("Invalid one-dimensional chain")
    size = _next_power_of_two(len(series))
    transformed = np.fft.fft(series - np.mean(series), n=2 * size)
    autocorrelation = np.fft.ifft(
        transformed * np.conjugate(transformed)
    )[: len(series)].real
    if autocorrelation[0] == 0.0 or not np.isfinite(autocorrelation[0]):
        return np.full(len(series), np.nan, dtype=float)
    autocorrelation /= autocorrelation[0]
    return autocorrelation


def integrated_autocorrelation_time(chain: np.ndarray, c: float = 5.0) -> np.ndarray:
    """Independently reproduce emcee 3.1.6 ``integrated_time(..., tol=0)``."""

    values = np.asarray(chain, dtype=float)
    if values.ndim != 3 or values.shape[2] != len(RAW_CHAIN_PARAMETER_ORDER):
        raise RawChainEvidenceError(f"Invalid chain for tau estimation: {values.shape}")
    steps, walkers, parameters = values.shape
    estimate = np.empty(parameters, dtype=float)
    for parameter in range(parameters):
        mean_acf = np.zeros(steps, dtype=float)
        for walker in range(walkers):
            mean_acf += _autocorrelation_function_1d(values[:, walker, parameter])
        mean_acf /= walkers
        cumulative_tau = 2.0 * np.cumsum(mean_acf) - 1.0
        window_mask = np.arange(len(cumulative_tau)) < c * cumulative_tau
        window = (
            int(np.argmin(window_mask))
            if np.any(window_mask)
            else len(cumulative_tau) - 1
        )
        estimate[parameter] = cumulative_tau[window]
    return estimate


def recompute_adaptive_evidence(
    chain: np.ndarray,
    *,
    minimum_steps: int,
    maximum_steps: int,
    check_interval: int,
    tau_multiple: float,
    relative_tolerance: float,
    required_stable_checks: int,
    require_terminal_decision: bool = True,
) -> dict[str, Any]:
    """Recompute every adaptive checkpoint and the first stopping decision."""

    values = np.asarray(chain, dtype=float)
    if values.ndim != 3 or values.shape[2] != len(RAW_CHAIN_PARAMETER_ORDER):
        raise RawChainEvidenceError("Invalid raw chain for adaptive audit")
    completed_steps = int(values.shape[0])
    walkers = int(values.shape[1])
    for value, description in (
        (minimum_steps, "minimum steps"),
        (maximum_steps, "maximum steps"),
        (check_interval, "check interval"),
        (required_stable_checks, "stable checks"),
    ):
        _exact_integer(value, description, minimum=1)
    if minimum_steps > maximum_steps or completed_steps > maximum_steps:
        raise RawChainEvidenceError("Raw-chain step count violates the adaptive bounds")
    if not math.isfinite(tau_multiple) or tau_multiple <= 0.0:
        raise RawChainEvidenceError("Invalid tau multiple")
    if not math.isfinite(relative_tolerance) or not 0.0 < relative_tolerance < 1.0:
        raise RawChainEvidenceError("Invalid tau relative tolerance")
    checks: list[dict[str, Any]] = []
    previous_tau: np.ndarray | None = None
    stable_streak = 0
    accepted_steps: int | None = None
    scheduled = 0
    while scheduled < completed_steps:
        next_step = min(scheduled + check_interval, maximum_steps)
        if next_step > completed_steps:
            raise RawChainEvidenceError("Raw chain ends between adaptive checkpoints")
        scheduled = next_step
        if scheduled < minimum_steps:
            continue
        current_tau = integrated_autocorrelation_time(values[:scheduled])
        valid = bool(
            current_tau.shape == (len(RAW_CHAIN_PARAMETER_ORDER),)
            and np.all(np.isfinite(current_tau))
            and np.all(current_tau > 0.0)
        )
        length_ok = bool(valid and np.all(scheduled >= tau_multiple * current_tau))
        stable = False
        relative_change: float | None = None
        if valid and previous_tau is not None:
            relative_change = float(
                np.max(np.abs(current_tau - previous_tau) / current_tau)
            )
            stable = bool(relative_change <= relative_tolerance)
        stable_streak = stable_streak + 1 if length_ok and stable else 0
        checks.append(
            {
                "production_steps": scheduled,
                "autocorrelation_time": (
                    [float(value) for value in current_tau] if valid else None
                ),
                "length_ok": length_ok,
                "stable": stable,
                "max_relative_tau_change": relative_change,
                "stable_check_streak": stable_streak,
            }
        )
        if stable_streak >= required_stable_checks:
            accepted_steps = scheduled
            break
        if valid:
            previous_tau = current_tau
    if (
        accepted_steps is not None
        and require_terminal_decision
        and accepted_steps != completed_steps
    ):
        raise RawChainEvidenceError("Raw chain continues after the first accepted gate")
    if accepted_steps is None and completed_steps < maximum_steps:
        raise RawChainEvidenceError("Raw chain stopped before convergence or maximum steps")
    final = checks[-1] if checks else None
    final_tau = None if final is None else final["autocorrelation_time"]
    ess = None
    if final_tau is not None:
        tau_array = np.asarray(final_tau, dtype=float)
        ess = [float(walkers * completed_steps / value) for value in tau_array]
    return {
        "production_steps_completed": completed_steps,
        "walkers": walkers,
        "autocorrelation_time": final_tau,
        "effective_sample_size_source_order": ess,
        "converged": accepted_steps is not None,
        "first_accepted_steps": accepted_steps,
        "convergence_checks": checks,
    }


def _same_number(left: Any, right: Any) -> bool:
    try:
        return bool(
            np.isclose(
                _finite_float(left, "declared numeric evidence"),
                _finite_float(right, "recomputed numeric evidence"),
                rtol=1.0e-12,
                atol=1.0e-12,
            )
        )
    except RawChainEvidenceError:
        return False


def compare_recomputed_diagnostic(
    recomputed: dict[str, Any], diagnostic: dict[str, Any], context: str
) -> None:
    """Require serialized tau/checkpoints/ESS to equal raw-byte recomputation."""

    for key in ("production_steps_completed", "converged"):
        if diagnostic.get(key) != recomputed.get(key):
            raise RawChainEvidenceError(f"Raw-chain {key} mismatch in {context}")
    for key in ("autocorrelation_time", "effective_sample_size_source_order"):
        declared = diagnostic.get(key)
        actual = recomputed.get(key)
        if not isinstance(declared, list) or not isinstance(actual, list):
            raise RawChainEvidenceError(f"Raw-chain {key} is missing in {context}")
        if len(declared) != len(actual) or not all(
            _same_number(left, right) for left, right in zip(declared, actual)
        ):
            raise RawChainEvidenceError(f"Raw-chain {key} mismatch in {context}")
    declared_checks = diagnostic.get("convergence_checks")
    actual_checks = recomputed.get("convergence_checks")
    if not isinstance(declared_checks, list) or len(declared_checks) != len(actual_checks):
        raise RawChainEvidenceError(f"Raw-chain checkpoint count mismatch in {context}")
    for index, (declared, actual) in enumerate(zip(declared_checks, actual_checks)):
        if not isinstance(declared, dict) or set(declared) != set(actual):
            raise RawChainEvidenceError(
                f"Raw-chain checkpoint schema mismatch in {context}:{index}"
            )
        for key in ("production_steps", "length_ok", "stable", "stable_check_streak"):
            if declared.get(key) != actual.get(key):
                raise RawChainEvidenceError(
                    f"Raw-chain checkpoint {key} mismatch in {context}:{index}"
                )
        for key in ("max_relative_tau_change",):
            if actual[key] is None:
                if declared.get(key) is not None:
                    raise RawChainEvidenceError(
                        f"Raw-chain checkpoint {key} mismatch in {context}:{index}"
                    )
            elif not _same_number(declared.get(key), actual[key]):
                raise RawChainEvidenceError(
                    f"Raw-chain checkpoint {key} mismatch in {context}:{index}"
                )
        declared_tau = declared.get("autocorrelation_time")
        actual_tau = actual.get("autocorrelation_time")
        if actual_tau is None:
            if declared_tau is not None:
                raise RawChainEvidenceError(
                    f"Raw-chain checkpoint tau mismatch in {context}:{index}"
                )
        elif (
            not isinstance(declared_tau, list)
            or len(declared_tau) != len(actual_tau)
            or not all(
                _same_number(left, right)
                for left, right in zip(declared_tau, actual_tau)
            )
        ):
            raise RawChainEvidenceError(
                f"Raw-chain checkpoint tau mismatch in {context}:{index}"
            )
