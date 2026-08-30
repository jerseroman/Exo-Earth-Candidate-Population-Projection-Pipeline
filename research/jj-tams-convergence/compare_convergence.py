#!/usr/bin/env python3
"""Compare fully regenerated TAMS runs at dR=1.0, 0.5 and 0.25 kpc."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

import numpy as np

DRS = [1.0, 0.5, 0.25]
QUANTITIES = ["N_G", "Lambda_ESHZ", "Lambda_earth10"]
DOMAINS = ["lineweaver_7_9", "full_JJ_4_14"]
CONTRACT_DIR = "freeze-contract"
CONTRACT_MANIFEST = "SHA256SUMS_tams_radial_convergence.txt"
RADIAL_COLUMNS = (
    "R_kpc",
    "dN_dR",
    "dL1_dR",
    "dL2_dR",
    "Sigma_TAMS_pc-2",
    "Sigma_thick_TAMS_pc-2",
)
RESULT_KEYS = {
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
DOMAIN_KEYS = {
    "R_kpc",
    "N_G",
    "Lambda_ESHZ",
    "Lambda_earth10",
    "mean_f_HZ",
    "mean_f_earth10",
    "L2_over_L1",
}
JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
EXPECTED_SELECTOR = (
    "5300<=Teff<=6000 K; age>=4.57 Gyr; thin+thick; "
    "Rstar<=PARSEC-TAMS(Teff); logg<7 remnant veto"
)
EXPECTED_OCCURRENCE_BRANCH = (
    "Bryson Model 1 hab2 constant-completeness + Kopparapu conservative HZ"
)
EXPECTED_C1 = 2_714_133_632.1901126
TUTORIAL_PARAMETERS_SHA256 = (
    "e5919225b94e9ce8d8a7ad31553f0932bd437e2ae14f117dc39a37934e78a1c6"
)
TUTORIAL_SFR_SHA256 = (
    "56d25b9ea61f454630a222ce6a6414bd1eaeb13bd165c25e9559ebe5c6b5039b"
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tag(dr):
    return str(dr).replace('.', 'p')


def rel(new, old):
    # Convergence convention used in the project: (finer - coarser) / finer.
    return (new - old) / new


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reject_constant(token):
    raise RuntimeError(f"Non-finite JSON constant is forbidden: {token}")


def finite_float(token):
    value = float(token)
    require(math.isfinite(value), f"Non-finite JSON number is forbidden: {token}")
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f"Duplicate JSON key is forbidden: {key!r}")
        value[key] = item
    return value


def load_strict_json(path):
    source = Path(path)
    require(source.is_file() and not source.is_symlink(), f"Missing regular JSON: {source}")
    try:
        return json.loads(
            source.read_bytes().decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot parse strict JSON {source}: {exc}") from exc


def stable_copy(source, destination):
    """Copy and hash one source through the same non-following file descriptor."""

    source = Path(source)
    destination = Path(destination)
    try:
        before = source.lstat()
    except OSError as exc:
        raise RuntimeError(f"Cannot inspect input {source}: {exc}") from exc
    require(
        not stat.S_ISLNK(before.st_mode) and stat.S_ISREG(before.st_mode),
        f"Missing regular input {source}",
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as reader, destination.open("xb") as writer:
            opened_before = os.fstat(reader.fileno())
            require(stat.S_ISREG(opened_before.st_mode), f"Input changed type: {source}")
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
            opened_after = os.fstat(reader.fileno())
    except OSError as exc:
        raise RuntimeError(f"Cannot snapshot input {source}: {exc}") from exc
    after = source.lstat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    require(
        len(identities) == 1
        and stat.S_ISREG(after.st_mode)
        and not stat.S_ISLNK(after.st_mode)
        and size == opened_after.st_size,
        f"Input changed while being snapshotted: {source}",
    )
    return {
        "filename": destination.name,
        "sha256": digest.hexdigest(),
        "size_bytes": size,
    }


def artifact_record(path, filename):
    source = Path(path)
    return {
        "filename": filename,
        "sha256": sha256(source),
        "size_bytes": source.stat().st_size,
    }


def finite_number(value, description):
    require(
        not isinstance(value, bool) and isinstance(value, (int, float)),
        f"{description} is not numeric",
    )
    number = float(value)
    require(math.isfinite(number), f"{description} is not finite")
    return number


def read_radial_table(path, dr):
    rows = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        require(tuple(reader.fieldnames or ()) == RADIAL_COLUMNS, "Radial-table schema changed")
        for row_number, raw in enumerate(reader, 2):
            require(None not in raw and all(value is not None for value in raw.values()),
                    f"Malformed radial-table row {row_number}")
            try:
                row = {name: float(raw[name]) for name in RADIAL_COLUMNS}
            except (TypeError, ValueError, OverflowError) as exc:
                raise RuntimeError(f"Invalid radial-table row {row_number}: {exc}") from exc
            require(all(math.isfinite(value) for value in row.values()),
                    f"Non-finite radial-table row {row_number}")
            require(row["dN_dR"] >= 0 and row["dL1_dR"] >= 0 and row["dL2_dR"] >= 0,
                    f"Negative radial density at row {row_number}")
            require(row["dL2_dR"] <= row["dL1_dR"],
                    f"Earth10 density exceeds HZ density at row {row_number}")
            require(0 <= row["Sigma_thick_TAMS_pc-2"] <= row["Sigma_TAMS_pc-2"],
                    f"Invalid thin/thick surface density at row {row_number}")
            expected_dndr = 2.0 * math.pi * row["R_kpc"] * 1.0e6 * row[
                "Sigma_TAMS_pc-2"
            ]
            require(math.isclose(row["dN_dR"], expected_dndr, rel_tol=2e-15, abs_tol=1e-6),
                    f"dN/dR geometry mismatch at row {row_number}")
            rows.append(row)
    expected_r = np.arange(4.0, 14.0 + dr / 2.0, dr, dtype=float)
    observed_r = np.asarray([row["R_kpc"] for row in rows], dtype=float)
    require(
        observed_r.shape == expected_r.shape
        and np.allclose(observed_r, expected_r, rtol=0.0, atol=1e-12),
        f"Radial grid does not exactly cover 4--14 kpc at dR={dr}",
    )
    return rows


def integrate_rows(rows, key, lo, hi):
    selected = [row for row in rows if lo <= row["R_kpc"] <= hi]
    radii = np.asarray([row["R_kpc"] for row in selected], dtype=float)
    values = np.asarray([row[key] for row in selected], dtype=float)
    require(len(radii) >= 2 and radii[0] == lo and radii[-1] == hi,
            f"Radial endpoints missing for {lo}--{hi}")
    return float(np.trapz(values, radii))


def validate_run_result(result, radial_path, dr):
    require(isinstance(result, dict) and set(result) == RESULT_KEYS,
            f"Result schema changed for dR={dr}")
    require(result["experiment"] == "final_TAMS_radial_convergence", "Experiment id changed")
    require(result["jj_commit"] == JJ_SHA, "JJ commit changed")
    require(result["isochrone_family"] == "Padova", "Isochrone family changed")
    require(result["host_selector"] == EXPECTED_SELECTOR, "Host selector changed")
    require(
        result["occurrence_branch"] == EXPECTED_OCCURRENCE_BRANCH,
        "Occurrence/climate branch changed",
    )
    require(math.isclose(finite_number(result["dR_kpc"], "dR_kpc"), dr,
                         rel_tol=0.0, abs_tol=1e-12), "dR label mismatch")
    rows = read_radial_table(radial_path, dr)
    require(type(result["radial_nodes"]) is int and result["radial_nodes"] == len(rows),
            "Radial-node count changed")
    require(
        type(result["selected_stellar_assembly_rows"]) is int
        and result["selected_stellar_assembly_rows"] > 0,
        "Selected stellar-assembly count must be positive",
    )
    require(
        type(result["compact_remnant_rows_rejected"]) is int
        and result["compact_remnant_rows_rejected"] >= 0,
        "Invalid compact-remnant count",
    )
    require(
        finite_number(
            result["compact_remnant_surface_weight_rejected_sum_pc-2"],
            "compact-remnant rejected weight",
        )
        >= 0,
        "Compact-remnant rejected weight is negative",
    )
    require(
        math.isclose(
            finite_number(result["C1"], "C1"),
            EXPECTED_C1,
            rel_tol=2e-15,
            abs_tol=0.0,
        ),
        "Occurrence normalization C1 changed",
    )
    domains = result["domains"]
    require(isinstance(domains, dict) and set(domains) == set(DOMAINS),
            "Radial result domain set changed")
    definitions = {
        "lineweaver_7_9": (7.0, 9.0),
        "full_JJ_4_14": (4.0, 14.0),
    }
    for name, (lo, hi) in definitions.items():
        declared = domains[name]
        require(isinstance(declared, dict) and set(declared) == DOMAIN_KEYS,
                f"Domain schema changed: {name}")
        require(declared["R_kpc"] == [lo, hi], f"Domain endpoints changed: {name}")
        derived = {
            "N_G": integrate_rows(rows, "dN_dR", lo, hi),
            "Lambda_ESHZ": integrate_rows(rows, "dL1_dR", lo, hi),
            "Lambda_earth10": integrate_rows(rows, "dL2_dR", lo, hi),
        }
        derived["mean_f_HZ"] = derived["Lambda_ESHZ"] / derived["N_G"]
        derived["mean_f_earth10"] = derived["Lambda_earth10"] / derived["N_G"]
        derived["L2_over_L1"] = derived["Lambda_earth10"] / derived["Lambda_ESHZ"]
        for quantity, expected in derived.items():
            observed = finite_number(declared[quantity], f"{name}:{quantity}")
            require(math.isclose(observed, expected, rel_tol=2e-15, abs_tol=1e-8),
                    f"Radial result does not derive from CSV: {name}:{quantity}")
    return rows


def expected_runtime_parameters(original_bytes, dr):
    try:
        text = original_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError(f"Tutorial parameters are not UTF-8: {exc}") from exc
    substitutions = (
        (r"(?m)^(Rmin\s+)4(\s+)", r"\g<1>4.0\g<2>"),
        (r"(?m)^(Rmax\s+)14(\s+)", r"\g<1>14.0\g<2>"),
        (r"(?m)^(dR\s+)1(\s+)", rf"\g<1>{dr}\g<2>"),
        (r"(?m)^(nprocess\s+)4(\s+)", r"\g<1>2\g<2>"),
    )
    for pattern, replacement in substitutions:
        text, count = re.subn(pattern, replacement, text, count=1)
        require(count == 1, f"Tutorial parameter substitution failed: {pattern}")
    return text.encode("utf-8")


def validate_runtime_inputs(destinations, dr):
    original = Path(destinations["parameters_original"]).read_bytes()
    runtime = Path(destinations["parameters_runtime"]).read_bytes()
    sfr = Path(destinations["sfr_peaks_parameters"]).read_bytes()
    require(
        hashlib.sha256(original).hexdigest() == TUTORIAL_PARAMETERS_SHA256,
        "parameters.original is not the exact pinned JJ tutorial2 file",
    )
    require(
        hashlib.sha256(sfr).hexdigest() == TUTORIAL_SFR_SHA256,
        "sfrd_peaks_parameters is not the exact pinned JJ tutorial2 file",
    )
    require(
        runtime == expected_runtime_parameters(original, dr),
        f"Runtime parameters contain changes beyond dR/R bounds/nprocess for dR={dr}",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    root = Path(args.root)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    contract = out / CONTRACT_DIR
    if contract.exists() and (not contract.is_dir() or any(contract.iterdir())):
        raise RuntimeError("Radial-convergence freeze-contract directory must be absent or empty")
    contract.mkdir(parents=True, exist_ok=True)

    runs = {}
    run_artifacts = {}
    contract_targets = []
    script_dir = Path(__file__).resolve().parent
    producer_sources = {
        "run_generator": (
            script_dir / "tams_radial_convergence.py",
            "tams_radial_convergence.py",
        ),
        "comparator": (Path(__file__).resolve(), "compare_convergence.py"),
    }
    producer_contract = {}
    for role, (source, name) in producer_sources.items():
        destination = contract / name
        record = stable_copy(source, destination)
        contract_targets.append(destination)
        producer_contract[role] = record

    runtime_source = root / "NUMERICAL_RUNTIME_POLICY.json"
    require(runtime_source.is_file() and not runtime_source.is_symlink(),
            "Missing regular NUMERICAL_RUNTIME_POLICY.json")
    runtime_destination = contract / runtime_source.name
    runtime_record = stable_copy(runtime_source, runtime_destination)
    contract_targets.append(runtime_destination)
    for dr in DRS:
        run_root = root / f"dr{tag(dr)}"
        p = run_root / f"tams_result_dr{tag(dr)}.json"
        artifacts = {}
        source_files = {
            "parameters_original": (
                run_root / "parameters.original",
                f"parameters_original_dr{tag(dr)}.txt",
            ),
            "parameters_runtime": (
                run_root / "parameters.runtime",
                f"parameters_runtime_dr{tag(dr)}.txt",
            ),
            "sfr_peaks_parameters": (
                run_root / "sfrd_peaks_parameters",
                f"sfrd_peaks_parameters_dr{tag(dr)}.txt",
            ),
            "radial_table": (
                run_root / f"tams_radial_dr{tag(dr)}.csv",
                f"tams_radial_dr{tag(dr)}.csv",
            ),
            "result": (p, f"tams_result_dr{tag(dr)}.json"),
        }
        destinations = {}
        for role, (source, name) in source_files.items():
            require(source.is_file() and not source.is_symlink(), f"Missing regular input {source}")
            destination = contract / name
            artifacts[role] = stable_copy(source, destination)
            contract_targets.append(destination)
            destinations[role] = destination
        runs[dr] = load_strict_json(destinations["result"])
        validate_runtime_inputs(destinations, dr)
        validate_run_result(runs[dr], destinations["radial_table"], dr)
        run_artifacts[str(dr)] = artifacts

    # Hard cross-check: the regenerated 0.5-kpc final TAMS run must reproduce the
    # already validated canonical provider, otherwise this comparison is invalid.
    c = runs[0.5]['domains']['lineweaver_7_9']
    require(abs(c['N_G'] - 263061992.36674243) < 1e-2, f"N_G anchor mismatch: {c['N_G']}")
    require(
        abs(c['Lambda_ESHZ'] - 105716685.0799756) < 1e-2,
        f"Lambda_ESHZ anchor mismatch: {c['Lambda_ESHZ']}",
    )
    require(
        abs(c['Lambda_earth10'] - 3376462.6740267016) < 1e-2,
        f"Lambda_earth10 anchor mismatch: {c['Lambda_earth10']}",
    )

    result = {
        'schema_version': 2,
        'experiment': 'final_TAMS_radial_convergence',
        'definition': 'delta_(coarse_to_fine)=(X_fine-X_coarse)/X_fine',
        'pass_threshold_abs_fraction': 0.01,
        'producer_contract': producer_contract,
        'numerical_runtime_policy': runtime_record,
        'run_artifacts': run_artifacts,
        'runs': {str(k): v for k, v in runs.items()},
        'comparisons': {},
        'pass': True,
    }
    rows = []
    for domain in DOMAINS:
        result['comparisons'][domain] = {}
        for coarse, fine in [(1.0, 0.5), (0.5, 0.25)]:
            name = f"{coarse}_to_{fine}"
            d = {}
            for q in QUANTITIES:
                x0 = runs[coarse]['domains'][domain][q]
                x1 = runs[fine]['domains'][domain][q]
                delta = rel(x1, x0)
                d[q] = {'coarse': x0, 'fine': x1, 'delta_fraction': delta, 'delta_percent': 100*delta}
                rows.append({
                    'domain': domain, 'coarse_dR_kpc': coarse, 'fine_dR_kpc': fine,
                    'quantity': q, 'coarse_value': x0, 'fine_value': x1,
                    'delta_fraction': delta, 'delta_percent': 100*delta,
                })
            result['comparisons'][domain][name] = d

    # Publication gate: final 0.5 -> 0.25 change must be <1% in N_G, L1 and L2
    # for the canonical 7-9 kpc estimand.
    final_cmp = result['comparisons']['lineweaver_7_9']['0.5_to_0.25']
    for q in QUANTITIES:
        if abs(final_cmp[q]['delta_fraction']) >= result['pass_threshold_abs_fraction']:
            result['pass'] = False
    if not result['pass']:
        raise RuntimeError('FINAL_TAMS_RADIAL_CONVERGENCE_FAIL: 0.5->0.25 exceeds 1%')

    table_path = out/'tams_radial_convergence_table.csv'
    with table_path.open('w', newline='', encoding='utf-8') as f:
        cols = ['domain','coarse_dR_kpc','fine_dR_kpc','quantity','coarse_value','fine_value','delta_fraction','delta_percent']
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
    result_path = out/'tams_radial_convergence_results.json'
    result_path.write_text(json.dumps(result, indent=2, allow_nan=False), encoding='utf-8')
    contract_table = contract / table_path.name
    contract_result = contract / result_path.name
    stable_copy(table_path, contract_table)
    stable_copy(result_path, contract_result)
    contract_targets.extend((contract_table, contract_result))
    (contract / CONTRACT_MANIFEST).write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in contract_targets),
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
