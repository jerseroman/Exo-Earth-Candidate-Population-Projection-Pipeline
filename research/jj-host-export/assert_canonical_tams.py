#!/usr/bin/env python3
"""Fail fast unless the canonical JJ artifact files are the corrected TAMS provider."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat

import numpy as np


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def is_portable_safe_leaf(value):
    """Return true only for one path leaf under both POSIX and Windows rules."""
    return (
        isinstance(value, str)
        and value not in {'', '.', '..'}
        and '\x00' not in value
        and '/' not in value
        and '\\' not in value
        and ':' not in value
        and PurePosixPath(value).name == value
        and PureWindowsPath(value).name == value
    )


def read_regular_bytes(path, description):
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise RuntimeError(f'Cannot inspect {description}: {exc}') from exc
    require(not stat.S_ISLNK(before.st_mode) and stat.S_ISREG(before.st_mode),
            f'{description} must be a regular non-symlink file')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, 'rb') as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
    except OSError as exc:
        raise RuntimeError(f'Cannot read {description}: {exc}') from exc
    after = candidate.lstat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    require(len(identities) == 1 and len(data) == opened_after.st_size
            and stat.S_ISREG(after.st_mode) and not stat.S_ISLNK(after.st_mode),
            f'{description} changed while being read')
    return data


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f'Duplicate JSON key: {key!r}')
        value[key] = item
    return value


def reject_constant(token):
    raise RuntimeError(f'Non-finite JSON constant: {token}')


def finite_float(token):
    value = float(token)
    require(math.isfinite(value), f'Non-finite JSON number: {token}')
    return value


def load_strict_json(path, description):
    try:
        return json.loads(
            read_regular_bytes(path, description).decode('utf-8'),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f'Cannot parse strict JSON {description}: {exc}') from exc


def verify_checksum_manifest(root, manifest_name, expected_names):
    manifest=root/manifest_name
    manifest_bytes = read_regular_bytes(manifest, f'checksum manifest {manifest_name}')
    listed=[]
    try:
        lines = manifest_bytes.decode('utf-8').splitlines()
    except UnicodeError as exc:
        raise RuntimeError(f'Non-UTF-8 checksum manifest {manifest_name}: {exc}') from exc
    for line in lines:
        parts=line.split('  ',1)
        require(len(parts)==2,f'Malformed checksum line in {manifest_name}: {line!r}')
        expected,name=parts
        require(is_portable_safe_leaf(name),f'Unsafe checksum filename in {manifest_name}: {name!r}')
        target=root/name
        observed=hashlib.sha256(
            read_regular_bytes(target, f'manifest target {name}')
        ).hexdigest()
        require(observed==expected,f'Checksum mismatch in {manifest_name}: {name}')
        listed.append(name)
    require(listed==list(expected_names),f'Unexpected file set in {manifest_name}: {listed}')


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True)
    a=ap.parse_args(); root=Path(a.out)
    s=load_strict_json(root/'jj_g_hosts_summary_padova.json', 'canonical host summary')
    require(s['host_provider_id']=='jj_padova_dr05_parsec_tams_v1', f"Unexpected host provider: {s}")
    require('logg' not in s['host_estimand'], f"Legacy logg selector remains: {s['host_estimand']}")
    require(s['host_estimand']['explicit_metallicity_dimension'] is False, 'Unexpected metallicity dimension')
    require(abs(s['N_G_hosts_age_ge_4p57_R4_14']-1238302534.419577)<1e-2, 'N_G R4--14 anchor mismatch')
    require(abs(s['N_G_hosts_age_ge_4p57_R7_9']-263061992.36670703)<1e-2, 'N_G R7--9 anchor mismatch')
    require(abs(s['thick_disk_fraction_R7_9']-0.19893903660103215)<1e-12, 'Thick-disk fraction anchor mismatch')

    R=[]; y=[]
    radial_bytes = read_regular_bytes(
        root/'jj_g_hosts_radial_padova.csv', 'canonical radial host table'
    )
    with io.StringIO(radial_bytes.decode('utf-8'), newline='') as f:
        for r in csv.DictReader(f):
            R.append(float(r['R_kpc'])); y.append(float(r['dN_dR_stars_kpc-1']))
    R=np.asarray(R); y=np.asarray(y); q=(R>=4)&(R<=14)
    n=float(np.trapz(y[q],R[q]))
    require(abs(n-1238302534.419577)<1e-2, f'Integrated N_G anchor mismatch: {n}')

    # Ensure the old provider is retained only under an explicit legacy name.
    require((root/'jj_g_hosts_radial_padova_legacy_logg43.csv').exists(), 'Missing legacy radial artifact')
    require((root/'jj_g_hosts_summary_padova_legacy_logg43.json').exists(), 'Missing legacy summary artifact')
    legacy=load_strict_json(
        root/'jj_g_hosts_summary_padova_legacy_logg43.json', 'legacy host summary'
    )
    require(abs(legacy['N_G_hosts_age_ge_4p57_R4_14']-937546039.0254495)<1e-2, 'Legacy N_G anchor mismatch')

    canonical_names=(
        'jj_g_hosts_radial_padova.csv',
        'jj_g_hosts_R_T_padova.csv',
        'jj_g_hosts_R_T_age_padova.csv',
        'jj_g_hosts_raw_eligible_padova.csv',
        'jj_g_hosts_summary_padova.json',
    )
    legacy_names=tuple(
        f'{Path(name).stem}_legacy_logg43{Path(name).suffix}'
        for name in canonical_names
    )
    verify_checksum_manifest(root,'SHA256SUMS_padova.txt',canonical_names)
    verify_checksum_manifest(root,'SHA256SUMS_padova_legacy_logg43.txt',legacy_names)

    print('CANONICAL_MAIN_FILES_TAMS_PASS',n)

if __name__=='__main__': main()
