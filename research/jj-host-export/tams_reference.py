#!/usr/bin/env python3
"""Immutable PARSEC-TAMS reference loader for the G-dwarf host provider."""
from pathlib import Path
import hashlib
import io
import numpy as np

REFERENCE_PATH = Path(__file__).resolve().parent / 'reference-data' / 'tams_parsec_danxhuber.txt'
EXPECTED_SHA256 = 'd2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac'
EXPECTED_ROWS = 49
G_SEGMENT_TMAX = 6060.24246


def load_full_tams_table():
    raw = REFERENCE_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise RuntimeError(f'TAMS reference checksum mismatch: {digest} != {EXPECTED_SHA256}')
    data = np.loadtxt(io.BytesIO(raw), dtype=float)
    if data.shape != (EXPECTED_ROWS, 2):
        raise RuntimeError(f'Unexpected TAMS table shape: {data.shape}')
    return data[:,0], data[:,1]


def load_g_dwarf_tams_segment():
    T, R = load_full_tams_table()
    use = T <= G_SEGMENT_TMAX + 1e-9
    T, R = T[use], R[use]
    if len(T) != 8:
        raise RuntimeError(f'Expected 8 rows in validated G segment, got {len(T)}')
    if not np.all(np.diff(T) > 0):
        raise RuntimeError('Validated G-star TAMS segment must be strictly increasing in Teff')
    if np.any(R <= 0):
        raise RuntimeError('TAMS radii must be positive')
    return T, R


def tams_radius_rsun(teff):
    """Interpolate R_TAMS in log10 radius; extrapolation is forbidden."""
    x = np.asarray(teff, dtype=float)
    T, R = load_g_dwarf_tams_segment()
    if np.any(x < T[0]) or np.any(x > T[-1]):
        raise ValueError(
            f'TAMS extrapolation forbidden: requested Teff range '
            f'[{float(np.min(x))}, {float(np.max(x))}] K outside [{T[0]}, {T[-1]}] K'
        )
    return 10.0 ** np.interp(x, T, np.log10(R))
