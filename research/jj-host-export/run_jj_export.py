#!/usr/bin/env python3
"""Reproducible JJ host-population export for the ESHZ equation.

Pinned science target:
  - JJ thin + thick disk only
  - 4 <= R_GC <= 14 kpc (official tutorial2 radial configuration)
  - G-dwarf operational cut: 5300 <= Teff <= 6000 K
  - dwarf/main-sequence proxy: 4.3 < logg < 7.0
  - age >= 4.57 Gyr
  - Padova/PARSEC primary isochrone set
  - no metallicity occurrence correction
  - no GHZ/SN environmental mask

The JJ stellar-assembly tables contain N in present-day number pc^-2. We sum N
for eligible rows to obtain Sigma_G(R), then integrate 2*pi*R*Sigma_G(R) over R.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

import numpy as np
from astropy.table import Table

JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
TMIN, TMAX = 5300.0, 6000.0
LOGG_MIN, LOGG_MAX = 4.3, 7.0
AGE_MIN = 4.57
RMIN_KPC, RMAX_KPC, DR_KPC = 4.0, 14.0, 0.5
T_EDGES = np.arange(5300.0, 6000.0 + 100.0, 100.0)
AGE_EDGES = np.arange(4.50, 13.25 + 0.25, 0.25)


def exact_radial_step(value: str) -> Decimal:
    """Parse the workflow assertion for the single audited production grid."""

    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError("radial step must be a decimal number") from exc
    if not parsed.is_finite() or parsed != Decimal("0.5"):
        raise argparse.ArgumentTypeError(
            "the audited production radial step must be exactly 0.5 kpc"
        )
    return parsed


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(args, cwd=None):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def verify_jj_worktree(jj_root):
    """Reject source edits and any untracked files outside locked isochrones."""
    for arguments in (["diff", "--quiet", "HEAD", "--"],
                      ["diff", "--cached", "--quiet", "HEAD", "--"]):
        result = subprocess.run(["git", *arguments], cwd=jj_root, check=False)
        if result.returncode != 0:
            raise RuntimeError("JJ tracked source differs from the pinned commit")
    untracked = git(["ls-files", "--others", "--exclude-standard"], cwd=jj_root)
    allowed_prefix = "jjmodel/input/isochrones/Padova/"
    unexpected = [
        item for item in untracked.splitlines()
        if item and not item.startswith(allowed_prefix)
    ]
    if unexpected:
        raise RuntimeError(
            "JJ checkout contains untracked files outside the locked Padova "
            f"input tree: {unexpected[:5]!r}"
        )


def write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    import csv
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def select_rows(tab: Table):
    teff = np.power(10.0, np.asarray(tab["logT"], dtype=float))
    logg = np.asarray(tab["logg"], dtype=float)
    age = np.asarray(tab["age"], dtype=float)
    n = np.asarray(tab["N"], dtype=float)
    keep = (
        (teff >= TMIN) & (teff <= TMAX) &
        (logg > LOGG_MIN) & (logg < LOGG_MAX) &
        (age >= AGE_MIN) & np.isfinite(n) & (n >= 0)
    )
    return teff[keep], age[keep], n[keep]


def validate_radial_grid(
    rmin: float, rmax: float, dr: float, grid: np.ndarray
) -> np.ndarray:
    """Fail closed unless the configured and realized JJ grid is exactly pinned."""

    observed = np.asarray(grid, dtype=float)
    configured = np.asarray([rmin, rmax, dr], dtype=float)
    if not np.all(np.isfinite(configured)) or not np.all(np.isfinite(observed)):
        raise RuntimeError("JJ radial configuration contains a non-finite value")
    if (rmin, rmax, dr) != (RMIN_KPC, RMAX_KPC, DR_KPC):
        raise RuntimeError(
            "Unexpected JJ radial config: "
            f"Rmin={rmin}, Rmax={rmax}, dR={dr}; expected "
            f"{RMIN_KPC}, {RMAX_KPC}, {DR_KPC} kpc"
        )
    expected = np.arange(RMIN_KPC, RMAX_KPC + DR_KPC / 2.0, DR_KPC)
    if observed.ndim != 1 or observed.shape != expected.shape or not np.allclose(
        observed, expected, rtol=0.0, atol=1.0e-12
    ):
        raise RuntimeError(
            "Realized JJ radial grid differs from the pinned inclusive "
            f"{RMIN_KPC:g}--{RMAX_KPC:g} kpc grid at dR={DR_KPC:g} kpc"
        )
    return observed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jj-root", required=True, help="Pinned askenja/jjmodel checkout")
    ap.add_argument("--run-dir", required=True, help="Working dir containing official tutorial2 parameters")
    ap.add_argument("--out", required=True)
    ap.add_argument("--iso", default="Padova", choices=["Padova", "MIST", "BaSTI"])
    ap.add_argument(
        "--expected-radial-step-kpc",
        required=True,
        type=exact_radial_step,
        help="Fail-closed assertion for the audited 0.5-kpc production grid",
    )
    args = ap.parse_args()

    jj_root = Path(args.jj_root).resolve()
    run_dir = Path(args.run_dir).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    actual_sha = git(["rev-parse", "HEAD"], cwd=jj_root)
    if actual_sha != JJ_SHA:
        raise RuntimeError(f"JJ commit mismatch: {actual_sha} != {JJ_SHA}")
    verify_jj_worktree(jj_root)

    os.chdir(run_dir)
    sys.path.insert(0, str(jj_root))

    from jjmodel.funcs import IMF
    from jjmodel.iof import dir_tree
    from jjmodel.input_ import p, a, inp
    from jjmodel.populations import stellar_assemblies_r

    radial_grid = validate_radial_grid(
        float(p.Rmin),
        float(p.Rmax),
        float(args.expected_radial_step_kpc),
        np.asarray(a.R, dtype=float),
    )
    if float(p.dR) != float(args.expected_radial_step_kpc):
        raise RuntimeError(
            f"JJ parameter dR={p.dR} differs from the explicit workflow assertion "
            f"{args.expected_radial_step_kpc} kpc"
        )

    dir_tree(p, make=True)

    imf_obj = IMF(0.08, 100.0)
    if int(p.imfkey) != 0:
        raise RuntimeError("This reproducible run expects JJ tutorial2 imfkey=0 (4BPL)")
    imf_obj.BPL_4slopes(p.a0, p.a1, p.a2, p.a3, p.m0, p.m1, p.m2)
    imf = imf_obj.number_stars

    for i, R in enumerate(radial_grid):
        sigmash_R = float(inp["SigmaR"][5][i])
        stellar_assemblies_r(
            float(R), p, a,
            inp["AMRd"][i], inp["AMRt"],
            inp["SFRd"][i], inp["SFRt"][i],
            sigmash_R, imf, args.iso, 3,
        )

    poptab = Path(a.T["poptab"])
    radial_rows = []
    detail_rows = []
    age_rows = []

    for R in radial_grid:
        sigmas = {}
        combined_teff, combined_age, combined_n = [], [], []
        for comp, label in [("d", "thin"), ("t", "thick")]:
            path = poptab / f"SSP_R{R}_{comp}_{args.iso}.csv"
            if not path.exists():
                alt = poptab / f"SSP_R{str(float(R))}_{comp}_{args.iso}.csv"
                path = alt if alt.exists() else path
            if not path.exists():
                raise FileNotFoundError(path)
            tab = Table.read(path, format="ascii.csv")
            teff, age, n = select_rows(tab)
            sigmas[label] = float(n.sum())
            combined_teff.append(teff); combined_age.append(age); combined_n.append(n)

            for j in range(len(T_EDGES)-1):
                lo, hi = T_EDGES[j], T_EDGES[j+1]
                mask = ((teff >= lo) & (teff <= hi)) if j == len(T_EDGES)-2 else ((teff >= lo) & (teff < hi))
                detail_rows.append([R, label, lo, hi, float(n[mask].sum())])

        teff = np.concatenate(combined_teff)
        age = np.concatenate(combined_age)
        n = np.concatenate(combined_n)
        sigma_total = sigmas["thin"] + sigmas["thick"]
        dN_dR = 2.0 * math.pi * float(R) * 1.0e6 * sigma_total
        radial_rows.append([R, sigmas["thin"], sigmas["thick"], sigma_total, dN_dR])

        for j in range(len(T_EDGES)-1):
            tlo, thi = T_EDGES[j], T_EDGES[j+1]
            tmask = ((teff >= tlo) & (teff <= thi)) if j == len(T_EDGES)-2 else ((teff >= tlo) & (teff < thi))
            for k in range(len(AGE_EDGES)-1):
                alo, ahi = AGE_EDGES[k], AGE_EDGES[k+1]
                amask = (age >= max(alo, AGE_MIN)) & (age < ahi)
                val = float(n[tmask & amask].sum())
                if val > 0:
                    age_rows.append([R, tlo, thi, alo, ahi, val])

    radial_rows.sort(key=lambda x: x[0])
    detail_rows.sort(key=lambda x: (x[0], x[1], x[2]))
    age_rows.sort(key=lambda x: (x[0], x[1], x[3]))

    radial_path = out / f"jj_g_hosts_radial_{args.iso.lower()}.csv"
    temp_path = out / f"jj_g_hosts_R_T_{args.iso.lower()}.csv"
    age_path = out / f"jj_g_hosts_R_T_age_{args.iso.lower()}.csv"
    write_csv(radial_path,
              ["R_kpc","Sigma_G_thin_pc-2","Sigma_G_thick_pc-2","Sigma_G_total_pc-2","dN_dR_stars_kpc-1"], radial_rows)
    write_csv(temp_path,
              ["R_kpc","component","T_lo_K","T_hi_K","Sigma_G_pc-2"], detail_rows)
    write_csv(age_path,
              ["R_kpc","T_lo_K","T_hi_K","age_lo_Gyr","age_hi_Gyr","Sigma_G_pc-2"], age_rows)

    R = np.array([r[0] for r in radial_rows], dtype=float)
    y = np.array([r[4] for r in radial_rows], dtype=float)
    N_total = float(np.trapz(y, R))

    summary = {
        "jj_repository": "askenja/jjmodel",
        "jj_commit": actual_sha,
        "jj_version_expected": "1.0.1",
        "jj_parameter_source": "jjmodel/tutorials/tutorial2/parameters at pinned commit",
        "jj_sfr_peaks_source": "jjmodel/tutorials/tutorial2/sfrd_peaks_parameters at pinned commit",
        "isochrone_family": args.iso,
        "host_estimand": {
            "Teff_K": [TMIN, TMAX],
            "logg": [LOGG_MIN, LOGG_MAX],
            "logg_interval": "open",
            "age_Gyr_min": AGE_MIN,
            "components": ["thin_disk", "thick_disk"],
            "R_kpc_integrated": [float(R.min()), float(R.max())]
        },
        "radial_grid_kpc": {
            "minimum": RMIN_KPC,
            "maximum": RMAX_KPC,
            "spacing": DR_KPC,
            "node_count": int(radial_grid.size),
        },
        "integration": (
            "N = integral_4^14 [2*pi*R*1e6*Sigma_G(R)] dR; "
            "trapezoidal on the pinned JJ 0.5-kpc grid"
        ),
        "N_G_hosts_age_ge_4p57_R4_14": N_total,
        "no_GHZ_SN_mask": True,
        "no_planet_occurrence_metallicity_correction": True,
        "python": sys.version,
        "platform": platform.platform(),
    }
    summary_path = out / f"jj_g_hosts_summary_{args.iso.lower()}.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    checksums = out / f"SHA256SUMS_{args.iso.lower()}.txt"
    files = [radial_path, temp_path, age_path, summary_path]
    checksums.write_text("".join(f"{sha256(pth)}  {pth.name}\n" for pth in files), encoding="utf-8")

    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
