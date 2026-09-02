#!/usr/bin/env python3
"""Run one fully regenerated JJ/PARSEC-TAMS radial-resolution experiment.

This script is intentionally independent of the canonical artifact-promotion path.
For the requested JJ radial spacing it:
  1. regenerates the official tutorial2 stellar assemblies,
  2. applies the final PARSEC-TAMS host selector,
  3. evaluates the frozen Bryson Model-1 constant-completeness + Kopparapu CHZ
     L1 and L2 integrals on every selected stellar assembly,
  4. integrates N_G, L1 and L2 over 7-9 kpc and 4-14 kpc.

Only radial numerical resolution is allowed to vary between experiments.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
from astropy.table import Table

JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
TMIN, TMAX = 5300.0, 6000.0
AGE_MIN = 4.57
LOGG_MAX = 7.0
LOGG_SUN = 4.438
TSUN_RADIUS = 5772.0
ALLOWED_DR = (1.0, 0.5, 0.25)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)

# Public PARSEC TAMS boundary used by the Berger/Huber evolstate implementation.
TAMS_T = np.array([
    5200.,5390.13944,5517.85139,5633.13293,5738.25706,5844.13178,
    5951.82290,6060.24246,6263.10943,6330.52896,6376.75894,6370.00833,
    6360.04224,6365.16989,6349.06831,6406.93031,6476.34536,6561.45266,
    6662.69603,6781.56611,6920.69962,7067.56807,7202.44582,7344.80043,
    7484.96890,7625.52940,7767.11973,7907.87872,8048.22298,8188.04084,
    8326.83579,8602.40727,9159.67364,9685.90042,10204.92929,10710.25966,
    11201.59844,11683.15127,12154.86109,12612.46575,13058.70166,
    13493.66736,13922.58891,14335.07601,14734.31669,15127.25055,
    15507.79317,15880.71310,16243.51448
])
TAMS_R = np.array([
    1.15,1.22926,1.28542,1.35053,1.42375,1.49188,1.55332,1.61155,
    1.51292,1.69428,1.87034,2.08391,2.31769,2.56130,2.84178,2.99416,
    3.13931,3.25953,3.37272,3.46581,3.53138,3.59009,3.66210,3.72130,
    3.77920,3.84025,3.89439,3.94839,4.00221,4.05219,4.10530,4.20431,
    4.37602,4.56052,4.72911,4.89345,5.05085,5.19876,5.34072,5.48056,
    5.61513,5.75195,5.87131,5.99901,6.12308,6.24748,6.37265,6.49419,
    6.61690
])

# Frozen canonical occurrence branch: Bryson Model 1, hab2, constant completeness.
F0 = 1.107
ALPHA = -1.082
BETA = -0.839
GAMMA = -2.671
T0, TBREAK, T1 = 3900.0, 5117.0, 6300.0
RUNAWAY = (1.107, 1.332e-4, 1.580e-8, -8.308e-12, -1.931e-15)
MAX_GREENHOUSE = (0.356, 6.171e-5, 1.698e-9, -3.198e-12, -5.575e-16)


def git(args, cwd=None):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def verify_jj_worktree(jj_root):
    """Reject source edits and untracked executable shadow files."""
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


def power_integral(lo, hi, p):
    return (hi ** (p + 1) - lo ** (p + 1)) / (p + 1)


ARFIT = power_integral(0.5, 2.5, ALPHA)
AIFIT = power_integral(0.2, 2.2, BETA)
Q1 = GAMMA + 3.16
Q2 = GAMMA + 4.49
GBAR = (
    10 ** (-11.839) * power_integral(T0, TBREAK, Q1)
    + 10 ** (-16.769) * power_integral(TBREAK, T1, Q2)
) / (T1 - T0)
C1 = 1.0 / (ARFIT * AIFIT * GBAR)
AR_HZ = power_integral(0.5, 1.5, ALPHA)
AR10 = power_integral(0.9, 1.1, ALPHA)


def hz_flux(T, coeff):
    x = np.asarray(T, float) - 5780.0
    s, a, b, c, d = coeff
    return s + a * x + b * x**2 + c * x**3 + d * x**4


def occurrence_prefactor(T):
    T = np.asarray(T, float)
    g = np.where(
        T <= TBREAK,
        10 ** (-11.839) * T**3.16,
        10 ** (-16.769) * T**4.49,
    )
    return F0 * C1 * T**GAMMA * g


def f_hz(T):
    outer = hz_flux(T, MAX_GREENHOUSE)
    inner = hz_flux(T, RUNAWAY)
    ai = (inner ** (BETA + 1) - outer ** (BETA + 1)) / (BETA + 1)
    return occurrence_prefactor(T) * AR_HZ * ai


def f_earth10(T):
    outer = hz_flux(T, MAX_GREENHOUSE)
    inner = hz_flux(T, RUNAWAY)
    lo = np.maximum(0.9, outer)
    hi = np.minimum(1.1, inner)
    ai = np.where(
        hi > lo,
        (hi ** (BETA + 1) - lo ** (BETA + 1)) / (BETA + 1),
        0.0,
    )
    return occurrence_prefactor(T) * AR10 * ai


def integrate(radial, key, lo, hi):
    rows = [r for r in radial if lo <= r["R_kpc"] <= hi]
    R = np.array([r["R_kpc"] for r in rows], float)
    y = np.array([r[key] for r in rows], float)
    if len(R) < 2 or abs(R[0] - lo) > 1e-9 or abs(R[-1] - hi) > 1e-9:
        raise RuntimeError(f"Domain endpoints not represented for {lo}-{hi}: {R}")
    return float(np.trapz(y, R))


def write_radial(path, radial):
    cols = ["R_kpc", "dN_dR", "dL1_dR", "dL2_dR", "Sigma_TAMS_pc-2", "Sigma_thick_TAMS_pc-2"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(radial)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jj-root", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--iso", default="Padova")
    args = ap.parse_args()

    jj_root = Path(args.jj_root).resolve()
    run_dir = Path(args.run_dir).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    actual_sha = git(["rev-parse", "HEAD"], cwd=jj_root)
    if actual_sha != JJ_SHA:
        raise RuntimeError(f"JJ commit mismatch: {actual_sha} != {JJ_SHA}")
    verify_jj_worktree(jj_root)

    sys.path.insert(0, str(jj_root))
    os.chdir(run_dir)
    from jjmodel.funcs import IMF
    from jjmodel.input_ import a, inp, p
    from jjmodel.iof import dir_tree
    from jjmodel.populations import stellar_assemblies_r

    dr = float(p.dR)
    if float(p.Rmin) != 4.0 or float(p.Rmax) != 14.0 or not any(abs(dr-x) < 1e-12 for x in ALLOWED_DR):
        raise RuntimeError(f"Unexpected JJ radial config: Rmin={p.Rmin}, Rmax={p.Rmax}, dR={p.dR}")

    dir_tree(p, make=True)
    imf_obj = IMF(0.08, 100.0)
    if int(p.imfkey) != 0:
        raise RuntimeError("Expected tutorial2 imfkey=0")
    imf_obj.BPL_4slopes(p.a0, p.a1, p.a2, p.a3, p.m0, p.m1, p.m2)
    imf = imf_obj.number_stars

    for i, R in enumerate(np.asarray(a.R, dtype=float)):
        stellar_assemblies_r(
            float(R), p, a,
            inp["AMRd"][i], inp["AMRt"],
            inp["SFRd"][i], inp["SFRt"][i],
            float(inp["SigmaR"][5][i]), imf, args.iso, 3,
        )

    poptab = Path(a.T["poptab"])
    radial = []
    selected_rows = 0
    compact_rejected_rows = 0
    compact_rejected_weight = 0.0

    for R in np.asarray(a.R, dtype=float):
        sigma_total = 0.0
        sigma_thick = 0.0
        weighted_l1 = 0.0
        weighted_l2 = 0.0
        for comp, label in [("d", "thin"), ("t", "thick")]:
            path = poptab / f"SSP_R{R}_{comp}_{args.iso}.csv"
            if not path.exists():
                path = poptab / f"SSP_R{str(float(R))}_{comp}_{args.iso}.csv"
            tab = Table.read(path, format="ascii.csv")
            age = np.asarray(tab["age"], float)
            mf = np.asarray(tab["Mf"], float)
            logL = np.asarray(tab["logL"], float)
            logT = np.asarray(tab["logT"], float)
            logg = np.asarray(tab["logg"], float)
            n = np.asarray(tab["N"], float)
            teff = 10**logT
            parent = (
                (teff >= TMIN) & (teff <= TMAX) & (age >= AGE_MIN)
                & np.isfinite(n) & (n >= 0) & np.isfinite(mf) & (mf > 0)
                & np.isfinite(logL) & np.isfinite(logg)
            )
            T = teff[parent]
            M = mf[parent]
            lg = logg[parent]
            wt = n[parent]
            rstar = np.sqrt(M * 10 ** (LOGG_SUN - lg))
            rtams = 10 ** np.interp(T, TAMS_T, np.log10(TAMS_R))
            below_tams = rstar <= rtams
            compact = below_tams & (lg >= LOGG_MAX)
            selected = below_tams & (lg < LOGG_MAX)
            compact_rejected_rows += int(np.count_nonzero(compact))
            compact_rejected_weight += float(wt[compact].sum())
            selected_rows += int(np.count_nonzero(selected))
            sw = wt[selected]
            sT = T[selected]
            sig = float(sw.sum())
            sigma_total += sig
            if label == "thick":
                sigma_thick += sig
            weighted_l1 += float(np.sum(sw * f_hz(sT)))
            weighted_l2 += float(np.sum(sw * f_earth10(sT)))

        fac = 2.0 * math.pi * float(R) * 1.0e6
        radial.append({
            "R_kpc": float(R),
            "dN_dR": fac * sigma_total,
            "dL1_dR": fac * weighted_l1,
            "dL2_dR": fac * weighted_l2,
            "Sigma_TAMS_pc-2": sigma_total,
            "Sigma_thick_TAMS_pc-2": sigma_thick,
        })

    radial.sort(key=lambda x: x["R_kpc"])
    domains = {}
    for name, lo, hi in [("lineweaver_7_9", 7.0, 9.0), ("full_JJ_4_14", 4.0, 14.0)]:
        N = integrate(radial, "dN_dR", lo, hi)
        L1 = integrate(radial, "dL1_dR", lo, hi)
        L2 = integrate(radial, "dL2_dR", lo, hi)
        require(
            N > 0 and L1 >= 0 and L2 >= 0 and L2 <= L1,
            f"Invalid integrated population ordering for {name}: {N=}, {L1=}, {L2=}",
        )
        domains[name] = {
            "R_kpc": [lo, hi],
            "N_G": N,
            "Lambda_ESHZ": L1,
            "Lambda_earth10": L2,
            "mean_f_HZ": L1 / N,
            "mean_f_earth10": L2 / N,
            "L2_over_L1": L2 / L1,
        }

    result = {
        "experiment": "final_TAMS_radial_convergence",
        "jj_commit": actual_sha,
        "isochrone_family": args.iso,
        "dR_kpc": dr,
        "radial_nodes": len(radial),
        "host_selector": "5300<=Teff<=6000 K; age>=4.57 Gyr; thin+thick; Rstar<=PARSEC-TAMS(Teff); logg<7 remnant veto",
        "occurrence_branch": "Bryson Model 1 hab2 constant-completeness + Kopparapu conservative HZ",
        "selected_stellar_assembly_rows": selected_rows,
        "compact_remnant_rows_rejected": compact_rejected_rows,
        "compact_remnant_surface_weight_rejected_sum_pc-2": compact_rejected_weight,
        "C1": C1,
        "domains": domains,
    }

    tag = str(dr).replace(".", "p")
    write_radial(out / f"tams_radial_dr{tag}.csv", radial)
    (out / f"tams_result_dr{tag}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
