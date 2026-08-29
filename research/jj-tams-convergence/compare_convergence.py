#!/usr/bin/env python3
"""Compare fully regenerated TAMS runs at dR=1.0, 0.5 and 0.25 kpc."""
import argparse
import csv
import json
from pathlib import Path

DRS = [1.0, 0.5, 0.25]
QUANTITIES = ["N_G", "Lambda_ESHZ", "Lambda_earth10"]
DOMAINS = ["lineweaver_7_9", "full_JJ_4_14"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tag(dr):
    return str(dr).replace('.', 'p')


def rel(new, old):
    # Convergence convention used in the project: (finer - coarser) / finer.
    return (new - old) / new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    root = Path(args.root)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    runs = {}
    for dr in DRS:
        p = root / f"dr{tag(dr)}" / f"tams_result_dr{tag(dr)}.json"
        runs[dr] = json.loads(p.read_text())
        require(
            abs(float(runs[dr]['dR_kpc']) - dr) < 1e-12,
            f"Radial-spacing label mismatch for {p}",
        )

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
        'experiment': 'final_TAMS_radial_convergence',
        'definition': 'delta_(coarse_to_fine)=(X_fine-X_coarse)/X_fine',
        'pass_threshold_abs_fraction': 0.01,
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

    with (out/'tams_radial_convergence_table.csv').open('w', newline='', encoding='utf-8') as f:
        cols = ['domain','coarse_dR_kpc','fine_dR_kpc','quantity','coarse_value','fine_value','delta_fraction','delta_percent']
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
    (out/'tams_radial_convergence_results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
