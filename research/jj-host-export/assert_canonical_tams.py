#!/usr/bin/env python3
"""Fail fast unless the canonical JJ artifact files are the corrected TAMS provider."""
import argparse
import csv
import json
from pathlib import Path

import numpy as np


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True)
    a=ap.parse_args(); root=Path(a.out)
    s=json.loads((root/'jj_g_hosts_summary_padova.json').read_text(encoding='utf-8'))
    require(s['host_provider_id']=='jj_padova_dr05_parsec_tams_v1', f"Unexpected host provider: {s}")
    require('logg' not in s['host_estimand'], f"Legacy logg selector remains: {s['host_estimand']}")
    require(s['host_estimand']['explicit_metallicity_dimension'] is False, 'Unexpected metallicity dimension')
    require(abs(s['N_G_hosts_age_ge_4p57_R4_14']-1238302534.419577)<1e-2, 'N_G R4--14 anchor mismatch')
    require(abs(s['N_G_hosts_age_ge_4p57_R7_9']-263061992.36670703)<1e-2, 'N_G R7--9 anchor mismatch')
    require(abs(s['thick_disk_fraction_R7_9']-0.19893903660103215)<1e-12, 'Thick-disk fraction anchor mismatch')

    R=[]; y=[]
    with (root/'jj_g_hosts_radial_padova.csv').open(newline='',encoding='utf-8') as f:
        for r in csv.DictReader(f):
            R.append(float(r['R_kpc'])); y.append(float(r['dN_dR_stars_kpc-1']))
    R=np.asarray(R); y=np.asarray(y); q=(R>=4)&(R<=14)
    n=float(np.trapz(y[q],R[q]))
    require(abs(n-1238302534.419577)<1e-2, f'Integrated N_G anchor mismatch: {n}')

    # Ensure the old provider is retained only under an explicit legacy name.
    require((root/'jj_g_hosts_radial_padova_legacy_logg43.csv').exists(), 'Missing legacy radial artifact')
    require((root/'jj_g_hosts_summary_padova_legacy_logg43.json').exists(), 'Missing legacy summary artifact')
    legacy=json.loads((root/'jj_g_hosts_summary_padova_legacy_logg43.json').read_text(encoding='utf-8'))
    require(abs(legacy['N_G_hosts_age_ge_4p57_R4_14']-937546039.0254495)<1e-2, 'Legacy N_G anchor mismatch')

    print('CANONICAL_MAIN_FILES_TAMS_PASS',n)

if __name__=='__main__': main()
