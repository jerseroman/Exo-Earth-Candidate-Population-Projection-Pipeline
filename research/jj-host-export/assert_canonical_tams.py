#!/usr/bin/env python3
"""Fail fast unless the canonical JJ artifact files are the corrected TAMS provider."""
from pathlib import Path
import argparse, csv, json
import numpy as np


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True)
    a=ap.parse_args(); root=Path(a.out)
    s=json.loads((root/'jj_g_hosts_summary_padova.json').read_text(encoding='utf-8'))
    assert s['host_provider_id']=='jj_padova_dr05_parsec_tams_v1', s
    assert 'logg' not in s['host_estimand'], s['host_estimand']
    assert s['host_estimand']['explicit_metallicity_dimension'] is False
    assert abs(s['N_G_hosts_age_ge_4p57_R4_14']-1238302534.419577)<1e-2
    assert abs(s['N_G_hosts_age_ge_4p57_R7_9']-263061992.36670703)<1e-2
    assert abs(s['thick_disk_fraction_R7_9']-0.19893903660103215)<1e-12

    R=[]; y=[]
    with (root/'jj_g_hosts_radial_padova.csv').open(newline='',encoding='utf-8') as f:
        for r in csv.DictReader(f):
            R.append(float(r['R_kpc'])); y.append(float(r['dN_dR_stars_kpc-1']))
    R=np.asarray(R); y=np.asarray(y); q=(R>=4)&(R<=14)
    n=float(np.trapz(y[q],R[q]))
    assert abs(n-1238302534.419577)<1e-2, n

    # Ensure the old provider is retained only under an explicit legacy name.
    assert (root/'jj_g_hosts_radial_padova_legacy_logg43.csv').exists()
    assert (root/'jj_g_hosts_summary_padova_legacy_logg43.json').exists()
    legacy=json.loads((root/'jj_g_hosts_summary_padova_legacy_logg43.json').read_text(encoding='utf-8'))
    assert abs(legacy['N_G_hosts_age_ge_4p57_R4_14']-937546039.0254495)<1e-2

    print('CANONICAL_MAIN_FILES_TAMS_PASS',n)

if __name__=='__main__': main()
