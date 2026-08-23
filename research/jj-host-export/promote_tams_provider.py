#!/usr/bin/env python3
"""Promote the validated PARSEC-TAMS host selection to the canonical JJ export files.

The workflow initially creates the legacy logg-selected files because those scripts
also generate the JJ stellar assemblies. After tams_ab_test.py creates the symmetric
pre-logg parent sample and B_TAMS_MS flag, this script:
  1. preserves the old main files with an explicit _legacy_logg43 suffix;
  2. rewrites the canonical jj_g_hosts_*_padova files from B_TAMS_MS rows;
  3. rewrites the canonical summary and checksum manifest.
"""
from pathlib import Path
import argparse, csv, hashlib, json, math, shutil, sys
import numpy as np

TMIN,TMAX=5300.0,6000.0
AGE_MIN=4.57
T_EDGES=np.arange(5300.0,6000.0+100.0,100.0)
AGE_EDGES=np.arange(4.50,13.25+0.25,0.25)
CANONICAL=[
    'jj_g_hosts_radial_padova.csv',
    'jj_g_hosts_R_T_padova.csv',
    'jj_g_hosts_R_T_age_padova.csv',
    'jj_g_hosts_raw_eligible_padova.csv',
    'jj_g_hosts_summary_padova.json',
    'SHA256SUMS_padova.txt',
]

def legacy_name(name):
    p=Path(name)
    return f'{p.stem}_legacy_logg43{p.suffix}'

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def trap(radial, field, lo, hi):
    q=[r for r in radial if lo <= r['R_kpc'] <= hi]
    R=np.array([r['R_kpc'] for r in q],float); y=np.array([r[field] for r in q],float)
    return float(np.trapz(y,R))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True)
    args=ap.parse_args(); out=Path(args.out)
    parent=out/'jj_g_hosts_parent_prelogg_padova.csv'
    if not parent.exists(): raise FileNotFoundError(parent)

    for name in CANONICAL:
        src=out/name
        if src.exists(): shutil.copy2(src,out/legacy_name(name))

    rows=[]
    with parent.open(newline='',encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if int(r['B_TAMS_MS']) != 1: continue
            rows.append({
                'R_kpc':float(r['R_kpc']), 'component':r['component'],
                'Teff_K':float(r['Teff_K']), 'age_Gyr':float(r['age_Gyr']),
                'logg':float(r['logg']), 'N_surface_pc-2':float(r['N_surface_pc-2'])
            })
    if not rows: raise RuntimeError('No PARSEC-TAMS rows selected')

    raw=out/'jj_g_hosts_raw_eligible_padova.csv'
    with raw.open('w',newline='',encoding='utf-8') as f:
        cols=['R_kpc','component','Teff_K','age_Gyr','logg','N_surface_pc-2']
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(rows)

    radii=sorted({r['R_kpc'] for r in rows})
    radial=[]; temp=[]; age=[]
    for R in radii:
        rr=[r for r in rows if r['R_kpc']==R]
        sig={c:sum(r['N_surface_pc-2'] for r in rr if r['component']==c) for c in ['thin','thick']}
        total=sig['thin']+sig['thick']
        radial.append({'R_kpc':R,'Sigma_G_thin_pc-2':sig['thin'],'Sigma_G_thick_pc-2':sig['thick'],
                       'Sigma_G_total_pc-2':total,'dN_dR_stars_kpc-1':2*math.pi*R*1e6*total})
        for comp in ['thin','thick']:
            cr=[r for r in rr if r['component']==comp]
            for i in range(len(T_EDGES)-1):
                lo,hi=T_EDGES[i],T_EDGES[i+1]
                s=sum(r['N_surface_pc-2'] for r in cr if (r['Teff_K']>=lo and (r['Teff_K']<=hi if i==len(T_EDGES)-2 else r['Teff_K']<hi)))
                temp.append({'R_kpc':R,'component':comp,'T_lo_K':lo,'T_hi_K':hi,'Sigma_G_pc-2':s})
        for i in range(len(T_EDGES)-1):
            tlo,thi=T_EDGES[i],T_EDGES[i+1]
            for j in range(len(AGE_EDGES)-1):
                alo,ahi=AGE_EDGES[j],AGE_EDGES[j+1]
                s=sum(r['N_surface_pc-2'] for r in rr if
                      r['Teff_K']>=tlo and (r['Teff_K']<=thi if i==len(T_EDGES)-2 else r['Teff_K']<thi)
                      and r['age_Gyr']>=max(alo,AGE_MIN) and r['age_Gyr']<ahi)
                if s>0: age.append({'R_kpc':R,'T_lo_K':tlo,'T_hi_K':thi,'age_lo_Gyr':alo,'age_hi_Gyr':ahi,'Sigma_G_pc-2':s})

    specs=[
      ('jj_g_hosts_radial_padova.csv',radial,['R_kpc','Sigma_G_thin_pc-2','Sigma_G_thick_pc-2','Sigma_G_total_pc-2','dN_dR_stars_kpc-1']),
      ('jj_g_hosts_R_T_padova.csv',temp,['R_kpc','component','T_lo_K','T_hi_K','Sigma_G_pc-2']),
      ('jj_g_hosts_R_T_age_padova.csv',age,['R_kpc','T_lo_K','T_hi_K','age_lo_Gyr','age_hi_Gyr','Sigma_G_pc-2']),
    ]
    for name,data,cols in specs:
        with (out/name).open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(data)

    N_full=trap(radial,'dN_dR_stars_kpc-1',4,14)
    N_79=trap(radial,'dN_dR_stars_kpc-1',7,9)
    comp_rad=[]
    for R in radii:
        rr=[r for r in rows if r['R_kpc']==R]
        d={'R_kpc':R}
        for comp in ['thin','thick']:
            sigma=sum(r['N_surface_pc-2'] for r in rr if r['component']==comp)
            d[comp]=2*math.pi*R*1e6*sigma
        comp_rad.append(d)
    N_thick79=trap(comp_rad,'thick',7,9)
    thick_frac=N_thick79/N_79

    summary={
      'jj_repository':'askenja/jjmodel',
      'jj_commit':'2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54',
      'jj_version_expected':'1.0.1',
      'jj_parameter_source':'jjmodel/tutorials/tutorial2/parameters at pinned commit',
      'jj_sfr_peaks_source':'jjmodel/tutorials/tutorial2/sfrd_peaks_parameters at pinned commit',
      'isochrone_family':'Padova/PARSEC',
      'host_provider_id':'jj_padova_dr05_parsec_tams_v1',
      'host_estimand':{
        'Teff_K':[TMIN,TMAX], 'age_Gyr_min':AGE_MIN,
        'main_sequence_selector':'Rstar <= public Berger/Huber PARSEC TAMS boundary at Teff, plus logg < 7 compact-remnant veto',
        'tams_boundary_dimensions':['Teff_K'],
        'explicit_metallicity_dimension':False,
        'components':['thin_disk','thick_disk'], 'R_kpc_integrated':[4.0,14.0]
      },
      'integration':'N = integral_4^14 [2*pi*R*1e6*Sigma_G(R)] dR; trapezoidal on JJ 0.5-kpc grid',
      'N_G_hosts_age_ge_4p57_R4_14':N_full,
      'N_G_hosts_age_ge_4p57_R7_9':N_79,
      'thick_disk_fraction_R7_9':thick_frac,
      'tams_transfer_assumption':(
        'The one-dimensional TAMS boundary has no explicit metallicity coordinate. '
        'Its application to both disk components is retained as an unquantified host-selection systematic; '
        'neither the sign nor the magnitude of the metallicity dependence is assumed here.'
      ),
      'legacy_provider_files_suffix':'_legacy_logg43',
      'no_GHZ_SN_mask':True,
      'no_planet_occurrence_metallicity_correction':True,
      'python':sys.version,
    }
    (out/'jj_g_hosts_summary_padova.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')

    mainfiles=[out/n for n in CANONICAL if n!='SHA256SUMS_padova.txt']
    (out/'SHA256SUMS_padova.txt').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in mainfiles),encoding='utf-8')

    assert abs(N_full-1238302534.419577) < 1e-2, N_full
    assert abs(N_79-263061992.36670703) < 1e-2, N_79
    assert abs(thick_frac-0.19893903660103215) < 1e-12, thick_frac
    print(json.dumps({'canonical_provider':'PARSEC-TAMS','rows':len(rows),'N_G_R4_14':N_full,'N_G_R7_9':N_79,'thick_disk_fraction_R7_9':thick_frac},indent=2))

if __name__=='__main__': main()
