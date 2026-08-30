#!/usr/bin/env python3
"""A/B validation of the frozen G-dwarf host selection.

A = legacy operational dwarf cut: 4.3 < logg < 7.0
B = radius below the public PARSEC TAMS boundary used by Berger/Huber evolstate,
    plus logg < 7 solely as a compact-remnant veto. The TAMS boundary is an
    upper-radius boundary and by itself cannot reject white-dwarf-like remnants.

The parent population is selected ONLY by Teff, age, Galactic component and
finite non-negative JJ surface-number weight. No lower-logg cut is applied before A/B.
The script also evaluates the frozen Bryson Model-1 + Kopparapu CHZ L1/L2
integrals on each selection and integrates them radially.

FeH from the JJ stellar-assembly table is preserved in the parent export so that
metallicity-dependent host-selection sensitivity can be evaluated on exactly the
same weighted population. In jjmodel this FeH field is assigned from the thin/thick
disk AMR value used to construct each stellar assembly.
"""
import argparse
import csv
import json
import math
import os
import sys
from pathlib import Path

import numpy as np
from astropy.table import Table
from occurrence_reference import f_earth10, f_hz
from tams_reference import EXPECTED_SHA256 as TAMS_REFERENCE_SHA256
from tams_reference import tams_radius_rsun

TMIN,TMAX=5300.0,6000.0
AGE_MIN=4.57
LOGG_MIN,LOGG_MAX=4.3,7.0
LOGG_SUN=4.438
TSUN_RADIUS=5772.0

def require(condition,message):
    if not condition:raise RuntimeError(message)

def integrate(radial, col, lo, hi):
    q=[r for r in radial if lo <= r['R_kpc'] <= hi]
    R=np.array([r['R_kpc'] for r in q]); y=np.array([r[col] for r in q])
    return float(np.trapz(y,R))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--jj-root',required=True); ap.add_argument('--run-dir',required=True)
    ap.add_argument('--out',required=True); ap.add_argument('--iso',default='Padova')
    a=ap.parse_args(); sys.path.insert(0,str(Path(a.jj_root).resolve())); os.chdir(Path(a.run_dir).resolve())
    from jjmodel.input_ import a as jj
    from jjmodel.input_ import p
    if abs(float(p.dR)-0.5)>1e-12: raise RuntimeError(f'TAMS A/B requires dR=0.5, got {p.dR}')
    poptab=Path(jj.T['poptab']); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    parent_path=out/'jj_g_hosts_parent_prelogg_padova.csv'
    header=['R_kpc','component','age_Gyr','FeH','Mini','Mf','logL','logT','Teff_K','logg','N_surface_pc-2','Rstar_g_Rsun','Rstar_L_Rsun','R_TAMS_Rsun','A_logg','B_TAMS_MS','f_HZ','f_earth10']
    rows_by_R={}; rel_radius=[]; n_parent=0; compact_rejected_rows=0
    with parent_path.open('w',newline='',encoding='utf-8') as fh:
        w=csv.writer(fh); w.writerow(header)
        for R in np.asarray(jj.R,dtype=float):
            acc={'A_N':0.,'B_N':0.,'A_L1':0.,'B_L1':0.,'A_L2':0.,'B_L2':0.}
            for comp,label in [('d','thin'),('t','thick')]:
                tab=Table.read(poptab/f'SSP_R{R}_{comp}_{a.iso}.csv',format='ascii.csv')
                required=['age','FeH','Mini','Mf','logL','logT','logg','N']
                miss=[c for c in required if c not in tab.colnames]
                if miss: raise RuntimeError(f'{R} {label}: missing {miss}; columns={tab.colnames}')
                age=np.asarray(tab['age'],float); feh=np.asarray(tab['FeH'],float)
                mini=np.asarray(tab['Mini'],float); mf=np.asarray(tab['Mf'],float)
                logL=np.asarray(tab['logL'],float); logT=np.asarray(tab['logT'],float); logg=np.asarray(tab['logg'],float); n=np.asarray(tab['N'],float)
                teff=10**logT
                keep=(teff>=TMIN)&(teff<=TMAX)&(age>=AGE_MIN)&np.isfinite(feh)&np.isfinite(n)&(n>=0)&np.isfinite(mf)&(mf>0)&np.isfinite(logL)&np.isfinite(logg)
                for vals in zip(age[keep],feh[keep],mini[keep],mf[keep],logL[keep],logT[keep],teff[keep],logg[keep],n[keep]):
                    ag,zfe,mi,m,lL,lT,T,lg,wt=map(float,vals)
                    rg=math.sqrt(m*10**(LOGG_SUN-lg)); rl=10**(lL/2)*(TSUN_RADIUS/T)**2
                    rt=float(tams_radius_rsun(T))
                    below_tams=(rg<=rt)
                    A=(lg>LOGG_MIN and lg<LOGG_MAX)
                    B=(below_tams and lg<LOGG_MAX)
                    if below_tams and lg>=LOGG_MAX: compact_rejected_rows+=1
                    fhz=float(f_hz(T)); fe=float(f_earth10(T)); n_parent+=1
                    if rg>0 and rl>0: rel_radius.append(abs(rg-rl)/((rg+rl)/2))
                    if A: acc['A_N']+=wt; acc['A_L1']+=wt*fhz; acc['A_L2']+=wt*fe
                    if B: acc['B_N']+=wt; acc['B_L1']+=wt*fhz; acc['B_L2']+=wt*fe
                    w.writerow([R,label,ag,zfe,mi,m,lL,lT,T,lg,wt,rg,rl,rt,int(A),int(B),fhz,fe])
            fac=2*math.pi*R*1e6
            rows_by_R[float(R)]={'R_kpc':float(R), **{k:fac*v for k,v in acc.items()}}
    radial=[rows_by_R[k] for k in sorted(rows_by_R)]
    rpath=out/'tams_ab_radial.csv'
    with rpath.open('w',newline='',encoding='utf-8') as f:
        cols=['R_kpc','A_N','B_N','A_L1','B_L1','A_L2','B_L2']; w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(radial)
    result={'parent_rows':n_parent,'dR_kpc':0.5,'logg_sun':LOGG_SUN,'Tsun_radius_K':TSUN_RADIUS,
            'TAMS_reference_sha256':TAMS_REFERENCE_SHA256,
            'TAMS_interpolation':'linear in Teff and log10(R/Rsun); no extrapolation',
            'parent_export_includes_FeH':True,
            'B_definition':'Rstar <= PARSEC TAMS radius AND logg < 7 compact-remnant veto',
            'compact_remnant_rows_rejected':compact_rejected_rows,
            'radius_reconstruction_rel_diff_median':float(np.median(rel_radius)),
            'radius_reconstruction_rel_diff_q95':float(np.quantile(rel_radius,.95)),
            'domains':{}}
    for name,lo,hi in [('lineweaver_7_9',7.,9.),('full_JJ_4_14',4.,14.)]:
        d={}
        for sel in ['A','B']:
            d[sel]={'N_G':integrate(radial,f'{sel}_N',lo,hi),'Lambda_ESHZ':integrate(radial,f'{sel}_L1',lo,hi),'Lambda_earth10':integrate(radial,f'{sel}_L2',lo,hi)}
        d['delta_B_vs_A']={k:(d['B'][k]-d['A'][k])/d['A'][k] for k in d['A']}
        result['domains'][name]=d
    for d in result['domains'].values():
        for sel in ['A','B']:
            require(
                d[sel]['Lambda_earth10'] <= d[sel]['Lambda_ESHZ'] + 1e-9,
                f"Population ordering failed for {sel}: {d[sel]}",
            )
    (out/'tams_ab_results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
