#!/usr/bin/env python3
"""Export row-level eligible JJ stellar assemblies for exact T-weighted occurrence integration."""
import argparse, csv, os, sys
from pathlib import Path
import numpy as np
from astropy.table import Table

TMIN,TMAX=5300.0,6000.0
LOGG_MIN,LOGG_MAX=4.3,7.0
AGE_MIN=4.57

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--jj-root',required=True)
    ap.add_argument('--run-dir',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--iso',default='Padova')
    args=ap.parse_args()
    sys.path.insert(0,str(Path(args.jj_root).resolve()))
    os.chdir(Path(args.run_dir).resolve())
    from jjmodel.input_ import p,a
    poptab=Path(a.T['poptab'])
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    path=out/f'jj_g_hosts_raw_eligible_{args.iso.lower()}.csv'
    nrows=0
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f)
        w.writerow(['R_kpc','component','Teff_K','age_Gyr','logg','N_surface_pc-2'])
        for R in np.asarray(a.R,dtype=float):
            for comp,label in [('d','thin'),('t','thick')]:
                src=poptab/f'SSP_R{R}_{comp}_{args.iso}.csv'
                tab=Table.read(src,format='ascii.csv')
                teff=10.0**np.asarray(tab['logT'],dtype=float)
                age=np.asarray(tab['age'],dtype=float)
                logg=np.asarray(tab['logg'],dtype=float)
                n=np.asarray(tab['N'],dtype=float)
                keep=((teff>=TMIN)&(teff<=TMAX)&(logg>LOGG_MIN)&(logg<LOGG_MAX)&(age>=AGE_MIN)&np.isfinite(n)&(n>=0))
                for vals in zip(teff[keep],age[keep],logg[keep],n[keep]):
                    w.writerow([float(R),label,*map(float,vals)])
                    nrows+=1
    print(f'Wrote {nrows} eligible stellar-assembly rows to {path}')

if __name__=='__main__':
    main()
