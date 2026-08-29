#!/usr/bin/env python3
"""Sensitivity of the frozen L1/L2 estimator to the conservative-HZ inner edge.

Input must be the canonical dR=0.5 PARSEC-TAMS row-level host export.
Two distinct tests are reported:

1. Numerical boundary perturbation: multiply the 1-Mearth Kopparapu runaway-
   greenhouse flux boundary by 0.95, 0.99, 1.00, 1.01, 1.05. These are pure
   sensitivity perturbations, not alternative climate models.

2. Published planetary-mass prescriptions: use the 0.1, 1 and 5 Mearth
   runaway-greenhouse coefficients from Kopparapu et al. (2014), ApJL 787 L29,
   Eq. (4), Table 1, DOI 10.1088/2041-8205/787/2/L29. The maximum-greenhouse
   outer boundary is unchanged across these mass cases, as stated in Table 1.
"""
import argparse
import csv
import json
import math
from pathlib import Path

import numpy as np

# Frozen Bryson Model 1 / hab2 / constant-completeness branch.
F0=1.107
ALPHA=-1.082
BETA=-0.839
GAMMA=-2.671
T0,TBREAK,T1=3900.,5117.,6300.

# Kopparapu et al. 2014 Eq. 4 / Table 1.
MAX_GREENHOUSE=(0.356,6.171e-5,1.698e-9,-3.198e-12,-5.575e-16)
RUNAWAY_BY_MASS={
    0.1:(0.99,1.209e-4,1.404e-8,-7.418e-12,-1.713e-15),
    1.0:(1.107,1.332e-4,1.580e-8,-8.308e-12,-1.931e-15),
    5.0:(1.188,1.433e-4,1.707e-8,-8.968e-12,-2.084e-15),
}
PERTURBATIONS=(0.95,0.99,1.0,1.01,1.05)


def require(condition,message):
    if not condition:raise RuntimeError(message)


def P(lo,hi,p):
    return (hi**(p+1)-lo**(p+1))/(p+1)

ARFIT=P(.5,2.5,ALPHA)
AIFIT=P(.2,2.2,BETA)
q1=GAMMA+3.16
q2=GAMMA+4.49
GBAR=(10**(-11.839)*P(T0,TBREAK,q1)+10**(-16.769)*P(TBREAK,T1,q2))/(T1-T0)
C1=1/(ARFIT*AIFIT*GBAR)
AR_HZ=P(.5,1.5,ALPHA)
AR10=P(.9,1.1,ALPHA)


def hz_flux(T,c):
    T=np.asarray(T,float); x=T-5780.
    s,a,b,cc,d=c
    return s+a*x+b*x**2+cc*x**3+d*x**4


def pref(T):
    T=np.asarray(T,float)
    g=np.where(T<=TBREAK,10**(-11.839)*T**3.16,10**(-16.769)*T**4.49)
    return F0*C1*T**GAMMA*g


def occurrence(T, runaway_coeff, inner_scale=1.0):
    T=np.asarray(T,float)
    outer=hz_flux(T,MAX_GREENHOUSE)
    inner=hz_flux(T,runaway_coeff)*inner_scale
    ai=(inner**(BETA+1)-outer**(BETA+1))/(BETA+1)
    f1=pref(T)*AR_HZ*ai
    lo=np.maximum(.9,outer)
    hi=np.minimum(1.1,inner)
    ai10=np.where(hi>lo,(hi**(BETA+1)-lo**(BETA+1))/(BETA+1),0.)
    f2=pref(T)*AR10*ai10
    return f1,f2


def load_rows(path):
    rows=[]
    with open(path,newline='',encoding='utf-8') as f:
        for r in csv.DictReader(f):
            rows.append((float(r['R_kpc']),float(r['Teff_K']),float(r['N_surface_pc-2'])))
    return rows


def integrate(rows, runaway_coeff, inner_scale=1.0, loR=7.0, hiR=9.0):
    byR={}
    for R,T,w in rows:
        if R < loR-1e-12 or R > hiR+1e-12:
            continue
        f1,f2=occurrence(np.array([T]),runaway_coeff,inner_scale)
        a=byR.setdefault(R,[0.,0.,0.])
        a[0]+=w
        a[1]+=w*float(f1[0])
        a[2]+=w*float(f2[0])
    radial=[]
    for R in sorted(byR):
        fac=2*math.pi*R*1e6
        radial.append((R,fac*byR[R][0],fac*byR[R][1],fac*byR[R][2]))
    arr=np.array(radial,float)
    if abs(arr[0,0]-loR)>1e-9 or abs(arr[-1,0]-hiR)>1e-9:
        raise RuntimeError(f'Missing radial endpoints: {arr[:,0]}')
    vals=[float(np.trapz(arr[:,i],arr[:,0])) for i in (1,2,3)]
    require(vals[0]>0 and vals[1]>=0 and vals[2]>=0 and vals[2]<=vals[1], f'Invalid population ordering: {vals}')
    return vals


def crossing_status(coeff):
    T=np.linspace(5300.,6000.,200001)
    y=hz_flux(T,coeff)-1.1
    if np.all(y<0):
        return {'status':'below_1p10_entire_interval','T_cross_K':None}
    if np.all(y>0):
        return {'status':'above_1p10_entire_interval','T_cross_K':None}
    idx=np.where(np.signbit(y[:-1]) != np.signbit(y[1:]))[0]
    if len(idx)!=1:
        return {'status':'multiple_or_tangent_crossings','T_cross_K':None}
    i=int(idx[0]); x0,x1=T[i],T[i+1]; y0,y1=y[i],y[i+1]
    root=x0-y0*(x1-x0)/(y1-y0)
    return {'status':'single_crossing','T_cross_K':float(root)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--input',required=True)
    ap.add_argument('--out',required=True)
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    rows=load_rows(a.input)

    baseN,baseL1,baseL2=integrate(rows,RUNAWAY_BY_MASS[1.0])
    require(abs(baseN-263061992.36674243)<1e-2, f'N_G anchor mismatch: {baseN}')
    require(abs(baseL1-105716685.0799756)<1e-2, f'Lambda_ESHZ anchor mismatch: {baseL1}')
    require(abs(baseL2-3376462.6740267016)<1e-2, f'Lambda_earth10 anchor mismatch: {baseL2}')

    perturb=[]
    for scale in PERTURBATIONS:
        N,L1,L2=integrate(rows,RUNAWAY_BY_MASS[1.0],scale)
        perturb.append({
            'inner_flux_scale':scale,
            'N_G':N,'Lambda_ESHZ':L1,'Lambda_earth10':L2,
            'delta_L1_percent':100*(L1/baseL1-1),
            'delta_L2_percent':100*(L2/baseL2-1),
        })

    # Infinitesimal centered log-derivative around the canonical boundary.
    eps=1e-4
    _,l1p,l2p=integrate(rows,RUNAWAY_BY_MASS[1.0],1+eps)
    _,l1m,l2m=integrate(rows,RUNAWAY_BY_MASS[1.0],1-eps)
    den=np.log(1+eps)-np.log(1-eps)
    dlnL1=float((np.log(l1p)-np.log(l1m))/den)
    dlnL2=float((np.log(l2p)-np.log(l2m))/den)

    mass=[]
    for M in (0.1,1.0,5.0):
        N,L1,L2=integrate(rows,RUNAWAY_BY_MASS[M])
        mass.append({
            'planet_mass_Mearth':M,
            'runaway_coefficients':RUNAWAY_BY_MASS[M],
            'N_G':N,'Lambda_ESHZ':L1,'Lambda_earth10':L2,
            'delta_L1_percent_vs_1Mearth':100*(L1/baseL1-1),
            'delta_L2_percent_vs_1Mearth':100*(L2/baseL2-1),
            'L2_over_L1':L2/L1,
            'B10_inner_edge_crossing':crossing_status(RUNAWAY_BY_MASS[M]),
        })

    result={
        'experiment':'HZ_inner_boundary_and_planet_mass_sensitivity',
        'host_provider':'jj_padova_dr05_parsec_tams_v1',
        'canonical_domain':'7-9 kpc',
        'canonical_occurrence':'Bryson Model 1 hab2 constant-completeness',
        'canonical_HZ':'Kopparapu 2014 1-Mearth runaway greenhouse + maximum greenhouse',
        'B10':'0.9-1.1 Rearth x 0.9-1.1 Searth intersect HZ',
        'C1':C1,
        'baseline':{'N_G':baseN,'Lambda_ESHZ':baseL1,'Lambda_earth10':baseL2},
        'local_log_sensitivity':{
            'dln_L1_dln_Sinner':dlnL1,
            'dln_L2_dln_Sinner':dlnL2,
            'epsilon':eps,
        },
        'inner_boundary_perturbations':perturb,
        'planet_mass_prescriptions':mass,
        'source':{
            'citation':'Kopparapu et al. 2014, ApJL 787 L29',
            'doi':'10.1088/2041-8205/787/2/L29',
            'location':'Eq. 4 and Table 1',
        },
    }

    with (out/'hz_inner_boundary_perturbations.csv').open('w',newline='',encoding='utf-8') as f:
        cols=list(perturb[0].keys()); w=csv.DictWriter(f,fieldnames=cols); w.writeheader(); w.writerows(perturb)
    with (out/'hz_planet_mass_sensitivity.csv').open('w',newline='',encoding='utf-8') as f:
        cols=['planet_mass_Mearth','N_G','Lambda_ESHZ','Lambda_earth10','delta_L1_percent_vs_1Mearth','delta_L2_percent_vs_1Mearth','L2_over_L1','crossing_status','T_cross_K']
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for r in mass:
            c=r['B10_inner_edge_crossing']
            w.writerow({
                'planet_mass_Mearth':r['planet_mass_Mearth'],'N_G':r['N_G'],'Lambda_ESHZ':r['Lambda_ESHZ'],'Lambda_earth10':r['Lambda_earth10'],
                'delta_L1_percent_vs_1Mearth':r['delta_L1_percent_vs_1Mearth'],'delta_L2_percent_vs_1Mearth':r['delta_L2_percent_vs_1Mearth'],
                'L2_over_L1':r['L2_over_L1'],'crossing_status':c['status'],'T_cross_K':c['T_cross_K'],
            })
    (out/'hz_sensitivity_results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
