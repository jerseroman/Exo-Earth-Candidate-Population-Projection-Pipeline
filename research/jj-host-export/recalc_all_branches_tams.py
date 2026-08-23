#!/usr/bin/env python3
"""Recompute frozen L1/L2 branch and GHZ sensitivity tables on PARSEC-TAMS hosts.

Input is tams_ab_test.py's parent export. Only rows with B_TAMS_MS=1 are used.
The frozen L0-L1-L2 equations are unchanged; this script changes no host physics.
"""
from pathlib import Path
import argparse, csv, json, math
import numpy as np

PARAMS={
  'constant': dict(F0=1.107, alpha=-1.082, beta=-0.839, gamma=-2.671),
  'zero': dict(F0=1.590, alpha=-1.175, beta=-1.195, gamma=-1.376),
}
HZ_COEF={
  'recent_venus': (1.776, 2.136e-4, 2.533e-8, -1.332e-11, -3.097e-15),
  'runaway_greenhouse': (1.107, 1.332e-4, 1.580e-8, -8.308e-12, -1.931e-15),
  'maximum_greenhouse': (0.356, 6.171e-5, 1.698e-9, -3.198e-12, -5.575e-16),
  'early_mars': (0.320, 5.547e-5, 1.526e-9, -2.874e-12, -5.011e-16),
}
MASKS=[
  ('lineweaver_7_9','Lineweaver 7-9 kpc',7.0,9.0),
  ('broad_solar_annulus_6_10','Broad solar annulus 6-10 kpc',6.0,10.0),
  ('inner_disk_4_8','Inner-disk sensitivity 4-8 kpc',4.0,8.0),
  ('full_JJ_4_14','Full JJ disk 4-14 kpc',4.0,14.0),
]
BRANCHES=[('CHZ','constant'),('CHZ','zero'),('OHZ','constant'),('OHZ','zero')]

def P(lo,hi,p): return (hi**(p+1)-lo**(p+1))/(p+1)

def hz_flux(T,c):
    x=np.asarray(T,float)-5780.0
    s,a,b,cc,d=c
    return s+a*x+b*x*x+cc*x**3+d*x**4

def C1(par):
    a,b,g=par['alpha'],par['beta'],par['gamma']
    ar=P(.5,2.5,a); ai=P(.2,2.2,b)
    q1=g+3.16; q2=g+4.49
    gb=(10**(-11.839)*P(3900.,5117.,q1)+10**(-16.769)*P(5117.,6300.,q2))/2400.0
    return 1.0/(ar*ai*gb)

for p in PARAMS.values(): p['C1']=C1(p)

def occurrence(T,hzdef,branch):
    p=PARAMS[branch]; T=np.asarray(T,float)
    g=np.where(T<=5117.,10**(-11.839)*T**3.16,10**(-16.769)*T**4.49)
    pre=p['F0']*p['C1']*T**p['gamma']*g
    if hzdef=='CHZ':
        inner=hz_flux(T,HZ_COEF['runaway_greenhouse']); outer=hz_flux(T,HZ_COEF['maximum_greenhouse'])
    else:
        inner=hz_flux(T,HZ_COEF['recent_venus']); outer=hz_flux(T,HZ_COEF['early_mars'])
    ai=(inner**(p['beta']+1)-outer**(p['beta']+1))/(p['beta']+1)
    fhz=pre*P(.5,1.5,p['alpha'])*ai
    lo=np.maximum(.9,outer); hi=np.minimum(1.1,inner)
    ai10=np.where(hi>lo,(hi**(p['beta']+1)-lo**(p['beta']+1))/(p['beta']+1),0.)
    f10=pre*P(.9,1.1,p['alpha'])*ai10
    return fhz,f10

def integrate(rad, field, lo, hi):
    q=[x for x in rad if lo <= x['R_kpc'] <= hi]
    R=np.array([x['R_kpc'] for x in q],float); y=np.array([x[field] for x in q],float)
    return float(np.trapz(y,R))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',required=True); ap.add_argument('--out',required=True)
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    acc={}
    with open(a.input,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if int(row['B_TAMS_MS']) != 1: continue
            R=float(row['R_kpc']); T=float(row['Teff_K']); w=float(row['N_surface_pc-2'])
            if R not in acc:
                acc[R]={'N':0.0}
                for hz,b in BRANCHES: acc[R][f'{hz}_{b}_L1']=0.; acc[R][f'{hz}_{b}_L2']=0.
            acc[R]['N'] += w
            for hz,b in BRANCHES:
                f1,f2=occurrence(T,hz,b)
                acc[R][f'{hz}_{b}_L1'] += w*float(f1)
                acc[R][f'{hz}_{b}_L2'] += w*float(f2)
    radial=[]
    for R in sorted(acc):
        fac=2*math.pi*R*1e6; d={'R_kpc':R,'dN':fac*acc[R]['N']}
        for hz,b in BRANCHES:
            d[f'{hz}_{b}_L1']=fac*acc[R][f'{hz}_{b}_L1']
            d[f'{hz}_{b}_L2']=fac*acc[R][f'{hz}_{b}_L2']
        radial.append(d)
    Tg=np.linspace(5300.,6000.,200001); unif={}
    for hz,b in BRANCHES:
        f1,f2=occurrence(Tg,hz,b)
        unif[f'{hz}_{b}']={'f_HZ':float(np.trapz(f1,Tg)/700.),'f_earth10':float(np.trapz(f2,Tg)/700.)}
    results={'host_provider':'JJ Padova/PARSEC, dR=0.5 kpc, PARSEC-TAMS + logg<7 remnant veto',
             'measure':'linear dI dr','uniform_reference_Teff_K':[5300,6000], 'uniform':unif,'masks':{}}
    for mid,label,lo,hi in MASKS:
        N=integrate(radial,'dN',lo,hi); m={'label':label,'R_kpc':[lo,hi],'N_G':N,'branches':{}}
        for hz,b in BRANCHES:
            L1=integrate(radial,f'{hz}_{b}_L1',lo,hi); L2=integrate(radial,f'{hz}_{b}_L2',lo,hi)
            assert L2 <= L1 + 1e-8
            u=unif[f'{hz}_{b}']; key=f'{hz}_{b}'
            m['branches'][key]={'mean_f_HZ':L1/N,'mean_f_earth10':L2/N,
                'RT_L1':(L1/N)/u['f_HZ'],'RT_L2':(L2/N)/u['f_earth10'],
                'Lambda_ESHZ':L1,'Lambda_earth10':L2,'L2_over_L1':L2/L1}
        results['masks'][mid]=m
    c=results['masks']['lineweaver_7_9']['branches']['CHZ_constant']
    assert abs(results['masks']['lineweaver_7_9']['N_G']-263061992.36674243) < 1e-2
    assert abs(c['Lambda_ESHZ']-105716685.0799756) < 1e-2
    assert abs(c['Lambda_earth10']-3376462.6740267016) < 1e-2
    p=out/'tams_branches_lineweaver_7_9.csv'
    cols=['branch','N_G','mean_f_HZ','mean_f_earth10','RT_L1','RT_L2','Lambda_ESHZ','Lambda_earth10','L2_over_L1_pct']
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for hz,b in BRANCHES:
            d=results['masks']['lineweaver_7_9']['branches'][f'{hz}_{b}']
            w.writerow({'branch':f'{hz}_{b}','N_G':results['masks']['lineweaver_7_9']['N_G'],
                'mean_f_HZ':d['mean_f_HZ'],'mean_f_earth10':d['mean_f_earth10'],'RT_L1':d['RT_L1'],'RT_L2':d['RT_L2'],
                'Lambda_ESHZ':d['Lambda_ESHZ'],'Lambda_earth10':d['Lambda_earth10'],'L2_over_L1_pct':100*d['L2_over_L1']})
    p=out/'tams_ghz_sensitivity_chz_constant.csv'; full=results['masks']['full_JJ_4_14']; fullc=full['branches']['CHZ_constant']
    cols=['mask_id','label','R_inner_kpc','R_outer_kpc','N_G','Lambda_ESHZ','Lambda_earth10','fraction_full_disk_hosts','fraction_full_disk_L2']
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for mid,label,lo,hi in MASKS:
            m=results['masks'][mid]; d=m['branches']['CHZ_constant']
            w.writerow({'mask_id':mid,'label':label,'R_inner_kpc':lo,'R_outer_kpc':hi,'N_G':m['N_G'],
              'Lambda_ESHZ':d['Lambda_ESHZ'],'Lambda_earth10':d['Lambda_earth10'],
              'fraction_full_disk_hosts':m['N_G']/full['N_G'],'fraction_full_disk_L2':d['Lambda_earth10']/fullc['Lambda_earth10']})
    p=out/'tams_branch_mask_matrix.csv'; cols=['mask_id','N_G']+[f'{hz}_{b}_{q}' for hz,b in BRANCHES for q in ['L1','L2']]
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for mid,_,_,_ in MASKS:
            m=results['masks'][mid]; row={'mask_id':mid,'N_G':m['N_G']}
            for hz,b in BRANCHES:
                d=m['branches'][f'{hz}_{b}']; row[f'{hz}_{b}_L1']=d['Lambda_ESHZ']; row[f'{hz}_{b}_L2']=d['Lambda_earth10']
            w.writerow(row)
    (out/'tams_all_branch_results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    print(json.dumps(results['masks']['lineweaver_7_9'],indent=2))

if __name__=='__main__': main()
