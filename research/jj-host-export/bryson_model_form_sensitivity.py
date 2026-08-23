#!/usr/bin/env python3
"""Compare Bryson Model 1 and Model 2 on the canonical PARSEC-TAMS hosts.

The comparison holds fixed the stellar provider, completeness branch (constant /
low bound), Kopparapu conservative HZ and B10 selection. Only the functional form
of the Bryson differential occurrence model changes.

Model definitions and medians are from Bryson et al. (2021), AJ 161:36,
Eq. (5) and Table 1, Poisson likelihood, hab2 stellar population, With
Uncertainty, Low Bound (constant-completeness):
  Model 1: F0=1.107, alpha=-1.082, beta=-0.839, gamma=-2.671, includes g(T)
  Model 2: F0=1.13,  alpha=-1.13,  beta=-0.85,  gamma=+1.19,  no g(T)
Model 2 therefore measures total Teff dependence directly rather than separating
out the geometric g(T) factor.
"""
from pathlib import Path
import argparse, csv, json, math
import numpy as np

T0,TBREAK,T1=3900.,5117.,6300.
RUNAWAY=(1.107,1.332e-4,1.580e-8,-8.308e-12,-1.931e-15)
MAXG=(0.356,6.171e-5,1.698e-9,-3.198e-12,-5.575e-16)
MODELS={
    'model1':{'F0':1.107,'alpha':-1.082,'beta':-0.839,'gamma':-2.671,'use_g':True},
    'model2':{'F0':1.13,'alpha':-1.13,'beta':-0.85,'gamma':1.19,'use_g':False},
}


def P(lo,hi,p):
    return (hi**(p+1)-lo**(p+1))/(p+1)


def hz_flux(T,c):
    T=np.asarray(T,float); x=T-5780.
    s,a,b,cc,d=c
    return s+a*x+b*x**2+cc*x**3+d*x**4


def normalization(m):
    ar=P(.5,2.5,m['alpha']); ai=P(.2,2.2,m['beta'])
    if m['use_g']:
        q1=m['gamma']+3.16; q2=m['gamma']+4.49
        tavg=(10**(-11.839)*P(T0,TBREAK,q1)+10**(-16.769)*P(TBREAK,T1,q2))/(T1-T0)
    else:
        tavg=P(T0,T1,m['gamma'])/(T1-T0)
    return 1/(ar*ai*tavg)

for m in MODELS.values():
    m['C']=normalization(m)


def occurrence(T,m):
    T=np.asarray(T,float)
    if m['use_g']:
        g=np.where(T<=TBREAK,10**(-11.839)*T**3.16,10**(-16.769)*T**4.49)
    else:
        g=1.0
    pre=m['F0']*m['C']*T**m['gamma']*g
    outer=hz_flux(T,MAXG); inner=hz_flux(T,RUNAWAY)
    ai=(inner**(m['beta']+1)-outer**(m['beta']+1))/(m['beta']+1)
    f1=pre*P(.5,1.5,m['alpha'])*ai
    lo=np.maximum(.9,outer); hi=np.minimum(1.1,inner)
    ai10=np.where(hi>lo,(hi**(m['beta']+1)-lo**(m['beta']+1))/(m['beta']+1),0.)
    f2=pre*P(.9,1.1,m['alpha'])*ai10
    return f1,f2


def load(path):
    rows=[]
    with open(path,newline='',encoding='utf-8') as f:
        for r in csv.DictReader(f):
            rows.append((float(r['R_kpc']),float(r['Teff_K']),float(r['N_surface_pc-2'])))
    return rows


def integrate(rows,m,loR=7.,hiR=9.):
    byR={}
    for R,T,w in rows:
        if not (loR<=R<=hiR): continue
        f1,f2=occurrence(np.array([T]),m)
        a=byR.setdefault(R,[0.,0.,0.]); a[0]+=w; a[1]+=w*float(f1[0]); a[2]+=w*float(f2[0])
    rr=[]
    for R in sorted(byR):
        fac=2*math.pi*R*1e6; rr.append((R,fac*byR[R][0],fac*byR[R][1],fac*byR[R][2]))
    arr=np.array(rr,float)
    vals=[float(np.trapz(arr[:,i],arr[:,0])) for i in (1,2,3)]
    assert vals[0]>0 and vals[1]>=vals[2]>=0
    return vals


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',required=True); ap.add_argument('--out',required=True)
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    rows=load(a.input)
    results={}
    for name,m in MODELS.items():
        N,L1,L2=integrate(rows,m)
        Tg=np.linspace(5300.,6000.,200001); u1,u2=occurrence(Tg,m)
        results[name]={
            'parameters':{k:v for k,v in m.items() if k!='C'},'C':m['C'],
            'N_G':N,'Lambda_ESHZ':L1,'Lambda_earth10':L2,
            'mean_f_HZ':L1/N,'mean_f_earth10':L2/N,
            'uniform_5300_6000_f_HZ':float(np.trapz(u1,Tg)/700.),
            'uniform_5300_6000_f_earth10':float(np.trapz(u2,Tg)/700.),
            'L2_over_L1':L2/L1,
        }
    b=results['model1']
    assert abs(b['N_G']-263061992.36674243)<1e-2
    assert abs(b['Lambda_ESHZ']-105716685.0799756)<1e-2
    assert abs(b['Lambda_earth10']-3376462.6740267016)<1e-2
    m2=results['model2']
    comparison={
        'delta_L1_percent_model2_vs_model1':100*(m2['Lambda_ESHZ']/b['Lambda_ESHZ']-1),
        'delta_L2_percent_model2_vs_model1':100*(m2['Lambda_earth10']/b['Lambda_earth10']-1),
        'ratio_L2_model2_to_model1':m2['Lambda_earth10']/b['Lambda_earth10'],
    }
    final={
        'experiment':'Bryson_model_form_sensitivity',
        'host_provider':'jj_padova_dr05_parsec_tams_v1',
        'domain':'7-9 kpc','HZ':'Kopparapu conservative 1-Mearth','completeness':'constant / low bound',
        'models':results,'comparison':comparison,
        'source':'Bryson et al. 2021 AJ 161:36, Eq. 5, Table 1; Poisson, hab2, With Uncertainty, Low Bound',
    }
    (out/'bryson_model_form_sensitivity.json').write_text(json.dumps(final,indent=2),encoding='utf-8')
    with (out/'bryson_model_form_sensitivity.csv').open('w',newline='',encoding='utf-8') as f:
        cols=['model','F0','alpha','beta','gamma','uses_gT','C','N_G','Lambda_ESHZ','Lambda_earth10','mean_f_HZ','mean_f_earth10','L2_over_L1']
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for name,m in results.items():
            p=m['parameters']; w.writerow({'model':name,'F0':p['F0'],'alpha':p['alpha'],'beta':p['beta'],'gamma':p['gamma'],'uses_gT':p['use_g'],'C':m['C'],'N_G':m['N_G'],'Lambda_ESHZ':m['Lambda_ESHZ'],'Lambda_earth10':m['Lambda_earth10'],'mean_f_HZ':m['mean_f_HZ'],'mean_f_earth10':m['mean_f_earth10'],'L2_over_L1':m['L2_over_L1']})
    print(json.dumps(final,indent=2))

if __name__=='__main__':
    main()
