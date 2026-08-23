#!/usr/bin/env python3
"""Audit a proposed differential metallicity-dependent PARSEC-TAMS sensitivity.

The canonical Berger/Huber one-dimensional TAMS curve remains the absolute
solar-metallicity baseline. Public PARSEC v1.2S evolutionary tracks are used
only to measure the *differential* response of the TAMS radius to metallicity:

  log R_2D(T,Z) = log R_Huber(T) +
                  [log R_PARSEC(T,Z) - log R_PARSEC(T,Z_solar)].

This construction would have three useful properties if the public track
archive supplied a continuous low-mass TAMS surface over the complete
5300--6000 K manuscript domain:
  1. at solar metallicity it is exactly the frozen canonical selector;
  2. it is insensitive to the special 5200 K / 1.15 Rsun low-Teff boundary
     anchor in the public Huber table, which is not reproduced by the current
     PARSEC track archive under the generator's age<20 Gyr rule;
  3. it isolates precisely the systematic under audit: metallicity transport.

The archived experiment previously admitted massive giant/supergiant phase-7
points into a temperature interpolation. This implementation now permits only
finite low-mass (M <= 2 Msun), compact (R < 10 Rsun) phase-7 anchors and stops
before computing any host counts when even one required metallicity curve lacks
full temperature coverage. JJ row-level FeH would be treated as scaled-solar
[M/H]; alpha-enhancement would remain unmodeled.
"""
from __future__ import annotations

import argparse, csv, hashlib, json, math, tarfile
from pathlib import Path
import numpy as np
from astropy.io import ascii
from tams_reference import tams_radius_rsun

BASE_URL='https://people.sissa.it/~sbressan/CAF09_V1.2S_M36_LT'
TMIN,TMAX=5300.,6000.
LOGG_MAX=7.0
TRACK_AGE_MAX_GYR=30.0
LOW_MASS_MAX_MSUN=2.0
MAX_TAMS_RADIUS_RSUN=10.0
ZX_SUN=0.0207
Y_P=0.2485
DYDZ=1.78
ANCHORS=[
 (0.0005,0.249,'Z0.0005Y0.249.tar.gz'),(0.001,0.250,'Z0.001Y0.25.tar.gz'),
 (0.002,0.252,'Z0.002Y0.252.tar.gz'),(0.004,0.256,'Z0.004Y0.256.tar.gz'),
 (0.006,0.259,'Z0.006Y0.259.tar.gz'),(0.008,0.263,'Z0.008Y0.263.tar.gz'),
 (0.010,0.267,'Z0.01Y0.267.tar.gz'),(0.014,0.273,'Z0.014Y0.273.tar.gz'),
 (0.017,0.279,'Z0.017Y0.279.tar.gz'),(0.020,0.284,'Z0.02Y0.284.tar.gz'),
 (0.030,0.302,'Z0.03Y0.302.tar.gz'),(0.040,0.321,'Z0.04Y0.321.tar.gz')]

def sha256(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
 return h.hexdigest()

def mh_from_z(z):
 y=Y_P+DYDZ*z; x=1-y-z
 return math.log10((z/x)/ZX_SUN)

def download(url,p):
 import requests
 if p.exists() and p.stat().st_size>1024:return
 with requests.get(url,stream=True,timeout=120) as r:
  r.raise_for_status()
  with open(p,'wb') as f:
   for c in r.iter_content(1024*1024):
    if c:f.write(c)

def safe_extract(tf,d):
 root=d.resolve()
 for m in tf.getmembers():
  q=(d/m.name).resolve()
  if root not in q.parents and q!=root:raise RuntimeError(m.name)
 tf.extractall(d)

def validate_low_mass_curve_points(points,z):
 pts=[q for q in points if 4700<=q[0]<=6400 and np.isfinite(q[2]) and q[2]<=LOW_MASS_MAX_MSUN and q[1]<MAX_TAMS_RADIUS_RSUN]
 pts.sort(key=lambda q:q[0])
 if len(pts)<4:raise RuntimeError(f'Z={z}: insufficient low-mass TAMS points ({len(pts)})')
 T=np.array([q[0] for q in pts]);R=np.array([q[1] for q in pts])
 if T.min()>TMIN or T.max()<TMAX:
  raise RuntimeError(f'Z={z}: low-mass TAMS coverage {T.min()}..{T.max()} K does not span {TMIN}..{TMAX} K')
 return pts,T,R

def build_curve(z,y,arcname,cache):
 arc=cache/arcname; download(f'{BASE_URL}/{arcname}',arc)
 d=cache/arcname.replace('.tar.gz','')
 if not (d/'.done').exists():
  d.mkdir(parents=True,exist_ok=True)
  with tarfile.open(arc,'r:gz') as tf:safe_extract(tf,d)
  (d/'.done').write_text('ok\n')
 pts=[]
 # Lexical filename order is mass order and reproduces the physical Huber
 # phase-7 sequence. ADD tracks are excluded.
 for p in sorted(d.rglob('*.DAT'),key=lambda q:q.name):
  if 'ADD' in p.name.upper():continue
  try:t=ascii.read(p)
  except Exception:continue
  if not {'PHASE','AGE','LOG_TE','LOG_L'}.issubset(t.colnames):continue
  ph=np.asarray(t['PHASE'],float); age=np.asarray(t['AGE'],float)
  u=np.where((ph==7.)&(age<TRACK_AGE_MAX_GYR*1e9))[0]
  if not len(u):continue
  k=int(u[0]); T=10**float(t['LOG_TE'][k]); L=float(t['LOG_L'][k])
  R=math.sqrt(10**L*(T/5777.)**(-4))
  mass=float(t['MASS'][k]) if 'MASS' in t.colnames else float('nan')
  pts.append((float(T),float(R),mass,p.name,float(age[k]/1e9)))
 pts,T,R=validate_low_mass_curve_points(pts,z)
 return {'Z':z,'Y':y,'MH':mh_from_z(z),'archive':arcname,'archive_sha256':sha256(arc),'points':pts,'T':T,'R':R}

def raw_logr(c,T):
 T=np.asarray(T,float)
 if np.any(T<c['T'].min()) or np.any(T>c['T'].max()):raise ValueError('Teff extrapolation')
 return np.interp(T,c['T'],np.log10(c['R']))

def validate_solar(c,refpath):
 # The physical phase-7 sequence reproduces all published Huber points from
 # 5390.13944 through 6060.24246 K. The 5200/1.15 low-Teff anchor is not a
 # phase-7 point produced by the current archive under age<20 Gyr and is
 # intentionally excluded from this track-regeneration validation.
 ref=np.loadtxt(refpath); ref=ref[(ref[:,0]>=5390.)&(ref[:,0]<=6060.3)]
 phys=np.array([[q[0],q[1]] for q in c['points'] if q[4]<20.],float)
 rows=[]
 for T,R in ref:
  j=int(np.argmin(abs(phys[:,0]-T)))
  rows.append((T,R,phys[j,0],phys[j,1],abs(phys[j,0]-T),abs(phys[j,1]-R)/R))
 mT=max(x[4] for x in rows); mR=max(x[5] for x in rows)
 if mT>0.01 or mR>1e-4:raise RuntimeError(f'solar track validation failed {mT=} {mR=}')
 return rows,mT,mR

def differential_rtams(T,feh,curves,solar):
 T=np.asarray(T,float); feh=np.asarray(feh,float)
 curves=sorted(curves,key=lambda c:c['MH']); mh=np.array([c['MH'] for c in curves])
 if feh.min()<mh.min() or feh.max()>mh.max():raise ValueError(f'FeH extrapolation: {feh.min()}..{feh.max()} vs {mh.min()}..{mh.max()}')
 solar_log=raw_logr(solar,T)
 deltas=np.vstack([raw_logr(c,T)-solar_log for c in curves])
 d=np.empty(len(T))
 for i,z in enumerate(feh):d[i]=np.interp(z,mh,deltas[:,i])
 return np.asarray(tams_radius_rsun(T),float)*10**d

def trap(rad,field,lo,hi):
 q=[r for r in rad if lo<=r['R_kpc']<=hi]; R=np.array([r['R_kpc'] for r in q]); y=np.array([r[field] for r in q])
 if abs(R[0]-lo)>1e-9 or abs(R[-1]-hi)>1e-9:raise RuntimeError('radial endpoints')
 return float(np.trapz(y,R))

def wquant(v,w,qs):
 v=np.asarray(v);w=np.asarray(w);o=np.argsort(v);v=v[o];w=w[o];c=np.cumsum(w);c=c/c[-1]
 return [float(np.interp(q,c,v)) for q in qs]

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--reference-tams',required=True);ap.add_argument('--cache',required=True);ap.add_argument('--out',required=True)
 a=ap.parse_args();cache=Path(a.cache);out=Path(a.out);cache.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True)
 parent=[]
 with open(a.input,newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):parent.append({'R_kpc':float(r['R_kpc']),'component':r['component'],'FeH':float(r['FeH']),'T':float(r['Teff_K']),'logg':float(r['logg']),'N':float(r['N_surface_pc-2']),'Rstar':float(r['Rstar_g_Rsun']),'B1':int(r['B_TAMS_MS'])==1,'fHZ':float(r['f_HZ']),'f10':float(r['f_earth10'])})
 feh=np.array([r['FeH'] for r in parent]); T=np.array([r['T'] for r in parent])
 am=np.array([mh_from_z(z) for z,_,_ in ANCHORS]); lo=max(0,np.searchsorted(am,feh.min(),'right')-1);hi=min(len(ANCHORS)-1,np.searchsorted(am,feh.max(),'left'))
 anchors=list(ANCHORS[int(lo):int(hi)+1])
 if not any(abs(z-.017)<1e-12 for z,_,_ in anchors):anchors.append((.017,.279,'Z0.017Y0.279.tar.gz'))
 curves=[];coverage_failures=[]
 for anchor in anchors:
  try:curves.append(build_curve(*anchor,cache))
  except RuntimeError as exc:coverage_failures.append({'Z':anchor[0],'archive':anchor[2],'error':str(exc)})
 if coverage_failures:
  assessment={'experiment':'differential_metallicity_PARSEC_TAMS_sensitivity','status':'FAIL_NOT_PUBLISHABLE','decision':'No metallicity-dependent TAMS correction is computed or used in manuscript v4.','reason':'The public archive does not provide a validated low-mass phase-7 TAMS surface over 5300--6000 K at every required metallicity.','low_mass_filter':{'maximum_mass_Msun':LOW_MASS_MAX_MSUN,'maximum_radius_Rsun_exclusive':MAX_TAMS_RADIUS_RSUN,'track_age_horizon_Gyr':TRACK_AGE_MAX_GYR},'coverage_failures':coverage_failures}
  with open(out/'metallicity_tams_differential_sensitivity.json','w') as f:json.dump(assessment,f,indent=2)
  print(json.dumps(assessment,indent=2));return
 curves=sorted(curves,key=lambda c:c['MH']);solar=next(c for c in curves if abs(c['Z']-.017)<1e-12)
 val,mT,mR=validate_solar(solar,Path(a.reference_tams))
 rt2=differential_rtams(T,feh,curves,solar);rs=np.array([r['Rstar'] for r in parent]);lg=np.array([r['logg'] for r in parent]);B2=(rs<=rt2)&(lg<LOGG_MAX)
 for i,r in enumerate(parent):r['B2']=bool(B2[i]);r['RT2']=float(rt2[i])
 rad=[]
 for R in sorted(set(r['R_kpc'] for r in parent)):
  rr=[r for r in parent if r['R_kpc']==R];d={'R_kpc':R};fac=2*math.pi*R*1e6
  for k,s in [('1D','B1'),('2D','B2')]:
   x=[r for r in rr if r[s]];d[f'N_{k}']=fac*sum(r['N'] for r in x);d[f'L1_{k}']=fac*sum(r['N']*r['fHZ'] for r in x);d[f'L2_{k}']=fac*sum(r['N']*r['f10'] for r in x)
   for c in ['thin','thick']:d[f'N_{k}_{c}']=fac*sum(r['N'] for r in x if r['component']==c)
  rad.append(d)
 res={'experiment':'differential_metallicity_PARSEC_TAMS_sensitivity','method':'R_Huber(T) * R_PARSEC(T,Z)/R_PARSEC(T,Zsolar)','JJ_FeH_interpretation':'JJ FeH treated as scaled-solar [M/H] for this sensitivity; alpha-enhancement not modeled','parent_FeH_range':[float(feh.min()),float(feh.max())],'track_age_horizon_Gyr':TRACK_AGE_MAX_GYR,'solar_track_validation':{'excluded_reference_anchor':'5200 K, 1.15 Rsun','validated_range_K':[5390.13944,6060.24246],'max_abs_dT_K':mT,'max_relative_dR':mR},'anchors':[{'Z':c['Z'],'Y':c['Y'],'MH':c['MH'],'sha256':c['archive_sha256'],'T_range':[float(c['T'].min()),float(c['T'].max())],'n_points':len(c['points'])} for c in curves],'domains':{}}
 for name,loR,hiR in [('lineweaver_7_9',7.,9.),('full_JJ_4_14',4.,14.)]:
  dd={}
  for k in ['1D','2D']:
   N=trap(rad,f'N_{k}',loR,hiR);L1=trap(rad,f'L1_{k}',loR,hiR);L2=trap(rad,f'L2_{k}',loR,hiR);th=trap(rad,f'N_{k}_thick',loR,hiR);tn=trap(rad,f'N_{k}_thin',loR,hiR)
   assert 0<=L2<=L1;dd[k]={'N_G':N,'Lambda_ESHZ':L1,'Lambda_earth10':L2,'thin_hosts':tn,'thick_hosts':th,'thick_fraction':th/N}
  dd['delta_2D_vs_1D']={x:(dd['2D'][x]-dd['1D'][x])/dd['1D'][x] for x in ['N_G','Lambda_ESHZ','Lambda_earth10']};res['domains'][name]=dd
 b=res['domains']['lineweaver_7_9']['1D'];assert abs(b['N_G']-263061992.3667424)<1e-2 and abs(b['Lambda_ESHZ']-105716685.0799756)<1e-2 and abs(b['Lambda_earth10']-3376462.6740267)<1e-2
 ch=[r for r in parent if 7<=r['R_kpc']<=9 and r['B1']!=r['B2']]
 for label,rows in [('gained',[r for r in ch if not r['B1'] and r['B2']]),('lost',[r for r in ch if r['B1'] and not r['B2']])]:
  res[label]={'rows':len(rows),'FeH_weighted_q16_q50_q84':wquant([r['FeH'] for r in rows],[r['N'] for r in rows],[.16,.5,.84]) if rows else [None,None,None]}
 with open(out/'metallicity_tams_differential_sensitivity.json','w') as f:json.dump(res,f,indent=2)
 with open(out/'metallicity_tams_differential_radial.csv','w',newline='') as f:w=csv.DictWriter(f,fieldnames=rad[0].keys());w.writeheader();w.writerows(rad)
 with open(out/'metallicity_tams_solar_validation.csv','w',newline='') as f:w=csv.writer(f);w.writerow(['ref_T','ref_R','track_T','track_R','dT','rel_dR']);w.writerows(val)
 with open(out/'metallicity_tams_anchor_points.csv','w',newline='') as f:
  w=csv.writer(f);w.writerow(['Z','Y','MH','Teff_K','R_Rsun','mass','file','age_Gyr'])
  for c in curves:
   for q in c['points']:w.writerow([c['Z'],c['Y'],c['MH'],*q])
 print(json.dumps(res,indent=2))
if __name__=='__main__':main()
