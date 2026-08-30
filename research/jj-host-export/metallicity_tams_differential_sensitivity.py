#!/usr/bin/env python3
"""Produce a fail-closed PARSEC metallicity-TAMS coverage audit.

The checksum-locked public PARSEC tracks are inspected only to decide whether
finite low-mass (M <= 2 Msun), compact (R < 10 Rsun) phase-7 anchors cover the
complete 5300--6000 K domain.  The current locked archives do not satisfy that
condition.  Therefore this program can emit only a ``FAIL_NOT_PUBLISHABLE``
coverage report and a validation-only native Z=0.017 node table.  It never
computes or exports a metallicity-dependent host correction.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import stat
import tarfile
import warnings
from pathlib import Path, PurePosixPath

import numpy as np
from astropy.io import ascii

BASE_URL='https://people.sissa.it/~sbressan/CAF09_V1.2S_M36_LT'
DEFAULT_DATA_LOCKS=Path(__file__).resolve().parents[2]/'provenance'/'DATA_LOCKS.json'
REPORT_NAME='metallicity_tams_differential_sensitivity.json'
SOLAR_POINTS_NAME='native_solar_tams_nodes.csv'
RUNTIME_NAME='NUMERICAL_RUNTIME_POLICY.json'
FORBIDDEN_CORRECTION_FILES={
 'metallicity_tams_differential_radial.csv',
 'metallicity_tams_solar_validation.csv',
 'metallicity_tams_anchor_points.csv',
}
TMIN,TMAX=5300.,6000.
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
ANCHOR_LOCK_IDS={
 'Z0.0005Y0.249.tar.gz':'parsec_tracks_z00005','Z0.001Y0.25.tar.gz':'parsec_tracks_z0001',
 'Z0.002Y0.252.tar.gz':'parsec_tracks_z0002','Z0.004Y0.256.tar.gz':'parsec_tracks_z0004',
 'Z0.006Y0.259.tar.gz':'parsec_tracks_z0006','Z0.008Y0.263.tar.gz':'parsec_tracks_z0008',
 'Z0.01Y0.267.tar.gz':'parsec_tracks_z001','Z0.014Y0.273.tar.gz':'parsec_tracks_z0014',
 'Z0.017Y0.279.tar.gz':'parsec_tracks_z0017','Z0.02Y0.284.tar.gz':'parsec_tracks_z002',
 'Z0.03Y0.302.tar.gz':'parsec_tracks_z003','Z0.04Y0.321.tar.gz':'parsec_tracks_z004',
}

class CoverageValidationError(RuntimeError):
 pass

def require(condition,message):
 if not condition:raise RuntimeError(message)

def read_regular_bytes(path,label):
 path=Path(path)
 try:
  before=path.lstat()
  require(stat.S_ISREG(before.st_mode),f'{label}: missing or unsafe regular file: {path}')
  flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
  fd=os.open(path,flags)
  try:
   opened=os.fstat(fd);after=path.lstat()
   require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(after.st_mode),f'{label}: unsafe file type: {path}')
   require((before.st_dev,before.st_ino)==(opened.st_dev,opened.st_ino)==(after.st_dev,after.st_ino),f'{label}: path changed while opening: {path}')
   with os.fdopen(fd,'rb',closefd=False) as f:data=f.read()
   finished=os.fstat(fd)
   require((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)==(finished.st_dev,finished.st_ino,finished.st_size,finished.st_mtime_ns),f'{label}: file changed while reading: {path}')
   require(len(data)==opened.st_size,f'{label}: short or inconsistent read: {path}')
   return data
  finally:
   os.close(fd)
 except (OSError,ValueError) as exc:
  raise RuntimeError(f'{label}: cannot read safe regular file {path}: {exc}') from exc

def write_exclusive_bytes(path,data,label):
 path=Path(path)
 flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
 try:
  fd=os.open(path,flags,0o644)
  with os.fdopen(fd,'wb') as f:
   f.write(data);f.flush();os.fsync(f.fileno())
 except (FileExistsError,OSError) as exc:
  raise RuntimeError(f'{label}: refusing unsafe or non-exclusive output path {path}: {exc}') from exc

def sha256(p):
 return hashlib.sha256(read_regular_bytes(p,'SHA-256 input')).hexdigest()

def require_regular_file(path,label):
 require(path.is_file() and not path.is_symlink(),f'{label}: missing or unsafe regular file: {path}')

def prepare_output_root(out):
 require(out.exists() and out.is_dir() and not out.is_symlink(),f'Output root must be an existing safe directory: {out}')
 entries={p.name for p in out.iterdir()}
 require(entries=={RUNTIME_NAME},f'Output root must initially contain only {RUNTIME_NAME}: {sorted(entries)}')
 require_regular_file(out/RUNTIME_NAME,'numerical runtime policy')
 for name in FORBIDDEN_CORRECTION_FILES:
  p=out/name
  require(not p.exists() and not p.is_symlink(),f'Forbidden correction artifact is present: {name}')

def mh_from_z(z):
 y=Y_P+DYDZ*z; x=1-y-z
 return math.log10((z/x)/ZX_SUN)

def load_archive_locks(path):
 path=Path(path)
 data=json.loads(read_regular_bytes(path,'data-lock registry').decode('utf-8'))
 locks=data.get('locks',{})
 by_filename={}
 required={name for _,_,name in ANCHORS};require(set(ANCHOR_LOCK_IDS)==required,'Internal PARSEC lock map is incomplete')
 for filename,lock_id in ANCHOR_LOCK_IDS.items():
  record=locks.get(lock_id)
  require(isinstance(record,dict),f'{lock_id}: missing PARSEC archive lock')
  require(record.get('filename')==filename,f'{lock_id}: unexpected PARSEC archive filename')
  require(record.get('distribution_role')=='fetch-only',f'{lock_id}: PARSEC archive must be fetch-only')
  require(record.get('source_url')==f"{BASE_URL}/{record['filename']}",f'{lock_id}: unexpected PARSEC source URL')
  require(isinstance(record.get('expected_size_bytes'),int) and record['expected_size_bytes']>0,f'{lock_id}: invalid size lock')
  digest=record.get('expected_sha256','')
  require(len(digest)==64 and all(c in '0123456789abcdef' for c in digest),f'{lock_id}: invalid SHA-256 lock')
  by_filename[filename]={**record,'lock_id':lock_id}
 require(set(by_filename)==required,f'Incomplete PARSEC archive lock set: {sorted(required-set(by_filename))}')
 return by_filename

def verify_archive_lock(p,lock):
 payload=read_regular_bytes(p,f"{lock['lock_id']} archive")
 size=len(payload)
 require(size==lock['expected_size_bytes'],f"{lock['lock_id']}: size mismatch {size} != {lock['expected_size_bytes']}")
 digest=hashlib.sha256(payload).hexdigest()
 require(digest==lock['expected_sha256'],f"{lock['lock_id']}: SHA-256 mismatch {digest} != {lock['expected_sha256']}")
 return {'lock_id':lock['lock_id'],'filename':p.name,'size_bytes':size,'sha256':digest}

def read_locked_archive(p,lock):
 payload=read_regular_bytes(p,f"{lock['lock_id']} archive")
 size=len(payload);digest=hashlib.sha256(payload).hexdigest()
 require(size==lock['expected_size_bytes'],f"{lock['lock_id']}: size mismatch {size} != {lock['expected_size_bytes']}")
 require(digest==lock['expected_sha256'],f"{lock['lock_id']}: SHA-256 mismatch {digest} != {lock['expected_sha256']}")
 return {'lock_id':lock['lock_id'],'filename':p.name,'size_bytes':size,'sha256':digest},payload

def download(url,p,lock):
 import requests
 require(url==lock['source_url'],f"{lock['lock_id']}: URL differs from data lock")
 require(not p.is_symlink(),f"{lock['lock_id']}: archive path must not be a symlink")
 if not p.exists():
  partial=p.with_name(p.name+'.part')
  require(not partial.exists() and not partial.is_symlink(),f"{lock['lock_id']}: partial download path already exists")
  partial_identity=None
  try:
   with requests.get(url,stream=True,timeout=120) as r:
    r.raise_for_status()
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(partial,flags,0o600)
    opened=os.fstat(fd);partial_identity=(opened.st_dev,opened.st_ino)
    with os.fdopen(fd,'wb') as f:
     for c in r.iter_content(1024*1024):
      if c:f.write(c)
     f.flush();os.fsync(f.fileno())
   read_locked_archive(partial,lock)
   require(not p.exists() and not p.is_symlink(),f"{lock['lock_id']}: destination appeared during download")
   os.link(partial,p,follow_symlinks=False)
  finally:
   if partial_identity is not None and (partial.exists() or partial.is_symlink()):
    current=partial.lstat()
    require((current.st_dev,current.st_ino)==partial_identity,f"{lock['lock_id']}: partial path changed before cleanup")
    partial.unlink()
 return read_locked_archive(p,lock)

def validated_track_members(tf):
 tracks=[];seen=set()
 for member in tf.getmembers():
  name=member.name;parts=PurePosixPath(name).parts
  require(name and '\\' not in name and not PurePosixPath(name).is_absolute() and '..' not in parts,f'unsafe TAR member: {name}')
  if member.isdir():continue
  require(member.isfile(),f'unsupported TAR member: {name}')
  require(name not in seen,f'duplicate TAR member: {name}')
  seen.add(name)
  if name.upper().endswith('.DAT') and 'ADD' not in PurePosixPath(name).name.upper():tracks.append(member)
 return sorted(tracks,key=lambda item:PurePosixPath(item.name).name)

def validate_low_mass_curve_points(points,z):
 pts=[q for q in points if all(np.isfinite(v) for v in (q[0],q[1],q[2],q[4])) and 4700<=q[0]<=6400 and 0<q[2]<=LOW_MASS_MAX_MSUN and 0<q[1]<MAX_TAMS_RADIUS_RSUN and 0<q[4]<TRACK_AGE_MAX_GYR]
 pts.sort(key=lambda q:q[0])
 if len(pts)<4:raise CoverageValidationError(f'Z={z}: insufficient low-mass TAMS points ({len(pts)})')
 T=np.array([q[0] for q in pts]);R=np.array([q[1] for q in pts])
 if T.min()>TMIN or T.max()<TMAX:
  raise CoverageValidationError(f'Z={z}: low-mass TAMS coverage {T.min()}..{T.max()} K does not span {TMIN}..{TMAX} K')
 return pts,T,R

def build_curve(z,y,arcname,cache,archive_locks):
 arc=cache/arcname;audit,payload=download(f'{BASE_URL}/{arcname}',arc,archive_locks[arcname])
 pts=[]
 # Parse only regular members from the verified in-memory archive. No mutable
 # extracted track cache or completion marker participates in the result.
 with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as tf:
  for member in validated_track_members(tf):
   source=tf.extractfile(member)
   require(source is not None,f'unreadable TAR member: {member.name}')
   with source:track_bytes=source.read()
   require(len(track_bytes)==member.size,f'short TAR member read: {member.name}')
   filename=PurePosixPath(member.name).name
   t=None
   try:t=ascii.read(io.BytesIO(track_bytes))
   except Exception as exc:  # noqa: BLE001 - Astropy readers raise varied errors
    warnings.warn(f'Skipping unreadable PARSEC track {filename}: {exc}',RuntimeWarning)
   if t is None:continue
   if not {'PHASE','AGE','LOG_TE','LOG_L'}.issubset(t.colnames):continue
   ph=np.asarray(t['PHASE'],float); age=np.asarray(t['AGE'],float)
   u=np.where((ph==7.)&(age<TRACK_AGE_MAX_GYR*1e9))[0]
   if not len(u):continue
   k=int(u[0]); T=10**float(t['LOG_TE'][k]); L=float(t['LOG_L'][k])
   R=math.sqrt(10**L*(T/5777.)**(-4))
   mass=float(t['MASS'][k]) if 'MASS' in t.colnames else float('nan')
   pts.append((float(T),float(R),mass,filename,float(age[k]/1e9)))
 pts,T,R=validate_low_mass_curve_points(pts,z)
 return {'Z':z,'Y':y,'MH':mh_from_z(z),'archive':arcname,'archive_lock_id':audit['lock_id'],'archive_size_bytes':audit['size_bytes'],'archive_sha256':audit['sha256'],'points':pts,'T':T,'R':R}

def validate_solar(c,refpath):
 # The physical phase-7 sequence reproduces all published Huber points from
 # 5390.13944 through 6060.24246 K. The 5200/1.15 low-Teff anchor is not a
 # phase-7 point produced by the current archive under age<20 Gyr and is
 # intentionally excluded from this track-regeneration validation.
 ref=np.loadtxt(io.BytesIO(read_regular_bytes(refpath,'canonical TAMS reference')));ref=ref[(ref[:,0]>=5390.)&(ref[:,0]<=6060.3)]
 phys=np.array([[q[0],q[1]] for q in c['points'] if q[4]<20.],float)
 rows=[]
 for T,R in ref:
  j=int(np.argmin(abs(phys[:,0]-T)))
  rows.append((T,R,phys[j,0],phys[j,1],abs(phys[j,0]-T),abs(phys[j,1]-R)/R))
 mT=max(x[4] for x in rows); mR=max(x[5] for x in rows)
 if mT>0.01 or mR>1e-4:raise RuntimeError(f'solar track validation failed {mT=} {mR=}')
 return rows,mT,mR

def native_solar_rows(solar):
 rows=[q for q in solar['points'] if 5150.<=q[0]<=6060.3]
 rows.sort(key=lambda q:q[0])
 require(len(rows)==9,f'Locked Z=0.017 archive must provide exactly 9 validation nodes, found {len(rows)}')
 require(all(np.isfinite(q[0]) and np.isfinite(q[1]) and np.isfinite(q[2]) and np.isfinite(q[4]) for q in rows),'Native solar validation nodes must be finite')
 require(all(q[2]<=LOW_MASS_MAX_MSUN and q[1]<MAX_TAMS_RADIUS_RSUN and q[4]<TRACK_AGE_MAX_GYR for q in rows),'Native solar validation node violates the low-mass filter')
 require(all(b[0]>a[0] and b[1]>a[1] for a,b in zip(rows,rows[1:])),'Native solar validation nodes must increase in temperature and radius')
 require(rows[0][0]<=TMIN and any(TMIN<=q[0]<5390.13944 for q in rows),'Native solar nodes do not bracket the 5300 K boundary')
 return rows

def write_native_solar_nodes(path,solar,rows):
 text=io.StringIO(newline='');w=csv.writer(text,lineterminator='\n')
 w.writerow(['Z','Y','MH','Teff_K','R_Rsun','mass','file','age_Gyr'])
 for T,R,mass,filename,age in rows:
  w.writerow([repr(float(solar['Z'])),repr(float(solar['Y'])),repr(float(solar['MH'])),repr(float(T)),repr(float(R)),repr(float(mass)),filename,repr(float(age))])
 write_exclusive_bytes(path,text.getvalue().encode('utf-8'),'native solar TAMS output')

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--reference-tams',required=True);ap.add_argument('--cache',required=True);ap.add_argument('--out',required=True);ap.add_argument('--data-locks',default=str(DEFAULT_DATA_LOCKS))
 a=ap.parse_args();cache=Path(a.cache);out=Path(a.out);input_path=Path(a.input);reference_path=Path(a.reference_tams)
 prepare_output_root(out)
 require(not cache.is_symlink(),f'Cache path must not be a symlink: {cache}')
 cache.mkdir(parents=True,exist_ok=True)
 require(cache.is_dir() and not cache.is_symlink(),f'Cache path is not a safe directory: {cache}')
 input_bytes=read_regular_bytes(input_path,'JJ host parent input')
 feh_values=[]
 try:
  reader=csv.DictReader(io.StringIO(input_bytes.decode('utf-8'),newline=''))
  require(reader.fieldnames is not None and reader.fieldnames.count('FeH')==1,'JJ host parent input must contain exactly one FeH column')
  for r in reader:feh_values.append(float(r['FeH']))
 except (UnicodeError,csv.Error,KeyError,TypeError,ValueError) as exc:
  raise RuntimeError(f'JJ host parent input is not a valid finite-FeH CSV: {exc}') from exc
 require(feh_values,'JJ host parent input contains no rows')
 feh=np.asarray(feh_values,float)
 require(np.all(np.isfinite(feh)),'JJ host parent input contains non-finite FeH')
 am=np.array([mh_from_z(z) for z,_,_ in ANCHORS]); lo=max(0,np.searchsorted(am,feh.min(),'right')-1);hi=min(len(ANCHORS)-1,np.searchsorted(am,feh.max(),'left'))
 anchors=list(ANCHORS[int(lo):int(hi)+1])
 if not any(abs(z-.017)<1e-12 for z,_,_ in anchors):anchors.append((.017,.279,'Z0.017Y0.279.tar.gz'))
 anchors.sort(key=lambda item:item[0])
 archive_locks=load_archive_locks(a.data_locks)
 curves=[];coverage_failures=[]
 for anchor in anchors:
  try:curves.append(build_curve(*anchor,cache,archive_locks))
  except CoverageValidationError as exc:
   audit=verify_archive_lock(cache/anchor[2],archive_locks[anchor[2]])
   coverage_failures.append({'Z':anchor[0],'archive':anchor[2],'archive_lock_id':audit['lock_id'],'archive_size_bytes':audit['size_bytes'],'archive_sha256':audit['sha256'],'error':str(exc)})
 require(coverage_failures,'Coverage unexpectedly passed; refusing to compute or publish a metallicity correction')
 solar_matches=[c for c in curves if abs(c['Z']-.017)<1e-12]
 require(len(solar_matches)==1,'Locked Z=0.017 validation curve is missing or ambiguous')
 solar=solar_matches[0]
 solar_rows=native_solar_rows(solar)
 _,mT,mR=validate_solar(solar,reference_path)
 solar_path=out/SOLAR_POINTS_NAME
 write_native_solar_nodes(solar_path,solar,solar_rows)
 required_lock_ids=[archive_locks[name]['lock_id'] for _,_,name in anchors]
 successful_ids={curve['archive_lock_id'] for curve in curves}
 failed_ids={failure['archive_lock_id'] for failure in coverage_failures}
 require(successful_ids.isdisjoint(failed_ids) and successful_ids|failed_ids==set(required_lock_ids),'Internal coverage partition is inconsistent')
 require('parsec_tracks_z0017' in successful_ids,'Solar archive must be successful coverage evidence')
 assessment={
  'schema_version':3,
  'experiment':'differential_metallicity_PARSEC_TAMS_coverage_audit',
  'status':'FAIL_NOT_PUBLISHABLE',
  'decision':'No metallicity-dependent TAMS correction is computed or used in manuscript v4.',
  'reason':'The public archive does not provide a validated low-mass phase-7 TAMS surface over 5300--6000 K at every required metallicity.',
  'parent_input':{'filename':input_path.name,'sha256':hashlib.sha256(input_bytes).hexdigest(),'size_bytes':len(input_bytes),'row_count':len(feh_values),'feh_min':float(feh.min()),'feh_max':float(feh.max())},
  'low_mass_filter':{'maximum_mass_Msun':LOW_MASS_MAX_MSUN,'maximum_radius_Rsun_exclusive':MAX_TAMS_RADIUS_RSUN,'track_age_horizon_Gyr':TRACK_AGE_MAX_GYR,'required_temperature_range_K':[TMIN,TMAX]},
  'coverage_failures':sorted(coverage_failures,key=lambda item:item['Z']),
  'coverage_evidence':{'required_lock_ids':required_lock_ids,'successful_lock_ids':[lock_id for lock_id in required_lock_ids if lock_id in successful_ids],'failed_lock_ids':[lock_id for lock_id in required_lock_ids if lock_id in failed_ids]},
  'correction_policy':{'applied':False,'publishable':False,'emitted_files':[]},
  'native_solar_reference':{
   'status':'PASS','role':'validation_only_not_a_metallicity_correction','metallicity_Z':solar['Z'],
   'points_file':SOLAR_POINTS_NAME,'points_sha256':sha256(solar_path),'node_count':len(solar_rows),
   'reference_validation_node_count':7,'max_abs_temperature_difference_K':float(mT),'max_relative_radius_difference':float(mR),
   'archive_lock_id':solar['archive_lock_id'],'archive_filename':solar['archive'],'archive_size_bytes':solar['archive_size_bytes'],'archive_sha256':solar['archive_sha256'],
  },
 }
 report_path=out/REPORT_NAME
 write_exclusive_bytes(report_path,(json.dumps(assessment,indent=2,sort_keys=True)+'\n').encode('utf-8'),'metallicity audit report')
 print(json.dumps(assessment,indent=2,sort_keys=True))
if __name__=='__main__':main()
