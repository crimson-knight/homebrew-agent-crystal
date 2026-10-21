"""Zero-calibration static image-provider discovery for the census source route."""
import argparse,ctypes,hashlib,importlib.util,json,math,os,plistlib,shutil,stat,sys,sysconfig,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent;SECONDS=300;MAX_METADATA=16*2**20
BOOTSTRAP_SHA='1955899cb535256cfa477d926d016819e52e747984722c44f76e39a4950fee0e';PUBLIC_SHA='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed';sha=lambda b:hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise RuntimeError(m)
def physical(path,maximum=8*2**20):
 p=Path(path);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=maximum and p.resolve(strict=True)==p,'Bounded stable physical input required');b=p.read_bytes();a=p.lstat();fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns);need(fields(s)==fields(a) and len(b)==s.st_size,'Original complete input returned');return b

def module(path,expected,name):
 need(sha(physical(path))==expected,'Exact source before import required');spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);need(sha(physical(path))==expected,'Imported source return required');return m

def admit(v,source,shared,nonce,env,now):
 need(v['format']=='atlas-census-static-provider-admission-v1' and v['static_metadata_admitted']is True and all(v[k]is False for k in ('metadata_calibrations_admitted','full_source_execution_admitted','compiler_API_native_workloads_admitted')),'Explicit zero-calibration static metadata authority required')
 need(v['observer_source_sha256']==source and v['shared_manifest_sha256']==shared and v['invocation_nonce']==nonce and type(nonce)is str and len(nonce)>=32,'Exact source/shared/fresh nonce binding required')
 need(v['expected_source_commit']==env.get('GITHUB_SHA') and v['runner_label']=='macos-26' and v['bootstrap_python_sha256']==BOOTSTRAP_SHA and type(v['maximum_seconds'])is int and v['maximum_seconds']==SECONDS,'Exact public source/image/Python/300-second selection required')
 need(v['trusted_CI_bootstrap_metadata_scope']is True and type(v['lease_receipt_sha256'])is str and len(v['lease_receipt_sha256'])==64 and all(c in '0123456789abcdef'for c in v['lease_receipt_sha256']),'Explicit trusted bootstrap and selected finite lease receipt required')
 need(all(type(v[k])in(int,float)and math.isfinite(v[k])for k in ('not_before_unix','latest_start_unix','complete_by_unix')) and v['not_before_unix']<=now<=v['latest_start_unix']<=v['not_before_unix']+3600 and v['complete_by_unix']>=v['latest_start_unix']+SECONDS and v['complete_by_unix']<=v['not_before_unix']+3900,'Finite externally selected full observation interval required');need(v['maximum_owned_metadata_bytes']==64*2**20 and type(v['maximum_owned_metadata_bytes'])is int and v['maximum_public_artifact_bytes']==24*2**20 and type(v['maximum_public_artifact_bytes'])is int,'Exact finite metadata/artifact reservations required');return v

def root_identity(path):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode)and path.resolve(strict=True)==path,'Physical owned output directory required');return(s.st_dev,s.st_ino,s.st_mode)
def write_owned(root,identity,name,raw):
 need(root_identity(root)==identity and Path(name).name==name,'Original owned root and literal output name required')
 fd=os.open(str(root/name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw)
 need(root_identity(root)==identity and physical(root/name,MAX_METADATA)==raw,'Complete original output bytes returned');return dict(path=name,bytes=len(raw),sha256=sha(raw))
def boot():
 lib=ctypes.CDLL(None);f=lib.sysctlbyname;f.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t];f.restype=ctypes.c_int;s=ctypes.c_size_t(128);b=ctypes.create_string_buffer(128);need(f(b'kern.bootsessionuuid',b,ctypes.byref(s),None,0)==0 and 0<s.value<=128,'Actual read-only kernel boot-session metadata required');return b.value.decode('ascii')

def platform(nonce):
 with open('/System/Library/CoreServices/SystemVersion.plist','rb')as f:v=plistlib.load(f)
 return dict(host=os.environ.get('RUNNER_NAME',''),boot=boot(),OS_build=v['ProductBuildVersion'],image_version=os.environ.get('ImageVersion',''),architecture=os.uname().machine,code_loading_scope='trusted CI metadata bootstrap; Apple shared-cache bodies remain unqualified',nonce=nonce)

def selection():
 names=dict(system_python='python3',ruby_launcher='ruby',bash='bash',sh='sh',chmod='chmod',uname='uname');roles={r:shutil.which(n)for r,n in names.items()};need(all(roles.values()),'All actual image lexical entrypoints required');roles['qualified_python']=str(Path(sys.executable).resolve());ruby=Path(roles['ruby_launcher']).resolve(strict=True)
 framework=Path('/System/Library/Frameworks/Ruby.framework/Versions/Current/usr/bin/ruby');roles['ruby_backend']=str(framework if str(ruby)=='/usr/bin/ruby' and framework.is_file() else ruby)
 roots=[sysconfig.get_path(k)for k in ('stdlib','platstdlib')];roots += [str(Path(sysconfig.get_config_var('DESTSHARED')or'/unavailable'))]
 roots += [str(Path(roles['ruby_backend']).resolve().parent.parent/'lib/ruby'),str(ruby.parent.parent/'lib/ruby')]
 roots=sorted(set(str(Path(r).resolve())for r in roots if r and Path(r).is_dir()));need(roots,'Statically derivable runtime input roots required');return roles,roots

def run(args):
 started=time.monotonic();deadline=started+SECONDS;source=physical(Path(__file__).resolve());need(sha(physical(Path(sys.executable).resolve(),32*2**20))==BOOTSTRAP_SHA,'Exact historical image Python bootstrap required; other bytes remain a new candidate')
 raw=physical(args.shared_root/'SOURCE_PINS.json');need(sha(raw)==args.shared_manifest_sha256,'Exact shared source manifest required');pins=json.loads(raw)['files'];protected={Path(__file__).resolve():sha(source),args.shared_root/'SOURCE_PINS.json':sha(raw)}
 for row in pins:
  rel=Path(row['path']);need(not rel.is_absolute()and'..'not in rel.parts,'Contained shared source required');p=args.shared_root/rel;b=physical(p);need(sha(b)==row['sha256']and len(b)==row['bytes'],'Exact shared implementation bytes required');protected[p]=sha(b)
 a=physical(args.admission);need(sha(a)==args.admission_sha256,'Independent external static-metadata admission hash required');admit(json.loads(a),sha(source),sha(raw),args.nonce,os.environ,time.time());protected[args.admission]=sha(a)
 helper=module(args.public_helper,PUBLIC_SHA,'static_provider_public_content_policy');protected[args.public_helper]=PUBLIC_SHA;shared=module(args.shared_root/'provider.py',next(r['sha256']for r in pins if r['path']=='provider.py'),'shared_static_provider_collector');need(not args.output.exists() and not args.output.is_symlink() and args.output.parent.resolve(strict=True)==args.output.parent,'Fresh physical owned metadata output required');args.output.mkdir(mode=0o700);root_id=root_identity(args.output);private=args.output/'private';private.mkdir(mode=0o700);(private/'home').mkdir(mode=0o700);(private/'calibration').mkdir(mode=0o700)
 result=dict(format='atlas-census-zero-calibration-static-provider-v1',passed=False,execution_admitted=False,calibration_commands=0,provider_approval_complete=False,actual_startup_observations_complete=False,full_source_behavior_accepted=False,actual_compiler_API_native_jobs=0,original_child_groups=[],private_removed=False,source_provider_return=False,finalization_errors=[]);profile=None
 try:
  roles,roots=selection();before_platform=platform(args.nonce);config=dict(providers=roles,execution_context=dict(owned_root=str(private),home=str(private/'home'),calibration_cwd=str(private/'calibration')));profile=shared.static_inputs(config,roots,deadline-60);need(time.monotonic()<deadline-60,'Original60-second complete return reserve required');returned=shared.static_inputs(config,roots,deadline);need(profile==returned,'Every original static provider/alias/stdlib/extension/native identity returned');need(platform(args.nonce)==before_platform,'Original host/boot/OS/image metadata returned');result.update(passed=True,static_native_file_closure_complete=profile['complete'],platform=before_platform,job={k:os.environ[k]for k in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','RUNNER_NAME')},runtime_roots=roots,ruby_backend_selection='unexecuted static candidate; RbConfig/startup equality pending',startup_inventory_scope='statically derived installation inputs; normal and isolated startup require independent calibration admission')
 except BaseException as e:result['error']=type(e).__name__+': '+str(e)
 finally:
  try:
   need(root_identity(args.output)==root_id,'Original owned output root required');shutil.rmtree(private);need(not private.exists(),'Complete private directory retirement required');result['private_removed']=True
   for p,h in protected.items():need(sha(physical(p))==h,'Every original source/admission/public helper returned exact')
   result['source_provider_return']=True
  except BaseException as e:result['finalization_errors'].append(type(e).__name__+': '+str(e))
  result.update(elapsed_seconds=time.monotonic()-started,maximum_seconds=SECONDS,observer_source_sha256=sha(source),shared_manifest_sha256=sha(raw),admission_sha256=sha(a));result['passed']=result['passed']and result['private_removed']and result['source_provider_return']and not result['finalization_errors']and result['elapsed_seconds']<=SECONDS
  outputs={'OBSERVATION_RESULT.json':result}
  if profile is not None:outputs['STATIC_PROFILE.json']=profile
  total=0;rows=[]
  for name,value in outputs.items():
   b=(json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode();helper.inspect_public_bytes(name,b);total+=len(b);need(total<=MAX_METADATA,'Complete16MiB metadata artifact ceiling required');rows.append(write_owned(args.output,root_id,name,b))
  stage=(json.dumps(dict(format='atlas-static-provider-value-free-stage-v1',files=rows,calibration_commands=0,raw_runtime_binaries_retained=False,source_provider_return=result['source_provider_return'],outer_command_return_required=True),sort_keys=True)+'\n').encode();helper.inspect_public_bytes('PUBLIC_STAGE.json',stage);write_owned(args.output,root_id,'PUBLIC_STAGE.json',stage)
  for row in rows:need(sha(physical(args.output/row['path'],MAX_METADATA))==row['sha256'],'Original complete public file return required')
  for p,h in protected.items():need(sha(physical(p))==h,'Final original source return required')
  need(time.monotonic()<=deadline,'Complete publication within original300-second horizon required')
 return 0 if result['passed']else 2
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('shared-root','public-helper','admission','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in ('shared-manifest-sha256','admission-sha256','nonce'):p.add_argument('--'+name,required=True)
 raise SystemExit(run(p.parse_args()))
