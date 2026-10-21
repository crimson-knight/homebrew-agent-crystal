"""Guarded exact-inline source admission and positive-stage evidence sensitivities."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,os,runpy,shutil,subprocess,sys,tempfile
from unittest import mock
P=Path(__file__).resolve().parent;A=P.parent/'grant_cache_policy_v100';parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();args.output.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();calls=[]
def guarded(*a,**k):calls.append('external');raise AssertionError('Guarded metadata-only source scope')
repo=args.output/'repository with spaces';(repo/'test/grant_cache_policy').mkdir(parents=True);(repo/'test/grant_assignment_cost').mkdir()
for src,dst in [(A/'source',repo/'test/grant_cache_policy'),(A/'grant_assignment_cost',repo/'test/grant_assignment_cost')]:
 for row in json.loads((src/'SOURCE_PINS.json').read_bytes())['files']:
  p=src/row['path'];q=dst/row['path'];q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes())
 (dst/'SOURCE_PINS.json').write_bytes((src/'SOURCE_PINS.json').read_bytes())
source=repo/'test/grant_cache_policy';sys.path.insert(0,str(source));spec=importlib.util.spec_from_file_location('peer_cases',source/'test_cache_policy.py');tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests);stage=tests.staging
results=[]
with mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded),mock.patch.object(os,'killpg',side_effect=guarded):
 # A successful outer receipt with missing underlying evidence must refuse.
 d=args.output/'missing-comparison';d.mkdir();(d/'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=True,diagnostic_complete=True)))
 result=stage.stage(d,args.output/'missing-comparison-public');results.append(dict(case='positive_missing_comparison',accepted=True,files=[r['path'] for r in result['files']]))
 # The actual reviewed controller fixture creates an accepted46-member stage.
 for mutation in ('COMMANDS.json','calibration_raw','missing_calibration'):
  d=args.output/mutation;d.mkdir();case=tests.CachePolicyControls();code,value,events=case.controller_fixture(d);source_root=d/'result'
  if code!=0:raise RuntimeError('Restored positive fixture required')
  if mutation=='COMMANDS.json':(source_root/'comparison/candidate/COMMANDS.json').write_text('[]\n')
  elif mutation=='calibration_raw':(source_root/'timing-calibration/probe.stderr.txt').write_text('SYNTHETIC changed calibration footer\n')
  else:shutil.rmtree(source_root/'timing-calibration')
  result=stage.stage(source_root,d/'public');results.append(dict(case=mutation,accepted=True,file_count=len(result['files'])))
# The exact workflow independently pins the seven new sources, then imports
# an inherited helper before the215-row core is revalidated in the controller.
base=repo/'test/grant_assignment_cost/same_job_policy.py';before=base.read_bytes();base.write_bytes(b'raise RuntimeError("PEER_CHANGED_CORE_IMPORTED_BEFORE_ADMISSION")\n'+before)
# Clear exact modules already imported by the source-only stage fixture.
for name,module in list(sys.modules.items()):
 location=getattr(module,'__file__',None)
 if location and (str(repo) in str(location)) and name!='peer_cases':sys.modules.pop(name,None)
lines=(A/'grant-cache-mac.proposed.yml').read_text().splitlines();blocks=[]
for i,line in enumerate(lines):
 if "<<'PYTHON'" in line:
  end=next(j for j in range(i+1,len(lines)) if lines[j].strip()=='PYTHON');blocks.append('\n'.join(row[10:] for row in lines[i+1:end])+'\n')
oldcwd=Path.cwd();os.chdir(repo)
try:
 with mock.patch.dict(os.environ,{'ATLAS_CACHE_PACKET_SHA256':sha(source/'SOURCE_PINS.json'),'RUNNER_TEMP':str(args.output)}),mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded),mock.patch.object(os,'killpg',side_effect=guarded):
  try:exec(compile(blocks[1],'<exact frozen workflow cache inline>','exec'))
  except RuntimeError as error:
   if 'PEER_CHANGED_CORE_IMPORTED_BEFORE_ADMISSION' not in str(error):raise
   results.append(dict(case='changed_core_import_before_admission',changed_helper_sha256=sha(base),changed_core_code_executed=True,error=str(error)))
  else:raise RuntimeError('Exact changed-core source sensitivity required')
finally:os.chdir(oldcwd);base.write_bytes(before)
value=dict(format='atlas-grant-cache-policy-independent-sensitivities-v1',results=results,guard_calls=len(calls),actual_local_compiler_native_container_ssh_workloads=0,optimization=sys.flags.optimize,probe_sha256=sha(Path(__file__)))
(args.output/'SENSITIVITIES.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');print(json.dumps(value,sort_keys=True))
