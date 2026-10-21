"""Guarded cross-process clock-origin sensitivity with the exact accepted data fixture."""
from pathlib import Path
import hashlib,importlib.util,json,os,subprocess,sys,time,zipfile
from unittest import mock
ROOT=Path(__file__).resolve().parent;AUTHOR=ROOT.parent/'grant_dirty_tool_transfer_v101';source=AUTHOR/'proof_tool_transfer.py'
expected='8b7813c1f10ac0fe13f51f06961b0811bebf4dcaeea655da4c9a2b566044f3b4'
if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise RuntimeError('Exact source required')
spec=importlib.util.spec_from_file_location('clock_source',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
provider=Path(sys.executable).resolve();actual_clock={'provider_path':str(provider),'provider_sha256':hashlib.sha256(provider.read_bytes()).hexdigest(),'Python_version':sys.version,'local_monotonic':time.monotonic(),'common_MONOTONIC':time.clock_gettime(time.CLOCK_MONOTONIC),'local_implementation':time.get_clock_info('monotonic').implementation}
parent=ROOT/'clock-origin-fixture';parent.mkdir();calls=[]
def guarded(*a,**kw):calls.append('external');raise AssertionError('Metadata fixture uses authored source/data')
with mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded),mock.patch.object(os,'killpg',side_effect=guarded):
 with mock.patch.object(module.time,'monotonic',return_value=10):workspace=module.initialize(parent)
 clock_sha=module.sha((workspace/'TRANSFER_CLOCK.json').read_bytes())
 artifact=ROOT.parent/'grant_dirty_tool_bootstrap_parent_actual_v101/tools-12310618101.zip'
 if module.sha(artifact.read_bytes())!='b92262e930c0dfdc5c47ba51c310f1fe0590e7e1a7e72c7a401bcd8bd3fad31a':raise RuntimeError('Exact data fixture required')
 (workspace/'download').mkdir()
 with zipfile.ZipFile(artifact) as archive:
  for item in archive.infolist():
   path=workspace/'download'/module.contained(item.filename);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(archive.read(item));path.chmod(0o644)
 with mock.patch.object(module.time,'monotonic',return_value=1):result=module.verify_transfer(workspace,clock_sha)
value={'source_sha256':expected,'actual_current_provider_clock_metadata':actual_clock,'mocked_initializer_process_clock':10,'mocked_fresh_verifier_process_clock':1,'actual_wall_wait_claimed':False,'result':result,'external_guard_calls':len(calls),'actual_compiler_native_container_browser_SSH_workloads':0}
(ROOT/'CLOCK_ORIGIN_SENSITIVITY.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');print(json.dumps({'passed':result['passed'],'elapsed_seconds':result['elapsed_seconds'],'maximum_seconds':result['maximum_seconds'],'guard_calls':len(calls),'local_vs_common_clock':[actual_clock['local_monotonic'],actual_clock['common_MONOTONIC']]}))
