"""Source-only native alias convergence sensitivity; all native files are authored bytes."""
import hashlib,importlib.util,json,os
from pathlib import Path
import struct,subprocess,sys,tempfile,time
from unittest import mock
ROOT=Path(__file__).resolve().parent
source=ROOT/'draft_observed/proof_tool_transfer.py'
spec=importlib.util.spec_from_file_location('draft_transfer',source);transfer=importlib.util.module_from_spec(spec);spec.loader.exec_module(transfer)
def macho(names):
 commands=[]
 for name in names:
  raw=name.encode()+b'\0';size=(24+len(raw)+7)//8*8;commands.append(struct.pack('<IIIIII',12,size,24,0,0,0)+raw+b'\0'*(size-24-len(raw)))
 body=b''.join(commands);return struct.pack('<IIIIIIII',0xFEEDFACF,0x100000C,0,6,len(commands),len(body),0,0)+body
calls=[]
def guarded(*a,**kw):calls.append('external');raise AssertionError('Source fixtures require authored inputs')
with tempfile.TemporaryDirectory(prefix='native alias return with spaces ',dir=ROOT) as temporary, mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded),mock.patch.object(os,'killpg',side_effect=guarded):
 root=Path(temporary).resolve();prefix=root/'brew';(prefix/'opt').mkdir(parents=True);direct=[];deps=[]
 for name,version in transfer.PACKAGES.items():
  package=prefix/'Cellar'/name/version;(package/'.brew').mkdir(parents=True);(package/'lib').mkdir();(package/'.brew'/(name+'.rb')).write_text('SYNTHETIC formula\n');(package/'INSTALL_RECEIPT.json').write_text(json.dumps({'arch':'arm64','source':{'versions':{'stable':version}}}));(prefix/'opt'/name).symlink_to(Path('../Cellar')/name/version);(package/'lib/dependency.dylib').write_bytes(macho(transfer.SYSTEM_IMPORTS));direct.append(str(prefix/'opt'/name/'lib/dependency.dylib'));deps.append({'full_name':name,'version':version,'revision':0,'pkg_version':version})
 package=prefix/'Cellar/libyaml'/transfer.PACKAGES['libyaml'];lib=package/'lib'
 (lib/'X.dylib').write_bytes(macho(transfer.SYSTEM_IMPORTS)+b'X');(lib/'Y.dylib').write_bytes(macho(transfer.SYSTEM_IMPORTS)+b'Y');alias=lib/'selected.dylib';alias.symlink_to('X.dylib')
 imports=[*transfer.SYSTEM_IMPORTS,*[str(prefix/'opt/libyaml/lib'/name) for name in ('X.dylib','Y.dylib','selected.dylib')]]
 Path(direct[0]).write_bytes(macho(imports));compiler=root/'compiler';(compiler/'bin').mkdir(parents=True);(compiler/'INSTALL_RECEIPT.json').write_text(json.dumps({'runtime_dependencies':deps}))
 admission={'job_identity':{'RUNNER_OS':'macOS','RUNNER_ARCH':'ARM64'},'providers':{'compiler_wrapper':{'path':str(compiler/'bin/crystal-alpha')}},'observed_profile_sha256':'a'*64,'runner':{'image_version':'synthetic-image'}}
 with mock.patch.object(transfer,'DIRECT',direct):
  before=transfer.collect_native(transfer.Budget(time.monotonic()+30),admission,prefix);old=os.readlink(alias);alias.unlink();alias.symlink_to('Y.dylib');after=transfer.collect_native(transfer.Budget(time.monotonic()+30),admission,prefix)
 result={'format':'draft-native-alias-return-sensitivity','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'alias_before':old,'alias_after':os.readlink(alias),'recorded_native_unchanged':before==after,'policy_view_unchanged':transfer.policy_view(before)==transfer.policy_view(after),'observed_library_count':len(before['libraries']),'selected_alias_recorded_as_first_path':any(r['declared_path'].endswith('/selected.dylib') for r in before['libraries']),'external_guard_calls':len(calls),'actual_local_compiler_native_container_browser_SSH_jobs':0,'before':before,'after':after}
(ROOT/'DRAFT_ALIAS_CONVERGENCE.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('before','after')},sort_keys=True))
