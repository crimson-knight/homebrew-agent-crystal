"""Replay the exact copied cleanup CLI with an authored unlink failure."""
import hashlib,json,os
from pathlib import Path
import runpy,stat,subprocess,sys
from unittest import mock
ROOT=Path(__file__).resolve().parent;AUTHOR=ROOT.parent/'grant_dirty_tool_transfer_v100';COPY=ROOT/'draft_cleanup_source';COPY.mkdir()
raw=(AUTHOR/'TRANSFER_SOURCE_PINS.json').read_bytes();manifest=json.loads(raw)
for row in manifest['files']:
 source=AUTHOR/row['path'];value=source.read_bytes()
 if len(value)!=row['bytes'] or hashlib.sha256(value).hexdigest()!=row['sha256']:raise RuntimeError('Draft source changed before snapshot')
 path=COPY/row['path'];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
(COPY/'TRANSFER_SOURCE_PINS.json').write_bytes(raw)
private=ROOT/'grant-proof-transfer-cleanup-case';private.mkdir(mode=0o700);(private/'tools').mkdir();(private/'tools/ameba').write_text('SYNTHETIC unexecuted provider');(private/'TRANSFER_RESULT.json').write_text('{"passed":true}');(private/'PROOF_TOOLS.json').write_text('{"execution_admitted":false}')
original=Path.unlink;calls=[]
def unlink(path,*a,**kw):
 if path==private/'tools/ameba':raise PermissionError('SYNTHETIC cleanup permission refusal')
 return original(path,*a,**kw)
def guarded(*a,**kw):calls.append('external');raise AssertionError('Source fixtures require authored process behavior')
old=sys.argv;sys.argv=[str(COPY/'proof_tool_transfer.py'),'cleanup','--root',str(private),'--transfer-sha256',hashlib.sha256(raw).hexdigest()];code=0
try:
 with mock.patch.object(Path,'unlink',unlink),mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded),mock.patch.object(os,'killpg',side_effect=guarded):
  try:runpy.run_path(str(COPY/'proof_tool_transfer.py'),run_name='__main__')
  except SystemExit as error:code=error.code
finally:sys.argv=old
result={'format':'draft-cleanup-CLI-return-sensitivity','transfer_manifest_sha256':hashlib.sha256(raw).hexdigest(),'helper_sha256':hashlib.sha256((COPY/'proof_tool_transfer.py').read_bytes()).hexdigest(),'CLI_exit_code':code,'retained_cleanup':json.loads((private/'CLEANUP.json').read_text()),'private_payload_preserved':(private/'tools/ameba').exists(),'external_guard_calls':len(calls),'actual_local_compiler_native_container_browser_SSH_jobs':0}
(ROOT/'DRAFT_CLEANUP_CLI.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
