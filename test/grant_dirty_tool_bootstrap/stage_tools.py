"""Copy a finite public proof-tool artifact after exact preparation-source checks."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parent
LABELS=('curl-version','git-version','download-cli','download-ameba','archive-git-probe','build-ameba')
FIXED=('BOOTSTRAP_RESULT.json','DRAFT_TOOL_REGISTRY.json','SDK_ADMISSION.json','COMMANDS.json',
    'PROVIDERS_BEFORE.json','PROVIDERS_AFTER.json','STDLIB_BEFORE.json','STDLIB_AFTER.json',
    'SOURCE_BEFORE.json','SOURCE_AFTER.json','inputs/cli.tar.gz','inputs/ameba.tar.gz',
    'tools/ameba','tools/amber-lsp','tools/crystal.yml') + tuple(label+'.'+stream+'.txt' for label in LABELS for stream in ('stdout','stderr'))

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(value,message):
    if not value:raise ValueError(message)

def stage(source,output,packet_sha256):
    source,output=source.resolve(),output.absolute()
    manifest=ROOT/'BOOTSTRAP_SOURCE_PINS.json'
    need(sha(manifest.read_bytes())==packet_sha256,'Exact externally pinned bootstrap source packet required')
    for row in json.loads(manifest.read_bytes())['files']:
        path=PurePosixPath(row['path'])
        need(str(path)==row['path'] and not path.is_absolute() and '..' not in path.parts,'Exact contained packet member required')
        current=ROOT/path
        need(not current.is_symlink() and current.is_file() and len(current.read_bytes())==row['bytes'] and sha(current.read_bytes())==row['sha256'],'Packet source differs before artifact staging')
    helper=ROOT/'vendor/public_evidence_rules.py'
    need(sha(helper.read_bytes())=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact public evidence helper required')
    spec=importlib.util.spec_from_file_location('proof_tools_public_evidence_rules',helper)
    rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
    need(source.is_dir() and output.parent.resolve(strict=True)==output.parent and not output.exists() and not output.is_symlink(),'Fresh physical public stage required')
    result_raw=rules.read_regular(source,'BOOTSTRAP_RESULT.json')
    result=json.loads(result_raw)
    need(result['execution_admitted'] is False,'Tool execution retains its independent admission')
    need(type(result['preparation_complete']) is bool and type(result['writers_confirmed_retired']) is bool,'Exact result status booleans required')
    selected=FIXED if result['writers_confirmed_retired'] is True else ('BOOTSTRAP_RESULT.json','DRAFT_TOOL_REGISTRY.json')
    need(result['writers_confirmed_retired'] is True or result['preparation_complete'] is False,'Unverified writers cannot produce complete preparation')
    rows=[];missing=[];payload={};total=0
    for name in selected:
        try:raw=rules.read_regular(source,name)
        except FileNotFoundError:
            need(result['preparation_complete'] is False,'Complete successful tool preparation requires every positive artifact member')
            missing.append(name);continue
        expected_archive=None
        if name=='inputs/cli.tar.gz':expected_archive='0a9fb1227af6574c689eae3d2f4d83281cc3edfab3d40799079d470bb2c7ce61'
        if name=='inputs/ameba.tar.gz':expected_archive='a0e91d582e0617b15c1bd3448c2d0db60c86454aa4d19887fcb6ee08d4ddf259'
        rules.inspect_public_bytes(name,raw,expected_archive)
        payload[name]=raw
    registry=json.loads(payload['DRAFT_TOOL_REGISTRY.json'])
    need(registry['execution_admitted'] is False and registry['preparation_complete'] is result['preparation_complete'],'Exact unadmitted registry/result join required')
    if result['preparation_complete'] is True:
        need(result['compiler_color']=='GREEN' and result['private_working_directory_removed'] is True and result['finalization_errors']==[],'GREEN complete returned source/provider/working-directory evidence required')
        for name,relative in [('ameba','tools/ameba'),('amber_lsp','tools/amber-lsp'),('api_card','tools/crystal.yml')]:
            row=registry['providers'][name]
            need(row['execution_admitted'] is False and row['bytes']==len(payload[relative]) and row['sha256']==sha(payload[relative]) and
                 row['mode']==((source/relative).stat().st_mode & 0o777),'Exact returned tool hash/mode/registry join required')
        commands=json.loads(payload['COMMANDS.json'])
        need(type(result['command_count']) is int and result['command_count']==len(LABELS) and
             [r['label'] for r in commands]==list(LABELS),'Exact six-command public return roster required')
        for command in commands:
            expected=128 if command['label']=='archive-git-probe' else 0
            terminal=command['terminal_group_observation']
            need(type(command['exit_code']) is int and command['exit_code']==expected and
                 type(command['expected_exit']) is int and command['expected_exit']==expected and command['refusal'] is None and
                 command['writers_confirmed_retired'] is True and terminal['status']=='absent','Successful expected command and original-group return required')
            need(all(type(v) is int and v>0 for v in (command['pid'],command['original_group'],terminal['group'])) and
                 command['pid']==command['original_group']==terminal['group'],'Positive exact command/group identities required')
            maximum=600 if command['label']=='build-ameba' else 45 if command['label'].startswith('download-') else 15
            need(type(command['maximum_seconds']) in (int,float) and command['maximum_seconds']==maximum and
                 type(command['elapsed_seconds']) in (int,float) and math.isfinite(command['elapsed_seconds']) and
                 0<=command['elapsed_seconds']<=maximum,'Exact finite original command maximum/elapsed required')
            for stream in ('stdout','stderr'):
                need(sha(payload[command['label']+'.'+stream+'.txt'])==command[stream+'_sha256'],'Exact command raw-stream hash join required')
    for name in ('BOOTSTRAP_SOURCE_PINS.json','BOOTSTRAP_INPUT_PINS.json','bootstrap_tools.py','stage_tools.py','test_bootstrap.py',
                 'vendor/public_evidence_rules.py',
                 'inputs/CLI_ARCHIVE_IDENTITY.json','inputs/AMEBA_ARCHIVE_IDENTITY.json','inputs/AMEBA_COMPLETE_TREE_READBACK.json'):
        raw=rules.read_regular(ROOT,name)
        destination='source/'+name
        rules.inspect_public_bytes(destination,raw)
        payload[destination]=raw
    for name,raw in payload.items():
        total+=len(raw);need(total<=64*2**20,'Finite64-MiB positive public artifact bound required')
        rows.append({'path':name,'bytes':len(raw),'sha256':sha(raw)})
    output.mkdir()
    for name,raw in payload.items():
        destination=output/rules.public_path(name);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
        destination.chmod(0o755 if name in ('tools/ameba','tools/amber-lsp') else 0o644)
    need(rules.read_regular(source,'BOOTSTRAP_RESULT.json')==result_raw,'Final preparation result changed while staging')
    receipt={'format':'grant-proof-tool-artifact-v1','preparation_complete':result['preparation_complete'],
        'execution_admitted':False,'files':rows,'missing':missing,'actual_tool_executions':0,
        'unqualified_writer_scope':result['writers_confirmed_retired'] is not True}
    (output/'PUBLIC_STAGE.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--packet-sha256',required=True)
    args=parser.parse_args();stage(args.source,args.output,args.packet_sha256)
