"""Stage a finite positive native-probe roster and retain actual refusals."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
FIXED=('RESULT.json','COMMANDS.json','SDK_ADMISSION.json','NATIVE_BEFORE.json','NATIVE_AFTER.json',
       'SOURCE_GATES.json','SOURCE_RETURN.json','STDLIB_AFTER.json','buffer_shim.o',
       'original.probe','fixed.probe','restored.probe')
COMMANDS=('build-shim',)+tuple(label for arm in ('original','fixed','restored') for label in
    ('format-'+arm,'build-'+arm,arm+'-counts',arm+'-memory'))
RAW=tuple(label+'.'+stream+'.txt' for label in COMMANDS for stream in ('stdout','stderr'))

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def stage(source,output,expected):
    controller=load(ROOT/'run_probe.py','native_probe_public_controller')
    controller.packet(expected)
    rules_path=ROOT/'vendor/public_evidence_rules.py'
    controller.need(controller.digest(rules_path)=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact accepted publication rules required')
    rules=load(rules_path,'native_probe_public_rules')
    source=source.resolve(strict=True)
    controller.need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical public stage required')
    initial=rules.read_regular(source,'RESULT.json')
    result=json.loads(initial)
    controller.need(type(result['complete']) is bool and type(result['writers_confirmed_retired']) is bool,'Exact native result statuses required')
    controller.need(result['full_target_cells_accepted']==0 and result['actual_compiler_memory_savings_accepted'] is False,
                    'Native mechanism and full compiler/target acceptance stay separate')
    selected=list(FIXED+RAW) if result['writers_confirmed_retired'] else ['RESULT.json']
    if result['writers_confirmed_retired'] and (source/'SOURCE_GATES.json').exists():
        gates=json.loads(rules.read_regular(source,'SOURCE_GATES.json'))
        selected+=['source_feedback/'+row['path'] for row in gates['raw_evidence']]
    payload={};missing=[];total=0
    for name in selected:
        try: raw=rules.read_regular(source,name)
        except FileNotFoundError:
            controller.need(result['complete'] is False,'Every positive successful native artifact member required')
            missing.append(name);continue
        rules.inspect_public_bytes(name,raw)
        payload[name]=raw
    if result['complete']:
        controller.need(result['errors']==[] and result['private_removed'] is True and result['elapsed_seconds']<=900,
                        'Complete deadline/return status required')
        records=json.loads(payload['COMMANDS.json'])
        controller.need([r['label'] for r in records]==list(COMMANDS) and result['command_count']==13,'Exact13-command successful roster required')
        for record in records:
            seconds=180 if record['label'].startswith('build-') and record['label']!='build-shim' else 15 if record['label'].startswith('format-') else 30
            controller.validate_command(record,record['label'],seconds,source)
        for arm in controller.ARMS:
            controller.need(controller.macho(source/(arm+'.probe'))==result['arms'][arm]['binary'],'Retained binary identity differs')
            for mode in controller.MODES:
                value=json.loads(payload[arm+'-'+mode+'.stdout.txt'])
                expected_result=controller.validate_result(value,arm,mode,json.loads(payload['NATIVE_BEFORE.json'])['policy']['llvm_library'])
                controller.need(expected_result==result['arms'][arm]['modes'][mode],'Exact physical result/controller join required')
        controller.need(controller.stable(source/'buffer_shim.o')[0]==result['shim_object'],'Retained shim object differs')
    manifest=controller.read(ROOT/'SOURCE_PINS.json')
    for name in ['SOURCE_PINS.json']+[r['path'] for r in manifest['files']]:
        raw=rules.read_regular(ROOT,name);rules.inspect_public_bytes('source/'+name,raw)
        payload['source/'+name]=raw
    for name,raw in payload.items():
        total+=len(raw);controller.need(total<=64*2**20,'Finite64-MiB public artifact bound required')
    output.mkdir(mode=0o700)
    rows=[]
    for name,raw in payload.items():
        path=output/rules.public_path(name);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(0o755 if name.endswith('.probe') else 0o644)
        controller.need(rules.read_regular(output,name)==raw,'Exact physical staged bytes required')
        rows.append({'path':name,'bytes':len(raw),'sha256':controller.digest(path),'mode':path.stat().st_mode&0o777})
    controller.need(rules.read_regular(source,'RESULT.json')==initial,'Final native result changed during staging')
    receipt={'format':'atlas-native-buffer-public-stage-v1','native_probe_complete':result['complete'],
             'unresolved_original_writer_scope':not result['writers_confirmed_retired'],'files':rows,'missing':missing,
             'native_source_policy':'Exact source packet and positive owned artifact members; provider files remain fingerprint evidence',
             'full_target_cells_accepted':0,'actual_compiler_memory_savings_accepted':False}
    controller.write(output/'PUBLIC_STAGE.json',receipt)
    rules.inspect_public_bytes('PUBLIC_STAGE.json',(output/'PUBLIC_STAGE.json').read_bytes())
    controller.need({p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}==set(payload)|{'PUBLIC_STAGE.json'},'Exact staged regular path roster required')
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--packet-sha256',required=True)
    args=parser.parse_args();stage(args.source,args.output,args.packet_sha256)
