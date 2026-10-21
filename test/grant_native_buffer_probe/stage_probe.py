"""Stage a finite positive native-probe roster and retain actual refusals."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import stat

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

def admit_packet(expected):
    """Verify the full supplied roster before importing the controller."""
    def physical(path,maximum):
        before=path.lstat()
        if not (stat.S_ISREG(before.st_mode) and path.resolve(strict=True)==path and before.st_size<=maximum):
            raise RuntimeError('Bounded physical stage source required')
        with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
            opened=os.fstat(stream.fileno());raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
        fields=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if not (fields(before)==fields(opened)==fields(after)==fields(path.lstat()) and len(raw)==before.st_size):
            raise RuntimeError('Stable stage source required')
        return raw,stat.S_IMODE(before.st_mode)
    raw,_=physical(ROOT/'SOURCE_PINS.json',2**20)
    if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('Exact externally pinned stage source manifest required')
    rows=json.loads(raw)['files']
    if not (1<=len(rows)<=64 and len({row['path'] for row in rows})==len(rows)):
        raise RuntimeError('Finite unique stage source roster required')
    for row in rows:
        name=PurePosixPath(row['path'])
        if str(name)!=row['path'] or name.is_absolute() or '..' in name.parts:raise RuntimeError('Contained stage source required')
        body,mode=physical(ROOT/name,256*2**20)
        if not (len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'] and mode==row['mode']):
            raise RuntimeError('Exact complete stage source required: '+row['path'])

def stage(source,output,expected):
    admit_packet(expected)
    controller=load(ROOT/'run_probe.py','native_probe_public_controller')
    protected_source=controller.packet(expected)
    rules_path=ROOT/'vendor/public_evidence_rules.py'
    controller.need(controller.digest(rules_path)=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact accepted publication rules required')
    rules=load(rules_path,'native_probe_public_rules')
    source=source.resolve(strict=True)
    controller.need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical public stage required')
    initial=rules.read_regular(source,'RESULT.json')
    result=json.loads(initial)
    controller.need(type(result['complete']) is bool and type(result['writers_confirmed_retired']) is bool,'Exact native result statuses required')
    controller.need(type(result['full_target_cells_accepted']) is int and result['full_target_cells_accepted']==0 and result['actual_compiler_memory_savings_accepted'] is False,
                    'Native mechanism and full compiler/target acceptance stay separate')
    selected=list(FIXED+RAW)+['NATIVE_POLICY.json'] if result['writers_confirmed_retired'] else ['RESULT.json']
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
        controller.need(result['errors']==[] and result['private_removed'] is True and
                        type(result['elapsed_seconds']) in (int,float) and controller.math.isfinite(result['elapsed_seconds']) and
                        0<=result['elapsed_seconds']<=900 and type(result['maximum_seconds']) is int and
                        result['maximum_seconds']==900 and type(result['return_reserve_seconds']) is int and
                        result['return_reserve_seconds']==60,
                        'Complete deadline/return status required')
        controller.need(result['source_packet_sha256']==expected,'Exact controller/source packet join required')
        names=('SDK_ADMISSION.json','NATIVE_POLICY.json','NATIVE_BEFORE.json','NATIVE_AFTER.json',
               'SOURCE_GATES.json','SOURCE_RETURN.json','STDLIB_AFTER.json')
        controller.need(set(result['return_evidence'])==set(names),'Complete positive identity return roster required')
        for name in names:
            observed=controller.stable(source/name,controller.MAX_OUTPUT)[0]
            controller.need(all(observed[key]==result['return_evidence'][name][key] for key in ('bytes','sha256','mode')),
                            'Exact positive identity return bytes/mode required: '+name)
        admitted=json.loads(payload['SDK_ADMISSION.json'])
        controller.need(admitted['job_identity']==result['job_identity'] and
                        admitted['observed_profile_sha256']==result['compiler_profile_sha256'],
                        'Complete same-job SDK/result identity join required')
        policy,observed_native,observed_aliases=controller.native_policy(source/'NATIVE_POLICY.json',result['native_policy_sha256'],admitted)
        before=json.loads(payload['NATIVE_BEFORE.json'])
        after=json.loads(payload['NATIVE_AFTER.json'])
        controller.need(before==dict(policy=policy,files=observed_native,aliases=observed_aliases) and
                        after==dict(files=observed_native,aliases=observed_aliases),
                        'Complete original/current/final native policy/input/alias join required')
        controller.source_gates(source/'SOURCE_GATES.json',result['source_gates_sha256'],policy,
                                result['job_identity'],raw_root=source/'source_feedback')
        returned=json.loads(payload['SOURCE_RETURN.json'])
        expected_working={arm:{'main.cr':controller.digest(ROOT/'buffer_probe.cr.txt'),
            'memory_buffer.cr':controller.digest(ROOT/('inputs/memory_buffer.fixed.cr.txt' if arm=='fixed' else 'inputs/memory_buffer.original.cr.txt'))}
            for arm in controller.ARMS}
        controller.need(returned['source_inputs_restored_exact'] is True and returned['working_files']==expected_working and
                        returned['protected_source_provider_sha256']==result['protected_inputs_before_sha256'],
                        'Complete original multi-file source/provider restoration required')
        controller.need(all(result['protected_inputs_before_sha256'].get(str(path))==sha for path,sha in protected_source.items()),
                        'Complete externally pinned controller/source protection roster required')
        for name,sha in result['protected_inputs_before_sha256'].items():
            controller.need(controller.digest(Path(name))==sha,'Exact live protected source/provider return required')
        controller.need(json.loads(payload['STDLIB_AFTER.json'])==admitted['stdlib'],
                        'Exact admitted/final full installed standard-library join required')
        records=json.loads(payload['COMMANDS.json'])
        controller.need([r['label'] for r in records]==list(COMMANDS) and type(result['command_count']) is int and
                        result['command_count']==13 and len(result['original_group_observations'])==13,
                        'Exact13-command successful roster required')
        for record,group in zip(records,result['original_group_observations']):
            controller.need(record['terminal_group_observation']==group,'Exact original command/final-group roster join required')
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
    for name,raw in payload.items():
        original=ROOT/name[7:] if name.startswith('source/') else source/name
        controller.need(rules.read_regular(original.parent,original.name)==raw,'Final staged source/evidence bytes changed: '+name)
    controller.packet(expected)
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
