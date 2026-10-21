"""Stage one exact finite frontend-evidence roster after complete return replay."""
import argparse,importlib.util,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from source_gate import BASE,admit,digest,need,read,stable,write
from vendor.command_contract import terminal
from vendor import public_evidence_rules as rules
from products import frontend_boundary as boundary
from products.parse_semantic_stats import parse
from products.parse_stage_stats import associate_observed_intervals
from observe_compiler import parse_ps
PROFILES=boundary.PROFILES

def review(source,expected,admitted):
    result=read(source/'RESULT.json');need(result.get('source_packet_sha256')==expected,'Exact source/result packet join required')
    need(result['passed'] is True and result['diagnostic_complete'] is True and result['compiler_color']=='GREEN' and result['finalization_errors']==[] and result['private_removed'] is True and result['writers_confirmed_retired'] is True and result['source_provider_return_accepted'] is True,'Complete positive frontend/source/provider/group/cache return required')
    need(type(result['maximum_seconds']) is int and result['maximum_seconds']==900 and type(result['return_seconds']) is int and result['return_seconds']==30 and type(result['elapsed_seconds']) in (int,float) and 0<=result['elapsed_seconds']<=900,'Original finite900-second complete horizon required')
    need(type(result['target_cells_accepted']) is int and result['target_cells_accepted']==0 and result['whole_build_provider_qualified'] is False,'Frontend diagnostic/full-target scopes differ')
    need(result['admitted_same_job']==admitted==read(source/'SDK_ADMISSION.json'),'Actual same-job SDK/source/profile join required')
    commands=read(source/'COMMANDS.json');need(commands==result['commands'] and type(result['command_count']) is int and result['command_count']==12 and [r['label'] for r in commands]==[label for p in PROFILES for label in (p+'-format',p+'-compile')],'Exact twelve original route commands required')
    need([r['profile'] for r in result['samples']]==list(PROFILES) and len(result['groups'])==12,'Complete ordered six-route result/group roster required')
    before=read(source/'SOURCE_BEFORE.json');after=read(source/'SOURCE_AFTER.json');need(before==after and before['sha256']==boundary.SOURCE and len(before['rows'])==1554,'Exact1554-row full original source return required')
    boundary.source_rows_equal(read(ROOT/'products/EXPECTED_SOURCE.json')['inputs'],before['rows'])
    selected=['RESULT.json','COMMANDS.json','SDK_ADMISSION.json','SOURCE_BEFORE.json','SOURCE_AFTER.json']
    backend=admitted['providers']['compiler_backend']['path']
    for i,profile in enumerate(PROFILES):
        value=read(source/(profile+'-RESULT.json'));need(value==result['samples'][i],'Exact retained route/result join required')
        need(value['source_sha256']==digest(ROOT/'products'/(profile+'.cr.txt')) and value['fixture_manifest_sha256']==digest(ROOT/'products'/(profile+'.json')),'Exact original route source/roster identities required')
        source_argument=Path(value['source_argument']);need(source_argument==source/'private/projection/grant/performance/results/frontend-diagnostic'/profile/'fixture.cr','Exact runtime-owned route source argument required')
        need(result['working_fixture_return'][profile]=={'fixture.cr':digest(ROOT/'products'/(profile+'.cr.txt')),'fixture.json':digest(ROOT/'products'/(profile+'.json'))},'Exact completed working fixture/manifest return required')
        argv=boundary.compiler_argv(backend,source_argument,source_argument.parent/'absent-output')
        format_record,compile_record=commands[2*i:2*i+2]
        need(compile_record['arguments']==argv==value['compiler_arguments'] and value['compiler_record']==compile_record,'Exact original compiler argv/source-record joins required')
        need(format_record['arguments']==[backend,'tool','format','--check','--no-color',str(source_argument)],'Exact actual formatter argv required')
        for record,seconds in ((format_record,10),(compile_record,120)):
            terminal(record,seconds,output=source,observation=result['groups'][commands.index(record)])
            selected += [record['label']+'.'+stream+'.txt' for stream in ('stdout','stderr')]
        need(not stable(source/(profile+'-format.stdout.txt')) and not stable(source/(profile+'-format.stderr.txt')) and not stable(source/(profile+'-compile.stderr.txt')),'Actual formatter/compiler GREEN requires exact empty diagnostic streams')
        stats=parse(stable(source/(profile+'-compile.stdout.txt')));need(stats==value['stats'],'Exact physical eleven-stage stats replay required')
        for phase in ('BEFORE','AFTER'):
            name=profile+'-STDLIB_'+phase+'.json';report=read(source/name)
            need(report['passed'] is True and report['delta']==dict(missing=[],extra=[],changed=[]) and report['expected_inventory']['rows']==report['actual_inventory']['rows'],'Complete exact prepared stdlib evidence required');selected.append(name)
        need(read(source/(profile+'-STDLIB_BEFORE.json'))==read(source/(profile+'-STDLIB_AFTER.json')),'Prepared stdlib report bytes/identity changed')
        observer=value['direct_compiler_observation'];need(observer==result['observer_results'][i] and observer['writers_confirmed_retired'] is True and observer['thread_joined'] is True and observer['overhead_qualified'] is False,'Complete separate direct observer return required')
        rows=observer['raw_observations'];metadata=observer['metadata_commands'];groups=observer['metadata_groups']
        need(1<=len(metadata)<=128 and len(metadata)==len(groups) and len(rows)==len(metadata)+1,'Finite complete direct observer/raw roster required')
        need(read(source/(profile+'-observer/COMMANDS.json'))==metadata,'Exact physical observer command journal required');selected.append(profile+'-observer/COMMANDS.json')
        births=set()
        for j,record in enumerate(metadata):
            need(record['label']=='sample-%03d'%j and record['arguments']==['/bin/ps','-p',str(compile_record['pid']),'-o','pid=,ppid=,pgid=,lstart=,rss=,comm='] and record['expected_exit']==0 and type(record['exit_code']) is int and record['exit_code'] in (0,1),'Exact finite direct-PID observation request/status required')
            terminal(dict(record,expected_exit=record['exit_code']),2,expected=record['exit_code'],output=source/(profile+'-observer'),observation=groups[j])
            raw=stable(source/(profile+'-observer')/(record['label']+'.stdout.txt')).decode();need(not stable(source/(profile+'-observer')/(record['label']+'.stderr.txt')),'Metadata stderr requires review')
            row=rows[j]
            if record['exit_code']==0:
                physical=parse_ps(raw,compile_record['pid'],result['controller_pid']);births.add(physical['birth']);need(all(physical[k]==row[k] for k in ('pid','birth','direct_rss_bytes','is_live','command')),'Actual direct PID raw/observation join required')
            else:need(not raw.strip() and row['is_live'] is False and row['direct_rss_bytes']==0,'Absent direct-PID observation differs')
            selected += [profile+'-observer/'+record['label']+'.'+stream+'.txt' for stream in ('stdout','stderr')]
        need(len(births)<=1 and type(observer['live_samples']) is int and observer['live_samples']==sum(r['is_live'] for r in rows[:-1]),'One actual sampled compiler lifetime/coverage required')
        need(rows[-1]['terminal_after_original_group_absence'] is True and rows[-1]['stdout_bytes']==len(stable(source/(profile+'-compile.stdout.txt'))),'Actual terminal stdout/absence join required')
        if births:need(associate_observed_intervals(stats,rows)==value['phase_intervals'],'Exact retained phase/sample association required')
        else:need(value['phase_intervals']['passed'] is False,'Absent sampled-RSS coverage stays explicit')
        selected.append(profile+'-RESULT.json')
    return result,selected

def stage(source,output,expected,admitted_reader=None):
    admit(expected)
    initial=stable(source/'RESULT.json');result=json.loads(initial)
    if result.get('passed') is True:
        if admitted_reader is None:
            from run_frontend import admission
            from types import SimpleNamespace
            settings=SimpleNamespace(**result['execution_inputs']);settings.driver=Path(settings.driver);settings.sdk_evidence=Path(settings.sdk_evidence)
            settings.repository=Path(settings.repository)
            _,context=admission(settings);admitted=context['admitted'];context['check']()
            need(result['metadata_provider']==context['metadata_provider'],'Exact current OS observation provider/version/hash return required')
        else:admitted=admitted_reader()
        result,selected=review(source,expected,admitted)
    else:
        selected=['RESULT.json']
        if result.get('writers_confirmed_retired') is True and (source/'COMMANDS.json').exists():
            commands=read(source/'COMMANDS.json');need(commands==result.get('commands') and len(commands)<=12,'Exact bounded failed original command roster required')
            selected.append('COMMANDS.json')
            for row in commands:
                need(row['label'] in [label for p in PROFILES for label in (p+'-format',p+'-compile')] and row['writers_confirmed_retired'] is True and row['terminal_group_observation']['status']=='absent','Only retired original failure streams enter publication')
                for stream in ('stdout','stderr'):
                    name=row['label']+'.'+stream+'.txt';need(digest(source/name)==row[stream+'_sha256'],'Exact retired failed raw hash required');selected.append(name)
            for attempt in result.get('observer_attempts',[]):
                need(attempt['profile'] in PROFILES and attempt['writers_confirmed_retired'] is True and len(attempt['metadata_commands'])<=128,'Finite retired observer failure roster required')
                folder=attempt['profile']+'-observer'
                if attempt['metadata_commands']:
                    need(read(source/folder/'COMMANDS.json')==attempt['metadata_commands'],'Exact failed observer journal required');selected.append(folder+'/COMMANDS.json')
                for index,row in enumerate(attempt['metadata_commands']):
                    need(row['label']=='sample-%03d'%index and row['writers_confirmed_retired'] is True and row['terminal_group_observation']['status']=='absent','Retired failed metadata streams required')
                    for stream in ('stdout','stderr'):
                        name=folder+'/'+row['label']+'.'+stream+'.txt';need(digest(source/name)==row[stream+'_sha256'],'Exact failed metadata raw hash required');selected.append(name)
            for name in ['SDK_ADMISSION.json','SOURCE_BEFORE.json','SOURCE_AFTER.json']:
                if (source/name).exists():selected.append(name)
    payload={}
    for name in selected:payload[name]=rules.read_regular(source,name);rules.inspect_public_bytes(name,payload[name])
    pins=read(ROOT/'SOURCE_PINS.json')
    for name in ['SOURCE_PINS.json']+[r['path'] for r in pins['files']]:
        body=rules.read_regular(ROOT,name);rules.inspect_public_bytes('source/'+name,body);payload['source/'+name]=body
    need(sum(map(len,payload.values()))<=64*2**20 and len(payload)<=2000,'Finite2000-member/64-MiB positive publication roster required')
    need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical public output required');output.mkdir(mode=0o700)
    rows=[]
    for name,raw in payload.items():
        path=output/rules.public_path(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644);rows.append(dict(path=name,bytes=len(raw),sha256=digest(path)))
    need(stable(source/'RESULT.json')==initial,'Result changed during staging')
    for name,raw in payload.items():need(rules.read_regular(ROOT if name.startswith('source/') else source,name[7:] if name.startswith('source/') else name)==raw,'Final selected source/evidence changed')
    admit(expected)
    receipt=dict(format='atlas-grant-frontend-public-stage-v1',diagnostic_complete=result.get('diagnostic_complete') is True,files=rows,target_cells_accepted=0,whole_build_provider_qualified=False)
    write(output/'PUBLIC_STAGE.json',receipt);return receipt
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet-sha256',required=True);a=p.parse_args();stage(a.source,a.output,a.packet_sha256)
