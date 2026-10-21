"""Run exact size-only archive controls under the pinned metadata supervisor."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import tarfile

ROOT=Path(__file__).resolve().parent
SUPERVISOR_SHA='f6b709e32790ad89a160910afac03beeffa5f160d7b06af4027ceae9f98da396'
MAX_SOURCE_BYTES=1048576
MAX_PROVIDER_BYTES=67108864
def need(value,message):
    if not value:raise RuntimeError(message)
def identity(path,maximum=MAX_SOURCE_BYTES):
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum,'Bounded physical metadata file required before reading')
    raw=path.read_bytes();after=path.lstat()
    fields=lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
    need(fields(before)==fields(after) and len(raw)==before.st_size,'Exact stable metadata source file required')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def parser_provider():
    path=Path(tarfile.__file__).resolve(strict=True);need(path.suffix=='.py','File-backed actual standard TAR parser source required');row=identity(path);info=path.lstat()
    return {'path':str(path),**row,'physical_identity':[info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns],'python_version':sys.version,'scope':'Fresh same-process source metadata; module source bytes remain separately unretained and actual hosted readback requires independent review'}
def inventory(root):return {p.relative_to(root).as_posix():identity(p) for p in sorted(root.rglob('*')) if p.is_file()}
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def controls(args):
    pins=ROOT/'CAPACITY_PINS.json';need(identity(pins)['sha256']==args.packet_sha256,'Exact externally selected capacity manifest required')
    value=json.loads(pins.read_text());need(value['route_manifest_sha256']==args.route_packet_sha256,'Exact selected route and capacity manifest join required')
    need(set(value['files'])=={'metadata_supervisor.py','run_capacity_controls.py','test_archive_capacity.py','test_provider_admission.py','test_portable_route.py','tarfile.cpython-3.15.0.py.txt'},'Exact complete six-file portable capacity source roster required')
    for name,row in value['files'].items():need(identity(ROOT/name)==row,'Exact capacity source member required')
    source=ROOT.parent/'ordinary_public_route';need(source.resolve(strict=True)==source,'Physical adjacent ordinary route source required')
    route_pins=source/'SOURCE_PINS.json';need(identity(route_pins)['sha256']==args.route_packet_sha256,'Exact corrected route manifest required')
    rows=json.loads(route_pins.read_text())['files'];need(len(rows)==48 and len({row['path'] for row in rows})==48,'Complete original 48-row route manifest required')
    for row in rows:
        path=Path(row['path']);need(not path.is_absolute() and '..' not in path.parts and str(path)==row['path'],'Contained exact route source path required')
        need(identity(source/path)=={key:row[key] for key in ('bytes','sha256')},'Exact corrected route source member required')
    provider=Path(args.python).resolve(strict=True);need(provider==Path(sys.executable).resolve() and identity(provider,MAX_PROVIDER_BYTES)['sha256']==args.python_sha256,'Exact actual metadata Python required')
    helper=ROOT/'metadata_supervisor.py';need(identity(helper)['sha256']==SUPERVISOR_SHA,'Exact metadata supervisor required')
    spec=importlib.util.spec_from_file_location('ordinary_capacity_metadata_supervisor',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    before=inventory(ROOT);route_before=inventory(source);provider_before=identity(provider,MAX_PROVIDER_BYTES);parser_before=parser_provider()
    output=args.output.absolute();need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical capacity output required');output.mkdir()
    runner=module.Runner(output);started=time.monotonic();runner.deadline=started+120
    result={'format':'ordinary-public-route-capacity-controls-v113','passed':False,'route_manifest_sha256':args.route_packet_sha256,'capacity_manifest_sha256':args.packet_sha256,'python':{'path':str(provider),**provider_before},'tar_parser_provider':parser_before,'source_file_allowance_bytes':MAX_SOURCE_BYTES,'provider_file_allowance_bytes':MAX_PROVIDER_BYTES,'command_budget_seconds':{'archive_capacity_each_mode':30,'provider_admission_each_mode':15,'declared_child_total':90,'common_runner_horizon':120},'actual_compiler_native_container_browser_SSH_jobs':0,'results':[],'finalization_errors':[]}
    environment={key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR','LANG','LC_ALL')};environment.update(PYTHONDONTWRITEBYTECODE='1',NO_COLOR='1')
    try:
        for mode,flags in (('ordinary',[]),('optimized',['-O'])):
            stdout,stderr=runner.run('archive-capacity-'+mode,[str(provider),'-I','-S','-B',*flags,str(ROOT/'test_portable_route.py'),'--source-root',str(source)],cwd=ROOT,environment=environment,seconds=30)
            summary=json.loads(stdout.strip().splitlines()[-1]);need({key:summary[key] for key in ('tests_run','errors','failures','skips','actual_guard_calls')}=={'tests_run':68,'errors':0,'failures':0,'skips':0,'actual_guard_calls':0},'Exact successful original and portable sixty-eight-case capacity cohort required')
            result['results'].append({'mode':mode,**summary})
        for mode,flags in (('ordinary',[]),('optimized',['-O'])):
            stdout,stderr=runner.run('provider-admission-'+mode,[str(provider),'-I','-S','-B',*flags,str(ROOT/'test_provider_admission.py')],cwd=ROOT,environment=environment,seconds=15)
            summary=json.loads(stdout.strip().splitlines()[-1]);need(summary=={'tests_run':6,'errors':0,'failures':0,'skips':0,'actual_guard_calls':0},'Exact successful six-case provider admission cohort required')
            result['results'].append({'mode':mode,'kind':'provider-admission',**summary})
        result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            need(before==inventory(ROOT) and route_before==inventory(source) and provider_before==identity(provider,MAX_PROVIDER_BYTES) and parser_before==parser_provider(),'Exact capacity source, route source, and provider return required')
            need(runner.writers_confirmed_retired and all(group['status']=='absent' for group in runner.group_observations),'All original metadata groups must return absent')
            result['source_and_provider_return_exact']=True
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>120:result['passed']=False;result['finalization_errors'].append('Complete capacity metadata deadline exceeded')
        result['commands']=runner.records;result['original_groups']=runner.group_observations;result['writers_confirmed_retired']=runner.writers_confirmed_retired
        write(output/'CAPACITY_CONTROL_RESULT.json',result)
    print(json.dumps({'passed':result['passed'],'writers_confirmed_retired':result['writers_confirmed_retired'],'actual_external_guard_calls':sum(row['actual_guard_calls'] for row in result['results'])},sort_keys=True))
    return 0 if result['passed'] else 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-sha256',required=True);parser.add_argument('--route-packet-sha256',required=True)
    parser.add_argument('--python',type=Path,required=True);parser.add_argument('--python-sha256',required=True);parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(controls(parser.parse_args()))
