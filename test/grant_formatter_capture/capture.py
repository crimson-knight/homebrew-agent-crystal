"""Capture one exact original formatter STDIN/STDOUT under fresh same-job SDK admission."""
import argparse,hashlib,importlib.util,json,math,os,platform,shutil,stat,sys,time
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parent
BODY_SECONDS=20;PHASE_SECONDS=120;RETURN_SECONDS=60;STREAM_BYTES=131072
FIXTURE_SHA='2840c874a1fc24e82af25af695310a5de1a7006ef4bf998103374bdb9294a01f'
def need(v,m):
    if not v:raise RuntimeError(m)
def clock(end):need(type(end) in (int,float) and math.isfinite(end) and time.monotonic()<=end,'Complete formatter phase deadline required')
def canonical(v):return (json.dumps(v,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
OWNED_ROOTS={};OWNED_FILES={}
def own(root):
    need(root.resolve(strict=True)==root and root.is_dir(),'Physical owned formatter output required');value=identity(root)[:3]
    if root in OWNED_ROOTS:need(OWNED_ROOTS[root]==value,'Original owned formatter output root required')
    else:OWNED_ROOTS[root]=value
def write(p,v):
    p=Path(p)
    for root,value in OWNED_ROOTS.items():
        if p.is_relative_to(root):need(identity(root)[:3]==value and p.parent.resolve(strict=True)==p.parent,'Original physical output ownership required before writing')
    if p in OWNED_FILES:need(identity(p)[:3]==OWNED_FILES[p],'Original owned formatter output file required')
    else:need(not p.exists() and not p.is_symlink(),'Fresh ordinary formatter output file required')
    raw=canonical(v);need(len(raw)<=4*2**20,'Finite formatter metadata receipt before writing required')
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_TRUNC if p in OWNED_FILES else os.O_EXCL),0o644),'wb') as stream:stream.write(raw);stream.flush();value=os.fstat(stream.fileno())
    OWNED_FILES[p]=[value.st_dev,value.st_ino,value.st_mode];need(identity(p)[:3]==OWNED_FILES[p] and p.stat().st_size==len(raw),'Exact owned formatter receipt return required')
def identity(p):
    s=Path(p).lstat();return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def physical(p,end,maximum=512*2**20):
    p=Path(p);clock(end);before=identity(p);need(stat.S_ISREG(before[2]) and 0<=before[3]<=maximum,'Finite physical formatter source/provider before reading required');h=hashlib.sha256();size=0
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        need([getattr(os.fstat(f.fileno()),k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')]==before,'Exact opened formatter identity required')
        while True:
            clock(end);raw=f.read(min(2**20,maximum+1-size))
            if not raw:break
            size+=len(raw);need(size<=maximum,'Complete formatter byte ceiling required');h.update(raw)
        need([getattr(os.fstat(f.fileno()),k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')]==before,'Exact opened formatter return required')
    clock(end);need(identity(p)==before and size==before[3],'Complete formatter physical return required');return dict(path=str(p),bytes=size,sha256=h.hexdigest(),physical_identity=before)
def load(p,h,name):
    need(hashlib.sha256(p.read_bytes()).hexdigest()==h,'Exact imported source pin required');spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);need(hashlib.sha256(p.read_bytes()).hexdigest()==h,'Imported source return required');return m
def protect(expected,end):
    p=ROOT/'SOURCE_PINS.json';raw=p.read_bytes();need(hashlib.sha256(raw).hexdigest()==expected,'External formatter packet pin required');rows=json.loads(raw)['files'];need(0<len(rows)<=32 and len({r['path'] for r in rows})==len(rows),'Finite complete formatter source roster required');result={p:physical(p,end,2**20)}
    for r in rows:
        q=PurePosixPath(r['path']);need(str(q)==r['path'] and not q.is_absolute() and '..' not in q.parts,'Contained formatter source required');p=ROOT/q;v=physical(p,end,16*2**20);need(v['bytes']==r['bytes'] and v['sha256']==r['sha256'] and stat.S_IMODE(p.stat().st_mode)==r['mode'],'Exact formatter source member required');result[p]=v
    return result
def admit(args,end):
    need(platform.system()=='Darwin' and platform.machine()=='arm64' and os.environ.get('GITHUB_ACTIONS')=='true','Actual same-job hosted Mac ARM64 formatter admission required')
    source=protect(args.packet_sha256,end);authority=json.loads((ROOT/'inputs/AUTHORITY.json').read_bytes());repo=args.repository.resolve(strict=True);sources={}
    for name,h in {**authority['sources'],**authority['inherited_workflow_fixtures']}.items():
        p=repo/name;v=physical(p,end,16*2**20);need(v['sha256']==h,'Exact inherited SDK/census source required');sources[p]=v
    model=load(repo/'test/grant_compiler_census_api/run_census.py',authority['sources']['test/grant_compiler_census_api/run_census.py'],'formatter_census_source_authority');model.manifest(repo/'test/grant_compiler_census_api',authority['census_manifest'])
    policy=load(repo/'test/grant_assignment_cost/same_job_policy.py',authority['sources']['test/grant_assignment_cost/same_job_policy.py'],'formatter_original_same_job_policy');protected=policy.protect_packet(authority['sources']['test/grant_assignment_cost/SOURCE_PINS.json']);driver=load(repo/'test/sdk_install_qualification.py',authority['sources']['test/sdk_install_qualification.py'],'formatter_original_command_supervisor');admitted=policy.metadata(args.sdk_evidence,os.environ);roster=policy.roster(args.sdk_evidence)
    for p,h in protected.items():
        v=physical(p,end,16*2**20);need(v['sha256']==h,'Exact protected SDK source required');sources[p]=v
    providers={k:physical(Path(v['path']).resolve(strict=True),end) for k,v in admitted['providers'].items()}
    need(all(v['sha256']==admitted['providers'][k]['sha256'] and v['bytes']==admitted['providers'][k]['bytes'] for k,v in providers.items()),'Exact freshly admitted provider bytes required')
    prefix=Path(admitted['providers']['compiler_wrapper']['path']).parents[1];stdlib=prefix/'share/agent-crystal/src';need(driver.tree_identity(stdlib)==admitted['stdlib'],'Complete fresh installed stdlib required')
    def check(deadline):
        clock(deadline);need(policy.metadata(args.sdk_evidence,os.environ)==admitted and policy.roster(args.sdk_evidence)==roster,'Fresh complete same-job SDK/profile/nonce return required');need(driver.tree_identity(stdlib)==admitted['stdlib'],'Complete installed stdlib return required')
        model.manifest(repo/'test/grant_compiler_census_api',authority['census_manifest'])
        for p,v in {**source,**sources}.items():need(physical(p,deadline,16*2**20)==v,'Complete inherited/current source physical return required')
        for k,v in providers.items():need(physical(v['path'],deadline)==v,'Complete formatter provider physical return required')
        clock(deadline)
    return dict(driver=driver,admitted=admitted,SDK_roster=roster,providers=providers,stdlib=str(stdlib),check=check,source=source)
def execute(args,context,started):
    end=started+PHASE_SECONDS;work=end-RETURN_SECONDS;output=args.output;own(output);runner=context['driver'].Runner(output);runner.deadline=work
    source=ROOT/'inputs/products/new_broad_hash.cr.txt';original=physical(source,work,9781);need(original['bytes']==9781 and original['sha256']==FIXTURE_SHA,'Exact original broad-hash source required');backend=context['providers']['compiler_backend'];private=output/'private';private.mkdir(mode=0o700);(private/'home').mkdir();(private/'cache').mkdir();root_id=identity(output)[:3]
    env={k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','LANG','LC_ALL')};env.update(HOME=str(private/'home'),CRYSTAL_CACHE_DIR=str(private/'cache'),CRYSTAL_PATH=context['stdlib'],CRYSTAL_WORKERS='1',NO_COLOR='1',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
    config=dict(backend=backend,source=original,argv=[backend['path'],'tool','format','--no-color','-'],environment=env,stream_bytes=STREAM_BYTES,record=str(output/'FORMATTER_EXEC.json'),body_deadline=work,output_identity=root_id,profile_sha256=context['admitted']['observed_profile_sha256']);write(private/'CONFIG.json',config);write(output/'FORMATTER_PLAN.json',config);config_hash=hashlib.sha256((private/'CONFIG.json').read_bytes()).hexdigest()
    result=dict(format='atlas-hosted-original-formatter-result-v1',passed=False,maximum_seconds=PHASE_SECONDS,return_seconds=RETURN_SECONDS,body_seconds=BODY_SECONDS,job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'],compiler_backend_sha256=backend['sha256'],source_manifest_sha256=args.packet_sha256,original_source=original,logical_argv=config['argv'],actual_formatter_commands=0,actual_target_cells_accepted=0,whole_build_memory_qualified=False,full_native_provider_acceptance=False,finalization_errors=[],source_provider_return_accepted=False,private_removed=False)
    write(output/'SDK_BEFORE.json',dict(admitted=context['admitted'],roster=context['SDK_roster']));write(output/'RESULT.json',result)
    try:
        need(work-time.monotonic()>=BODY_SECONDS,'Full original20-second formatter body and60-second return capacity required')
        planned=[sys.executable,'-I','-S','-B',ROOT/'formatter_exec.py','--config',private/'CONFIG.json','--config-sha256',config_hash]
        runner.run('formatter',planned,cwd=private,environment=env,seconds=BODY_SECONDS)
        need(len(runner.records)==len(runner.group_observations)==1,'Exactly one original formatter process/group required');record=json.loads((output/'FORMATTER_EXEC.json').read_bytes());row=runner.records[0]
        need(record['pid']==record['process_group']==row['pid']==row['original_group'] and type(row['pid']) is int and row['pid']>0 and row['arguments']==list(map(str,planned)) and record['environment']==env and record['backend']==backend and record['argv']==config['argv'] and record['stdin']==original and record['stdin_descriptor']==0 and record['profile_sha256']==config['profile_sha256'] and record['config_sha256']==config_hash and record['file_size_limit']==[STREAM_BYTES,STREAM_BYTES],'Exact exec/opened STDIN/provider/profile/PID/group/limit joins required')
        need(row['maximum_seconds']==BODY_SECONDS and 0<=row['elapsed_seconds']<=BODY_SECONDS and row['expected_exit']==0 and row['exit_code']==0 and row['refusal'] is None and row['terminal_group_observation']==runner.group_observations[0] and row['writers_confirmed_retired'] is True and runner.group_observations[0]['status']=='absent','Unchanged original formatter terminal/group return required')
        need((output/'formatter.stdout.txt').stat().st_size>0,'Actual formatter STDOUT required');result['passed']=True
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        result['actual_formatter_commands']=len(runner.records);result['commands']=runner.records;result['groups']=runner.group_observations;result['writers_confirmed_retired']=runner.writers_confirmed_retired
        try:
            need(runner.writers_confirmed_retired and all(g['status']=='absent' for g in runner.group_observations),'Original formatter writers must return before private cleanup')
            for stream in ('stdout','stderr'):
                p=output/('formatter.'+stream+'.txt')
                if p.exists():
                    v=physical(p,end,STREAM_BYTES);need(not runner.records or v['sha256']==runner.records[0][stream+'_sha256'],'Complete original raw formatter stream return required')
            need(physical(source,end,9781)==original,'Original physically opened source return required');context['check'](end);need(identity(output)[:3]==root_id,'Original owned formatter output root required');result['source_provider_return_accepted']=True;write(output/'SDK_AFTER.json',dict(admitted=context['admitted'],roster=context['SDK_roster']));shutil.rmtree(private);result['private_removed']=True
        except BaseException as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>PHASE_SECONDS:result['passed']=False;result['finalization_errors'].append('Complete formatter phase deadline exceeded')
        write(output/'RESULT.json',result)
    return 0 if result['passed'] else 2

def stage(source,output,pin):
    end=time.monotonic()+30;protected=protect(pin,end);need(not output.exists() and source.resolve(strict=True)==source,'Fresh public formatter projection required');result=json.loads((source/'RESULT.json').read_bytes());need(result['format']=='atlas-hosted-original-formatter-result-v1' and result['source_manifest_sha256']==pin,'Exact formatter result/source join required');names=['RESULT.json'];rules=None
    if result.get('writers_confirmed_retired') is True:
        for name in ['COMMANDS.json','FORMATTER_PLAN.json','FORMATTER_EXEC.json','formatter.stdout.txt','formatter.stderr.txt','SDK_BEFORE.json','SDK_AFTER.json']:
            if (source/name).exists():names.append(name)
    before={name:physical(source/name,end,4*2**20) for name in names};payload={name:(source/name).read_bytes() for name in names};need(sum(map(len,payload.values()))<=8*2**20 and all(len(v)<=4*2**20 for v in payload.values()),'Finite complete formatter projection required')
    need('COMMANDS.json' not in payload or json.loads(payload['COMMANDS.json'])==result.get('commands',[]),'Exact original command journal/result join required')
    for stream in ('stdout','stderr'):
        name='formatter.'+stream+'.txt'
        if name in payload:need(len(payload[name])<=STREAM_BYTES and (not result.get('commands') or hashlib.sha256(payload[name]).hexdigest()==result['commands'][0][stream+'_sha256']),'Exact bounded actual raw stream projection required')
    rules=load(ROOT/'vendor/public_evidence_rules.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','formatter_public_rules')
    try:
        for name,raw in payload.items():rules.public_path(name);rules.inspect_public_bytes(name,raw)
    except (ValueError,RuntimeError):
        output.mkdir();write(output/'STAGING_REFUSAL.json',dict(format='atlas-hosted-formatter-clean-stage-refusal-v1',capture_passed=False,matching_contents_included=False,files=[dict(path=n,bytes=len(v),sha256=hashlib.sha256(v).hexdigest()) for n,v in payload.items()]));return False
    for name,v in before.items():need(physical(source/name,end,4*2**20)==v,'Complete original raw staging return required')
    for p,v in protected.items():need(physical(p,end,16*2**20)==v,'Complete staging source return required')
    output.mkdir();rows=[]
    for name,raw in payload.items():(output/name).write_bytes(raw);rows.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    write(output/'PUBLIC_STAGE.json',dict(format='atlas-hosted-formatter-public-stage-v1',files=rows,capture_passed=result['passed'],matching_contents_included=False,actual_target_cells_accepted=0));replay(output,pin);return result['passed']
def replay(root,pin):
    end=time.monotonic()+30;protected=protect(pin,end);allowed={'RESULT.json','COMMANDS.json','FORMATTER_PLAN.json','FORMATTER_EXEC.json','formatter.stdout.txt','formatter.stderr.txt','SDK_BEFORE.json','SDK_AFTER.json','PUBLIC_STAGE.json'};actual={p.name for p in root.iterdir()};need(actual<=allowed and all(p.is_file() and not p.is_symlink() for p in root.iterdir()),'Exact positive formatter public file roster required');before={name:physical(root/name,end,4*2**20) for name in actual};stage=json.loads((root/'PUBLIC_STAGE.json').read_bytes());need({r['path'] for r in stage['files']}==actual-{'PUBLIC_STAGE.json'} and len(stage['files'])==len(actual)-1,'Complete formatter stage roster required')
    for row in stage['files']:need(all(before[row['path']][k]==row[k] for k in ('bytes','sha256')),'Exact public formatter byte/hash join required')
    result=json.loads((root/'RESULT.json').read_bytes());need(result['source_manifest_sha256']==pin and stage['capture_passed']==result['passed'],'Exact formatter public source/result join required')
    if 'COMMANDS.json' in actual:need(json.loads((root/'COMMANDS.json').read_bytes())==result['commands'],'Exact public formatter command journal required')
    if result['passed']:
        need(result['source_provider_return_accepted'] is True and result['private_removed'] is True and result['finalization_errors']==[] and result['writers_confirmed_retired'] is True and len(result['commands'])==len(result['groups'])==1 and result['groups'][0]['status']=='absent','Complete successful formatter return required');need((root/'SDK_BEFORE.json').read_bytes()==(root/'SDK_AFTER.json').read_bytes(),'Exact complete before/after SDK return required');row=result['commands'][0];entry=json.loads((root/'FORMATTER_EXEC.json').read_bytes());plan=json.loads((root/'FORMATTER_PLAN.json').read_bytes());need(entry['pid']==entry['process_group']==row['pid']==row['original_group'] and entry['argv']==result['logical_argv']==plan['argv'] and entry['stdin']==result['original_source']==plan['source'] and entry['config_sha256']==hashlib.sha256((root/'FORMATTER_PLAN.json').read_bytes()).hexdigest() and entry['profile_sha256']==result['compiler_profile_sha256'],'Complete original formatter STDIN/argv/provider/profile/PID/group joins required')
        sdk=json.loads((root/'SDK_BEFORE.json').read_bytes())['admitted'];provider=sdk['providers']['compiler_backend']
        need(result['job_identity']==sdk['job_identity'],'Exact original public same-job SDK identity required')
        need(type(result['actual_formatter_commands']) is int and result['actual_formatter_commands']==len(result['commands'])==1,'Exact one original public formatter command required')
        need(type(entry['stdin_descriptor']) is int and entry['stdin_descriptor']==0,'Exact original public formatter STDIN descriptor0 required')
        need(entry['backend']==plan['backend'] and entry['environment']==plan['environment'] and entry['file_size_limit']==[STREAM_BYTES,STREAM_BYTES] and plan['profile_sha256']==result['compiler_profile_sha256']==sdk['observed_profile_sha256'] and plan['backend']['sha256']==result['compiler_backend_sha256']==provider['sha256'] and all(plan['backend'][k]==provider[k] for k in ('path','bytes','sha256')),'Complete exact public provider/profile/environment/kernel-limit return required')
        need(plan['argv']==[plan['backend']['path'],'tool','format','--no-color','-'] and plan['source']['bytes']==9781 and plan['source']['sha256']==FIXTURE_SHA and result['body_seconds']==BODY_SECONDS and result['maximum_seconds']==PHASE_SECONDS and result['return_seconds']==RETURN_SECONDS and 0<=result['elapsed_seconds']<=PHASE_SECONDS,'Exact original public formatter source/argv/phase bounds required')
        need(row['maximum_seconds']==BODY_SECONDS and 0<=row['elapsed_seconds']<=BODY_SECONDS and row['expected_exit']==row['exit_code']==0 and row['refusal'] is None and row['writers_confirmed_retired'] is True and row['terminal_group_observation']==result['groups'][0],'Complete original public command/group/time return required')
    for channel in ('stdout','stderr'):
        name='formatter.'+channel+'.txt'
        if name in actual:need(before[name]['bytes']<=STREAM_BYTES and before[name]['sha256']==result['commands'][0][channel+'_sha256'],'Exact actual raw formatter stream return required')
    for name,row in before.items():need(physical(root/name,end,4*2**20)==row,'Complete final public formatter return required')
    for p,row in protected.items():need(physical(p,end,16*2**20)==row,'Complete final formatter reader source return required')
    return result
def main(a):
    started=time.monotonic()
    if a.operation=='stage':return 0 if stage(a.source,a.output,a.packet_sha256) else 2
    need(a.output.is_absolute() and a.output.parent.resolve(strict=True)==a.output.parent and not a.output.exists(),'Fresh physical formatter output required');a.output.mkdir(mode=0o700);own(a.output)
    try:context=admit(a,started+40)
    except BaseException as error:write(a.output/'RESULT.json',dict(format='atlas-hosted-original-formatter-result-v1',passed=False,source_manifest_sha256=a.packet_sha256,actual_formatter_commands=0,writers_confirmed_retired=True,groups=[],error=type(error).__name__+': '+str(error),finalization_errors=[],actual_target_cells_accepted=0));return 2
    return execute(a,context,started)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['capture','stage']);p.add_argument('--repository',type=Path,required=True);p.add_argument('--sdk-evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source',type=Path);p.add_argument('--packet-sha256',required=True);raise SystemExit(main(p.parse_args()))
