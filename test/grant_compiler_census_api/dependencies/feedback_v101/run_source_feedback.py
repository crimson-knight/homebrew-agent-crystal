"""Produce same-job Crystal source gates under admitted SDK and analysis-tool identities."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time

ROOT=Path(__file__).resolve().parent
ARMS=('original','fixed','restored')
OUTER_SECONDS=1800
RETURN_SECONDS=120
COMMAND_SECONDS=1575
MAX_COMMANDS=69
MAX_RAW=8*2**20
PROBE_SHA='b870bfa171405927244d58b2ff676617c76de1f23f355bf9c86fd2a2a8b1b0cf'
TRANSFER_SHA='439df1016cdfdfa237521eccf1f47f9fc72827a4990c3c35b2ec4d8371e4cd92'
TRANSFER_HELPER_SHA='8db41f1a4c4829dee29f2e3d7f28e038bcf3d6e402d66067432e87091f74e097'


def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')
def stable(path,maximum=32*2**20):
    p=Path(path);before=p.lstat();need(stat.S_ISREG(before.st_mode) and before.st_size<=maximum,'Bounded ordinary input required')
    fields=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
    need(fields(before)==fields(opened)==fields(after)==fields(p.lstat()) and len(raw)==before.st_size,'Stable complete physical source/provider required')
    return raw
def digest(path):return sha(stable(path,256*2**20))
def load(path,expected,name):
    need(digest(path)==expected,'Exact imported source required: '+str(path));spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);need(digest(path)==expected,'Imported source return required');return module

def manifest(root,name,expected,maximum):
    raw=stable(root/name,2**20);need(sha(raw)==expected,'Exact external source manifest required: '+name);rows=json.loads(raw)['files'];need(0<len(rows)<=maximum and len({r['path'] for r in rows})==len(rows),'Finite complete source roster required');protected={root/name:expected}
    for row in rows:
        relative=PurePosixPath(row['path']);need(str(relative)==row['path'] and not relative.is_absolute() and '..' not in relative.parts,'Contained source roster required')
        path=root/relative;value=stable(path);need(len(value)==row['bytes'] and sha(value)==row['sha256'],'Pinned source member differs: '+str(relative));protected[path]=row['sha256']
    return protected

def revalidate(protected):
    for path,expected in protected.items():need(digest(path)==expected,'Protected source/provider changed: '+str(path))

def admit(args):
    need(os.environ.get('GITHUB_ACTIONS')=='true','Actual execution belongs to admitted hosted automation')
    protected=manifest(ROOT,'SOURCE_PINS.json',args.packet_sha256,128)
    probe=load(ROOT/'probe/run_probe.py',digest(ROOT/'probe/run_probe.py'),'feedback_probe_authority');protected.update(probe.packet(PROBE_SHA))
    base=json.loads(stable(ROOT/'probe/BASE_INPUT_PINS.json'))
    for row in base['base_files']:
        p=args.repository/row['path'];raw=stable(p);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'Exact accepted revision1 base required');protected[p]=row['sha256']
    policy_path=args.repository/'test/grant_assignment_cost/same_job_policy.py';sdk=load(policy_path,protected[policy_path],'feedback_same_job_sdk');protected.update(sdk.protect_packet(base['base_files'][4]['sha256']))
    admitted=sdk.metadata(args.sdk_evidence,os.environ);driver=load(args.repository/'test/sdk_install_qualification.py',sdk.DRIVER_SHA256,'feedback_qualified_Runner')
    paths={k:Path(v['path']) for k,v in admitted['providers'].items()}
    for name,path in paths.items():need(digest(path)==admitted['providers'][name]['sha256'],'Actual same-job provider bytes required');protected[path]=admitted['providers'][name]['sha256']
    need(digest(Path(sys.executable).resolve())==args.python_sha256==admitted['runner']['python_sha256'],'Same actual admitted Python backend required')
    prefix=Path(stable(args.sdk_evidence/'brew-prefix.stdout.txt').decode().strip()).resolve(strict=True);stdlib=prefix/'share/agent-crystal/src'
    need(driver.tree_identity(stdlib)==admitted['stdlib'],'Same actual installed stdlib required')
    need(paths['compiler_wrapper']==prefix/'bin/crystal-alpha' and paths['compiler_backend']==prefix/'libexec/agent-crystal-bin','Actual ordinary installed wrapper/backend paths required')
    driver.verify_wrapper(stable(paths['compiler_wrapper']).decode(),paths['compiler_backend'],stdlib,Path(stable(args.sdk_evidence/'brew-root.stdout.txt').decode().strip()),'Darwin')
    for name,relative in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
        p=prefix/relative;need(digest(p)==digest(args.sdk_evidence/name),'Actual installed source/receipt join required');protected[p]=digest(p)
    transfer_root=args.transfer_packet.resolve(strict=True);protected.update(manifest(transfer_root,'SOURCE_PINS.json','e186b50c45c15da64ede2801b41e1b05112222dd25cc969ca628c1a1007a8d0e',256));protected.update(manifest(transfer_root,'TRANSFER_SOURCE_PINS.json',TRANSFER_SHA,54))
    sys.path.insert(0,str(transfer_root));transfer=load(transfer_root/'proof_tool_transfer.py',TRANSFER_HELPER_SHA,'feedback_transfer_authority')
    proof=load(transfer_root/'dirty_proof.py',protected[transfer_root/'dirty_proof.py'],'feedback_proof_authority')
    tools=proof.admit_tools(args.proof_tools,args.proof_tools_sha256)
    need(digest(args.tool_policy)==args.tool_policy_sha256,'Externally reviewed positive analysis native policy required')
    tool_policy=transfer.decode(stable(args.tool_policy,2**20));need(tool_policy['execution_admitted'] is True,'Independently reviewed analysis native admission remains required')
    budget=transfer.Budget(time.monotonic()+45);original_transfer=transfer.tool_return(args.tool_workspace,budget)
    need(original_transfer.get('execution_source_return_inside_lease') is True,'Completed v102 transfer lease and execution-source return required')
    observed=transfer.decode(budget.read(args.tool_workspace/'NATIVE_OBSERVATION.json'));native=transfer.collect_native(budget,admitted,tool_root=args.tool_workspace/'tools')
    need(observed['passed'] is True and observed['native']==native and tools['same_job']==admitted['job_identity'],'Real same-job selected native observation and registry required')
    need(transfer.registry(args.tool_workspace/'tools',tool_policy,native)==tools,'Exact reviewed analysis policy/native/source registry join required')
    for path in (args.proof_tools,args.tool_policy,args.tool_workspace/'TRANSFER_RESULT.json',args.tool_workspace/'NATIVE_OBSERVATION.json'):protected[path]=digest(path)
    for row in tools['tools'].values():protected[Path(row['path'])]=row['sha256']
    corpus=tools['tools']['amber_lsp'];protected[Path(corpus['api_corpus_path'])]=corpus['api_corpus_sha256']
    sdk_roster=sdk.roster(args.sdk_evidence)
    def check():
        need(sdk.metadata(args.sdk_evidence,os.environ)==admitted and sdk.roster(args.sdk_evidence)==sdk_roster,'Exact fresh SDK/source/job return required')
        need(driver.tree_identity(stdlib)==admitted['stdlib'],'Installed stdlib return required')
        need(transfer.collect_native(transfer.Budget(time.monotonic()+45),admitted,tool_root=args.tool_workspace/'tools')==native,'Complete selected tool native/alias return required')
        transfer.tool_return(args.tool_workspace,transfer.Budget(time.monotonic()+30));need(proof.admit_tools(args.proof_tools,args.proof_tools_sha256)==tools,'Original admitted tools must return unchanged');revalidate(protected)
    return {'probe':probe,'driver':driver,'proof':proof,'admitted':admitted,'tools':tools,'paths':paths,'protected':protected,'check':check,'native':native}

def environment(private,wrapper):
    value={k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR')}
    value.update(HOME=str(private/'home'),PATH=str(wrapper.parent)+os.pathsep+value.get('PATH',''),CRYSTAL_WORKERS='1',LC_ALL='C',NO_COLOR='1',PYTHONDONTWRITEBYTECODE='1')
    need(Path(shutil.which('crystal-alpha',path=value['PATH']) or '').resolve(strict=True)==wrapper.resolve(strict=True),'Released API lookup must select the actual admitted crystal-alpha')
    return value

def project_sources(output,probe):
    private=output/'private';private.mkdir();(private/'home').mkdir();projects={};expected={}
    metadata='name: atlas_native_buffer_probe\nversion: 0.1.0\ncrystal: ">= 1.21.0"\nlicense: MIT\ndescription: Exact native buffer ownership source compatibility fixture\ntargets:\n  atlas_native_buffer_probe:\n    main: src/main.cr\n'
    for arm in ARMS:
        root=private/arm;(root/'src').mkdir(parents=True)
        files={'src/main.cr':stable(probe.ROOT/'buffer_probe.cr.txt'),'src/memory_buffer.cr':stable(probe.ROOT/('inputs/memory_buffer.fixed.cr.txt' if arm=='fixed' else 'inputs/memory_buffer.original.cr.txt')),'shard.yml':metadata.encode()}
        for name,raw in files.items():p=root/name;p.write_bytes(raw);expected[p]=sha(raw)
        projects[arm]=root
    return private,projects,expected

def command_roster(methods):
    rows=[('amber-lsp-version',10),('ameba-version',10)]
    for index in range(len(methods)):rows.extend([('api-'+str(index),10),('api-verify-'+str(index),10)])
    for arm in ARMS:rows += [('format-'+arm,15),('diagnostics-'+arm+'-main',15),('diagnostics-'+arm+'-buffer',15),('lint-'+arm,120),('no-codegen-'+arm,180)]
    need(len(rows)==MAX_COMMANDS and sum(s for _,s in rows)==COMMAND_SECONDS,'Complete unchanged worst-case command horizon required');return rows

def execute(args,context,started):
    output=args.output;need(output.is_absolute() and output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical source-feedback output required');output.mkdir()
    probe=context['probe'];driver=context['driver'];proof=context['proof'];admitted=context['admitted'];tools=context['tools'];runner=driver.Runner(output);runner.deadline=started+OUTER_SECONDS-RETURN_SECONDS
    methods=json.loads(stable(probe.ROOT/'API_PREREQUISITES.json'))['methods'];need(len(methods)==len(set(methods))==26,'Exact26 API method cards required');roster=command_roster(methods);allowed=dict(roster)
    source_hashes={name:digest(probe.ROOT/name) for name in ('buffer_probe.cr.txt','inputs/memory_buffer.original.cr.txt','inputs/memory_buffer.fixed.cr.txt')}
    result={'format':'atlas-native-buffer-source-feedback-controller-v1','passed':False,'compiler_color':'UNEXECUTED','source_sha256':source_hashes,'job_identity':admitted['job_identity'],'compiler_profile_sha256':admitted['observed_profile_sha256'],'command_seconds_worst_case':COMMAND_SECONDS,'maximum_seconds':OUTER_SECONDS,'return_seconds':RETURN_SECONDS,'original_groups':[],'finalization_errors':[],'actual_target_cells_accepted':0,'full_native_memory_qualified':False,'private_removed':False,'source_provider_return_accepted':False}
    expected={};projects={};private=None;cards=[];complete=False;launched={}
    original_run=runner.run
    def bounded_run(label,argv,*,cwd,environment,seconds):
        need(label in allowed and seconds==allowed[label] and len(runner.records)<MAX_COMMANDS and runner.deadline-time.monotonic()>=seconds+1,'Full original command maximum plus finite metadata reserve required before launch')
        return original_run(label,argv,cwd=cwd,environment=environment,seconds=seconds)
    runner.run=bounded_run
    def run(label,argv,root,env,seconds):
        need(len(runner.records)<MAX_COMMANDS and label in allowed and allowed[label]==seconds and runner.deadline-time.monotonic()>=seconds,'Original finite full command reservation required')
        runner.run(label,list(map(str,argv)),cwd=root,environment=env,seconds=seconds)
        record=runner.records[-1];stdout,stderr=proof.terminal(record,seconds,output=output)
        need(record['label']==label and record['arguments']==list(map(str,argv)) and record['maximum_seconds']==seconds,'Exact feedback command identity required');probe.working_bound(private);launched[label]=json.loads(json.dumps(record));return stdout,stderr
    try:
        need(time.monotonic()-started<=45 and runner.deadline-time.monotonic()>=COMMAND_SECONDS,'All1575 original command seconds plus full return reserve required')
        private,projects,expected=project_sources(output,probe);wrapper=context['paths']['compiler_wrapper'];env=environment(private,wrapper)
        for label,name,version in [('amber-lsp-version','amber_lsp','2.0.7'),('ameba-version','ameba','1.7.0-dev')]:
            stdout,stderr=run(label,[tools['tools'][name]['path'],'--version'],projects['fixed'],env,10);need(version in stdout and not stderr,'Actual admitted analysis-tool version required')
        lookup_env=dict(env,CRYSTAL_CACHE_DIR=str(projects['fixed']/'cache'))
        for index,method in enumerate(methods):
            need(runner.deadline-time.monotonic()>=22,'Complete lookup and possible compiler verification reservation required')
            count=len(runner.records);card=proof.lookup(runner,tools['tools']['amber_lsp']['path'],method,index,projects['fixed'],lookup_env,output)
            need(len(runner.records)-count in (1,2),'One actual lookup and bounded unknown verification required');probe.working_bound(private)
            for row in runner.records[count:]:launched[row['label']]=json.loads(json.dumps(row))
            cards.append({'query':method,'project':str(projects['fixed']),'card':card})
        for arm in ARMS:
            root=projects[arm];main=root/'src/main.cr';buffer=root/'src/memory_buffer.cr';current=dict(env,CRYSTAL_CACHE_DIR=str(root/'cache'))
            stdout,stderr=run('format-'+arm,[wrapper,'tool','format','--check',main,buffer],root,current,15);need(not stdout and not stderr,'Actual source format must be GREEN')
            for label,path in [('main',main),('buffer',buffer)]:
                stdout,stderr=run('diagnostics-'+arm+'-'+label,[tools['tools']['amber_lsp']['path'],'--check',path],root,current,15);need(stdout=='amber-lsp: covered no diagnostics\n' and not stderr,'Actual covered zero-diagnostic source required')
            stdout,stderr=run('lint-'+arm,[tools['tools']['ameba']['path'],'--no-color','--format','dot','--config',ROOT/'inputs/AMEBA.yml',main,buffer],root,current,120)
            need(not stderr and re.search(r'^2 inspected, 0 failures?$',stdout,re.M) and not re.search(r'\b(?:error|warning)\b',stdout,re.I),'Actual full-source Ameba result must be GREEN')
            argv=[wrapper,'build',main,'--no-codegen','--no-color','--error-on-warnings','-Dwithout_mt','--threads','1']+(['-Datlas_fixed_buffer'] if arm=='fixed' else [])
            stdout,stderr=run('no-codegen-'+arm,argv,root,current,180)
            if stdout or stderr:result['compiler_color']='YELLOW';raise RuntimeError('Every exact whole-harness no-codegen command requires zero warnings/errors/output')
        result['compiler_color']='GREEN';complete=True
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)
        if runner.records and runner.records[-1]['label'].startswith('no-codegen-') and runner.records[-1]['exit_code']!=0 and runner.records[-1]['refusal'] is None:result['compiler_color']='RED'
    finally:
        try:
            context['check']();revalidate(expected)
            need(runner.writers_confirmed_retired and len(runner.records)==len(runner.group_observations),'All original feedback writers must return')
            seen=[];raw=[]
            for record,group in zip(runner.records,runner.group_observations):
                label=record['label'];need(record==launched.get(label),'Every actual command/stream/terminal observation must return unchanged');need(label in allowed and label not in seen and record['maximum_seconds']==allowed[label],'Exact unique feedback command budget roster required');seen.append(label)
                stdout,stderr=proof.terminal(record,allowed[label],unknown=record['exit_code']==4,output=output,observation=group)
                need(record['arguments'][0] in [str(context['paths']['compiler_wrapper']),tools['tools']['amber_lsp']['path'],tools['tools']['ameba']['path']],'Original admitted executable command return required')
                raw.append({'record':record,'stdout':stdout,'stderr':stderr})
            need(time.monotonic()<=started+OUTER_SECONDS,'Original complete source-feedback return horizon required')
            write(output/'API_CARDS.json',cards);write(output/'ADMISSION.json',{'SDK':admitted,'tools':tools,'selected_native':context['native'],'protected':{str(p):h for p,h in context['protected'].items()}})
            (output/'COMMAND_EVIDENCE.jsonl').write_text(''.join(json.dumps(row,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n' for row in raw))
            source_rows=[]
            for path,digest_before in expected.items():
                relative=path.relative_to(private);target=output/'project_sources'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(stable(path));need(digest(target)==digest_before,'Exact projected source return evidence required');source_rows.append({'path':str(target.relative_to(output)),'bytes':target.stat().st_size,'sha256':digest_before,'actual_project_path':str(path)})
            write(output/'PROJECT_SOURCES.json',source_rows)
            if private is not None:
                probe.working_bound(private);shutil.rmtree(private);need(not private.exists(),'Owned source-feedback private projection must retire');result['private_removed']=True
            result['source_provider_return_accepted']=True;result['passed']=complete and result['private_removed']
        except BaseException as error:result['finalization_errors'].append(type(error).__name__+': '+str(error));result['passed']=False
        result.update(elapsed_seconds=time.monotonic()-started,original_groups=runner.group_observations,writers_confirmed_retired=runner.writers_confirmed_retired,commands=len(runner.records))
        if result['elapsed_seconds']>OUTER_SECONDS:result['passed']=False
        write(output/'RESULT.json',result)
        evidence=[];names=['COMMAND_EVIDENCE.jsonl','API_CARDS.json','ADMISSION.json','PROJECT_SOURCES.json','RESULT.json']+[str(p.relative_to(output)) for p in sorted((output/'project_sources').rglob('*')) if p.is_file()]
        total=0
        for name in names:
            path=output/name
            if not path.exists():continue
            value=stable(path,MAX_RAW);total+=len(value);evidence.append({'path':name,'bytes':len(value),'sha256':sha(value)})
        if total>MAX_RAW:result['passed']=False;result['finalization_errors'].append('Native consumer eight-MiB complete source-feedback evidence ceiling exceeded');write(output/'RESULT.json',result);evidence=[]
        gates={'format':'atlas-native-buffer-source-gates-v1','job_identity':admitted['job_identity'],'compiler_profile_sha256':admitted['observed_profile_sha256'],'source_sha256':source_hashes,'compiler_color':result['compiler_color'],'raw_evidence':evidence,'format_accepted':result['passed'],'producer_format':'atlas-native-buffer-source-feedback-controller-v1','command_count':len(runner.records),'command_maximum_count':MAX_COMMANDS,'maximum_seconds':OUTER_SECONDS,'writers_confirmed_retired':runner.writers_confirmed_retired,'private_removed':result['private_removed'],'source_provider_return_accepted':result['passed'],'producer_manifest_sha256':args.packet_sha256,'proof_tools_sha256':args.proof_tools_sha256,'tool_native_policy_sha256':args.tool_policy_sha256,'controller_result_sha256':digest(output/'RESULT.json'),'feedback_return':{'result_path':'RESULT.json','command_evidence_path':'COMMAND_EVIDENCE.jsonl','admission_path':'ADMISSION.json','project_sources_path':'PROJECT_SOURCES.json','maximum_seconds':OUTER_SECONDS,'command_maximum_count':MAX_COMMANDS,'return_reserve_seconds':RETURN_SECONDS}}
        for key in ('lookup_accepted','diagnostics_accepted','lint_accepted','no_codegen_accepted','baseline_sdk_specs_accepted','tool_provider_review_accepted'):gates[key]=result['passed']
        write(output/'SOURCE_GATES.json',gates)
    return 0 if result['passed'] else 2


def main(args):
    started=time.monotonic()
    need(args.output.is_absolute() and args.output.parent.resolve(strict=True)==args.output.parent and not args.output.exists(),'Fresh physical owned source-feedback output required')
    try:
        context=admit(args);return execute(args,context,started)
    except BaseException as error:
        if not args.output.exists():args.output.mkdir()
        result={'format':'atlas-native-buffer-source-feedback-admission-refusal-v1','passed':False,'error':type(error).__name__+': '+str(error),'actual_target_cells_accepted':0,'elapsed_seconds':time.monotonic()-started,'maximum_seconds':OUTER_SECONDS,'actual_compiler_feedback_commands_accepted':False}
        write(args.output/'ADMISSION_REFUSAL.json',result)
        path=args.output/'SOURCE_GATES.json'
        gates=json.loads(stable(path)) if path.exists() else {'format':'atlas-native-buffer-source-gates-v1','job_identity':{},'compiler_profile_sha256':'UNADMITTED','source_sha256':{},'compiler_color':'UNEXECUTED','raw_evidence':[]}
        for key in ('lookup_accepted','diagnostics_accepted','lint_accepted','no_codegen_accepted','baseline_sdk_specs_accepted','tool_provider_review_accepted','format_accepted','source_provider_return_accepted'):gates[key]=False
        gates['admission_error']=result['error'];write(path,gates)
        return 2

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','proof-tools','tool-policy','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python','proof-tools','tool-policy'):p.add_argument('--'+name+'-sha256',required=True)
    raise SystemExit(main(p.parse_args()))
