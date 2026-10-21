"""Detach only this job's setup tap link and restore its post-action contract."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import source_modes
from route_support import ROOT,need,read,write,sha,stable,revalidate,verify_commands,command_maximum,source_packet
from run_route import get_context,run_command,clean_environment,tap_readback,ALIAS,ALPHA

TAP='crimson-knight/agent-crystal'
REPOSITORY='crimson-knight/homebrew-agent-crystal'
SECONDS=300
MAX_FILES=512
MAX_BYTES=64*2**20
ROUTE_PHASES=(('OBSERVATION_RESULT.json','', 'observation'),
              ('PROVIDER_PREPARATION_RESULT.json','provider-preparation','preparation'),
              ('REVIEW_HOLD_RESULT.json','review-command-output','consumer'),
              ('CONSUMER_RESULT.json','consumer-command-output','consumer'),
              ('BOTTLE_RESULT.json','','bottle'))
SDK_LIMITS=dict(zip(('brew-prefix','brew-root','brew-receipt','alpha-version','ruby-identity','install-bundle',
    'default-specs','without-mt-specs','tutorial-build','tutorial-normal','tutorial-regression',
    'runtime-dependency-metadata','crypto-consumer-format','crypto-consumer-build','crypto-consumer-elf','crypto-consumer-runtime'),
    (45,45,45,30,30,30,300,300,300,30,30,45,15,120,10,10)))


def physical_directory(path):
    need(path.is_absolute() and path.resolve(strict=True)==path and path.is_dir() and not path.is_symlink(),'Physical absolute ordinary directory required')
    need(path.stat().st_uid==os.getuid(),'Current-job owned directory required')
    return path


def node_identity(path):
    value=path.lstat();return [value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns]


def tree_identity(root):
    physical_directory(root);started=time.monotonic();rows=[];directories=[];total=0
    def failed(error):raise error
    for directory,dirs,files in os.walk(root,followlinks=False,onerror=failed):
        for name in sorted(dirs):
            path=Path(directory)/name;need(not path.is_symlink() and path.is_dir(),'Ordinary preserved source directories required');directories.append({'path':path.relative_to(root).as_posix(),'identity':node_identity(path)})
        for name in sorted(files):
            path=Path(directory)/name;row,raw=stable(path,8*2**20);total+=len(raw)
            need(len(rows)<MAX_FILES and total<=MAX_BYTES and time.monotonic()-started<=20,'Finite complete CI/public source identity required')
            rows.append({'path':path.relative_to(root).as_posix(),'bytes':len(raw),'sha256':row['sha256'],'mode':row['mode'],'identity':node_identity(path)})
        need(len(directories)<=MAX_FILES and time.monotonic()-started<=20,'Finite complete source directory identity required')
    return {'files':sorted(rows,key=lambda r:r['path']),'directories':sorted(directories,key=lambda r:r['path']),'bytes':total}


def tracked_identity(workspace,text):
    rows=[];total=0;started=time.monotonic()
    for line in text.splitlines():
        header,name=line.split('\t',1);mode,kind,blob=header.split();relative=PurePosixPath(name)
        need(str(relative)==name and not relative.is_absolute() and '..' not in relative.parts and '.git' not in relative.parts and not name.startswith('"'),'Contained canonical tracked source path required')
        need(mode in ('100644','100755') and kind=='blob' and re.fullmatch('[0-9a-f]{40}',blob) is not None,'Ordinary exact tracked source modes/Git blobs required')
        path=workspace/relative;need(path.parent.resolve(strict=True)==path.parent,'Physical tracked source parent required');info=path.lstat();row,raw=stable(path,8*2**20);total+=len(raw)
        need(source_modes.physical_identity(info)==source_modes.physical_identity(path.lstat()),'Stable complete tracked source permission identity required')
        permission=source_modes.observe(info,mode)
        need(permission['accepted'] and sha_git(raw)==blob,'Current checkout bytes/Git executable class and safe permission profile must equal current-job source')
        need(len(rows)<MAX_FILES and total<=MAX_BYTES and time.monotonic()-started<=20,'Finite tracked source closure required')
        rows.append({'path':name,'mode':mode,'bytes':len(raw),'sha256':row['sha256'],'git_blob':blob})
        if source_modes.DEFAULT_POLICY==source_modes.POLICY:rows[-1]['permission']=permission
    need(rows and len({r['path'] for r in rows})==len(rows),'Nonempty unique complete tracked source closure required')
    return sorted(rows,key=lambda r:r['path'])


def sha_git(raw):
    import hashlib
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def checkout_readback(runner,providers,output,env,workspace,commit,phase):
    stdout,_=run_command(runner,providers,'ci-checkout-'+phase,'git',['-C',workspace,'rev-parse','--show-toplevel','HEAD','HEAD^{tree}'],output,env,15)
    fields=stdout.splitlines();need(len(fields)==3 and fields[:2]==[str(workspace),commit] and re.fullmatch('[0-9a-f]{40}',fields[2]) is not None,'Exact current-job workspace/commit/tree required')
    listing,_=run_command(runner,providers,'ci-tree-'+phase,'git',['-C',workspace,'ls-tree','-r','--full-tree','HEAD'],output,env,15)
    return {'workspace':str(workspace),'commit':commit,'tree':fields[2],'tracked_files':tracked_identity(workspace,listing)}


def current_context(args):
    need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')==REPOSITORY,'Exact owning hosted repository required')
    need(all(re.fullmatch('[1-9][0-9]*',os.environ.get(k,'')) is not None for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')),'Current run and attempt identity required')
    commit=os.environ.get('GITHUB_SHA','');need(re.fullmatch('[0-9a-f]{40}',commit) is not None,'Exact current-job source commit required')
    workspace=physical_directory(Path(os.environ['GITHUB_WORKSPACE']));need(workspace==Path.cwd().resolve(strict=True) and ROOT.is_relative_to(workspace),'Actual current-job checkout/source location required')
    need((workspace/'.git').is_dir() and not (workspace/'.git').is_symlink(),'Ordinary CI checkout Git directory required')
    need(args.setup_tap_name==TAP,'Exact pinned setup action tap output required')
    return workspace,commit


def assert_fresh(runner,providers,output,env,label):
    need(all(__import__('shutil').which(alias) is None for alias in ALIAS),'Fresh ordinary compiler aliases required before CI tap mutation')
    stdout,_=run_command(runner,providers,label,'brew',['list','--versions','agent-crystal'],output,env,15,1)
    need(not stdout.strip(),'Fresh formula absence requires the empty actual version roster')


def link_identity(path,workspace):
    value=path.lstat();need(stat.S_ISLNK(value.st_mode) and value.st_uid==os.getuid(),'Current-user owned setup checkout symlink required')
    target=os.readlink(path);need(target==str(workspace) and path.resolve(strict=True)==workspace,'Only the exact current-job setup checkout target is admissible')
    return {'path':str(path),'target':target,'identity':node_identity(path)}


def detach(args,driver,protected,providers):
    output=args.output.absolute();need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical CI preparation evidence required');output.mkdir()
    started=time.monotonic();runner=driver.Runner(output);runner.deadline=started+SECONDS;env=clean_environment()
    result={'format':'ordinary-current-CI-checkout-preparation-v108','passed':False,'checkout_alias_detached':False,'writers_confirmed_retired':False,'original_groups':[],'finalization_errors':[],'actual_default_route_accepted':False}
    before=workspace=commit=alias=None
    try:
        workspace,commit=current_context(args);result['job_identity']={k:os.environ.get(k) for k in ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_WORKSPACE','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','RUNNER_NAME')};assert_fresh(runner,providers,output,env,'ci-formula-absence-before')
        text,_=run_command(runner,providers,'ci-brew-root','brew',['--repository'],output,env,15);brew_root=physical_directory(Path(text.strip()))
        text,_=run_command(runner,providers,'ci-tap-location','brew',['--repository',TAP],output,env,15)
        alias=brew_root/'Library/Taps/crimson-knight/homebrew-agent-crystal'
        need(text.strip()==str(alias)==args.setup_repository_path and alias.parent.resolve(strict=True)==alias.parent,'Exact setup output and ordinary Homebrew tap location required')
        original_link=link_identity(alias,workspace);before=checkout_readback(runner,providers,output,env,workspace,commit,'before')
        origin,_=run_command(runner,providers,'ci-checkout-origin','git',['-C',workspace,'remote','get-url','origin'],output,env,15)
        need(origin.strip() in ('https://github.com/'+REPOSITORY,'https://github.com/'+REPOSITORY+'.git'),'Exact current owning checkout origin required')
        write(output/'CI_CHECKOUT_BEFORE.json',before);write(output/'CI_ALIAS_BEFORE.json',original_link)
        need(link_identity(alias,workspace)==original_link,'Exact owned alias identity before ordinary untap required')
        run_command(runner,providers,'ci-untap-owned-checkout','brew',['untap',TAP],output,env,30)
        need(not alias.exists() and not alias.is_symlink(),'Ordinary untap must remove only the CI checkout alias')
        result['checkout_alias_detached']=True
        after=checkout_readback(runner,providers,output,env,workspace,commit,'after');need(after==before,'Current-job checkout must survive ordinary untap unchanged');write(output/'CI_CHECKOUT_AFTER.json',after)
        assert_fresh(runner,providers,output,env,'ci-formula-absence-after');result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected)
            if before is not None:
                physical_directory(workspace)
                for row in before['tracked_files']:need(stable(workspace/row['path'])[0]['sha256']==row['sha256'],'Checkout source survival required on every preparation return')
            verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result.update(writers_confirmed_retired=runner.writers_confirmed_retired,original_groups=runner.group_observations,elapsed_seconds=time.monotonic()-started,maximum_seconds=SECONDS,observed_providers=providers,source_return_protected=protected)
        if result['elapsed_seconds']>SECONDS or not runner.writers_confirmed_retired:result['passed']=False;result['finalization_errors'].append('Finite CI preparation/original return refused')
        write(output/'CI_PREPARATION_RESULT.json',result)
    return 0 if result['passed'] else 2


def returned_route(directory,outcome_text):
    """Join every reached phase before any public-clone or setup-link mutation."""
    need(isinstance(outcome_text,str) and 0<len(outcome_text.encode())<=1024,'Explicit bounded actual workflow outcomes required')
    outcomes=json.loads(outcome_text)
    need(type(outcomes) is dict and set(outcomes) in ({'bottle'},{'observation','preparation','consumer'}) and
         all(v in ('success','failure','cancelled','skipped') for v in outcomes.values()),'Exact route workflow outcome roster required')
    directory=directory.absolute();need(directory.parent.resolve(strict=True)==directory.parent,'Physical owned route-output parent required')
    if directory.exists() or directory.is_symlink():physical_directory(directory)
    started=time.monotonic();results=[];raw_bytes=0;read_count=0
    def bounded_read(path,maximum=8*2**20):
        nonlocal raw_bytes,read_count
        row,raw=stable(path,maximum);raw_bytes+=len(raw);read_count+=1
        need(raw_bytes<=MAX_BYTES and read_count<=MAX_FILES and time.monotonic()-started<=10,'Finite complete reached-route return evidence required')
        return row,raw
    def phase(name,folder,sdk=False):
        path=directory/name;identity,raw=bounded_read(path);value=json.loads(raw)
        need(value.get('writers_confirmed_retired') is True,'Every reached default-route phase must return its original writers before CI restoration')
        key='owned_group_observations' if sdk else 'original_groups' if 'original_groups' in value else 'original_group_observations'
        need(key in value and type(value[key]) is list,'Explicit complete reached-phase group roster required')
        groups=value[key];need(all(g.get('status')=='absent' for g in groups),'Every reached default-route original group must be absent')
        command_path=directory/folder/'COMMANDS.json'
        if command_path.exists() or command_path.is_symlink():
            _,command_raw=bounded_read(command_path);commands=json.loads(command_raw)
        else:commands=[]
        need(type(commands) is list and len(commands)==len(groups)<=96,'Exact reached-phase command/group count join required')
        if not sdk:verify_commands(commands,groups,successful=False)
        for command,group in zip(commands,groups):
            label=command['label'];need(re.fullmatch('[a-zA-Z0-9_-]+',label) is not None,'Contained reached command label required')
            need(command['writers_confirmed_retired'] is True and command['terminal_group_observation']==group and
                 all(type(v) is int and v>0 for v in (command['pid'],command['original_group'],group['group'])) and
                 command['pid']==command['original_group']==group['group'],'Exact original reached command/group retirement required')
            if sdk:
                need(label in SDK_LIMITS and type(command['maximum_seconds']) in (int,float) and 0<command['maximum_seconds']<=SDK_LIMITS[label],
                     'Original bounded SDK command maximum required')
            for stream in ('stdout','stderr'):
                _,stream_raw=bounded_read(directory/folder/(label+'.'+stream+'.txt'),4*2**20)
                need(sha(stream_raw)==command[stream+'_sha256'],'Reached command raw hash differs before restoration')
        need(stable(path,8*2**20)[0]==identity,'Reached result changed while reading its original return')
        results.append({'file':name,'sha256':identity['sha256'],'passed':value.get('passed'),
                        'observation_complete':value.get('observation_complete'),'returned_commands':len(commands),
                        'scope':'Explicit returned zero-command phase' if not commands else 'Returned original command/group/raw roster'})
    for name,folder,step in ROUTE_PHASES:
        path=directory/name
        present=path.exists() or path.is_symlink()
        if step not in outcomes:
            need(not present,'Result belongs to a different actual workflow route');continue
        if outcomes[step]=='skipped':
            need(not present,'Skipped workflow phase cannot carry a reached result')
            if folder:need(not (directory/folder).exists() and not (directory/folder).is_symlink(),'Skipped workflow phase has reached command state')
            continue
        if name=='CONSUMER_RESULT.json' and not present:
            need(not (directory/folder).exists() and not (directory/folder).is_symlink(),'Reached consumer lacks its original return result')
            review=directory/'REVIEW_HOLD_RESULT.json'
            need(review.exists() and read(review).get('approval_consumed') is False,'Positive review-without-resume boundary required')
            continue
        need(present,'Launched workflow phase lacks its original return result: '+name)
        phase(name,folder)
    sdk=directory/'sdk'
    if sdk.exists() or sdk.is_symlink():
        physical_directory(sdk);need((sdk/'READINESS_RESULT.json').exists(),'Reached SDK lacks its original return result')
        phase('sdk/READINESS_RESULT.json','sdk',sdk=True)
    if not results:
        need(all(v=='skipped' for v in outcomes.values()),'Positive not-launched workflow boundary required')
        if directory.exists():need(not any(directory.iterdir()),'Not-launched route output must be absent or empty')
    return {'format':'ordinary-route-return-boundary-v107','workflow_outcomes':outcomes,'results':results,
            'scope':'Explicit workflow not-launched boundary' if not results else 'Every reached phase returned original writers/groups',
            'raw_evidence_bytes':raw_bytes,'read_file_count':read_count}


def restore(args,driver,protected,providers):
    output=args.output.resolve(strict=True);directory=output/'restoration';directory.mkdir();started=time.monotonic();runner=driver.Runner(directory);runner.deadline=started+SECONDS;env=clean_environment()
    result={'format':'ordinary-CI-setup-post-restoration-v108','passed':False,'public_clone_preserved':False,'CI_checkout_link_restored':False,'actual_default_route_accepted':False,'unaccepted_clone_preservation_requested':getattr(args,'preserve_unaccepted_public_clone',False),'default_route_evidence_scope':'Recorded before CI setup restoration; original route acceptance stays in its own receipts','finalization_errors':[]}
    before=None
    try:
        preparation=read(output/'CI_PREPARATION_RESULT.json');need(preparation['writers_confirmed_retired'] is True,'Preparation writers must return before setup restoration');need(preparation['observed_providers']==providers,'The same exact observed providers must span CI setup restoration')
        workspace,commit=current_context(args);before=read(output/'CI_CHECKOUT_BEFORE.json');need(checkout_readback(runner,providers,directory,env,workspace,commit,'restore-before')==before,'Original CI checkout must survive the complete default-route interval')
        alias=Path(read(output/'CI_ALIAS_BEFORE.json')['path']);need(str(alias)==args.setup_repository_path,'Exact original setup alias path required')
        boundary=returned_route(args.route_output,args.route_step_outcomes)
        result['default_route_return_boundary']=boundary;result['default_route_returns']=boundary['results']
        if alias.is_symlink():
            need(link_identity(alias,workspace)==read(output/'CI_ALIAS_BEFORE.json'),'Only the unchanged original setup link can already satisfy restoration');result['CI_checkout_link_restored']=True;result['restoration_scope']='Unchanged original CI link; detachment did not complete'
        else:
            need(preparation['passed'] is True and preparation['checkout_alias_detached'] is True,'Successful exact original checkout detachment required')
            if alias.exists():
                need(boundary['results'],'A returned actual default-route result is required before preserving its public clone')
                physical_directory(alias);need(alias!=workspace and not workspace.is_relative_to(alias) and not alias.is_relative_to(workspace),'Independent public clone must be physically separate from the CI checkout')
                public=tap_readback(runner,providers,directory,env,'ci-public',require_source=not getattr(args,'preserve_unaccepted_public_clone',False));result['preserved_clone_dependency_source_accepted']=public['working_tree_source_accepted'];result['actual_default_route_accepted']=False;need(public['path']==str(alias) and public['commit']==ALPHA,'Exact independently cloned ordinary default tap required')
                identity=tree_identity(alias);root_stat=alias.stat();root_identity=[root_stat.st_dev,root_stat.st_ino,root_stat.st_mode,root_stat.st_uid]
                preserved=output/'preserved-public-tap';need(not preserved.exists() and not preserved.is_symlink(),'Fresh owned public clone preservation path required')
                write(output/'PUBLIC_CLONE_BEFORE_RESTORATION.json',{'tap':public,'root_identity':root_identity,'filesystem':identity})
                need(returned_route(args.route_output,args.route_step_outcomes)==boundary,'Reached return evidence changed before public clone preservation')
                need(time.monotonic()+2<=runner.deadline,'Original restoration deadline capacity required before public clone preservation')
                alias.rename(preserved)
                stat_after=preserved.stat();need([stat_after.st_dev,stat_after.st_ino,stat_after.st_mode,stat_after.st_uid]==root_identity and tree_identity(preserved)==identity,'Complete public clone identities must survive preservation')
                text,_=run_command(runner,providers,'ci-preserved-source','git',['-C',preserved,'rev-parse','HEAD','HEAD^{tree}'],directory,env,15);need(text.splitlines()==[public['commit'],public['tree']],'Preserved public origin commit/tree required')
                origin,_=run_command(runner,providers,'ci-preserved-origin','git',['-C',preserved,'remote','get-url','origin'],directory,env,15);need(origin.strip()==public['origin'],'Preserved public origin required')
                result['public_clone_preserved']=True;result['preserved_public_clone']=str(preserved)
                write(output/'PUBLIC_CLONE_AFTER_RESTORATION.json',{'tap':{**public,'path':str(preserved)},'root_identity':root_identity,'filesystem':identity})
            result['restoration_scope']='Returned public clone preserved' if result['public_clone_preserved'] else 'Detached link restored after route did not create a public clone'
            need(returned_route(args.route_output,args.route_step_outcomes)==boundary,'Reached return evidence changed before setup link restoration')
            need(time.monotonic()+2<=runner.deadline,'Original restoration deadline capacity required before setup link restoration')
            alias.symlink_to(str(workspace),target_is_directory=True);result['restored_link']=link_identity(alias,workspace);result['CI_checkout_link_restored']=True
        need(checkout_readback(runner,providers,directory,env,workspace,commit,'restore-after')==before,'Original checkout must survive CI setup link restoration')
        result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected)
            if before is not None:
                physical_directory(workspace)
                for row in before['tracked_files']:need(stable(workspace/row['path'])[0]['sha256']==row['sha256'],'Checkout source survival required on every restoration return')
            verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result.update(writers_confirmed_retired=runner.writers_confirmed_retired,original_groups=runner.group_observations,elapsed_seconds=time.monotonic()-started,maximum_seconds=SECONDS,observed_providers=providers,source_return_protected=protected)
        if result['elapsed_seconds']>SECONDS or not runner.writers_confirmed_retired:result['passed']=False;result['finalization_errors'].append('Finite CI restoration/original return refused')
        write(output/'CI_RESTORATION_RESULT.json',result)
    return 0 if result['passed'] else 2


def stage(args):
    import importlib.util
    protected=source_packet(args.packet_sha256);source=args.output.resolve(strict=True);need(not args.stage.exists(),'Fresh fixed CI evidence stage required')
    helper=ROOT/'vendor/public_evidence_rules.py';need(stable(helper)[0]['sha256']=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact public evidence rules required');spec=importlib.util.spec_from_file_location('CI_public_rules',helper);rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
    selected={'CI_PREPARATION_RESULT.json','CI_CHECKOUT_BEFORE.json','CI_CHECKOUT_AFTER.json','CI_ALIAS_BEFORE.json','CI_RESTORATION_RESULT.json','PUBLIC_CLONE_BEFORE_RESTORATION.json','PUBLIC_CLONE_AFTER_RESTORATION.json','restoration/TAP_WORKTREE_ci-public.json'};payload={};started=time.monotonic()
    for name in tuple(selected):
        if not (source/name).exists():selected.remove(name)
    for folder,result_name in [('', 'CI_PREPARATION_RESULT.json'),('restoration','CI_RESTORATION_RESULT.json')]:
        path=source/folder/'COMMANDS.json'
        if not path.exists():continue
        result=read(source/result_name)
        if result['writers_confirmed_retired'] is not True:continue
        rows=read(path);verify_commands(rows,result['original_groups'],successful=result['passed'] is True);selected.add((Path(folder)/'COMMANDS.json').as_posix())
        for row in rows:
            for stream in ('stdout','stderr'):
                name=(Path(folder)/(row['label']+'.'+stream+'.txt')).as_posix();need(stable(source/name)[0]['sha256']==row[stream+'_sha256'],'Exact original CI raw output hash required');selected.add(name)
    total=0
    for name in sorted(selected):
        rules.public_path(name);row,raw=stable(source/name,2**20);rules.inspect_public_bytes(name,raw);total+=len(raw);need(total<=16*2**20 and time.monotonic()-started<=30,'Finite16-MiB/30-second CI metadata evidence required');payload[name]=raw
    manifest_raw=stable(ROOT/'SOURCE_PINS.json',2**20)[1];need(sha(manifest_raw)==args.packet_sha256,'Executed CI source manifest required');rules.inspect_public_bytes('SOURCE_PINS.json',manifest_raw);payload['SOURCE_PINS.json']=manifest_raw
    args.stage.mkdir()
    for name,raw in payload.items():target=args.stage/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    write(args.stage/'PUBLIC_STAGE.json',{'files':[{'path':n,'bytes':len(v),'sha256':sha(v)} for n,v in payload.items()],'preserved_public_clone_uploaded':False,'actual_default_route_acceptance':'Separate original default-route results','source_manifest_sha256':args.packet_sha256,'actual_local_workloads':0});revalidate(protected)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=['detach','restore','stage'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet-sha256',required=True);p.add_argument('--setup-tap-name');p.add_argument('--setup-repository-path');p.add_argument('--route-output',type=Path);p.add_argument('--route-step-outcomes');p.add_argument('--preserve-unaccepted-public-clone',action='store_true');p.add_argument('--stage',type=Path)
    for name in ('brew','git','curl','bash','python'):p.add_argument('--'+name,type=Path);p.add_argument('--'+name+'-sha256')
    args=p.parse_args()
    if args.mode=='stage':stage(args)
    else:raise SystemExit((detach if args.mode=='detach' else restore)(args,*get_context(args)))
