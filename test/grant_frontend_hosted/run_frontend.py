"""Six exact semantic-only routes under fresh same-job SDK admission."""
import argparse,hashlib,importlib.util,json,math,os,platform,re,shutil,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from source_gate import BASE,BASE_SHA,admit,digest,need,read,stable,write
PROFILES=('library_floor','declarations','new_empty','new_keywords','new_broad_hash','canonical_create')
DRIVER_SHA='dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
SECONDS=900;RETURN=30;COMPILER=120;FORMAT=10

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def admission(args):
    need(platform.system()=='Darwin' and platform.machine()=='arm64' and os.environ.get('GITHUB_ACTIONS')=='true','Actual execution belongs to supported hosted Mac ARM64')
    protected=admit(args.packet_sha256,args.repository)
    sys.path[:0]=[str(BASE),str(BASE/'vendor'),str(ROOT/'products')]
    policy=load(BASE/'same_job_policy.py','frontend_same_job_policy');sdk=policy.metadata(args.sdk_evidence,os.environ)
    need(digest(args.driver)==DRIVER_SHA and digest(Path(sys.executable).resolve())==args.python_sha256==sdk['runner']['python_sha256'],'Exact actual same-job Python/Runner required')
    need(digest(Path('/bin/ps'))==args.ps_sha256,'Exact observed operating-system metadata provider required')
    driver=load(args.driver,'frontend_original_sdk_driver')
    providers=sdk['providers'];backend=Path(providers['compiler_backend']['path']);wrapper=Path(providers['compiler_wrapper']['path']);prefix=wrapper.parent.parent
    need(wrapper==Path((args.sdk_evidence/'brew-prefix.stdout.txt').read_text().strip()).resolve()/'bin/crystal-alpha' and backend==prefix/'libexec/agent-crystal-bin','Exact ordinary installed compiler paths required')
    stdlib=prefix/'share/agent-crystal/src';driver.verify_wrapper(wrapper.read_text(),backend,stdlib,Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip()),'Darwin')
    for name,row in providers.items():protected[Path(row['path'])]=row['sha256']
    for name,relative in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
        path=prefix/relative;need(digest(path)==digest(args.sdk_evidence/name),'Exact installed formula/receipt return required');protected[path]=digest(path)
    protected.update({args.driver:DRIVER_SHA,Path(sys.executable).resolve():args.python_sha256,Path('/bin/ps'):args.ps_sha256})
    evidence=policy.roster(args.sdk_evidence)
    def check():
        need(policy.metadata(args.sdk_evidence,os.environ)==sdk and policy.roster(args.sdk_evidence)==evidence,'Fresh same-job SDK evidence/provider context changed')
        need(driver.tree_identity(stdlib)==sdk['stdlib'],'Complete installed stdlib changed')
        admit(args.packet_sha256,args.repository)
        for path,sha in protected.items():need(digest(path)==sha,'Protected source/provider changed: '+str(path))
    check()
    from stage_grant_sources import stage
    from verify_compile_acceptance import source_input_inventory
    return driver,dict(metadata_provider=dict(path='/bin/ps',sha256=args.ps_sha256,macOS_version=platform.mac_ver()[0],kernel_release=platform.release(),github_image_version=os.environ.get('ImageVersion'),github_image_os=os.environ.get('ImageOS'),scope='Individually observed same-job OS metadata provider; complete native loader closure remains separate'),admitted=sdk,stdlib=stdlib,backend=backend,wrapper=wrapper,protected=protected,check=check,stage=stage,inventory=source_input_inventory)

def execute(args,driver,context,started):
    from products import frontend_boundary as boundary
    from products.prepared_stdlib import audit_prepared_stdlib
    from products.parse_semantic_stats import parse
    from products.parse_stage_stats import associate_observed_intervals
    from observe_compiler import Observer
    from format_projection import measured_source,projection
    from vendor.command_contract import terminal
    need(args.output.is_absolute() and args.output.parent.resolve(strict=True)==args.output.parent and not args.output.exists(),'Fresh physical owned frontend output required')
    output=args.output;output.mkdir();private=output/'private';private.mkdir()
    runner=driver.Runner(output);runner.deadline=started+SECONDS-RETURN
    result=dict(metadata_provider=context.get('metadata_provider',{'scope':'SYNTHETIC guarded metadata provider'}),controller_pid=os.getpid(),execution_inputs={name:str(getattr(args,name)) for name in ('repository','driver','sdk_evidence','packet_sha256','python_sha256','ps_sha256')},format='atlas-grant-hosted-frontend-six-v1',passed=False,diagnostic_complete=False,compiler_color='UNEXECUTED',maximum_seconds=SECONDS,return_seconds=RETURN,source_packet_sha256=args.packet_sha256,admitted_same_job=context['admitted'],samples=[],observer_results=[],finalization_errors=[],command_count=0,target_cells_accepted=0,required_target_cells=144,whole_build_provider_qualified=False,retained_live_frontend_bytes_qualified=False,overhead_qualified=False,API_lookup_accepted=False,Ameba_lint_accepted=False,route_runtime_behavior_accepted=False,source_provider_return_accepted=False)
    write(output/'RESULT.json',result);before=None;grant=None;observers=[];working={}
    result['route_source_projections']={}
    try:
        boundary.verify_products(ROOT/'products',read(ROOT/'products/FRONTEND_MATERIALIZATION.json'))
        boundary.verify_producer_evidence(ROOT/'products',read(ROOT/'products/FRONTEND_MATERIALIZATION.json'))
        result['source_projection']=context['stage'](BASE/'inputs/grant-source-and-frozen-dependencies.tar.gz',private/'projection');grant=private/'projection/grant'
        before,fingerprint=context['inventory'](grant);need(len(before)==1554 and fingerprint==boundary.SOURCE,'Exact full original Grant/dependency1554-row closure required')
        boundary.source_rows_equal(read(ROOT/'products/EXPECTED_SOURCE.json')['inputs'],before)
        write(output/'SOURCE_BEFORE.json',dict(rows=before,sha256=fingerprint));write(output/'SDK_ADMISSION.json',context['admitted'])
        for index,profile in enumerate(PROFILES):
            need(runner.deadline-time.monotonic()>=(len(PROFILES)-index)*(COMPILER+FORMAT),'All remaining full original route horizons required')
            work=grant/'performance/results/frontend-diagnostic'/profile;work.mkdir(parents=True)
            original=stable(ROOT/'products'/(profile+'.cr.txt'))
            result['route_source_projections'][profile]=projection(profile,original)
            fixture=work/'fixture.cr';fixture.write_bytes(measured_source(profile,original));(work/'fixture.json').write_bytes(stable(ROOT/'products'/(profile+'.json')))
            fixture.chmod(0o644);(work/'fixture.json').chmod(0o644)
            working[profile]={name:digest(work/name) for name in ('fixture.cr','fixture.json')}
            boundary.require_source_paths(grant,fixture,profile)
            cache=private/('cache-'+profile);cache.mkdir();prepared=cache/'budget-stdlib';shutil.copytree(context['stdlib'],prepared,symlinks=True)
            overlay=grant/'performance/vendor/memory_budget/runtime_overlay';manifest=overlay/'manifest.json'
            for row in read(manifest)['files']:
                source=overlay/row['file'];target=prepared/row['file'];need(digest(source)==row['sha256'],'Exact retained runtime overlay required')
                mode=target.stat().st_mode&0o777 if target.exists() else source.stat().st_mode&0o777
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(stable(source));target.chmod(mode)
            prepared_identity=audit_prepared_stdlib(context['stdlib'],prepared,overlay,manifest,output/(profile+'-STDLIB_BEFORE.json'))
            cache_before=boundary.cache_inventory(cache)
            env={k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR')}
            home=private/'home';home.mkdir(exist_ok=True);temporary=private/'tmp';temporary.mkdir(exist_ok=True)
            env.update(HOME=str(home),TMPDIR=str(temporary),CRYSTAL_CACHE_DIR=str(cache),CRYSTAL_WORKERS='1',CRYSTAL_PATH='lib:'+str(prepared),MEMORY_BUDGET_REQUIRE_ALLOCATION='1',LC_ALL='C',NO_COLOR='1')
            format_label=profile+'-format';runner.run(format_label,[context['backend'],'tool','format','--check','--no-color',fixture],cwd=grant,environment=env,seconds=FORMAT)
            terminal(runner.records[-1],FORMAT,output=output);need(not stable(output/(format_label+'.stdout.txt')) and not stable(output/(format_label+'.stderr.txt')),'GREEN actual formatter required')
            need(all(digest(work/name)==sha for name,sha in working[profile].items()),'Exact working route source/manifest after formatter required')
            need(runner.deadline-time.monotonic()>=COMPILER,'Full original120-second compiler horizon required')
            argv=boundary.compiler_argv(context['backend'],fixture,work/'absent-output');boundary.require_command(argv,context['backend'],fixture,work/'absent-output')
            observer=Observer(driver,context['backend'],output/(profile+'-observer'),runner.deadline);observers.append(observer)
            label=profile+'-compile'
            raw,errors=observer.run(runner,label,argv,cwd=grant,environment=env,seconds=COMPILER)
            record=runner.records[-1];terminal(record,COMPILER,output=output);need(not errors,'Compiler stderr is RED/YELLOW; exact raw retained')
            need(all(digest(work/name)==sha for name,sha in working[profile].items()),'Exact working route source/manifest after compiler required')
            stats=parse(stable(output/(label+'.stdout.txt')));observation=observer.complete(record);result['observer_results'].append(observation)
            intervals=associate_observed_intervals(stats,observation['raw_observations']) if observation['live_samples'] else dict(passed=False,reason='No live direct compiler PID sample; phase stats remain separately observed',whole_build_provider_qualified=False)
            need(not (work/'absent-output').exists() and not (work/'absent-output').is_symlink(),'No-codegen top-level output must remain absent')
            after_cache=boundary.cache_inventory(cache);boundary.require_semantic_cache(cache_before,after_cache)
            need(audit_prepared_stdlib(context['stdlib'],prepared,overlay,manifest,output/(profile+'-STDLIB_AFTER.json'))==prepared_identity,'Exact SDK-prepared stdlib return required')
            rows,after=context['inventory'](grant);boundary.source_rows_equal(before,rows);need(after==fingerprint,'Full original source changed during route')
            sample=dict(profile=profile,source_format_projection=result['route_source_projections'][profile],source_sha256=digest(fixture),fixture_manifest_sha256=digest(work/'fixture.json'),source_argument=str(fixture),compiler_arguments=list(map(str,argv)),compiler_record=record,stats=stats,direct_compiler_observation=observation,phase_intervals=intervals,prepared_stdlib=prepared_identity,cache_before=cache_before,cache_after=after_cache,compiler_color='GREEN',actual_top_level_binary_absent=True)
            result['samples'].append(sample);write(output/(profile+'-RESULT.json'),sample)
        result.update(passed=True,diagnostic_complete=True,compiler_color='GREEN')
    except Exception as error:
        result['error']=type(error).__name__+': '+str(error)
        if runner.records and runner.records[-1]['label'].endswith(('-compile','-format')):
            last=runner.records[-1];diagnostics=(output/(last['label']+'.stdout.txt')).read_text()+(output/(last['label']+'.stderr.txt')).read_text()
            result['compiler_color']='RED' if last['exit_code']!=0 else 'YELLOW' if re.search(r'(?im)\bwarning(?:s)?\b',diagnostics) else 'GREEN'
    finally:
        try:
            context['check']()
            if before is not None:
                rows,fingerprint=context['inventory'](grant);boundary.source_rows_equal(before,rows);need(fingerprint==boundary.SOURCE,'Final full1554-source return required');write(output/'SOURCE_AFTER.json',dict(rows=rows,sha256=fingerprint))
                for profile,expected in working.items():
                    work=grant/'performance/results/frontend-diagnostic'/profile
                    need(all(digest(work/name)==sha and (work/name).stat().st_mode&0o777==0o644 for name,sha in expected.items()),'Complete original working fixture/manifest byte/mode return required')
                result['working_fixture_return']=working
            result['source_provider_return_accepted']=True
        except Exception as error:result['finalization_errors'].append('Source/provider return: '+str(error))
        result['commands']=runner.records;result['groups']=runner.group_observations
        result['observer_attempts']=[dict(profile=PROFILES[i],pid=getattr(o,'pid',None),metadata_commands=getattr(o.runner,'records',[]),metadata_groups=getattr(o.runner,'group_observations',[]),raw_observations=getattr(o,'samples',[]),errors=getattr(o,'errors',[]),thread_joined=o.thread is None or not o.thread.is_alive(),writers_confirmed_retired=o.runner.writers_confirmed_retired) for i,o in enumerate(observers)]
        result['command_count']=len(runner.records)
        result['writers_confirmed_retired']=runner.writers_confirmed_retired and all(o.thread is None or not o.thread.is_alive() for o in observers) and all(o.runner.writers_confirmed_retired for o in observers)
        try:
            if result['passed']:
                need([r['label'] for r in runner.records]==[label for p in PROFILES for label in (p+'-format',p+'-compile')],'Exact twelve original route commands required')
                for i,row in enumerate(runner.records):terminal(row,COMPILER if row['label'].endswith('-compile') else FORMAT,output=output,observation=runner.group_observations[i])
            if result['writers_confirmed_retired']:
                shutil.rmtree(private)
            else:result['finalization_errors'].append('Unresolved original compiler/observer writers; private inputs preserved')
        except Exception as error:result['finalization_errors'].append('Command/cleanup return: '+str(error))
        result['private_removed']=not private.exists();result['elapsed_seconds']=time.monotonic()-started
        if not (math.isfinite(result['elapsed_seconds']) and 0<=result['elapsed_seconds']<=SECONDS):result['finalization_errors'].append('Original900-second ladder horizon exceeded')
        result['passed']=result['diagnostic_complete']=result['passed'] and not result['finalization_errors'] and result['private_removed'] and result['writers_confirmed_retired']
        result['metric_coverage']=dict(stage_GC_capacity=bool(result['samples']),live_heap_bytes=False,direct_PID_RSS_sampled=all(r['direct_compiler_observation']['live_samples']>0 for r in result['samples']) and len(result['samples'])==6,internal_native_execution_absence=False,observer_overhead_qualified=False,full_target_cells_accepted=0)
        write(output/'COMMANDS.json',runner.records);write(output/'RESULT.json',result)
    return 0 if result['passed'] else 2

def main(args):
    started=time.monotonic();admit(args.packet_sha256)
    try:driver,context=admission(args)
    except Exception as error:
        need(not args.output.exists(),'Fresh admission-refusal output required');args.output.mkdir();write(args.output/'RESULT.json',dict(format='atlas-grant-hosted-frontend-admission-refusal-v1',passed=False,diagnostic_complete=False,error=type(error).__name__+': '+str(error),writers_confirmed_retired=True,private_removed=True,target_cells_accepted=0));return 2
    return execute(args,driver,context,started)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','driver','sdk-evidence','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python','ps'):p.add_argument('--'+name+'-sha256',required=True)
    raise SystemExit(main(p.parse_args()))
