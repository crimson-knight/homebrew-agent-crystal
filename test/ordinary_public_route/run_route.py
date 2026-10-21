"""Observe the ordinary public installer, then resume frozen use of retained providers."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

from route_support import ROOT,need,sha,read,write,stable,source_packet,revalidate,load_driver,inventory,catalog,verify_commands,extract_provider

ALPHA=read(ROOT/'inputs/ALPHA_MAIN.json')['main_commit']
SDK='6aaf4f953189c051bf11543e64d4c9f3f36e2cd3'
INSTALLER_URL='https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/22cb077900945471d7281b8f3f60633bc9ebf08e/install.sh'
INSTALLER_SHA='970e0e1c0d72cd9c3041220662d65d391edcac42eed7acb7849a7704817c9dcb'
TOTAL=7800
OBSERVE=4200
INSTALL=2700
SDK_SECONDS=840
CONSUMER=1800
RETURN_RESERVE=120
ALIAS=('acrystal','agent-crystal','crystal-alpha')
CLOCK_PROTOCOL='POSIX_CLOCK_MONOTONIC'

def retained_now():
    return time.clock_gettime(time.CLOCK_MONOTONIC)

def retained_runner_deadline(absolute,maximum,reserve=0):
    return time.monotonic()+min(maximum,absolute-retained_now()-reserve)


def clean_environment():
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR','GITHUB_ACTIONS','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_REPOSITORY','RUNNER_NAME','RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion')}
    env.update(HOMEBREW_NO_AUTO_UPDATE='1',HOMEBREW_NO_ANALYTICS='1',HOMEBREW_NO_INSTALL_CLEANUP='1',NONINTERACTIVE='1',CRYSTAL_WORKERS='1',PYTHONDONTWRITEBYTECODE='1',NO_COLOR='1')
    need(not any(k.startswith('AGENT_CRYSTAL_') for k in env),'Ordinary installer defaults require absent selection overrides')
    return env


def get_context(args):
    need(os.environ.get('GITHUB_ACTIONS')=='true' and (platform.system(),platform.machine()) in [('Darwin','arm64'),('Linux','x86_64')],'Hosted supported macOS ARM64/Linux x86_64 required')
    protected=source_packet(args.packet_sha256);driver=load_driver(getattr(args,'sdk_mode','source')=='bottle')
    providers={}
    for name in ('brew','git','curl','bash','python'):
        path=Path(getattr(args,name)).resolve(strict=True);row,_=stable(path)
        need(row['sha256']==getattr(args,name+'_sha256'),'Exact observed provider SHA required: '+name)
        providers[name]=row;protected[str(path)]=row['sha256']
    need(providers['python']['path']==str(Path(sys.executable).resolve()),'Same observed Python backend required')
    return driver,protected,providers


def run_command(runner,providers,label,tool,args,cwd,environment,seconds=30,expected_exit=0):
    need(len(runner.records)<96,'Finite outer command protocol required')
    need(runner.deadline-time.monotonic()>=seconds+2,'Complete original command maximum plus return reserve required')
    value=runner.run(label,[providers[tool]['path'],*map(str,args)],cwd=cwd,environment=environment,seconds=seconds,expected_exit=expected_exit)
    need(runner.records[-1]['maximum_seconds']==seconds,'Required command maximum remains unchanged')
    return value


def tap_readback(runner,providers,output,environment,phase):
    text,_=run_command(runner,providers,phase+'-tap-root','brew',['--repository','crimson-knight/agent-crystal'],output,environment)
    tap=Path(text.strip()).resolve(strict=True)
    head,_=run_command(runner,providers,phase+'-tap-commit','git',['-C',tap,'rev-parse','HEAD','HEAD^{tree}'],output,environment)
    tree=read(ROOT/'inputs/ALPHA_MAIN.json')['exact_tree']
    need(head.splitlines()==[ALPHA,tree],'Ordinary default tap must equal reviewed promoted main')
    remote,_=run_command(runner,providers,phase+'-tap-origin','git',['-C',tap,'remote','get-url','origin'],output,environment)
    need(remote.strip() in ('https://github.com/crimson-knight/homebrew-agent-crystal','https://github.com/crimson-knight/homebrew-agent-crystal.git'),'Actual public tap origin required')
    rows=read(ROOT/'inputs/ALPHA_FILES.json')['files']
    for row in rows:
        item,_=stable(tap/row['file']);need(item['sha256']==row['sha256'] and item['bytes']==row['bytes'] and item['mode']==(0o755 if row['mode']=='100755' else 0o644),'Exact ordinary tap working-tree source required')
    return {'path':str(tap),'commit':ALPHA,'tree':tree,'origin':remote.strip(),'files':rows}


def sdk_return(directory):
    result=read(directory/'READINESS_RESULT.json')
    need(result['passed'] is True and result['compiler_color']=='GREEN' and result['writers_confirmed_retired'] is True and result['private_cache_removed'] is True,'Actual GREEN SDK/source/original-group return required')
    for key,value in [('default_examples',39),('without_mt_examples',39),('installed_bundle_files',69),('tutorial_normal_exit',0),('tutorial_regression_exit',1)]:
        need(type(result[key]) is int and result[key]==value,'Exact public SDK count/status required: '+key)
    need(result['sdk_commit']=='58c20acfed71e27cbcf207014f29d7c7b53dab18','Exact accepted SDK source tree prerequisite required')
    before=read(directory/'STDLIB_BEFORE.json');need(before==read(directory/'STDLIB_AFTER.json'),'Exact returned installed standard library required')
    return result


def provider_candidate(output,providers):
    return {'format':'public-default-provider-candidate-v1','status':'UNADMITTED','execution_admitted':False,
        'alpha_default_commit':ALPHA,'public_SDK_main_commit':SDK,'accepted_SDK_tree_commit':'58c20acfed71e27cbcf207014f29d7c7b53dab18',
        'installed_providers':read(output/'sdk/PROVIDER_IDENTITIES.json'),'compiler_profile':read(output/'sdk/REVIEWED_COMPILER_PROFILE.json'),
        'original_tools':providers,'native_profile_accepted':False,'Git_provider_accepted':False,'Minecart_provider_accepted':False,
        'preparation_interfaces':['scripts/prepare_native_manifest.rb','scripts/prepare_git_manifest.rb','scripts/prepare_toolchain_profile.rb --inspect','scripts/prepare_toolchain_profile.rb'],
        'pending':['Independent native/Git/Minecart/source attribution review','Retained-provider schema-3 admission','Actual public SDK frozen consumer','Separate Amber/Grant/adapter/Micrate package-script and migration journey']}


def observe(args,driver,protected,providers):
    output=args.output.absolute();need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical retained workspace required');output.mkdir()
    started=time.monotonic();env=clean_environment();runner=driver.Runner(output);runner.deadline=started+OBSERVE
    result={'format':'ordinary-public-route-observation-v105','passed':False,'ordinary_installation_accepted':False,'SDK_readiness_accepted':False,
        'frozen_consumer_accepted':False,'native_profile_accepted':False,'Amber_V2_full_consumer_accepted':False,'adapter_Micrate_journey_accepted':False,
        'clock_protocol':CLOCK_PROTOCOL,'started_monotonic':retained_now(),'absolute_monotonic_deadline':None,'retained_review_maximum_seconds':900,'consumer_maximum_seconds':CONSUMER,
        'job_identity':{k:os.environ.get(k) for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_REPOSITORY','RUNNER_NAME')},
        'process_boot_session':Path('/proc/sys/kernel/random/boot_id').read_text().strip() if platform.system()=='Linux' else os.environ.get('RUNNER_NAME'),
        'finalization_errors':[],'Grant_target_cells_accepted':0}
    result['absolute_monotonic_deadline']=result['started_monotonic']+TOTAL
    sdk_groups_retired=True;catalog_snapshot=None;tap=None;core_identity=None;git_identity=None
    try:
        need(all(shutil.which(alias) is None for alias in ALIAS),'Fresh ordinary alias absence required')
        run=lambda label,tool,argv,seconds=30,expected=0:run_command(runner,providers,label,tool,argv,output,env,seconds,expected)
        absent,_=run('initial-formula-absence','brew',['list','--versions','agent-crystal'],expected=1);need(not absent.strip(),'Fresh ordinary formula absence requires an empty version roster')
        head,_=run('public-default-main','git',['ls-remote','https://github.com/crimson-knight/homebrew-agent-crystal.git','refs/heads/main'])
        need(head.split()==[ALPHA,'refs/heads/main'],'Current ordinary public main must equal reviewed source')
        run('homebrew-version','brew',['--version']);run('homebrew-config','brew',['config'])
        for tool in ('git','curl','bash','python'):run('observed-'+tool+'-version',tool,['--version'],15)
        brewroot,_=run('homebrew-repository','brew',['--repository']);homebrew_repo=Path(brewroot.strip()).resolve(strict=True)
        tap_location,_=run('initial-tap-location','brew',['--repository','crimson-knight/agent-crystal']);initial_tap=Path(tap_location.strip()).absolute()
        need(tap_location.strip() and not initial_tap.exists() and not initial_tap.is_symlink(),'Fresh public tap absence required')
        git_identity,_=run('homebrew-source','git',['-C',homebrew_repo,'rev-parse','HEAD','HEAD^{tree}'])
        need(len(git_identity.split())==2 and all(re.fullmatch('[0-9a-f]{40}',v) is not None for v in git_identity.split()),'Observed Homebrew source commit/tree required')
        cache,_=run('homebrew-cache','brew',['--cache']);cache=Path(cache.strip()).resolve(strict=True)
        write(output/'CATALOG_INITIAL.json',catalog(cache))
        installer=output/'public-install.sh'
        run('download-public-installer','curl',['--fail','--location','--silent','--show-error','--proto','=https','--tlsv1.2','--connect-timeout','15','--max-time','30','--max-filesize','1048576','--output',installer,INSTALLER_URL],45)
        need(stable(installer)[0]['sha256']==INSTALLER_SHA,'Public checksum installer source required')
        run('ordinary-default-install','bash',[installer],INSTALL)
        tap=tap_readback(runner,providers,output,env,'installed');need(tap['path']==str(initial_tap),'Actual default tap must equal its initial public location');result['ordinary_installation_accepted']=True
        prefix_text,_=run('actual-installed-prefix','brew',['--prefix','agent-crystal']);prefix=Path(prefix_text.strip()).resolve(strict=True)
        if getattr(args,'sdk_mode','source')=='bottle':
            accepted_row,accepted_raw=stable(args.bottle_acceptance)
            need(accepted_row['sha256']==args.bottle_acceptance_sha256,'Exact independently accepted published bottle receipt required')
            acceptance=json.loads(accepted_raw)
            need(acceptance['bottle_artifacts_reviewed'] is True,'Returned bottle/source/provider review is required before default bottle qualification')
            profile=acceptance['platforms'][platform.system()]['qualified_build_profile']
            need(stable(prefix/'libexec/agent-crystal-bin')[0]['sha256']==profile['compiler_sha256'],'Ordinary poured backend must equal independently qualified distributed provider')
        aliases={}
        for alias in ALIAS:
            lexical=Path(shutil.which(alias) or '').absolute();physical=lexical.resolve(strict=True)
            need(physical==prefix/'bin'/alias,'Each public alias must select this ordinary installation')
            aliases[alias]={'lexical':str(lexical),'physical':str(physical),'sha256':stable(physical)[0]['sha256']}
            protected[str(physical)]=aliases[alias]['sha256']
            run('alias-'+alias,'bash',['-c','exec "$1" --version','ordinary-alias',lexical])
        write(output/'ALIASES_BEFORE.json',aliases)
        run('installed-formula-tests','brew',['test','crimson-knight/agent-crystal/agent-crystal'],120)
        run('installed-dependency-metadata','brew',['info','--json=v2','--installed'],60)
        core=homebrew_repo/'Library/Taps/homebrew/homebrew-core'
        core_identity=None
        if core.is_dir():
            raw,_=run('homebrew-core-source','git',['-C',core,'rev-parse','HEAD','HEAD^{tree}']);core_identity=raw.splitlines()
        catalog_snapshot=catalog(cache);need(catalog_snapshot or core_identity,'Exact API catalog or core Git source identity required')
        write(output/'CATALOG_BEFORE.json',{'cache':str(cache),'API':catalog_snapshot,'homebrew_commit_tree':git_identity.splitlines(),'core_commit_tree':core_identity})
        (output/'resolved-catalog').mkdir()
        for name,row in catalog_snapshot.items():
            current,raw=stable(Path(row['path']));need(current==row,'Exact resolved API bytes required');(output/'resolved-catalog'/name).write_bytes(raw)
        write(output/'TAP_BEFORE.json',tap)
        need(runner.deadline-time.monotonic()>=SDK_SECONDS+RETURN_RESERVE,'Full original SDK840-second interval plus return reserve required')
        selected='bottle_vendor' if getattr(args,'sdk_mode','source')=='bottle' else 'vendor'
        lock=read(ROOT/selected/'test/sdk_source_lock.json');sdk_code=driver.qualify(output/'sdk',lock)
        sdk_raw=read(output/'sdk/READINESS_RESULT.json');sdk_groups_retired=sdk_raw.get('writers_confirmed_retired') is True
        need(sdk_code==0,'Original public SDK qualifier refused');sdk_return(output/'sdk');result['SDK_readiness_accepted']=True
        result['SDK_artifact_roster']=inventory(output/'sdk',128)
        profile=provider_candidate(output,providers);write(output/'DRAFT_PROVIDER_CANDIDATE.json',profile)
        result['pending_refusal']='Frozen consumer requires separately reviewed actual schema-3/native/Git/Minecart inputs on this retained provider'
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected)
            if tap is not None and runner.writers_confirmed_retired and sdk_groups_retired:
                need(tap_readback(runner,providers,output,env,'returned')==tap,'Exact default tap source required on return')
            if git_identity is not None and runner.writers_confirmed_retired and sdk_groups_retired:
                returned,_=run_command(runner,providers,'homebrew-source-return','git',['-C',homebrew_repo,'rev-parse','HEAD','HEAD^{tree}'],output,env)
                need(returned==git_identity,'Homebrew source commit/tree changed on return')
            if core_identity is not None and runner.writers_confirmed_retired and sdk_groups_retired:
                returned,_=run_command(runner,providers,'homebrew-core-return','git',['-C',core,'rev-parse','HEAD','HEAD^{tree}'],output,env)
                need(returned.splitlines()==core_identity,'Homebrew core source commit/tree changed on return')
            if catalog_snapshot is not None:
                after=catalog(cache);need(after==catalog_snapshot,'Resolved public catalog changed during qualification');write(output/'CATALOG_AFTER.json',after)
            if 'aliases' in locals():
                for item in aliases.values():need(str(Path(item['lexical']).resolve(strict=True))==item['physical'] and stable(item['physical'])[0]['sha256']==item['sha256'],'Public alias changed on return')
                write(output/'ALIASES_AFTER.json',aliases)
            verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['writers_confirmed_retired']=runner.writers_confirmed_retired and sdk_groups_retired
        result['original_group_observations']=runner.group_observations;result['terminal_elapsed_seconds']=time.monotonic()-started
        if result['terminal_elapsed_seconds']>OBSERVE:result['finalization_errors'].append('Complete observation deadline exceeded')
        result['observation_complete']=result['ordinary_installation_accepted'] and result['SDK_readiness_accepted'] and 'error' not in result and not result['finalization_errors'] and result['writers_confirmed_retired']
        result['observed_providers']=providers;result['source_return_protected']=protected
        write(output/'OBSERVATION_RESULT.json',result)
    return 2


def consumer_admission(path,expected,result,output):
    row,raw=stable(path,64*2**20);need(row['sha256']==expected,'Exact independently selected consumer admission required')
    admission=json.loads(raw)
    need(admission['execution_admitted'] is True and admission['status']=='PARENT_AND_PEER_REVIEWED_SOURCE_PROVIDER_INPUTS','Full consumer admission remains a real gate')
    need(admission['observation_sha256']==stable(output/'OBSERVATION_RESULT.json')[0]['sha256'] and admission['job_identity']==result['job_identity'],'Same actual observation/job identity required')
    need(admission['alpha_commit']==ALPHA and admission['sdk_commit']==SDK,'Exact promoted public source required')
    need(all(type(admission[key]) is str and re.fullmatch('[0-9a-f]{64}',admission[key]) is not None for key in ('parent_receipt_sha256','peer_receipt_sha256')),'Independent parent/peer source-provider receipt pins required')
    profile_text=admission['profile_text'];need(type(profile_text) is str and len(profile_text.encode())<=1024*1024,'Exact bounded reviewed profile bytes required')
    profile=json.loads(profile_text);need(type(profile['schema_version']) is int and profile['schema_version']==3,'Frozen installation requires schema3')
    observed=read(output/'sdk/REVIEWED_COMPILER_PROFILE.json')
    for field in ('compiler_sha256','wrapper_sha256','stdlib_sha256','ruby_sha256','ruby_launcher_sha256','counter_protocol'):
        need(profile[field]==observed[field],'Retained actual compiler/Ruby/stdlib profile identity required')
    native=admission['native_manifest_text'];git=admission['git_manifest_text'];need(type(native) is str and type(git) is str,'Original reviewed native/Git manifest bytes required')
    json.loads(native);json.loads(git)
    need(sha(native.encode())==profile['native_component_manifest_sha256'] and sha(git.encode())==profile['git_provider_manifest_sha256'],'Exact native/Git manifest byte joins required')
    return admission,profile,profile_text,native,git


def retained_deadline(result):
    need(result['clock_protocol']==CLOCK_PROTOCOL,'Common host-wide monotonic clock protocol required')
    values=[result['started_monotonic'],result['absolute_monotonic_deadline']]
    need(all(type(v) in (int,float) and math.isfinite(v) and v>=0 for v in values),'Exact finite retained monotonic bounds required')
    need(result['absolute_monotonic_deadline']==result['started_monotonic']+TOTAL,'Original complete retained deadline must remain exact')
    need(result['started_monotonic']<=retained_now()<=result['absolute_monotonic_deadline'],'Same live retained monotonic interval required')
    return result['absolute_monotonic_deadline']


def resume(args,driver,protected,providers):
    output=args.output.resolve(strict=True);old=read(output/'OBSERVATION_RESULT.json');started=time.monotonic()
    result={'format':'ordinary-public-route-frozen-return-v105','passed':False,'frozen_consumer_accepted':False,'Amber_V2_full_consumer_accepted':False,'adapter_Micrate_journey_accepted':False,'Grant_target_cells_accepted':0,'finalization_errors':[]}
    runner=driver.Runner(output/'consumer-command-output');runner.deadline=retained_runner_deadline(old['absolute_monotonic_deadline'],CONSUMER,RETURN_RESERVE)
    try:
        retained_deadline(old)
        need(old['observation_complete'] is True and old['writers_confirmed_retired'] is True,'Complete returned ordinary installation/SDK observation required')
        need(retained_now()-old['started_monotonic']<=TOTAL and old['absolute_monotonic_deadline']-RETURN_RESERVE-retained_now()>=CONSUMER,'All original1800 consumer seconds must remain within retained7800-second horizon')
        need(old['job_identity']=={k:os.environ.get(k) for k in old['job_identity']},'Same retained runner/job identity required')
        need(old['observed_providers']==providers,'Same actual original providers required');revalidate(old['source_return_protected']);sdk_return(output/'sdk')
        need(inventory(output/'sdk',128)==old['SDK_artifact_roster'],'Exact reviewed SDK artifact bytes required through the hold')
        admission,profile,profile_text,native,git=consumer_admission(args.admission,args.admission_sha256,old,output)
        runner.output.mkdir()
        current=read(output/'sdk/PROVIDER_IDENTITIES.json')
        for row in current.values():need(stable(Path(row['path']))[0]['sha256']==row['sha256'],'Actual retained installed provider changed')
        consumer=output/'consumer';consumer.mkdir();shutil.copyfile(ROOT/'consumer/shard.yml',consumer/'shard.yml')
        public=read(ROOT/'inputs/SDK_MAIN.json');archive=output/'public-SDK-main.tar.gz';env=clean_environment()
        run_command(runner,providers,'download-public-SDK','curl',['--fail','--location','--silent','--show-error','--proto','=https','--tlsv1.2','--connect-timeout','15','--max-time','45','--max-filesize',public['anonymous_archive']['bytes'],'--output',archive,public['anonymous_archive']['url']],output,env,60)
        lock=read(ROOT/'vendor/test/sdk_source_lock.json')['sdk'];lock.update(commit=SDK,archive_sha256=public['anonymous_archive']['sha256'],archive_bytes=public['anonymous_archive']['bytes'])
        source=output/'public-SDK-main';driver.extract_sdk(archive,source,lock);driver.verify_source(source,lock['files'])
        inputdir=output/'admitted-inputs';inputdir.mkdir();(inputdir/'profile.json').write_text(profile_text);(inputdir/'native.json').write_text(native);(inputdir/'git.json').write_text(git)
        if 'minecart_distribution' in admission:
            package=admission['minecart_distribution'];need(package['url'].startswith('https://github.com/crimson-knight/shards/releases/download/'),'Reviewed public Minecart release origin required')
            archive=output/'minecart-provider.tar.gz'
            run_command(runner,providers,'download-reviewed-minecart','curl',['--fail','--location','--silent','--show-error','--proto','=https','--tlsv1.2','--connect-timeout','15','--max-time','30','--max-filesize',package['bytes'],'--output',archive,package['url']],output,env,45)
            extraction=output/'reviewed-tools';roster=extract_provider(archive,extraction,package);write(output/'MINECART_PROVIDER_ROSTER.json',roster)
            need(package['executable'] in {r['path'] for r in roster},'Exact reviewed provider executable member required')
            minecart=(extraction/package['executable']).resolve(strict=True)
        else:minecart=Path(admission['minecart_path']).resolve(strict=True)
        need(stable(minecart)[0]['sha256']==profile['minecart_sha256'],'Reviewed actual Minecart binary required')
        ruby=current['ruby_launcher']['path'];compiler=current['compiler_wrapper']['path'];stdlib=Path(current['compiler_backend']['path']).parent.parent/'share/agent-crystal/src'
        env.update(MEMORY_BUDGET_COMPILER=compiler,MEMORY_BUDGET_STDLIB=str(stdlib),MEMORY_BUDGET_RUBY_LAUNCHER=ruby,MEMORY_BUDGET_MINECART=str(minecart),MEMORY_BUDGET_TOOLCHAIN_LOCK=str(inputdir/'profile.json'),MEMORY_BUDGET_TOOLCHAIN_PROFILE_SHA256=stable(inputdir/'profile.json')[0]['sha256'],MEMORY_BUDGET_NATIVE_COMPONENT_LOCK=str(inputdir/'native.json'),MEMORY_BUDGET_GIT_PROVIDER_LOCK=str(inputdir/'git.json'))
        pinned={str(consumer/'shard.yml'):stable(consumer/'shard.yml')[0]['sha256']}
        run_command(runner,providers,'consumer-install-bundle','bash',['-c','exec "$1" "$2" "$3"','install-sdk',ruby,source/'scripts/install_bundle.rb',consumer],consumer,env,30)
        bundle=consumer/'performance/vendor/memory_budget';manifest=next(row['sha256'] for row in lock['files'] if row['file']=='PACKAGE_PINS.json');before=driver.verify_bundle(bundle,manifest)
        run_command(runner,providers,'consumer-profile','bash',['-c','exec "$1" "$2" --json','profile',ruby,bundle/'scripts/toolchain_profile.rb'],consumer,env,30)
        run_command(runner,providers,'consumer-write-lock','bash',['-c','exec "$1" "$2" "$3" "$4"','writer',ruby,ROOT/'write_consumer_lock.rb',bundle/'scripts/toolchain_profile.rb',bundle],consumer,env,600)
        lock_text,_=run_command(runner,providers,'consumer-lock-check','bash',['-c','exec "$1" "$2" "$3"','lock',ruby,ROOT/'validate_consumer_lock.rb',ROOT/'consumer/EXPECTED_LOCK.yml'],consumer,env,15)
        write(output/'FROZEN_LOCK_RECEIPT.json',json.loads(lock_text));pinned[str(consumer/'shard.lock')]=stable(consumer/'shard.lock')[0]['sha256']
        run_command(runner,providers,'consumer-frozen-install','bash',['-c','exec "$1" "$2"','frozen',ruby,bundle/'scripts/install_frozen_dependencies.rb'],consumer,env,600)
        revalidate(pinned);driver.verify_source(consumer/'lib/memory_budget',lock['files'])
        stdout,stderr=run_command(runner,providers,'consumer-budget-spec','bash',['-c','exec "$1" "$2" spec "$3" -Dfiber_allocation_tally -Dwithout_mt','budget',ruby,bundle/'scripts/budget.rb','lib/memory_budget/docs/0.1.1/examples/fiber_budget_spec.cr'],consumer,env,120)
        driver.verify_spec_result(stdout,stderr,1);need(driver.verify_bundle(bundle,manifest)==before,'Returned installed consumer bundle must remain exact')
        revalidate(pinned);driver.verify_source(source,lock['files']);need(stable(minecart)[0]['sha256']==profile['minecart_sha256'],'Minecart changed on return')
        shutil.copyfile(consumer/'performance/results/dependency-toolchain.json',output/'FROZEN_DEPENDENCY_RECEIPT.json')
        result['frozen_consumer_accepted']=True;result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:revalidate(protected);revalidate(old['source_return_protected']);verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['finalization_errors'].append(type(error).__name__+': '+str(error));result['passed']=False
        if runner.writers_confirmed_retired:
            for path in (output/'consumer',output/'public-SDK-main'):
                if path.exists():
                    try:shutil.rmtree(path)
                    except Exception as error:result['passed']=False;result['finalization_errors'].append('Owned consumer cleanup: '+str(error))
        result['private_consumer_removed']=not (output/'consumer').exists() and not (output/'public-SDK-main').exists()
        result['writers_confirmed_retired']=runner.writers_confirmed_retired;result['original_groups']=runner.group_observations
        result['elapsed_seconds']=time.monotonic()-started;result['absolute_monotonic_deadline']=old['absolute_monotonic_deadline']
        if result['elapsed_seconds']>CONSUMER or retained_now()>old['absolute_monotonic_deadline']:result['passed']=False;result['finalization_errors'].append('Complete retained consumer deadline exceeded')
        write(output/'CONSUMER_RESULT.json',result)
    return 0 if result['passed'] else 2


def main(args):
    driver,protected,providers=get_context(args)
    return observe(args,driver,protected,providers) if args.mode=='observe' else resume(args,driver,protected,providers)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',choices=['observe','resume'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True)
    for name in ('brew','git','curl','bash','python'):parser.add_argument('--'+name,type=Path,required=True);parser.add_argument('--'+name+'-sha256',required=True)
    parser.add_argument('--sdk-mode',choices=['source','bottle'],default='source');parser.add_argument('--bottle-acceptance',type=Path);parser.add_argument('--bottle-acceptance-sha256')
    parser.add_argument('--admission',type=Path);parser.add_argument('--admission-sha256');raise SystemExit(main(parser.parse_args()))
