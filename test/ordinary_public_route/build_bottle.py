"""Build an unadmitted normal Homebrew bottle and retain exact qualification inputs."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import time
from urllib.parse import urlsplit

from route_support import catalog,ROOT,need,sha,read,write,stable,revalidate,inventory,verify_commands
from run_route import get_context,clean_environment,run_command,tap_readback,sdk_return,ALPHA,SDK

ROOT_URL='https://github.com/crimson-knight/homebrew-agent-crystal/releases/download/agent-crystal-1.21.0-incremental-1_2-bottle.1'

def archive_roster(path):
    rows=[];total=0
    with tarfile.open(path,'r:gz') as archive:
        for index,member in enumerate(archive):
            name=member.name.rstrip('/');relative=PurePosixPath(name)
            need(index<4096 and str(relative)==name and not relative.is_absolute() and '..' not in relative.parts,'Finite contained bottle header roster required')
            need(member.isfile() or member.isdir() or member.issym(),'Bottle metadata admits ordinary files/directories and explicit aliases')
            row={'path':name,'mode':member.mode,'bytes':member.size,'kind':'file' if member.isfile() else 'directory' if member.isdir() else 'symlink'}
            if member.isfile():
                need(member.size<=128*2**20,'Bounded bottle file required');raw=archive.extractfile(member).read(128*2**20+1)
                need(len(raw)==member.size,'Complete bottle member bytes required');row['sha256']=sha(raw);total+=len(raw);need(total<=256*2**20,'Finite expanded bottle bytes required')
            if member.issym():row['target']=member.linkname
            rows.append(row)
    need(len({r['path'] for r in rows})==len(rows),'Distinct bottle headers required')
    backends=[r for r in rows if r['path'].endswith('/libexec/agent-crystal-bin')];need(len(backends)==1 and backends[0]['kind']=='file','Exact complete distributed compiler backend member required')
    return {'files':rows,'archive_backend':backends[0],'expanded_bytes':total,'native_profile_accepted':False,'scope':'Exact returned archive members; installed-prefix relocation and loader qualification remain separate'}


def bottle_inputs(directory,root_url):
    json_files=list(directory.glob('*.bottle.json'));archives=list(directory.glob('*.bottle.tar.gz'))
    need(len(json_files)==len(archives)==1,'One bottle JSON and one complete bottle archive required')
    row,raw=stable(json_files[0],16*2**20);data=json.loads(raw)
    need(set(data)=={'crimson-knight/agent-crystal/agent-crystal'},'Exact formula bottle JSON key required')
    item=next(iter(data.values()));formula=item['formula'];bottle=item['bottle']
    need(formula['name']=='agent-crystal' and formula['pkg_version']=='1.21.0-incremental-1_2' and formula['tap_git_revision']==ALPHA,'Exact selected formula/source revision required')
    need(formula['tap_git_remote'] in ('https://github.com/crimson-knight/homebrew-agent-crystal','https://github.com/crimson-knight/homebrew-agent-crystal.git'),'Public source recipe origin required')
    need(bottle['root_url']==root_url and type(bottle['rebuild']) is int and bottle['rebuild']==0,'Exact reviewed bottle release root and rebuild required')
    need(len(bottle['tags'])==1,'One actual platform bottle per job required')
    tag,metadata=next(iter(bottle['tags'].items()));need(tag in ('arm64_tahoe','x86_64_linux'),'Supported actual bottle platform tag required')
    need(metadata['local_filename']==archives[0].name and re.fullmatch(r'[A-Za-z0-9_.%+@-]+',metadata['filename']) is not None,'Contained exact bottle filename required')
    archive,_=stable(archives[0],128*2**20);need(archive['sha256']==metadata['sha256'],'Complete returned bottle hash must equal Homebrew JSON')
    return {'json':row,'archive':archive,'tag':tag,'cellar':bottle['cellar'],'rebuild':bottle['rebuild'],'filename':metadata['filename'],'local_filename':metadata['local_filename'],'root_url':root_url,'tap_commit':ALPHA,'source_version':'1.21.0-incremental-1','formula_revision':2}

def portable_bottle_identity(row):
    normalized=dict(row)
    for key in ('json','archive'):normalized[key]={k:v for k,v in row[key].items() if k!='mode'};normalized[key]['path']=Path(row[key]['path']).name
    return normalized


def build(args,driver,protected,providers):
    output=args.output.absolute();need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical bottle workspace required');output.mkdir()
    env=clean_environment();started=time.monotonic();runner=driver.Runner(output);runner.deadline=started+4500
    result={'format':'alpha-bottle-preparation-v105','passed':False,'release_publication_admitted':False,'bottle_provider_accepted':False,'finalization_errors':[],'compiler_source_version':'1.21.0-incremental-1','Grant_target_cells_accepted':0}
    sdk_retired=True;tap=None;brew_identity=None;catalog_snapshot=None;core_identity=None
    try:
        need(args.root_url==ROOT_URL,'Exact reviewed release-root version required')
        run=lambda label,tool,argv,seconds=30,expected=0:run_command(runner,providers,label,tool,argv,output,env,seconds,expected)
        run('initial-formula-absence','brew',['list','--versions','agent-crystal'],expected=1)
        run('homebrew-version','brew',['--version']);run('homebrew-config','brew',['config'])
        root_text,_=run('homebrew-repository','brew',['--repository']);brew_repo=Path(root_text.strip()).resolve(strict=True)
        brew_identity,_=run('homebrew-source','git',['-C',brew_repo,'rev-parse','HEAD','HEAD^{tree}'])
        cache_text,_=run('homebrew-cache','brew',['--cache']);cache=Path(cache_text.strip()).resolve(strict=True)
        run('tap-public-default','brew',['tap','crimson-knight/agent-crystal'],120)
        tap=tap_readback(runner,providers,output,env,'before-bottle');write(output/'TAP_BEFORE.json',tap)
        run('build-for-normal-bottle','brew',['install','--build-bottle','crimson-knight/agent-crystal/agent-crystal'],2700)
        run('installed-dependency-metadata','brew',['info','--json=v2','--installed'],60)
        run('create-bottle','brew',['bottle','--json','--no-rebuild','--root-url',ROOT_URL,'crimson-knight/agent-crystal/agent-crystal'],300)
        returned=bottle_inputs(output,ROOT_URL);write(output/'BOTTLE_INPUTS.json',returned)
        write(output/'BOTTLE_ARCHIVE_ROSTER.json',archive_roster(Path(returned['archive']['path'])))
        catalog_snapshot=catalog(cache);core=brew_repo/'Library/Taps/homebrew/homebrew-core'
        if core.is_dir():
            text,_=run('homebrew-core-source','git',['-C',core,'rev-parse','HEAD','HEAD^{tree}']);core_identity=text.splitlines()
        need(catalog_snapshot or core_identity,'Actual resolved core/API source identity required')
        write(output/'CATALOG_BEFORE.json',{'API':catalog_snapshot,'homebrew_commit_tree':brew_identity.splitlines(),'core_commit_tree':core_identity})
        (output/'resolved-catalog').mkdir()
        for name,row in catalog_snapshot.items():
            current,raw=stable(row['path']);need(current==row,'Exact resolved API bytes required');(output/'resolved-catalog'/name).write_bytes(raw)
        need(runner.deadline-time.monotonic()>=840+180,'Full original SDK840 seconds plus return reserve required')
        code=driver.qualify(output/'sdk',read(ROOT/'vendor/test/sdk_source_lock.json'))
        sdk_retired=read(output/'sdk/READINESS_RESULT.json').get('writers_confirmed_retired') is True
        need(code==0,'SDK source build readiness must succeed after bottling');sdk_return(output/'sdk')
        write(output/'DRAFT_BOTTLE_PROVIDER.json',{'status':'UNADMITTED','execution_admitted':False,'bottle':returned,'SDK_source_tree':SDK,
            'qualified_build_provider':read(output/'sdk/PROVIDER_IDENTITIES.json'),'qualified_build_profile':read(output/'sdk/REVIEWED_COMPILER_PROFILE.json'),
            'native_qualification':False,'pending':['Independent returned bottle/recipe/provider review','Checksum publication and coupled formula/SDK lock source review','Fresh ordinary installer actual bottle pour','Native/Git/schema3 and frozen consumer/device proof']})
        need(bottle_inputs(output,ROOT_URL)==returned,'Returned bottle/source bytes must remain exact')
        result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected)
            if runner.writers_confirmed_retired and sdk_retired:
                if tap is not None:need(tap_readback(runner,providers,output,env,'after-bottle')==tap,'Exact public source return required')
                if brew_identity is not None:
                    text,_=run('homebrew-source-return','git',['-C',brew_repo,'rev-parse','HEAD','HEAD^{tree}']);need(text==brew_identity,'Homebrew source changed on return')
                if core_identity is not None:
                    text,_=run('homebrew-core-return','git',['-C',core,'rev-parse','HEAD','HEAD^{tree}']);need(text.splitlines()==core_identity,'Core source changed on return')
            if catalog_snapshot is not None:
                after=catalog(cache);need(after==catalog_snapshot,'Resolved dependency catalog changed on return');write(output/'CATALOG_AFTER.json',after)
            verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['observed_providers']=providers;result['source_return_protected']=protected
        result['writers_confirmed_retired']=runner.writers_confirmed_retired and sdk_retired;result['original_groups']=runner.group_observations
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>4500 or not result['writers_confirmed_retired']:result['passed']=False;result['finalization_errors'].append('Complete bottle deadline/original return refused')
        write(output/'BOTTLE_RESULT.json',result)
    return 0 if result['passed'] else 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True);parser.add_argument('--root-url',default=ROOT_URL)
    for name in ('brew','git','curl','bash','python'):parser.add_argument('--'+name,type=Path,required=True);parser.add_argument('--'+name+'-sha256',required=True)
    args=parser.parse_args();raise SystemExit(build(args,*get_context(args)))
