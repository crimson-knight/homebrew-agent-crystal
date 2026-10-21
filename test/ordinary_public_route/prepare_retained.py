"""Return unadmitted SDK native/Git preparation bytes on the retained installation."""
import argparse
import os
from pathlib import Path
import shutil
import time
from route_support import ROOT,need,read,write,stable,inventory,verify_commands,revalidate
from run_route import get_context,run_command,clean_environment,retained_deadline,retained_runner_deadline


def bounded_roots(roots,maximum_bytes=2*1024**3,maximum_nodes=8192,seconds=30):
    deadline=time.monotonic()+seconds;seen=set();total=nodes=0
    for root in roots:
        root=Path(root);need(root.resolve(strict=True)==root and root.is_dir() and not root.is_symlink(),'Physical versioned candidate library root required')
        def unreadable(error):raise error
        for directory,dirs,files in os.walk(root,followlinks=False,onerror=unreadable):
            for name in dirs+files:
                need(time.monotonic()<deadline,'Finite native-candidate census deadline exceeded')
                path=Path(directory)/name;stat=path.lstat();nodes+=1;need(nodes<=maximum_nodes,'Finite native-candidate node count exceeded')
                need(path.is_symlink() or path.is_file() or path.is_dir(),'Native candidate physical node kind requires review')
                if path.is_file() and not path.is_symlink() and (stat.st_dev,stat.st_ino) not in seen:
                    seen.add((stat.st_dev,stat.st_ino));total+=stat.st_size;need(total<=maximum_bytes,'Finite native-candidate file byte budget exceeded')
    return {'physical_file_bytes':total,'physical_nodes':nodes,'maximum_bytes':maximum_bytes,'maximum_nodes':maximum_nodes,'scope':'unadmitted metadata census; link/load closure pending'}


def prepare(args,driver,protected,providers):
    output=args.output.resolve(strict=True);old=read(output/'OBSERVATION_RESULT.json');directory=output/'provider-preparation';directory.mkdir();runner=driver.Runner(directory);started=time.monotonic();runner.deadline=retained_runner_deadline(retained_deadline(old),210,1920)
    result={'status':'UNADMITTED','execution_admitted':False,'native_manifest_prepared':False,'Git_manifest_prepared':False,'inspection_prepared':False,'finalization_errors':[]}
    try:
        need(old['observation_complete'] is True and old['writers_confirmed_retired'] is True,'Returned ordinary provider must precede preparation')
        need(inventory(output/'sdk',128)==old['SDK_artifact_roster'],'Exact reviewed SDK input bytes required before preparation')
        sdk=directory/'sdk-source';lock=read(ROOT/'vendor/test/sdk_source_lock.json')['sdk'];driver.extract_sdk(output/'sdk/sdk-source.tar.gz',sdk,lock);driver.verify_source(sdk,lock['files'])
        installed=read(output/'sdk/PROVIDER_IDENTITIES.json');prefix=Path(installed['compiler_backend']['path']).parent.parent
        brewroot=Path((output/'sdk/brew-root.stdout.txt').read_text().strip()).resolve(strict=True)
        receipt=read(output/'sdk/INSTALL_RECEIPT.json');roots=[]
        for row in receipt['runtime_dependencies']:
            name=row['full_name'].rsplit('/',1)[-1];need(name and '/' not in name and '..' not in name,'Literal actual receipt dependency required')
            path=brewroot/'opt'/name/'lib'
            if path.is_dir():
                physical=path.resolve(strict=True);need(physical.is_relative_to(brewroot/'Cellar'),'Actual installed native dependency must belong to the declared Cellar');roots.append(str(physical))
        roots=sorted(set(roots));need(roots,'Nonempty actual runtime library roots required');write(directory/'NATIVE_CENSUS.json',bounded_roots(roots))
        linux=os.environ.get('RUNNER_OS')=='Linux';loader='LD_LIBRARY_PATH' if linux else 'DYLD_LIBRARY_PATH'
        config={'schema_version':2,'loader_family':'elf_ld' if linux else 'darwin_dyld','profile':'UNADMITTED-ordinary-retained-native','environment':{'CRYSTAL_LIBRARY_PATH':roots,loader:roots,'PKG_CONFIG_LIBDIR':[],'PKG_CONFIG_PATH':[]},'files':[],'loader_trace':False}
        write(directory/'NATIVE_ROOTS.proposed.json',config)
        version=(output/'observed-git-version.stdout.txt').read_text().strip()
        git={'profile':'UNADMITTED-ordinary-retained-git','git_path':providers['git']['path'],'git_sha256':providers['git']['sha256'],'git_version':version,'delegate_directory':str(directory/'git-delegate')};write(directory/'GIT_ROOTS.proposed.json',git)
        env=clean_environment();ruby=installed['ruby_launcher']['path']
        for label,script,inputfile,target in [('native-candidate','prepare_native_manifest.rb','NATIVE_ROOTS.proposed.json','NATIVE_MANIFEST.draft.json'),('Git-candidate','prepare_git_manifest.rb','GIT_ROOTS.proposed.json','GIT_MANIFEST.draft.json')]:
            stdout,_=run_command(runner,providers,label,'bash',['-c','exec "$1" "$2" "$3"','SDK-candidate',ruby,sdk/'scripts'/script,directory/inputfile],directory,env,60)
            (directory/target).write_text(stdout);read(directory/target);result['native_manifest_prepared' if label=='native-candidate' else 'Git_manifest_prepared']=True
        source_lock=read(ROOT/'vendor/test/sdk_source_lock.json')
        attribution={'schema_version':1,'status':'UNADMITTED_SOURCE_ATTRIBUTION','compiler_source_commit':source_lock['alpha']['source_commit'],
            'compiler_backend_sha256':installed['compiler_backend']['sha256'],'stdlib_sha256':source_lock['alpha']['stdlib_sha256'],
            'source_url':'https://github.com/crimson-knight/crystal/archive/refs/tags/v1.21.0-incremental-1.tar.gz','source_archive_sha256':source_lock['alpha']['source_archive_sha256'],
            'installation_receipt_sha256':[stable(output/'sdk/INSTALL_RECEIPT.json')[0]['sha256']]};write(directory/'COMPILER_SOURCE_ATTRIBUTION.draft.json',attribution)
        minecart=shutil.which('minecart');paths={'profile':'UNADMITTED-ordinary-retained-schema3','compiler_entrypoint':installed['compiler_wrapper']['path'],
            'stdlib_root':str(prefix/'share/agent-crystal/src'),'ruby_launcher':ruby,'minecart_path':minecart or str(directory/'MINECART_REQUIRES_REVIEW'),
            'compiler_source_commit':source_lock['alpha']['source_commit'],'compiler_version':(output/'sdk/alpha-version.stdout.txt').read_text(),
            'compiler_provenance':str(directory/'COMPILER_SOURCE_ATTRIBUTION.draft.json'),'minecart_version':'Minecart 2025.11.25.8',
            'native_manifest':str(directory/'NATIVE_MANIFEST.draft.json'),'git_manifest':str(directory/'GIT_MANIFEST.draft.json'),
            'provenance_files':[str(output/'sdk/INSTALL_RECEIPT.json'),str(output/'sdk/INSTALLED_FORMULA.rb'),str(output/'sdk/SOURCE_LOCK.json')]};write(directory/'PROFILE_INSPECTION_PATHS.json',paths)
        stdout,stderr=run_command(runner,providers,'profile-inspection','bash',['-c','exec "$1" "$2" --inspect "$3"','profile-inspect',ruby,sdk/'scripts/prepare_toolchain_profile.rb',directory/'PROFILE_INSPECTION_PATHS.json'],directory,env,15,0 if minecart else 1)
        if minecart:
            (directory/'PROFILE_INSPECTION.unreviewed.json').write_text(stdout);result['inspection_prepared']=True
        else:result['profile_inspection_refusal']='Actual Minecart provider is absent; SDK inspect returned its recorded nonzero refusal'
        result['pending_refusal']='Independent complete native/Git/provider/source attribution and Minecart review precedes schema3 execution admission'
        driver.verify_source(sdk,lock['files'])
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            verify_commands(runner.records,runner.group_observations);revalidate(protected);revalidate(old['source_return_protected'])
            for row in read(output/'sdk/PROVIDER_IDENTITIES.json').values():need(stable(row['path'])[0]['sha256']==row['sha256'],'Installed provider changed during preparation')
        except Exception as error:result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['writers_confirmed_retired']=runner.writers_confirmed_retired;result['original_groups']=runner.group_observations;result['elapsed_seconds']=time.monotonic()-started
        result['metadata_complete']=result['native_manifest_prepared'] and result['Git_manifest_prepared'] and result['inspection_prepared'] and not result['finalization_errors'] and result['writers_confirmed_retired']
        write(output/'PROVIDER_PREPARATION_RESULT.json',result)
    return 0 if result['metadata_complete'] else 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True)
    for name in ('brew','git','curl','bash','python'):parser.add_argument('--'+name,type=Path,required=True);parser.add_argument('--'+name+'-sha256',required=True)
    args=parser.parse_args();raise SystemExit(prepare(args,*get_context(args)))
