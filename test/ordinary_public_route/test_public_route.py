"""Guarded public-route/provider and bottle controls; all compiler/native providers are synthetic."""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import route_support as support
import run_route as route
import build_bottle as bottle
import finalize_bottle as finalize
import prepare_retained
import stage_results
GUARD_CALLS=[]
FIXTURES=Path(os.environ.get('ORDINARY_ROUTE_FIXTURE_ROOT',str(ROOT.parent/'fixtures')))

class PublicRouteControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='public route source controls with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guarded(*args,**settings):GUARD_CALLS.append('external');raise AssertionError('Guarded source fixture requires authored process provider')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.guards.enter_context(mock.patch(target,side_effect=guarded))
        self.addCleanup(lambda:self.assertEqual(GUARD_CALLS,[]))
    def source_file(self,name,data=b'SYNTHETIC provider'):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o755);return p
    def full_observe(self,scenario='normal'):
        output=self.root/'retained';tap=self.root/'tap';tap_fixture=self.root/'tap source fixture';tap_fixture.mkdir();prefix=self.root/'prefix';(prefix/'bin').mkdir(parents=True)
        archive=ROOT/'inputs/public-alpha-main.tar.gz';self.assertEqual(support.stable(archive)[0]['sha256'],'1fc53c2285e208497bf3cb58fb6b36a4ec44eb4ea4a14442766ee9cce7aaccc4')
        with tarfile.open(archive,'r:gz') as stream:
            for member in stream:
                if member.isfile():
                    p=tap_fixture/member.name.split('/',1)[1];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(stream.extractfile(member).read());p.chmod(0o755 if member.mode&0o111 else 0o644)
        brewrepo=self.root/'brewrepo';brewrepo.mkdir();cache=self.root/'cache';(cache/'api').mkdir(parents=True);(cache/'api/formula.jws.json').write_text('SYNTHETIC public catalog')
        providers={name:support.stable(self.source_file('provider-'+name))[0] for name in ('brew','git','curl','bash','python')}
        for alias in route.ALIAS:self.source_file('prefix/bin/'+alias,b'SYNTHETIC static admitted alias')
        installed=[False];outer=self
        class Runner:
            def __init__(inner,out):inner.output=out;inner.deadline=time.monotonic()+840;inner.records=[];inner.group_observations=[];inner.writers_confirmed_retired=True
            def run(inner,label,argv,*,cwd,environment=None,seconds=300,expected_exit=0):
                stdout='';stderr='';code=expected_exit
                if label=='public-default-main':stdout=(route.ALPHA if scenario!='changed-public-main' else 'a'*40)+'\trefs/heads/main\n'
                if label=='homebrew-repository':stdout=str(brewrepo)+'\n'
                if label=='initial-tap-location':stdout=str(tap)+'\n'
                if label in ('homebrew-source','homebrew-source-return'):stdout=('c'*40 if label=='homebrew-source-return' and scenario=='homebrew-source-change' else 'a'*40)+'\n'+'b'*40+'\n'
                if label=='homebrew-cache':stdout=str(cache)+'\n'
                if label=='download-public-installer':
                    Path(argv[argv.index('--output')+1]).write_bytes((ROOT/'inputs/public-install.sh').read_bytes())
                    if scenario=='changed-installer':Path(argv[argv.index('--output')+1]).write_text('SYNTHETIC changed installer')
                if label=='ordinary-default-install':
                    outer.assertEqual(seconds,2700);outer.assertFalse(any(k.startswith('AGENT_CRYSTAL_') for k in environment));installed[0]=True
                    shutil.copytree(tap_fixture,tap)
                    if scenario=='install-failure':raise RuntimeError('SYNTHETIC installation failed')
                if label.endswith('-tap-root'):stdout=str(tap)+'\n'
                if label.endswith('-tap-commit'):stdout=route.ALPHA+'\nc2ba279e208af7a5b0e837ffbf869b2d062c609c\n'
                if label.endswith('-tap-origin'):stdout='https://github.com/crimson-knight/homebrew-agent-crystal.git\n'
                if label=='actual-installed-prefix':stdout=str(prefix)+'\n'
                if label=='download-public-SDK':shutil.copyfile(FIXTURES/'sdk-main.tar.gz',Path(argv[argv.index('--output')+1]))
                if label=='consumer-install-bundle':
                    source=Path(argv[-2]).parent.parent;consumer=Path(argv[-1]);bundle=consumer/'performance/vendor/memory_budget';bundle.mkdir(parents=True)
                    for row in support.read(source/'PACKAGE_PINS.json')['files']:
                        target=bundle/row['file'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/row['file'],target)
                    shutil.copyfile(source/'PACKAGE_PINS.json',bundle/'PACKAGE_PINS.json')
                if label=='consumer-write-lock':
                    outer.assertIn('write_consumer_lock.rb',' '.join(map(str,argv)));shutil.copyfile(ROOT/'consumer/EXPECTED_LOCK.yml',cwd/'shard.lock')
                if label=='consumer-lock-check':stdout=json.dumps({'SYNTHETIC':'authored actual-writer lock observation'})
                if label=='consumer-frozen-install':
                    outer.assertTrue((cwd/'shard.lock').is_file());shutil.copytree(output/'public-SDK-main',cwd/'lib/memory_budget');(cwd/'performance/results').mkdir();support.write(cwd/'performance/results/dependency-toolchain.json',{'SYNTHETIC':'frozen receipt'})
                if label=='consumer-budget-spec':stdout='1 examples, 0 failures, 0 errors, 0 pending\n'
                for stream,value in [('stdout',stdout),('stderr',stderr)]:(inner.output/(label+'.'+stream+'.txt')).write_text(value)
                group={'group':123,'status':'absent'};inner.group_observations.append(group)
                inner.records.append({'label':label,'arguments':list(map(str,argv)),'expected_exit':expected_exit,'exit_code':code,'pid':123,'original_group':123,'maximum_seconds':seconds,'elapsed_seconds':.01,'refusal':None,'writers_confirmed_retired':True,'terminal_group_observation':group,'stdout_sha256':support.sha(stdout.encode()),'stderr_sha256':support.sha(stderr.encode())})
                support.write(inner.output/'COMMANDS.json',inner.records)
                return stdout,stderr
        def qualify(directory,lock):
            directory.mkdir()
            for name in support.read(ROOT/'inputs/SDK_ARTIFACT_ROSTER.json')['platforms']['Darwin']:
                target=directory/name
                if name=='sdk-source.tar.gz':shutil.copyfile(FIXTURES/'sdk58c.tar.gz',target)
                else:target.write_text('{}\n' if name.endswith('.json') else '')
            result={'passed':scenario!='SDK-failure','compiler_color':'GREEN','writers_confirmed_retired':scenario!='SDK-unretired','private_cache_removed':True,'default_examples':39,'without_mt_examples':39,'installed_bundle_files':69,'tutorial_normal_exit':0,'tutorial_regression_exit':1,'sdk_commit':'58c20acfed71e27cbcf207014f29d7c7b53dab18'}
            backend=outer.source_file('prefix/libexec/agent-crystal-bin');ruby=Path(providers['bash']['path'])
            actual={'compiler_backend':support.stable(backend)[0],'compiler_wrapper':support.stable(prefix/'bin/crystal-alpha')[0],'ruby_backend':support.stable(ruby)[0],'ruby_launcher':support.stable(ruby)[0]}
            profile={'schema_version':1,'counter_protocol':1,'compiler_sha256':actual['compiler_backend']['sha256'],'wrapper_sha256':actual['compiler_wrapper']['sha256'],'stdlib_sha256':'f'*64,'ruby_sha256':actual['ruby_backend']['sha256'],'ruby_launcher_sha256':actual['ruby_launcher']['sha256']}
            for name,value in [('READINESS_RESULT.json',result),('RUNNER.json',{'system':'Darwin'}),('STDLIB_BEFORE.json',{'SYNTHETIC':'std'}),('STDLIB_AFTER.json',{'SYNTHETIC':'std'}),('PROVIDER_IDENTITIES.json',actual),('REVIEWED_COMPILER_PROFILE.json',profile)]:support.write(directory/name,value)
            if scenario=='catalog-change':(cache/'api/formula.jws.json').write_text('SYNTHETIC changed catalog')
            if scenario=='alias-change':(prefix/'bin/acrystal').write_text('SYNTHETIC changed alias')
            return 1 if scenario=='SDK-failure' else 0
        authority=support.load_driver()
        driver=types.SimpleNamespace(Runner=Runner,qualify=qualify,extract_sdk=authority.extract_sdk,verify_source=authority.verify_source,verify_bundle=authority.verify_bundle,verify_spec_result=authority.verify_spec_result)
        self.last_Runner=Runner;self.last_qualify=qualify
        self.last_driver=driver;self.last_protected=protected={r['path']:r['sha256'] for r in providers.values()}
        args=types.SimpleNamespace(output=output,sdk_mode='source')
        def which(name):return str(prefix/'bin'/name) if name in route.ALIAS and installed[0] else None
        with mock.patch.object(route.shutil,'which',side_effect=which):code=route.observe(args,driver,protected,providers)
        return code,support.read(output/'OBSERVATION_RESULT.json'),output,providers
    def test_full_ordinary_default_observation_retains_true_SDK_and_false_consumer(self):
        code,result,out,providers=self.full_observe();self.assertEqual(code,2);self.assertTrue(result['observation_complete']);self.assertTrue(result['SDK_readiness_accepted']);self.assertFalse(result['frozen_consumer_accepted']);self.assertEqual(support.read(out/'DRAFT_PROVIDER_CANDIDATE.json')['status'],'UNADMITTED')
    def test_changed_public_main_refuses_before_install(self):
        code,result,out,p=self.full_observe('changed-public-main');self.assertFalse(result['ordinary_installation_accepted']);self.assertFalse(result['observation_complete'])
    def test_changed_public_installer_refuses_before_execution(self):
        code,result,out,p=self.full_observe('changed-installer');self.assertFalse(result['ordinary_installation_accepted']);self.assertIn('checksum',result['error'])
    def test_actual_install_failure_remains_primary_failure(self):
        code,result,out,p=self.full_observe('install-failure');self.assertFalse(result['observation_complete']);self.assertIn('installation failed',result['error'])
    def test_SDK_failure_retains_separate_install_scope(self):
        code,result,out,p=self.full_observe('SDK-failure');self.assertTrue(result['ordinary_installation_accepted']);self.assertFalse(result['SDK_readiness_accepted']);self.assertFalse(result['observation_complete'])
    def test_unretired_SDK_refuses_return(self):
        code,result,out,p=self.full_observe('SDK-unretired');self.assertFalse(result['writers_confirmed_retired']);self.assertFalse(result['observation_complete'])
    def test_catalog_change_refuses_final_source_return(self):
        code,result,out,p=self.full_observe('catalog-change');self.assertFalse(result['observation_complete']);self.assertTrue(any('catalog' in e for e in result['finalization_errors']))
    def test_Homebrew_source_change_refuses_final_identity(self):
        code,result,out,p=self.full_observe('homebrew-source-change')
        self.assertFalse(result['observation_complete']);self.assertTrue(any('Homebrew source' in e for e in result['finalization_errors']))
    def test_alias_change_refuses_final_identity(self):
        code,result,out,p=self.full_observe('alias-change');self.assertFalse(result['observation_complete']);self.assertTrue(result['finalization_errors'])
    def test_environment_uses_normal_default_and_one_runtime_worker(self):
        with mock.patch.dict(os.environ,{'AGENT_CRYSTAL_FORMULA_PATH':'SYNTHETIC local override','AGENT_CRYSTAL_TAP':'SYNTHETIC other tap','CRYSTAL_VERSION':'wrong'}):
            env=route.clean_environment();self.assertFalse(any(k.startswith('AGENT_CRYSTAL_') for k in env));self.assertNotIn('CRYSTAL_VERSION',env);self.assertEqual(env['CRYSTAL_WORKERS'],'1')
    def test_source_and_bottle_predicates_keep_opposite_exact_flags(self):
        original=support.load_driver();bottled=support.load_driver(True);expected=support.read(ROOT/'vendor/test/sdk_source_lock.json')['alpha']
        item={'versions':{'stable':expected['source_version']},'revision':2,'urls':{'stable':{'checksum':expected['source_archive_sha256']}},'installed':[{'version':expected['installed_package_version'],'poured_from_bottle':False}]}
        original.verify_formula_receipt([item],expected)
        with self.assertRaises(Exception):bottled.verify_formula_receipt([item],expected)
        item['installed'][0]['poured_from_bottle']=True;bottled.verify_formula_receipt([item],expected)
        with self.assertRaises(Exception):original.verify_formula_receipt([item],expected)
        item['installed'][0]['poured_from_bottle']=1
        with self.assertRaises(Exception):bottled.verify_formula_receipt([item],expected)
    def test_pending_schema3_cannot_be_promoted_by_observation(self):
        code,result,out,p=self.full_observe();path=ROOT/'CONSUMER_ADMISSION.pending.json'
        with self.assertRaisesRegex(RuntimeError,'real gate'):route.consumer_admission(path,support.stable(path)[0]['sha256'],result,out)
    def test_FIFO_and_symlink_source_inputs_refuse(self):
        fifo=self.root/'unwritten FIFO';os.mkfifo(fifo)
        with self.assertRaises(RuntimeError):support.stable(fifo)
        alias=self.root/'alias';alias.symlink_to(self.source_file('regular'))
        with self.assertRaises(RuntimeError):support.stable(alias)
    def test_unretired_original_group_journal_refuses(self):
        with self.assertRaises(RuntimeError):support.verify_commands([{'pid':True}],[])
    def test_bottle_hash_tampering_refuses(self):
        out=self.root/'bottle';out.mkdir();archive=out/'agent-crystal--1.21.0-incremental-1_2.arm64_tahoe.bottle.tar.gz';archive.write_bytes(b'SYNTHETIC bottle bytes')
        data={'crimson-knight/agent-crystal/agent-crystal':{'formula':{'name':'agent-crystal','pkg_version':'1.21.0-incremental-1_2','tap_git_revision':route.ALPHA,'tap_git_remote':'https://github.com/crimson-knight/homebrew-agent-crystal.git'},'bottle':{'root_url':bottle.ROOT_URL,'rebuild':0,'cellar':'/opt/homebrew/Cellar','tags':{'arm64_tahoe':{'filename':archive.name,'local_filename':archive.name,'sha256':support.stable(archive)[0]['sha256']}}}}}
        support.write(out/'x.bottle.json',data);self.assertEqual(bottle.bottle_inputs(out,bottle.ROOT_URL)['tag'],'arm64_tahoe');archive.write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'hash'):bottle.bottle_inputs(out,bottle.ROOT_URL)
    def test_unreviewed_bottle_acceptance_refuses_formula_generation(self):
        p=self.root/'admission.json';support.write(p,{'bottle_artifacts_reviewed':False})
        with self.assertRaisesRegex(RuntimeError,'review'):finalize.finalize([],p,support.stable(p)[0]['sha256'],self.root/'generated')
    def test_actual_entrypoint_requires_hosted_scope(self):
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),self.assertRaisesRegex(RuntimeError,'Hosted'):route.get_context(types.SimpleNamespace())
    def test_retained_absolute_deadline_rejects_invalid_and_extended_values(self):
        now=route.retained_now();normal={'clock_protocol':route.CLOCK_PROTOCOL,'started_monotonic':now-1,'absolute_monotonic_deadline':now-1+route.TOTAL};self.assertEqual(route.retained_deadline(normal),normal['absolute_monotonic_deadline'])
        for value in (False,float('nan'),float('inf'),-1,normal['absolute_monotonic_deadline']+1):
            changed={**normal,'absolute_monotonic_deadline':value}
            with self.subTest(value=value),self.assertRaises(RuntimeError):route.retained_deadline(changed)
    def test_pending_resume_preserves_next_admitted_attempt_directory(self):
        code,result,out,p=self.full_observe();args=types.SimpleNamespace(output=out,admission=ROOT/'CONSUMER_ADMISSION.pending.json',admission_sha256=support.stable(ROOT/'CONSUMER_ADMISSION.pending.json')[0]['sha256'])
        self.assertEqual(route.resume(args,self.last_driver,self.last_protected,p),2);self.assertFalse((out/'consumer-command-output').exists())
    def test_native_census_caps_files_bytes_and_time(self):
        root=self.root/'libraries';root.mkdir();(root/'one').write_bytes(b'SYNTHETIC');self.assertEqual(prepare_retained.bounded_roots([root])['physical_nodes'],1)
        for options in ({'maximum_bytes':1},{'maximum_nodes':0},{'seconds':0}):
            with self.subTest(options=options),self.assertRaises(RuntimeError):prepare_retained.bounded_roots([root],**options)
    def test_native_census_refuses_alias_root_and_special_node(self):
        root=self.root/'libraries';root.mkdir();alias=self.root/'libraries alias';alias.symlink_to(root)
        with self.assertRaises(RuntimeError):prepare_retained.bounded_roots([alias])
        os.mkfifo(root/'FIFO')
        with self.assertRaises(RuntimeError):prepare_retained.bounded_roots([root])
    def staged_source(self):
        packet=self.root/'packet';shutil.copytree(ROOT,packet,ignore=shutil.ignore_patterns('SOURCE_PINS.json','__pycache__'))
        rows=[{'path':p.relative_to(packet).as_posix(),'bytes':p.stat().st_size,'sha256':support.stable(p)[0]['sha256']} for p in packet.rglob('*') if p.is_file()]
        support.write(packet/'SOURCE_PINS.json',{'files':rows});return packet,support.stable(packet/'SOURCE_PINS.json')[0]['sha256']
    def test_positive_artifact_retains_exact_raw_and_source_roster(self):
        code,result,out,p=self.full_observe();packet,pin=self.staged_source()
        with mock.patch.object(stage_results,'ROOT',packet),mock.patch.object(support,'ROOT',packet):receipt=stage_results.stage(out,self.root/'public',pin)
        self.assertFalse(receipt['unqualified_writer_scope']);self.assertTrue((self.root/'public/sdk/READINESS_RESULT.json').is_file());self.assertFalse((self.root/'public/consumer').exists())
    def test_changed_raw_or_missing_successful_SDK_file_refuses_public_stage(self):
        code,result,out,p=self.full_observe();packet,pin=self.staged_source();(out/'homebrew-version.stdout.txt').write_text('changed raw')
        with mock.patch.object(stage_results,'ROOT',packet),mock.patch.object(support,'ROOT',packet),self.assertRaisesRegex(RuntimeError,'raw stream hash'):stage_results.stage(out,self.root/'public',pin)
        (out/'sdk/PROFILE_DERIVATION.json').unlink()
        with mock.patch.object(stage_results,'ROOT',packet),mock.patch.object(support,'ROOT',packet),self.assertRaisesRegex(RuntimeError,'physical artifact roster'):stage_results.stage(out,self.root/'public',pin)
    def test_unretired_snapshot_contains_only_result_and_source(self):
        code,result,out,p=self.full_observe('SDK-unretired');packet,pin=self.staged_source()
        with mock.patch.object(stage_results,'ROOT',packet),mock.patch.object(support,'ROOT',packet):receipt=stage_results.stage(out,self.root/'public',pin)
        self.assertTrue(receipt['unqualified_writer_scope']);self.assertFalse((self.root/'public/sdk').exists());self.assertFalse((self.root/'public/COMMANDS.json').exists())
    def valid_admission(self,out,result):
        native='{"SYNTHETIC":"native metadata"}\n';git='{"SYNTHETIC":"Git metadata"}\n';profile={**support.read(out/'sdk/REVIEWED_COMPILER_PROFILE.json'),'schema_version':3,'native_component_manifest_sha256':support.sha(native.encode()),'git_provider_manifest_sha256':support.sha(git.encode()),'minecart_sha256':support.stable(self.source_file('minecart'))[0]['sha256']}
        document={'status':'PARENT_AND_PEER_REVIEWED_SOURCE_PROVIDER_INPUTS','execution_admitted':True,'observation_sha256':support.stable(out/'OBSERVATION_RESULT.json')[0]['sha256'],'job_identity':result['job_identity'],'alpha_commit':route.ALPHA,'sdk_commit':route.SDK,'parent_receipt_sha256':'a'*64,'peer_receipt_sha256':'b'*64,'profile_text':json.dumps(profile),'native_manifest_text':native,'git_manifest_text':git,'minecart_path':str(self.root/'minecart')}
        path=self.root/'SYNTHETIC reviewed response.json';support.write(path,document);return types.SimpleNamespace(output=out,admission=path,admission_sha256=support.stable(path)[0]['sha256'])
    def test_guarded_full_writer_frozen_consumer_preserves_source_and_returns(self):
        code,result,out,p=self.full_observe();args=self.valid_admission(out,result)
        returned=route.resume(args,self.last_driver,self.last_protected,p);receipt=support.read(out/'CONSUMER_RESULT.json')
        self.assertEqual(returned,0,receipt);self.assertTrue(receipt['frozen_consumer_accepted']);self.assertTrue(receipt['private_consumer_removed']);self.assertFalse(receipt['adapter_Micrate_journey_accepted'])
        labels=[r['label'] for r in support.read(out/'consumer-command-output/COMMANDS.json')]
        self.assertEqual(labels,['download-public-SDK','consumer-install-bundle','consumer-profile','consumer-write-lock','consumer-lock-check','consumer-frozen-install','consumer-budget-spec'])
    def test_changed_reviewed_profile_or_SDK_evidence_refuses_before_consumer(self):
        code,result,out,p=self.full_observe();args=self.valid_admission(out,result);(out/'sdk/PROFILE_DERIVATION.json').write_text('{} changed')
        self.assertEqual(route.resume(args,self.last_driver,self.last_protected,p),2)
        self.assertIn('SDK artifact bytes',support.read(out/'CONSUMER_RESULT.json')['error']);self.assertFalse((out/'consumer-command-output').exists())
    def authored_bottle(self,tag):
        out=self.root/tag;out.mkdir();archive=out/('agent-crystal--1.21.0-incremental-1_2.'+tag+'.bottle.tar.gz')
        with tarfile.open(archive,'w:gz') as stream:
            raw=b'SYNTHETIC returned compiler bytes';member=tarfile.TarInfo('agent-crystal/1.21.0-incremental-1_2/libexec/agent-crystal-bin');member.size=len(raw);member.mode=0o755;stream.addfile(member,io.BytesIO(raw))
        data={'crimson-knight/agent-crystal/agent-crystal':{'formula':{'name':'agent-crystal','pkg_version':'1.21.0-incremental-1_2','tap_git_revision':route.ALPHA,'tap_git_remote':'https://github.com/crimson-knight/homebrew-agent-crystal.git'},'bottle':{'root_url':bottle.ROOT_URL,'rebuild':0,'cellar':'any_skip_relocation','tags':{tag:{'filename':archive.name,'local_filename':archive.name,'sha256':support.stable(archive)[0]['sha256']}}}}}
        support.write(out/'authored.bottle.json',data);row=bottle.bottle_inputs(out,bottle.ROOT_URL);support.write(out/'BOTTLE_INPUTS.json',row)
        support.write(out/'BOTTLE_ARCHIVE_ROSTER.json',bottle.archive_roster(archive));support.write(out/'BOTTLE_RESULT.json',{'passed':True,'writers_confirmed_retired':True,'finalization_errors':[]})
        profile={'compiler_sha256':support.sha(b'SYNTHETIC installed compiler bytes')};providers={'compiler_backend':{'sha256':profile['compiler_sha256']}}
        support.write(out/'DRAFT_BOTTLE_PROVIDER.json',{'bottle':row,'qualified_build_profile':profile,'qualified_build_provider':providers})
        (out/'sdk').mkdir()
        for name,value in [('READINESS_RESULT.json',{}),('PROVIDER_IDENTITIES.json',providers),('REVIEWED_COMPILER_PROFILE.json',profile),('STDLIB_BEFORE.json',{}),('STDLIB_AFTER.json',{}),('INSTALL_RECEIPT.json',{})]:support.write(out/'sdk'/name,value)
        (out/'sdk/INSTALLED_FORMULA.rb').write_bytes((ROOT/'vendor/Formula/agent-crystal.rb').read_bytes())
        rows=[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,'sha256':support.stable(p)[0]['sha256']} for p in out.rglob('*') if p.is_file()]
        support.write(out/'PUBLIC_STAGE.json',{'files':rows});return out,row
    def bottle_approval(self,paths,rows):
        response={'bottle_artifacts_reviewed':True,'parent_receipt_sha256':'a'*64,'peer_receipt_sha256':'b'*64,'archive_sha256':[r['archive']['sha256'] for r in rows],'result_sha256':[support.stable(p/'BOTTLE_RESULT.json')[0]['sha256'] for p in paths],'reviewed_artifact_manifest_sha256':[support.stable(p/'PUBLIC_STAGE.json')[0]['sha256'] for p in paths]}
        path=self.root/'reviewed bottle inputs.json';support.write(path,response);return path
    def full_bottle(self,scenario='normal'):
        _,_,original,providers=self.full_observe(scenario)
        template,row=self.authored_bottle('arm64_tahoe');outer=self;parent=self.last_Runner
        class BottleRunner(parent):
            def run(inner,label,argv,**settings):
                if label=='create-bottle':
                    outer.assertEqual(settings['seconds'],300)
                    outer.assertEqual(argv[1:],['bottle','--json','--no-rebuild','--root-url',bottle.ROOT_URL,'crimson-knight/agent-crystal/agent-crystal'])
                    shutil.copyfile(Path(row['archive']['path']),inner.output/Path(row['archive']['path']).name)
                    shutil.copyfile(Path(row['json']['path']),inner.output/'authored.bottle.json')
                if label=='build-for-normal-bottle':
                    outer.assertEqual(settings['seconds'],2700);outer.assertIn('--build-bottle',argv)
                return super().run(label,argv,**settings)
        authority=types.SimpleNamespace(Runner=BottleRunner,qualify=self.last_qualify)
        args=types.SimpleNamespace(output=self.root/'actual bottle protocol fixture',root_url=bottle.ROOT_URL)
        code=bottle.build(args,authority,self.last_protected,providers)
        return code,support.read(args.output/'BOTTLE_RESULT.json'),args.output
    def test_guarded_complete_bottle_protocol_retains_unadmitted_registry(self):
        code,result,out=self.full_bottle();self.assertEqual(code,0);self.assertTrue(result['passed']);self.assertFalse(result['bottle_provider_accepted']);self.assertFalse(result['release_publication_admitted'])
        self.assertFalse(support.read(out/'DRAFT_BOTTLE_PROVIDER.json')['execution_admitted'])
        rows=support.read(out/'COMMANDS.json');self.assertEqual(len([r for r in rows if r['label']=='after-bottle-tap-root']),1)
        receipt=stage_results.stage(out,self.root/'bottle public stage',support.stable(ROOT/'SOURCE_PINS.json')[0]['sha256'])
        self.assertTrue(any(r['path'].endswith('.bottle.tar.gz') for r in receipt['files']))
    def test_guarded_bottle_SDK_failure_preserves_actual_refusal_and_return(self):
        code,result,out=self.full_bottle('SDK-failure');self.assertEqual(code,2);self.assertFalse(result['passed']);self.assertIn('readiness must succeed',result['error']);self.assertEqual(result['finalization_errors'],[])
        self.assertTrue(result['writers_confirmed_retired'])
        self.assertTrue(any(r['label']=='after-bottle-tap-root' for r in support.read(out/'COMMANDS.json')))

    def test_complete_bottle_roster_and_backend_member(self):
        out,row=self.authored_bottle('arm64_tahoe');roster=bottle.archive_roster(Path(row['archive']['path']));self.assertEqual(len(roster['files']),1);self.assertFalse(roster['native_profile_accepted'])
    def test_bottle_special_archive_kind_refuses(self):
        path=self.root/'special bottle.tar.gz'
        with tarfile.open(path,'w:gz') as stream:
            node=tarfile.TarInfo('agent-crystal/unwritten_fifo');node.type=tarfile.FIFOTYPE;stream.addfile(node)
        with self.assertRaisesRegex(RuntimeError,'ordinary files'):bottle.archive_roster(path)
    def test_two_reviewed_platforms_generate_exact_formula_and_lock_inputs(self):
        one,row1=self.authored_bottle('arm64_tahoe');two,row2=self.authored_bottle('x86_64_linux');approval=self.bottle_approval([one,two],[row1,row2]);out=self.root/'formula successor'
        platforms=finalize.finalize([one,two],approval,support.stable(approval)[0]['sha256'],out)
        self.assertEqual(set(platforms),{'Darwin','Linux'});formula=(out/'Formula/agent-crystal.rb').read_text();self.assertIn('  bottle do\n',formula);self.assertIn('revision 2',formula)
        self.assertEqual(support.read(out/'test/sdk_source_lock.json')['alpha']['formula_sha256'],support.stable(out/'Formula/agent-crystal.rb')[0]['sha256']);self.assertFalse(support.read(out/'RELEASE_INPUTS.json')['publication_admitted'])
    def test_changed_reviewed_provider_bytes_refuse_formula_generation(self):
        one,row1=self.authored_bottle('arm64_tahoe');two,row2=self.authored_bottle('x86_64_linux');approval=self.bottle_approval([one,two],[row1,row2]);(one/'DRAFT_BOTTLE_PROVIDER.json').write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'changed after independent acceptance'):finalize.finalize([one,two],approval,support.stable(approval)[0]['sha256'],self.root/'formula successor')

    def test_retained_clock_and_runner_translation_cross_process_origin(self):
        with mock.patch.object(route.time,'clock_gettime',return_value=50000),mock.patch.object(route.time,'monotonic',return_value=3):
            self.assertEqual(route.retained_now(),50000)
            self.assertEqual(route.retained_runner_deadline(53000,1800,120),1803)
            self.assertEqual(route.retained_runner_deadline(51000,1800,120),883)
            value={'clock_protocol':route.CLOCK_PROTOCOL,'started_monotonic':49000,'absolute_monotonic_deadline':56800}
            self.assertEqual(route.retained_deadline(value),56800)
            value['clock_protocol']='process-relative legacy clock'
            with self.assertRaisesRegex(RuntimeError,'host-wide'):route.retained_deadline(value)

    def test_review_hold_refuses_unreturned_preparation_before_polling(self):
        import wait_resume
        code,result,out,providers=self.full_observe()
        support.write(out/'PROVIDER_PREPARATION_RESULT.json',{'writers_confirmed_retired':False,'finalization_errors':[]})
        args=types.SimpleNamespace(output=out,review_branch='ordinary-consumer-admission/source-fixture')
        self.assertEqual(wait_resume.wait(args,self.last_driver,self.last_protected,providers),2)
        returned=support.read(out/'REVIEW_HOLD_RESULT.json')
        self.assertIn('preparation must return',returned['error'])
        self.assertFalse(returned['approval_consumed']);self.assertEqual(returned['original_groups'],[])

    def test_public_fixture_fetch_rejects_checksum_before_publication(self):
        import fetch_fixtures
        target=self.root/'never published fixtures'
        class Response:
            def __enter__(self):return io.BytesIO(b'wrong public bytes')
            def __exit__(self,*args):pass
        with self.assertRaisesRegex(RuntimeError,'size/checksum'):
            fetch_fixtures.fetch(target,opener=lambda *a,**kw:Response(),clock=lambda:0)
        self.assertFalse(target.exists())
    def test_public_fixture_fetch_rejects_oversize_before_publication(self):
        import fetch_fixtures
        target=self.root/'oversized fixtures'
        class Response:
            def __enter__(self):return io.BytesIO(b'x'*(fetch_fixtures.FIXTURES[0][2]+1))
            def __exit__(self,*args):pass
        with self.assertRaisesRegex(RuntimeError,'byte ceiling'):
            fetch_fixtures.fetch(target,opener=lambda *a,**kw:Response(),clock=lambda:0)
        self.assertFalse(target.exists())
    def test_hosted_provider_argument_roster_binds_actual_resolved_files(self):
        import hosted_entry
        provider=self.root/'metadata backend with spaces';provider.write_text('SYNTHETIC metadata bytes')
        with mock.patch.object(hosted_entry.sys,'platform','linux'),mock.patch.object(hosted_entry.sys,'executable',str(provider)):
            argv,rows=hosted_entry.provider_arguments({},which=lambda name:str(provider))
        self.assertEqual(set(rows),{'brew','git','curl','bash','python'})
        for row in rows.values():self.assertEqual(row['sha256'],support.stable(provider)[0]['sha256'])
        self.assertEqual(len(argv),20)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicRouteControls))
    print(json.dumps({'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'actual_guard_calls':len(GUARD_CALLS)},sort_keys=True));sys.exit(0 if result.wasSuccessful() and not result.skipped and not GUARD_CALLS else 2)
