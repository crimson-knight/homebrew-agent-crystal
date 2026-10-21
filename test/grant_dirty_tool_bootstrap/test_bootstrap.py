"""Guarded complete preparation and corruption controls; compiler execution stays mocked."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
boot=load('proof_tool_bootstrap',ROOT/'bootstrap_tools.py')
stage=load('proof_tool_stage',ROOT/'stage_tools.py')
PROVIDERS=Path(os.environ.get('ATLAS_BOOTSTRAP_FIXTURE_INPUTS',str(ROOT.parents[1]/'grant_dirty_tool_providers_v100')))
ACTUAL_PROCESS_GUARD_CALLS=[]


class BootstrapControls(unittest.TestCase):
    def setUp(self):
        self.private=tempfile.TemporaryDirectory(prefix='proof tools source controls with spaces ')
        self.addCleanup(self.private.cleanup);self.root=Path(self.private.name).resolve()
        self.guard_calls=[]
        self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guarded(*args,**options):
            ACTUAL_PROCESS_GUARD_CALLS.append('actual process/signal')
            self.guard_calls.append('actual process/signal');raise AssertionError('Source fixtures use authored process providers')
        for name in ['subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg']:
            self.guards.enter_context(mock.patch(name,side_effect=guarded))
        self.addCleanup(lambda:self.assertEqual(self.guard_calls,[]))

    def native(self,name):
        path=self.root/name;path.write_bytes(b'\xcf\xfa\xed\xfe'+struct.pack('<III',0x100000c,0,2)+b'\0'*16+b'SYNTHETIC source fixture')
        path.chmod(0o755);return path

    def full(self,scenario='normal'):
        outer=self
        wrapper=self.native('compiler');git=self.native('git');curl=self.native('curl')
        stdlib=self.root/'stdlib';stdlib.mkdir();(stdlib/'one.cr').write_text('SYNTHETIC source')
        stdlib_identity=lambda root:{'files':{p.name:boot.digest(p) for p in root.iterdir()}}
        context={'paths':{'compiler_wrapper':str(wrapper),'git':str(git),'curl':str(curl)},
            'hashes':{'compiler_wrapper':boot.digest(wrapper),'git':boot.digest(git),'curl':boot.digest(curl)},
            'stdlib':stdlib,'stdlib_identity':stdlib_identity(stdlib),'job_identity':{'SYNTHETIC':'unit-only'},
            'observed_profile_sha256':'a'*64,'revalidate':lambda:None}
        class FakeRunner:
            def __init__(inner,output):
                inner.output=output;inner.deadline=time.monotonic()+840;inner.records=[];inner.group_observations=[];inner.writers_confirmed_retired=True
                if scenario=='insufficient-build-budget':inner.deadline=time.monotonic()+604
            def run(inner,label,argv,*,cwd,environment=None,expected_exit=0,seconds=300):
                raw=b'';error=b'';code=expected_exit
                if label=='curl-version':raw=b'curl SYNTHETIC source-fixture provider\n'
                if label=='git-version':raw=b'git version SYNTHETIC-source-fixture\n'
                if label.startswith('download-'):
                    fixture='amber_cli-darwin-arm64.tar.gz' if label=='download-cli' else 'ameba-cdd58b34.tar.gz'
                    shutil.copyfile(PROVIDERS/fixture,Path(argv[argv.index('--output')+1]))
                    if scenario=='archive-corruption' and label=='download-cli':
                        Path(argv[argv.index('--output')+1]).write_bytes(b'corrupt')
                if label=='archive-git-probe':
                    outer.assertEqual(environment['AMEBA_BUILD_VERSION'],'1.7.0-dev')
                    outer.assertEqual(environment['GIT_CEILING_DIRECTORIES'],str(cwd.parent))
                    outer.assertEqual(environment['CRYSTAL_WORKERS'],'1')
                    error=b'fatal: not a git repository (or any of the parent directories): .git\n'
                    if scenario=='unexpected-git-success':code=0
                if label=='build-ameba':
                    outer.assertEqual(seconds,600);outer.assertIn('-Dwithout_mt',argv)
                    outer.assertIn('--error-on-warnings',argv);outer.assertIn('--release',argv)
                    outer.assertEqual(argv,[str(wrapper),'build','src/cli.cr','--release','--threads','1','--error-on-warnings','-Dwithout_mt','-o',str(inner.output/'tools/ameba')])
                    output=Path(argv[-1]);output.write_bytes(wrapper.read_bytes());output.chmod(0o755)
                    if scenario=='warnings':error=b'Warning: SYNTHETIC compile warning\n'
                    if scenario=='build-failure':code=1;error=b'Error: SYNTHETIC compiler refusal\n'
                    if scenario=='source-change':(cwd/'src/cli.cr').write_text('SYNTHETIC source corruption')
                    if scenario=='provider-change':git.write_bytes(b'changed identified provider')
                    if scenario=='unretired':inner.writers_confirmed_retired=False
                    if scenario=='wrong-binary':output.write_bytes(b'SYNTHETIC wrong format')
                for channel,data in [('stdout',raw),('stderr',error)]:
                    (inner.output/(label+'.'+channel+'.txt')).write_bytes(data)
                observation={'group':71,'status':'absent' if inner.writers_confirmed_retired else 'unverifiable'}
                inner.group_observations.append(observation)
                inner.records.append({'label':label,'arguments':[str(v) for v in argv],'exit_code':code,'expected_exit':expected_exit,
                    'maximum_seconds':seconds,'elapsed_seconds':.01,'pid':71,'original_group':71,'terminal_group_observation':observation,
                    'writers_confirmed_retired':inner.writers_confirmed_retired,'stdout_sha256':hashlib.sha256(raw).hexdigest(),
                    'stderr_sha256':hashlib.sha256(error).hexdigest(),'refusal':None})
                boot.write(inner.output/'COMMANDS.json',inner.records)
                if code!=expected_exit:raise RuntimeError(label+' returned modeled nonzero')
                if not inner.writers_confirmed_retired:raise RuntimeError('SYNTHETIC original group unverifiable')
                return raw.decode(),error.decode()
        driver=types.SimpleNamespace(Runner=FakeRunner,tree_identity=stdlib_identity)
        args=types.SimpleNamespace(output=self.root/'result')
        protected={Path(p):h for p,h in zip(context['paths'].values(),context['hashes'].values())}
        code=boot.execute(args,driver,context,protected)
        result=boot.read(args.output/'BOOTSTRAP_RESULT.json');registry=boot.read(args.output/'DRAFT_TOOL_REGISTRY.json')
        return code,result,registry,args.output

    def test_complete_guarded_source_compile_returns_unadmitted_tools(self):
        code,result,registry,output=self.full()
        self.assertEqual(code,0);self.assertTrue(result['preparation_complete']);self.assertEqual(result['compiler_color'],'GREEN')
        self.assertEqual(result['command_count'],6);self.assertEqual(result['actual_tool_executions'],0)
        self.assertFalse(registry['execution_admitted']);self.assertEqual(len(registry['providers']),3)
        self.assertTrue(all(p['execution_admitted'] is False for p in registry['providers'].values()))
        self.assertTrue(result['private_working_directory_removed'])
        self.assertEqual(result['returned_tools']['amber_lsp']['sha256'],'3691c7fdb6d489b44973c5f76493db83d32ad50fc3932fb2aabfa21062a1de4a')
        self.assertEqual(len(boot.read(output/'SOURCE_AFTER.json')['ameba']),372)

    def test_changed_archive_refuses_before_build_and_cleans(self):
        code,result,registry,out=self.full('archive-corruption');self.assertEqual(code,2)
        self.assertIn('archive bytes',result['error']);self.assertLess(result['command_count'],6)
        self.assertTrue(result['private_working_directory_removed'])

    def test_unexpected_git_success_refuses_ordinary_source_fallback_claim(self):
        code,result,registry,out=self.full('unexpected-git-success');self.assertEqual(code,2)
        self.assertEqual(result['compiler_color'],'UNEXECUTED');self.assertTrue(result['private_working_directory_removed'])

    def test_returned_compile_warning_is_YELLOW_and_refuses(self):
        code,result,registry,out=self.full('warnings');self.assertEqual(code,2)
        self.assertEqual(result['compiler_color'],'YELLOW');self.assertFalse(registry['preparation_complete'])

    def test_compiler_error_is_RED_and_preserves_raw(self):
        code,result,registry,out=self.full('build-failure');self.assertEqual(code,2)
        self.assertEqual(result['compiler_color'],'RED');self.assertIn('SYNTHETIC compiler refusal',(out/'build-ameba.stderr.txt').read_text())

    def test_source_change_refuses_return_identity(self):
        code,result,registry,out=self.full('source-change');self.assertEqual(code,2)
        self.assertTrue(any('fingerprints' in s for s in result['finalization_errors']))

    def test_provider_change_refuses_return_identity(self):
        code,result,registry,out=self.full('provider-change');self.assertEqual(code,2)
        self.assertTrue(any('Protected source/provider' in s for s in result['finalization_errors']))

    def test_unretired_group_preserves_private_files_and_refuses(self):
        code,result,registry,out=self.full('unretired');self.assertEqual(code,2)
        self.assertFalse(result['writers_confirmed_retired']);self.assertFalse(result['private_working_directory_removed'])
        self.assertTrue((out/'private').is_dir());self.assertFalse(registry['execution_admitted'])

    def test_wrong_native_binary_refuses(self):
        code,result,registry,out=self.full('wrong-binary');self.assertEqual(code,2)
        self.assertIn('Mach-O',result['error']);self.assertTrue(result['private_working_directory_removed'])

    def test_insufficient_full_build_budget_refuses_before_compiler(self):
        code,result,registry,out=self.full('insufficient-build-budget');self.assertEqual(code,2)
        self.assertEqual(result['compiler_color'],'UNEXECUTED');self.assertEqual(result['command_count'],5)
        self.assertIn('launch reserve',result['error']);self.assertTrue(result['private_working_directory_removed'])

    def staged_source(self):
        copy=self.root/'packet';shutil.copytree(ROOT,copy,ignore=shutil.ignore_patterns('BOOTSTRAP_SOURCE_PINS.json','__pycache__'))
        rows=[{'path':p.relative_to(copy).as_posix(),'bytes':p.stat().st_size,'sha256':boot.digest(p)} for p in copy.rglob('*') if p.is_file()]
        boot.write(copy/'BOOTSTRAP_SOURCE_PINS.json',{'files':rows})
        return copy,boot.digest(copy/'BOOTSTRAP_SOURCE_PINS.json')

    def test_positive_artifact_stage_retains_registry_binary_source_and_raw(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source()
        with mock.patch.object(stage,'ROOT',packet):receipt=stage.stage(out,self.root/'public',pin)
        self.assertEqual(receipt['missing'],[]);self.assertFalse(receipt['execution_admitted'])
        self.assertTrue((self.root/'public/tools/ameba').is_file())
        self.assertTrue((self.root/'public/source/inputs/AMEBA_COMPLETE_TREE_READBACK.json').is_file())

    def test_changed_returned_binary_refuses_registry_join(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source();(out/'tools/ameba').write_bytes(b'changed')
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'registry join'):
            stage.stage(out,self.root/'public',pin)

    def test_changed_raw_command_stream_refuses_hash_join(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source();(out/'git-version.stdout.txt').write_text('changed harmless metadata')
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'raw-stream hash join'):
            stage.stage(out,self.root/'public',pin)

    def test_changed_binary_mode_refuses_return_identity(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source();(out/'tools/ameba').chmod(0o644)
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'mode/registry join'):
            stage.stage(out,self.root/'public',pin)

    def test_changed_command_budget_exit_and_group_facts_refuse(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source()
        original=boot.read(out/'COMMANDS.json')
        for field,value in [('pid',False),('original_group',-1),('maximum_seconds',999999),
                            ('elapsed_seconds',float('nan')),('expected_exit',False)]:
            changed=json.loads(json.dumps(original));changed[0][field]=value;boot.write(out/'COMMANDS.json',changed)
            with self.subTest(field=field),mock.patch.object(stage,'ROOT',packet),self.assertRaises(ValueError):
                stage.stage(out,self.root/'public',pin)

    def test_returned_tool_execution_flag_retains_independent_admission(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source()
        registry['providers']['ameba']['execution_admitted']=True;boot.write(out/'DRAFT_TOOL_REGISTRY.json',registry)
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'registry join'):
            stage.stage(out,self.root/'public',pin)

    def test_credential_shaped_selected_stream_refuses_public_stage(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source()
        (out/'git-version.stdout.txt').write_text('ghp_'+'A'*30)
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'credential-shaped'):
            stage.stage(out,self.root/'public',pin)

    def test_extra_checkout_metadata_stays_outside_positive_artifact(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source();extra=out/'.git';extra.mkdir();(extra/'config.json').write_text('SYNTHETIC private metadata')
        with mock.patch.object(stage,'ROOT',packet):receipt=stage.stage(out,self.root/'public',pin)
        self.assertFalse((self.root/'public/.git').exists());self.assertFalse(any('.git/' in r['path'] for r in receipt['files']))

    def test_missing_success_member_refuses(self):
        code,result,registry,out=self.full();packet,pin=self.staged_source();(out/'SOURCE_AFTER.json').unlink()
        with mock.patch.object(stage,'ROOT',packet),self.assertRaisesRegex(ValueError,'every positive artifact'):
            stage.stage(out,self.root/'public',pin)

    def test_unretired_public_stage_retains_only_result_and_source_metadata(self):
        code,result,registry,out=self.full('unretired');packet,pin=self.staged_source()
        with mock.patch.object(stage,'ROOT',packet):receipt=stage.stage(out,self.root/'public',pin)
        self.assertTrue(receipt['unqualified_writer_scope']);self.assertFalse((self.root/'public/tools').exists())
        self.assertFalse((self.root/'public/build-ameba.stderr.txt').exists())

    def test_MachO_arm64_header_and_executable_mode_are_required(self):
        path=self.native('native');boot.macho(path);path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'Mach-O'):boot.macho(path)

    def test_special_physical_input_refuses_before_read(self):
        path=self.root/'unwritten FIFO';os.mkfifo(path)
        with self.assertRaisesRegex(RuntimeError,'regular input'):boot.regular(path)

    def test_symlink_physical_input_refuses(self):
        target=self.native('native');alias=self.root/'alias';alias.symlink_to(target.name)
        with self.assertRaisesRegex(RuntimeError,'regular input'):boot.regular(alias)

    def test_color_classifier_preserves_all_three_states(self):
        self.assertEqual(boot.compiler_color({'exit_code':0},'',''),('GREEN',False))
        self.assertEqual(boot.compiler_color({'exit_code':0},'Warning: sample',''),('YELLOW',True))
        self.assertEqual(boot.compiler_color({'exit_code':1},'','Error: sample'),('RED',False))

    def test_local_actual_bootstrap_requires_hosted_Mac(self):
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),self.assertRaisesRegex(RuntimeError,'hosted Mac'):
            boot.prepare(types.SimpleNamespace())


    def test_explicit_single_compiler_thread_and_runtime_worker_are_distinct(self):
        code,result,registry,out=self.full()
        self.assertEqual(code,0)
        command=result['compile_argv']
        self.assertEqual(command.count('--threads'),1)
        self.assertEqual(command[command.index('--threads')+1],'1')
        self.assertEqual(result['build_environment']['CRYSTAL_WORKERS'],'1')
        self.assertFalse(registry['execution_admitted'])

    def verify_compile_thread_mutation_refuses(self,replacement):
        source=(ROOT/'bootstrap_tools.py').read_text()
        boundary="'--threads', '1', "
        self.assertEqual(source.count(boundary),1)
        mutated=source.replace(boundary,replacement,1)
        namespace=dict(boot.__dict__)
        exec(compile(mutated,str(ROOT/'bootstrap_tools.py'),'exec'),namespace)
        with mock.patch.object(boot,'execute',namespace['execute']):
            code,result,registry,out=self.full()
        self.assertEqual(code,2)
        self.assertIn('AssertionError',result['error'])
        self.assertEqual(result['compiler_color'],'UNEXECUTED')
        self.assertFalse(registry['preparation_complete'])
        self.assertTrue(result['private_working_directory_removed'])

    def test_missing_compiler_thread_flag_refuses_exact_argv_fixture(self):
        self.verify_compile_thread_mutation_refuses('')

    def test_two_compiler_threads_refuse_exact_argv_fixture(self):
        self.verify_compile_thread_mutation_refuses("'--threads', '2', ")



if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BootstrapControls))
    print(json.dumps({'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'skipped':len(result.skipped),'actual_process_guard_calls':len(ACTUAL_PROCESS_GUARD_CALLS)},sort_keys=True))
    sys.exit(0 if result.wasSuccessful() and not result.skipped and not ACTUAL_PROCESS_GUARD_CALLS else 2)
