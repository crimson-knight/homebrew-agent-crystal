"""Behavioral fixtures execute the real controller and publication reader under guards."""
import ast,copy,hashlib,importlib.util,io,json,os,shutil,sys,tempfile,time,unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path[:0]=[str(ROOT),str(ROOT/'products')]
import source_gate as gate
import run_frontend as host
import stage_results as staging
from products import frontend_boundary as boundary
from products.parse_semantic_stats import STAGES,parse
from products.parse_stage_stats import associate_observed_intervals
from observe_compiler import parse_ps,Observer as ActualObserver
CALLS=[]
def raw_stats():
    lines=[]
    for name in STAGES:
        prefix=(name+':').ljust(34);lines += [prefix,prefix+' 0:00:00.010 ('+format(1.0,'7.2f')+'MB)']
    return '\n'.join(lines)+'\n'
def record(label,seconds,output,pid=123):
    sample=dict(status='absent',elapsed_seconds=.01)
    group=dict(group=pid,status='absent',scope='original POSIX process group',phase='direct_child_returned',maximum_drain_seconds=5,elapsed_seconds=.01,samples=[sample],initial_sample=sample,terminal_sample=sample,bounded_drain_exhausted=False,drain_deadline=2.,original_command_deadline=3.)
    return dict(label=label,arguments=[],pid=pid,original_group=pid,expected_exit=0,exit_code=0,refusal=None,maximum_seconds=seconds,elapsed_seconds=.1,writers_confirmed_retired=True,terminal_group_observation=group,stdout_sha256=gate.digest(output/(label+'.stdout.txt')),stderr_sha256=gate.digest(output/(label+'.stderr.txt')))
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class HostedFrontend(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hosted frontend fixture with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.stack=ExitStack();self.addCleanup(self.stack.close)
        def guard(*a,**k):CALLS.append('external');raise AssertionError('Guarded source providers required')
        for name in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.stack.enter_context(mock.patch(name,side_effect=guard))
        sys.path[:0]=[str(gate.BASE),str(gate.BASE/'vendor')]
        source_stage=load(gate.BASE/'stage_grant_sources.py','frontend_test_frozen_stage')
        source_inventory=load(gate.BASE/'vendor/verify_compile_acceptance.py','frontend_test_frozen_inventory')
        self.stdlib=self.root/'stdlib';self.stdlib.mkdir();(self.stdlib/'sample.cr').write_text('SYNTHETIC standard-library source\n')
        self.backend=self.root/'backend';self.backend.write_text('SYNTHETIC compiler provider');self.backend.chmod(0o755)
        self.wrapper=self.root/'wrapper';self.wrapper.write_text('SYNTHETIC wrapper provider');self.wrapper.chmod(0o755)
        self.admitted=dict(job_identity={'SYNTHETIC':'same-job'},observed_profile_sha256='a'*64,providers=dict(compiler_backend=dict(path=str(self.backend),sha256=gate.digest(self.backend)),compiler_wrapper=dict(path=str(self.wrapper),sha256=gate.digest(self.wrapper))))
        self.args=SimpleNamespace(repository=self.root,driver=self.root/'driver',sdk_evidence=self.root/'sdk',output=self.root/'result',packet_sha256=gate.digest(ROOT/'SOURCE_PINS.json'),python_sha256='b'*64,ps_sha256='c'*64)
        self.scenario='normal';outer=self;self.instances=[]
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=0;outer.instances.append(s)
            def run(s,label,argv,*,cwd,environment,seconds):
                raw=raw_stats() if label.endswith('-compile') else '';err=''
                if outer.scenario=='stats' and label=='new_empty-compile':raw+='Changed stats\n'
                if outer.scenario=='warning' and label=='new_empty-compile':err='Warning: SYNTHETIC warning\n'
                if outer.scenario=='fixture-drift' and label=='new_empty-compile':Path(argv[argv.index('--stats')+1]).write_text('SYNTHETIC changed working source')
                if outer.scenario=='cache-object' and label=='new_empty-compile':(Path(environment['CRYSTAL_CACHE_DIR'])/'unexpected.o').write_bytes(b'SYNTHETIC native object')
                for stream,value in [('stdout',raw),('stderr',err)]:(s.output/(label+'.'+stream+'.txt')).write_text(value)
                row=record(label,seconds,s.output);row['arguments']=list(map(str,argv))
                if outer.scenario=='timeout' and label=='new_empty-compile':row.update(refusal='Command exceeded its time budget',elapsed_seconds=121)
                if outer.scenario=='group' and label=='new_empty-compile':s.writers_confirmed_retired=False;row['writers_confirmed_retired']=False;row['terminal_group_observation']['status']='present'
                s.records.append(row);s.group_observations.append(row['terminal_group_observation']);gate.write(s.output/'COMMANDS.json',s.records)
                if row['refusal'] or not s.writers_confirmed_retired:raise RuntimeError('SYNTHETIC command refusal')
                return raw,err
        self.driver=SimpleNamespace(Runner=Runner)
        class Observer:
            def __init__(s,driver,backend,output,deadline):s.output=output;output.mkdir();s.thread=None;s.runner=SimpleNamespace(writers_confirmed_retired=True)
            def run(s,runner,label,argv,**kwargs):s.label=label;return runner.run(label,argv,**kwargs)
            def complete(s,row):
                path=s.output/'sample-000.stdout.txt';path.write_text('123 '+str(os.getpid())+' 123 Wed Oct 21 00:00:00 2026 2048 '+str(outer.backend)+'\n');(s.output/'sample-000.stderr.txt').write_text('')
                metadata=record('sample-000',2,s.output,222);metadata['arguments']=['/bin/ps','-p','123','-o','pid=,ppid=,pgid=,lstart=,rss=,comm='];gate.write(s.output/'COMMANDS.json',[metadata])
                raw=(outer.args.output/(s.label+'.stdout.txt')).stat().st_size
                live=dict(pid=123,birth='Wed Oct 21 00:00:00 2026',direct_rss_bytes=2*2**20,command=str(outer.backend),is_live=True,monotonic_before=100.,monotonic_after=100.01,stdout_bytes=raw,metadata_record_index=0)
                terminal=dict(pid=123,birth=live['birth'],direct_rss_bytes=0,is_live=False,monotonic_before=100.1,monotonic_after=100.11,stdout_bytes=raw,terminal_after_original_group_absence=True)
                return dict(raw_observations=[live,terminal],metadata_commands=[metadata],metadata_groups=[metadata['terminal_group_observation']],writers_confirmed_retired=True,thread_joined=True,live_samples=1,first_sample_latency_seconds=.01,sample_interval_seconds=1.,maximum_samples=128,overhead_qualified=False,scope='SYNTHETIC guarded direct-PID sample')
        self.stack.enter_context(mock.patch('observe_compiler.Observer',Observer))
        def check():
            if self.scenario=='return':raise RuntimeError('SYNTHETIC SDK/provider return differs')
        self.context=dict(admitted=self.admitted,stdlib=self.stdlib,backend=self.backend,wrapper=self.wrapper,protected={},check=check,stage=source_stage.stage,inventory=source_inventory.source_input_inventory)
    def perform(self):
        code=host.execute(self.args,self.driver,self.context,time.monotonic());return code,gate.read(self.args.output/'RESULT.json')
    def positive(self):
        code,result=self.perform();self.assertEqual(code,0);self.assertTrue(result['passed']);return result
    def stage(self):return staging.stage(self.args.output,self.root/'public',self.args.packet_sha256,admitted_reader=lambda:self.admitted)
    def test_complete_actual_controller_six_routes_and_unchanged_original_source(self):
        result=self.positive();self.assertEqual(result['command_count'],12);self.assertEqual([s['profile'] for s in result['samples']],list(host.PROFILES));self.assertTrue(result['private_removed']);self.assertTrue(result['source_provider_return_accepted'])
    def test_actual_positive_stager_keeps_every_named_raw_cohort(self):
        self.positive();result=self.stage();self.assertTrue(result['diagnostic_complete']);names={r['path'] for r in result['files']};self.assertIn('canonical_create-observer/sample-000.stdout.txt',names);self.assertFalse(any('/private/' in n or '.git' in n for n in names))
    def test_changed_compiler_raw_refuses_publication(self):
        self.positive();(self.args.output/'new_empty-compile.stdout.txt').write_text('Changed actual compiler output')
        with self.assertRaises((RuntimeError,ValueError)):self.stage()
    def test_changed_route_result_refuses_publication(self):
        self.positive();path=self.args.output/'new_empty-RESULT.json';value=gate.read(path);value['source_sha256']='0'*64;gate.write(path,value)
        with self.assertRaises(RuntimeError):self.stage()
    def test_missing_and_alias_raw_refuse_publication(self):
        self.positive();p=self.args.output/'new_empty-compile.stderr.txt';p.unlink()
        with self.assertRaises(FileNotFoundError):self.stage()
        p.symlink_to(self.backend)
        with self.assertRaises((RuntimeError,ValueError)):self.stage()
    def test_same_job_provider_return_failure_refuses(self):
        self.scenario='return';code,result=self.perform();self.assertEqual(code,2);self.assertFalse(result['source_provider_return_accepted']);self.assertTrue(result['private_removed'])
    def test_original_group_presence_preserves_private_and_failed_scope(self):
        self.scenario='group';code,result=self.perform();self.assertEqual(code,2);self.assertFalse(result['writers_confirmed_retired']);self.assertFalse(result['private_removed']);self.assertTrue((self.args.output/'private').exists())
    def test_deadline_refusal_keeps_original_command_and_raw(self):
        self.scenario='timeout';code,result=self.perform();self.assertEqual(code,2);self.assertIn('SYNTHETIC command refusal',result['error']);self.assertEqual(result['commands'][-1]['refusal'],'Command exceeded its time budget')
    def test_warning_is_yellow_and_measurement_refuses(self):
        self.scenario='warning';code,result=self.perform();self.assertEqual(code,2);self.assertEqual(result['compiler_color'],'YELLOW')
    def test_changed_stats_grammar_refuses_and_retains_raw(self):
        self.scenario='stats';code,result=self.perform();self.assertEqual(code,2);self.assertTrue((self.args.output/'new_empty-compile.stdout.txt').exists())
    def test_unexpected_semantic_native_cache_output_refuses(self):
        self.scenario='cache-object';code,result=self.perform();self.assertEqual(code,2);self.assertIn('Unexpected semantic cache',result['error'])
    def test_all_remaining_compiler_horizons_required_before_first_route(self):
        code=host.execute(self.args,self.driver,self.context,time.monotonic()-100);self.assertEqual(code,2);self.assertEqual(gate.read(self.args.output/'RESULT.json')['commands'],[])
    def test_failed_result_stage_keeps_retired_raw_without_qualification(self):
        self.scenario='timeout';self.perform();receipt=self.stage();names={r['path'] for r in receipt['files'] if not r['path'].startswith('source/')};self.assertIn('RESULT.json',names);self.assertIn('new_empty-compile.stdout.txt',names);self.assertIn('new_empty-compile.stderr.txt',names);self.assertFalse(receipt['diagnostic_complete'])
    def test_credential_shaped_fixed_raw_refuses_publication(self):
        self.positive();p=self.args.output/'new_empty-compile.stderr.txt';p.write_text('Authorization: Bearer '+('X'*30))
        with self.assertRaises((RuntimeError,ValueError)):self.stage()
    def test_changed_observer_journal_refuses_publication(self):
        self.positive();p=self.args.output/'new_empty-observer/COMMANDS.json';value=gate.read(p);value[0]['pid']=True;gate.write(p,value)
        with self.assertRaises(RuntimeError):self.stage()
    def test_observer_metadata_direct_parent_group_and_rss(self):
        value=parse_ps('123 9 123 Wed Oct 21 00:00:00 2026 1024 /backend',123,9);self.assertEqual(value['direct_rss_bytes'],2**20)
        for raw in ('123 8 123 Wed Oct 21 00:00:00 2026 1024 /backend','123 9 124 Wed Oct 21 00:00:00 2026 1024 /backend','malformed'):
            with self.assertRaises(RuntimeError):parse_ps(raw,123,9)
    def test_metric_names_preserve_gc_capacity_and_rss_lower_bound(self):
        parsed=parse(raw_stats().encode());self.assertFalse(parsed['live_bytes_measured']);self.assertFalse(parsed['compiler_peak_qualified']);self.assertEqual(len(parsed['stages']),11)
    def test_changed_original_source_before_import_refuses(self):
        projected=self.root/'source';shutil.copytree(ROOT,projected);target=projected/'run_frontend.py';target.write_text('raise RuntimeError("Changed source executed")')
        with mock.patch.object(gate,'ROOT',projected):
            with self.assertRaises(RuntimeError):gate.admit(self.args.packet_sha256)
    def test_changed_complete_core_before_import_refuses(self):
        projected=self.root/'core';shutil.copytree(gate.BASE,projected);(projected/'same_job_policy.py').write_text('raise RuntimeError("Changed inherited source executed")')
        with mock.patch.object(gate,'BASE',projected):
            with self.assertRaises(RuntimeError):gate.admit(self.args.packet_sha256)
    def test_missing_source_and_alias_refuse_before_import(self):
        projected=self.root/'source';shutil.copytree(ROOT,projected);target=projected/'run_frontend.py';target.unlink()
        with mock.patch.object(gate,'ROOT',projected):
            with self.assertRaises(FileNotFoundError):gate.admit(self.args.packet_sha256)
            target.symlink_to(ROOT/'run_frontend.py')
            with self.assertRaises(RuntimeError):gate.admit(self.args.packet_sha256)
    def test_wrong_same_job_admission_refuses_positive_staging(self):
        self.positive()
        with self.assertRaises(RuntimeError):staging.stage(self.args.output,self.root/'public',self.args.packet_sha256,admitted_reader=lambda:{'changed_job':True})
    def test_original_route_stats_source_manifest_bindings(self):
        for profile in host.PROFILES:
            value=gate.read(ROOT/'products'/(profile+'.json'));self.assertEqual(value['source_sha256'],gate.digest(ROOT/'products'/(profile+'.cr.txt')))
        self.assertEqual(gate.digest(ROOT/'products/canonical_create.cr.txt'),boundary.CANONICAL)
    def test_bootstrap_passes_external_source_pin_to_execution(self):
        import bootstrap
        with mock.patch.object(bootstrap,'admit',side_effect=lambda expected,repository:gate.admit(expected)),mock.patch.object(bootstrap.runpy,'run_path') as called:
            bootstrap.main('run',self.args.packet_sha256,['--driver','fixture'])
            self.assertEqual(sys.argv[-2:],['--packet-sha256',self.args.packet_sha256]);called.assert_called_once()
    def test_finite900_horizon_refuses_terminal_overrun(self):
        original_check=self.context['check']
        def delayed():original_check();self.context['clock'][0]=1001.
        self.context['clock']=[100.];self.context['check']=delayed
        with mock.patch.object(host.time,'monotonic',side_effect=lambda:self.context['clock'][0]):code=host.execute(self.args,self.driver,self.context,100.)
        self.assertEqual(code,2);self.assertIn('Original900-second ladder horizon exceeded',gate.read(self.args.output/'RESULT.json')['finalization_errors'])


    def actual_observer(self,scenario='present'):
        import observe_compiler
        outer=self
        class Thread:
            def __init__(s,**kwargs):s.joined=False
            def start(s):pass
            def join(s,timeout):s.joined=True
            def is_alive(s):return scenario=='thread-live'
        self.stack.enter_context(mock.patch.object(observe_compiler.threading,'Thread',Thread))
        driver=SimpleNamespace(subprocess=SimpleNamespace(Popen=lambda *a,**k:SimpleNamespace(pid=123)))
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=0
            def run(s,label,argv,*,cwd,environment,seconds):
                raw=raw_stats() if label=='compiler' else ('123 '+str(os.getpid())+' 123 Wed Oct 21 00:00:00 2026 2048 '+str(outer.backend)+'\n')
                if scenario=='absent' and label!='compiler':raw=''
                for stream,value in [('stdout',raw),('stderr','')]: (s.output/(label+'.'+stream+'.txt')).write_text(value)
                if label=='compiler':driver.subprocess.Popen(list(map(str,argv)))
                row=record(label,seconds,s.output,123 if label=='compiler' else 222);row['arguments']=list(map(str,argv))
                if scenario=='absent' and label!='compiler':row['exit_code']=1
                if scenario=='refused' and label!='compiler':row['refusal']='Command exceeded its time budget'
                s.records.append(row);s.group_observations.append(row['terminal_group_observation'])
                if row['exit_code'] or row['refusal']:raise RuntimeError('SYNTHETIC metadata result')
                return raw,''
        driver.Runner=Runner
        output=self.root/'actual-observer-controller';output.mkdir();main=Runner(output)
        observer=ActualObserver(driver,self.backend,self.root/'actual-observer',time.monotonic()+120)
        observer.run(main,'compiler',[str(self.backend),'build','fixture.cr'],cwd=self.root,environment={},seconds=120)
        self.assertEqual(observer.pid,123);self.assertTrue(observer.thread.joined)
        return observer,main
    def test_actual_observer_hook_and_source_provider_return(self):
        observer,main=self.actual_observer();observer.sample();value=observer.complete(main.records[-1])
        self.assertEqual(value['live_samples'],1);self.assertEqual(value['metadata_commands'][0]['arguments'][2],'123');self.assertTrue(value['writers_confirmed_retired']);self.assertFalse(value['overhead_qualified'])
    def test_actual_observer_absent_pid_stays_missing_rss_coverage(self):
        observer,main=self.actual_observer('absent');observer.sample();value=observer.complete(main.records[-1]);self.assertEqual(value['live_samples'],0);self.assertEqual(value['metadata_commands'][0]['exit_code'],1)
    def test_actual_observer_refusal_retained_and_rejected(self):
        observer,main=self.actual_observer('refused');observer.sample()
        with self.assertRaises(RuntimeError):observer.complete(main.records[-1])
        self.assertTrue(observer.errors);self.assertEqual(observer.runner.records[0]['refusal'],'Command exceeded its time budget')
    def test_actual_observer_thread_return_is_required(self):
        observer,main=self.actual_observer('thread-live');observer.sample()
        with self.assertRaises(RuntimeError):observer.complete(main.records[-1])


    def test_actual_observation_window_covers_stream_offset_read(self):
        observer,main=self.actual_observer();clock=[10.0]
        class Stream:
            def stat(s):clock[0]=11.0;return SimpleNamespace(st_size=123)
        observer.stream=Stream()
        with mock.patch('observe_compiler.time.monotonic',side_effect=lambda:clock[0]):observer.sample()
        self.assertEqual(observer.samples[0]['monotonic_before'],10.0)
        self.assertEqual(observer.samples[0]['monotonic_after'],11.0)
        self.assertEqual(observer.samples[0]['stdout_bytes'],123)


    def test_changed_working_fixture_source_refuses_before_measurement(self):
        self.scenario='fixture-drift';code,result=self.perform();self.assertEqual(code,2)
        self.assertIn('Exact working route source/manifest after compiler',result['error'])
        self.assertFalse(result['source_provider_return_accepted'])

def main():
    gate.admit(gate.digest(ROOT/'SOURCE_PINS.json'))
    import test_frontend_boundaries
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(HostedFrontend),unittest.defaultTestLoader.loadTestsFromModule(test_frontend_boundaries)])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    summary=dict(tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),guard_calls=len(CALLS),actual_local_compiler_native_container_browser_ssh_workload_jobs=0);print(json.dumps(summary));return 0 if result.wasSuccessful() and not CALLS else 2
if __name__=='__main__':raise SystemExit(main())
