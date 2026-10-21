"""Guarded producer behavior; compiler/native/tool processes are authored providers."""
import ast
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT));import run_source_feedback as producer
import stage_source_feedback as staging
spec=importlib.util.spec_from_file_location('feedback_test_probe',ROOT/'probe/run_probe.py');probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
spec=importlib.util.spec_from_file_location('feedback_test_terminal',ROOT/'probe/vendor/command_contract.py');contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
CALLS=[]

class FeedbackControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='source feedback actual project fixture with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.stack=ExitStack();self.addCleanup(self.stack.close)
        def guard(*a,**k):CALLS.append('external');raise AssertionError('Guarded source/native fixture provider required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.stack.enter_context(mock.patch(target,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(CALLS,[]))
        self.input=self.root/'frozen probe copy';(self.input/'inputs').mkdir(parents=True)
        for name in ('buffer_probe.cr.txt','inputs/memory_buffer.original.cr.txt','inputs/memory_buffer.fixed.cr.txt','API_PREREQUISITES.json'):shutil.copyfile(ROOT/'probe'/name,self.input/name)
        self.wrapper=self.root/'installed/bin/crystal-alpha';self.wrapper.parent.mkdir(parents=True);self.wrapper.write_text('SYNTHETIC admitted compiler');self.wrapper.chmod(0o755)
        self.tools={}
        for name in ('amber_lsp','ameba'):
            p=self.root/name;p.write_text('SYNTHETIC admitted '+name);p.chmod(0o755);self.tools[name]={'path':str(p)}
        source=(ROOT/'inputs/dirty_proof.authority.py').read_text();tree=ast.parse(source);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='lookup');namespace={'need':producer.need,'json':json,'terminal':contract.terminal};exec(compile(ast.Module(body=[function],type_ignores=[]),'exact inherited lookup','exec'),namespace)
        self.proof=SimpleNamespace(lookup=namespace['lookup'],terminal=contract.terminal)
        self.scenario='normal';self.instances=[];outer=self
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=0;outer.instances.append(s)
            def run(s,label,argv,*,cwd,environment,seconds):
                stdout='';stderr='';code=0
                if label=='amber-lsp-version':stdout='amber-lsp 2.0.7\n'
                if label=='ameba-version':stdout='Ameba 1.7.0-dev\n'
                if label.startswith('api-'):
                    method=argv[2];unknown=outer.scenario=='unknown' and not label.startswith('api-verify-');code=4 if unknown else 0
                    value={'query':method,'status':'unknown' if unknown else 'found','freshness':'fresh','entries':[] if unknown else [{'name':method,'return_type':'SYNTHETIC signature'}],'failure_reason':None,'api_card_errors':[],'card_notes':[]}
                    if label.startswith('api-verify-'):value['status']='present';value['verification_status']='present'
                    if outer.scenario=='wrong-query':value['query']='Other.method'
                    if outer.scenario=='stale-card':value['freshness']='stale'
                    if outer.scenario=='card-errors':value['api_card_errors']=['SYNTHETIC invalid card']
                    if outer.scenario=='verify-unavailable' and label=='api-0':value.update(status='unknown',entries=[]);code=4
                    if outer.scenario=='verify-unavailable' and label=='api-verify-0':value.update(status='unknown',verification_status='unavailable',entries=[]);code=2
                    stdout=json.dumps(value)+'\n'
                    outer.assertEqual(cwd.name,'fixed');outer.assertIn('--root',argv);outer.assertEqual(Path(argv[argv.index('--root')+1]),cwd)
                if label.startswith('diagnostics-'):stdout='amber-lsp: covered no diagnostics\n'
                if label.startswith('lint-'):stdout='..\n2 inspected, 0 failures\n'
                if outer.scenario=='diagnostic-warning' and label=='diagnostics-fixed-main':stdout='amber-lsp: covered 1 diagnostic, 0 errors\n'
                if outer.scenario=='diagnostic-declined' and label=='diagnostics-fixed-main':stdout='amber-lsp: declined unsupported project\n';code=2
                if outer.scenario=='lint-warning' and label=='lint-original':stdout='2 inspected, 0 failures\nwarning: SYNTHETIC warning\n'
                if outer.scenario=='format-output' and label=='format-original':stdout='SYNTHETIC formatter changed source\n'
                if outer.scenario=='compiler-warning' and label=='no-codegen-fixed':stderr='Warning: SYNTHETIC warning\n'
                if outer.scenario=='compiler-error' and label=='no-codegen-fixed':stderr='Error: SYNTHETIC failure\n';code=1
                if label.startswith('no-codegen-'):
                    outer.assertIn('--no-codegen',argv);outer.assertIn('-Dwithout_mt',argv);outer.assertEqual(argv[argv.index('--threads')+1],'1');outer.assertEqual('-Datlas_fixed_buffer' in argv,label.endswith('-fixed'))
                for stream,value in [('stdout',stdout),('stderr',stderr)]:(s.output/(label+'.'+stream+'.txt')).write_text(value)
                sample={'status':'absent','elapsed_seconds':.01};group={'status':'absent','scope':'original POSIX process group','group':123,'phase':'direct_child_returned','maximum_drain_seconds':5,'elapsed_seconds':.01,'samples':[sample],'initial_sample':sample,'terminal_sample':sample,'bounded_drain_exhausted':False,'drain_deadline':2.,'original_command_deadline':3.}
                row={'label':label,'arguments':list(map(str,argv)),'expected_exit':0,'exit_code':code,'refusal':None,'maximum_seconds':seconds,'elapsed_seconds':.1,'writers_confirmed_retired':True,'pid':123,'original_group':123,'terminal_group_observation':group,'stdout_sha256':producer.digest(s.output/(label+'.stdout.txt')),'stderr_sha256':producer.digest(s.output/(label+'.stderr.txt'))}
                if outer.scenario in ('timeout','unretired') and label=='api-0':
                    row['refusal']='Command exceeded its time budget';row['elapsed_seconds']=seconds+1
                    if outer.scenario=='unretired':s.writers_confirmed_retired=False;row['writers_confirmed_retired']=False;group['status']='present'
                s.records.append(row);s.group_observations.append(group);producer.write(s.output/'COMMANDS.json',s.records)
                if code or row['refusal']:raise RuntimeError('SYNTHETIC command refused '+label)
                return stdout,stderr
        self.driver=SimpleNamespace(Runner=Runner)
        def check():
            if self.scenario in ('provider-return','SDK-return','native-return','job-return','tool-return'):raise RuntimeError('SYNTHETIC '+self.scenario+' differs')
            if self.scenario=='project-source-return':
                p=self.args.output/'private/fixed/src/main.cr';p.write_text('SYNTHETIC changed source')
            if self.scenario=='raw-return':(self.args.output/'amber-lsp-version.stdout.txt').write_text('SYNTHETIC changed raw')
            if self.scenario=='record-return':self.instances[-1].records[0]['arguments'].append('SYNTHETIC added option')
        self.context={'probe':SimpleNamespace(ROOT=self.input,working_bound=probe.working_bound),'driver':self.driver,'proof':self.proof,'admitted':{'job_identity':{'SYNTHETIC':'same-job'},'observed_profile_sha256':'a'*64},'tools':{'tools':self.tools},'paths':{'compiler_wrapper':self.wrapper},'protected':{},'check':check,'native':{'SYNTHETIC':'independently admitted selected native inputs'}}
        self.args=SimpleNamespace(output=self.root/'feedback evidence',packet_sha256='b'*64,proof_tools_sha256='c'*64,tool_policy_sha256='d'*64)
    def perform(self):
        code=producer.execute(self.args,self.context,time.monotonic());return code,json.loads((self.args.output/'SOURCE_GATES.json').read_bytes()),json.loads((self.args.output/'RESULT.json').read_bytes())
    def test_positive_producer_passes_actual_frozen_gate_consumer(self):
        code,gates,result=self.perform();self.assertEqual(code,0);self.assertEqual(result['commands'],43);self.assertTrue(gates['source_provider_return_accepted']);probe.source_gates(self.args.output/'SOURCE_GATES.json',producer.digest(self.args.output/'SOURCE_GATES.json'),{'compiler_profile_sha256':'a'*64},{'SYNTHETIC':'same-job'});self.assertFalse((self.args.output/'private').exists())
    def test_all_unknown_cards_take_exact_compiler_verification_path(self):
        self.scenario='unknown';code,gates,result=self.perform();self.assertEqual(code,0);self.assertEqual(result['commands'],69);self.assertEqual(sum(r['label'].startswith('api-verify-') for r in self.instances[0].records),26)
    def test_exact_original_candidate_restored_sources_are_retained(self):
        self.perform();r=self.args.output/'project_sources';self.assertEqual((r/'original/src/memory_buffer.cr').read_bytes(),(r/'restored/src/memory_buffer.cr').read_bytes());self.assertEqual((r/'fixed/src/memory_buffer.cr').read_bytes(),(self.input/'inputs/memory_buffer.fixed.cr.txt').read_bytes())
    def test_finite_full_command_budget_is_1575_seconds(self):
        methods=json.loads((self.input/'API_PREREQUISITES.json').read_bytes())['methods'];rows=producer.command_roster(methods);self.assertEqual(len(rows),69);self.assertEqual(sum(r[1] for r in rows),1575)
    def test_compiler_and_cache_flags_are_explicit_for_each_arm(self):
        self.perform();rows=self.instances[0].records;self.assertEqual(sum(r['label'].startswith('no-codegen-') for r in rows),3)
    def test_inherited_lookup_body_remains_exact(self):
        source=ast.parse((ROOT/'inputs/dirty_proof.authority.py').read_bytes());self.assertTrue(any(isinstance(n,ast.FunctionDef) and n.name=='lookup' for n in source.body))
    def test_all_project_configuration_is_package_manifest_metadata(self):
        self.perform();text=(self.args.output/'project_sources/fixed/shard.yml').read_text();self.assertIn('targets:',text);self.assertNotIn('CRYSTAL_',text)
    def test_admission_refusal_writes_negative_gate(self):
        with mock.patch.object(producer,'admit',side_effect=RuntimeError('SYNTHETIC missing independently admitted tool registry')):self.assertEqual(producer.main(self.args),2)
        gates=json.loads((self.args.output/'SOURCE_GATES.json').read_bytes());self.assertFalse(gates['tool_provider_review_accepted']);self.assertTrue((self.args.output/'ADMISSION_REFUSAL.json').exists())
    def test_main_positive_uses_actual_producer_body(self):
        with mock.patch.object(producer,'admit',return_value=self.context):self.assertEqual(producer.main(self.args),0)
    def test_insufficient_full_horizon_refuses_before_first_command(self):
        self.assertEqual(producer.execute(self.args,self.context,time.monotonic()-46),2);self.assertEqual(self.instances[0].records,[])
    def test_missing_harness_source_refuses(self):
        (self.input/'buffer_probe.cr.txt').unlink()
        with self.assertRaises(FileNotFoundError):self.perform()
    def test_changed_private_projection_refuses_final_return(self):
        self.scenario='project-source-return';code,gates,result=self.perform();self.assertEqual(code,2);self.assertFalse(gates['no_codegen_accepted']);self.assertTrue(result['finalization_errors'])
    def test_lossless_raw_evidence_reconstructs_every_stream_hash(self):
        self.perform()
        for text in (self.args.output/'COMMAND_EVIDENCE.jsonl').read_text().splitlines():
            row=json.loads(text)
            for stream in ('stdout','stderr'):self.assertEqual(producer.sha(row[stream].encode()),row['record'][stream+'_sha256'])
    def test_environment_uses_admitted_wrapper_and_one_runtime_worker(self):
        p=self.root/'private env';p.mkdir();(p/'home').mkdir()
        with mock.patch.dict(os.environ,{'CRYSTAL_OPTS':'SYNTHETIC foreign options','LD_PRELOAD':'SYNTHETIC foreign preload','CRYSTAL_PATH':'SYNTHETIC foreign overlay'}):env=producer.environment(p,self.wrapper)
        self.assertEqual(env['CRYSTAL_WORKERS'],'1');self.assertNotIn('CRYSTAL_OPTS',env);self.assertNotIn('LD_PRELOAD',env);self.assertNotIn('CRYSTAL_PATH',env)

    def test_actual_admission_requires_hosted_automation(self):
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):self.assertEqual(producer.main(self.args),2)
        self.assertIn('admitted hosted automation',json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['error'])
    def test_actual_admission_refuses_changed_own_manifest_before_import(self):
        self.args.packet_sha256='0'*64
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):self.assertEqual(producer.main(self.args),2)
        self.assertIn('source manifest',json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['error'])
    def test_actual_admission_refuses_missing_base_source_before_tools(self):
        self.args.packet_sha256=producer.digest(ROOT/'SOURCE_PINS.json');self.args.repository=self.root/'absent base source'
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):self.assertEqual(producer.main(self.args),2)
        self.assertIn('FileNotFoundError',json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['error'])
    def stage_args(self):
        return SimpleNamespace(source=self.args.output,output=self.root/'positive public stage',packet_sha256=producer.digest(ROOT/'SOURCE_PINS.json'))
    def test_positive_fixed_stage_keeps_complete_raw_and_exact_sources(self):
        self.perform();args=self.stage_args();staging.stage(args);value=json.loads((args.output/'PUBLIC_STAGE.json').read_bytes());self.assertTrue(value['complete_source_feedback_accepted']);self.assertTrue((args.output/'COMMAND_EVIDENCE.jsonl').is_file());self.assertFalse((args.output/'private').exists())
    def test_stager_refuses_changed_positive_raw_bytes(self):
        self.perform();(self.args.output/'API_CARDS.json').write_text('SYNTHETIC changed output');args=self.stage_args()
        with self.assertRaises(RuntimeError):staging.stage(args)
        self.assertFalse(args.output.exists())
    def test_unknown_writers_stage_only_controller_and_static_source(self):
        self.perform();path=self.args.output/'RESULT.json';value=json.loads(path.read_bytes());value.update(passed=False,writers_confirmed_retired=False);producer.write(path,value);args=self.stage_args();staging.stage(args);self.assertFalse((args.output/'COMMAND_EVIDENCE.jsonl').exists());self.assertFalse((args.output/'SOURCE_GATES.json').exists());self.assertTrue((args.output/'RESULT.json').is_file())
    def test_compiler_error_keeps_RED_traffic_light(self):
        self.scenario='compiler-error';code,gates,result=self.perform();self.assertEqual(result['compiler_color'],'RED');self.assertEqual(code,2)

# Each named scenario exercises the actual producer body and preserves its first error.
def refusal_case(scenario):
    def case(self):
        self.scenario=scenario;code,gates,result=self.perform();self.assertEqual(code,2);self.assertFalse(gates['lookup_accepted']);self.assertFalse(result['passed']);self.assertTrue('error' in result or result['finalization_errors'])
    return case
for scenario in ('wrong-query','stale-card','card-errors','verify-unavailable','diagnostic-warning','diagnostic-declined','lint-warning','format-output','compiler-warning','compiler-error','timeout','unretired','provider-return','SDK-return','native-return','job-return','tool-return','raw-return','record-return'):
    setattr(FeedbackControls,'test_'+scenario.replace('-','_')+'_refuses',refusal_case(scenario))

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FeedbackControls));print(json.dumps({'passed':result.wasSuccessful(),'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'guard_calls':len(CALLS)},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() and not CALLS else 2)
