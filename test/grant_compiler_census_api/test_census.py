"""Guarded metadata/source fixtures; every tool/compiler process is synthetic."""
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent; sys.path.insert(0,str(ROOT))
import run_census as subject
import compiler_proxy as proxy
import artifact
import launch_census as entry

class CensusControls(unittest.TestCase):
    def _setUp_v104(self):
        parent = Path(os.environ['ATLAS_FIXTURE_ROOT']).resolve(); self.temp = tempfile.TemporaryDirectory(prefix='census source fixture with spaces ',dir=parent); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.stack = ExitStack(); self.addCleanup(self.stack.close); self.calls = []
        def guarded(*args,**kwargs):self.calls.append('external'); raise AssertionError('Guarded source fixture requires an authored provider')
        for target in ('subprocess.Popen','os.execve','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.stack.enter_context(mock.patch(target,side_effect=guarded))
        self.addCleanup(lambda:self.assertEqual(self.calls,[])); self.scenario = 'normal'; self.runners = []
        self.wrapper = self.root/'installed/bin/crystal-alpha'; self.wrapper.parent.mkdir(parents=True); self.wrapper.write_text('SYNTHETIC admitted static wrapper'); self.wrapper.chmod(0o755)
        self.backend = self.root/'installed/libexec/agent-crystal-bin'; self.backend.parent.mkdir(); self.backend.write_text('SYNTHETIC admitted backend'); self.backend.chmod(0o755)
        self.sdk = self.root/'SDK'; self.sdk.mkdir(); (self.sdk/'brew-prefix.stdout.txt').write_text(str(self.root/'installed')+'\n'); (self.sdk/'brew-root.stdout.txt').write_text(str(self.root/'brew')+'\n')
        self.tools = {}
        for key in ('amber_lsp','ameba'):
            path = self.root/key; path.write_text('SYNTHETIC admitted '+key); path.chmod(0o755); self.tools[key] = dict(path=str(path))
        self.llvm = self.root/'llvm-config'; self.llvm.write_text('SYNTHETIC LLVM metadata provider'); self.llvm.chmod(0o755)
        self.admission = dict(job_identity=dict(SYNTHETIC='same job',run_attempt='1',nonce='fixture'),observed_profile_sha256='a'*64,providers=dict(compiler_wrapper=dict(path=str(self.wrapper),sha256=subject.sha(self.wrapper.read_bytes())),compiler_backend=dict(path=str(self.backend),sha256=subject.sha(self.backend.read_bytes()))))
        self.args = SimpleNamespace(operation='execute',output=self.root/'output',sdk_evidence=self.sdk,packet_sha256=subject.sha((ROOT/'SOURCE_PINS.json').read_bytes()),decision_sha256='b'*64,proof_tools_sha256='c'*64,tool_policy_sha256='d'*64,native_policy_sha256='e'*64,policy_result_sha256='f'*64)
        self.material = dict(format='atlas-native-buffer-policy-materialization-v1',passed=True,execution_admitted=True,finalization_errors=[],job_identity=self.admission['job_identity'],compiler_profile_sha256='a'*64,compiler_backend_sha256=self.admission['providers']['compiler_backend']['sha256'],stable_view_sha256='8'*64,policies={})
        self.native_policy = dict(llvm_library=str(self.root/'libLLVM.dylib'))
        for field,name,value in [('native_policy','NATIVE_POLICY.json',self.native_policy),('tool_policy','TOOL_POLICY.json',dict(execution_admitted=True)),('proof_tools','PROOF_TOOLS.json',dict(tools=self.tools)),('policy_result','POLICY_RESULT.json',self.material)]:
            path = self.root/name; path.write_bytes(subject.canonical(value)); setattr(self.args,field,path); setattr(self.args,field+'_sha256',subject.sha(path.read_bytes()))
            if field != 'policy_result':self.material['policies'][name] = subject.sha(path.read_bytes())
        self.args.policy_result.write_bytes(subject.canonical(self.material)); self.args.policy_result_sha256 = subject.sha(self.args.policy_result.read_bytes())
        self.llvm_identity = dict(format='atlas-census-llvm-config-stable-v1',declared_path=str(self.llvm),resolved_path=str(self.llvm),bytes=self.llvm.stat().st_size,sha256=subject.sha(self.llvm.read_bytes()),mode=0o755,imports=['/usr/lib/libSystem.B.dylib'],rpaths=[],links=[],package_version='21.1.8',selected_llvm_library=str(self.root/'libLLVM.dylib'),dependencies=[dict(imported='/usr/lib/libSystem.B.dylib',scope='Apple-platform',shared_cache_body_qualified=False)],unresolved_imports=[],native_file_closure_covered=True,dyld_shared_cache_bytes_qualified=False)
        self.decision = dict(format='atlas-compiler-census-api-review-decision-v1',execution_admitted=True,scope='compiler-census-api-and-concrete-receiver-only',independent_review_sha256='9'*64,reviewed_native_stable_view_sha256='8'*64,reviewed_llvm_config=self.llvm_identity,LLVM_config_code_loading_reviewed=True,Apple_platform_code_loading_reviewed=True,protocol=subject.decode(subject.canonical(dict(source_manifest_sha256=self.args.packet_sha256,api_roster_sha256=subject.sha((ROOT/'API_ROSTER.json').read_bytes()),compiler_distribution_sha256=subject.ARCHIVE_SHA,compiler_commit=subject.COMPILER_COMMIT,canonical_gc_sha256=subject.CANONICAL_GC_SHA,accepted_analysis_stable_sha256=subject.STABLE_TOOLS_SHA,context=subject.CONTEXT,maximum_seconds=2700,command_roster=subject.command_roster()))))
        self.args.decision = self.root/'SCOPE_DECISION.json'; self.seal_decision()
        outer = self
        class Runner:
            def __init__(runner,output):runner.output=output; runner.records=[]; runner.group_observations=[]; runner.writers_confirmed_retired=True; runner.deadline=0; outer.runners.append(runner)
            def run(runner,label,argv,*,cwd,environment,expected_exit=0,seconds=300):
                stdout = ''; stderr = ''; code = expected_exit
                if label == 'pkg-config-version':stdout='3.0.10\n'
                if label == 'pkg-config-bdw-gc-version':stdout='8.2.12\n'
                if label == 'pkg-config-bdw-gc-pcfiledir':stdout=environment['PKG_CONFIG_LIBDIR']+'\n'
                if label == 'llvm-config-version':stdout = '21.1.8\n'
                if label == 'amber-lsp-version':stdout = 'amber-lsp 2.0.7\n'
                if label == 'ameba-version':stdout = 'Ameba 1.7.0-dev\n'
                if label.startswith('api-'):
                    query = argv[2]; unknown = outer.scenario in ('all-unknown','unavailable') and not label.startswith('api-verify-'); code = 4 if unknown else 0
                    answer = dict(query=query,status='unknown' if unknown else 'found',freshness='fresh',entries=[] if unknown else [dict(name=query,return_type='SYNTHETIC signature')],api_card_errors=[],failure_reason=None,verification_status='present' if label.startswith('api-verify-') else None)
                    if outer.scenario == 'wrong-query':answer['query']='SYNTHETIC changed question'
                    if outer.scenario == 'stale':answer['freshness']='stale'
                    if outer.scenario == 'absent' and label == 'api-0':answer.update(status='absent',entries=[]); code=5
                    if outer.scenario == 'card-errors':answer['api_card_errors']=['SYNTHETIC card error']
                    if outer.scenario == 'unavailable' and label.startswith('api-verify-'):answer.update(status='unknown',verification_status='unavailable',failure_reason='SYNTHETIC unsupported receiver',entries=[]); code=2
                    stdout = json.dumps(answer)+'\n'; outer.assertEqual(cwd,Path(argv[argv.index('--root')+1]))
                if label == 'compatibility-gc_stats_wrong_type':stderr = 'Error: SYNTHETIC UInt64 cannot match String\n'
                if outer.scenario == 'wrong-type-control-green' and label == 'compatibility-gc_stats_wrong_type':code=0; stderr=''
                if outer.scenario == 'warning' and label == 'compatibility-gc_stats':stderr='Warning: SYNTHETIC compiler warning\n'
                if outer.scenario == 'compile-error' and label == 'compatibility-initialized_graph':code=1; stderr='Error: SYNTHETIC incompatible receiver\n'
                if outer.scenario == 'format-refusal' and label == 'format-source_origins':code=1; stderr='SYNTHETIC formatting required\n'
                sample=dict(status='absent',elapsed_seconds=.01); group=dict(status='absent',scope='original POSIX process group',group=1000+len(runner.records),phase='direct_child_returned',maximum_drain_seconds=5,elapsed_seconds=.01,samples=[sample],initial_sample=sample,terminal_sample=sample,bounded_drain_exhausted=False,drain_deadline=2.,original_command_deadline=3.)
                for stream,text in [('stdout',stdout),('stderr',stderr)]:(runner.output/(label+'.'+stream+'.txt')).write_text(text)
                row=dict(label=label,arguments=list(map(str,argv)),expected_exit=expected_exit,exit_code=code,refusal=None,maximum_seconds=seconds,elapsed_seconds=.1,writers_confirmed_retired=True,pid=group['group'],original_group=group['group'],terminal_group_observation=group,stdout_sha256=subject.sha(stdout.encode()),stderr_sha256=subject.sha(stderr.encode()))
                if label.startswith('compatibility-'):
                    config=subject.decode(subject.stable(Path(environment['ATLAS_CENSUS_PROXY_CONFIG']))); original_arguments=list(map(str,argv[1:])); record=dict(original_arguments=original_arguments,executed_arguments=[config['backend'],*proxy.derive(original_arguments,str(cwd),config['stdlib'])],cwd=str(cwd),project_role='canonical-project',source_resolutions={value:str(Path(value).resolve()) for value in original_arguments if value.endswith('.cr')},pid=group['group'],process_group=group['group'],configuration_sha256=environment['ATLAS_CENSUS_PROXY_CONFIG_SHA256'],environment={key:environment.get(key) for key in sorted(set(config['environment'])|{'CRYSTAL_CACHE_DIR'})})
                    with open(config['journal'],'ab') as stream:stream.write(subject.canonical(record)+b'\n')
                if outer.scenario == 'timeout' and label == 'api-0':row.update(refusal='SYNTHETIC command deadline',elapsed_seconds=seconds+1)
                if outer.scenario == 'unretired' and label == 'api-0':runner.writers_confirmed_retired=False; row['writers_confirmed_retired']=False; group['status']='present'
                runner.records.append(row); runner.group_observations.append(group)
                if code != expected_exit or row['refusal'] or not runner.writers_confirmed_retired:raise RuntimeError('SYNTHETIC original Runner refusal')
                return stdout,stderr
        def check():
            if self.scenario in ('provider-return','SDK-return','tool-return','native-return','job-return'):raise RuntimeError('SYNTHETIC changed '+self.scenario)
            if self.scenario == 'source-return':(self.args.output/'private/compiler/census_probes/gc_stats.cr').write_text('SYNTHETIC changed source')
            if self.scenario == 'raw-return':(self.args.output/'api-0.stdout.txt').write_text('SYNTHETIC changed raw output')
            if self.scenario == 'record-return':self.runners[-1].records[0]['arguments'].append('SYNTHETIC changed argv')
        self.context = dict(driver=SimpleNamespace(Runner=Runner),paths=dict(compiler_wrapper=self.wrapper,compiler_backend=self.backend),tools=dict(tools=self.tools),admitted=self.admission,native_policy=self.native_policy,llvm_config=self.llvm_identity,check=check,decision=self.decision,protected={},probe=SimpleNamespace(native_policy=lambda *args:(self.native_policy,{},{})))
        self.context['metadata_native_receipt']=dict(format='atlas-native-buffer-provider-observation-v1',passed=True,complete=True,source_provider_return_accepted=True,job_identity=self.admission['job_identity'],compiler_profile_sha256=self.admission['observed_profile_sha256'],stable_view_sha256=self.material['stable_view_sha256'],source_manifest_sha256='81823332a17911e16169d784da046ff4c9e5755aee4bb628724778cc5bc55693',receipt_sha256='f'*64)
    def setUp(self):
        self._setUp_v104()
        import fixture_v105
        self.pkg=fixture_v105.descriptor(subject,self.root/'pkgconf fixture')
        self.context['pkgconf']=self.pkg
        self.decision.update(reviewed_pkgconf=self.pkg,pkgconf_code_loading_reviewed=True)
        self.seal_decision()
        self.args.pkgconf_observation=self.root/'PKGCONF_INPUTS.original.json'
        self.args.pkgconf_observation.write_bytes(subject.canonical(dict(SYNTHETIC='direct controller native-policy fixture')))
        self.args.pkgconf_observation_sha256=subject.sha(self.args.pkgconf_observation.read_bytes())
    def seal_decision(self):
        self.args.decision.write_bytes(subject.canonical(self.decision)); self.args.decision_sha256=subject.sha(self.args.decision.read_bytes())
    def synthetic_project(self,project,deadline):
        project.mkdir(); (project/'src').mkdir(); path=project/'src/fixture.cr'; path.write_text('# SYNTHETIC complete-project test seam\n')
        rows={'src':dict(path='src',kind='directory',mode=stat_mode(project/'src')),'src/fixture.cr':dict(path='src/fixture.cr',kind='file',mode=0o644,bytes=path.stat().st_size,sha256=subject.sha(path.read_bytes()))}
        return subject.physical_tree(project,rows,deadline)
    def perform(self,real_archive=False,started=None):
        owned=subject.Owned(self.args.output); owned.write('PKGCONF_INPUTS.json',subject.stable(self.args.pkgconf_observation,16*2**20))
        with (mock.patch.object(subject,'extract_project',side_effect=self.synthetic_project) if not real_archive else ExitStack()):code=subject.execute(self.args,self.context,owned,time.monotonic() if started is None else started)
        return code,json.loads((self.args.output/'RESULT.json').read_bytes())
    def test_real_complete_archive_and_canonical_gc_source(self):
        project=self.root/'complete project'; before=subject.extract_project(project,time.monotonic()+60); rows={name:{k:v for k,v in row.items() if k!='physical_identity'} for name,row in before['files'].items()}; self.assertEqual(len(rows),3190); self.assertEqual(sum(row['kind']=='file' for row in rows.values()),2752); self.assertEqual(subject.physical_tree(project,rows,time.monotonic()+60),before); self.assertEqual(subject.sha((project/'src/gc/boehm.cr').read_bytes()),subject.CANONICAL_GC_SHA)
    def test_positive_actual_controller_body(self):
        code,result=self.perform(); self.assertEqual(code,0); self.assertEqual(result['commands'],70); self.assertEqual(result['compiler_color'],'GREEN'); self.assertTrue(result['source_provider_return_accepted']); self.assertTrue(result['private_removed']); self.assertFalse((self.args.output/'private').exists())
    def test_real_archive_producer_stager_reader_and_resealed_damage(self):
        code,result=self.perform(real_archive=True); self.assertEqual(code,0); public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
        original=(public/'RESULT.json').read_bytes(); stage_original=(public/'PUBLIC_STAGE.json').read_bytes()
        for key,value in [('compiler_color','YELLOW'),('private_removed',False),('commands',False),('maximum_seconds',2700.0),('compiler_profile_sha256','0'*64),('actual_target_cells_accepted',1)]:
            with self.subTest(key=key):
                bad=json.loads(original); bad[key]=value; (public/'RESULT.json').write_bytes(subject.canonical(bad)); manifest=json.loads(stage_original)
                for row in manifest['files']:
                    if row['path']=='RESULT.json':row.update(bytes=(public/'RESULT.json').stat().st_size,sha256=subject.sha((public/'RESULT.json').read_bytes()))
                (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(manifest))
                with self.assertRaises(RuntimeError):artifact.replay(public,self.args.packet_sha256)
                (public/'RESULT.json').write_bytes(original); (public/'PUBLIC_STAGE.json').write_bytes(stage_original)
        for label in ('amber-lsp-version','ameba-version'):
            originals={name:(public/name).read_bytes() for name in (label+'.stdout.txt','COMMAND_EVIDENCE.jsonl','PUBLIC_STAGE.json')}; text='SYNTHETIC unrelated version\n'; (public/(label+'.stdout.txt')).write_text(text); journal=[json.loads(line) for line in originals['COMMAND_EVIDENCE.jsonl'].splitlines()]
            for item in journal:
                if item['record']['label']==label:item['stdout']=text; item['record']['stdout_sha256']=subject.sha(text.encode())
            (public/'COMMAND_EVIDENCE.jsonl').write_bytes(b''.join(subject.canonical(item)+b'\n' for item in journal)); projection=json.loads(stage_original)
            for row in projection['files']:
                raw=(public/row['path']).read_bytes(); row.update(bytes=len(raw),sha256=subject.sha(raw))
            (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(projection))
            with self.assertRaises(RuntimeError):artifact.replay(public,self.args.packet_sha256)
            for name,raw in originals.items():(public/name).write_bytes(raw)
        added=public/'unexpected.json'; added.write_text('{"SYNTHETIC":"unselected public member"}\n'); projection=json.loads(stage_original); projection['files'].append(dict(path='unexpected.json',bytes=added.stat().st_size,sha256=subject.sha(added.read_bytes()))); (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(projection))
        with self.assertRaisesRegex(RuntimeError,'fixed source-selected'):artifact.replay(public,self.args.packet_sha256)
        added.unlink(); (public/'PUBLIC_STAGE.json').write_bytes(stage_original)
        original_proxy=(public/'PROXY_COMMANDS.jsonl').read_bytes(); records=[json.loads(line) for line in original_proxy.splitlines()]; records[0]['SYNTHETIC_public_content_control']='ghp_'+('A'*36); (public/'PROXY_COMMANDS.jsonl').write_bytes(b''.join(subject.canonical(row)+b'\n' for row in records)); projection=json.loads(stage_original)
        for row in projection['files']:
            if row['path']=='PROXY_COMMANDS.jsonl':row.update(bytes=(public/row['path']).stat().st_size,sha256=subject.sha((public/row['path']).read_bytes()))
        (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(projection))
        with self.assertRaisesRegex(ValueError,'credential-shaped'):artifact.replay(public,self.args.packet_sha256)
        (public/'PROXY_COMMANDS.jsonl').write_bytes(original_proxy); (public/'PUBLIC_STAGE.json').write_bytes(stage_original)
        self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
    def test_metadata_only_observation_returns_no_tool_commands(self):
        self.args.operation='observe'; self.context['native_materialization']=self.material; self.context['llvm_config_physical']=dict(SYNTHETIC='retained exact original alias chain')
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(subject.main(self.args),0)
        self.assertEqual(self.runners,[]); result=json.loads((self.args.output/'CENSUS_PROVIDER_CANDIDATE.json').read_bytes()); self.assertFalse(result['execution_admitted']); self.assertEqual(result['actual_compiler_commands'],0)
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertFalse(artifact.replay(public,self.args.packet_sha256)['execution_admitted'])
    def test_metadata_reader_refuses_resealed_missing_changed_and_stale_joins(self):
        self.args.operation='observe'; self.context['native_materialization']=self.material; self.context['llvm_config_physical']=dict(SYNTHETIC='retained exact original alias chain')
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(subject.main(self.args),0)
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertFalse(artifact.replay(public,self.args.packet_sha256)['execution_admitted'])
        candidate_raw=(public/'CENSUS_PROVIDER_CANDIDATE.json').read_bytes(); metadata_raw=(public/'METADATA_ADMISSION.json').read_bytes(); projection_raw=(public/'PUBLIC_STAGE.json').read_bytes()
        controls=[('remove-provider',lambda v:v.pop('llvm_config')),('changed-provider',lambda v:v.__setitem__('llvm_config',{})),('stale-job',lambda v:v.__setitem__('job_identity',dict(SYNTHETIC='another job'))),('stale-profile',lambda v:v.__setitem__('compiler_profile_sha256','0'*64)),('stale-backend',lambda v:v.__setitem__('compiler_backend_sha256','0'*64)),('stale-native',lambda v:v.__setitem__('native_stable_view_sha256','0'*64)),('missing-physical-return',lambda v:v.__setitem__('llvm_config_physical',{})),('changed-admission-hash',lambda v:v.__setitem__('metadata_admission_sha256','0'*64)),('wrong-max-type',lambda v:v.__setitem__('maximum_seconds',120.0))]
        for label,change in controls:
            with self.subTest(label=label):
                candidate=json.loads(candidate_raw); change(candidate); (public/'CENSUS_PROVIDER_CANDIDATE.json').write_bytes(subject.canonical(candidate)); projection=json.loads(projection_raw)
                for row in projection['files']:
                    body=(public/row['path']).read_bytes(); row.update(bytes=len(body),sha256=subject.sha(body))
                (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(projection))
                with self.assertRaises((RuntimeError,KeyError)):artifact.replay(public,self.args.packet_sha256)
                (public/'CENSUS_PROVIDER_CANDIDATE.json').write_bytes(candidate_raw); (public/'METADATA_ADMISSION.json').write_bytes(metadata_raw); (public/'PUBLIC_STAGE.json').write_bytes(projection_raw)
        self.assertFalse(artifact.replay(public,self.args.packet_sha256)['execution_admitted'])
    def test_metadata_reader_revalidates_complete_source_after_final_physical_return(self):
        self.args.operation='observe'; self.context['native_materialization']=self.material; self.context['llvm_config_physical']=dict(SYNTHETIC='retained exact original alias chain')
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(subject.main(self.args),0)
        public=self.root/'source-return-public'; artifact.stage(self.args.output,public,self.args.packet_sha256)
        copied=self.root/'owned source copy'; shutil.copytree(ROOT,copied)
        spec=importlib.util.spec_from_file_location('owned_source_return_artifact',copied/'artifact.py'); reader=importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
        self.assertTrue(reader.replay(public,self.args.packet_sha256)['passed'])
        proxy_source=copied/'compiler_proxy.py'; original=proxy_source.read_bytes(); physical=reader.physical; observations=[]
        def late_physical(*args,**kwargs):
            paths=physical(*args,**kwargs); observations.append(True)
            if len(observations)==2:proxy_source.write_bytes(original+b'\n# SYNTHETIC final-source-return sensitivity\n')
            return paths
        with mock.patch.object(reader,'physical',side_effect=late_physical),self.assertRaises(RuntimeError):reader.replay(public,self.args.packet_sha256)
        self.assertEqual(len(observations),2); self.assertNotEqual(proxy_source.read_bytes(),original)
        proxy_source.write_bytes(original); self.assertTrue(reader.replay(public,self.args.packet_sha256)['passed'])
    def test_literal_metadata_return_compares_self_consistent_receipt_to_fresh_inputs(self):
        self.args.operation='observe'; self.context['native_materialization']=self.material; self.context['llvm_config_physical']=dict(SYNTHETIC='retained exact original alias chain')
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(subject.main(self.args),0)
        values=SimpleNamespace(**vars(self.args)); args=SimpleNamespace(source=self.args.output,packet_sha256=self.args.packet_sha256)
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(entry.metadata_return(subject,args,values),0)
        candidate_raw=(self.args.output/'CENSUS_PROVIDER_CANDIDATE.json').read_bytes(); admission_raw=(self.args.output/'METADATA_ADMISSION.json').read_bytes()
        for field in ('job','profile','backend','native','descriptor','physical'):
            candidate=json.loads(candidate_raw); admitted=json.loads(admission_raw)
            if field=='job':candidate['job_identity']=dict(SYNTHETIC='self-consistent other job'); admitted['SDK']['job_identity']=candidate['job_identity']; admitted['native_receipt']['job_identity']=candidate['job_identity']
            if field=='profile':candidate['compiler_profile_sha256']='0'*64; admitted['SDK']['observed_profile_sha256']='0'*64; admitted['native_receipt']['compiler_profile_sha256']='0'*64
            if field=='backend':candidate['compiler_backend_sha256']='0'*64; admitted['SDK']['providers']['compiler_backend']['sha256']='0'*64
            if field=='native':candidate['native_stable_view_sha256']='0'*64; admitted['native_receipt']['stable_view_sha256']='0'*64
            if field=='descriptor':candidate['llvm_config']['sha256']='0'*64; admitted['llvm_config_before']['sha256']='0'*64
            if field=='physical':candidate['llvm_config_physical']=dict(SYNTHETIC='self-consistent other physical input'); admitted['llvm_config_physical_before']=candidate['llvm_config_physical']
            metadata=subject.canonical(admitted); candidate['metadata_admission_sha256']=subject.sha(metadata); (self.args.output/'METADATA_ADMISSION.json').write_bytes(metadata); (self.args.output/'CENSUS_PROVIDER_CANDIDATE.json').write_bytes(subject.canonical(candidate))
            artifact.validate_metadata_candidate(subject,candidate,metadata,self.args.packet_sha256)
            with mock.patch.object(subject,'admit_observation',return_value=self.context),self.assertRaises(RuntimeError):entry.metadata_return(subject,args,values)
            (self.args.output/'CENSUS_PROVIDER_CANDIDATE.json').write_bytes(candidate_raw); (self.args.output/'METADATA_ADMISSION.json').write_bytes(admission_raw)
        with mock.patch.object(subject,'admit_observation',return_value=self.context):self.assertEqual(entry.metadata_return(subject,args,values),0)
    def test_main_actual_admission_failure_retains_refusal(self):
        with mock.patch.object(subject,'admit',side_effect=RuntimeError('SYNTHETIC missing same-job admission')):self.assertEqual(subject.main(self.args),2)
        self.assertEqual(self.runners,[]); self.assertFalse(json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['passed'])
    def test_proxy_actual_launch_journals_then_executes_same_process(self):
        project=self.root/'proxy project'; project.mkdir(); (project/'probe.cr').write_text('# SYNTHETIC receiver'); private=self.root; journal=self.root/'proxy.jsonl'; journal.write_bytes(b'')
        environment=dict(PATH='/usr/bin:/bin',HOME=str(self.root),CRYSTAL_CACHE_DIR=str(self.root/'cache'),CRYSTAL_PATH=str(project))
        config=dict(format='atlas-census-compiler-proxy-v1',providers=[dict(path=str(self.backend),sha256=subject.sha(self.backend.read_bytes()))],project=str(project),private=str(private),private_identity=subject.identity(private)[:3],stdlib=str(self.root/'stdlib'),environment={k:v for k,v in environment.items() if k!='CRYSTAL_CACHE_DIR'},backend=str(self.backend),journal=str(journal),journal_identity=subject.identity(journal)[:3])
        path=self.root/'config.json'; path.write_bytes(subject.canonical(config)); environment.update(ATLAS_CENSUS_PROXY_CONFIG=str(path),ATLAS_CENSUS_PROXY_CONFIG_SHA256=subject.sha(path.read_bytes()))
        class ExecObserved(Exception):pass
        with mock.patch('os.getcwd',return_value=str(project)),mock.patch('os.execve',side_effect=ExecObserved) as executed:
            with self.assertRaises(ExecObserved):proxy.launch(['build','--no-codegen',str(project/'probe.cr')],environment)
        row=json.loads(journal.read_bytes()); self.assertEqual(row['pid'],os.getpid()); self.assertEqual(row['process_group'],os.getpgrp()); self.assertEqual(row['original_arguments'],['build','--no-codegen',str(project/'probe.cr')]); self.assertEqual(row['executed_arguments'],[str(self.backend),*row['original_arguments'],*proxy.FLAGS]); self.assertEqual(executed.call_args.args[0],str(self.backend))
    def test_proxy_changed_provider_refuses_before_exec(self):
        path=self.root/'config.json'; value=dict(format='atlas-census-compiler-proxy-v1',private=str(self.root),private_identity=subject.identity(self.root)[:3],providers=[dict(path=str(self.backend),sha256='0'*64)]); path.write_bytes(subject.canonical(value))
        with self.assertRaises(RuntimeError):proxy.launch(['--version'],dict(ATLAS_CENSUS_PROXY_CONFIG=str(path),ATLAS_CENSUS_PROXY_CONFIG_SHA256=subject.sha(path.read_bytes())))
    def test_plain_source_inode_change_is_detected(self):
        project=self.root/'SYNTHETIC source'; original=self.synthetic_project(project,time.monotonic()+30); rows={key:{k:v for k,v in value.items() if k!='physical_identity'} for key,value in original['files'].items()}; old=project/'src/fixture.cr'; replacement=project/'replacement'; replacement.write_bytes(old.read_bytes()); os.replace(replacement,old); self.assertNotEqual(subject.physical_tree(project,rows,time.monotonic()+30),original)
    def test_original_source_alias_and_special_node_kind_refusal(self):
        project=self.root/'SYNTHETIC source'; original=self.synthetic_project(project,time.monotonic()+30); rows={key:{k:v for k,v in value.items() if k!='physical_identity'} for key,value in original['files'].items()}; file=project/'src/fixture.cr'; file.unlink(); file.symlink_to(self.args.native_policy)
        with self.assertRaises(RuntimeError):subject.physical_tree(project,rows,time.monotonic()+30)
    def native_config_fixture(self,imports,rpaths=None):
        brew=self.root/'brew'; package=brew/'Cellar/llvm@21/21.1.8'; (package/'bin').mkdir(parents=True); (package/'lib').mkdir(); (brew/'opt').mkdir(); (brew/'opt/llvm@21').symlink_to(package)
        config=package/'bin/llvm-config'; config.write_text('SYNTHETIC Mach-O LLVM config bytes'); config.chmod(0o755); library=package/'lib/libLLVM.dylib'; library.write_text('SYNTHETIC covered LLVM library')
        def resolve(path):
            logical=Path(path); links=[]
            alias=brew/'opt/llvm@21'
            if str(logical).startswith(str(alias)):
                links.append(dict(path=str(alias),target=os.readlink(alias),physical_identity=subject.identity(alias)))
            physical=logical.resolve(strict=True); return dict(declared_path=str(logical),resolved_path=str(physical),links=links,resolved_physical_identity=subject.identity(physical))
        value=dict(path=str(library),bytes=library.stat().st_size,sha256=subject.sha(library.read_bytes()),mode=0o644)
        context=dict(transfer=SimpleNamespace(resolve_native=resolve),provider_parser=SimpleNamespace(macho=lambda raw,transfer:dict(imports=imports,rpaths=rpaths or []),resolve_input=lambda path,transfer:resolve(path)),selected_llvm_library=str(library),covered_native_files={str(library):value})
        return context,config,library
    def test_extra_config_loader_dependency_joins_prior_exact_bytes(self):
        context,config,library=self.native_config_fixture(['@loader_path/../lib/libLLVM.dylib','/usr/lib/libSystem.B.dylib']); value=subject.llvm_config_identity(self.args,context); self.assertTrue(value['native_file_closure_covered']); self.assertEqual(value['unresolved_imports'],[]); self.assertEqual(value['dependencies'][0]['scope'],'admitted-native-file'); self.assertFalse(value['dyld_shared_cache_bytes_qualified'])
    def test_extra_config_uncovered_library_is_retained_unadmitted(self):
        context,config,library=self.native_config_fixture(['@loader_path/../lib/libLLVM.dylib']); context['covered_native_files']={}; value=subject.llvm_config_identity(self.args,context); self.assertFalse(value['native_file_closure_covered']); self.assertEqual(value['dependencies'][0]['scope'],'uncovered-native-file'); self.assertTrue(value['unresolved_imports'])
    def test_extra_config_changed_prior_library_bytes_refuse_coverage(self):
        context,config,library=self.native_config_fixture(['@loader_path/../lib/libLLVM.dylib']); library.write_text('SYNTHETIC changed native bytes'); self.assertFalse(subject.llvm_config_identity(self.args,context)['native_file_closure_covered'])
    def test_extra_config_rpath_unresolved_is_explicit(self):
        context,config,library=self.native_config_fixture(['@rpath/libExtra.dylib'],['@loader_path/../lib']); value=subject.llvm_config_identity(self.args,context); self.assertTrue(value['unresolved_imports']); self.assertFalse(value['native_file_closure_covered'])
    def test_extra_config_same_bytes_inode_drift_changes_physical_return(self):
        context,config,library=self.native_config_fixture(['@loader_path/../lib/libLLVM.dylib']); before=subject.llvm_config_physical(self.args,context); replacement=library.parent/'replacement'; replacement.write_bytes(library.read_bytes()); os.replace(replacement,library); self.assertNotEqual(subject.llvm_config_physical(self.args,context),before)
    def test_extra_config_package_library_mismatch_refuses(self):
        context,config,library=self.native_config_fixture([]); context['selected_llvm_library']=str(self.root/'different/lib/libLLVM.dylib')
        with self.assertRaises(RuntimeError):subject.llvm_config_identity(self.args,context)
    def test_execute_refuses_uncovered_import_even_reviewer_flag_is_positive(self):
        self.llvm_identity.update(unresolved_imports=[dict(SYNTHETIC='uncovered input')],native_file_closure_covered=False); self.decision['reviewed_llvm_config']=self.llvm_identity; self.seal_decision(); self.context['llvm_config']=self.llvm_identity
        with mock.patch.object(subject,'llvm_config_identity',return_value=self.llvm_identity):
            with self.assertRaises(RuntimeError):subject.admit_decision(self.args,self.context,{})
    def test_every_unknown_takes_actual_verify_path(self):
        self.scenario='all-unknown'; code,result=self.perform(); self.assertEqual(code,0); self.assertEqual(result['commands'],126); self.assertEqual(sum(row['label'].startswith('api-verify-') for row in self.runners[-1].records),56)
    def test_unavailable_retains_every_card_and_concrete_probe(self):
        self.scenario='unavailable'; code,result=self.perform(); self.assertEqual(code,2); self.assertTrue(result['diagnostic_collection_complete']); self.assertEqual(result['commands'],126); self.assertFalse(result['required_API_cards_accepted']); self.assertEqual(len(json.loads((self.args.output/'API_CARDS.json').read_bytes())),56)
    def test_absent_keeps_remaining_card_evidence(self):
        self.scenario='absent'; code,result=self.perform(); self.assertEqual(code,2); self.assertTrue(result['diagnostic_collection_complete']); self.assertEqual(result['commands'],70)
    def test_original_command_budget_and_complete_phase(self):
        rows=subject.command_roster(); self.assertEqual(len(rows),126); self.assertEqual(sum(seconds for _,seconds in rows),2310); self.assertLessEqual(120+2310+180,2700); self.assertEqual(dict(rows)['api-0'],120); self.assertEqual(dict(rows)['compatibility-gc_stats_wrong_type'],60)
    def test_insufficient_complete_reservation_launches_zero_commands(self):
        code,result=self.perform(started=time.monotonic()-121); self.assertEqual(code,2); self.assertEqual(result['commands'],0)
    def test_preexisting_output_is_untouched(self):
        self.args.output.mkdir(); marker=self.args.output/'ADMISSION_REFUSAL.json'; marker.write_text('SYNTHETIC original bytes')
        with self.assertRaises(RuntimeError):subject.main(self.args)
        self.assertEqual(marker.read_text(),'SYNTHETIC original bytes')
    def test_aliased_output_is_untouched(self):
        target=self.root/'original'; target.mkdir(); self.args.output.symlink_to(target)
        with self.assertRaises(RuntimeError):subject.main(self.args)
        self.assertEqual(list(target.iterdir()),[])
    def test_owned_output_replacement_refuses_write(self):
        owned=subject.Owned(self.args.output); owned.write('PKGCONF_INPUTS.json',subject.stable(self.args.pkgconf_observation,16*2**20)); moved=self.root/'moved'; self.args.output.rename(moved); self.args.output.mkdir()
        with self.assertRaises(RuntimeError):owned.json('RESULT.json',{})
    def test_owned_file_alias_refuses_write(self):
        owned=subject.Owned(self.args.output); owned.write('PKGCONF_INPUTS.json',subject.stable(self.args.pkgconf_observation,16*2**20)); (self.args.output/'RESULT.json').symlink_to(self.args.native_policy)
        with self.assertRaises(RuntimeError):owned.json('RESULT.json',{})
    def test_source_manifest_changed_refuses_before_import(self):
        with self.assertRaises(RuntimeError):subject.manifest(ROOT,'0'*64)
    def test_installed_entrypoint_changed_manifest_refuses(self):
        with self.assertRaises(RuntimeError):entry.protect('0'*64)
    def test_native_policy_positive_complete_join(self):
        self.assertEqual(subject.native_inputs(self.args,self.context,{})[0],self.native_policy)
    def test_distinct_positive_decision(self):
        with mock.patch.object(subject,'llvm_config_identity',return_value=self.llvm_identity):self.assertEqual(subject.admit_decision(self.args,self.context,{}),self.decision)
    def test_missing_distinct_decision_refuses(self):
        self.args.decision.unlink()
        with self.assertRaises(FileNotFoundError):subject.admit_decision(self.args,self.context,{})
    def test_all_gc_counter_calls_and_exact_original_questions_retained(self):
        roster=json.loads((ROOT/'API_ROSTER.json').read_bytes()); previous=json.loads((ROOT/'inputs/FRONTEND_API_ROSTER.v100.json').read_bytes()); self.assertEqual([row['query'] for row in roster['queries'][:15]],[row['query'] for row in previous['queries']]); self.assertEqual(len(roster['gc_stats_fields']),5); self.assertEqual(len(roster['gc_prof_stats_fields']),12)
    def test_lossless_failed_command_and_raw_return(self):
        self.scenario='timeout'; code,result=self.perform(); rows=[json.loads(raw) for raw in (self.args.output/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()]; self.assertEqual(code,2); self.assertEqual(len(rows),result['commands']); self.assertEqual(rows[-1]['record']['refusal'],'SYNTHETIC command deadline'); self.assertTrue(result['private_removed'])
    def test_card_json_duplicate_and_nonfinite_refuse(self):
        self.assertFalse(subject.card('{"query":"Q","query":"Q"}','Q',0)['accepted']); self.assertFalse(subject.card('{"query":"Q","x":NaN}','Q',0)['accepted'])
    def test_safe_stager_positive_and_extra_credential_directory_excluded(self):
        self.perform(); secret=self.args.output/'.git'; secret.mkdir(); (secret/'config.json').write_text('{"SYNTHETIC":"private extra metadata"}'); destination=self.root/'public'; value=artifact.stage(self.args.output,destination,self.args.packet_sha256); self.assertTrue(value['passed']); self.assertFalse((destination/'.git').exists()); self.assertFalse((destination/'private').exists())
    def test_public_projection_directory_alias_refuses(self):
        self.perform(); destination=self.root/'public'; artifact.stage(self.args.output,destination,self.args.packet_sha256); (destination/'extra-alias').symlink_to(self.root)
        with self.assertRaises(RuntimeError):artifact.physical(destination)
        (destination/'extra-alias').unlink(); (destination/'empty-extra').mkdir()
        with self.assertRaises(RuntimeError):artifact.physical(destination)
    def test_public_projection_fifo_refuses(self):
        self.perform(); destination=self.root/'public'; artifact.stage(self.args.output,destination,self.args.packet_sha256); os.mkfifo(destination/'extra-fifo')
        with self.assertRaises(RuntimeError):artifact.physical(destination)

def stat_mode(path):return path.stat().st_mode & 0o777

def add_scenarios():
    for scenario in ('wrong-query','stale','card-errors','wrong-type-control-green','warning','compile-error','format-refusal','timeout','unretired','provider-return','SDK-return','tool-return','native-return','job-return','source-return','raw-return','record-return'):
        def method(self,scenario=scenario):
            self.scenario=scenario; code,result=self.perform(); self.assertEqual(code,2); self.assertFalse(result['passed']); self.assertEqual(result['actual_target_cells_accepted'],0)
            if scenario == 'unretired':self.assertFalse(result['private_removed']); self.assertTrue((self.args.output/'private').exists())
        setattr(CensusControls,'test_controller_refuses_'+scenario.replace('-','_'),method)
    for field,value in [('execution_admitted',False),('scope','native-buffer-ownership-probe-only'),('protocol',{}),('LLVM_config_code_loading_reviewed',False),('independent_review_sha256','pending'),('reviewed_llvm_config',{})]:
        def method(self,field=field,value=value):
            self.decision[field]=value; self.seal_decision()
            with mock.patch.object(subject,'llvm_config_identity',return_value=self.llvm_identity):
                with self.assertRaises(RuntimeError):subject.admit_decision(self.args,self.context,{})
        setattr(CensusControls,'test_distinct_decision_refuses_'+field,method)
    for field,value in [('passed',False),('execution_admitted',False),('finalization_errors',['SYNTHETIC return refusal']),('job_identity',{}),('compiler_profile_sha256','0'*64),('compiler_backend_sha256','0'*64),('policies',{})]:
        def method(self,field=field,value=value):
            self.material[field]=value; self.args.policy_result.write_bytes(subject.canonical(self.material)); self.args.policy_result_sha256=subject.sha(self.args.policy_result.read_bytes())
            with self.assertRaises((RuntimeError,KeyError)):subject.native_inputs(self.args,self.context,{})
        setattr(CensusControls,'test_native_return_refuses_'+field,method)
add_scenarios()

class ProxyControls(unittest.TestCase):
    def test_exact_verifier_argv_derives_one_worker_and_source_feature_flags(self):
        result=proxy.derive(['build','--no-codegen','/owned/project/probe.cr'],'/owned/project','/installed/src'); self.assertEqual(result,['build','--no-codegen','/owned/project/probe.cr']+proxy.FLAGS); self.assertEqual(result[result.index('--threads')+1],'1')
    def test_actual_relative_docs_entrypoint_is_supported(self):
        result=proxy.derive(['docs','--format=json','--project-name=crystal','--project-version=1','src/compiler/crystal.cr'],'/owned/project','/installed/src'); self.assertIn('src/compiler/crystal.cr',result)
    def test_docs_retains_metadata_scope_and_target_flags(self):
        result=proxy.derive(['docs','--format=json','src/docs_main.cr'],'/owned/project','/installed/src'); self.assertEqual(result[-14:],[part for flag in proxy.DOCS_DEFINES for part in ('-D',flag)]+['--error-on-warnings','--no-color'])
    def test_codegen_build_refuses(self):
        with self.assertRaises(RuntimeError):proxy.derive(['build','/owned/project/probe.cr'],'/owned/project','/installed/src')
    def test_changed_compiler_flags_refuse(self):
        for flags in (['--threads','2'],['--mcpu','generic'],['-Dwithout_interpreter'],['--release'],['-o','/owned/output']):
            with self.subTest(flags=flags),self.assertRaises(RuntimeError):proxy.derive(['build','--no-codegen','/owned/project/probe.cr']+flags,'/owned/project','/installed/src')
    def test_source_escape_refuses(self):
        with self.assertRaises(RuntimeError):proxy.derive(['build','--no-codegen','/elsewhere/probe.cr'],'/owned/project','/installed/src')
    def test_unsupported_tool_context_refuses(self):
        with self.assertRaises(RuntimeError):proxy.derive(['tool','context','/owned/project/probe.cr'],'/owned/project','/installed/src')

if __name__ == '__main__':unittest.main(verbosity=2)
