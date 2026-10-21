"""Guarded original-Runner, API-order and real-callback receipt sensitivity fixtures."""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'vendor'))
import dirty_proof as proof
import hook_callback as hook
import execution_context as context
import proof_command
from propose_dirty_transition import sha, derive, PATHS


def command(label, maximum=10, expected=0, exit_code=None, arguments=None, pid=8100):
    sample=dict(status='absent',elapsed_seconds=0.0)
    group=dict(group=pid,status='absent',scope='original POSIX process group',phase='direct_child_returned',
        bounded_drain_exhausted=False,maximum_drain_seconds=5.0,elapsed_seconds=0.0,
        original_command_deadline=100.0,drain_deadline=100.0,samples=[sample],initial_sample=sample,terminal_sample=sample)
    return dict(label=label,arguments=arguments or ['/reviewed/provider'],pid=pid,original_group=pid,
        exit_code=expected if exit_code is None else exit_code,expected_exit=expected,elapsed_seconds=1.0,
        maximum_seconds=maximum,refusal=None,writers_confirmed_retired=True,terminal_group_observation=group,
        stdout_sha256=sha(b''),stderr_sha256=sha(b''))


def card(method, unknown=False):
    return dict(query=method,status='unknown' if unknown else 'found',api_card_errors=[],freshness='fresh',
        entries=[] if unknown else [{'signature':'actual fixture signature'}],failure_reason=None,
        verification_status=None if unknown else 'present')


def write_record(output,row,stdout,stderr=''):
    for stream,raw in [('stdout',stdout),('stderr',stderr)]:
        data=raw.encode();(output/(row['label']+'.'+stream+'.txt')).write_bytes(data);row[stream+'_sha256']=sha(data)


class LookupRunner:
    def __init__(self, output, unknown=True):
        self.records=[];self.output=output;self.unknown=unknown;self.mutate=None
    def run(self,label,arguments,**options):
        unknown=self.unknown and not label.startswith('api-verify-')
        value=card(arguments[2],unknown)
        row=command(label,arguments=arguments,exit_code=4 if unknown else 0)
        write_record(self.output,row,json.dumps(value))
        if self.mutate:self.mutate(row)
        self.records.append(row)
        if unknown:raise RuntimeError('Expected0; actual explicit unknown4')
        return json.dumps(value),''


def hosted_admission():
    from same_job_policy import DRIVER_SHA256, LOCK_SHA256
    job=dict(GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,GITHUB_JOB='exact',RUNNER_NAME='same',RUNNER_OS='macOS',RUNNER_ARCH='ARM64')
    runner=dict(run_id='1',run_attempt='1',source_commit='a'*40,system='Darwin',machine='arm64',qualification_script_sha256=DRIVER_SHA256,source_lock_sha256=LOCK_SHA256)
    return dict(job_identity=job,runner=runner,observed_profile_sha256='a'*64,observed_provider_sha256='b'*64)


def hosted_environment():
    return dict(hosted_admission()['job_identity'],GITHUB_ACTIONS='true',ATLAS_GRANT_JOB_NONCE='a'*64)


def completed_proof(output=None):
    rows=[]
    for index,(label,maximum,expected) in enumerate(proof.expected_commands()):
        args=['/reviewed/provider']
        raw=''
        if label.startswith('api-'):
            method=proof.API_METHODS[int(label[4:])]
            args=['/reviewed/amber-lsp','lookup',method,'--root','/actual/grant','--json']
            raw=json.dumps(card(method))
        row=command(label,maximum,expected,arguments=args,pid=8100+index)
        if output is not None:write_record(output,row,raw)
        rows.append(row)
    if output is not None:
        (output/'COMMANDS.json').write_text(json.dumps(rows))
        (output/'CALLBACK_RECEIPT.json').write_text(json.dumps(dict(callback_verified=True,project='/actual/grant',proof_tools={'amber_lsp':{'path':'/reviewed/amber-lsp'}})))
    from propose_dirty_transition import COMPARATORS
    cards=[dict(phase=phase,method=method,card=card(method)) for phase in ('standard','comparison','transition') for method in proof.api_sequence(phase)]
    shared_source=dict(carrier_sha256=sha((ROOT/'source/captured_column_assignment.cr.txt').read_bytes()),comparator_sha256=sha(COMPARATORS.encode()))
    shared_evidence=sha(json.dumps([row for row in cards if row['phase'] != 'transition'],sort_keys=True,allow_nan=False).encode())
    admission=hosted_admission()
    return dict(passed=True,finalization_errors=[],elapsed_seconds=100,commands=rows,actual_project='/actual/grant',
        same_job_admission=admission,execution_context=context.hosted_value(Path('/actual/grant'),admission),
        reviewed_tools={'tools':{'amber_lsp':{'path':'/reviewed/amber-lsp'}}},api_cards=cards,
        shared_comparison_api_source=shared_source,shared_comparison_api_cards_sha256=shared_evidence,
        writers_confirmed_retired=True,overlays=[dict(restored=True) for _ in range(4)],
        groups=[row['terminal_group_observation'] for row in rows],actual_callback_verified=True,
        callback_receipt_sha256=sha((output/'CALLBACK_RECEIPT.json').read_bytes()) if output is not None else 'a'*64,api_phases=['standard','comparison','transition'],api_lookup_accepted=True)


class PrerequisiteControls(unittest.TestCase):
    def test_unknown_card_inside_ten_seconds_accepts_retired_exact_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);runner=LookupRunner(output)
            value=proof.lookup(runner,'/reviewed/lsp','Hash#delete',0,output,{},output)
            self.assertEqual(value,card('Hash#delete'));self.assertEqual(len(runner.records),2)

    def test_unknown_card_resource_refusals_never_retry(self):
        for text in ('Command exceeded its time budget','Command exceeded its raw-output budget','Original owned process group is present'):
            with self.subTest(text=text),tempfile.TemporaryDirectory() as directory:
                output=Path(directory);runner=LookupRunner(output);runner.mutate=lambda row:row.update(refusal=text)
                with self.assertRaises(RuntimeError):proof.lookup(runner,'/reviewed/lsp','Hash#delete',0,output,{},output)
                self.assertEqual(len(runner.records),1);self.assertEqual(runner.records[0]['refusal'],text)

    def test_unknown_card_late_unqualified_wrong_status_or_group_refuses(self):
        cases=[lambda r:r.update(elapsed_seconds=10.1),lambda r:r.update(writers_confirmed_retired=False),
            lambda r:r.update(stdout_sha256=None),lambda r:r.update(exit_code=True),
            lambda r:r['terminal_group_observation'].update(status='present'),lambda r:r.update(original_group=8101),
            lambda r:r.update(maximum_seconds=11),lambda r:r.update(elapsed_seconds=float('nan'))]
        for mutate in cases:
            with tempfile.TemporaryDirectory() as directory:
                output=Path(directory);runner=LookupRunner(output);runner.mutate=mutate
                with self.assertRaises(Exception):proof.lookup(runner,'/reviewed/lsp','Hash#delete',0,output,{},output)
                self.assertEqual(len(runner.records),1)

    def test_changed_unknown_raw_stream_refuses_before_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);runner=LookupRunner(output)
            runner.mutate=lambda row:(output/(row['label']+'.stdout.txt')).write_text('{}')
            with self.assertRaises(RuntimeError):proof.lookup(runner,'/reviewed/lsp','Hash#delete',0,output,{},output)
            self.assertEqual(len(runner.records),1)

    def test_original_actual_runner_deadline_reproduction_refuses_without_verification(self):
        path=ROOT/'vendor/sdk_install_qualification.py'
        self.assertEqual(sha(path.read_bytes()),proof.DRIVER_SHA256)
        spec=importlib.util.spec_from_file_location('dirty_deadline_actual_runner',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
        clock=SimpleNamespace(value=0.0)
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            class Process:
                pid=8100
                def __init__(self,arguments,**options):
                    options['stdout'].write(json.dumps(card(arguments[2],True)).encode());options['stdout'].flush();clock.value=11.0
                def poll(self):return 4
                def wait(self,timeout):return 4
            with mock.patch.object(driver.time,'monotonic',side_effect=lambda:clock.value), \
                 mock.patch.object(driver.subprocess,'Popen',side_effect=Process), \
                 mock.patch.object(driver.Runner,'observe_group',return_value={'status':'absent'}):
                runner=driver.Runner(output);runner.deadline=100
                with self.assertRaisesRegex(RuntimeError,'refusal remains|refusals|failed command'):
                    proof.lookup(runner,'/mocked/lsp','Hash#delete',0,output,{},output)
                self.assertEqual(len(runner.records),1)
                self.assertEqual(runner.records[0]['refusal'],'Command exceeded its time budget')
                self.assertEqual(runner.records[0]['elapsed_seconds'],11)

    def test_complete_return_accepts_full_exact_ordered_raw_roster(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);value=completed_proof(output);proof.complete_return(value,output)

    def test_complete_return_preserves_every_deadline_output_group_refusal(self):
        for label in ('amber_lsp-version','api-0','transition-spec-0','restored-probe-run'):
            for refusal in ('Command exceeded its time budget','Command exceeded its raw-output budget','Original owned process group is unverifiable'):
                value=completed_proof();next(row for row in value['commands'] if row['label']==label)['refusal']=refusal
                with self.assertRaisesRegex(RuntimeError,'failed command'):proof.complete_return(value)

    def test_reordered_late_or_missing_api_phase_refuses_completion(self):
        for mutation in ('late','swap','missing','phase','callback','root','card','shared'):
            value=completed_proof()
            if mutation=='late':value['commands'].append(value['commands'].pop(2))
            if mutation=='swap':value['commands'][2:4]=reversed(value['commands'][2:4])
            if mutation=='missing':value['commands'].pop(2);value['groups'].pop(2)
            if mutation=='phase':value['api_phases']=['comparison','standard','transition']
            if mutation=='callback':value['execution_context']['local_application_source_edits_admitted']=True
            if mutation=='root':value['actual_project']='/changed/root'
            if mutation=='card':value['api_cards'][0]['method']='changed method'
            if mutation=='shared':value['shared_comparison_api_source']['carrier_sha256']='0'*64
            with self.assertRaises(RuntimeError):proof.complete_return(value)

    def test_failed_verification_retains_both_records_and_refuses(self):
        for change in ('deadline','output','group','status','hash'):
            with tempfile.TemporaryDirectory() as directory:
                output=Path(directory);runner=LookupRunner(output)
                def mutate(row):
                    if row['label'].startswith('api-verify-'):
                        if change in ('deadline','output','group'):row['refusal']=change+' refusal'
                        if change=='status':row['exit_code']=1
                        if change=='hash':row['stdout_sha256']=None
                runner.mutate=mutate
                with self.assertRaises(Exception):proof.lookup(runner,'/reviewed/lsp','Hash#delete',0,output,{},output)
                self.assertEqual(len(runner.records),2)

    def test_complete_return_unknown_card_requires_exact_next_successful_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);value=completed_proof(output)
            index=next(i for i,row in enumerate(value['commands']) if row['label']=='api-0')
            first=value['commands'][index];first['exit_code']=4
            write_record(output,first,json.dumps(card(proof.API_METHODS[0],True)))
            verified=command('api-verify-0',arguments=[*first['arguments'],'--verify'],pid=9000)
            write_record(output,verified,json.dumps(card(proof.API_METHODS[0])))
            value['commands'].insert(index+1,verified);value['groups'].insert(index+1,verified['terminal_group_observation'])
            (output/'COMMANDS.json').write_text(json.dumps(value['commands']))
            proof.complete_return(value,output)
            first['refusal']='Command exceeded its time budget'
            (output/'COMMANDS.json').write_text(json.dumps(value['commands']))
            with self.assertRaisesRegex(RuntimeError,'failed command'):proof.complete_return(value,output)

    def test_api_roster_budget_and_shared_comparator_source_are_exact(self):
        self.assertEqual((len(proof.STANDARD_API),len(proof.COMPARISON_API),len(proof.TRANSITION_API)),(29,8,4))
        self.assertEqual(len(set(proof.API_METHODS)),41)
        self.assertEqual(len(proof.expected_commands())+41,113)
        self.assertEqual(sum(row[1] for row in proof.expected_commands())+410,6540)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for arm in ('comparison','transition'):
                for name,raw in derive(arm).items():
                    if raw is not None:
                        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
                observed=proof.shared_comparison_source(root)
                if arm=='comparison':original=observed
                else:self.assertEqual(original,observed)
            path=root/PATHS[1];path.write_bytes(path.read_bytes().replace(b'previous_database_value !=',b'previous_database_value =='))
            with self.assertRaises(RuntimeError):proof.shared_comparison_source(root)

    def actual_proof_fixture(self, root, refused_method=None, missing_callback=False,late_label=None):
        from contextlib import contextmanager
        from dirty_overlay import apply as actual_apply
        grant=root/'grant';grant.mkdir()
        for name,raw in derive('original').items():
            if raw is not None:
                item=grant/name;item.parent.mkdir(parents=True,exist_ok=True);item.write_bytes(raw);item.chmod(0o644)
        for group in proof.SPEC_GROUPS:
            for name in group:
                item=grant/name;item.parent.mkdir(parents=True,exist_ok=True);item.write_bytes(b'exact source fixture')
        sdk=root/'sdk';sdk.mkdir();(sdk/'brew-root.stdout.txt').write_text('/brew')
        prefix=root/'prefix';wrapper=prefix/'bin/crystal-alpha';wrapper.parent.mkdir(parents=True);wrapper.write_text('fixture wrapper')
        for retained,name in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
            item=prefix/name;item.parent.mkdir(parents=True,exist_ok=True);item.write_text('fixture');(sdk/retained).write_text('fixture')
        callback=root/'callback.json'
        tools=dict(tools={name:dict(path='/exact/'+name,sha256='a'*64,version='2.0.7' if name=='amber_lsp' else '1.7.0-dev',**({'api_corpus_path':'/exact/corpus','api_corpus_sha256':'a'*64} if name=='amber_lsp' else {})) for name in ('amber_lsp','ameba')})
        callback.write_text(json.dumps(dict(callback_verified=True,project=str(grant),proof_tools=tools['tools'])))
        trace=[];instances=[]
        class Runner:
            def __init__(self,output):
                self.output=output;self.records=[];self.group_observations=[];self.writers_confirmed_retired=True;instances.append(self)
            def run(self,label,arguments,**kwargs):
                trace.append(label)
                if label.startswith('api-'):
                    if arguments[2]==refused_method:raise RuntimeError('Actual fixture API card refused')
                    stdout=json.dumps(card(arguments[2]));stderr=''
                elif label.endswith('-version'):stdout=tools['tools'][label[:-8]]['version']+'\n';stderr=''
                elif label.endswith('-lint'):stdout=str(sum((grant/name).exists() for name in PATHS)+1)+' inspected, 0 failures\n';stderr=''
                elif '-spec-' in label:stdout='10 examples, 0 failures, 0 errors, 0 pending\n';stderr=''
                elif label.endswith('-probe-build'):Path(arguments[-1]).write_bytes(b'private binary fixture');stdout='';stderr=''
                elif label=='transition-probe-baseline-canary':stdout='Dirty contract: present nil baseline';stderr=''
                else:stdout='';stderr=''
                row=command(label,maximum=kwargs['seconds'],expected=kwargs.get('expected_exit',0),arguments=[str(a) for a in arguments],pid=8100+len(self.records))
                write_record(self.output,row,stdout,stderr)
                if label==late_label:row['elapsed_seconds']=row['maximum_seconds']+1
                self.records.append(row);self.group_observations.append(row['terminal_group_observation'])
                (self.output/'COMMANDS.json').write_text(json.dumps(self.records))
                return stdout,stderr
        @contextmanager
        def overlay(project,arm,retired,observation):
            trace.append('materialize-'+arm)
            with actual_apply(project,arm,retired,observation):yield
        fake_driver=SimpleNamespace(Runner=Runner,verify_wrapper=lambda *a:None,tree_identity=lambda *a:{'exact':'stdlib'})
        fake_spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
        admission=dict(hosted_admission(),providers={'compiler_wrapper':dict(path=str(wrapper),sha256='a'*64),'compiler_backend':dict(path=str(prefix/'libexec/agent-crystal-bin'),sha256='a'*64)},stdlib={'exact':'stdlib'})
        original_digest=proof.digest
        def digest(path):
            path=Path(path)
            return original_digest(path) if (path.is_file() and path.name in ('callback.json','CALLBACK_RECEIPT.json','captured_column_assignment.cr.txt','captured_column_assignment.cr')) or path.name.endswith('.stdout.txt') or path.name.endswith('.stderr.txt') else 'a'*64
        callback_admission=RuntimeError('Real callback prerequisite remains unadmitted') if missing_callback else None
        if missing_callback:mock_environment=dict(hosted_environment(),GITHUB_ACTIONS='false')
        else:mock_environment=hosted_environment()
        with mock.patch.dict(os.environ,mock_environment),mock.patch.object(context,'source_input_inventory',return_value=([],hook.ORIGINAL_SOURCE_SHA256)), \
             mock.patch.object(proof,'admit_tools',return_value=tools),mock.patch.object(proof,'metadata',return_value=admission), \
             mock.patch.object(proof,'digest',side_effect=digest),mock.patch.object(proof,'DRIVER_SHA256','a'*64), \
             mock.patch.object(proof.importlib.util,'spec_from_file_location',return_value=fake_spec), \
             mock.patch.object(proof.importlib.util,'module_from_spec',return_value=fake_driver), \
             mock.patch.object(proof,'source_input_inventory',return_value=([], 'fp')),mock.patch.object(proof,'fingerprint',return_value='fp'), \
             mock.patch.object(proof,'apply',side_effect=overlay),mock.patch.object(proof.time,'monotonic',return_value=0.0), \
             mock.patch.object(proof.hook_callback,'admit',side_effect=callback_admission,return_value=dict(receipt={'callback_verified':True},protected={})), \
             mock.patch.object(proof,'probe_observation',return_value=dict(allocation_calls=0,requested_bytes=0,elapsed_nanoseconds=100)):
            error=None
            try:value=proof.run(root/'output',grant,wrapper,root/'driver.py',root/'tools.json','a'*64,sdk,6600,callback,sha(callback.read_bytes()))
            except Exception as caught:error=str(caught);value=json.loads((root/'output/PROOF_RESULT.json').read_bytes())
        return trace,value,error

    def test_actual_proof_orchestration_orders_all_cards_before_corresponding_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            trace,value,error=self.actual_proof_fixture(Path(directory).resolve())
            self.assertIsNone(error,error);self.assertTrue(value['passed'])
            self.assertLess(max(trace.index('api-'+str(proof.API_METHODS.index(m))) for m in proof.STANDARD_API),trace.index('materialize-original'))
            for arm in ('comparison','transition'):
                self.assertLess(max(trace.index('api-'+str(proof.API_METHODS.index(m))) for m in proof.api_sequence(arm)),trace.index(arm+'-format'))
            self.assertEqual(value['api_phases'],['standard','comparison','transition'])
            self.assertTrue(all(row['restored'] for row in value['overlays']))

    def test_refused_lookup_stops_each_actual_proof_phase_before_behavior(self):
        for phase in ('standard','comparison','transition'):
            with tempfile.TemporaryDirectory() as directory:
                trace,value,error=self.actual_proof_fixture(Path(directory).resolve(),proof.api_sequence(phase)[0])
                self.assertIsNotNone(error);self.assertFalse(value['passed'])
                self.assertNotIn(('materialize-original' if phase=='standard' else phase+'-format'),trace)
                self.assertTrue(all(row['restored'] for row in value['overlays']))

    def test_terminal_reader_refusal_is_persisted_after_full_mocked_proof_return(self):
        with tempfile.TemporaryDirectory() as directory:
            trace,value,error=self.actual_proof_fixture(Path(directory).resolve(),late_label='restored-probe-run')
            self.assertIsNotNone(error);self.assertFalse(value['passed'])
            self.assertIn('completion_error',value)
            self.assertEqual(value['commands'][-1]['elapsed_seconds'],61)
            self.assertTrue(all(row['restored'] for row in value['overlays']))

    def test_missing_real_callback_stops_actual_proof_before_api_overlay_or_native_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            trace,value,error=self.actual_proof_fixture(Path(directory).resolve(),missing_callback=True)
            self.assertEqual(trace,[]);self.assertFalse(value['passed']);self.assertIsNotNone(error)

    def callback_fixture(self, root):
        grant=root/'grant';grant.mkdir();probe=grant/hook.PROBE_RELATIVE;probe.parent.mkdir(parents=True)
        probe.write_bytes((ROOT/'source/hook_callback_probe.cr.txt').read_bytes())
        adapter=root/'adapter.rb';adapter.write_bytes(b'fixture exact adapter')
        config=root/'hooks.json';registered='checksum '+hook.ADAPTER_SHA256+' load '+str(adapter)
        config.write_text(json.dumps({'hooks':{'PostToolUse':[{'hooks':[{'command':registered}]}]}}))
        payload=root/'payload.json';payload.write_text(json.dumps(dict(cwd=str(grant),session_id='real-fixture-session',hook_event_name='PostToolUse',tool_name='apply_patch')))
        observation=root/'observation.json';observation.write_text(json.dumps(dict(phase='posttool',cwd=str(grant),session_id='real-fixture-session',tool_name='apply_patch',adapter_path=str(adapter),adapter_sha256=hook.ADAPTER_SHA256,route_sha256='9ae9fa90e4971d50b3985aca1a3c6ea3b1c2bc676697a249263cb2a939c3177a',files=[str(probe)])))
        provider=root/'compiler';provider.write_bytes(b'exact fixture provider')
        providers={'compiler_backend':dict(path=str(provider),sha256=sha(provider.read_bytes()))}
        admission=dict(job_identity={'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','RUNNER_NAME':'same'},providers=providers)
        tools=dict(tools={'amber_lsp':{'sha256':'b'*64}})
        command_row=command('callback',maximum=300,arguments=['/bin/sh','-c',registered])
        write_record(root,command_row,'actual fixture callback stdout')
        value=dict(format='atlas-grant-real-hook-callback-v1',callback_verified=True,issuer='actual-harness-PostToolUse',
            session_id='real-fixture-session',job_identity=admission['job_identity'],nonce='a'*64,project=str(grant),
            source_tree_sha256=hook.ORIGINAL_SOURCE_SHA256,packet_sha256=sha((ROOT/'SOURCE_PINS.json').read_bytes()),
            providers=providers,proof_tools=tools['tools'],python=dict(path=str(Path(sys.executable).resolve()),sha256=sha(Path(sys.executable).resolve().read_bytes())),
            monotonic_clock='same-host-boot',started_monotonic=9.0,completed_monotonic=10.0,
            evidence={name:dict(path=str(path),sha256=sha(path.read_bytes())) for name,path in [('adapter',adapter),('config',config),('payload',payload),('observation',observation)]},
            dispatch=dict(stdin_sha256=sha(payload.read_bytes()),origin='actual-hook-registry',hook_event_name='PostToolUse',registered_command=registered,session_id='real-fixture-session',argv=command_row['arguments']),
            callback_providers={name:dict(path=path,sha256=sha(Path(path).read_bytes())) for name,path in [('registered_shell','/bin/sh'),('ruby_launcher','/usr/bin/ruby')]},
            command=command_row,command_output=str(root))
        path=root/'receipt.json'
        return grant,admission,tools,value,path,adapter,config

    def check_callback(self, root, mutate=None, tamper=None):
        grant,admission,tools,value,path,adapter,config=self.callback_fixture(root)
        if mutate:mutate(value)
        path.write_text(json.dumps(value))
        with mock.patch.object(hook,'ADAPTER_SHA256',sha(adapter.read_bytes())),mock.patch.object(hook,'CONFIG_SHA256',sha(config.read_bytes())), \
             mock.patch.object(hook,'source_input_inventory',return_value=([],hook.ORIGINAL_SOURCE_SHA256)):
            # Match the changed adapter fixture in all exact byte/source joins.
            data=json.loads(config.read_bytes());old=value['evidence']['adapter']['sha256']
            command_text=data['hooks']['PostToolUse'][0]['hooks'][0]['command'].replace('cbb09db5b1d69e960dd1dc93bf0c7e21df6360ef9fd6d357d20829bf14b3fa1c',old)
            data['hooks']['PostToolUse'][0]['hooks'][0]['command']=command_text;config.write_text(json.dumps(data))
            value['dispatch']['registered_command']=command_text
            value['dispatch']['argv']=['/bin/sh','-c',command_text];value['command']['arguments']=['/bin/sh','-c',command_text]
            observed=Path(value['evidence']['observation']['path']);obs=json.loads(observed.read_bytes());obs['adapter_sha256']=old;observed.write_text(json.dumps(obs))
            value['evidence']['config']['sha256']=sha(config.read_bytes());value['evidence']['observation']['sha256']=sha(observed.read_bytes());path.write_text(json.dumps(value))
            config_pin=sha(config.read_bytes())
            expected=sha(path.read_bytes())
            if tamper:tamper(value,path)
            with mock.patch.object(hook,'CONFIG_SHA256',config_pin):
                return hook.admit(path,expected,grant,admission,tools,{'ATLAS_GRANT_JOB_NONCE':'a'*64},now=11.0)

    def test_callback_fixture_is_explicitly_mocked_and_valid_complete_receipt_accepts(self):
        with tempfile.TemporaryDirectory() as directory:
            value=self.check_callback(Path(directory).resolve());self.assertTrue(value['receipt']['callback_verified'])

    def test_missing_callback_receipt_refuses(self):
        with self.assertRaises(RuntimeError):hook.admit(None,None,Path('/grant'),{}, {},{})

    def test_wrong_failed_stale_job_provider_and_source_callback_receipts_refuse(self):
        changes=[lambda v:v.update(callback_verified=False),lambda v:v.update(completed_monotonic=-1),
            lambda v:v.update(project='/wrong/project'),lambda v:v.update(source_tree_sha256='0'*64),
            lambda v:v.update(packet_sha256='0'*64),lambda v:v.update(nonce='0'*64),
            lambda v:v.update(job_identity={'GITHUB_RUN_ID':'old'}),lambda v:v.update(providers={}),
            lambda v:v['command'].update(exit_code=1),lambda v:v['command'].update(refusal='deadline refused'),
            lambda v:v['dispatch'].update(origin='direct invocation'),lambda v:v.update(issuer='direct invocation'),
            lambda v:v.update(python={}),lambda v:v.update(proof_tools={}),lambda v:v.update(callback_providers={})]
        for mutate in changes:
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(Exception):self.check_callback(Path(directory).resolve(),mutate)

    def test_callback_old_completion_and_future_clock_refuse(self):
        for started,completed in ((-1000,-999),(12,13)):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(RuntimeError):self.check_callback(Path(directory).resolve(),lambda v:v.update(started_monotonic=started,completed_monotonic=completed))

    def test_changed_callback_receipt_adapter_config_payload_observation_or_output_refuses(self):
        for name in ('receipt','adapter','config','payload','observation','stdout'):
            def tamper(value,path):
                target=path if name=='receipt' else Path(value['command_output'])/'callback.stdout.txt' if name=='stdout' else Path(value['evidence'][name]['path'])
                target.write_bytes(b'changed exact callback evidence')
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(Exception):self.check_callback(Path(directory).resolve(),tamper=tamper)

    def test_hosted_context_uses_exact_github_sdk_authority_and_preserves_local_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory).resolve();admission=hosted_admission()
            with mock.patch.object(context,'source_input_inventory',return_value=([],hook.ORIGINAL_SOURCE_SHA256)), \
                 mock.patch.object(context.hook_callback,'admit',side_effect=AssertionError('Hosted fixtures use SDK/API authority')):
                value=context.admit(project,admission,{},environment=hosted_environment())['value']
                self.assertEqual(value['kind'],'hosted-ci-fixture-automation')
                self.assertFalse(value['local_application_source_edits_admitted']);self.assertFalse(value['actual_callback_verified'])
                context.complete(value,project,admission)

    def test_local_application_edit_context_refuses_missing_genuine_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(context,'source_input_inventory',return_value=([],hook.ORIGINAL_SOURCE_SHA256)):
                with self.assertRaisesRegex(RuntimeError,'real supplied callback'):
                    context.admit(Path(directory).resolve(),hosted_admission(),{},environment={})

    def test_mismatched_hosted_run_attempt_runner_nonce_source_and_driver_refuse(self):
        for field in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA','GITHUB_JOB','RUNNER_NAME','RUNNER_OS','RUNNER_ARCH','ATLAS_GRANT_JOB_NONCE','driver'):
            with tempfile.TemporaryDirectory() as directory:
                environment=hosted_environment();admission=hosted_admission()
                if field=='driver':admission['runner']['qualification_script_sha256']='0'*64
                else:environment[field]='changed'
                with mock.patch.object(context,'source_input_inventory',return_value=([],hook.ORIGINAL_SOURCE_SHA256)):
                    with self.assertRaises(RuntimeError):context.admit(Path(directory).resolve(),admission,{},environment=environment)

    def test_real_initial_registry_and_callback_admission_stay_pending(self):
        pending=json.loads((ROOT/'PROOF_TOOLS_PENDING.json').read_bytes())
        self.assertFalse(pending['execution_admitted'])
        self.assertFalse(json.loads((ROOT/'CALLBACK_PENDING.json').read_bytes())['callback_verified'])


if __name__=='__main__':
    with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('Guarded source fixtures')), \
         mock.patch.object(os,'kill',side_effect=AssertionError('Guarded source fixtures')), \
         mock.patch.object(os,'killpg',side_effect=AssertionError('Guarded source fixtures')):
        unittest.main(verbosity=2)
