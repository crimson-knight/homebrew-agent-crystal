"""Repository-cwd bootstrap, cleanup and immutable-decision fixture controls."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent;WORK=ROOT.parents[1];sys.path.insert(0,str(ROOT))
import fetch_decision
CALLS=[]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class EntrypointControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='installed provider bootstrap with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.repo=self.root/'repository';self.repo.mkdir();self.source=self.repo/'test/grant_native_provider';shutil.copytree(ROOT,self.source)
        self.launch=load(self.source/'launch.py','new_owned_launch');self.args=SimpleNamespace(operation='observe',packet_sha256=self.launch.sha(self.source/'SOURCE_PINS.json'),repository=self.repo,sdk_evidence=self.root/'SDK',transfer_packet=(ROOT.parent/'grant_dirty_transition' if (ROOT.parent/'grant_dirty_transition').exists() else WORK/'grant_dirty_tool_transfer_v103'),probe_packet=(ROOT.parent/'grant_native_buffer_probe' if (ROOT.parent/'grant_native_buffer_probe').exists() else ROOT.parent/'integration/native_v103/source'),feedback_packet=(ROOT.parent/'grant_native_buffer_source_feedback' if (ROOT.parent/'grant_native_buffer_source_feedback').exists() else ROOT.parent/'integration/feedback_v101/source'),python_sha256='a'*64,tool_workspace=self.root/'tools',output=self.root/'refused',source=None,feedback_result=self.root/'feedback',probe_result=self.root/'probe',feedback_attempted=False,probe_attempted=False)
    def guarded(self):
        def guard(*a,**k):CALLS.append(repr(a));raise AssertionError('Actual source entrypoint retains zero workload commands')
        return patch.object(subprocess,'Popen',guard)
    def test_repository_cwd_actual_runpy_entrypoint_refuses_unadmitted_host(self):
        old=Path.cwd();argv=[str(self.source/'launch.py'),'observe']
        for name in ('repository','sdk_evidence','transfer_packet','tool_workspace','probe_packet','feedback_packet','output','packet_sha256','python_sha256'):argv.extend(['--'+name.replace('_','-'),str(getattr(self.args,name))])
        try:
            os.chdir(self.repo)
            with self.guarded(),patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),patch.object(sys,'argv',argv),self.assertRaises(SystemExit) as caught:runpy.run_path(str(self.source/'launch.py'),run_name='__main__')
            self.assertEqual(caught.exception.code,2);self.assertFalse(json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['execution_admitted'])
        finally:os.chdir(old)
    def test_changed_own_executable_refuses_before_import(self):
        path=self.source/'provider_observation.py';path.write_bytes(path.read_bytes()+b'\nraise AssertionError("SYNTHETIC changed source imported")\n')
        with self.guarded(),self.assertRaisesRegex(RuntimeError,'source roster'):self.launch.main(self.args)
        self.assertFalse(self.args.output.exists())
    def test_missing_native_manifest_refuses_before_delegate(self):
        self.args.probe_packet=self.root/'absent'
        with self.guarded(),self.assertRaises((RuntimeError,OSError)):self.launch.main(self.args)
    def test_changed_coupling_is_rejected_by_own_manifest(self):
        (self.source/'inputs/COUPLING.json').write_text('{}')
        with self.guarded(),self.assertRaises(RuntimeError):self.launch.main(self.args)
    def test_existing_output_receipt_survives_admission_refusal(self):
        self.args.output.mkdir();path=self.args.output/'ADMISSION_REFUSAL.json';path.write_text('SYNTHETIC existing receipt')
        sys.path.insert(0,str(self.source));import provider_observation as producer
        with self.guarded(),patch.object(producer,'admit',side_effect=AssertionError('admission was reached')),self.assertRaises(RuntimeError):producer.main(self.args)
        self.assertEqual(path.read_text(),'SYNTHETIC existing receipt')
    def test_output_alias_preserves_its_target_receipt(self):
        target=self.root/'existing-target';target.mkdir();path=target/'ADMISSION_REFUSAL.json';path.write_text('SYNTHETIC existing target receipt');self.args.output.symlink_to(target)
        sys.path.insert(0,str(self.source));import provider_observation as producer
        with self.guarded(),patch.object(producer,'admit',side_effect=AssertionError('admission was reached')),self.assertRaises(RuntimeError):producer.main(self.args)
        self.assertEqual(path.read_text(),'SYNTHETIC existing target receipt')
    def test_replaced_cli_root_preserves_original_and_refuses_replacement_write(self):
        sys.path.insert(0,str(self.source));import provider_observation as producer
        def refuse(args,deadline):args.output.rename(self.root/'original-claimed-output');args.output.mkdir();raise RuntimeError('SYNTHETIC original admission refusal')
        with self.guarded(),patch.object(producer,'admit',side_effect=refuse),self.assertRaises(RuntimeError) as caught:producer.main(self.args)
        self.assertFalse((self.args.output/'ADMISSION_REFUSAL.json').exists());self.assertIn('original admission refusal',str(caught.exception.__context__))
    def test_source_controls_delegate_all_four_pinned_suites(self):
        self.args.operation='controls'
        with self.guarded(),patch.object(self.launch.runpy,'run_path',return_value={}) as delegate:self.assertEqual(self.launch.main(self.args),0)
        self.assertEqual([Path(call.args[0]).name for call in delegate.call_args_list],['test_provider_observation.py','test_entrypoints.py','test_source_feedback.py','test_probe.py'])
    def test_false_policy_result_refuses_feedback_delegation(self):
        self.args.operation='feedback';self.args.policies=self.root/'policies';self.args.policies.mkdir();(self.args.policies/'POLICY_RESULT.json').write_text('{"passed":false,"execution_admitted":false}')
        with self.guarded(),self.assertRaises(RuntimeError):self.launch.main(self.args)
    def test_unretired_consumer_preserves_tools_and_retains_cleanup_reason(self):
        self.args.operation='cleanup';self.args.feedback_attempted=True;self.args.feedback_result.mkdir();(self.args.feedback_result/'RESULT.json').write_text('{"writers_confirmed_retired":false}');self.args.source=self.root/'public';self.args.source.mkdir();(self.args.source/'BUNDLE_STAGE.json').write_text('{}')
        with self.guarded():self.assertEqual(self.launch.main(self.args),2)
        result=json.loads((self.args.source/'TRANSFER_CLEANUP.json').read_bytes());self.assertFalse(result['complete']);self.assertTrue(result['private_payload_preserved']);self.assertIn('writers',result['error'])
    def test_false_original_cleanup_is_propagated(self):
        self.args.operation='cleanup';self.args.source=self.root/'public';self.args.source.mkdir();(self.args.source/'BUNDLE_STAGE.json').write_text('{}')
        sys.path.insert(0,str(self.source));import provider_observation as p
        original=p.load
        def fixture_load(path,*args,**kwargs):
            return SimpleNamespace(cleanup=lambda *a:dict(complete=False,error='SYNTHETIC original cleanup failure')) if path.name=='proof_tool_transfer.py' else original(path,*args,**kwargs)
        with self.guarded(),patch.object(p,'load',side_effect=fixture_load):self.assertEqual(self.launch.main(self.args),2)
        self.assertFalse(json.loads((self.args.source/'TRANSFER_CLEANUP.json').read_bytes())['complete'])
    def test_immutable_decision_url_rejects_mutable_ref_before_network(self):
        with patch.object(fetch_decision.urllib.request,'urlopen',side_effect=AssertionError('mutable URL contacted')),self.assertRaises(RuntimeError):fetch_decision.fetch('https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/main/review.json','a'*64,self.root/'DECISION.json')
    def test_actual_download_reader_enforces_exact_independent_hash(self):
        url='https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/'+'a'*40+'/review.json';raw=b'{"SYNTHETIC":"reviewed"}\n'
        class Response(io.BytesIO):
            status=200
            def geturl(self):return url
        with patch.object(fetch_decision.urllib.request,'urlopen',return_value=Response(raw)):
            result=fetch_decision.fetch(url,hashlib.sha256(raw).hexdigest(),self.root/'DECISION.json')
        self.assertEqual(result['bytes'],len(raw));self.assertEqual((self.root/'DECISION.json').read_bytes(),raw)
    def test_download_hash_mismatch_retains_fresh_output_absence(self):
        url='https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/'+'a'*40+'/review.json'
        class Response(io.BytesIO):
            status=200
            def geturl(self):return url
        with patch.object(fetch_decision.urllib.request,'urlopen',return_value=Response(b'SYNTHETIC changed')),self.assertRaises(RuntimeError):fetch_decision.fetch(url,'0'*64,self.root/'DECISION.json')
        self.assertFalse((self.root/'DECISION.json').exists())

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EntrypointControls));print(json.dumps(dict(tests=result.testsRun,passed=result.wasSuccessful(),external_workload_guard_calls=CALLS)));raise SystemExit(0 if result.wasSuccessful() and not CALLS else 1)
