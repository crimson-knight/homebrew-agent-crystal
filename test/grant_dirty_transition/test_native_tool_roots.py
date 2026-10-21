"""Guarded physical graph controls for the actual incomplete Apple-root refusal."""
from contextlib import ExitStack
import argparse,json,os
from pathlib import Path
import subprocess,sys,tempfile,time,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import proof_tool_transfer as transfer
import test_tool_transfer as original
CALLS=[]

class ToolRootControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='tool rooted native graph with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guard(*a,**k):CALLS.append('external');raise AssertionError('Guarded data-only native headers required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.guards.enter_context(mock.patch(target,side_effect=guard))
        self.prefix,self.direct,self.admission=original.native_fixture(self.root)
        for name in transfer.PACKAGES:
            (self.prefix/'opt'/name/'lib/dependency.dylib').write_bytes(original.macho([transfer.SYSTEM_IMPORTS[0]]))
        self.authority=self.root/'source authority';(self.authority/'transfer_inputs').mkdir(parents=True);self.tools=self.root/'tools';self.tools.mkdir();self.declared=[]
        for name,imports in [('amber-lsp',[self.direct[0],*transfer.SYSTEM_IMPORTS]),('ameba',[*self.direct[1:],*transfer.SYSTEM_IMPORTS])]:
            p=self.tools/name;raw=original.macho(imports);p.write_bytes(raw);p.chmod(0o755);self.declared.append({'member':'tools/'+name,'bytes':len(raw),'sha256':transfer.sha(raw),'load_commands':[{'command':'0xc','path':v} for v in imports]})
        (self.authority/'transfer_inputs/STATIC_TOOL_LOAD_COMMANDS.json').write_text(json.dumps(self.declared))
        self.guards.enter_context(mock.patch.object(transfer,'ROOT',self.authority));self.guards.enter_context(mock.patch.object(transfer,'DIRECT',self.direct))
    def collect(self,progress=None):return transfer.collect_native(transfer.Budget(time.monotonic()+30),self.admission,self.prefix,tool_root=self.tools,evidence=progress)
    def test_predecessor_library_only_roots_reproduce_missing_Apple_refusal(self):
        progress={}
        with self.assertRaisesRegex(RuntimeError,'Complete accepted Apple import names'):transfer.collect_native(transfer.Budget(time.monotonic()+30),self.admission,self.prefix,evidence=progress)
        self.assertEqual(progress['Apple_imports'],[transfer.SYSTEM_IMPORTS[0]]);self.assertEqual(progress['missing_Apple_imports'],[transfer.SYSTEM_IMPORTS[1]]);self.assertFalse(progress['complete'])
    def test_exact_tool_roots_supply_direct_Apple_imports_and_preserve_all_libraries(self):
        value=self.collect();self.assertEqual(value['Apple_imports'],list(transfer.SYSTEM_IMPORTS));self.assertEqual(len(value['libraries']),4);self.assertEqual([r['tool'] for r in value['tool_native_roots']],['amber-lsp','ameba']);self.assertFalse(value['dyld_cache_bytes_qualified']);self.assertFalse(value['full_native_memory_qualified'])
    def test_tool_roots_are_parsed_from_actual_authored_MachO_bytes(self):
        roots=transfer.tool_native_roots(self.tools,transfer.Budget(time.monotonic()+30));self.assertEqual(roots[0]['imports'],sorted([self.direct[0],*transfer.SYSTEM_IMPORTS]));self.assertEqual(roots[0]['sha256'],transfer.sha((self.tools/'amber-lsp').read_bytes()))
    def test_changed_tool_bytes_refuse_before_graph_acceptance(self):
        p=self.tools/'amber-lsp';p.write_bytes(p.read_bytes()+b'changed')
        with self.assertRaisesRegex(RuntimeError,'Exact transferred tool bytes'):self.collect()
    def test_missing_second_tool_retains_first_tool_root_evidence(self):
        (self.tools/'ameba').unlink();progress={}
        with self.assertRaises(FileNotFoundError):self.collect(progress)
        self.assertEqual(progress['phase'],'tool-roots');self.assertEqual(len(progress['tool_native_roots']),1);self.assertFalse(progress['complete'])
    def test_invalid_tool_kind_refuses_finitely(self):
        (self.tools/'amber-lsp').unlink();os.mkfifo(self.tools/'amber-lsp')
        with self.assertRaises(RuntimeError):self.collect()
    def test_changed_declared_tool_header_refuses(self):
        self.declared[0]['load_commands'].append({'command':'0xc','path':'/usr/lib/unreviewed.dylib'});(self.authority/'transfer_inputs/STATIC_TOOL_LOAD_COMMANDS.json').write_text(json.dumps(self.declared))
        with self.assertRaises(RuntimeError):self.collect()
    def test_missing_genuine_native_dependency_still_refuses_with_frontier(self):
        first=self.prefix/'opt/openssl@3/lib/dependency.dylib';missing=str(self.prefix/'opt/libyaml/lib/missing.dylib');first.write_bytes(original.macho([transfer.SYSTEM_IMPORTS[0],missing]));progress={}
        with self.assertRaises(FileNotFoundError):self.collect(progress)
        self.assertEqual(progress['current'],missing);self.assertTrue(progress['libraries']);self.assertTrue(progress['tool_native_roots']);self.assertFalse(progress['complete'])
    def test_native_byte_drift_changes_return(self):
        before=self.collect();p=self.prefix/'opt/libyaml/lib/dependency.dylib';p.write_bytes(p.read_bytes()+b'changed');after=self.collect();self.assertNotEqual(before,after)
    def test_same_byte_tool_replacement_changes_full_return_identity(self):
        before=self.collect();p=self.tools/'ameba';raw=p.read_bytes();p.unlink();p.write_bytes(raw);p.chmod(0o755);after=self.collect();self.assertNotEqual(before,after);self.assertEqual(transfer.policy_view(before),transfer.policy_view(after))
    def test_policy_view_binds_tool_hash_and_imports_with_stable_job_independent_paths(self):
        value=self.collect();view=transfer.policy_view(value);self.assertEqual(len(view['tool_native_roots']),2);self.assertNotIn('path',view['tool_native_roots'][0]);self.assertEqual(view['tool_native_roots'][0]['imports'],value['tool_native_roots'][0]['imports'])
    def test_complete_progress_retains_actual_root_frontier_and_Apples(self):
        progress={};self.collect(progress);self.assertTrue(progress['complete']);self.assertEqual(progress['phase'],'complete');self.assertEqual(progress['pending'],[]);self.assertEqual(progress['Apple_imports'],list(transfer.SYSTEM_IMPORTS))
    def test_failed_observation_serializes_partial_native_graph(self):
        import same_job_policy
        root=self.root/'observation';root.mkdir();(root/'TRANSFER_RESULT.json').write_text('{"passed":true}')
        missing=str(self.prefix/'opt/libyaml/lib/missing.dylib');(self.prefix/'opt/openssl@3/lib/dependency.dylib').write_bytes(original.macho([missing]))
        actual=transfer.collect_native
        def collect(budget,admitted,**kwargs):return actual(budget,admitted,self.prefix,tool_root=self.tools,evidence=kwargs.get('evidence'))
        with mock.patch.object(same_job_policy,'metadata',return_value=self.admission),mock.patch.object(transfer,'tool_return',return_value=True),mock.patch.object(transfer,'collect_native',side_effect=collect):
            with self.assertRaisesRegex(RuntimeError,'Retained failed'):transfer.observe(root,root/'sdk',ROOT/'ANALYSIS_NATIVE_POLICY.json')
        value=transfer.decode((root/'NATIVE_OBSERVATION.json').read_bytes());self.assertFalse(value['passed']);self.assertFalse(value['execution_admitted']);self.assertEqual(value['native_progress_before']['current'],missing);self.assertEqual(len(value['native_progress_before']['tool_native_roots']),2)
    def test_original_runtime_and_byte_file_horizons_remain_exact(self):
        self.assertEqual((transfer.TRANSFER_SECONDS,transfer.OBSERVATION_SECONDS,transfer.MAX_NATIVE_FILES,transfer.MAX_NATIVE_PATHS,transfer.MAX_TOTAL_BYTES),(180,120,24,96,96*2**20))

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ToolRootControls));print(json.dumps({'passed':result.wasSuccessful(),'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'external_guard_calls':len(CALLS),'actual_local_workloads':0},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() and not CALLS else 2)
