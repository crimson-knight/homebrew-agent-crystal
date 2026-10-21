"""Guarded physical source restoration, four-arm budgets and actual-owner sensitivity controls."""
import copy
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'vendor'))
import propose_dirty_transition as proposal
import dirty_overlay
import prepare_dirty_plan as plan
import dirty_proof
import run_dirty_experiment as controller
import run_dirty_contrast as contrast
import stage_dirty_result_artifact as artifact
from stage_grant_sources import stage
from verify_compile_acceptance import source_input_inventory
from verify_dirty_owners import verify as owners, HELPERS, FIELDS, calls
from retained_symbols import sha

VALIDATION = ROOT.parent/(ROOT.name+'_validation')
VALIDATION.mkdir(exist_ok=True)
DIRTY_WORKFLOW_FIXTURE = None


def workflow_bytes():
    path = DIRTY_WORKFLOW_FIXTURE if DIRTY_WORKFLOW_FIXTURE is not None else ROOT.parents[1]/'.github/workflows/grant-dirty-transition-mac.yml'
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Exact physical integrated dirty workflow or explicit packet-only fixture required')
    return path.read_text()


def temporary():
    return tempfile.TemporaryDirectory(prefix='dirty-source-',dir=str(VALIDATION))


def minimal(root):
    root.mkdir()
    for name,raw in proposal.derive('original').items():
        if raw is not None:
            path = root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
    return root


def owner_image(arm):
    base = 0x1000
    raw = bytearray(4096)
    rows = []
    targets = {}
    def add(symbol,address,branches=()):
        offset = address-base
        for index,target in enumerate(branches):
            struct.pack_into('<I',raw,offset+index*4,0x94000000 | (((target-(address+index*4))//4)&0x3ffffff))
        row = dict(symbol=symbol,address=address,function_start=True,next_function_extent_bytes=16,extent_sha256=sha(bytes(raw[offset:offset+16])))
        rows.append(row)
    if arm in ('comparison','transition'):
        for index,name in enumerate(HELPERS[:2] if arm == 'comparison' else HELPERS):
            targets[name] = base+index*16
        for name,address in targets.items():
            branches = (targets[HELPERS[0]],targets[HELPERS[1]]) if name == HELPERS[2] else ()
            add('*Grant::Dirty::'+name+'<Grant::Dirty::CapturedColumnAssignment>:Bool',address,branches)
    for index in range(2):
        for number,field in enumerate(FIELDS):
            branches = [targets[name] for name in (HELPERS[:2] if arm == 'comparison' else HELPERS[2:])] if targets else []
            add('*AcceptancePerson%04d#%s=<String>:String'%(index,field),base+256+(index*16+number)*16,branches)
    raw = bytes(raw)
    return raw,dict(binary_sha256=sha(raw),text=dict(address=base,file_offset=0,bytes=len(raw)),definitions=rows)


class DirtySourceControls(unittest.TestCase):
    def test_both_literal_operators_and_entire_setter_perimeter_are_preserved(self):
        original = proposal.derive('original')
        for arm,replacement in [('comparison',proposal.CONTROL),('transition',proposal.FULL)]:
            value = proposal.derive(arm)
            self.assertEqual(value[proposal.PATHS[0]].replace(replacement.encode(),proposal.BLOCK.encode()),original[proposal.PATHS[0]])
            self.assertIn(b'previous_database_value != captured.current_database_value',value[proposal.PATHS[1]])
            self.assertIn(b'previous_database_value == captured.current_database_value',value[proposal.PATHS[1]])
            self.assertEqual(value[proposal.PATHS[0]].count(replacement.encode()),2)

    def test_carriers_fix_getter_storage_types_and_keep_mutable_references(self):
        captured = (ROOT/'source/captured_column_assignment.cr.txt').read_text()
        recorded = (ROOT/'source/recorded_column_assignment.cr.txt').read_text()
        self.assertIn('struct CapturedColumnAssignment',captured)
        self.assertEqual(captured.count(': Grant::Base::DirtyValue\n'),2)
        self.assertIn('struct RecordedColumnAssignment',recorded)
        self.assertNotIn('.dup',captured+recorded+proposal.TRANSITION)
        self.assertIn('has_key?(attribute_name)',proposal.TRANSITION)

    def test_source_plan_matches_each_full_physical_inventory_and_restores_modes(self):
        with temporary() as directory:
            root = Path(directory)
            stage(ROOT/'inputs/grant-source-and-frozen-dependencies.tar.gz',root/'source')
            grant = root/'source/grant'
            original = source_input_inventory(grant)
            prepared = plan.prepare(root/'plan',grant,Path('/reviewed/bin/crystal-alpha'))
            self.assertEqual(len(original[0]),1554)
            self.assertEqual(prepared['ordered_arms'],list(plan.ARMS))
            for arm in plan.ARMS:
                observation = {}
                with dirty_overlay.apply(grant,arm,observation=observation):
                    rows,fingerprint = source_input_inventory(grant)
                    self.assertEqual(rows,plan.source_rows(arm))
                    self.assertEqual(fingerprint,prepared['source_fingerprints'][arm])
                self.assertTrue(observation['restored'])
                self.assertEqual(source_input_inventory(grant),original)
                self.assertFalse((grant/'src/grant/dirty').exists())

    def test_exception_restores_complete_roster(self):
        with temporary() as directory:
            root = minimal(Path(directory)/'grant')
            observation = {}
            with self.assertRaisesRegex(ValueError,'behavior refused'):
                with dirty_overlay.apply(root,'transition',observation=observation):
                    raise ValueError('behavior refused')
            self.assertTrue(observation['restored'])
            self.assertFalse((root/'src/grant/dirty').exists())

    def test_wrong_original_bytes_mode_alias_and_unowned_new_file_refuse_before_writes(self):
        for change in ('bytes','mode','alias','new'):
            with self.subTest(change=change),temporary() as directory:
                root = minimal(Path(directory)/'grant')
                path = root/proposal.PATHS[0]
                if change == 'bytes':path.write_bytes(b'changed')
                if change == 'mode':path.chmod(0o600)
                if change == 'alias':
                    path.rename(path.with_suffix('.saved'))
                    path.symlink_to(path.with_suffix('.saved'))
                if change == 'new':
                    path = root/proposal.PATHS[2]
                    path.parent.mkdir()
                    path.write_bytes(b'unowned')
                before = (root/proposal.PATHS[1]).read_bytes()
                with self.assertRaises(RuntimeError):
                    with dirty_overlay.apply(root,'transition'):
                        self.fail('Refusal precedes writes')
                self.assertEqual((root/proposal.PATHS[1]).read_bytes(),before)

    def test_unresolved_original_group_preserves_private_overlay(self):
        with temporary() as directory:
            root = minimal(Path(directory)/'grant')
            observation = {}
            with self.assertRaisesRegex(RuntimeError,'groups remain unresolved'):
                with dirty_overlay.apply(root,'transition',retired=lambda:False,observation=observation):pass
            self.assertTrue(observation['restoration_deferred'])
            self.assertFalse(observation['restored'])
            self.assertEqual((root/proposal.PATHS[0]).read_bytes(),proposal.derive('transition')[proposal.PATHS[0]])
            self.assertTrue((root/proposal.PATHS[3]).is_file())

    def test_active_source_drift_is_retained_as_refusal_after_safe_restoration(self):
        with temporary() as directory:
            root = minimal(Path(directory)/'grant')
            observation = {}
            with self.assertRaisesRegex(RuntimeError,'Active overlay changed'):
                with dirty_overlay.apply(root,'transition',observation=observation):
                    (root/proposal.PATHS[0]).write_bytes(b'drift')
            self.assertEqual((root/proposal.PATHS[0]).read_bytes(),proposal.derive('original')[proposal.PATHS[0]])
            self.assertTrue(observation['restoration_errors'])

    def test_new_source_symlink_preserves_refusal_and_original_error(self):
        with temporary() as directory:
            root = minimal(Path(directory)/'grant')
            observation = {}
            try:
                with dirty_overlay.apply(root,'transition',observation=observation):
                    path = root/proposal.PATHS[2]
                    path.unlink()
                    path.symlink_to(root/proposal.PATHS[0])
                    raise ValueError('original behavior error')
            except RuntimeError as error:
                self.assertIsInstance(error.__context__,ValueError)
            else:self.fail('Unsafe replacement earns a retained restoration refusal')
            self.assertFalse(observation['restored'])

    def test_all_four_owner_modes_require_actual_calls(self):
        for arm in plan.ARMS:
            raw,census = owner_image(arm)
            self.assertTrue(owners(raw,census,arm)['owner_and_direct_call_predicate_passed'])

    def test_duplicate_or_narrow_global_owner_refuses(self):
        for kind in ('duplicate','narrow'):
            raw,census = owner_image('transition')
            if kind == 'duplicate':census['definitions'].append(copy.deepcopy(census['definitions'][0]))
            else:census['definitions'][0]['symbol']=census['definitions'][0]['symbol'].replace('Grant::Dirty::CapturedColumnAssignment','Int32')
            with self.assertRaises(RuntimeError):owners(raw,census,'transition')

    def test_missing_setter_and_changed_direct_branch_refuse(self):
        for kind in ('missing','branch'):
            raw,census = owner_image('transition')
            if kind == 'missing':census['definitions'].pop()
            else:
                value = bytearray(raw);value[256:260]=b'\0'*4;raw=bytes(value)
                census['binary_sha256']=sha(raw);census['definitions'][3]['extent_sha256']=sha(raw[256:272])
            with self.assertRaises(RuntimeError):owners(raw,census,'transition')

    def test_changed_binary_and_non_function_interval_refuse(self):
        raw,census = owner_image('transition')
        with self.assertRaises(RuntimeError):owners(raw+b'x',census,'transition')
        census['definitions'][0]['function_start']=False
        with self.assertRaises(RuntimeError):owners(raw,census,'transition')

    def test_pending_or_changed_proof_registry_refuses(self):
        path = ROOT/'PROOF_TOOLS_PENDING.json'
        with self.assertRaisesRegex(RuntimeError,'explicit prerequisite'):dirty_proof.admit_tools(path,sha(path.read_bytes()))
        with self.assertRaisesRegex(RuntimeError,'SHA-256'):dirty_proof.admit_tools(path,'0'*64)

    def test_guarded_provider_preflight_admits_exact_origins_and_refuses_changed_tool_or_tree(self):
        with temporary() as directory:
            root=Path(directory)
            value=json.loads((ROOT/'PROOF_PROVIDER_ARGUMENTS.json').read_bytes())['tool_fields']
            for name,row in value.items():
                path=root/name;path.write_bytes(b'x'*3590088 if name=='amber_lsp' else b'bounded provider metadata fixture\n');path.chmod(0o755)
                row['path']=str(path)
                if name=='ameba':row['sha256']=sha(path.read_bytes())
            corpus=root/'share/amber_cli/api/crystal.yml';corpus.parent.mkdir(parents=True);corpus.write_bytes(b'x'*9858);corpus.chmod(0o644)
            value['amber_lsp']['api_corpus_path']=str(corpus)
            registry=root/'registry.json'
            def save():
                registry.write_text(json.dumps(dict(format='atlas-grant-hosted-proof-tools-v1',execution_admitted=True,tools=value)))
                return sha(registry.read_bytes())
            actual_digest=dirty_proof.digest
            def provider_digest(path):
                if Path(path)==root/'amber_lsp':return value['amber_lsp']['sha256']
                if Path(path)==corpus:return value['amber_lsp']['api_corpus_sha256']
                return actual_digest(path)
            with mock.patch.object(dirty_proof,'digest',side_effect=provider_digest):
                expected=save()
                self.assertEqual(dirty_proof.admit_tools(registry,expected)['tools'],value)
                value['ameba']['source_git_tree_sha1']='0'*40
                with self.assertRaisesRegex(RuntimeError,'standing Ameba'):dirty_proof.admit_tools(registry,save())
                value['ameba']['source_git_tree_sha1']='5fe9fbff073fc9a41923f19d8a43b9b35a528ac8'
                expected=save();(root/'ameba').write_bytes(b'changed provider')
                with self.assertRaises(RuntimeError):dirty_proof.admit_tools(registry,expected)

    def test_unknown_api_exit4_keeps_raw_refusal_then_requires_exact_json_verification(self):
        with temporary() as directory:
            output=Path(directory)
            known=dict(query='Hash#delete',status='found',api_card_errors=[],freshness='fresh',entries=[{'signature':'delete(key)'}],failure_reason=None,verification_status='present')
            unknown=dict(known,status='unknown',entries=[],verification_status=None)
            from test_dirty_prerequisites import command, write_record
            class Runner:
                def __init__(self):self.records=[]
                def run(self,label,arguments,**kwargs):
                    row=command(label,arguments=[str(item) for item in arguments],exit_code=4 if label=='api-0' else 0)
                    value=unknown if label=='api-0' else known
                    write_record(output,row,json.dumps(value));self.records.append(row)
                    if label=='api-0':raise RuntimeError('retained original unknown-card status')
                    return json.dumps(value),''
            runner=Runner()
            result=dirty_proof.lookup(runner,'/reviewed/amber-lsp','Hash#delete',0,output,{},output)
            self.assertEqual(result,known)
            self.assertEqual([row['label'] for row in runner.records],['api-0','api-verify-0'])
            known['query']='wrong method'
            with self.assertRaises(RuntimeError):dirty_proof.lookup(Runner(),'/reviewed/amber-lsp','Hash#delete',0,output,{},output)

    def test_original_spec_coverage_refuses_missing_failed_or_pending_results(self):
        self.assertEqual(dirty_proof.spec_counts('10 examples, 0 failures, 0 errors, 0 pending\n')['examples'],10)
        for raw in ('','0 examples, 0 failures, 0 errors, 0 pending','10 examples, 1 failures, 0 errors, 0 pending','10 examples, 0 failures, 0 errors, 1 pending'):
            with self.assertRaises(RuntimeError):dirty_proof.spec_counts(raw)

    def test_complete_proof_refuses_unresolved_hashless_or_changed_return(self):
        from test_dirty_prerequisites import completed_proof
        value=completed_proof()
        dirty_proof.complete_return(value)
        for mutation in ('group','hash','source','deadline'):
            broken=copy.deepcopy(value)
            if mutation=='group':broken['groups'][0]['status']='present'
            if mutation=='hash':broken['commands'][0]['stdout_sha256']=None
            if mutation=='source':broken['overlays'][0]['restored']=False
            if mutation=='deadline':broken['elapsed_seconds']=6600.1
            with self.assertRaises(RuntimeError):dirty_proof.complete_return(broken)

    def test_budget_composes_all_horizons_and_four_arm_reservations(self):
        self.assertEqual((plan.TOTAL_SECONDS,plan.SETUP_SECONDS,plan.PROOF_SECONDS,plan.MEASUREMENT_SECONDS,plan.CONTROLLER_RETURN_SECONDS),(15000,600,6600,7200,600))
        self.assertEqual(sum((600,6600,7200,600)),15000)
        self.assertEqual((contrast.GLOBAL_SECONDS,contrast.ARM_SECONDS),(7200,1500))
        with mock.patch.object(controller.time,'monotonic',return_value=7200):controller.reserve(15000,7800,'measurement')
        with mock.patch.object(controller.time,'monotonic',return_value=7200.1):
            with self.assertRaises(RuntimeError):controller.reserve(15000,7800,'measurement')

    def test_artifact_worst_case_roster_fits_original_entry_and_byte_contract(self):
        with temporary() as directory:
            source=Path(directory)/'source';(source/'proof').mkdir(parents=True)
            for index in range(len(dirty_proof.API_METHODS)):
                (source/'proof'/('api-verify-'+str(index)+'.stdout.txt')).write_bytes(b'')
            rows=artifact.expected_roster(source)
            self.assertLessEqual(len(rows),320)
            self.assertEqual(len(rows),len(set((str(root),name) for root,name in rows)))

    def test_artifact_retains_actual_early_refusal_and_names_unexecuted_evidence(self):
        with temporary() as directory:
            root=Path(directory);source=root/'source';source.mkdir()
            (source/'DIRTY_EXPERIMENT_RESULT.json').write_text('{"passed":false,"error":"provider refusal"}')
            with mock.patch.object(artifact,'expected_roster',return_value=[(source,'DIRTY_EXPERIMENT_RESULT.json'),(source,'proof/PROOF_RESULT.json')]):
                result=artifact.stage(source,root/'artifact')
            self.assertEqual(json.loads((root/'artifact/DIRTY_EXPERIMENT_RESULT.json').read_bytes())['error'],'provider refusal')
            self.assertIn('proof/PROOF_RESULT.json',result['missing_failure_evidence'])

    def test_probe_covers_literal_equality_identity_typed_layout_and_actual_regression(self):
        raw=(ROOT/'source/dirty_contract_probe.cr.txt').read_text()
        for value in ('Float64::NAN','1_i32, 1_i64','Bytes[1, 2]','UUID.empty','Time.utc','present nil baseline',
                      'original reference identity','empty/reverted pending reference retained','array baseline alias retained',
                      'typeof(captured.previous_database_value) == Grant::Base::DirtyValue','GC.stats.total_bytes','sizeof(Grant::Dirty::CapturedColumnAssignment)',
                      'GRANT_DIRTY_INJECT_INVALID_BASELINE'):
            self.assertIn(value,raw)

    def test_new_workflow_is_manual_and_preserves_original_sdk_install_and_budget_phases(self):
        raw=workflow_bytes()
        self.assertIn('workflow_dispatch:',raw)
        self.assertNotIn('  push:',raw)
        for value in ('timeout-minutes: 350','timeout-minutes: 45','timeout-minutes: 15','timeout-minutes: 252',
                      'qualify_same_job_sdk.py','run_dirty_experiment.py','stage_dirty_result_artifact.py',
                      'PROOF_TOOLS_PENDING.json','persist-credentials: false'):
            self.assertIn(value,raw)

    def test_missing_or_changed_new_workflow_refuses_in_the_physical_layout(self):
        with temporary() as directory:
            path=Path(directory)/'workflow.yml'
            module=sys.modules[__name__]
            with mock.patch.object(module,'DIRTY_WORKFLOW_FIXTURE',path):
                with self.assertRaises(RuntimeError):workflow_bytes()
            raw=workflow_bytes()
            path.write_text(raw.replace('timeout-minutes: 252','timeout-minutes: 82'))
            with mock.patch.object(module,'DIRTY_WORKFLOW_FIXTURE',path):
                with self.assertRaises(AssertionError):self.test_new_workflow_is_manual_and_preserves_original_sdk_install_and_budget_phases()

    def test_probe_protocol_rejects_lost_work_extra_output_and_missing_layout(self):
        behavior=json.loads((ROOT/'inputs/FIXTURE_2.json').read_bytes())['expected_behavior']
        prefix='GRANT_COMPILE_ACCEPTANCE_BEHAVIOR='+json.dumps(behavior)+'\n'
        setter='GRANT_DIRTY_SETTERS allocation_calls=0 requested_bytes=0 elapsed_nanoseconds=100 iterations=10000 checksum=60000\n'
        tail='GRANT_DIRTY_CONTRACT=PASS\n'
        value=dirty_proof.probe_observation(prefix+setter+tail,'original')
        self.assertEqual(value['iterations'],10000)
        for raw in (prefix+setter+tail+'extra\n',(prefix+setter+tail).replace('checksum=60000','checksum=59999'),prefix+tail):
            with self.assertRaises(RuntimeError):dirty_proof.probe_observation(raw,'original')
        with self.assertRaises(RuntimeError):dirty_proof.probe_observation(prefix+setter+tail,'comparison')

    def test_warmed_setter_budget_preserves_original_calls_bytes_and_explicit_time_cap(self):
        row=dict(allocation_calls=1,requested_bytes=16,elapsed_nanoseconds=1000000)
        value={arm:dict(row) for arm in plan.ARMS}
        self.assertTrue(dirty_proof.runtime_budget(value)['passed'])
        for metric,changed in [('allocation_calls',2),('requested_bytes',17),('elapsed_nanoseconds',3000001)]:
            broken=copy.deepcopy(value);broken['transition'][metric]=changed
            with self.assertRaisesRegex(RuntimeError,'budget exceeded'):dirty_proof.runtime_budget(broken)

    def controller_fixture(self,root,proof_elapsed=1,setup_elapsed=1,pending=False):
        clock=SimpleNamespace(value=0.0)
        args=SimpleNamespace(output=root/'output',driver=ROOT/'vendor/sdk_install_qualification.py',sdk_evidence=root/'sdk',
            proof_tools=ROOT/'PROOF_TOOLS_PENDING.json',proof_tools_sha256='a'*64,
            python_sha256='a'*64,time_sha256='a'*64,timing_true_sha256='a'*64,packet_sha256='a'*64)
        admission=dict(providers={},job_identity={'job':'exact'})
        def project(archive,destination):
            (destination/'grant').mkdir(parents=True);clock.value=setup_elapsed
            return {'source':'exact'}
        def prepare(destination,grant,wrapper):
            destination.mkdir();(destination/'DIRTY_PLAN.json').write_text('{}')
        def proof(output,*arguments,**kwargs):
            output.mkdir();clock.value+=proof_elapsed
            value=dict(passed=True)
            (output/'PROOF_RESULT.json').write_text(json.dumps(value));return value
        def qualify(settings,**kwargs):
            settings.output.mkdir(parents=True)
            value=dict(diagnostic_complete=True,owner_shape_accepted=True,samples=[dict(arm=arm,source_overlay=dict(restored=True)) for arm in plan.ARMS])
            (settings.output/'COMPARISON_RESULT.json').write_text(json.dumps(value));return 0
        admission['providers']['compiler_wrapper']=dict(path='/reviewed/crystal-alpha',sha256='a'*64)
        with mock.patch.object(controller.time,'monotonic',side_effect=lambda:clock.value), \
             mock.patch.object(controller,'digest',return_value='a'*64),mock.patch.object(controller,'protect_packet',return_value={}), \
             mock.patch.object(controller,'metadata',return_value=admission),mock.patch.object(controller,'stage',side_effect=project), \
             mock.patch.object(controller,'prepare',side_effect=prepare), \
             mock.patch.object(controller,'calibrate',return_value=dict(profile={'exact':'profile'})), \
             mock.patch.object(controller,'calibration_return'),mock.patch.object(controller,'arm_return'), \
             mock.patch.object(controller,'qualify',side_effect=qualify) as measured, \
             mock.patch.object(controller.dirty_proof,'run',side_effect=proof) as proved, \
             mock.patch.object(controller.dirty_proof,'complete_return'), \
             mock.patch.object(controller.dirty_proof,'admit_tools',side_effect=RuntimeError('Pending reviewed proof tools') if pending else None,return_value={'tools':{}}):
            code=controller.run(args)
        return code,json.loads((args.output/'DIRTY_EXPERIMENT_RESULT.json').read_bytes()),proved.call_count,measured.call_count

    def test_controller_mocked_complete_return_preserves_all_four_arms_and_scope(self):
        with temporary() as directory:
            code,value,proved,measured=self.controller_fixture(Path(directory))
            self.assertEqual((code,proved,measured),(0,1,1))
            self.assertEqual(value['ordered_arms'],list(plan.ARMS))
            self.assertEqual(value['actual_target_cells_accepted'],0)
            self.assertFalse(value['memory_savings_accepted'])
            self.assertFalse(value['same_job_sdk_phase']['inside_controller_horizon'])

    def test_controller_pending_tools_and_setup_overrun_preserve_unexecuted_scopes(self):
        for pending,setup in [(True,1),(False,601)]:
            with self.subTest(pending=pending),temporary() as directory:
                code,value,proved,measured=self.controller_fixture(Path(directory),pending=pending,setup_elapsed=setup)
                self.assertEqual((code,proved,measured),(2,0,0))
                self.assertFalse(value['measurement_launch_admitted'])
                self.assertIn('error',value)

    def test_controller_requires_every_measurement_horizon_after_proof(self):
        with temporary() as directory:
            code,value,proved,measured=self.controller_fixture(Path(directory),proof_elapsed=7200)
            self.assertEqual((code,proved,measured),(2,1,0))
            self.assertIn('7800-second reservation',value['error'])
            self.assertFalse(value['diagnostic_complete'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--dirty-workflow-fixture',type=Path)
    options,remaining=parser.parse_known_args()
    DIRTY_WORKFLOW_FIXTURE=options.dirty_workflow_fixture
    sys.argv=[sys.argv[0],*remaining]
    with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('Source-only workload guard')), \
         mock.patch.object(os,'kill',side_effect=AssertionError('Source-only signal guard')), \
         mock.patch.object(os,'killpg',side_effect=AssertionError('Source-only group guard')):
        unittest.main(verbosity=2)
