"""Guarded physical provider/producer/reader fixtures for the separate API-only route."""
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent; sys.path.insert(0,str(ROOT))
import run_census as model
import api_provider as api
import artifact
import launch_api
import test_census as original


def image(imports=(), rpaths=(), kind=2):
    commands = []
    for value in imports:
        raw = value.encode()+b'\0'; size = (24+len(raw)+7)//8*8
        commands.append(struct.pack('<IIIIII',12,size,24,0,0,0)+raw+b'\0'*(size-24-len(raw)))
    for value in rpaths:
        raw = value.encode()+b'\0'; size = (12+len(raw)+7)//8*8
        commands.append(struct.pack('<III',0x8000001c,size,12)+raw+b'\0'*(size-12-len(raw)))
    if not commands:commands = [struct.pack('<II',0x1b,24)+b'\0'*16]
    body = b''.join(commands)
    return struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,kind,len(commands),len(body),0,0)+body


class ApiOnlyControls(original.CensusControls):
    def setUp(self):
        super().setUp()
        candidates = [ROOT.parent/'grant_dirty_transition']+[parent/'grant_dirty_tool_transfer_v103' for parent in ROOT.parents]
        transfer_root = next(path for path in candidates if path.is_dir())
        model.manifest(transfer_root,'e186b50c45c15da64ede2801b41e1b05112222dd25cc969ca628c1a1007a8d0e',256)
        transfer = model.load(transfer_root/'proof_tool_transfer.py','8db41f1a4c4829dee29f2e3d7f28e038bcf3d6e402d66067432e87091f74e097','api_fixture_original_transfer')
        parser,_ = api.provider(model)
        accepted=model.decode(model.stable(ROOT/'dependencies/provider_v101/inputs/ACCEPTED_TOOL_NATIVE_INPUTS.json'))
        transfer.policy_view=lambda native:copy.deepcopy(accepted)
        self.prefix = self.root/'brew'; self.package = self.prefix/'Cellar/llvm@21/21.1.8'; self.config = self.package/'bin/llvm-config'; self.library = self.package/'lib/libLLVM.dylib'
        self.write(self.config,image(['/usr/lib/libSystem.B.dylib']),0o755); self.write(self.library,image(['/usr/lib/libSystem.B.dylib'],kind=6))
        (self.prefix/'opt').mkdir(); (self.prefix/'opt/llvm@21').symlink_to(self.package)
        self.receipt = dict(source=dict(versions=dict(stable='21.1.8'),spec='stable',tap='homebrew/core',tap_git_head='1'*40),arch='arm64',compiler='clang',poured_from_bottle=True,time=1)
        self.write(self.package/'INSTALL_RECEIPT.json',model.canonical(self.receipt)); self.write(self.package/'.brew/llvm@21.rb',b'# SYNTHETIC exact LLVM21.1.8 formula\n')
        self.actual_native = dict(tool_native_roots=[],packages=[],libraries=[],lexical_resolutions=[],Apple_imports=['/usr/lib/libSystem.B.dylib'],unresolved_system=['/usr/lib/dyld'],system_files=[],image_version='SYNTHETIC',same_job=self.admission['job_identity'])
        self.static_context = dict(admitted=self.admission,provider_parser=parser,transfer=transfer,tool_native=self.actual_native,driver=self.context['driver'],protected={},check=lambda end:None)
        self.static_context['protected'][transfer_root/'dirty_proof.py']=model.sha(model.stable(transfer_root/'dirty_proof.py'))
        self.args.transfer_packet = transfer_root; self.args.repository = self.root/'repo'; self.args.repository.mkdir(); self.args.tool_workspace = self.root/'workspace'; self.args.tool_workspace.mkdir(); self.args.policies = self.root/'fresh policies'
        self.args.python_sha256 = model.sha(model.stable(Path(sys.executable).resolve(),32*2**20))
        # The v105 provider scope adds two exact ordinary package fixtures.
        for name,version in [('pkgconf','3.0.10'),('bdw-gc','8.2.12')]:
            package=self.prefix/'Cellar'/name/version
            receipt=copy.deepcopy(self.receipt);receipt['source']['versions']['stable']=version
            self.write(package/'INSTALL_RECEIPT.json',model.canonical(receipt));self.write(package/'.brew'/(name+'.rb'),b'# SYNTHETIC exact selected package formula\n')
            (self.prefix/'opt'/name).symlink_to(package)
        self.write(self.prefix/'Cellar/pkgconf/3.0.10/bin/pkgconf',image(['/usr/lib/libSystem.B.dylib']),0o755)
        (self.prefix/'bin').mkdir();(self.prefix/'bin/pkg-config').symlink_to('../Cellar/pkgconf/3.0.10/bin/pkgconf')
        self.write(self.prefix/'Cellar/bdw-gc/8.2.12/lib/libgc.1.dylib',image(['/usr/lib/libSystem.B.dylib'],kind=6))
        self.write(self.prefix/'Cellar/bdw-gc/8.2.12/lib/pkgconfig/bdw-gc.pc',b'prefix=/SYNTHETIC\nVersion: 8.2.12\nName: bdw-gc\nDescription: SYNTHETIC GC metadata\nLibs: -lgc\n')
        self.args.operation='observe-pkgconf'
        observed=self.collect();current=dict(self.static_context,static_inputs=observed)
        self.args.pkgconf_observation.write_bytes(model.canonical(api.observation_record(model,self.args,current,time.monotonic())))
        self.args.pkgconf_observation_sha256=model.sha(self.args.pkgconf_observation.read_bytes());self.args.operation='observe'
    def write(self,path,raw,mode=0o644):
        path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw); path.chmod(mode)
    def collect(self):return api.collect(model,self.args,self.static_context,time.monotonic()+30)
    def observe(self):
        with mock.patch.object(api,'base',return_value=self.static_context):
            self.assertEqual(api.observe(model,self.args,model.Owned(self.args.output)),0)
        (self.args.output/'PKGCONF_INPUTS.json').write_bytes(model.stable(self.args.pkgconf_observation,16*2**20))
        return json.loads((self.args.output/'LLVM_STATIC_INPUTS.json').read_bytes())
    def decision_for(self, observed):
        self.decision.update(reviewed_pkgconf=observed['stable_view']['pkgconf'],pkgconf_code_loading_reviewed=True,reviewed_llvm_config=observed['llvm_config'],reviewed_native_stable_view_sha256=observed['stable_view_sha256'],reviewed_api_only_static_view=observed['stable_view'])
        self.seal_decision()
    def test_static_complete_without_any_cc_header_or_subprocess(self):
        observed=self.collect(); self.assertTrue(observed['complete']); self.assertEqual(len(observed['stable_view']['images']),4); self.assertEqual(self.calls,[])
        self.assertFalse(any('clang' in row['path'] or '/include/' in row['path'] for row in observed['physical']['files']))
    def test_literal_producer_stager_and_reader_positive(self):
        observed=self.observe(); self.assertTrue(observed['passed']); self.assertEqual(observed['actual_compiler_API_native_commands'],0)
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed']); self.assertEqual(self.runners,[])
    def test_missing_llvm_image_refuses(self):
        self.library.unlink()
        with self.assertRaises((RuntimeError,FileNotFoundError)):self.collect()
    def test_changed_llvm_version_receipt_refuses(self):
        self.receipt['source']['versions']['stable']='21.1.7'; self.write(self.package/'INSTALL_RECEIPT.json',model.canonical(self.receipt))
        with self.assertRaises(RuntimeError):self.collect()
    def test_invalid_file_kind_refuses(self):
        self.config.unlink(); self.config.mkdir()
        with self.assertRaises(RuntimeError):self.collect()
    def test_recursive_selected_imports_and_alias_convergence(self):
        extra=self.package/'lib/extra.dylib'; self.write(extra,image(['/usr/lib/libSystem.B.dylib'],kind=6)); alias=self.package/'lib/extra-alias.dylib'; alias.symlink_to(extra.name)
        self.write(self.config,image([str(extra),str(alias)]),0o755)
        observed=self.collect(); self.assertTrue(observed['complete']); self.assertEqual(len(observed['stable_view']['images']),5)
        self.assertIn(str(alias),[row['declared_path'] for row in observed['physical']['resolutions']])
    def test_absent_static_import_keeps_unresolved(self):
        self.write(self.config,image([str(self.package/'lib/absent.dylib')]),0o755)
        observed=self.collect(); self.assertFalse(observed['complete']); self.assertEqual(observed['stable_view']['unresolved'][0]['reason'],'selected import is absent')
    def test_ambiguous_rpath_keeps_unresolved(self):
        for directory in ('first','second'):self.write(self.package/directory/'same.dylib',image(kind=6))
        self.write(self.config,image(['@rpath/same.dylib'],[str(self.package/'first'),str(self.package/'second')]),0o755)
        self.assertFalse(self.collect()['complete'])
    def test_unsupported_executable_path_keeps_unresolved(self):
        self.write(self.config,image(['@executable_path/neighbor.dylib']),0o755); self.assertFalse(self.collect()['complete'])
    def test_static_deadline_refuses(self):
        with self.assertRaises(RuntimeError):api.collect(model,self.args,self.static_context,time.monotonic()-1)
    def test_image_count_ceiling_refuses(self):
        self.write(self.config,image([str(self.library)]),0o755)
        with mock.patch.object(api,'MAX_IMAGES',1),self.assertRaises(RuntimeError):self.collect()
    def test_changed_library_bytes_are_distinct_stable_inputs(self):
        before=self.collect(); self.write(self.library,image(['/usr/lib/libc++.1.dylib'],kind=6)); self.assertNotEqual(before['stable_view_sha256'],self.collect()['stable_view_sha256'])
    def test_physical_inode_change_refuses_original_return(self):
        with mock.patch.object(api,'base',return_value=self.static_context):_,_,context=api.fresh(model,self.args,30)
        raw=self.library.read_bytes(); self.library.rename(self.library.with_suffix('.old')); self.write(self.library,raw)
        with self.assertRaises(RuntimeError):context['check']()
    def test_alias_retarget_changes_physical_and_stable_view(self):
        before=self.collect(); alias=self.prefix/'opt/llvm@21'; alias.unlink(); alias.symlink_to('../Cellar/llvm@21/21.1.8')
        after=self.collect(); self.assertNotEqual(before['stable_view_sha256'],after['stable_view_sha256']); self.assertNotEqual(before['physical'],after['physical'])
    def test_receipt_install_timestamp_is_job_physical_not_cross_job_stable(self):
        before=self.collect(); self.receipt['time']=200; self.write(self.package/'INSTALL_RECEIPT.json',model.canonical(self.receipt)); after=self.collect()
        self.assertEqual(before['stable_view'],after['stable_view']); self.assertNotEqual(before['physical'],after['physical'])
    def test_reader_refuses_resealed_static_receipt_job_profile_and_descriptor(self):
        self.observe(); public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256)
        originals={name:(public/name).read_bytes() for name in ('LLVM_STATIC_INPUTS.json','PUBLIC_STAGE.json')}
        for change in ('job','profile','descriptor','return'):
            with self.subTest(change=change):
                value=json.loads(originals['LLVM_STATIC_INPUTS.json'])
                if change=='job':value['job_identity']={}
                if change=='profile':value['compiler_profile_sha256']='0'*64
                if change=='descriptor':value['inputs']['llvm_config']={}
                if change=='return':value['source_provider_return_accepted']=False
                (public/'LLVM_STATIC_INPUTS.json').write_bytes(model.canonical(value)); projection=json.loads(originals['PUBLIC_STAGE.json'])
                for row in projection['files']:
                    if row['path']=='LLVM_STATIC_INPUTS.json':row.update(bytes=(public/row['path']).stat().st_size,sha256=model.sha((public/row['path']).read_bytes()))
                (public/'PUBLIC_STAGE.json').write_bytes(model.canonical(projection))
                with self.assertRaises((RuntimeError,KeyError)):artifact.replay(public,self.args.packet_sha256)
                for name,raw in originals.items():(public/name).write_bytes(raw)
        self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
    def test_failed_static_input_returns_partial_and_original_error(self):
        self.library.unlink()
        with mock.patch.object(api,'base',return_value=self.static_context):self.assertEqual(api.observe(model,self.args,model.Owned(self.args.output)),2)
        self.assertFalse(json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes())['passed']); self.assertTrue((self.args.output/'LLVM_STATIC_PARTIAL.json').exists()); self.assertEqual(self.calls,[])
    def test_distinct_positive_decision_and_fresh_policy(self):
        observed=self.collect(); self.decision_for(observed)
        original_load=model.load
        proof=SimpleNamespace(admit_tools=lambda path,expected:model.decode(model.stable(path)))
        with mock.patch.object(api,'base',return_value=self.static_context),mock.patch.object(model,'load',side_effect=lambda path,expected,name:proof if name=='census_api_only_original_proof_tool_reader' else original_load(path,expected,name)):
            context=api.admit(model,self.args); context['check']()
        material=model.decode(model.stable(self.args.policies/'POLICY_RESULT.json')); self.assertEqual(material['format'],'atlas-census-api-only-policy-materialization-v1'); self.assertTrue(context['tools']['execution_admitted']); self.assertFalse(context['native_policy']['C_shim_and_headers_qualified'])
    def test_unreviewed_decision_refuses_before_registry_materialization(self):
        observed=self.collect(); self.decision_for(observed); self.decision['execution_admitted']=False; self.seal_decision()
        with mock.patch.object(api,'base',return_value=self.static_context),self.assertRaises(RuntimeError):api.admit(model,self.args)
        self.assertFalse(self.args.policies.exists())
    def test_changed_stable_view_refuses_positive_decision(self):
        observed=self.collect(); self.decision_for(observed); self.write(self.library,image(['/usr/lib/libc++.1.dylib'],kind=6))
        with mock.patch.object(api,'base',return_value=self.static_context),self.assertRaises(RuntimeError):api.admit(model,self.args)
    def test_context_source_return_failure_refuses_metadata(self):
        self.static_context['check']=lambda end:(_ for _ in ()).throw(RuntimeError('SYNTHETIC source/provider return'))
        with mock.patch.object(api,'base',return_value=self.static_context):self.assertEqual(api.observe(model,self.args,model.Owned(self.args.output)),2)
        failure=json.loads((self.args.output/'ADMISSION_REFUSAL.json').read_bytes()); self.assertTrue(failure['finalization_errors'])
    def test_complete_static_observation_restored_positive(self):
        before=self.collect(); raw=self.config.read_bytes(); self.config.write_bytes(b'SYNTHETIC broken Mach-O')
        with self.assertRaises((RuntimeError,struct.error)):self.collect()
        self.config.write_bytes(raw); self.assertEqual(before['stable_view'],self.collect()['stable_view'])
    def test_original_controller_and_exact_command_limits_preserved(self):
        self.assertEqual(len(model.command_roster()),126); self.assertEqual(sum(v for _,v in model.command_roster()),2310); self.assertEqual((model.OUTER_SECONDS,model.PREPARATION_SECONDS,model.RETURN_SECONDS),(2700,120,180))
    def test_api_policy_actual_controller_and_public_reader(self):
        observed=self.collect(); self.decision_for(observed)
        # The admitted current registry is supplied by the authored original
        # Runner fixture; actual commands remain guarded in every test case.
        policy=dict(pkgconf=observed['stable_view']['pkgconf'],format='atlas-census-api-only-provider-policy-v1',scope=api.SCOPE,execution_admitted=True,llvm_library=observed['stable_view']['selected']['llvm_library'],llvm_config=observed['llvm_config'],stable_view_sha256=observed['stable_view_sha256'],job_identity=self.admission['job_identity'],compiler_profile_sha256=self.admission['observed_profile_sha256'],compiler_backend_sha256=self.admission['providers']['compiler_backend']['sha256'],scope_decision_sha256=self.args.decision_sha256,C_shim_and_headers_qualified=False,whole_build_memory_qualified=False,actual_target_cells_accepted=0)
        self.native_policy=policy; self.args.native_policy.write_bytes(model.canonical(policy)); self.material.update(format='atlas-census-api-only-policy-materialization-v1',scope=api.SCOPE,stable_view_sha256=observed['stable_view_sha256'],scope_decision_sha256=self.args.decision_sha256,source_manifest_sha256=self.args.packet_sha256); self.material['policies']['NATIVE_POLICY.json']=model.sha(self.args.native_policy.read_bytes()); self.args.policy_result.write_bytes(model.canonical(self.material)); self.context.update(pkgconf=observed['stable_view']['pkgconf'],native_policy=policy,decision=self.decision,llvm_config=observed['llvm_config'])
        code,result=self.perform(real_archive=True); self.assertEqual(code,0)
        current=dict(self.static_context,static_inputs=observed); receipt=api.observation_record(model,self.args,current,time.monotonic()); (self.args.output/'LLVM_STATIC_INPUTS.json').write_bytes(model.canonical(receipt))
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
    def test_literal_manifest_first_entrypoint_observe_stage_return(self):
        args=SimpleNamespace(**vars(self.args)); args.operation='observe'
        original_spec=importlib.util.spec_from_file_location
        def prepared_spec(name,path,*a,**k):
            spec=original_spec(name,path,*a,**k)
            if Path(path).name=='api_provider.py':
                original_exec=spec.loader.exec_module
                def execute(module):
                    original_exec(module)
                    module.base=lambda *values:dict(self.static_context,protected=dict(self.static_context['protected']),check=lambda end:None)
                spec.loader.exec_module=execute
            return spec
        with mock.patch.object(importlib.util,'spec_from_file_location',side_effect=prepared_spec):self.assertEqual(launch_api.main(args),0)
        args.source=args.output; args.output=self.root/'literal public'; args.operation='stage'; self.assertEqual(launch_api.main(args),0); self.assertTrue(artifact.replay(args.output,args.packet_sha256)['passed'])
        args.operation='return'
        with mock.patch.object(importlib.util,'spec_from_file_location',side_effect=prepared_spec):self.assertEqual(launch_api.main(args),0)
    def test_cleanup_original_complete_and_independent_public_return(self):
        original_load=model.load
        synthetic=SimpleNamespace(cleanup=lambda root:dict(complete=True,maximum_seconds=30,removed=['SYNTHETIC tools'],preserved=[]))
        with mock.patch.object(model,'load',side_effect=lambda path,expected,name:synthetic if name=='api_only_original_tool_cleanup' else original_load(path,expected,name)):
            self.assertEqual(api.cleanup(model,self.args,model.Owned(self.args.output)),0)
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256); self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
    def test_incomplete_original_cleanup_retains_nonzero(self):
        original_load=model.load
        synthetic=SimpleNamespace(cleanup=lambda root:dict(complete=False,maximum_seconds=30,removed=[],preserved=['SYNTHETIC tools']))
        with mock.patch.object(model,'load',side_effect=lambda path,expected,name:synthetic if name=='api_only_original_tool_cleanup' else original_load(path,expected,name)):
            self.assertEqual(api.cleanup(model,self.args,model.Owned(self.args.output)),2)
        value=model.decode(model.stable(self.args.output/'TRANSFER_CLEANUP.json')); self.assertFalse(value['complete']); self.assertTrue(value['private_payload_preserved'])
    def test_per_file_byte_ceiling_is_preserved(self):
        with mock.patch.object(api,'MAX_FILE',16),self.assertRaises(RuntimeError):self.collect()
    def test_aggregate_byte_ceiling_is_preserved(self):
        with mock.patch.object(api,'MAX_TOTAL',16),self.assertRaises(RuntimeError):self.collect()
    def test_reader_refuses_unexpected_directory_alias_and_restores(self):
        self.observe(); public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256)
        alias=public/'unselected-directory'; alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(RuntimeError):artifact.replay(public,self.args.packet_sha256)
        alias.unlink(); self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
    def test_metadata_refusal_retains_failure_after_restaged_candidate(self):
        self.observe(); (self.args.output/'ADMISSION_REFUSAL.json').write_bytes(model.canonical(dict(passed=False,error='SYNTHETIC late return refusal')))
        public=self.root/'public'; artifact.stage(self.args.output,public,self.args.packet_sha256)
        with self.assertRaises(RuntimeError):artifact.replay(public,self.args.packet_sha256)
    def test_actual_entrypoint_changed_manifest_refuses_before_delegation(self):
        args=SimpleNamespace(**vars(self.args)); args.packet_sha256='0'*64; args.operation='observe'
        with self.assertRaises(RuntimeError):launch_api.main(args)
        self.assertFalse(args.output.exists()); self.assertEqual(self.calls,[])


if __name__ == '__main__':
    names = sorted(name for name in ApiOnlyControls.__dict__ if name.startswith('test_'))
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(ApiOnlyControls(name) for name in names))
    raise SystemExit(0 if result.wasSuccessful() else 1)
