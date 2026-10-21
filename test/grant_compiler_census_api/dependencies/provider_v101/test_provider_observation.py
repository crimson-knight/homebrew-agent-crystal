"""Guarded complete producer/reader/policy/stager behavior with authored Mach-O inputs."""
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import provider_observation as subject
import stage_observation as staging
WORK=ROOT.parents[1]
CALLS=[]
def load(path,name,expected):
    if subject.digest(path,1e30)!=expected:raise RuntimeError('Exact fixture authority before import required')
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
TRANSFER=ROOT.parent/'grant_dirty_transition' if (ROOT.parent/'grant_dirty_transition').exists() else WORK/'grant_dirty_tool_transfer_v103'
NATIVE=ROOT.parent/'grant_native_buffer_probe' if (ROOT.parent/'grant_native_buffer_probe').exists() else ROOT.parent/'integration/native_v103/source'
coupling=json.loads((ROOT/'inputs/COUPLING.json').read_bytes());subject.protect(TRANSFER,'SOURCE_PINS.json',subject.CORE_SHA,256,1e30);subject.protect(TRANSFER,'TRANSFER_SOURCE_PINS.json',subject.TRANSFER_SHA,54,1e30);native_inputs=subject.protect(NATIVE,'SOURCE_PINS.json',coupling['native'],64,1e30)
transfer=load(TRANSFER/'proof_tool_transfer.py','fixture_reviewed_transfer',subject.TOOL_HELPER_SHA)
contract=load(ROOT/'inputs/command_contract.py','fixture_original_contract','33418b91a8ed01e0d3b442781fb5c7ebdbfbb32927e5caecb9747251d9dd52c9')
probe=load(NATIVE/'run_probe.py','fixture_pin_integrated_native',native_inputs[NATIVE/'run_probe.py'])

def image(imports=(),rpaths=(),kind=2):
    commands=[]
    for name in imports:
        raw=name.encode()+b'\0';length=(24+len(raw)+7)//8*8;commands.append(struct.pack('<IIIIII',12,length,24,0,0,0)+raw+b'\0'*(length-24-len(raw)))
    for name in rpaths:
        raw=name.encode()+b'\0';length=(12+len(raw)+7)//8*8;commands.append(struct.pack('<III',0x8000001c,length,12)+raw+b'\0'*(length-12-len(raw)))
    if not commands:commands=[struct.pack('<II',0x1b,24)+b'\0'*16]
    body=b''.join(commands);return struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,kind,len(commands),len(body),0,0)+body

class ProviderControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='provider full synthetic fixture with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.stack=ExitStack();self.addCleanup(self.stack.close);self.scenario='normal'
        def guard(*a,**k):CALLS.append(repr(a));raise AssertionError('Guarded metadata fixture executes authored in-process providers')
        self.stack.enter_context(patch.object(subprocess,'Popen',guard));self.stack.enter_context(patch.object(os,'system',guard));self.stack.enter_context(patch.object(os,'killpg',guard))
        self.prefix=self.root/'homebrew';self.llvm=self.prefix/'Cellar/llvm@21/21.1.8';self.toolchain=self.root/'Xcode/Toolchains/XcodeDefault.xctoolchain';self.sdk=self.root/'Xcode/SDK/MacOSX.sdk';self.resource=self.toolchain/'usr/lib/clang/17';self.cc=self.toolchain/'usr/bin/clang';self.ld=self.toolchain/'usr/bin/ld'
        self.write(self.cc,image(),0o755);self.write(self.ld,image(),0o755);self.library=self.llvm/'lib/libLLVM.dylib';self.write(self.library,image(['/usr/lib/libSystem.B.dylib'],kind=6));self.config=self.llvm/'bin/llvm-config';self.write(self.config,b'SYNTHETIC llvm-config',0o755)
        (self.prefix/'opt').mkdir(parents=True);(self.prefix/'opt/llvm@21').symlink_to(self.llvm)
        self.write(self.prefix/'bin/brew',b'SYNTHETIC brew',0o755)
        receipt=dict(source=dict(versions=dict(stable='21.1.8'),spec='stable',tap='homebrew/core'),arch='arm64',compiler='clang',poured_from_bottle=True,time=1)
        self.write(self.llvm/'INSTALL_RECEIPT.json',json.dumps(receipt).encode());self.write(self.llvm/'.brew/llvm@21.rb',b'SYNTHETIC pinned LLVM21.1.8 formula')
        self.header=self.sdk/'usr/include/stdio.h';self.write(self.header,b'SYNTHETIC selected header');self.write(self.resource/'include/stdint.h',b'SYNTHETIC selected builtin header')
        self.write(self.sdk/'SDKSettings.json',b'{"SYNTHETIC":"SDK"}');self.write(self.sdk/'usr/lib/libSystem.tbd',b'SYNTHETIC selected linker stub');self.platform=self.root/'SystemVersion.plist';self.write(self.platform,b'SYNTHETIC platform')
        self.xcrun=self.root/'xcrun';self.xcode=self.root/'xcode-select';self.codesign=self.root/'codesign';self.write(self.xcrun,b'SYNTHETIC xcrun',0o755);self.write(self.xcode,b'SYNTHETIC xcode-select',0o755);self.write(self.codesign,b'SYNTHETIC signature verifier',0o755)
        self.repository=self.root/'repository';self.repository.mkdir();self.probe_root=self.root/'probe';self.write(self.probe_root/'buffer_shim.c',b'SYNTHETIC unchanged frozen shim')
        self.evidence=self.root/'SDK';self.evidence.mkdir();(self.evidence/'brew-root.stdout.txt').write_text(str(self.prefix)+'\n');(self.evidence/'SAME_JOB_BINDING.json').write_text('{"SYNTHETIC":"fresh nonce"}\n')
        self.package=dict(versions=dict(stable='21.1.8'),installed=[dict(version='21.1.8')])
        outer=self
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=1e30
            def run(s,label,argv,*,cwd,environment,seconds):
                args=list(map(str,argv));stderr='';code=0
                values={'developer':str(outer.root/'Xcode'),'sdk':str(outer.sdk),'cc-path':str(outer.cc),'ld-path':str(outer.ld),'sdk-version':'26.0','sdk-build':'SYNTHETIC-26','cc-version':'SYNTHETIC Apple clang17','cc-resource':str(outer.resource),'headers':'shim.o: '+ ' '.join(str(p).replace(' ','\\ ') for p in [outer.probe_root/'buffer_shim.c',outer.header,outer.resource/'include/stdint.h']),'cc-search':'SYNTHETIC '+str(outer.sdk),'link-search':'SYNTHETIC '+str(outer.sdk)+' '+str(outer.ld),'llvm-version':'21.1.8','llvm-library':str(outer.prefix/'opt/llvm@21/lib/libLLVM.dylib'),'llvm-package':json.dumps(dict(formulae=[outer.package]))}
                stdout=(values[label] if label in values else 'SYNTHETIC Apple signature provenance and verified result')+'\n'
                if outer.scenario=='wrong-llvm' and label=='llvm-version':stdout='21.1.7\n'
                if outer.scenario=='missing-header' and label=='headers':stdout+=' '+str(outer.sdk/'usr/include/absent.h')
                if outer.scenario=='cc-refusal' and label=='cc-version':code=2;stderr='SYNTHETIC metadata failure\n'
                for stream,raw in [('stdout',stdout),('stderr',stderr)]:(s.output/(label+'.'+stream+'.txt')).write_text(raw)
                sample=dict(status='absent',elapsed_seconds=.001);group=dict(status='absent',scope='original POSIX process group',group=123,phase='direct_child_returned',maximum_drain_seconds=5.,elapsed_seconds=.001,samples=[sample],initial_sample=sample,terminal_sample=sample,bounded_drain_exhausted=False,drain_deadline=2.,original_command_deadline=3.)
                record=dict(label=label,arguments=args,exit_code=code,expected_exit=0,refusal=None,maximum_seconds=seconds,elapsed_seconds=.01,writers_confirmed_retired=True,pid=123,original_group=123,terminal_group_observation=group,stdout_sha256=subject.digest(s.output/(label+'.stdout.txt'),1e30),stderr_sha256=subject.digest(s.output/(label+'.stderr.txt'),1e30))
                if outer.scenario=='unretired' and label=='headers':s.writers_confirmed_retired=False;record['writers_confirmed_retired']=False;record['refusal']='SYNTHETIC unresolved writer';group['status']='present'
                s.records.append(record);s.group_observations.append(group);subject.write(s.output/'COMMANDS.json',s.records)
                if code or record['refusal']:raise RuntimeError('SYNTHETIC refused '+label)
                return stdout,stderr
        self.admitted=dict(job_identity=dict(GITHUB_RUN_ID='SYNTHETIC-fresh-job'),observed_profile_sha256='a'*64,providers=dict(compiler_wrapper=dict(sha256='b'*64),compiler_backend=dict(sha256='c'*64)),runner=dict(source_lock_sha256='d'*64,image_os='macos26',image_version='SYNTHETIC'))
        self.native=dict(tool_native_roots=[],packages=[],libraries=[],lexical_resolutions=[],Apple_imports=['/usr/lib/libSystem.B.dylib'],unresolved_system=['/usr/lib/dyld'],system_files=[],image_version='SYNTHETIC')
        self.tools=self.root/'tools';self.tools.mkdir()
        def check(deadline):
            if self.scenario=='source-return':raise RuntimeError('SYNTHETIC changed source')
            if self.scenario=='inode-return':
                raw=self.header.read_bytes();self.header.rename(self.header.with_suffix('.saved'));self.header.write_bytes(raw)
        self.context=dict(admitted=self.admitted,driver=SimpleNamespace(Runner=Runner),transfer=transfer,tool_native=self.native,contract=contract,metadata_paths=dict(xcrun=str(self.xcrun),xcode_select=str(self.xcode),codesign=str(self.codesign),platform=str(self.platform)),check=check,probe=SimpleNamespace(__file__=probe.__file__,ROOT=self.probe_root,environment=probe.environment,native_policy=probe.native_policy),proof=SimpleNamespace(admit_tools=lambda *a:None))
        self.args=SimpleNamespace(output=self.root/'observation',repository=self.repository,sdk_evidence=self.evidence,probe_packet=self.probe_root,probe_packet_sha256='e'*64,packet_sha256='f'*64,tool_workspace=self.root,operation='observe')
    def write(self,path,raw,mode=0o644):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
    def perform(self):
        code=subject.execute_observation(self.args,self.context,time.monotonic());return code,json.loads((self.args.output/'OBSERVATION.json').read_bytes())
    def policy_args(self,value):
        decision=dict(format='atlas-native-buffer-stable-review-decision-v1',execution_admitted=True,scope='native-buffer-and-analysis-tools-only',Apple_platform_code_loading_reviewed=True,compiler_driver_search_policy_reviewed=True,selected_native_closure_reviewed=True,independent_review_sha256='1'*64,origin_observation_sha256='2'*64,stable_view=value['stable_view'],stable_view_sha256=value['stable_view_sha256'])
        path=self.root/'DECISION.json';subject.write(path,decision)
        return SimpleNamespace(output=self.root/'policies',observation=self.args.output,observation_sha256=subject.digest(self.args.output/'OBSERVATION.json',1e30),decision=path,decision_sha256=subject.digest(path,1e30),sdk_evidence=self.evidence,tool_workspace=self.root,packet_sha256=self.args.packet_sha256,probe_packet_sha256=self.args.probe_packet_sha256)
    def test_complete_actual_producer_reader_and_stager(self):
        code,value=self.perform();self.assertEqual(code,0);self.assertEqual(len(value['commands']),20);self.assertFalse(value['execution_admitted']);self.assertEqual(subject.admit_observation(self.args.output,subject.digest(self.args.output/'OBSERVATION.json',1e30)),value)
        result=staging.stage(SimpleNamespace(source=self.args.output,output=self.root/'public',packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));self.assertTrue(result['complete_observation']);self.assertGreater(len(result['files']),30);subject.admit_public_projection(self.root/'public',subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_header_argv_preserves_the_actual_compile_preprocessing_context(self):
        _,value=self.perform();context=value['shim_compile_context'];argv=context['original_argv'];self.assertEqual(context['preprocessing_argv'],[v for v in argv[:-2] if v!='-c']+['-E','-M']);self.assertTrue(all(flag in context['preprocessing_argv'] for flag in ('-Wall','-Wextra','-Werror','-O2')))
    def test_only_linked_current_tmp_scratch_names_normalize(self):
        def trace(name,flag='-O2',linked=None):return '',json.dumps(str(self.cc))+' "-cc1" '+json.dumps(flag)+' "-o" '+json.dumps(str(self.root/name))+'\n'+json.dumps(str(self.ld))+' "-o" "/dev/null" '+json.dumps(str(self.root/(linked or name)))+'\n'
        first=subject.link_trace(*trace('null-a.o'),str(self.root),str(self.ld));second=subject.link_trace(*trace('null-b.o'),str(self.root),str(self.ld));changed=subject.link_trace(*trace('null-b.o','-O0'),str(self.root),str(self.ld))
        self.assertNotEqual(first['raw_sha256'],second['raw_sha256']);self.assertEqual(first['semantic_sha256'],second['semantic_sha256']);self.assertNotEqual(first['semantic_sha256'],changed['semantic_sha256'])
    def test_changed_linked_scratch_or_outside_tmp_refuses(self):
        raw=json.dumps(str(self.cc))+' "-cc1" "-o" '+json.dumps(str(self.root/'null-a.o'))+'\n'+json.dumps(str(self.ld))+' '+json.dumps(str(self.root/'null-b.o'))+'\n'
        with self.assertRaises(RuntimeError):subject.link_trace('',raw,str(self.root),str(self.ld))
        raw=raw.replace('null-b.o','null-a.o')
        with self.assertRaises(RuntimeError):subject.link_trace('',raw,str(self.root/'other'),str(self.ld))
    def test_fresh_tmpdir_role_keeps_current_raw_environment_exact(self):
        private=self.root/'planned-private';obj=self.root/'shim.o'
        with patch.dict(os.environ,{'TMPDIR':'/SYNTHETIC/job-one'}):first=subject.shim_compile_context(self.context['probe'],str(self.cc),private,obj)
        with patch.dict(os.environ,{'TMPDIR':'/SYNTHETIC/job-two'}):second=subject.shim_compile_context(self.context['probe'],str(self.cc),private,obj)
        self.assertNotEqual(first['environment'],second['environment']);self.assertEqual(subject.stable_shim_context(first),subject.stable_shim_context(second))
    def test_public_directory_alias_refuses_and_restored_projection_passes(self):
        self.perform();public=self.root/'public';staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));receipt=subject.digest(self.args.output/'OBSERVATION.json',1e30);subject.admit_public_projection(public,receipt)
        private=self.root/'private-checkout';self.write(private/'.git/config',b'SYNTHETIC private metadata');alias=public/'unexpected-checkout';alias.symlink_to(private)
        with self.assertRaises(RuntimeError):subject.admit_public_projection(public,receipt)
        alias.unlink();subject.admit_public_projection(public,receipt)
    def test_public_special_node_refuses_before_content_read(self):
        self.perform();public=self.root/'public';staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));os.mkfifo(public/'unexpected-fifo')
        with self.assertRaises(RuntimeError):subject.admit_public_projection(public,subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_mocked_conditional_header_changes_with_optimization_and_pic_context(self):
        code,value=self.perform();self.assertEqual(code,0);context=value['shim_compile_context'];self.write(self.sdk/'usr/include/conditional_context.h',b'#if defined(__OPTIMIZE__) && defined(__PIC__)\n#include "optimized_pic.h"\n#else\n#include "fallback.h"\n#endif\n')
        def authored_preprocessor(argv,implicit_darwin_pic=True):return 'optimized_pic.h' if '-O2' in argv and ('-fPIC' in argv or implicit_darwin_pic) else 'fallback.h'
        self.assertEqual(authored_preprocessor(context['preprocessing_argv']),authored_preprocessor(context['original_argv']));self.assertEqual(authored_preprocessor([v for v in context['preprocessing_argv'] if v!='-O2']),'fallback.h');self.assertEqual(authored_preprocessor(context['preprocessing_argv'],False),'fallback.h');self.assertEqual(authored_preprocessor(context['preprocessing_argv']+['-fPIC'],False),'optimized_pic.h')
    def test_native_build_and_return_reject_environment_drift(self):
        _,value=self.perform();context=value['shim_compile_context'];private=Path(context['planned_private']);policy=dict(shim_compile_context=context)
        self.assertEqual(probe.verify_shim_context(policy,context['original_argv'],context['environment'],private),context)
        changed=dict(context['environment'],SDKROOT='/SYNTHETIC/changed/sdk')
        with self.assertRaises(RuntimeError):probe.verify_shim_context(policy,context['original_argv'],changed,private)
    def test_observation_return_rejects_changed_compiler_search_environment(self):
        original=self.context['check']
        def change(deadline):original(deadline);os.environ['SDKROOT']='/SYNTHETIC/changed/sdk'
        self.context['check']=change
        with patch.dict(os.environ,{},clear=False):code,value=self.perform()
        self.assertEqual(code,2);self.assertTrue(any('shim compile environment' in value for value in value['finalization_errors']))
    def test_replaced_output_root_refuses_every_later_receipt_write(self):
        subject.owned_root(self.args.output);self.args.output.rename(self.root/'original-output');self.args.output.mkdir()
        with self.assertRaises(RuntimeError):subject.write(self.args.output/'OBSERVATION.json',dict(passed=True))
        self.assertFalse((self.args.output/'OBSERVATION.json').exists())
    def test_replaced_output_file_refuses_receipt_overwrite(self):
        subject.owned_root(self.args.output);path=self.args.output/'OBSERVATION.json';subject.write(path,dict(passed=False));path.rename(self.args.output/'original.json');path.write_text('SYNTHETIC replacement')
        with self.assertRaises(RuntimeError):subject.write(path,dict(passed=True))
        self.assertEqual(path.read_text(),'SYNTHETIC replacement')
    def test_replaced_snapshot_directory_refuses_later_snapshot_write(self):
        subject.owned_root(self.args.output);path=self.args.output/'provider-bytes';subject.write_bytes(path/'first.bin',b'SYNTHETIC first');path.rename(self.args.output/'original-provider-bytes');path.mkdir()
        with self.assertRaises(RuntimeError):subject.write_bytes(path/'next.bin',b'SYNTHETIC next')
        self.assertFalse((path/'next.bin').exists())
    def test_actual_accepted_analysis_input_view_and_root_decision_join(self):
        accepted=json.loads((ROOT/'inputs/ACCEPTED_TOOL_NATIVE_INPUTS.json').read_bytes());self.assertEqual(subject.accepted_analysis_native(SimpleNamespace(policy_view=lambda value:value),accepted,1e30),accepted)
    def test_changed_analysis_input_view_refuses_before_observation(self):
        accepted=json.loads((ROOT/'inputs/ACCEPTED_TOOL_NATIVE_INPUTS.json').read_bytes());accepted['SYNTHETIC_CHANGED_NATIVE_INPUT']=True
        with self.assertRaises(RuntimeError):subject.accepted_analysis_native(SimpleNamespace(policy_view=lambda value:value),accepted,1e30)
    def test_changed_restricted_root_decision_refuses(self):
        original=subject.stable
        def changed(path,deadline,maximum=subject.MAX_FILE):
            row,raw=original(path,deadline,maximum)
            return (row,raw+b' ') if Path(path).name=='ROOT_ANALYSIS_SOURCE_DECISION.json' else (row,raw)
        with patch.object(subject,'stable',changed),self.assertRaises(RuntimeError):subject.accepted_analysis_native(SimpleNamespace(policy_view=lambda value:value),{},1e30)
    def test_positive_policy_uses_real_native_reader_and_registry(self):
        _,value=self.perform();args=self.policy_args(value)
        with patch.object(transfer,'registry',return_value=dict(execution_admitted=True,SYNTHETIC='reviewed tools')):self.assertEqual(subject.materialize(args,self.context,time.monotonic()),0)
        policy=json.loads((args.output/'NATIVE_POLICY.json').read_bytes());self.assertEqual(policy['compiler_profile_sha256'],'a'*64);self.assertEqual(len(policy['auxiliary_header_files']),2);probe.native_policy(args.output/'NATIVE_POLICY.json',subject.digest(args.output/'NATIVE_POLICY.json',1e30),self.admitted)
    def test_fresh_sdk_profile_join_is_separate_from_stable_review(self):
        _,value=self.perform();args=self.policy_args(value);self.admitted['observed_profile_sha256']='9'*64;self.admitted['providers']['compiler_backend']['sha256']='8'*64;value['compiler_profile_sha256']='9'*64;subject.write(self.args.output/'OBSERVATION.json',value);args.observation_sha256=subject.digest(self.args.output/'OBSERVATION.json',1e30)
        with patch.object(transfer,'registry',return_value=dict(execution_admitted=True)):self.assertEqual(subject.materialize(args,self.context,time.monotonic()),0)
        self.assertEqual(json.loads((args.output/'NATIVE_POLICY.json').read_bytes())['compiler_backend_sha256'],'8'*64)
    def test_same_byte_header_inode_replacement_refuses_return(self):
        self.scenario='inode-return';code,value=self.perform();self.assertEqual(code,2);self.assertTrue(value['finalization_errors'])
    def test_same_byte_header_inode_replacement_refuses_policy(self):
        _,value=self.perform();args=self.policy_args(value);raw=self.header.read_bytes();self.header.rename(self.header.with_suffix('.saved'));self.header.write_bytes(raw)
        with self.assertRaises(RuntimeError):subject.materialize(args,self.context,time.monotonic())
    def test_auxiliary_header_same_byte_inode_refuses_probe_reader(self):
        _,value=self.perform();args=self.policy_args(value)
        with patch.object(transfer,'registry',return_value=dict(execution_admitted=True)):self.assertEqual(subject.materialize(args,self.context,time.monotonic()),0)
        raw=self.header.read_bytes();self.header.rename(self.header.with_suffix('.saved'));self.header.write_bytes(raw)
        with self.assertRaises(RuntimeError):probe.native_policy(args.output/'NATIVE_POLICY.json',subject.digest(args.output/'NATIVE_POLICY.json',1e30),self.admitted)
    def test_header_kind_drift_refuses(self):
        self.header.unlink();self.header.symlink_to(self.platform)
        self.assertEqual(self.perform()[0],2)
    def test_library_import_frontier_is_retained(self):
        self.write(self.library,image(['@rpath/libmissing.dylib'],kind=6));code,value=self.perform();self.assertEqual(code,2);self.assertTrue(value['native_graph']['unresolved']);self.assertGreater(len(value['partial_census']['snapshots']),0)
    def test_actual_header_dependency_roster_has_a_finite_ceiling(self):
        with self.assertRaises(RuntimeError):subject.header_paths('a.o: '+' '.join('/a/'+str(i) for i in range(514)))
    def test_actual_duplicate_header_dependency_refuses(self):
        with self.assertRaises(RuntimeError):subject.header_paths('a.o: /a /a')
    def test_exported_argv_keeps_one_preprocessor_and_no_codegen_commands(self):
        _,v=self.perform();rows={r['label']:r['arguments'] for r in v['commands']};self.assertIn('-M',rows['headers']);self.assertIn('-E',rows['headers']);self.assertIn('-###',rows['cc-search']);self.assertIn('-###',rows['link-search']);self.assertEqual(sum(r['maximum_seconds'] for r in v['commands']),180)
    def test_partial_metadata_refusal_keeps_original_error_and_return(self):
        self.scenario='cc-refusal';code,v=self.perform();self.assertEqual(code,2);self.assertIn('cc-version',v['error']);self.assertTrue(v['source_provider_return_accepted']);self.assertEqual(len(v['commands']),7)
    def test_unretired_writer_stage_selects_only_observation(self):
        self.scenario='unretired';self.perform();r=staging.stage(SimpleNamespace(source=self.args.output,output=self.root/'public',packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));self.assertEqual([f['path'] for f in r['files']],['OBSERVATION.json'])
    def test_observation_return_source_failure_stays_a_failure(self):
        self.scenario='source-return';code,v=self.perform();self.assertEqual(code,2);self.assertTrue(v['finalization_errors'])
    def test_alias_retarget_is_rejected_before_policy(self):
        _,v=self.perform();a=self.policy_args(v);alias=self.prefix/'opt/llvm@21';alias.unlink();alias.symlink_to(self.root)
        with self.assertRaises((RuntimeError,OSError)):subject.materialize(a,self.context,time.monotonic())
    def test_stable_view_excludes_physical_inodes_but_keeps_library_bytes(self):
        _,v=self.perform();other=copy.deepcopy(v)
        for r in other['census']['files']:r['physical_identity'][1]+=1
        for r in other['native_graph']['images']:r['physical_identity'][1]+=1
        self.assertEqual(subject.stable_view(other),v['stable_view']);other['census']['files'][0]['sha256']='0'*64;self.assertNotEqual(subject.stable_view(other),v['stable_view'])
    def test_receipt_install_time_has_explicit_semantic_review_view(self):
        _,v=self.perform();other=copy.deepcopy(v)
        for r in other['census']['files']:
            if r['kind'].endswith('receipt'):r['sha256']='0'*64;r['bytes']+=1
        other['package']['receipt_sha256']='0'*64;self.assertEqual(subject.stable_view(other),v['stable_view'])
    def test_changed_semantic_package_refuses_fresh_view(self):
        _,v=self.perform();other=copy.deepcopy(v)
        for r in other['census']['files']:
            if r['kind'].endswith('receipt'):r['stable_receipt']['arch']='x86_64'
        self.assertNotEqual(subject.stable_view(other),v['stable_view'])
    def test_universal_arm64_slice_uses_original_import_reader(self):
        raw=image(['/usr/lib/libSystem.B.dylib']);fat=struct.pack('>II',0xcafebabe,1)+struct.pack('>IIIII',0x100000c,0,28,len(raw),0)+raw;self.assertEqual(subject.macho(fat,transfer)['imports'],['/usr/lib/libSystem.B.dylib'])
    def test_truncated_universal_slice_refuses(self):
        with self.assertRaises(RuntimeError):subject.macho(struct.pack('>II',0xcafebabe,1),transfer)
    def test_selected_snapshot_tamper_refuses_reader(self):
        _,v=self.perform();(self.args.output/v['census']['snapshots'][0]['path']).write_bytes(b'changed')
        with self.assertRaises(RuntimeError):subject.admit_observation(self.args.output,subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_raw_stream_tamper_refuses_real_reader(self):
        self.perform();(self.args.output/'headers.stdout.txt').write_text('changed')
        with self.assertRaises(RuntimeError):subject.admit_observation(self.args.output,subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_policy_requires_current_job_and_current_profile(self):
        _,v=self.perform();a=self.policy_args(v);self.admitted['job_identity']={'GITHUB_RUN_ID':'SYNTHETIC other job'}
        with self.assertRaises(RuntimeError):subject.materialize(a,self.context,time.monotonic())
    def test_external_decision_sha_is_mandatory(self):
        _,v=self.perform();a=self.policy_args(v);a.decision_sha256='0'*64
        with self.assertRaises(RuntimeError):subject.materialize(a,self.context,time.monotonic())
    def test_preparation_does_not_admit_false_review(self):
        _,v=self.perform();a=self.policy_args(v);d=json.loads(a.decision.read_bytes());d['execution_admitted']=False;subject.write(a.decision,d);a.decision_sha256=subject.digest(a.decision,1e30)
        with self.assertRaises(RuntimeError):subject.materialize(a,self.context,time.monotonic())
    def test_missing_apple_code_loading_review_refuses(self):
        _,v=self.perform();a=self.policy_args(v);d=json.loads(a.decision.read_bytes());d['Apple_platform_code_loading_reviewed']=False;subject.write(a.decision,d);a.decision_sha256=subject.digest(a.decision,1e30)
        with self.assertRaises(RuntimeError):subject.materialize(a,self.context,time.monotonic())
    def test_observation_admission_budget_exhaustion_is_recorded(self):
        code=subject.execute_observation(self.args,self.context,time.monotonic()-300);v=json.loads((self.args.output/'OBSERVATION.json').read_bytes());self.assertEqual(code,2);self.assertFalse(v['passed']);self.assertEqual(v['commands'],[])
    def test_late_policy_return_failure_disarms_all_execution_flags(self):
        _,v=self.perform();a=self.policy_args(v);self.scenario='source-return'
        with patch.object(transfer,'registry',return_value=dict(execution_admitted=True)):self.assertEqual(subject.materialize(a,self.context,time.monotonic()),2)
        for name in ('NATIVE_POLICY.json','TOOL_POLICY.json','PROOF_TOOLS.json','POLICY_RESULT.json'):self.assertFalse(json.loads((a.output/name).read_bytes())['execution_admitted'])
    def test_changed_probe_source_join_refuses_policy(self):
        _,v=self.perform();a=self.policy_args(v);a.probe_packet_sha256='0'*64
        with self.assertRaises(RuntimeError):subject.materialize(a,self.context,time.monotonic())
    def test_exact_external_observation_sha_is_required(self):
        self.perform()
        with self.assertRaises(RuntimeError):subject.admit_observation(self.args.output,'0'*64)
    def test_parent_traversal_after_intermediate_alias_preserves_posix_resolution(self):
        self.write(self.root/'actual/sub/file',b'SYNTHETIC actual target');(self.root/'alias').symlink_to(self.root/'actual/sub')
        self.write(self.root/'actual/neighbor',b'SYNTHETIC selected neighbor');resolved=subject.resolve_input(str(self.root/'alias/../neighbor'),transfer)
        self.assertEqual(resolved['resolved_path'],str(self.root/'actual/neighbor'));self.assertEqual(len(resolved['links']),1)
    def test_valid_observation_ignores_unselected_checkout_metadata_in_public_stage(self):
        self.perform();self.write(self.args.output/'.git/config',b'SYNTHETIC checkout metadata');r=staging.stage(SimpleNamespace(source=self.args.output,output=self.root/'public',packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));self.assertTrue(all('.git' not in f['path'] for f in r['files']))
    def test_public_projection_keeps_apple_toolchain_and_headers_private(self):
        _,v=self.perform();public=self.root/'public';staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)))
        projection=json.loads((public/'PUBLIC_PROJECTION.json').read_bytes())
        for r in projection['snapshots']:
            if r['original_path'] in (str(self.cc),str(self.ld),str(self.header)):
                self.assertEqual(r['visibility'],'private-fingerprint-only');self.assertFalse((public/r['path']).exists());self.assertTrue((self.args.output/r['path']).exists())
    def test_missing_private_snapshot_refuses_public_attestation(self):
        _,v=self.perform();row=next(r for r in v['census']['snapshots'] if r['original_path']==str(self.header));(self.args.output/row['path']).unlink()
        with self.assertRaises((RuntimeError,OSError)):staging.stage(SimpleNamespace(source=self.args.output,output=self.root/'public',packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)))
    def test_changed_public_metadata_roster_refuses_projection_reader(self):
        self.perform();public=self.root/'public';staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=subject.digest(ROOT/'SOURCE_PINS.json',1e30)));v=json.loads((public/'PUBLIC_PROJECTION.json').read_bytes());v['snapshots'].pop();subject.write(public/'PUBLIC_PROJECTION.json',v)
        with self.assertRaises(RuntimeError):subject.admit_public_projection(public,subject.digest(self.args.output/'OBSERVATION.json',1e30))

def refusal_case(scenario):
    def check(self):
        self.scenario=scenario;code,v=self.perform();self.assertEqual(code,2);self.assertFalse(v['passed']);self.assertFalse(v['execution_admitted'])
    return check
for scenario in ('wrong-llvm','missing-header'):setattr(ProviderControls,'test_'+scenario.replace('-','_')+'_refuses',refusal_case(scenario))

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProviderControls))
    print(json.dumps(dict(tests=result.testsRun,passed=result.wasSuccessful(),external_workload_guard_calls=CALLS)))
    raise SystemExit(0 if result.wasSuccessful() and not CALLS else 1)
