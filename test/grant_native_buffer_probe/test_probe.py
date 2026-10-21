"""Guarded source/physical fixtures; native allocation and compilation remain hosted."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('buffer_probe_test_controller',ROOT/'run_probe.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
stage_spec=importlib.util.spec_from_file_location('buffer_probe_test_stage',ROOT/'stage_probe.py')
stage_module=importlib.util.module_from_spec(stage_spec);stage_spec.loader.exec_module(stage_module)
GUARD_CALLS=[]
def guard(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','ctypes.dlopen') or event.startswith('os.exec'):
        GUARD_CALLS.append(event)
        raise RuntimeError('Source fixture external execution refused')
sys.addaudithook(guard)

def snapshot(label,values,index,mode):
    return {'label':label,'counters':[values.get(n,0) for n in probe.COUNTERS],
            'monotonic_ns':1000000+index*1000,'user_cpu_ns':index*100,'system_cpu_ns':index*10,
            'current_rss_bytes':1024 if mode=='memory' else None,
            'self_peak_rss_bytes':2048 if mode=='memory' else None,
            'physical_footprint_bytes':3072 if mode=='memory' else None}

def native_result(arm,mode,library):
    """Explicit modeled ledger: this function executes no LLVM API."""
    fixed=arm=='fixed'
    states=[];v={n:0 for n in probe.COUNTERS}
    states.append(snapshot('start',v,0,mode))
    def allocate(size,count=1):
        v['allocations']+=count;v['total_requested_payload_bytes']+=size
        v['caller_owned_outstanding_bytes']+=size
        v['peak_caller_owned_bytes']=max(v['peak_caller_owned_bytes'],v['caller_owned_outstanding_bytes'])
    def retire(size,count=1):
        v['caller_owned_outstanding_bytes']-=size;v['bytes_retired_by_disposer']+=size
        v['wrapper_dispose_attempts']+=count;v['real_disposer_entered']+=count;v['real_disposer_completed']+=count
    def transfer(size):
        v['caller_owned_outstanding_bytes']-=size;v['bytes_transferred_to_consuming_ir']+=size
        v['consuming_ir_entered']+=1;v['consuming_ir_completed']+=1
        v['contexts_created']+=1;v['contexts_disposed']+=1
    allocate(64*2**20,64);states.append(snapshot('allocated64',v,1,mode))
    if fixed:retire(64*2**20,64)
    states.append(snapshot('explicit_dispose64',v,2,mode))
    allocate(262144)
    if fixed:retire(262144)
    v['file_errors']=1
    allocate(32);retire(32)
    if not fixed:
        v['wrapper_dispose_attempts']+=1;v['intercepted_nonowned_release_attempts']+=1
    states.append(snapshot('manual_finalizer_twice',v,3,mode))
    ir_size=len(b'define i32 @answer() { ret i32 42 }\n')
    invalid_size=len(b'this is invalid LLVM IR\n')
    allocate(ir_size);transfer(ir_size);v['verified_answer_modules']+=1
    allocate(128)
    if fixed:retire(128)
    v['borrowed_bitcode_calls']+=1;v['verified_answer_modules']+=1
    allocate(32)
    if fixed:retire(32)
    v['borrowed_bitcode_calls']+=1;v['native_diagnostics']+=1
    v['contexts_created']+=2;v['contexts_disposed']+=2
    states.append(snapshot('borrowed_bitcode',v,4,mode))
    for size in (ir_size,invalid_size):
        allocate(size);transfer(size)
        if not fixed:
            v['wrapper_dispose_attempts']+=1;v['intercepted_nonowned_release_attempts']+=1
    v['verified_answer_modules']+=1
    states.append(snapshot('consuming_ir',v,5,mode))
    allocate(2**20)
    states.append(snapshot('deliberate_omission',v,6,mode))
    allocate(2**20);retire(2**20)
    states.append(snapshot('natural_gc_finalizer',v,7,mode))
    retire(v['caller_owned_outstanding_bytes'],1 if fixed else 68)
    states.append(snapshot('native_cleanup',v,8,mode))
    return {'format':'atlas-native-buffer-probe-v1','arm':arm,'mode':mode,'loaded_llvm_image':library,
            'snapshots':states,'gc_finalizer_observed':True,'finalizer_rounds':1,
            'native_refusal_messages':['modeled missing file','modeled invalid bitcode','modeled invalid IR'],
            'consumed_native_destructor_observed':False,
            'llvm_answer_behavior':'Independent parsed module verifies and retains ret i32 42'}

def command_record(label,seconds,output):
    terminal={'status':'absent','scope':'original POSIX process group','group':123,
              'phase':'direct_child_returned','maximum_drain_seconds':5,'elapsed_seconds':0.01,
              'samples':[{'status':'absent','elapsed_seconds':0.01}],
              'initial_sample':{'status':'absent','elapsed_seconds':0.01},
              'terminal_sample':{'status':'absent','elapsed_seconds':0.01},
              'bounded_drain_exhausted':False,'drain_deadline':2.0,'original_command_deadline':3.0}
    return {'label':label,'exit_code':0,'expected_exit':0,'refusal':None,'maximum_seconds':seconds,'elapsed_seconds':0.1,
            'writers_confirmed_retired':True,'pid':123,'original_group':123,'terminal_group_observation':terminal,
            'stdout_sha256':probe.digest(output/(label+'.stdout.txt')),
            'stderr_sha256':probe.digest(output/(label+'.stderr.txt'))}

class FakeRunner:
    instances=[]
    refusal_label=None
    unresolved=False
    def __init__(self,output):
        self.output=output;self.records=[];self.group_observations=[];self.writers_confirmed_retired=True
        self.deadline=0;self.instances.append(self)
    def run(self,label,argv,*,cwd,environment,seconds):
        raw=b''
        if label=='build-shim':Path(argv[-1]).write_bytes(b'modeled object')
        if label.startswith('build-') and label!='build-shim':
            binary=Path(argv[argv.index('-o')+1]);binary.write_bytes(struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,0,0,0,0));binary.chmod(0o755)
        if label.endswith('-counts') or label.endswith('-memory'):
            raw=(json.dumps(native_result(argv[2],argv[3],argv[1]))+'\n').encode()
        for stream,value in (('stdout',raw),('stderr',b'')):
            (self.output/(label+'.'+stream+'.txt')).write_bytes(value)
        record=command_record(label,seconds,self.output)
        if label==self.refusal_label:
            record['refusal']='Command exceeded its time budget';record['elapsed_seconds']=seconds+1
            if self.unresolved:
                self.writers_confirmed_retired=False;record['writers_confirmed_retired']=False
                record['terminal_group_observation']['status']='present'
            self.records.append(record);self.group_observations.append(record['terminal_group_observation'])
            raise RuntimeError(record['refusal'])
        self.records.append(record);self.group_observations.append(record['terminal_group_observation'])

class FakeDriver:
    Runner=FakeRunner
    @staticmethod
    def tree_identity(path):return {'fixture':'unchanged'}

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='native buffer source fixture ')
        self.root=Path(self.temp.name).resolve()
        self.library=self.root/'LLVM.dylib';self.library.write_bytes(b'modeled LLVM image')
        self.cc=self.root/'cc';self.cc.write_bytes(b'modeled CC');self.cc.chmod(0o755)
        self.admitted={'observed_profile_sha256':'a'*64,'providers':{'compiler_wrapper':{'sha256':'b'*64},'compiler_backend':{'sha256':'c'*64}},
                       'job_identity':{'fixture':'same-job'},'stdlib':{'fixture':'unchanged'}}
        self.policy={'format':'atlas-native-buffer-provider-policy-v1','execution_admitted':True,'scope':'native-buffer-ownership-probe-only',
            'compiler_profile_sha256':'a'*64,'compiler_wrapper_sha256':'b'*64,'compiler_backend_sha256':'c'*64,
            'llvm_version':'21.1.8','llvm_source_commit':'2078da43e25a4623cab2d0d60decddf709aaea28',
            'selected_native_closure_reviewed':True,'compiler_driver_search_policy_reviewed':True,
            'native_files':[probe.stable(self.cc)[0],probe.stable(self.library)[0]],'cc':str(self.cc),'llvm_library':str(self.library),'aliases':[]}
        self.policy_path=self.root/'POLICY.json';probe.write(self.policy_path,self.policy)
        raw=self.root/'feedback.txt';raw.write_text('modeled actual-source feedback\n')
        self.gates={'format':'atlas-native-buffer-source-gates-v1','job_identity':self.admitted['job_identity'],'compiler_profile_sha256':'a'*64,
            'lookup_accepted':True,'diagnostics_accepted':True,'lint_accepted':True,'no_codegen_accepted':True,'baseline_sdk_specs_accepted':True,
            'source_sha256':{n:probe.digest(ROOT/n) for n in ('buffer_probe.cr.txt','inputs/memory_buffer.original.cr.txt','inputs/memory_buffer.fixed.cr.txt')},
            'compiler_color':'GREEN','tool_provider_review_accepted':True,
            'raw_evidence':[{'path':raw.name,'bytes':raw.stat().st_size,'sha256':probe.digest(raw)}]}
        self.complete_feedback_fixture()
        self.gates_path=self.root/'GATES.json';probe.write(self.gates_path,self.gates)
        FakeRunner.instances=[];FakeRunner.refusal_label=None;FakeRunner.unresolved=False
    def complete_feedback_fixture(self):
        """Model the separately reviewed producer's lossless physical return."""
        ordered=[('amber-lsp-version',10),('ameba-version',10)]
        ordered += [('api-'+str(index),10) for index in range(26)]
        for arm in probe.ARMS:
            ordered += [('format-'+arm,15),('diagnostics-'+arm+'-main',15),('diagnostics-'+arm+'-buffer',15),
                        ('lint-'+arm,120),('no-codegen-'+arm,180)]
        records=[];lines=[]
        for label,seconds in ordered:
            for stream in ('stdout','stderr'):(self.root/(label+'.'+stream+'.txt')).write_text('')
            row=command_record(label,seconds,self.root)
            records.append(row);lines.append(json.dumps(dict(record=row,stdout='',stderr='')))
        (self.root/'COMMAND_EVIDENCE.jsonl').write_text('\n'.join(lines)+'\n')
        producer={'format':'atlas-native-buffer-source-feedback-controller-v1','passed':True,'compiler_color':'GREEN',
            'source_sha256':self.gates['source_sha256'],'job_identity':self.admitted['job_identity'],
            'compiler_profile_sha256':self.admitted['observed_profile_sha256'],'command_seconds_worst_case':1575,
            'maximum_seconds':1800,'return_seconds':120,'original_groups':[row['terminal_group_observation'] for row in records],
            'finalization_errors':[],'private_removed':True,'source_provider_return_accepted':True,'elapsed_seconds':1.0,
            'writers_confirmed_retired':True,'commands':len(records),'actual_target_cells_accepted':0,'full_native_memory_qualified':False}
        probe.write(self.root/'RESULT.json',producer)
        probe.write(self.root/'ADMISSION.json',{'modeled_same_job_admission':self.admitted})
        probe.write(self.root/'PROJECT_SOURCES.json',{'source_sha256':self.gates['source_sha256']})
        probe.write(self.root/'API_CARDS.json',{'modeled_cards':26})
        self.gates.update(format_accepted=True,producer_format=producer['format'],command_count=len(records),
            command_maximum_count=69,maximum_seconds=1800,writers_confirmed_retired=True,private_removed=True,
            source_provider_return_accepted=True,producer_manifest_sha256=probe.SOURCE_FEEDBACK_MANIFEST_SHA256,proof_tools_sha256='e'*64,
            tool_native_policy_sha256='f'*64,controller_result_sha256=probe.digest(self.root/'RESULT.json'),
            feedback_return={'result_path':'RESULT.json','command_evidence_path':'COMMAND_EVIDENCE.jsonl',
                'admission_path':'ADMISSION.json','project_sources_path':'PROJECT_SOURCES.json','maximum_seconds':1800,
                'command_maximum_count':69,'return_reserve_seconds':120})
        for name in ('COMMAND_EVIDENCE.jsonl','API_CARDS.json','ADMISSION.json','PROJECT_SOURCES.json','RESULT.json'):
            path=self.root/name
            self.gates['raw_evidence'].append({'path':name,'bytes':path.stat().st_size,'sha256':probe.digest(path)})

    def tearDown(self):self.temp.cleanup()
    def native(self,arm='fixed',mode='counts'):
        return native_result(arm,mode,str(self.library))
    def validate(self,value,arm='fixed',mode='counts'):
        return probe.validate_result(value,arm,mode,str(self.library))
    def change(self,value,path,replacement):
        result=copy.deepcopy(value);current=result
        for key in path[:-1]:current=current[key]
        current[path[-1]]=replacement
        return result
    def execute(self):
        args=argparse_namespace(output=self.root/'output',native_policy=self.policy_path,
            native_policy_sha256=probe.digest(self.policy_path),source_gates=self.gates_path,source_gates_sha256=probe.digest(self.gates_path))
        context={'started':probe.time.monotonic(),'admitted':self.admitted,'paths':{'compiler_wrapper':'/modeled/crystal-alpha'},
                 'stdlib':self.root,'revalidate':lambda:None}
        return probe.execute(args,FakeDriver,context,{}),args
    def test_three_arm_native_ledger(self):
        for arm in probe.ARMS:
            for mode in probe.MODES:self.validate(self.native(arm,mode),arm,mode)
    def test_original_restored_counters_match(self):
        self.assertEqual(self.validate(self.native('original'),'original')['counters'],self.validate(self.native('restored'),'restored')['counters'])
    def test_native_call_sensitivity(self):
        value=self.native();value['snapshots'][2]['counters'][5]=0
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_native_refusal_raw_required(self):
        for bad in ('abc',['one','','three']):
            value=self.native();value['native_refusal_messages']=bad
            with self.assertRaises(RuntimeError):self.validate(value)
    def test_source_feedback_executes_before_native(self):
        self.gates['lookup_accepted']=False;probe.write(self.gates_path,self.gates)
        code,args=self.execute();self.assertEqual(code,2)
        self.assertEqual(FakeRunner.instances[0].records,[])
        self.assertTrue((args.output/'NATIVE_BEFORE.json').exists())
    def test_working_entry_capacity(self):
        class FakePath:
            @staticmethod
            def lstat():return argparse_namespace(st_mode=0o100644,st_size=0)
        class FakeRoot:
            def __init__(self,count):self.count=count
            def rglob(self,pattern):return (FakePath() for _ in range(self.count))
        self.assertEqual(probe.working_bound(FakeRoot(8192))['entries'],8192)
        with self.assertRaises(RuntimeError):probe.working_bound(FakeRoot(8193))
    def test_working_symlink_refused(self):
        alias=self.root/'owned-alias';alias.symlink_to(self.cc)
        with self.assertRaises(RuntimeError):probe.working_bound(self.root)
    def test_caller_byte_sensitivity(self):
        value=self.native();value['snapshots'][-1]['counters'][2]=1
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_consumed_heap_claim_refused(self):
        value=self.native();value['consumed_native_destructor_observed']=True
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_wrong_loaded_image_refused(self):
        value=self.native();value['loaded_llvm_image']='/changed/LLVM.dylib'
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_shape_truncation_refused(self):
        for mutate in (lambda v:v['snapshots'].pop(),lambda v:v['snapshots'][0]['counters'].pop()):
            value=self.native();mutate(value)
            with self.assertRaises(RuntimeError):self.validate(value)
    def test_counter_grammar_refused(self):
        for bad in (True,-1,1.5,2**64):
            value=self.native();value['snapshots'][0]['counters'][0]=bad
            with self.assertRaises(RuntimeError):self.validate(value)
    def test_gc_positive_control_required(self):
        value=self.native();value['gc_finalizer_observed']=False
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_gc_bound_required(self):
        value=self.native();value['finalizer_rounds']=5
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_context_return_required(self):
        value=self.native();value['snapshots'][-1]['counters'][18]=4
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_memory_availability_refused(self):
        value=self.native('fixed','memory');value['snapshots'][0]['physical_footprint_bytes']=0
        with self.assertRaises(RuntimeError):self.validate(value,mode='memory')
    def test_counts_mode_keeps_memory_unavailable(self):
        value=self.native();value['snapshots'][0]['current_rss_bytes']=1024
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_clock_drift_refused(self):
        value=self.native();value['snapshots'][1]['monotonic_ns']=1
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_wrapper_inputs_exact(self):
        original=(ROOT/'inputs/memory_buffer.original.cr.txt').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),'78205f4cb4dbbb5c3639b89903234879449b61462165165b04376a8ce7fcaabc')
        fixed=(ROOT/'inputs/memory_buffer.fixed.cr.txt').read_text()
        self.assertIn('def dispose\n    finalize',fixed)
        self.assertIn('return if @finalized\n    @finalized = true\n    LibLLVM.dispose_memory_buffer',fixed)
        self.assertIn('def release_ownership : LibLLVM::MemoryBufferRef',fixed)
    def test_exact_single_worker_and_space_argv(self):
        argv=probe.compile_argv('crystal-alpha',self.root/'main.cr',self.root/'a b.o',self.root/'binary','fixed')
        self.assertEqual(argv[argv.index('--threads')+1],'1')
        self.assertEqual(shlex.split(argv[argv.index('--link-flags')+1]),[str(self.root/'a b.o')])
        self.assertEqual(argv[-1],'-Datlas_fixed_buffer')
    def test_original_flag_boundary(self):
        for arm in ('original','restored'):
            self.assertNotIn('-Datlas_fixed_buffer',probe.compile_argv('alpha','m','o','b',arm))
    def test_environment_filters_options(self):
        with mock.patch.dict(os.environ,{'CRYSTAL_OPTS':'--no-cache','CRYSTAL_PATH':'changed','DYLD_INSERT_LIBRARIES':'changed','USER':'fixture'}):
            result=probe.environment(self.root,str(self.cc))
        self.assertEqual(shlex.split(result['CC']),[str(self.cc)]);self.assertEqual(result['CRYSTAL_WORKERS'],'1')
        self.assertFalse({'CRYSTAL_OPTS','CRYSTAL_PATH','DYLD_INSERT_LIBRARIES'}&set(result))
    def test_native_policy_positive(self):
        probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_unadmitted_policy_refused(self):
        self.policy['execution_admitted']=False;probe.write(self.policy_path,self.policy)
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_profile_scope_refused(self):
        self.admitted['observed_profile_sha256']='d'*64
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_native_version_refused(self):
        self.policy['llvm_version']='21.1.7';probe.write(self.policy_path,self.policy)
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_native_mode_drift_refused(self):
        self.cc.chmod(0o644)
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_native_kind_drift_refused(self):
        self.library.unlink();self.library.symlink_to(self.cc)
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_native_duplicate_roster_refused(self):
        self.policy['native_files'].append(self.policy['native_files'][0]);probe.write(self.policy_path,self.policy)
        with self.assertRaises(RuntimeError):probe.native_policy(self.policy_path,probe.digest(self.policy_path),self.admitted)
    def test_native_alias_return(self):
        path=self.root/'libalias';path.symlink_to(self.library.name)
        rows=[{'path':str(path),'target':self.library.name,'resolved_path':str(self.library)}]
        self.assertEqual(probe.aliases(rows),rows)
        path.unlink();path.symlink_to(self.cc.name)
        with self.assertRaises(RuntimeError):probe.aliases(rows)
    def test_source_gates_positive(self):
        probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
    def test_source_gate_raw_bytes_required(self):
        (self.root/'feedback.txt').write_text('changed')
        with self.assertRaises(RuntimeError):probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
    def test_source_gate_source_join_required(self):
        self.gates['source_sha256']['buffer_probe.cr.txt']='0'*64;probe.write(self.gates_path,self.gates)
        with self.assertRaises(RuntimeError):probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
    def test_source_gate_job_required(self):
        with self.assertRaises(RuntimeError):probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,{'fixture':'other-job'})
    def test_source_gate_path_escape_refused(self):
        self.gates['raw_evidence'][0]['path']='../feedback.txt';probe.write(self.gates_path,self.gates)
        with self.assertRaises(RuntimeError):probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
    def test_regular_file_bound(self):
        with self.assertRaises(RuntimeError):probe.stable(self.library,1)
    def test_macho_header_control(self):
        self.cc.write_bytes(b'changed header')
        with self.assertRaises(RuntimeError):probe.macho(self.cc)
    def test_complete_mocked_execution(self):
        code,args=self.execute();self.assertEqual(code,0)
        result=probe.read(args.output/'RESULT.json')
        self.assertTrue(result['complete']);self.assertEqual(result['command_count'],13)
        self.assertTrue(result['private_removed']);self.assertEqual(len(result['arms']),3)
        self.assertEqual(len(result['observer_contrasts']),3)
        self.assertEqual(len(FakeRunner.instances[0].records),13)
        self.assertTrue(all(v['status']=='absent' for v in result['original_group_observations']))
    def test_complete_positive_public_stage(self):
        code,args=self.execute();self.assertEqual(code,0)
        expected=probe.digest(ROOT/'SOURCE_PINS.json')
        receipt=stage_module.stage(args.output,self.root/'public',expected)
        self.assertTrue(receipt['native_probe_complete']);self.assertEqual(receipt['missing'],[])
        self.assertIn('source/run_probe.py',{r['path'] for r in receipt['files']})
        self.assertIn('source_feedback/feedback.txt',{r['path'] for r in receipt['files']})
        self.assertFalse((self.root/'public/private').exists())
    def test_positive_public_stage_requires_raw(self):
        code,args=self.execute();self.assertEqual(code,0)
        (args.output/'fixed-counts.stdout.txt').unlink()
        with self.assertRaises(RuntimeError):stage_module.stage(args.output,self.root/'public',probe.digest(ROOT/'SOURCE_PINS.json'))
    def test_positive_public_stage_requires_binary_bytes(self):
        code,args=self.execute();self.assertEqual(code,0)
        (args.output/'original.probe').write_bytes(b'changed')
        with self.assertRaises(RuntimeError):stage_module.stage(args.output,self.root/'public',probe.digest(ROOT/'SOURCE_PINS.json'))
    def test_positive_public_stage_refuses_credentials(self):
        code,args=self.execute();self.assertEqual(code,0)
        (args.output/'fixed-counts.stderr.txt').write_bytes(b'authorization: bearer '+b'X'*24)
        with self.assertRaises(ValueError):stage_module.stage(args.output,self.root/'public',probe.digest(ROOT/'SOURCE_PINS.json'))
    def test_failure_public_stage_preserves_actual_refusal(self):
        self.policy['execution_admitted']=False;probe.write(self.policy_path,self.policy)
        code,args=self.execute();self.assertEqual(code,2)
        receipt=stage_module.stage(args.output,self.root/'public',probe.digest(ROOT/'SOURCE_PINS.json'))
        self.assertFalse(receipt['native_probe_complete']);self.assertTrue(receipt['missing'])
        result=probe.read(self.root/'public/RESULT.json')
        self.assertIn('Explicit scoped',result['errors'][0])
    def test_unresolved_public_stage_preserves_result_only(self):
        FakeRunner.refusal_label='original-counts';FakeRunner.unresolved=True
        code,args=self.execute();self.assertEqual(code,2)
        receipt=stage_module.stage(args.output,self.root/'public',probe.digest(ROOT/'SOURCE_PINS.json'))
        selected={row['path'] for row in receipt['files'] if not row['path'].startswith('source/')}
        self.assertEqual(selected,{'RESULT.json'})
        self.assertTrue(receipt['unresolved_original_writer_scope'])
    def test_refused_command_preserved(self):
        FakeRunner.refusal_label='fixed-counts'
        code,args=self.execute();self.assertEqual(code,2)
        result=probe.read(args.output/'RESULT.json');self.assertFalse(result['complete'])
        self.assertIn('Command exceeded',result['errors'][0]);self.assertTrue(result['private_removed'])
        self.assertTrue((args.output/'fixed-counts.stdout.txt').exists())
    def test_unresolved_group_preserves_private(self):
        FakeRunner.refusal_label='original-counts';FakeRunner.unresolved=True
        code,args=self.execute();self.assertEqual(code,2)
        result=probe.read(args.output/'RESULT.json')
        self.assertFalse(result['writers_confirmed_retired']);self.assertTrue((args.output/'private').exists())
    def test_admission_refusal_retained_before_calls(self):
        self.policy['execution_admitted']=False;probe.write(self.policy_path,self.policy)
        code,args=self.execute();self.assertEqual(code,2)
        self.assertEqual(FakeRunner.instances[0].records,[])
        self.assertIn('Explicit scoped',probe.read(args.output/'RESULT.json')['errors'][0])
    def test_exact_native_source_contract_sites(self):
        text=(ROOT/'buffer_shim.c').read_text()
        self.assertIn('dispose_buffer(pointer);\n  counters[7]++',text)
        self.assertIn('entry->state = 3; counters[2] -= entry->size',text)
        self.assertIn('if (!entry) { counters[6]++; return; }',text)
        self.assertIn('used >= CAPACITY || find_live(pointer)',text)
        self.assertIn('LLVMParseBitcodeInContext2',text);self.assertIn('LLVMParseIRInContext',text)
    def test_13_command_positive_roster(self):
        self.assertEqual(len(stage_module.COMMANDS),13)
        self.assertEqual(len(stage_module.FIXED+stage_module.RAW),38)
    def test_packet_hash_refusal(self):
        with self.assertRaises(RuntimeError):probe.packet('0'*64)
    def test_slow_return_record_refused(self):
        for stream in ('stdout','stderr'):(self.root/('fixture.'+stream+'.txt')).write_bytes(b'')
        record=command_record('fixture',10,self.root);record['elapsed_seconds']=11
        with self.assertRaises(RuntimeError):probe.validate_command(record,'fixture',10,self.root)
    def test_original_refusal_record_refused(self):
        for stream in ('stdout','stderr'):(self.root/('fixture.'+stream+'.txt')).write_bytes(b'')
        record=command_record('fixture',10,self.root);record['refusal']='time budget'
        with self.assertRaises(RuntimeError):probe.validate_command(record,'fixture',10,self.root)
    def test_return_group_identity_refused(self):
        for stream in ('stdout','stderr'):(self.root/('fixture.'+stream+'.txt')).write_bytes(b'')
        record=command_record('fixture',10,self.root);record['original_group']=124
        with self.assertRaises(RuntimeError):probe.validate_command(record,'fixture',10,self.root)
    def test_stream_corruption_refused(self):
        for stream in ('stdout','stderr'):(self.root/('fixture.'+stream+'.txt')).write_bytes(b'')
        record=command_record('fixture',10,self.root);(self.root/'fixture.stderr.txt').write_bytes(b'changed')
        with self.assertRaises(RuntimeError):probe.validate_command(record,'fixture',10,self.root)
    def test_deadline_admission_reserves_all_arms(self):
        with mock.patch.object(probe.time,'monotonic',return_value=1000):
            args=argparse_namespace(output=self.root/'output',native_policy=self.policy_path,native_policy_sha256=probe.digest(self.policy_path),
                source_gates=self.gates_path,source_gates_sha256=probe.digest(self.gates_path))
            context={'started':0,'admitted':self.admitted,'paths':{'compiler_wrapper':'/modeled/alpha'},'stdlib':self.root,'revalidate':lambda:None}
            self.assertEqual(probe.execute(args,FakeDriver,context,{}),2)
        result=probe.read(args.output/'RESULT.json');self.assertFalse(result['complete'])


    def positive_output(self):
        code,args=self.execute();self.assertEqual(code,0)
        return args.output
    def stage_refusal(self,source):
        with self.assertRaises((RuntimeError,ValueError,KeyError,FileNotFoundError,TypeError)):
            stage_module.stage(source,self.root/'refused-public',probe.digest(ROOT/'SOURCE_PINS.json'))
    def reseal_return(self,source,name):
        result=probe.read(source/'RESULT.json')
        result['return_evidence'][name]=probe.stable(source/name,probe.MAX_OUTPUT)[0]
        probe.write(source/'RESULT.json',result)
    def rewrite_feedback(self,records=None,result_change=None,gates_change=None):
        producer=probe.read(self.root/'RESULT.json')
        if records is None:records=[json.loads(line)['record'] for line in (self.root/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()]
        producer['commands']=len(records)
        producer['original_groups']=[copy.deepcopy(row['terminal_group_observation']) for row in records]
        if result_change:result_change(producer)
        probe.write(self.root/'RESULT.json',producer)
        lines=[json.dumps(dict(record=row,stdout='',stderr='')) for row in records]
        (self.root/'COMMAND_EVIDENCE.jsonl').write_text('\n'.join(lines)+'\n')
        self.gates['command_count']=len(records)
        self.gates['controller_result_sha256']=probe.digest(self.root/'RESULT.json')
        for row in self.gates['raw_evidence']:
            member=self.root/row['path'];row.update(bytes=member.stat().st_size,sha256=probe.digest(member))
        if gates_change:gates_change(self.gates)
        probe.write(self.gates_path,self.gates)
    def feedback_refusal(self):
        with self.assertRaises((RuntimeError,ValueError,KeyError,FileNotFoundError,TypeError)):
            probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
    def test_v101_exact_five_predecessor_stage_refusals(self):
        source=self.positive_output()
        names=('NATIVE_AFTER.json','SOURCE_RETURN.json','STDLIB_AFTER.json','source_feedback/feedback.txt','SOURCE_GATES.json')
        for index,name in enumerate(names):
            with self.subTest(member=name):
                path=source/name;raw=path.read_bytes()
                if name=='source_feedback/feedback.txt':path.write_text('Changed retained feedback bytes\n')
                elif name=='SOURCE_GATES.json':
                    value=probe.read(path);value['source_sha256']['buffer_probe.cr.txt']='0'*64;probe.write(path,value)
                elif name=='SOURCE_RETURN.json':probe.write(path,{'source_inputs_restored_exact':False})
                else:probe.write(path,{'changed':True})
                self.stage_refusal(source);path.write_bytes(raw)
                accepted=stage_module.stage(source,self.root/('restored-public-'+str(index)),probe.digest(ROOT/'SOURCE_PINS.json'))
                self.assertTrue(accepted['native_probe_complete'])
    def test_v101_known_peak_zero_refusal_and_restore(self):
        value=self.native()
        for row in value['snapshots']:row['counters'][3]=0
        with self.assertRaises(RuntimeError):self.validate(value)
        self.validate(self.native())
    def test_v101_peak_covers_outstanding_and_total(self):
        for replacement in (1,2**40,True,1.0):
            with self.subTest(replacement=replacement):
                value=self.native();value['snapshots'][1]['counters'][3]=replacement
                with self.assertRaises(RuntimeError):self.validate(value)
    def test_v101_peak_and_cpu_monotonicity(self):
        for key in ('peak','user_cpu_ns','system_cpu_ns'):
            with self.subTest(counter=key):
                value=self.native()
                if key=='peak':value['snapshots'][-1]['counters'][3]=1
                else:value['snapshots'][-1][key]=0
                with self.assertRaises(RuntimeError):self.validate(value)
    def test_v101_cumulative_native_counter_return(self):
        value=self.native();value['snapshots'][5]['counters'][15]=0
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_v101_retirement_fits_allocation_count(self):
        value=self.native();value['snapshots'][2]['counters'][0]=63
        with self.assertRaises(RuntimeError):self.validate(value)
    def test_v101_all_seven_return_members_missing_and_alias(self):
        source=self.positive_output()
        for name in probe.read(source/'RESULT.json')['return_evidence']:
            with self.subTest(member=name):
                path=source/name;raw=path.read_bytes();path.unlink()
                self.stage_refusal(source)
                backup=self.root/('held-'+name);backup.write_bytes(raw);path.symlink_to(backup)
                self.stage_refusal(source);path.unlink();path.write_bytes(raw)
    def test_v101_semantic_native_return_refuses_resealed_change(self):
        source=self.positive_output();probe.write(source/'NATIVE_AFTER.json',{'changed':True})
        self.reseal_return(source,'NATIVE_AFTER.json');self.stage_refusal(source)
    def test_v101_semantic_source_return_refuses_resealed_false(self):
        source=self.positive_output();value=probe.read(source/'SOURCE_RETURN.json');value['source_inputs_restored_exact']=False
        probe.write(source/'SOURCE_RETURN.json',value);self.reseal_return(source,'SOURCE_RETURN.json');self.stage_refusal(source)
    def test_v101_semantic_stdlib_return_refuses_resealed_change(self):
        source=self.positive_output();probe.write(source/'STDLIB_AFTER.json',{'changed':True})
        self.reseal_return(source,'STDLIB_AFTER.json');self.stage_refusal(source)
    def test_v101_original_raw_policy_admission_is_retained(self):
        source=self.positive_output();self.assertEqual((source/'NATIVE_POLICY.json').read_bytes(),self.policy_path.read_bytes())
        with (source/'NATIVE_POLICY.json').open('ab') as stream:stream.write(b' ')
        self.reseal_return(source,'NATIVE_POLICY.json');self.stage_refusal(source)
    def test_v101_original_raw_gates_admission_is_retained(self):
        source=self.positive_output();self.assertEqual((source/'SOURCE_GATES.json').read_bytes(),self.gates_path.read_bytes())
        with (source/'SOURCE_GATES.json').open('ab') as stream:stream.write(b' ')
        self.reseal_return(source,'SOURCE_GATES.json');self.stage_refusal(source)
    def test_v101_sdk_result_identity_join(self):
        source=self.positive_output();value=probe.read(source/'SDK_ADMISSION.json');value['job_identity']={'fixture':'other-job'}
        probe.write(source/'SDK_ADMISSION.json',value);self.reseal_return(source,'SDK_ADMISSION.json');self.stage_refusal(source)
    def test_v101_command_and_result_groups_join(self):
        source=self.positive_output();value=probe.read(source/'RESULT.json')
        value['original_group_observations'][0]['group']=124;probe.write(source/'RESULT.json',value);self.stage_refusal(source)
    def test_v101_complete_stage_typed_status_and_horizon(self):
        source=self.positive_output();path=source/'RESULT.json';raw=path.read_bytes()
        for name,replacement in [('complete',1),('command_count',13.0),('full_target_cells_accepted',False),
                                 ('maximum_seconds',900.0),('return_reserve_seconds',True),('elapsed_seconds',901),
                                 ('elapsed_seconds',float('nan')),('source_packet_sha256','0'*64)]:
            with self.subTest(name=name,value=replacement):
                value=json.loads(raw);value[name]=replacement;probe.write(path,value)
                self.stage_refusal(source);path.write_bytes(raw)
    def test_v101_feedback_exact_source_roster(self):
        self.gates['source_sha256']['extra.cr']='0'*64;probe.write(self.gates_path,self.gates);self.feedback_refusal()
    def test_v101_feedback_duplicate_missing_alias_raw(self):
        raw=copy.deepcopy(self.gates)
        self.gates['raw_evidence'].append(self.gates['raw_evidence'][0]);probe.write(self.gates_path,self.gates);self.feedback_refusal()
        self.gates=copy.deepcopy(raw);probe.write(self.gates_path,self.gates)
        member=self.root/'ADMISSION.json';body=member.read_bytes();member.unlink();self.feedback_refusal()
        held=self.root/'held-admission';held.write_bytes(body);member.symlink_to(held);self.feedback_refusal()
    def test_v101_feedback_failed_return_even_with_rebound_raw_hashes(self):
        self.rewrite_feedback(result_change=lambda value:value.update(passed=False));self.feedback_refusal()
    def test_v101_feedback_provider_job_and_source_join(self):
        self.rewrite_feedback(result_change=lambda value:value.update(job_identity={'fixture':'other-job'}));self.feedback_refusal()
    def test_v101_feedback_exact_finite_elapsed_and_status_types(self):
        raw={path:path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        gates=copy.deepcopy(self.gates)
        for name,replacement in [('elapsed_seconds',-1),('elapsed_seconds',1801),('elapsed_seconds',float('nan')),
                                 ('maximum_seconds',True),('actual_target_cells_accepted',False),('private_removed',1),
                                 ('source_provider_return_accepted',False),('finalization_errors',['return failed'])]:
            with self.subTest(field=name,value=replacement):
                for path,body in raw.items():path.write_bytes(body)
                self.gates=copy.deepcopy(gates)
                self.rewrite_feedback(result_change=lambda value:value.update({name:replacement}));self.feedback_refusal()
    def test_v101_feedback_unknown_card_requires_immediate_successful_verify(self):
        records=[json.loads(line)['record'] for line in (self.root/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()]
        records[2]['exit_code']=4
        verify=copy.deepcopy(records[2]);verify.update(label='api-verify-0',exit_code=0)
        records.insert(3,verify);self.rewrite_feedback(records)
        probe.source_gates(self.gates_path,probe.digest(self.gates_path),self.policy,self.admitted['job_identity'])
        records.pop(3);self.rewrite_feedback(records);self.feedback_refusal()
    def test_v101_feedback_unknown_resource_refusal_stays_failed(self):
        records=[json.loads(line)['record'] for line in (self.root/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()]
        records[2].update(exit_code=4,refusal='Command exceeded its time budget')
        verify=copy.deepcopy(records[2]);verify.update(label='api-verify-0',exit_code=0,refusal=None)
        records.insert(3,verify);self.rewrite_feedback(records);self.feedback_refusal()
    def test_v101_feedback_original_command_group_output_deadline_controls(self):
        original=[json.loads(line)['record'] for line in (self.root/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()]
        for name,replacement in [('pid',True),('original_group',124),('elapsed_seconds',11),('maximum_seconds',11),
                                 ('exit_code',True),('stdout_sha256','0'*64),('writers_confirmed_retired',False),
                                 ('refusal','Command output exceeded its byte limit')]:
            with self.subTest(field=name,value=replacement):
                records=copy.deepcopy(original);records[2][name]=replacement
                self.rewrite_feedback(records);self.feedback_refusal()
    def test_v101_feedback_controller_group_and_command_roster_join(self):
        self.rewrite_feedback(result_change=lambda value:value['original_groups'][2].update(group=124));self.feedback_refusal()
    def test_v101_feedback_extra_command_refused(self):
        records=[json.loads(line)['record'] for line in (self.root/'COMMAND_EVIDENCE.jsonl').read_text().splitlines()];records.append(copy.deepcopy(records[-1]))
        self.rewrite_feedback(records);self.feedback_refusal()
    def test_v101_final_publication_rechecks_selected_raw(self):
        source=self.positive_output();original=stage_module.load
        def changed_load(path,name):
            module=original(path,name)
            if name=='native_probe_public_rules':
                read_regular=module.read_regular
                def changed_read(root,name):
                    raw=read_regular(root,name)
                    if root==self.root/'refused-public' and name=='RESULT.json':
                        (source/'source_feedback/feedback.txt').write_text('Changed during publication\n')
                    return raw
                module.read_regular=changed_read
            return module
        with mock.patch.object(stage_module,'load',side_effect=changed_load):self.stage_refusal(source)


    def test_v101_memory_peak_is_a_monotonic_observation(self):
        value=self.native(mode='memory');value['snapshots'][-1]['self_peak_rss_bytes']=1
        with self.assertRaises(RuntimeError):self.validate(value,mode='memory')
    def test_v101_exact_separate_producer_source_pin(self):
        self.gates['producer_manifest_sha256']='0'*64;probe.write(self.gates_path,self.gates);self.feedback_refusal()
    def test_v101_feedback_read_and_decode_share_admitted_bytes(self):
        original=probe.validate_feedback_return
        def mutate(gates,root,payload):
            (root/'COMMAND_EVIDENCE.jsonl').write_text('Changed during complete feedback replay')
            return original(gates,root,payload)
        with mock.patch.object(probe,'validate_feedback_return',side_effect=mutate):self.feedback_refusal()


    def test_v101_stager_full_source_admission_precedes_import(self):
        import shutil
        projected=self.root/'source projection';shutil.copytree(ROOT,projected)
        target=projected/'run_probe.py';held=target.read_bytes()
        for kind in ('changed','missing','alias'):
            with self.subTest(kind=kind):
                target.unlink()
                if kind=='changed':target.write_text('raise RuntimeError("Changed controller executed")')
                elif kind=='alias':target.symlink_to(ROOT/'run_probe.py')
                with mock.patch.object(stage_module,'ROOT',projected),mock.patch.object(stage_module,'load') as loading:
                    self.stage_refusal(self.root)
                    loading.assert_not_called()
                if target.is_symlink() or target.exists():target.unlink()
                target.write_bytes(held)


    def test_v101_complete_protected_source_roster_is_required(self):
        source=self.positive_output();result=probe.read(source/'RESULT.json');returned=probe.read(source/'SOURCE_RETURN.json')
        key=str(ROOT/'run_probe.py');self.assertIn(key,result['protected_inputs_before_sha256'])
        del result['protected_inputs_before_sha256'][key];del returned['protected_source_provider_sha256'][key]
        probe.write(source/'RESULT.json',result);probe.write(source/'SOURCE_RETURN.json',returned)
        self.reseal_return(source,'SOURCE_RETURN.json');self.stage_refusal(source)


    def test_v101_final_identity_hashing_stays_inside_original900_seconds(self):
        clock=[100.0];original=probe.stable
        def slow_final(path,maximum=256*2**20):
            value=original(path,maximum)
            if Path(path).name=='STDLIB_AFTER.json':clock[0]=1001.0
            return value
        with mock.patch.object(probe.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(probe,'stable',side_effect=slow_final):
            code,args=self.execute()
        self.assertEqual(code,2);result=probe.read(args.output/'RESULT.json')
        self.assertFalse(result['complete']);self.assertEqual(result['elapsed_seconds'],901)
        self.assertTrue(any('post-hash terminal deadline' in error for error in result['errors']))


    def test_v101_controller_source_mode_return_is_complete(self):
        admitted=[False];original_packet=probe.packet;original_stable=probe.stable
        def packet(expected):
            value=original_packet(expected);admitted[0]=True;return value
        def mode_drift(path,maximum=256*2**20):
            row,raw=original_stable(path,maximum)
            if admitted[0] and Path(path)==ROOT/'buffer_probe.cr.txt':row['mode']^=0o100
            return row,raw
        with mock.patch.object(probe,'packet',side_effect=packet),mock.patch.object(probe,'stable',side_effect=mode_drift):
            code,args=self.execute()
        self.assertEqual(code,2);result=probe.read(args.output/'RESULT.json')
        self.assertFalse(result['complete']);self.assertTrue(any('full packet source/mode' in error for error in result['errors']))

def argparse_namespace(**values):
    from types import SimpleNamespace
    return SimpleNamespace(**values)

if __name__=='__main__':
    stream=io.StringIO();suite=unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests)
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    summary={'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
             'skipped':len(result.skipped),'actual_external_guard_calls':len(GUARD_CALLS),
             'actual_compiler_native_container_browser_ssh_workload_jobs':0}
    sys.stderr.write(stream.getvalue());sys.stdout.write(json.dumps(summary)+'\n')
    raise SystemExit(0 if result.wasSuccessful() and not GUARD_CALLS else 1)
