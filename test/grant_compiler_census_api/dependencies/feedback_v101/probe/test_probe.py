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
        self.gates_path=self.root/'GATES.json';probe.write(self.gates_path,self.gates)
        FakeRunner.instances=[];FakeRunner.refusal_label=None;FakeRunner.unresolved=False
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
