"""Guarded formatter body/STDIN/return/staging controls with original byte fixtures."""
import copy,hashlib,importlib.util,json,os,resource,shutil,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import capture as subject
import formatter_exec as adapter
CALLS=[]
class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('ATLAS_FIXTURE_ROOT'));self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve(strict=True);self.out=self.root/'output';self.out.mkdir();self.backend=self.root/'backend';self.backend.write_bytes(b'SYNTHETIC exact provider');self.backend.chmod(0o755);self.scenario='normal';self.records=[];outer=self
        self.args=SimpleNamespace(output=self.out,packet_sha256=hashlib.sha256((subject.ROOT/'SOURCE_PINS.json').read_bytes()).hexdigest());self.admitted=dict(job_identity=dict(SYNTHETIC='fresh job'),observed_profile_sha256='a'*64,providers={});self.context=dict(admitted=self.admitted,SDK_roster=[dict(SYNTHETIC='complete SDK roster')],providers=dict(compiler_backend=subject.physical(self.backend,1e30)),stdlib='/SYNTHETIC/stdlib')
        def check(end):
            if self.scenario=='source-return':raise RuntimeError('SYNTHETIC changed source')
            if self.scenario=='SDK-return':raise RuntimeError('SYNTHETIC changed SDK')
        self.admitted['providers']['compiler_backend']={k:self.context['providers']['compiler_backend'][k] for k in ('path','bytes','sha256')}
        self.context['check']=check
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=0
            def run(s,label,argv,*,cwd,environment,seconds):
                outer.assertEqual(seconds,20);config=json.loads((cwd/'CONFIG.json').read_bytes());outer.assertEqual(config['argv'],[str(outer.backend),'tool','format','--no-color','-']);outer.assertEqual(config['source']['sha256'],subject.FIXTURE_SHA);outer.assertEqual(config['source']['bytes'],9781)
                stdout=b'SYNTHETIC exact formatted source\n';stderr=b''
                if outer.scenario=='empty':stdout=b''
                if outer.scenario=='failure':stderr=b'SYNTHETIC formatter failure\n'
                if outer.scenario=='limit':stdout=b'x'*(subject.STREAM_BYTES+1)
                for channel,raw in [('stdout',stdout),('stderr',stderr)]:(s.output/('formatter.'+channel+'.txt')).write_bytes(raw)
                group=dict(group=1234,status='present' if outer.scenario=='unreturned' else 'absent');s.group_observations=[group];s.writers_confirmed_retired=group['status']=='absent';row=dict(label=label,arguments=list(map(str,argv)),pid=1234,original_group=1234,maximum_seconds=20,elapsed_seconds=.01,exit_code=1 if outer.scenario=='failure' else 0,expected_exit=0,refusal=None,writers_confirmed_retired=s.writers_confirmed_retired,terminal_group_observation=group,stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_sha256=hashlib.sha256(stderr).hexdigest());
                if outer.scenario=='deadline':row.update(refusal='SYNTHETIC body deadline',elapsed_seconds=20.1)
                s.records=[row];subject.write(s.output/'COMMANDS.json',s.records)
                subject.write(s.output/'FORMATTER_EXEC.json',dict(pid=1235 if outer.scenario=='pid' else 1234,process_group=1234,argv=config['argv'],backend=config['backend'],environment=config['environment'],stdin=config['source'],stdin_descriptor=0,profile_sha256=config['profile_sha256'],config_sha256=hashlib.sha256((cwd/'CONFIG.json').read_bytes()).hexdigest(),file_size_limit=[subject.STREAM_BYTES]*2))
                if outer.scenario in ('failure','unreturned'):raise RuntimeError('SYNTHETIC original supervisor refusal')
                if outer.scenario=='raw-return':(s.output/'formatter.stdout.txt').write_bytes(b'changed')
                return stdout.decode(),stderr.decode()
        self.context['driver']=SimpleNamespace(Runner=Runner)
        self.guards=[]
        def guarded(*a,**k):CALLS.append('external');raise AssertionError('Modeled process required')
        for name in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):
            guard=patch(name,side_effect=guarded);guard.start();self.addCleanup(guard.stop)
        self.addCleanup(lambda:self.assertEqual(CALLS,[]))
    def perform(self):
        code=subject.execute(self.args,self.context,time.monotonic());return code,json.loads((self.out/'RESULT.json').read_bytes())
    def test_positive_exact_source_argv_group_and_public_raw_return(self):
        code,v=self.perform();self.assertEqual(code,0);self.assertTrue(v['private_removed']);public=self.root/'public';self.assertTrue(subject.stage(self.out,public,self.args.packet_sha256));self.assertEqual((public/'formatter.stdout.txt').read_bytes(),b'SYNTHETIC exact formatted source\n')
    def test_formatter_failure_retains_exact_raw_and_group(self):
        self.scenario='failure';code,v=self.perform();self.assertEqual(code,2);self.assertTrue(v['writers_confirmed_retired']);self.assertFalse(subject.stage(self.out,self.root/'public',self.args.packet_sha256));self.assertTrue((self.root/'public/formatter.stderr.txt').is_file())
    def test_unreturned_group_preserves_private_and_refuses(self):
        self.scenario='unreturned';code,v=self.perform();self.assertEqual(code,2);self.assertFalse(v['private_removed']);self.assertTrue((self.out/'private').exists())
    def test_body_pid_mismatch_refuses(self):self.scenario='pid';self.assertEqual(self.perform()[0],2)
    def test_raw_hash_change_refuses(self):self.scenario='raw-return';self.assertEqual(self.perform()[0],2)
    def test_source_return_change_refuses(self):self.scenario='source-return';self.assertEqual(self.perform()[0],2)
    def test_SDK_return_change_refuses(self):self.scenario='SDK-return';self.assertEqual(self.perform()[0],2)
    def test_one_byte_over_raw_limit_refuses(self):self.scenario='limit';self.assertEqual(self.perform()[0],2)
    def test_exact_raw_limit_accepts_physical_capture(self):
        p=self.root/'exact';p.write_bytes(b'\0'*subject.STREAM_BYTES);self.assertEqual(subject.physical(p,1e30,subject.STREAM_BYTES)['bytes'],subject.STREAM_BYTES)
    def test_early_raw_capacity_precedes_open(self):
        p=self.root/'over';p.write_bytes(b'\0'*(subject.STREAM_BYTES+1))
        with patch.object(subject.os,'open',side_effect=AssertionError('Unadmitted file opened')),self.assertRaises(RuntimeError):subject.physical(p,1e30,subject.STREAM_BYTES)
    def test_complete_phase_exhaustion_refuses_before_launch(self):
        code=subject.execute(self.args,self.context,time.monotonic()-45);self.assertEqual(code,2);self.assertEqual(json.loads((self.out/'RESULT.json').read_bytes())['actual_formatter_commands'],0)
    def test_changed_external_source_pin_refuses(self):
        with self.assertRaises(RuntimeError):subject.protect('0'*64,1e30)
    def test_hosted_admission_requires_actual_job(self):
        with patch.object(subject.platform,'system',return_value='Linux'),self.assertRaises(RuntimeError):subject.admit(SimpleNamespace(packet_sha256=self.args.packet_sha256),1e30)
    def test_changed_raw_stage_refuses(self):
        self.perform();(self.out/'formatter.stdout.txt').write_bytes(b'changed')
        with self.assertRaises(RuntimeError):subject.stage(self.out,self.root/'public',self.args.packet_sha256)
    def test_private_credential_raw_produces_clean_refusal(self):
        self.perform();secret=('ghp_'+'A'*36).encode();p=self.out/'formatter.stdout.txt';p.write_bytes(secret);v=json.loads((self.out/'RESULT.json').read_bytes());v['commands'][0]['stdout_sha256']=hashlib.sha256(secret).hexdigest();subject.write(self.out/'RESULT.json',v);subject.write(self.out/'COMMANDS.json',v['commands']);self.assertFalse(subject.stage(self.out,self.root/'public',self.args.packet_sha256));self.assertEqual([p.name for p in (self.root/'public').iterdir()],['STAGING_REFUSAL.json'])
    def test_adapter_exact_opened_STDIN_fd0_exec_and_limits(self):
        source=subject.ROOT/'inputs/products/new_broad_hash.cr.txt';v=subject.physical(source,1e30,9781);cfg=dict(backend=subject.physical(self.backend,1e30),source=v,argv=[str(self.backend),'tool','format','--no-color','-'],environment=dict(SYNTHETIC='fixed environment'),stream_bytes=131072,record=str(self.root/'exec.json'),body_deadline=1e30,profile_sha256='a'*64);path=self.root/'config.json';subject.write(path,cfg);calls=[]
        class Replaced(Exception):pass
        def replace(*args):calls.append(args);raise Replaced()
        with patch.object(adapter.resource,'setrlimit') as limit,patch.object(adapter.resource,'getrlimit',return_value=(131072,131072)),patch.object(adapter.os,'dup2') as dup,patch.object(adapter.os,'set_inheritable') as inheritable,patch.object(adapter.os,'execve',side_effect=replace),self.assertRaises(Replaced):adapter.perform(path,hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(calls[0],(str(self.backend),cfg['argv'],cfg['environment']));limit.assert_any_call(resource.RLIMIT_FSIZE,(131072,131072));limit.assert_any_call(resource.RLIMIT_CORE,(0,0));inheritable.assert_called_once_with(0,True);self.assertEqual(json.loads((self.root/'exec.json').read_bytes())['stdin'],v)
    def test_empty_formatter_output_refuses(self):self.scenario='empty';self.assertEqual(self.perform()[0],2)
    def test_original20_second_body_refusal_is_retained(self):self.scenario='deadline';self.assertEqual(self.perform()[0],2)
    def test_original_owned_output_root_refuses_replacement_writes(self):
        subject.own(self.out);self.out.rename(self.root/'original-output');self.out.mkdir()
        with self.assertRaises(RuntimeError):subject.write(self.out/'RESULT.json',dict(passed=True))
        self.assertFalse((self.out/'RESULT.json').exists())
    def test_adapter_changed_opened_STDIN_refuses_before_exec(self):
        source=self.root/'original.txt';source.write_bytes((subject.ROOT/'inputs/products/new_broad_hash.cr.txt').read_bytes());original=subject.physical(source,1e30);source.write_bytes(source.read_bytes()[:-1]+b'X');cfg=dict(backend=subject.physical(self.backend,1e30),source=original,argv=[str(self.backend),'tool','format','--no-color','-'],stream_bytes=131072,body_deadline=1e30);p=self.root/'changed-config';subject.write(p,cfg)
        with patch.object(adapter.os,'execve',side_effect=AssertionError('Changed STDIN executed')),self.assertRaises(RuntimeError):adapter.perform(p,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_adapter_changed_argv_refuses_before_STDIN_open(self):
        cfg=dict(backend=subject.physical(self.backend,1e30),source=dict(path=str(self.root/'missing')),argv=[str(self.backend),'tool','format','--check','-'],stream_bytes=131072,body_deadline=1e30);p=self.root/'argv-config';subject.write(p,cfg)
        with self.assertRaisesRegex(RuntimeError,'argv'):adapter.perform(p,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_adapter_changed_config_refuses_before_exec(self):
        p=self.root/'config';p.write_bytes(b'{}')
        with patch.object(adapter.os,'execve',side_effect=AssertionError('Unadmitted exec')),self.assertRaises(RuntimeError):adapter.perform(p,'0'*64)
    def test_resealed_exec_provider_environment_and_limit_refuse_public_stage(self):
        self.perform();path=self.out/'FORMATTER_EXEC.json';original=path.read_bytes();entry=json.loads(original)
        for index,(key,value) in enumerate([('backend',dict(sha256='0'*64)),('environment',dict(SYNTHETIC='changed')),('file_size_limit',[131073,131073])]):
            with self.subTest(key=key):
                changed=copy.deepcopy(entry);changed[key]=value;subject.write(path,changed)
                with self.assertRaises(RuntimeError):subject.stage(self.out,self.root/('public-resealed-'+str(index)),self.args.packet_sha256)
                subject.write(path,entry)
    def test_post_launch_exception_preserves_existing_partial_result(self):
        self.out.rmdir();self.args.operation='capture';sentinel=dict(actual_formatter_commands=1,groups=[dict(status='present')],passed=False)
        def partial(*a):subject.write(self.out/'RESULT.json',sentinel);raise RuntimeError('SYNTHETIC partial return')
        with patch.object(subject,'admit',return_value=self.context),patch.object(subject,'execute',side_effect=partial),self.assertRaisesRegex(RuntimeError,'partial return'):subject.main(self.args)
        self.assertEqual(json.loads((self.out/'RESULT.json').read_bytes()),sentinel)
    def test_adapter_missing_physical_source_refuses(self):
        p=self.root/'config';cfg=dict(backend=subject.physical(self.backend,1e30),source=dict(path=str(self.root/'missing')),argv=[str(self.backend),'tool','format','--no-color','-'],stream_bytes=131072,body_deadline=1e30);subject.write(p,cfg)
        with self.assertRaises(OSError):adapter.perform(p,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_changed_public_job_identity_refuses(self):
        self.perform();p=self.out/'RESULT.json';original=json.loads(p.read_bytes())
        for index,value in enumerate((dict(SYNTHETIC='different job'),{},None)):
            with self.subTest(value=value):
                changed=copy.deepcopy(original);changed['job_identity']=value;subject.write(p,changed)
                with self.assertRaisesRegex(RuntimeError,'same-job SDK identity'):subject.stage(self.out,self.root/('public-job-'+str(index)),self.args.packet_sha256)
                subject.write(p,original)
        self.assertTrue(subject.stage(self.out,self.root/'public-job-restored',self.args.packet_sha256))
    def test_changed_public_command_count_refuses(self):
        self.perform();p=self.out/'RESULT.json';original=json.loads(p.read_bytes())
        for index,value in enumerate((0,2,True,'1',1.0)):
            with self.subTest(value=value):
                changed=copy.deepcopy(original);changed['actual_formatter_commands']=value;subject.write(p,changed)
                with self.assertRaisesRegex(RuntimeError,'one original public formatter command'):subject.stage(self.out,self.root/('public-count-'+str(index)),self.args.packet_sha256)
                subject.write(p,original)
        self.assertTrue(subject.stage(self.out,self.root/'public-count-restored',self.args.packet_sha256))
    def test_changed_public_stdin_descriptor_refuses(self):
        self.perform();p=self.out/'FORMATTER_EXEC.json';original=json.loads(p.read_bytes())
        for index,value in enumerate((9,False,'0',0.0)):
            with self.subTest(value=value):
                changed=copy.deepcopy(original);changed['stdin_descriptor']=value;subject.write(p,changed)
                with self.assertRaisesRegex(RuntimeError,'STDIN descriptor0'):subject.stage(self.out,self.root/('public-descriptor-'+str(index)),self.args.packet_sha256)
                subject.write(p,original)
        self.assertTrue(subject.stage(self.out,self.root/'public-descriptor-restored',self.args.packet_sha256))

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));print(json.dumps(dict(passed=result.wasSuccessful(),tests=result.testsRun,external_guard_calls=CALLS)));raise SystemExit(0 if result.wasSuccessful() and not CALLS else 1)
