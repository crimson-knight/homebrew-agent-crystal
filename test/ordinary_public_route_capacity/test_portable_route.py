"""Original bulk/chunked parser assertions plus guarded portable-route behavior."""
import contextlib,hashlib,importlib.util,io,json,os,shutil,stat,sys,tarfile,tempfile,time,types,unittest,runpy
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import test_archive_capacity as original
ROUTE=original.ARGS.source_root.resolve(strict=True);sys.path.insert(0,str(ROUTE))
import route_support as support,run_route as route,hosted_entry as hosted,prepare_ci_checkout as ci,stage_results as stage
import test_ci_checkout as old_ci
screen=original.screen
upstream=ROOT/'tarfile.cpython-3.15.0.py.txt'
if hashlib.sha256(upstream.read_bytes()).hexdigest()!='0b443116a6f406012ebe06455bb472d659fee6e402e0f0ed44b2da8b33de8d61':raise RuntimeError('Exact upstream CPython3.15.0 parser source required')
text=upstream.read_text();safe_source=text[text.index('def _safe_read('):text.index('def _safe_print(')];space={'_EXTHEADER_READ_CHUNK':1048576};exec(compile(safe_source,str(upstream),'exec'),space);safe_read=space['_safe_read']
GUARDS=[]
class ChunkedOriginalControls(original.ArchiveCapacityControls):
    def setUp(self):
        super().setUp();actual=screen.MetadataAllowanceReader.read
        def chunked(stream,size=-1):return safe_read(stream,size) if size>1048576 else actual(stream,size)
        self.guards.enter_context(mock.patch.object(screen.MetadataAllowanceReader,'read',chunked))

class PortableControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='portable ordinary controls ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        def guard(*a,**k):GUARDS.append('external');raise AssertionError('Guarded authored metadata provider required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.stack.enter_context(mock.patch(target,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(GUARDS,[]))
    def brew(self):
        prefix=self.root/'normal prefix';physical=prefix/'Homebrew/bin/brew';physical.parent.mkdir(parents=True);physical.write_bytes(b'SYNTHETIC pinned brew provider');physical.chmod(0o755);lexical=prefix/'bin/brew';lexical.parent.mkdir();lexical.symlink_to('../Homebrew/bin/brew');return lexical,physical
    def test_lexical_brew_and_physical_body_are_separate(self):
        lexical,physical=self.brew();value=support.observe_invocation(lexical);self.assertEqual(value['lexical'],str(lexical));self.assertEqual(value['physical'],support.stable(physical)[0]);self.assertEqual(value['aliases'][0]['target'],'../Homebrew/bin/brew');support.verify_invocation(value)
    def test_lexical_alias_replacement_with_same_target_refuses(self):
        lexical,_=self.brew();v=support.observe_invocation(lexical);lexical.unlink();lexical.symlink_to('../Homebrew/bin/brew')
        with self.assertRaisesRegex(RuntimeError,'provider return'):support.verify_invocation(v)
    def test_changed_alias_target_refuses(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);other=physical.with_name('other');other.write_bytes(physical.read_bytes());lexical.unlink();lexical.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError,'provider return'):support.verify_invocation(v)
    def test_missing_alias_refuses(self):
        lexical,_=self.brew();v=support.observe_invocation(lexical);lexical.unlink()
        with self.assertRaises(FileNotFoundError):support.verify_invocation(v)
    def test_same_byte_physical_replacement_refuses(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);raw=physical.read_bytes();physical.unlink();physical.write_bytes(raw);physical.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'provider return'):support.verify_invocation(v)
    def test_changed_physical_body_refuses(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);physical.write_bytes(b'SYNTHETIC changed body')
        with self.assertRaisesRegex(RuntimeError,'provider return'):support.verify_invocation(v)
    def test_physical_permission_change_refuses(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);physical.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,'provider return'):support.verify_invocation(v)
    def test_cycle_alias_refuses_with_finite_chain(self):
        lexical,_=self.brew();lexical.unlink();lexical.symlink_to('brew')
        with self.assertRaisesRegex(RuntimeError,'Finite complete provider alias chain'):support.observe_invocation(lexical)
    def test_hosted_provider_arguments_keep_lexical_brew(self):
        lexical,physical=self.brew()
        with mock.patch.object(hosted.sys,'platform','linux'),mock.patch.object(hosted.sys,'executable',str(physical)):argv,rows=hosted.provider_arguments({},which=lambda name:str(lexical if name=='brew' else physical))
        self.assertEqual(len(argv),20);self.assertEqual(argv[1],str(lexical));self.assertEqual(rows['brew']['path'],str(physical));self.assertEqual(rows['brew']['invocation'],support.observe_invocation(lexical))
    def model_runner(self,prefix,repository):
        outer=self
        class Runner:
            records=[];deadline=time.monotonic()+120
            def run(inner,label,argv,**kw):
                outer.seen.append((label,argv));inner.records.append({'maximum_seconds':kw['seconds']})
                return (str(prefix) if argv[-1]=='--prefix' else str(repository))+'\n',''
        return Runner()
    def test_literal_stage_and_complete_gate_retain_invocation_metadata(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);source=self.root/'route-result';source.mkdir();destination=self.root/'public-stage';support.write(source/'OBSERVATION_RESULT.json',{'passed':False,'writers_confirmed_retired':True,'original_groups':[]});support.write(source/'HOMEBREW_INVOCATION.json',{'invocation':v,'accepted':True});packet=support.stable(ROUTE/'SOURCE_PINS.json')[0]['sha256']
        for args in (["--source",str(source),"--output",str(destination),"--retain-clean-refusals"],["--source",str(destination),"--require-complete"]):
            with mock.patch.object(sys,'argv',[str(ROUTE/'launch.py'),'--entrypoint','stage_results.py','--packet-sha256',packet,*args]):runpy.run_path(str(ROUTE/'launch.py'),run_name='__main__')
        self.assertEqual(support.read(destination/'HOMEBREW_INVOCATION.json')['invocation'],v);self.assertTrue(support.read(destination/'PUBLIC_STAGE.json')['screening_complete'])
    def selected_context(self,physical_change=False,hash_change=False):
        lexical,physical=self.brew();raw=physical.read_bytes();row=support.stable(physical)[0];normal='/home/linuxbrew/.linuxbrew/bin/brew';selected='/home/linuxbrew/.linuxbrew/'+('other' if physical_change else 'Homebrew')+'/bin/brew';base=Path.resolve;actual_stable=support.stable;python=Path(sys.executable).resolve();args=types.SimpleNamespace(packet_sha256='fixture',brew=Path(normal),brew_sha256='0'*64 if hash_change else row['sha256'],python=python,python_sha256=support.stable(python)[0]['sha256'])
        for tool in ('git','curl','bash'):setattr(args,tool,physical);setattr(args,tool+'_sha256',row['sha256'])
        def resolve(path,*a,**k):return Path(selected) if str(path)==normal else base(path,*a,**k)
        def stable(path,*a,**k):return ({**row,'path':selected},raw) if str(path)==selected else actual_stable(path,*a,**k)
        descriptor={'lexical':normal,'physical':{**row,'path':selected},'physical_identity':ci.node_identity(physical),'aliases':[],'directories':[]}
        with mock.patch.dict(os.environ,GITHUB_ACTIONS='true'),mock.patch.object(route.platform,'system',return_value='Linux'),mock.patch.object(route.platform,'machine',return_value='x86_64'),mock.patch.object(route,'source_packet',return_value={}),mock.patch.object(route,'load_driver',return_value='modeled driver'),mock.patch.object(Path,'resolve',resolve),mock.patch.object(route,'stable',side_effect=stable),mock.patch.object(support,'observe_invocation',return_value=descriptor):return route.get_context(args)
    def test_actual_hosted_context_requires_and_retains_normal_invocation(self):
        driver,protected,providers=self.selected_context();self.assertEqual(driver,'modeled driver');self.assertEqual(providers['brew']['invocation']['lexical'],'/home/linuxbrew/.linuxbrew/bin/brew');self.assertEqual(len(protected.invocations),1)
    def test_actual_hosted_context_refuses_different_physical_repository(self):
        with self.assertRaisesRegex(RuntimeError,'physical relationship'):self.selected_context(physical_change=True)
    def test_actual_hosted_context_refuses_changed_physical_provider_hash(self):
        with self.assertRaisesRegex(RuntimeError,'Exact observed provider SHA'):self.selected_context(hash_change=True)
    def test_actual_command_invokes_lexical_alias(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);providers={'brew':{**v['physical'],'invocation':v}};self.seen=[];runner=self.model_runner(lexical.parent.parent,physical.parent.parent)
        route.run_command(runner,providers,'homebrew-version','brew',['--version'],self.root,{},30);self.assertEqual(self.seen[0][1][0],str(lexical));self.assertNotEqual(self.seen[0][1][0],str(physical))
    def test_changed_alias_refuses_before_command(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);providers={'brew':{**v['physical'],'invocation':v}};self.seen=[];runner=self.model_runner('', '');lexical.unlink()
        with self.assertRaises(FileNotFoundError):route.run_command(runner,providers,'homebrew-version','brew',[],self.root,{},30)
        self.assertEqual(self.seen,[])
    def test_normal_prefix_repository_preflight_retains_outputs(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);p={'brew':{**v['physical'],'invocation':v}};self.seen=[];out=self.root/'out';out.mkdir();value=route.homebrew_layout(self.model_runner(lexical.parent.parent,physical.parent.parent),p,out,{})
        self.assertTrue(value['accepted']);self.assertEqual(support.read(out/'HOMEBREW_INVOCATION.json'),value);self.assertEqual([x[0] for x in self.seen],['homebrew-invocation-prefix','homebrew-invocation-repository'])
    def test_physical_prefix_regression_refuses_before_build(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);p={'brew':{**v['physical'],'invocation':v}};self.seen=[];out=self.root/'out';out.mkdir()
        with self.assertRaisesRegex(RuntimeError,'normal Homebrew prefix'):route.homebrew_layout(self.model_runner(physical.parent.parent,physical.parent.parent),p,out,{})
        self.assertFalse(support.read(out/'HOMEBREW_INVOCATION.json')['accepted'])
    def test_changed_repository_refuses_preflight(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);p={'brew':{**v['physical'],'invocation':v}};self.seen=[];out=self.root/'out';out.mkdir()
        with self.assertRaisesRegex(RuntimeError,'normal Homebrew prefix'):route.homebrew_layout(self.model_runner(lexical.parent.parent,self.root/'different'),p,out,{})
    def test_protected_alias_return_survives_physical_hash_equality(self):
        lexical,physical=self.brew();v=support.observe_invocation(lexical);protected=support.ProviderProtection({str(physical):v['physical']['sha256']},[v]);support.revalidate(protected);lexical.unlink()
        with self.assertRaises(FileNotFoundError):support.revalidate(protected)
    def clone(self):
        root=self.root/'clone';(root/'.git/objects/pack').mkdir(parents=True);(root/'source.txt').write_bytes(b'SYNTHETIC tracked source');return root
    def test_Git_pack_above_8_MiB_streams_and_preserves_complete_hash(self):
        root=self.clone();p=root/'.git/objects/pack/public.pack';raw=b'0'*(8*2**20+1);p.write_bytes(raw);value=ci.tree_identity(root);file=next(v for v in value['files'] if v['path'].endswith('public.pack'));self.assertEqual(file['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(value['Git_storage_bytes'],len(raw));self.assertEqual(file['identity'],ci.node_identity(p));self.assertEqual(ci.tree_identity(root),value)
    def test_tracked_file_above_8_MiB_keeps_original_refusal(self):
        root=self.clone();(root/'source.txt').write_bytes(b'0'*(8*2**20+1))
        with self.assertRaisesRegex(RuntimeError,'Bounded ordinary file'):ci.tree_identity(root)
    def test_Git_single_file_capacity_refuses_before_open(self):
        root=self.clone();p=root/'.git/public';p.write_bytes(b'a');actual=p.lstat();fake=types.SimpleNamespace(**{k:getattr(actual,k) for k in ('st_dev','st_ino','st_mode','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_nlink')},st_size=ci.GIT_STORAGE_FILE_BYTES+1)
        with mock.patch.object(Path,'lstat',return_value=fake),mock.patch.object(ci.os,'open') as opening,self.assertRaisesRegex(RuntimeError,'before opening'):ci.streamed_storage(p,ci.GIT_STORAGE_FILE_BYTES,time.monotonic()+10)
        self.assertEqual(opening.call_count,0)
    def test_production_Git_and_tracked_capacity_values_remain_distinct(self):
        self.assertEqual((ci.GIT_STORAGE_FILE_BYTES,ci.GIT_STORAGE_TOTAL_BYTES,ci.GIT_STORAGE_FILES,ci.TREE_ENTRIES,ci.GIT_READ_CHUNK),(536870912,2147483648,4096,8192,1048576));self.assertEqual((ci.MAX_BYTES,ci.MAX_FILES,ci.SECONDS),(67108864,512,300));self.assertEqual(sum(ci.RestorationBudget.CAPS.values()),300)
    def test_Git_total_capacity_refuses_before_next_file_read(self):
        root=self.clone();(root/'.git/a').write_bytes(b'12');(root/'.git/b').write_bytes(b'34')
        with mock.patch.object(ci,'GIT_STORAGE_TOTAL_BYTES',3),self.assertRaisesRegex(RuntimeError,'before opening'):ci.tree_identity(root)
    def test_Git_file_count_capacity_refuses(self):
        root=self.clone();(root/'.git/a').write_bytes(b'');(root/'.git/b').write_bytes(b'')
        with mock.patch.object(ci,'GIT_STORAGE_FILES',1),self.assertRaisesRegex(RuntimeError,'before opening'):ci.tree_identity(root)
    def test_complete_entry_capacity_refuses_before_insertion(self):
        root=self.clone()
        with mock.patch.object(ci,'TREE_ENTRIES',2),self.assertRaisesRegex(RuntimeError,'before insertion'):ci.tree_identity(root)
    def test_Git_symlink_refuses(self):
        root=self.clone();(root/'.git/alias').symlink_to(root/'source.txt')
        with self.assertRaisesRegex(RuntimeError,'regular Git storage'):ci.tree_identity(root)
    def test_Git_unsafe_mode_refuses(self):
        root=self.clone();p=root/'.git/public';p.write_bytes(b'a');p.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'safe Git storage'):ci.tree_identity(root)
    def test_expired_Git_census_refuses_before_read(self):
        root=self.clone();p=root/'.git/public';p.write_bytes(b'a')
        with self.assertRaisesRegex(RuntimeError,'deadline required before opening'):ci.streamed_storage(p,ci.GIT_STORAGE_FILE_BYTES,time.monotonic()-1)
    def test_ownership_identity_refuses_physical_replacement(self):
        root=self.clone();p=root/'.git/public';p.write_bytes(b'a');actual=ci.os.fstat
        def changed(fd):v=actual(fd);return types.SimpleNamespace(**{k:getattr(v,k) for k in ('st_dev','st_mode','st_size','st_mtime_ns','st_ctime_ns')},st_ino=v.st_ino+1)
        with mock.patch.object(ci.os,'fstat',side_effect=changed),self.assertRaisesRegex(RuntimeError,'opened Git storage'):ci.streamed_storage(p,ci.GIT_STORAGE_FILE_BYTES,time.monotonic()+10)
    def test_parser_cache_keeps_public_seek_tell_and_whole_extension_read(self):
        case=original.ArchiveCapacityControls();raw=case.extension(1049089)+case.header()+b'\0'*1024;tracked=original.ReadObservation(raw);reader=screen.MetadataAllowanceReader(tracked);self.assertEqual(reader.read(512),raw[:512]);self.assertEqual([(x['start'],x['requested']) for x in tracked.reads],[(0,512),(512,1049600)]);self.assertEqual(reader.tell(),512);self.assertEqual(safe_read(reader,1049600),raw[512:1050112]);reader.seek(600);self.assertEqual(reader.read(10),raw[600:610]);self.assertEqual(len(tracked.reads),2)
    def test_unknown_partial_header_request_refuses(self):
        reader=screen.MetadataAllowanceReader(io.BytesIO(b'0'*1024))
        with self.assertRaisesRegex(RuntimeError,'complete standard parser header'):reader.read(1)
    def test_sparse_header_refuses_before_extension_read(self):
        header=original.ArchiveCapacityControls().header(kind=tarfile.GNUTYPE_SPARSE);tracked=original.ReadObservation(header+b'\0'*1024);reader=screen.MetadataAllowanceReader(tracked)
        with self.assertRaisesRegex(RuntimeError,'nonsparse'):reader.read(512)
        self.assertEqual([(x['start'],x['requested']) for x in tracked.reads],[(0,512)])
    def test_malformed_header_refuses_at_standard_header_parser(self):
        tracked=original.ReadObservation(b'x'*512+b'\0'*1024);reader=screen.MetadataAllowanceReader(tracked)
        with self.assertRaises(tarfile.HeaderError):reader.read(512)
    def test_phase_deadline_refuses_and_restores_original_context(self):
        now=[0.0];runner=types.SimpleNamespace(deadline=300)
        with mock.patch.object(ci.time,'monotonic',side_effect=lambda:now[0]):
            budget=ci.RestorationBudget(runner,0)
            with self.assertRaisesRegex(RuntimeError,'phase deadline'):
                with budget.phase('checkout-before'):now[0]=41
        self.assertEqual(runner.deadline,300);self.assertEqual(ci._RESTORE_PHASE_DEADLINE,float('inf'));self.assertEqual(budget.records[0]['status'],'refused')
    def test_mutation_requires_all_remaining_return_capacity(self):
        budget=ci.RestorationBudget(types.SimpleNamespace(deadline=300),0)
        with mock.patch.object(ci.time,'monotonic',return_value=1),self.assertRaisesRegex(RuntimeError,'following restoration phases'):budget.admit_mutation()

class PortableRestorationControls(unittest.TestCase):
    def setUp(self):
        self.case=old_ci.CICheckoutControls('test_ordinary_public_clone_is_preserved_and_CI_link_restored');self.case.setUp();self.addCleanup(self.case.doCleanups)
    def test_actual_restore_preserves_large_Git_pack_and_safe_stage(self):
        c=self.case;c.returned_clone();pack=c.alias/'.git/objects/pack/public.pack';pack.parent.mkdir(parents=True);raw=b'0'*(8*2**20+1);pack.write_bytes(raw);before=ci.tree_identity(c.alias);code,result=c.restore();self.assertEqual(code,0);self.assertTrue(result['public_clone_preserved']);self.assertTrue(result['CI_checkout_link_restored']);self.assertEqual(ci.tree_identity(c.args.output/'preserved-public-tap'),before);self.assertEqual(result['restoration_phase_budget']['maximum_seconds'],300)
        c.args.stage=c.root/'positive stage';c.args.packet_sha256=support.stable(ROUTE/'SOURCE_PINS.json')[0]['sha256']
        with mock.patch.object(sys,'argv',[str(ROUTE/'launch.py'),'--entrypoint','prepare_ci_checkout.py','--packet-sha256',c.args.packet_sha256,'--mode','stage','--output',str(c.args.output),'--stage',str(c.args.stage)]):runpy.run_path(str(ROUTE/'launch.py'),run_name='__main__')
        self.assertFalse(support.read(c.args.stage/'PUBLIC_STAGE.json')['preserved_public_clone_uploaded']);self.assertTrue((c.args.stage/'PUBLIC_CLONE_AFTER_RESTORATION.json').is_file())
    def test_changed_Git_pack_after_rename_refuses_original_identity(self):
        c=self.case;c.returned_clone();pack=c.alias/'.git/public.pack';pack.write_bytes(b'original');rename=Path.rename
        def changed(path,target):v=rename(path,target);(target/'.git/public.pack').write_bytes(b'changed');return v
        with mock.patch.object(Path,'rename',changed):code,value=c.restore()
        self.assertEqual(code,2);self.assertFalse(value['CI_checkout_link_restored']);self.assertTrue((c.args.output/'preserved-public-tap').is_dir())
    def test_unreturned_writer_refuses_before_large_clone_preservation(self):
        c=self.case;c.returned_clone();support.write(c.args.route_output/'BOTTLE_RESULT.json',{'writers_confirmed_retired':False});code,value=c.restore();self.assertEqual(code,2);self.assertTrue(c.alias.is_dir());self.assertFalse((c.args.output/'preserved-public-tap').exists())
    def test_full_return_deadline_refuses_before_clone_rename(self):
        c=self.case;c.returned_clone();actual=ci.tree_identity;now=[time.monotonic()]
        def late(path):value=actual(path);now[0]+=301;return value
        with mock.patch.object(ci.time,'monotonic',side_effect=lambda:now[0]),mock.patch.object(ci,'tree_identity',side_effect=late):code,value=c.restore()
        self.assertEqual(code,2);self.assertTrue(c.alias.is_dir());self.assertFalse((c.args.output/'preserved-public-tap').exists());self.assertTrue(value['finalization_errors'])

if __name__=='__main__':
    classes=(ChunkedOriginalControls,) if original.ARGS.case==['chunked-original'] else (original.ArchiveCapacityControls,ChunkedOriginalControls,PortableControls,PortableRestorationControls)
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(k) for k in classes])
    result=unittest.TextTestRunner(verbosity=2).run(suite);guards=GUARDS+original.GUARD_CALLS+old_ci.GUARD_CALLS
    print(json.dumps({'tests_run':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skips':len(result.skipped),'actual_guard_calls':len(guards),'original_bulk_cases':14,'original_chunked_cases':14,'source_model_only':True},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() and not guards else 2)
