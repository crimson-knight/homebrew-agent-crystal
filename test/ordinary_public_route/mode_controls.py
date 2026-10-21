"""Production-policy physical and guarded security/source/return controls."""
import json
import os
from pathlib import Path
import stat
import types
import unittest
from unittest import mock
import source_modes as modes
import route_support as support
import run_route as route
import prepare_ci_checkout as ci

GUARD_CALLS=[]

class SourceModeControls(unittest.TestCase):
    def setUp(self):
        from test_ci_checkout import CICheckoutControls
        self.case=CICheckoutControls('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        patch=mock.patch.object(modes,'DEFAULT_POLICY',modes.POLICY);patch.start();self.addCleanup(patch.stop)
        self.case.returned_clone();self.target=self.case.alias/'Formula/agent-crystal.rb';self.ordinal=0
    def profile(self,name):
        for row in support.read(route.ROOT/'inputs/ALPHA_FILES.json')['files']:(self.case.alias/row['file']).chmod(modes.PROFILES[row['mode']][name])
    def observe(self):
        self.ordinal+=1;out=self.case.root/('production source metadata '+str(self.ordinal));out.mkdir();return route.tap_source_observation(self.case.alias,out,'before-bottle')
    def row(self,value):return next(v for v in value['files'] if v['file']=='Formula/agent-crystal.rb')
    def accepted_profile(self,name):
        self.profile(name);value=self.observe();self.assertTrue(value['source_admitted']);self.assertTrue(all(v['permission']['profile']==name and v['git_blob_matches'] for v in value['files']));self.assertTrue(all(v['observed_security']['uid']==os.getuid() for v in value['files']));self.assertFalse(support.read(self.case.args.route_output/'BOTTLE_RESULT.json')['passed'])
    def test_production_022_profile_accepts_exact_source(self):self.accepted_profile('022')
    def test_production_002_profile_accepts_exact_source(self):self.accepted_profile('002')
    def test_production_077_profile_accepts_exact_source(self):self.accepted_profile('077')
    def test_002_raw_full_mode_differences_remain_visible(self):
        self.profile('002');value=self.observe();self.assertEqual(sum(r['differences']==['mode'] for r in value['files']),23);self.assertTrue(all(r['admission_differences']==[] for r in value['files']));self.assertEqual(self.row(value)['expected']['mode'],0o644);self.assertEqual(self.row(value)['observed']['mode'],0o664)
    def test_mixed_reviewed_profiles_keep_each_actual_mode(self):
        self.profile('077');self.target.chmod(0o664);value=self.observe();self.assertTrue(value['source_admitted']);self.assertEqual(self.row(value)['permission']['profile'],'002')
    def tracked_profile(self,name):
        for git_mode in ('100644','100755'):
            path=self.case.source/('owned '+git_mode);path.write_bytes(b'SYNTHETIC exact source');path.chmod(modes.PROFILES[git_mode][name]);blob=ci.sha_git(path.read_bytes());rows=ci.tracked_identity(self.case.workspace,git_mode+' blob '+blob+'\ttest/route/'+path.name+'\n');self.assertEqual(rows[0]['permission']['profile'],name);self.assertEqual(rows[0]['mode'],git_mode)
    def test_tracked_022_class_and_blob_accept(self):self.tracked_profile('022')
    def test_tracked_002_class_and_blob_accept(self):self.tracked_profile('002')
    def test_tracked_077_class_and_blob_accept(self):self.tracked_profile('077')
    def test_physical_umask_profiles_create_expected_file_modes(self):
        for mask,name in ((0o022,'022'),(0o002,'002'),(0o077,'077')):
            for git_mode,create_mode in (('100644',0o666),('100755',0o777)):
                path=self.case.root/('creation '+name+' '+git_mode);previous=os.umask(mask)
                try:
                    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,create_mode);os.close(fd)
                finally:os.umask(previous)
                value=modes.observe(path.stat(),git_mode);self.assertTrue(value['accepted']);self.assertEqual(value['profile'],name)
    def test_current_default_is_production_policy(self):self.assertEqual(modes.DEFAULT_POLICY,modes.POLICY)
    def test_unknown_policy_refuses(self):
        with mock.patch.object(modes,'DEFAULT_POLICY','unreviewed'),self.assertRaises(RuntimeError):modes.observe(self.target.stat(),'100644')
    def test_unknown_Git_mode_refuses(self):
        with self.assertRaises(RuntimeError):modes.observe(self.target.stat(),'120000')
    def test_regular_source_with_added_execute_bit_refuses(self):
        self.target.chmod(0o755);value=self.observe();self.assertFalse(value['source_admitted']);self.assertIn('permission',self.row(value)['admission_differences'])
    def test_executable_source_with_removed_execute_bit_refuses(self):
        (self.case.alias/'install.sh').chmod(0o644);self.assertFalse(self.observe()['source_admitted'])
    def test_world_writable_modes_refuse(self):
        for mode in (0o666,0o777):self.target.chmod(mode);self.assertFalse(self.observe()['source_admitted'])
    def test_special_permission_bits_refuse(self):
        for mode in (0o4644,0o2644,0o1644):self.target.chmod(mode);self.assertFalse(self.observe()['source_admitted'])
    def test_unreviewed_read_write_profile_refuses(self):
        self.target.chmod(0o640);self.assertFalse(self.observe()['source_admitted'])
    def test_owner_write_permission_required(self):
        self.target.chmod(0o444);self.assertFalse(self.observe()['source_admitted'])
    def test_other_owner_is_observed_and_refused(self):
        with mock.patch.object(modes.os,'getuid',return_value=os.getuid()+1):
            value=self.observe();self.assertFalse(value['source_admitted']);self.assertIn('current-user-ownership',self.row(value)['permission']['refusals']);self.assertNotEqual(self.row(value)['observed_security']['uid'],self.row(value)['observed_security']['current_uid'])
    def test_group_write_requires_current_group_membership(self):
        self.target.chmod(0o664);info=self.target.stat();wrong=types.SimpleNamespace(st_mode=info.st_mode,st_uid=info.st_uid,st_gid=max([os.getgid(),*os.getgroups()])+1,st_nlink=1);value=modes.observe(wrong,'100644');self.assertFalse(value['accepted']);self.assertIn('current-user-group-membership-for-group-write',value['refusals'])
    def test_hardlinked_source_refuses(self):
        os.link(self.target,self.case.root/'outside source link');value=self.observe();self.assertFalse(value['source_admitted']);self.assertEqual(self.row(value)['observed_security']['link_count'],2)
    def test_source_symlink_refuses(self):
        self.target.unlink();self.target.symlink_to(self.case.source/'fixture.py');self.assertFalse(self.observe()['source_admitted'])
    def test_source_directory_refuses(self):
        self.target.unlink();self.target.mkdir();self.assertFalse(self.observe()['source_admitted'])
    def test_source_FIFO_refuses_before_open(self):
        self.target.unlink();os.mkfifo(self.target);value=self.observe();self.assertFalse(value['source_admitted']);self.assertEqual(self.row(value)['observed']['kind'],'special')
    def test_same_size_changed_source_hash_and_blob_refuse(self):
        raw=self.target.read_bytes();self.target.write_bytes(bytes([raw[0]^1])+raw[1:]);value=self.observe();row=self.row(value);self.assertFalse(value['source_admitted']);self.assertEqual(row['differences'],['sha256']);self.assertIn('git_blob',row['admission_differences'])
    def test_changed_source_size_refuses(self):
        self.target.write_bytes(b'SYNTHETIC changed source');value=self.observe();self.assertFalse(value['source_admitted']);self.assertIn('bytes',self.row(value)['differences'])
    def test_missing_source_refuses(self):
        self.target.unlink();self.assertFalse(self.observe()['source_admitted'])
    def test_permission_identity_change_during_read_refuses(self):
        original=route.stable
        def changed(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==self.target:path.chmod(0o664)
            return value
        with mock.patch.object(route,'stable',side_effect=changed):value=self.observe()
        self.assertFalse(value['source_admitted']);self.assertIn('identity',self.row(value)['error'])
    def test_actual_readback_accepts_002_source_with_exact_Git_identity(self):
        self.profile('002');out=self.case.root/'readback';out.mkdir();runner=self.case.driver.Runner(out);value=route.tap_readback(runner,self.case.providers,out,{},'ci-public');self.assertTrue(value['working_tree_source_accepted']);self.assertEqual(value['commit'],route.ALPHA);self.assertEqual(len(runner.records),3)
    def test_readback_return_detects_drift_between_two_compatible_modes(self):
        self.profile('002');out=self.case.root/'readback before';out.mkdir();before=route.tap_readback(self.case.driver.Runner(out),self.case.providers,out,{},'ci-public');self.target.chmod(0o644);out=self.case.root/'readback after';out.mkdir();after=route.tap_readback(self.case.driver.Runner(out),self.case.providers,out,{},'ci-public');self.assertTrue(before['working_tree_source_accepted'] and after['working_tree_source_accepted']);self.assertNotEqual(before,after);row=next(r for r in before['actual_source_files'] if r['file']=='Formula/agent-crystal.rb');self.assertEqual(row['observed']['mode'],0o664);self.assertEqual(row['security']['uid'],os.getuid())
    def restore_profile(self,name):
        self.profile(name);before=ci.tree_identity(self.case.alias);code,result=self.case.restore();self.assertEqual(code,0);self.assertTrue(result['preserved_clone_dependency_source_accepted']);self.assertFalse(result['actual_default_route_accepted']);self.assertEqual(ci.tree_identity(self.case.args.output/'preserved-public-tap'),before);self.assertTrue(self.case.alias.is_symlink())
    def test_actual_restore_accepts_002_and_preserves_full_modes(self):self.restore_profile('002')
    def test_actual_restore_accepts_077_and_preserves_full_modes(self):self.restore_profile('077')
    def test_compatible_modes_keep_unreturned_writer_refusal(self):
        self.profile('002');support.write(self.case.args.route_output/'BOTTLE_RESULT.json',{'writers_confirmed_retired':False});code,result=self.case.restore();self.assertEqual(code,2);self.assertFalse(self.case.alias.is_symlink());self.assertFalse((self.case.args.output/'preserved-public-tap').exists())
    def test_compatible_modes_keep_changed_provider_refusal(self):
        self.profile('002');Path(self.case.providers['brew']['path']).write_bytes(b'SYNTHETIC provider drift');code,result=self.case.restore();self.assertEqual(code,2);self.assertTrue(result['finalization_errors'])
    def test_current_checkout_compatible_mode_drift_still_refuses_return(self):
        (self.case.source/'fixture.py').chmod(0o664);code,result=self.case.restore();self.assertEqual(code,2);self.assertFalse(self.case.alias.is_symlink())
