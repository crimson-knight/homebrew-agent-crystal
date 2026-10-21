"""Guarded CI checkout and separately attributable public-clone restoration controls."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import route_support as support
import prepare_ci_checkout as ci
import run_route as route
GUARD_CALLS=[]

class CICheckoutControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='owned CI checkout controls with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guard(*a,**k):GUARD_CALLS.append('external');raise AssertionError('Authored source fixture process provider required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.guards.enter_context(mock.patch(target,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(GUARD_CALLS,[]))
        self.workspace=self.root/'CI workspace';self.workspace.mkdir();(self.workspace/'.git').mkdir();(self.workspace/'.git/config').write_text('SYNTHETIC authored Git metadata')
        self.source=self.workspace/'test/route';self.source.mkdir(parents=True);(self.source/'fixture.py').write_text('SYNTHETIC current-job reviewed source\n')
        self.listing='100644 blob '+ci.sha_git((self.source/'fixture.py').read_bytes())+'\ttest/route/fixture.py\n'
        self.commit='b89270770bfb38e8f1820ebd202b61bec43a2c9c';self.tree='3d0dfc01688c9df5b3927c32b2c44f01efc66637'
        self.brew=self.root/'Homebrew';self.alias=self.brew/'Library/Taps/crimson-knight/homebrew-agent-crystal';self.alias.parent.mkdir(parents=True);self.alias.symlink_to(self.workspace,target_is_directory=True)
        self.providers={}
        for name in ('brew','git','curl','bash','python'):
            path=self.root/('provider-'+name);path.write_text('SYNTHETIC pinned '+name);self.providers[name]=support.stable(path)[0]
        self.protected={row['path']:row['sha256'] for row in self.providers.values()}
        self.args=types.SimpleNamespace(output=self.root/'CI evidence',setup_tap_name=ci.TAP,setup_repository_path=str(self.alias),route_output=self.root/'returned route')
        self.args.route_step_outcomes=json.dumps({'bottle':'skipped'})
        self.scenario='normal';outer=self
        class Runner:
            def __init__(s,output):s.output=output;s.records=[];s.group_observations=[];s.writers_confirmed_retired=True;s.deadline=time.monotonic()+ci.SECONDS
            def run(s,label,argv,*,cwd,environment,seconds,expected_exit=0):
                outer.assertEqual(seconds,support.command_maximum(label));stdout='';stderr='';code=expected_exit
                if label.startswith('ci-formula-absence'):
                    if outer.scenario=='installed-formula':stdout='agent-crystal 1.21.0\n';code=0
                elif label=='ci-brew-root':stdout=str(outer.brew)+'\n'
                elif label=='ci-tap-location':stdout=str(outer.alias)+'\n'
                elif label.startswith('ci-checkout-'):stdout=str(outer.workspace)+'\n'+outer.commit+'\n'+outer.tree+'\n'
                elif label.startswith('ci-tree-'):stdout=outer.listing
                if label=='ci-checkout-origin':stdout='https://github.com/'+ci.REPOSITORY+'.git\n'
                if label=='ci-untap-owned-checkout':
                    outer.assertEqual(argv[1:],['untap',ci.TAP])
                    if outer.scenario!='failed-untap' and outer.scenario!='leftover-alias':outer.alias.unlink()
                    if outer.scenario=='failed-untap':code=1;stderr='SYNTHETIC ordinary untap refusal'
                    if outer.scenario=='source-change':(outer.source/'fixture.py').write_text('SYNTHETIC altered source')
                    if outer.scenario=='source-removal':shutil.rmtree(outer.workspace)
                    if outer.scenario=='provider-change':Path(outer.providers['brew']['path']).write_text('SYNTHETIC changed provider')
                if label=='ci-public-tap-root':stdout=str(outer.alias)+'\n'
                if label=='ci-public-tap-commit':stdout=route.ALPHA+'\n'+support.read(ROOT/'inputs/ALPHA_MAIN.json')['exact_tree']+'\n'
                if label=='ci-public-tap-origin':stdout='https://github.com/'+ci.REPOSITORY+'.git\n'
                if label=='ci-preserved-source':stdout=route.ALPHA+'\n'+support.read(ROOT/'inputs/ALPHA_MAIN.json')['exact_tree']+'\n'
                if label=='ci-preserved-origin':stdout='https://github.com/'+ci.REPOSITORY+'.git\n'
                for stream,text in [('stdout',stdout),('stderr',stderr)]:(s.output/(label+'.'+stream+'.txt')).write_text(text)
                group={'group':321,'status':'absent'};s.group_observations.append(group)
                s.records.append({'label':label,'arguments':list(map(str,argv)),'expected_exit':expected_exit,'exit_code':code,'pid':321,'original_group':321,'maximum_seconds':seconds,'elapsed_seconds':.01,'refusal':None,'writers_confirmed_retired':True,'terminal_group_observation':group,'stdout_sha256':support.sha(stdout.encode()),'stderr_sha256':support.sha(stderr.encode())});support.write(s.output/'COMMANDS.json',s.records)
                if code!=expected_exit:raise RuntimeError('SYNTHETIC expected command return refused: '+label)
                return stdout,stderr
        self.driver=types.SimpleNamespace(Runner=Runner)
        self.guards.enter_context(mock.patch.object(ci,'ROOT',self.source))
        self.guards.enter_context(mock.patch('pathlib.Path.cwd',return_value=self.workspace))
        self.guards.enter_context(mock.patch('shutil.which',return_value=None))
        self.environment={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':ci.REPOSITORY,'GITHUB_RUN_ID':'12345','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':self.commit,'GITHUB_WORKSPACE':str(self.workspace)}
        self.guards.enter_context(mock.patch.dict(os.environ,self.environment,clear=True))
    def detach(self):
        code=ci.detach(self.args,self.driver,self.protected,self.providers);return code,support.read(self.args.output/'CI_PREPARATION_RESULT.json')
    def returned_clone(self):
        self.assertEqual(self.detach()[0],0);self.alias.mkdir()
        with tarfile.open(ROOT/'inputs/public-alpha-main.tar.gz','r:gz') as stream:
            for member in stream:
                if member.isfile():
                    p=self.alias/member.name.split('/',1)[1];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(stream.extractfile(member).read());p.chmod(0o755 if member.mode&0o111 else 0o644)
        (self.alias/'.git').mkdir();(self.alias/'.git/config').write_text('SYNTHETIC public clone metadata')
        self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'})
    def returned_phase(self,name,directory,groups=None):
        directory.mkdir(parents=True,exist_ok=True)
        group={'group':123,'status':'absent'}
        for channel in ('stdout','stderr'):(directory/('homebrew-version.'+channel+'.txt')).write_bytes(b'')
        command={'label':'homebrew-version','pid':123,'original_group':123,'expected_exit':0,'exit_code':0,
            'maximum_seconds':30,'elapsed_seconds':.01,'refusal':None,'writers_confirmed_retired':True,
            'terminal_group_observation':group,'stdout_sha256':support.sha(b''),'stderr_sha256':support.sha(b'')}
        support.write(directory/'COMMANDS.json',[command])
        support.write(self.args.route_output/name,{'passed':False,'writers_confirmed_retired':True,
            'original_groups':[group] if groups is None else groups})
    def restore(self):
        code=ci.restore(self.args,self.driver,self.protected,self.providers);return code,support.read(self.args.output/'CI_RESTORATION_RESULT.json')
    def test_owned_checkout_link_detaches_with_original_source_surviving(self):
        code,r=self.detach();self.assertEqual(code,0);self.assertTrue(r['checkout_alias_detached']);self.assertFalse(self.alias.exists());self.assertTrue(self.source.is_dir());self.assertEqual(support.read(self.args.output/'CI_CHECKOUT_BEFORE.json'),support.read(self.args.output/'CI_CHECKOUT_AFTER.json'))
    def test_ordinary_public_clone_is_preserved_and_CI_link_restored(self):
        self.returned_clone();before=ci.tree_identity(self.alias);code,r=self.restore();self.assertEqual(code,0);self.assertTrue(r['public_clone_preserved']);self.assertTrue(r['CI_checkout_link_restored']);self.assertEqual(self.alias.resolve(),self.workspace);self.assertEqual(ci.tree_identity(self.args.output/'preserved-public-tap'),before);self.assertFalse(r['default_route_returns'][0]['passed'])
    def test_detached_link_without_public_clone_restores_after_early_route_failure(self):
        self.detach();code,r=self.restore();self.assertEqual(code,0);self.assertFalse(r['public_clone_preserved']);self.assertIn('did not create',r['restoration_scope'])
    def test_failed_untap_retains_original_link_and_idempotent_restoration(self):
        self.scenario='failed-untap';self.assertEqual(self.detach()[0],2);code,r=self.restore();self.assertEqual(code,0);self.assertTrue(r['CI_checkout_link_restored']);self.assertEqual(self.alias.resolve(),self.workspace)
    def test_ordinary_directory_at_setup_path_refuses_detachment(self):
        self.alias.unlink();self.alias.mkdir();self.assertEqual(self.detach()[0],2);self.assertTrue(self.alias.is_dir())
    def test_retargeted_link_refuses_detachment(self):
        other=self.root/'other';other.mkdir();self.alias.unlink();self.alias.symlink_to(other);self.assertEqual(self.detach()[0],2);self.assertEqual(self.alias.resolve(),other)
    def test_setup_path_mismatch_refuses(self):
        self.args.setup_repository_path=str(self.root/'other');self.assertEqual(self.detach()[0],2);self.assertTrue(self.alias.is_symlink())
    def test_setup_tap_mismatch_refuses(self):
        self.args.setup_tap_name='other/tap';self.assertEqual(self.detach()[0],2)
    def test_wrong_repository_refuses(self):
        os.environ['GITHUB_REPOSITORY']='other/repository';self.assertEqual(self.detach()[0],2)
    def test_wrong_workspace_refuses(self):
        os.environ['GITHUB_WORKSPACE']=str(self.root);self.assertEqual(self.detach()[0],2)
    def test_changed_current_job_commit_refuses(self):
        os.environ['GITHUB_SHA']='a'*40;self.assertEqual(self.detach()[0],2)
    def test_invalid_run_identity_refuses(self):
        os.environ['GITHUB_RUN_ATTEMPT']='0';self.assertEqual(self.detach()[0],2)
    def test_installed_formula_refuses_before_untap(self):
        self.scenario='installed-formula';self.assertEqual(self.detach()[0],2);self.assertTrue(self.alias.is_symlink())
    def test_available_compiler_alias_refuses_before_untap(self):
        with mock.patch('shutil.which',return_value='/SYNTHETIC/compiler'):self.assertEqual(self.detach()[0],2)
    def test_source_drift_after_untap_refuses_with_return_error(self):
        self.scenario='source-change';code,r=self.detach();self.assertEqual(code,2);self.assertTrue(r['finalization_errors']);self.assertTrue(r['checkout_alias_detached'])
    def test_source_removal_after_untap_refuses(self):
        self.scenario='source-removal';self.assertEqual(self.detach()[0],2)
    def test_provider_change_after_untap_refuses(self):
        self.scenario='provider-change';code,r=self.detach();self.assertEqual(code,2);self.assertTrue(r['finalization_errors'])
    def test_leftover_alias_refuses_success(self):
        self.scenario='leftover-alias';self.assertEqual(self.detach()[0],2)
    def test_retargeted_link_during_route_refuses_restoration(self):
        self.detach();other=self.root/'other';other.mkdir();self.alias.symlink_to(other);self.assertEqual(self.restore()[0],2);self.assertEqual(self.alias.resolve(),other)
    def test_public_clone_drift_refuses_before_move(self):
        self.returned_clone();(self.alias/'Formula/agent-crystal.rb').write_text('SYNTHETIC changed recipe');self.assertEqual(self.restore()[0],2);self.assertTrue(self.alias.is_dir());self.assertFalse((self.args.output/'preserved-public-tap').exists())
    def test_public_clone_without_returned_result_refuses(self):
        self.returned_clone();(self.args.route_output/'BOTTLE_RESULT.json').unlink();self.assertEqual(self.restore()[0],2);self.assertTrue(self.alias.is_dir())
    def test_unretired_route_refuses_public_clone_move(self):
        self.returned_clone();support.write(self.args.route_output/'BOTTLE_RESULT.json',{'writers_confirmed_retired':False});self.assertEqual(self.restore()[0],2);self.assertTrue(self.alias.is_dir())
    def test_existing_preservation_destination_refuses(self):
        self.returned_clone();(self.args.output/'preserved-public-tap').mkdir();self.assertEqual(self.restore()[0],2);self.assertTrue(self.alias.is_dir())
    def test_failed_restoration_link_preserves_public_clone_and_refuses(self):
        self.returned_clone()
        with mock.patch.object(Path,'symlink_to',side_effect=PermissionError('SYNTHETIC restore failure')):code,r=self.restore()
        self.assertEqual(code,2);self.assertTrue(r['public_clone_preserved']);self.assertTrue((self.args.output/'preserved-public-tap').is_dir());self.assertFalse(r['CI_checkout_link_restored'])
    def test_failed_public_clone_move_refuses(self):
        self.returned_clone()
        with mock.patch.object(Path,'rename',side_effect=PermissionError('SYNTHETIC move failure')):self.assertEqual(self.restore()[0],2)
        self.assertTrue(self.alias.is_dir())
    def test_checkout_drift_during_public_route_refuses_restoration(self):
        self.returned_clone();(self.source/'fixture.py').write_text('SYNTHETIC changed checkout');code,r=self.restore();self.assertEqual(code,2);self.assertTrue(r['finalization_errors'])
    def test_special_kind_public_clone_refuses(self):
        self.returned_clone();os.mkfifo(self.alias/'unwritten FIFO');self.assertEqual(self.restore()[0],2);self.assertTrue(self.alias.is_dir())
    def test_public_clone_alias_member_refuses(self):
        self.returned_clone();(self.alias/'unexpected alias').symlink_to(self.alias/'Formula');self.assertEqual(self.restore()[0],2)
    def test_tracked_blob_or_mode_mismatch_refuses(self):
        self.listing=self.listing.replace('100644','100755');self.assertEqual(self.detach()[0],2)
    def test_tracked_escape_refuses(self):
        with self.assertRaises(RuntimeError):ci.tracked_identity(self.workspace,'100644 blob '+'a'*40+'\t../escape\n')
    def test_physical_source_file_bounds_refuse(self):
        with mock.patch.object(ci,'MAX_FILES',0),self.assertRaises(RuntimeError):ci.tree_identity(self.workspace)
    def test_physical_source_byte_bounds_refuse(self):
        with mock.patch.object(ci,'MAX_BYTES',0),self.assertRaises(RuntimeError):ci.tree_identity(self.workspace)
    def test_named_command_roster_rejects_extra_preparation_commands(self):
        with self.assertRaises(RuntimeError):support.command_maximum('ci-arbitrary-operation')
    def test_predecessor_actual_checkout_commit_refuses_public_default_gate(self):
        output=self.root/'predecessor';output.mkdir();runner=self.driver.Runner(output)
        def call(*a,**k):return (str(self.workspace)+'\n','') if a[2].endswith('-tap-root') else (self.commit+'\n'+self.tree+'\n','')
        with mock.patch.object(route,'run_command',side_effect=call),self.assertRaisesRegex(RuntimeError,'promoted main'):route.tap_readback(runner,self.providers,output,{},'before-bottle')
    def test_final_journal_preserves_named_command_budgets(self):
        self.detach();rows=support.read(self.args.output/'COMMANDS.json');support.verify_commands(rows,support.read(self.args.output/'CI_PREPARATION_RESULT.json')['original_groups']);self.assertTrue(all(row['maximum_seconds']==support.command_maximum(row['label']) for row in rows))

    def stage_fixture(self):
        path=self.source/'vendor/public_evidence_rules.py';path.parent.mkdir();shutil.copyfile(ROOT/'vendor/public_evidence_rules.py',path)
        support.write(self.source/'SOURCE_PINS.json',{'files':[{'path':'fixture.py','bytes':len((self.source/'fixture.py').read_bytes()),'sha256':support.stable(self.source/'fixture.py')[0]['sha256']}]})
        self.args.packet_sha256=support.stable(self.source/'SOURCE_PINS.json')[0]['sha256'];self.args.stage=self.root/'fixed public stage'
    def test_positive_stage_retains_manifest_and_excludes_public_clone_payload(self):
        self.returned_clone();self.restore();self.stage_fixture()
        with mock.patch.object(ci,'source_packet',return_value=self.protected):ci.stage(self.args)
        roster=support.read(self.args.stage/'PUBLIC_STAGE.json');self.assertEqual(roster['source_manifest_sha256'],self.args.packet_sha256);self.assertFalse(roster['preserved_public_clone_uploaded']);self.assertTrue((self.args.stage/'SOURCE_PINS.json').is_file());self.assertFalse(any('preserved-public-tap' in r['path'] or '.git' in Path(r['path']).parts for r in roster['files']))
    def test_changed_raw_output_refuses_stage(self):
        self.detach();self.stage_fixture();(self.args.output/'ci-brew-root.stdout.txt').write_text('SYNTHETIC changed raw output')
        with mock.patch.object(ci,'source_packet',return_value=self.protected),self.assertRaisesRegex(RuntimeError,'raw output'):ci.stage(self.args)
        self.assertFalse(self.args.stage.exists())
    def test_unretired_CI_result_stages_only_fixed_metadata(self):
        self.detach();self.stage_fixture();value=support.read(self.args.output/'CI_PREPARATION_RESULT.json');value['writers_confirmed_retired']=False;support.write(self.args.output/'CI_PREPARATION_RESULT.json',value)
        with mock.patch.object(ci,'source_packet',return_value=self.protected):ci.stage(self.args)
        self.assertFalse((self.args.stage/'COMMANDS.json').exists());self.assertTrue((self.args.stage/'CI_PREPARATION_RESULT.json').exists())
    def test_public_clone_identity_drift_during_move_refuses(self):
        self.returned_clone();original=Path.rename
        def change(path,target):
            value=original(path,target);(Path(target)/'.git/config').write_text('SYNTHETIC drift during move');return value
        with mock.patch.object(Path,'rename',change):code,r=self.restore()
        self.assertEqual(code,2);self.assertFalse(r['CI_checkout_link_restored']);self.assertTrue((self.args.output/'preserved-public-tap').is_dir())
    def test_complete_preparation_deadline_exhaustion_refuses(self):
        with mock.patch.object(ci,'SECONDS',0):code,r=self.detach()
        self.assertEqual(code,2);self.assertFalse(r['passed']);self.assertTrue(r['finalization_errors'])

    def test_changed_provider_between_transitions_refuses_before_restoration(self):
        self.detach();path=Path(self.providers['git']['path']);path.write_text('SYNTHETIC replacement provider');self.providers['git']=support.stable(path)[0];self.protected[str(path)]=self.providers['git']['sha256']
        code,r=self.restore();self.assertEqual(code,2);self.assertIn('same exact observed providers',r['error']);self.assertFalse(self.alias.exists())

    def test_no_clone_unretired_route_refuses_before_link(self):
        self.detach();self.args.route_output.mkdir();self.args.route_step_outcomes=json.dumps({'bottle':'failure'})
        support.write(self.args.route_output/'BOTTLE_RESULT.json',{'passed':False,'writers_confirmed_retired':False,'original_groups':[{'group':777,'status':'present'}]})
        code,r=self.restore();self.assertEqual(code,2);self.assertFalse(self.alias.exists());self.assertFalse(r['CI_checkout_link_restored'])
    def test_no_clone_returned_route_restores_with_journal_join(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'})
        code,r=self.restore();self.assertEqual(code,0);self.assertTrue(self.alias.is_symlink())
        self.assertEqual(r['default_route_returns'][0]['returned_commands'],1)
    def test_no_clone_returned_zero_command_early_phase(self):
        self.detach();self.args.route_output.mkdir();self.args.route_step_outcomes=json.dumps({'bottle':'failure'})
        support.write(self.args.route_output/'BOTTLE_RESULT.json',{'passed':False,'writers_confirmed_retired':True,'original_groups':[]})
        code,r=self.restore();self.assertEqual(code,0);self.assertIn('zero-command',r['default_route_returns'][0]['scope'])
    def test_no_clone_positive_not_launched_workflow(self):
        self.detach();code,r=self.restore();self.assertEqual(code,0)
        self.assertEqual(r['default_route_return_boundary']['workflow_outcomes'],{'bottle':'skipped'})
        self.assertIn('not-launched',r['default_route_return_boundary']['scope'])
    def test_no_clone_failed_step_without_result_refuses(self):
        self.detach();self.args.route_step_outcomes=json.dumps({'bottle':'failure'})
        code,r=self.restore();self.assertEqual(code,2);self.assertFalse(self.alias.exists())
    def test_no_clone_cancelled_step_without_result_refuses(self):
        self.detach();self.args.route_step_outcomes=json.dumps({'bottle':'cancelled'})
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_skipped_step_with_reached_result_refuses(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_missing_actual_workflow_boundary_refuses(self):
        self.detach();self.args.route_step_outcomes=None
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_unknown_workflow_boundary_refuses(self):
        self.detach();self.args.route_step_outcomes=json.dumps({'bottle':'unknown'})
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_no_clone_changed_command_group_refuses(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});rows=support.read(self.args.route_output/'COMMANDS.json')
        rows[0]['original_group']=999;support.write(self.args.route_output/'COMMANDS.json',rows)
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_no_clone_changed_raw_output_refuses(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});(self.args.route_output/'homebrew-version.stdout.txt').write_text('changed')
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_no_clone_missing_journal_for_recorded_groups_refuses(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});(self.args.route_output/'COMMANDS.json').unlink()
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_unretired_later_preparation_refuses_no_clone(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('OBSERVATION_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'observation':'success','preparation':'failure','consumer':'skipped'})
        support.write(self.args.route_output/'PROVIDER_PREPARATION_RESULT.json',{'writers_confirmed_retired':False,'original_groups':[{'group':777,'status':'present'}]})
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_nested_sdk_unretired_refuses_no_clone(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});sdk=self.args.route_output/'sdk';sdk.mkdir()
        support.write(sdk/'READINESS_RESULT.json',{'writers_confirmed_retired':False,'owned_group_observations':[{'group':777,'status':'present'}]})
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_reached_sdk_missing_result_refuses_no_clone(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});(self.args.route_output/'sdk').mkdir()
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_return_evidence_drift_before_public_clone_mutation_refuses(self):
        self.returned_clone();original=ci.tree_identity
        def drift(path):
            value=original(path)
            if path==self.alias:support.write(self.args.route_output/'BOTTLE_RESULT.json',{'writers_confirmed_retired':False})
            return value
        with mock.patch.object(ci,'tree_identity',side_effect=drift):self.assertEqual(self.restore()[0],2)
        self.assertTrue(self.alias.is_dir());self.assertFalse((self.args.output/'preserved-public-tap').exists())
    def test_actual_hosted_restore_interface_requires_boundary(self):
        import hosted_entry
        args=types.SimpleNamespace(packet_sha256='fixture',output=self.root/'hosted',action='restore-ci-tap',
            setup_tap_name=ci.TAP,setup_repository_path=str(self.alias),route_output=self.args.route_output,route_step_outcomes=None)
        with mock.patch.object(hosted_entry,'source_packet',return_value={}),mock.patch.object(hosted_entry,'provider_arguments',return_value=([],{})):
            with self.assertRaisesRegex(RuntimeError,'actual workflow outcomes'):hosted_entry.main(args)
    def test_actual_hosted_restore_interface_preserves_boundary(self):
        import hosted_entry
        args=types.SimpleNamespace(packet_sha256='fixture',output=self.root/'hosted',action='restore-ci-tap',
            setup_tap_name=ci.TAP,setup_repository_path=str(self.alias),route_output=self.args.route_output,
            route_step_outcomes=json.dumps({'bottle':'skipped'}))
        captured=[]
        def invoked(*a,**k):captured.extend(sys.argv)
        with mock.patch.object(hosted_entry,'source_packet',return_value={}),mock.patch.object(hosted_entry,'provider_arguments',return_value=([],{})),mock.patch.object(hosted_entry.runpy,'run_path',side_effect=invoked):hosted_entry.main(args)
        self.assertEqual(captured[captured.index('--route-step-outcomes')+1],args.route_step_outcomes)
    def test_return_evidence_drift_after_clone_move_refuses_link(self):
        self.returned_clone();original=Path.rename
        def change(path,target):
            value=original(path,target)
            support.write(self.args.route_output/'BOTTLE_RESULT.json',{'writers_confirmed_retired':False})
            return value
        with mock.patch.object(Path,'rename',change):code,r=self.restore()
        self.assertEqual(code,2);self.assertFalse(self.alias.exists());self.assertTrue((self.args.output/'preserved-public-tap').is_dir())
        self.assertFalse(r['CI_checkout_link_restored'])
    def test_returned_nested_sdk_joins_raw_before_link(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('BOTTLE_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'bottle':'failure'});sdk=self.args.route_output/'sdk';sdk.mkdir()
        group={'group':456,'status':'absent'}
        for channel in ('stdout','stderr'):(sdk/('brew-prefix.'+channel+'.txt')).write_bytes(b'')
        command={'label':'brew-prefix','pid':456,'original_group':456,'maximum_seconds':45,'writers_confirmed_retired':True,
            'terminal_group_observation':group,'stdout_sha256':support.sha(b''),'stderr_sha256':support.sha(b'')}
        support.write(sdk/'COMMANDS.json',[command]);support.write(sdk/'READINESS_RESULT.json',{'passed':False,'writers_confirmed_retired':True,'owned_group_observations':[group]})
        code,r=self.restore();self.assertEqual(code,0);self.assertEqual(r['default_route_returns'][-1]['file'],'sdk/READINESS_RESULT.json')
    def test_unretired_review_phase_refuses_no_clone(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('OBSERVATION_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'observation':'success','preparation':'skipped','consumer':'failure'})
        support.write(self.args.route_output/'REVIEW_HOLD_RESULT.json',{'writers_confirmed_retired':False,'original_groups':[{'group':777,'status':'present'}]})
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())
    def test_skipped_phase_with_reached_directory_refuses(self):
        self.detach();self.args.route_output.mkdir();self.returned_phase('OBSERVATION_RESULT.json',self.args.route_output)
        self.args.route_step_outcomes=json.dumps({'observation':'success','preparation':'skipped','consumer':'skipped'})
        (self.args.route_output/'provider-preparation').mkdir()
        self.assertEqual(self.restore()[0],2);self.assertFalse(self.alias.exists())

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CICheckoutControls));print(json.dumps({'tests_run':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skips':len(result.skipped),'actual_guard_calls':len(GUARD_CALLS)},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() and not GUARD_CALLS else 2)
