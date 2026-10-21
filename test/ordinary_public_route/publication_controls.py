"""Guarded whole-file/public-origin and clean-publication behavior controls."""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import bottle_source_screen as screen
import stage_results as stage
import route_support as support
import build_bottle as bottle

ROOT=Path(__file__).resolve().parent
FIXTURES=Path(os.environ.get('ORDINARY_ROUTE_FIXTURE_ROOT',str(ROOT.parent/'fixtures')))
GUARD_CALLS=[]

class PublicationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive=FIXTURES/'compiler-source.tar.gz'
        if support.stable(archive)[0]['sha256']!=screen.SOURCE_ARCHIVE_SHA:raise RuntimeError('Exact formula-pinned public source fixture required')
        cls.public={}
        with tarfile.open(archive,'r:gz') as stream:
            for name,(size,digest) in screen.PUBLIC_SOURCE.items():
                item=stream.getmember('crystal-1.21.0-incremental-1/src/'+name);value=stream.extractfile(item).read(size+1)
                if len(value)!=size or support.sha(value)!=digest:raise RuntimeError('Exact two public whole-file bodies required')
                cls.public[name]=value
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='scoped publication physical controls with spaces ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guard(*a,**k):GUARD_CALLS.append('external');raise AssertionError('Guarded publication fixture provider required')
        for key in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.guards.enter_context(mock.patch(key,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(GUARD_CALLS,[]));self.rules=stage.load_rules();self.authority=screen.provenance(ROOT);self.bottle={'source_version':screen.VERSION,'formula_revision':2,'tap_commit':screen.TAP_COMMIT};self.packet=support.stable(ROOT/'SOURCE_PINS.json')[0]['sha256']
    def inspect(self,name='uri.cr',raw=None,path=None,authority=None,bottle_value=None,verified=True):
        return screen.inspect_member('authored.bottle.tar.gz',path or screen.PREFIX+name,self.public[name] if raw is None else raw,self.rules,self.bottle if bottle_value is None else bottle_value,self.authority if authority is None else authority,verified)
    def fixture(self,contents):
        out=self.root/'original private artifact';out.mkdir();archive=out/'agent-crystal--1.21.0-incremental-1_2.arm64_tahoe.bottle.tar.gz'
        with tarfile.open(archive,'w:gz',compresslevel=9) as stream:
            for name,raw in contents:
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o644;stream.addfile(item,io.BytesIO(raw))
        value={'crimson-knight/agent-crystal/agent-crystal':{'formula':{'name':'agent-crystal','pkg_version':screen.VERSION+'_2','tap_git_revision':screen.TAP_COMMIT,'tap_git_remote':'https://github.com/crimson-knight/homebrew-agent-crystal.git'},'bottle':{'root_url':bottle.ROOT_URL,'rebuild':0,'cellar':'any_skip_relocation','tags':{'arm64_tahoe':{'filename':archive.name,'local_filename':archive.name,'sha256':support.stable(archive)[0]['sha256']}}}}};support.write(out/'authored.bottle.json',value);support.write(out/'BOTTLE_INPUTS.json',bottle.bottle_inputs(out,bottle.ROOT_URL));support.write(out/'BOTTLE_RESULT.json',{'passed':True,'writers_confirmed_retired':True,'original_groups':[],'finalization_errors':[]});return out,archive
    def secret(self):return b'Authorization: Bearer '+b'A'*32
    def test_original_uri_source_still_refused_by_unchanged_rules(self):
        with self.assertRaises(ValueError):self.rules.inspect_public_bytes('uri.cr',self.public['uri.cr'])
    def test_original_playground_source_still_refused_by_unchanged_rules(self):
        with self.assertRaises(ValueError):self.rules.inspect_public_bytes('server.cr',self.public['compiler/crystal/tools/playground/server.cr'])
    def test_exact_uri_source_recognized_in_ordinary_bottle(self):
        self.assertEqual(self.inspect()['origin_classification'],'exact-reviewed-public-compiler-source')
    def test_exact_playground_source_recognized_in_ordinary_bottle(self):
        self.assertEqual(self.inspect('compiler/crystal/tools/playground/server.cr')['source_archive_sha256'],screen.SOURCE_ARCHIVE_SHA)
    def test_same_size_mutated_public_body_refuses(self):
        raw=self.public['uri.cr'];raw=bytes([raw[0]^1])+raw[1:]
        with self.assertRaises(ValueError):self.inspect(raw=raw)
    def test_public_body_with_new_credential_refuses(self):
        with self.assertRaises(ValueError):self.inspect(raw=self.public['uri.cr']+self.secret())
    def test_exact_body_wrong_path_refuses(self):
        with self.assertRaises(ValueError):self.inspect(path=screen.PREFIX+'other/uri.cr')
    def test_exact_body_wrong_package_version_refuses(self):
        with self.assertRaises(ValueError):self.inspect(path=screen.PREFIX.replace('_2/','_3/')+'uri.cr')
    def test_wrong_source_version_refuses(self):
        with self.assertRaises(ValueError):self.inspect(bottle_value=dict(self.bottle,source_version='changed'))
    def test_wrong_revision_type_and_value_refuse(self):
        for value in (True,3):
            with self.assertRaises(ValueError):self.inspect(bottle_value=dict(self.bottle,formula_revision=value))
    def test_wrong_tap_commit_refuses(self):
        with self.assertRaises(ValueError):self.inspect(bottle_value=dict(self.bottle,tap_commit='0'*40))
    def test_unverified_whole_archive_refuses(self):
        with self.assertRaises(ValueError):self.inspect(verified=False)
    def test_changed_formula_archive_provenance_refuses(self):
        with self.assertRaises(ValueError):self.inspect(authority=dict(self.authority,compiler_source_archive_sha256='0'*64))
    def test_missing_public_provenance_refuses(self):
        with self.assertRaises(ValueError):self.inspect(authority={})
    def test_unknown_GitHub_token_rule_remains_strict(self):
        with self.assertRaises(ValueError):self.inspect(raw=b'gh' + b'p_' + b'X'*32)
    def test_unknown_authorization_rule_remains_strict(self):
        with self.assertRaises(ValueError):self.inspect(raw=self.secret())
    def test_unknown_private_key_rule_remains_strict(self):
        with self.assertRaises(ValueError):self.inspect(raw=b'-----BEGIN '+b'PRIVATE KEY-----')
    def test_unknown_credential_URL_rule_remains_strict(self):
        with self.assertRaises(ValueError):self.inspect(raw=b'https://person:' + b'unknown-value' + b'@example.test/')
    def test_safe_diagnostics_include_no_matching_body(self):
        raw=self.secret();value=screen.diagnostic('authored.tar.gz','sample.txt',raw,screen.categories(raw,self.rules),self.rules);self.assertNotIn(raw.decode(),json.dumps(value));self.assertEqual(value['pattern_categories'],['authorization-header-credential-shape'])
    def test_sensitive_member_path_is_replaced_by_digest(self):
        name='gh'+'p_'+'X'*32;value=screen.diagnostic('authored.tar.gz',name,b'x',[],self.rules);self.assertIsNone(value['member_path']);self.assertEqual(value['member_path_sha256'],support.sha(name.encode()))
    def test_real_stager_recognizes_both_public_sources(self):
        out,archive=self.fixture([(screen.PREFIX+n,v) for n,v in self.public.items()]);dest=self.root/'clean projection';receipt=stage.stage(out,dest,self.packet,retain_clean_refusals=True);self.assertTrue(receipt['screening_complete']);self.assertEqual(receipt['recognized_public_source_count'],2);stage.verify_projection(dest,self.packet,complete=True)
    def test_known_public_then_unknown_private_match_keeps_refusal(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr']),('unreviewed/runtime.txt',self.secret())]);before=support.stable(archive)[0];dest=self.root/'clean refused projection'
        with self.assertRaises(ValueError):stage.stage(out,dest,self.packet,retain_clean_refusals=True)
        receipt=stage.verify_projection(dest,self.packet);self.assertFalse(receipt['screening_complete']);self.assertFalse((dest/archive.name).exists());self.assertEqual(support.stable(archive)[0],before);self.assertTrue((dest/'BOTTLE_RESULT.json').is_file());self.assertTrue((dest/'source/SOURCE_PINS.json').is_file());self.assertEqual(support.read(dest/'STAGING_DIAGNOSTICS.json')['refusals'][0]['member_path'],'unreviewed/runtime.txt')
        with self.assertRaises(RuntimeError):stage.verify_projection(dest,self.packet,complete=True)
    def test_wrong_public_path_retains_safe_actual_member_diagnostics(self):
        out,archive=self.fixture([('wrong/uri.cr',self.public['uri.cr'])]);dest=self.root/'path refused projection'
        with self.assertRaises(ValueError):stage.stage(out,dest,self.packet,retain_clean_refusals=True)
        self.assertEqual(support.read(dest/'STAGING_DIAGNOSTICS.json')['refusals'][0]['member_path'],'wrong/uri.cr');self.assertFalse((dest/archive.name).exists())
    def test_changed_retained_bottle_version_keeps_clean_negative_projection(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr'])]);value=support.read(out/'authored.bottle.json');next(iter(value.values()))['formula']['pkg_version']='changed';support.write(out/'authored.bottle.json',value);dest=self.root/'version refused projection'
        with self.assertRaises(RuntimeError):stage.stage(out,dest,self.packet,retain_clean_refusals=True)
        self.assertFalse(stage.verify_projection(dest,self.packet)['screening_complete']);self.assertFalse((dest/archive.name).exists());rows=support.read(dest/'STAGING_DIAGNOSTICS.json')['refusals'];actual=next(r for r in rows if r['member_path']=='authored.bottle.json');self.assertEqual(actual['sha256'],support.stable(out/'authored.bottle.json')[0]['sha256']);self.assertEqual(actual['bytes'],(out/'authored.bottle.json').stat().st_size)
    def test_provenance_refusal_retains_exact_safe_source_identities(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr'])]);dest=self.root/'provenance refused projection'
        with mock.patch.object(screen,'provenance',side_effect=RuntimeError('Changed reviewed provenance')):
            with self.assertRaises(RuntimeError):stage.stage(out,dest,self.packet,retain_clean_refusals=True)
            self.assertFalse(stage.verify_projection(dest,self.packet)['screening_complete'])
        rows=support.read(dest/'STAGING_DIAGNOSTICS.json')['refusals'];formula=next(r for r in rows if r['member_path']=='source/bottle_vendor/Formula/agent-crystal.rb');self.assertEqual(formula['sha256'],screen.FORMULA_SHA);self.assertFalse((dest/archive.name).exists());self.assertEqual(formula['pattern_categories'],['public-source-provenance-admission'])
    def test_context_diagnostic_size_cap_precedes_read(self):
        path=self.root/'large metadata';path.touch();path.open('r+b').truncate(8*2**20+1);rows=stage.context_diagnostics([('large.json',path)],'context','unadmitted-input',self.rules);self.assertTrue(rows[0]['identity_unavailable']);self.assertIsNone(rows[0]['sha256'])
    def test_context_diagnostic_alias_keeps_hash_unavailable(self):
        path=self.root/'alias metadata';path.symlink_to(ROOT/'SOURCE_PINS.json');rows=stage.context_diagnostics([('alias.json',path)],'context','unadmitted-input',self.rules);self.assertTrue(rows[0]['identity_unavailable']);self.assertIsNone(rows[0]['sha256'])
    def test_projection_extra_file_refuses_before_upload(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr'])]);dest=self.root/'projection with extra';stage.stage(out,dest,self.packet,retain_clean_refusals=True);(dest/'extra.txt').write_bytes(self.secret())
        with self.assertRaises(RuntimeError):stage.verify_projection(dest,self.packet)
    def test_projection_changed_body_and_forged_hash_still_screened(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr'])]);dest=self.root/'projection with mutation';stage.stage(out,dest,self.packet,retain_clean_refusals=True);path=dest/'BOTTLE_RESULT.json';path.write_bytes(self.secret());value=support.read(dest/'PUBLIC_STAGE.json');row=next(x for x in value['files'] if x['path']=='BOTTLE_RESULT.json');row.update(bytes=path.stat().st_size,sha256=support.stable(path)[0]['sha256']);support.write(dest/'PUBLIC_STAGE.json',value)
        with self.assertRaises(ValueError):stage.verify_projection(dest,self.packet)
    def test_missing_clean_projection_refuses(self):
        with self.assertRaises(FileNotFoundError):stage.verify_projection(self.root,self.packet)
    def test_actual_CLI_retains_clean_refusal_then_final_gate_refuses(self):
        out,archive=self.fixture([('unreviewed/runtime.txt',self.secret())]);dest=self.root/'CLI retained clean refusal';argv=sys.argv[:]
        try:
            sys.argv=[str(ROOT/'stage_results.py'),'--source',str(out),'--output',str(dest),'--packet-sha256',self.packet,'--retain-clean-refusals'];runpy.run_path(str(ROOT/'stage_results.py'),run_name='__main__');self.assertFalse(support.read(dest/'PUBLIC_STAGE.json')['screening_complete'])
            sys.argv=[str(ROOT/'stage_results.py'),'--source',str(dest),'--packet-sha256',self.packet,'--require-complete']
            with self.assertRaises(RuntimeError):runpy.run_path(str(ROOT/'stage_results.py'),run_name='__main__')
        finally:sys.argv[:]=argv
    def test_default_function_refusal_preserves_fresh_destination(self):
        out,archive=self.fixture([('unreviewed/runtime.txt',self.secret())]);dest=self.root/'strict default projection'
        with self.assertRaises(ValueError):stage.stage(out,dest,self.packet)
        self.assertFalse(dest.exists())
    def test_retention_CLI_rejects_an_existing_clean_projection(self):
        out,archive=self.fixture([(screen.PREFIX+'uri.cr',self.public['uri.cr'])]);dest=self.root/'prior attempt clean projection';stage.stage(out,dest,self.packet);argv=sys.argv[:]
        try:
            sys.argv=[str(ROOT/'stage_results.py'),'--source',str(out),'--output',str(dest),'--packet-sha256',self.packet,'--retain-clean-refusals']
            with self.assertRaisesRegex(RuntimeError,'Fresh current-attempt'):runpy.run_path(str(ROOT/'stage_results.py'),run_name='__main__')
        finally:sys.argv[:]=argv
