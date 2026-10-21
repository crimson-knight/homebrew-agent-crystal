"""Exercise ordinary catalog capture, preservation and public-stage behavior."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent/'ordinary_public_route'

def sealed_body(path,maximum=64*2**20):
    path=Path(path);before=path.lstat()
    if path.resolve(strict=True)!=path or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<=before.st_size<=maximum:raise RuntimeError('Bounded physical ordinary source required')
    fields=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        opened=os.fstat(stream.fileno());body=stream.read(maximum+1);after=os.fstat(stream.fileno())
    if fields(before)!=fields(opened) or fields(before)!=fields(after) or fields(before)!=fields(path.lstat()) or len(body)!=before.st_size:raise RuntimeError('Stable complete source return required')
    return body

def source_return(packet_sha,control_sha):
    def need(value):
        if not value:raise RuntimeError('Exact source/control provider required')
    manifest=ROOT/'SOURCE_PINS.json';raw=sealed_body(manifest,2**20)
    need(hashlib.sha256(raw).hexdigest()==packet_sha)
    rows=json.loads(raw)['files'];need(len(rows)==48 and len({row['path'] for row in rows})==48)
    for row in rows:
        name=Path(row['path']);need(not name.is_absolute() and '..' not in name.parts and str(name)==row['path'])
        body=sealed_body(ROOT/name);need(len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'])
    need(hashlib.sha256(sealed_body(Path(__file__))).hexdigest()==control_sha)

def run_control_cohort(output,packet_sha,control_sha):
    source_return(packet_sha,control_sha)
    driver=ROOT/'vendor/test/sdk_install_qualification.py'
    if hashlib.sha256(driver.read_bytes()).hexdigest()!='d63a6dae115a58fa1fb4330203f219a429b6f3dcbe7ade36054ad847dd76a227':raise RuntimeError('Original pinned Runner required')
    spec=importlib.util.spec_from_file_location('ordinary_catalog_original_Runner',driver);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=Path(output);output.parent.resolve(strict=True)
    if not output.is_absolute() or output.exists() or output.is_symlink():raise RuntimeError('Fresh physical catalog-control output required')
    output.mkdir();runner=module.Runner(output);runner.deadline=time.monotonic()+60
    python=Path(sys.executable).resolve();python_sha=hashlib.sha256(python.read_bytes()).hexdigest()
    environment={key:value for key,value in os.environ.items() if key in ('PATH','HOME','LANG','LC_ALL','TMPDIR')};environment['PYTHONDONTWRITEBYTECODE']='1'
    counts=[]
    try:
        for mode in ('ordinary','optimized'):
            argv=[python,'-I','-S','-B']+(['-O'] if mode=='optimized' else [])+[Path(__file__),'--worker',packet_sha,control_sha]
            stdout,stderr=runner.run('catalog-'+mode,argv,cwd=ROOT,environment=environment,seconds=20)
            matches=re.findall(r'^Ran (\d+) tests in',stderr,re.M)
            if stdout or matches!=['22'] or not stderr.rstrip().endswith('OK'):raise RuntimeError('Complete22-case catalog behavior cohort required')
            counts.append(22);source_return(packet_sha,control_sha)
        if hashlib.sha256(python.read_bytes()).hexdigest()!=python_sha:raise RuntimeError('Exact observed Python body return required')
    finally:
        result=dict(passed=counts==[22,22] and runner.writers_confirmed_retired and all(row['status']=='absent' for row in runner.group_observations),cases=sum(counts),commands=runner.records,groups=runner.group_observations,writers_confirmed_retired=runner.writers_confirmed_retired,source_manifest_sha256=packet_sha,control_source_sha256=control_sha,observed_python_sha256=python_sha,actual_compiler_native_workloads=0)
        (output/'CATALOG_CONTROL_RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    if not result['passed']:raise RuntimeError('Complete catalog controls and original-group return required')
    print(json.dumps(dict(passed=True,cases=44,all_groups_absent=True)))

if __name__=='__main__' and len(sys.argv)>1:
    if sys.argv[1]=='--output':
        if len(sys.argv)!=5:raise RuntimeError('Output, packet SHA and control SHA required')
        run_control_cohort(sys.argv[2],sys.argv[3],sys.argv[4]);raise SystemExit(0)
    if sys.argv[1]=='--worker':
        if len(sys.argv)!=4:raise RuntimeError('Exact worker source pins required')
        source_return(sys.argv[2],sys.argv[3]);sys.argv[:]=[sys.argv[0]]

sys.path.insert(0,str(ROOT))
import route_support as support
import stage_results


class CatalogControls(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='catalog controls with spaces ')
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name).resolve();self.cache=self.root/'cache';self.api=self.cache/'api';self.api.mkdir(parents=True)
        self.guards=ExitStack();self.addCleanup(self.guards.close);self.external_calls=[]
        def guarded(*args,**kwargs):
            self.external_calls.append('external');raise AssertionError('Source fixture uses authored providers')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):
            self.guards.enter_context(mock.patch(target,side_effect=guarded))
        self.addCleanup(lambda:self.assertEqual(self.external_calls,[]))

    def member(self,name,body=b'SYNTHETIC package catalog'):
        path=self.api/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);path.chmod(0o644);return path

    def test_legacy_catalogs_keep_original_names_and_bytes(self):
        for name in ('formula.jws.json','formula.json'):self.member(name)
        rows=support.catalog(self.cache);self.assertEqual(set(rows),{'formula.jws.json','formula.json'})
        self.assertTrue(all(row['sha256']==hashlib.sha256(b'SYNTHETIC package catalog').hexdigest() for row in rows.values()))

    def test_current_linux_catalog_is_captured(self):
        self.member('internal/packages.x86_64_linux.jws.json')
        self.assertEqual(set(support.catalog(self.cache)),{'internal/packages.x86_64_linux.jws.json'})

    def test_current_mac_catalog_and_legacy_are_retained_together(self):
        for name in ('formula.jws.json','formula.json','internal/packages.arm64_tahoe.jws.json'):self.member(name)
        self.assertEqual(len(support.catalog(self.cache)),3)

    def test_payload_index_and_unrelated_cache_members_keep_their_own_scope(self):
        self.member('internal/packages.x86_64_linux.jws.json');self.member('internal/packages.x86_64_linux.payload.json');self.member('internal/executables.txt')
        self.assertEqual(set(support.catalog(self.cache)),{'internal/packages.x86_64_linux.jws.json'})

    def test_ambiguous_platform_catalogs_refuse_before_reading_payload(self):
        self.member('internal/packages.x86_64_linux.jws.json');self.member('internal/packages.arm64_tahoe.jws.json')
        with mock.patch.object(support,'stable',side_effect=AssertionError('Payload read before complete admission')):
            with self.assertRaisesRegex(RuntimeError,'unambiguous'):support.catalog(self.cache)

    def test_symlink_internal_directory_refuses(self):
        external=self.root/'external';external.mkdir();(self.api/'internal').symlink_to(external)
        with self.assertRaisesRegex(RuntimeError,'directory'):support.catalog(self.cache)

    def test_symlink_catalog_root_refuses(self):
        alias=self.root/'alias-cache';alias.mkdir();(alias/'api').symlink_to(self.api)
        with self.assertRaisesRegex(RuntimeError,'catalog root'):support.catalog(alias)

    def test_symlink_member_refuses(self):
        path=self.member('internal/original.json');(self.api/'internal/packages.x86_64_linux.jws.json').symlink_to(path)
        with self.assertRaisesRegex(RuntimeError,'ordinary catalog'):support.catalog(self.cache)

    def test_FIFO_member_refuses_before_open(self):
        (self.api/'internal').mkdir();os.mkfifo(self.api/'internal/packages.x86_64_linux.jws.json')
        with mock.patch.object(support.os,'open',side_effect=AssertionError('FIFO payload was opened')):
            with self.assertRaisesRegex(RuntimeError,'ordinary catalog'):support.catalog(self.cache)

    def test_oversized_member_refuses_before_open(self):
        path=self.member('internal/packages.x86_64_linux.jws.json')
        with path.open('r+b') as stream:stream.truncate(64*2**20+1)
        with mock.patch.object(support.os,'open',side_effect=AssertionError('Oversized payload was opened')):
            with self.assertRaisesRegex(RuntimeError,'ordinary catalog'):support.catalog(self.cache)

    def test_directory_count_refuses_before_payload_read(self):
        for index in range(65):self.member('internal/unrelated-'+str(index))
        with self.assertRaisesRegex(RuntimeError,'directory census'):support.catalog(self.cache)

    def test_expired_catalog_observation_refuses(self):
        self.member('internal/packages.x86_64_linux.jws.json')
        with mock.patch.object(support.time,'monotonic',side_effect=[0,6]):
            with self.assertRaisesRegex(RuntimeError,'directory census'):support.catalog(self.cache)

    def test_changed_directory_during_capture_refuses(self):
        self.member('internal/packages.x86_64_linux.jws.json');original=support.stable
        def changed(path,*args):
            result=original(path,*args);self.member('internal/added-after-capture');return result
        with mock.patch.object(support,'stable',side_effect=changed):
            with self.assertRaisesRegex(RuntimeError,'directory return'):support.catalog(self.cache)

    def stage(self):
        name='internal/packages.x86_64_linux.jws.json';self.member(name);snapshot=support.catalog(self.cache)
        output=self.root/'returned output';output.mkdir();(output/'resolved-catalog').mkdir()
        support.retain_catalog(snapshot,output/'resolved-catalog')
        support.write(output/'CATALOG_BEFORE.json',{'API':snapshot})
        support.write(output/'BOTTLE_RESULT.json',{'passed':False,'writers_confirmed_retired':True})
        return output,name

    def test_nested_capture_reaches_actual_public_selector(self):
        output,name=self.stage();selected,uncertain,bottle=stage_results.select_evidence(output)
        self.assertFalse(uncertain);self.assertIsNone(bottle);self.assertIn('resolved-catalog/'+name,selected)
        self.assertEqual((output/'resolved-catalog'/name).read_bytes(),b'SYNTHETIC package catalog')

    def test_changed_staged_catalog_refuses(self):
        output,name=self.stage();(output/'resolved-catalog'/name).write_bytes(b'SYNTHETIC changed catalog')
        with self.assertRaisesRegex(RuntimeError,'staging bytes'):stage_results.select_evidence(output)

    def test_undeclared_internal_catalog_refuses(self):
        output,name=self.stage();support.write(output/'CATALOG_BEFORE.json',{'API':{}})
        with self.assertRaisesRegex(RuntimeError,'staging roster'):stage_results.select_evidence(output)

    def test_changed_source_catalog_refuses_retention(self):
        self.member('internal/packages.x86_64_linux.jws.json');snapshot=support.catalog(self.cache)
        self.member('internal/packages.x86_64_linux.jws.json',b'SYNTHETIC changed source')
        output=self.root/'retention';output.mkdir()
        with self.assertRaisesRegex(RuntimeError,'resolved API bytes'):support.retain_catalog(snapshot,output)

    def public_catalog(self,mode=0o600):
        output,name=self.stage();captured=output/'resolved-catalog'/name;captured.chmod(mode)
        declared=support.read(output/'CATALOG_BEFORE.json');declared['API'][name]['mode']=mode;support.write(output/'CATALOG_BEFORE.json',declared)
        pin=hashlib.sha256((ROOT/'SOURCE_PINS.json').read_bytes()).hexdigest();public=self.root/'public stage'
        receipt=stage_results.stage(output,public,pin)
        return public,name,pin,receipt

    def test_literal_public_stage_preserves_private_catalog_mode(self):
        public,name,pin,receipt=self.public_catalog()
        self.assertEqual(stat.S_IMODE((public/'resolved-catalog'/name).stat().st_mode),0o600)
        self.assertTrue(stage_results.verify_projection(public,pin,complete=True)['screening_complete'])

    def test_public_reader_refuses_catalog_mode_change_with_exact_bytes(self):
        public,name,pin,receipt=self.public_catalog();(public/'resolved-catalog'/name).chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'staging bytes and mode'):stage_results.verify_projection(public,pin,complete=True)

    def test_public_reader_refuses_missing_declared_catalog_after_projection_rewrite(self):
        public,name,pin,receipt=self.public_catalog();path='resolved-catalog/'+name;(public/path).unlink()
        receipt['files']=[row for row in receipt['files'] if row['path']!=path];receipt['file_count']=len(receipt['files']);support.write(public/'PUBLIC_STAGE.json',receipt)
        with self.assertRaisesRegex(RuntimeError,'staging roster'):stage_results.verify_projection(public,pin,complete=True)

    def test_restored_catalog_mode_restores_public_acceptance(self):
        public,name,pin,receipt=self.public_catalog();path=public/'resolved-catalog'/name;path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'staging bytes and mode'):stage_results.verify_projection(public,pin,complete=True)
        path.chmod(0o600);self.assertTrue(stage_results.verify_projection(public,pin,complete=True)['screening_complete'])

    def test_empty_catalog_preserves_separate_core_checkout_route(self):
        self.assertEqual(support.catalog(self.cache),{})


if __name__=='__main__':
    unittest.main(verbosity=2)
