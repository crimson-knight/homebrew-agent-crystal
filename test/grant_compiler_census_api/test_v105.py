"""Compact active-profile controls; full owned-layout replay has a separate gate."""
import ast,base64,copy,hashlib,importlib.util,json,os
from pathlib import Path
import sys,tempfile,time,types,unittest
from contextlib import ExitStack
from unittest import mock
ROOT=Path(__file__).resolve().parent
BASE=Path(os.environ.get('ATLAS_CENSUS_V105_BASE',str(ROOT)))
def digest(raw):return hashlib.sha256(raw).hexdigest()
def load(name):
 p=ROOT/(name+'.py');spec=importlib.util.spec_from_file_location('v105_'+name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
pkg=load('pkgconf_provider');proxy=load('compiler_proxy');model=load('run_census')
sys.modules['pkgconf_provider']=pkg
fixture=load('fixture_v105')
class V105Controls(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close);self.calls=[]
  def external(*a,**k):self.calls.append(True);raise AssertionError('Authored metadata provider required')
  for name in ('subprocess.Popen','os.execve','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):self.stack.enter_context(mock.patch(name,side_effect=external))
  self.addCleanup(lambda:self.assertEqual(self.calls,[]))
  self.tmp=tempfile.TemporaryDirectory(prefix='v105 compact fixture ',dir=os.environ['ATLAS_FIXTURE_ROOT']);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.value=fixture.descriptor(model,self.root/'selected pkgconf with spaces')
 def test_profile_build_matches_ordinary_make_context(self):
  argv=proxy.derive(['build','--no-codegen','/owned/project/probe.cr'],'/owned/project','/installed/src')
  self.assertEqual(argv[3:],proxy.FLAGS);self.assertEqual(argv[argv.index('--threads')+1],'1');self.assertIn('--release',argv);self.assertIn('--no-debug',argv);self.assertNotIn('-Dwithout_mt',argv);self.assertIn('--error-on-warnings',argv)
  self.assertEqual(model.CONTEXT['compiled_Grant_application_flags'],['without_mt'])
 def test_docs_uses_supported_define_form_and_strict_warnings(self):
  original=['docs','--format=json','-D','without_mt','src/compiler/requires.cr']
  result=proxy.derive(original,'/owned/project','/installed/src')
  self.assertEqual(result[:3],['docs','--format=json','src/compiler/requires.cr']);self.assertNotIn('--release',result);self.assertNotIn('--no-debug',result);self.assertNotIn('without_mt',result);self.assertFalse(model.CONTEXT['docs_semantic_profile']['machine_code_generation_qualified']);self.assertFalse(model.CONTEXT['docs_semantic_profile']['compiler_concurrency_qualified']);self.assertFalse(model.CONTEXT['docs_semantic_profile']['debug_metadata_generation_qualified'])
  self.assertEqual(result[-14:],[p for flag in proxy.DOCS_DEFINES for p in ('-D',flag)]+['--error-on-warnings','--no-color'])
 def test_unreviewed_verifier_flags_refuse(self):
  for extra in (['--threads','2'],['-Dwithout_mt'],['--release'],['--prelude','empty']):
   with self.subTest(extra=extra),self.assertRaises(RuntimeError):proxy.derive(['build','--no-codegen','/owned/project/probe.cr',*extra],'/owned/project','/installed/src')
 def test_unreviewed_docs_context_refuses(self):
  for extra in (['-D','unknown_feature'],['--release'],['--no-debug'],['--threads','1'],['--threads=1'],['--unknown']):
   with self.subTest(extra=extra),self.assertRaises(RuntimeError):proxy.derive(['docs','--format=json','src/compiler/requires.cr',*extra],'/owned/project','/installed/src')
 def test_complete_roster_and_original_limits(self):
  rows=model.command_roster();self.assertEqual(len(rows),126);self.assertEqual(sum(v for _,v in rows),2310);self.assertEqual(rows[:3],[('pkg-config-version',10),('pkg-config-bdw-gc-version',10),('pkg-config-bdw-gc-pcfiledir',10)]);self.assertEqual((model.OUTER_SECONDS,model.PREPARATION_SECONDS,model.RETURN_SECONDS),(2700,120,180));self.assertLessEqual(120+2310+180,2700)
 def test_all_original_questions_probes_and_canonical_gc_exact(self):
  pins=json.loads((ROOT/'SOURCE_PINS.json').read_bytes())['files'];base=json.loads((BASE/'SOURCE_PINS.json').read_bytes())['files'];old={r['path']:r for r in base};new={r['path']:r for r in pins}
  for name in ['API_ROSTER.json','COUNTER_PHASE_MAP.json','COUNTER_PHASE_MAP.md','inputs/compiler-source.tar.gz','inputs/COMPILER_ARCHIVE_ROSTER.json']:
   self.assertEqual(new[name],old[name])
  self.assertEqual(len(json.loads((BASE/'API_ROSTER.json').read_bytes())['queries']),56);self.assertEqual(len(model.PROBES),4);self.assertEqual(model.CANONICAL_GC_SHA,'526f1819cfc10f3a97a62da8c0dab11116c4e48bcc07c59903ee562a2f7ed307')
 def test_exact_pkgconf_metadata_positive(self):self.assertEqual(pkg.validate(model,self.value),self.value)
 def test_bad_versions_and_integer_metadata_refuse(self):
  for key,bad in [('package_version','3.0.9'),('pc_version','0.0.0'),('mode',False),('bytes',True),('sha256','0'*63),('native_file_closure_covered',1)]:
   with self.subTest(key=key):
    value=copy.deepcopy(self.value);value[key]=bad
    with self.assertRaises(RuntimeError):pkg.validate(model,value)
 def test_resealed_pcfile_wrong_missing_duplicate_version_refuses(self):
  for raw in (b'Name: GC\n',b'Version: 0.0.0\n',b'Version: 8.2.12\nVersion: 8.2.12\n',b'Version: 8.2.12\x00\n',b'x'*65537):
   value=copy.deepcopy(self.value);value.update(pcfile_contents=raw.decode(),pc_version='8.2.12');value['pcfile'].update(bytes=len(raw),sha256=digest(raw))
   with self.subTest(raw=raw[:32]),self.assertRaises(RuntimeError):pkg.validate(model,value)
 def test_selected_alias_roles_and_pc_directory_refuse_changed(self):
  for operation in ('alias','physical','pcdir','missing'):
   value=copy.deepcopy(self.value)
   if operation=='alias':value['lexical'][1]['declared_path']='/elsewhere/meta.pc'
   if operation=='physical':value['lexical'][0]['resolved_path']='/elsewhere/pkgconf'
   if operation=='pcdir':value['pcfiledir']='/elsewhere'
   if operation=='missing':value['lexical'].pop()
   with self.subTest(operation=operation),self.assertRaises(RuntimeError):pkg.validate(model,value)
 def test_environment_is_exact_selected_gc_metadata(self):self.assertEqual(pkg.environment(self.value),dict(PKG_CONFIG_LIBDIR=self.value['pcfiledir'],PKG_CONFIG_PATH='',PKG_CONFIG_SYSROOT_DIR=''))
 def test_physical_census_missing_changed_role_refuses(self):
  files={p:dict(path=p,bytes=1,sha256='0'*64,mode=0o644) for p in [self.value['resolved_path'],self.value['pcfile']['path'],self.value['selected_gc_library']]}
  with self.assertRaises(RuntimeError):pkg.validate(model,self.value,files)
  files.pop(self.value['selected_gc_library'])
  with self.assertRaises(RuntimeError):pkg.validate(model,self.value,files)
 def test_transparent_launcher_reaches_exact_original_provider(self):
  code=pkg.launcher(model,self.value,sys.executable);calls=[]
  with mock.patch('os.execve',side_effect=lambda *a:calls.append(a)),mock.patch.object(sys,'argv',['pkg-config','--modversion','bdw-gc']):exec(compile(code,'<authored-pkgconf-launcher>','exec'),{})
  self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],self.value['resolved_path']);self.assertEqual(calls[0][1],[self.value['resolved_path'],'--modversion','bdw-gc'])
 def test_changed_provider_launcher_refuses_and_restores(self):
  code=pkg.launcher(model,self.value,sys.executable);path=Path(self.value['resolved_path']);original=path.read_bytes();path.write_bytes(original+b' changed')
  with self.assertRaises(SystemExit) as error:exec(compile(code,'<authored-pkgconf-launcher>','exec'),{})
  self.assertEqual(error.exception.code,78);path.write_bytes(original)
  with mock.patch('os.execve',return_value=None):exec(compile(code,'<authored-pkgconf-launcher>','exec'),{})
 def test_replaced_provider_alias_refuses(self):
  code=pkg.launcher(model,self.value,sys.executable);p=Path(self.value['resolved_path']);raw=p.read_bytes();other=p.with_name('different');other.write_bytes(raw);p.unlink();p.symlink_to(other.name)
  with self.assertRaises(SystemExit):exec(compile(code,'<authored-pkgconf-launcher>','exec'),{})
 def test_prior_receipt_exact_job_profile_and_bytes(self):
  path=self.root/'observed.json';value=dict(passed=True,SDK=dict(job='same',profile='a'*64),inputs=dict(native='exact'));path.write_bytes(model.canonical(value));args=types.SimpleNamespace(pkgconf_observation=path,pkgconf_observation_sha256=digest(path.read_bytes()),packet_sha256='e'*64)
  context=dict(admitted=value['SDK']);self.assertEqual(pkg.retained(model,args,context,value['inputs'],lambda m,v,s:v),path.read_bytes())
  for part in ('SDK','inputs','hash','missing'):
   args.pkgconf_observation_sha256=digest(path.read_bytes());ctx=copy.deepcopy(context);observed=value['inputs']
   if part=='SDK':ctx['admitted']['job']='different'
   if part=='inputs':observed={}
   if part=='hash':args.pkgconf_observation_sha256='0'*64
   if part=='missing':args.pkgconf_observation=None
   with self.subTest(part=part),self.assertRaises(RuntimeError):pkg.retained(model,args,ctx,observed,lambda m,v,s:v)
   args.pkgconf_observation=path
 def test_expired_phase_guard_retains_original_horizon(self):
  with self.assertRaises(RuntimeError):model.clock(time.monotonic()-1)
 def test_legacy_proxy_replay_is_separately_labeled(self):
  old=json.loads((ROOT/'inputs/V104_EXECUTABLE_ANCESTRY.json').read_bytes())['files']['compiler_proxy.py'];raw=base64.b64decode(old['base64']);self.assertEqual(digest(raw),old['sha256']);scope={};exec(compile(raw,'<retained-v104-proxy>','exec'),scope)
  argv=scope['derive'](['build','--no-codegen','/owned/project/probe.cr'],'/owned/project','/installed/src');self.assertIn('-Dwithout_mt',argv);self.assertNotIn('--release',argv)
 def test_reader_helper_load_precedes_pkgconf_decode(self):
  raw=(ROOT/'artifact.py').read_text();part=raw[raw.index("if metadata['native_receipt']['format'] =="):raw.index('    result = model.decode',raw.index("if metadata['native_receipt']['format'] =="))];self.assertLess(part.index('helper_api ='),part.index('pkg_observed='))
 def test_failure_retains_partial_and_refusal(self):
  source=(ROOT/'launch_api.py').read_text();self.assertIn("owned.write('PKGCONF_PARTIAL.json'",source);self.assertIn("owned.write('PKGCONF_REFUSAL.json'",source);self.assertIn('PKGCONF_PARTIAL.json',load('artifact').FIXED)
 def controller_case(self,scenario='normal',mutate=None,started=None):
  # Small synthetic source projection exercises the literal active execute body.
  # Complete3190-node source/installed/YAML replay retains its separate gate.
  artifact=load('artifact');sys.modules.update(run_census=model,compiler_proxy=proxy,artifact=artifact,fixture_v105=fixture)
  spec=importlib.util.spec_from_file_location('v105_legacy_entry_fixture',BASE/'launch_census.py');entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry);sys.modules['launch_census']=entry
  tests=load('test_census');case=tests.CensusControls('test_positive_actual_controller_body')
  original_stable=model.stable;original_load=model.load
  def source_path(path):
   path=Path(path)
   if path.is_relative_to(ROOT) and not path.exists():return BASE/path.relative_to(ROOT)
   return path
  def stable(path,*a,**k):return original_stable(source_path(path),*a,**k)
  def loaded(path,expected,name):return original_load(source_path(path),expected,name)
  original_read=Path.read_bytes
  reads=mock.patch.object(Path,'read_bytes',lambda path:original_read(source_path(path)))
  reads.start()
  try:
   case.setUp()
   case.scenario=scenario
   if mutate is not None:mutate(case)
   with mock.patch.object(model,'stable',side_effect=stable),mock.patch.object(model,'load',side_effect=loaded):
    code,result=case.perform(started=started)
   self.assertTrue(result['writers_confirmed_retired']);self.assertTrue(result['private_removed'],result.get('error'));self.assertTrue(result['source_provider_return_accepted'],result['finalization_errors']);self.assertEqual(result['finalization_errors'],[])
   return code,result
  finally:
   case.doCleanups();reads.stop()
 def test_literal_active_producer_positive_with_small_synthetic_projection(self):
  code,result=self.controller_case();self.assertEqual(code,0);self.assertTrue(result['passed']);self.assertEqual(result['commands'],70);self.assertEqual(result['compiler_color'],'GREEN')
 def test_literal_active_producer_keeps_strict_warning_refusal(self):
  code,result=self.controller_case('warning');self.assertEqual(code,2);self.assertFalse(result['passed']);self.assertEqual(result['compiler_color'],'YELLOW')
 def test_literal_active_producer_pkgconf_bad_behavior_refuses(self):
  def mutate(case):
   old=case.context['driver'].Runner
   class BadPkg(old):
    def run(runner,label,*a,**k):
     stdout,stderr=super().run(label,*a,**k)
     if label=='pkg-config-bdw-gc-version':
      stdout='0.0.0\n';(runner.output/(label+'.stdout.txt')).write_text(stdout);runner.records[-1]['stdout_sha256']=model.sha(stdout.encode())
     return stdout,stderr
   case.context['driver']=types.SimpleNamespace(Runner=BadPkg)
  code,result=self.controller_case(mutate=mutate);self.assertEqual(code,2);self.assertFalse(result['passed']);self.assertEqual(result['commands'],2);self.assertIn('Actual reviewed pkgconf/GC metadata behavior',result['error'])
 def static_case(self,operation):
  api=load('api_provider');artifact=load('artifact');launch=load('launch_api')
  sys.modules.update(run_census=model,compiler_proxy=proxy,artifact=artifact,api_provider=api,launch_api=launch,fixture_v105=fixture)
  spec=importlib.util.spec_from_file_location('v105_legacy_entry_for_static',BASE/'launch_census.py');entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry);sys.modules['launch_census']=entry
  original=load('test_census');sys.modules['test_census']=original;cases=load('test_api_only');case=cases.ApiOnlyControls('test_static_complete_without_any_cc_header_or_subprocess')
  original_read=Path.read_bytes;oldstable=model.stable;oldload=model.load;oldmanifest=model.manifest
  def source_path(path):
   path=Path(path)
   return BASE/path.relative_to(ROOT) if path.is_relative_to(ROOT) and not path.exists() else path
  with mock.patch.object(Path,'read_bytes',lambda p:original_read(source_path(p))),mock.patch.object(model,'stable',side_effect=lambda p,*a,**k:oldstable(source_path(p),*a,**k)),mock.patch.object(model,'load',side_effect=lambda p,e,n:oldload(source_path(p),e,n)),mock.patch.object(model,'manifest',side_effect=lambda p,*a,**k:oldmanifest(source_path(p),*a,**k)):
   try:
    case.setUp();before=case.collect();self.assertTrue(before['complete']);self.assertEqual(len(before['stable_view']['images']),4);self.assertEqual(before['stable_view']['pkgconf']['pc_version'],'8.2.12');api.validate_observation(model,api.observation_record(model,case.args,dict(case.static_context,static_inputs=before),time.monotonic()),case.args.packet_sha256)
    if operation=='alias':
     alias=case.prefix/'bin/pkg-config';alias.unlink();alias.symlink_to('../opt/pkgconf/bin/pkgconf');after=case.collect();self.assertNotEqual(before['physical'],after['physical']);self.assertNotEqual(before['stable_view'],after['stable_view'])
    if operation=='metadata':
     pc=case.prefix/'Cellar/bdw-gc/8.2.12/lib/pkgconfig/bdw-gc.pc';raw=pc.read_bytes();pc.write_bytes(raw.replace(b'8.2.12',b'0.0.0'))
     with self.assertRaises(RuntimeError):case.collect()
     pc.write_bytes(raw);self.assertEqual(before['stable_view'],case.collect()['stable_view'])
   finally:case.doCleanups()
 def test_literal_static_pkgconf_GC_metadata_collection(self):self.static_case('positive')
 def test_literal_static_pkgconf_alias_identity_changes(self):self.static_case('alias')
 def test_literal_static_GC_version_refuses_and_restores(self):self.static_case('metadata')
 def test_original_assertion_methods_and_assertion_counts_preserved(self):
  ancestry=json.loads((ROOT/'inputs/V104_EXECUTABLE_ANCESTRY.json').read_bytes())['files']
  for name in ('test_census.py','test_api_only.py','test_v104.py'):
   old=ast.parse(base64.b64decode(ancestry[name]['base64']));new=ast.parse((ROOT/name).read_bytes())
   def assertions(tree):
    return {node.name:[call.func.attr for call in ast.walk(node) if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and call.func.attr.startswith('assert')] for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name.startswith('test_')}
   self.assertEqual(assertions(old),assertions(new))
 def test_full_profile_authority_and_workflow_composition(self):
  profile=json.loads((ROOT/'inputs/HOST_PROFILE_SOURCE.v105.json').read_bytes());phases=json.loads((ROOT/'inputs/WORKFLOW_COMPOSITION.v105.json').read_bytes());self.assertEqual(profile['Grant_application_defines'],['without_mt']);self.assertFalse(profile['actual_new_host_profile_qualified']);self.assertEqual(sum(seconds for _,seconds in phases['phases']),9060);self.assertEqual(phases['maximum_minutes'],151);self.assertEqual(phases['API_command_seconds'],2310);self.assertFalse(phases['initial_execution_admitted']);self.assertEqual(dict(phases['phases'])['pkgconf_static_metadata'],180)
 def test_all_changed_source_parses_and_source_pins_return(self):
  rows=json.loads((ROOT/'SOURCE_PINS.json').read_bytes())['files'];self.assertLessEqual(len(rows),128)
  for row in rows:
   p=ROOT/row['path'];p=p if p.exists() else BASE/row['path'];raw=p.read_bytes();self.assertEqual(len(raw),row['bytes']);self.assertEqual(digest(raw),row['sha256'])
   if row['path'].endswith('.py'):ast.parse(raw)
if __name__=='__main__':unittest.main(verbosity=2)
