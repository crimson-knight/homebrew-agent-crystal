"""Focused guarded full-compiler selection, ordering, and failed-command return controls."""
import copy,hashlib,importlib.util,json,os,shutil,sys,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT));import test_census as original;import run_census as subject;import artifact;import launch_api
class V104Controls(original.CensusControls):
 def timeout(self):
  self.scenario='timeout';old=self.context['driver'].Runner
  class TimeoutRunner(old):
   def run(runner,label,*a,**k):
    try:return super().run(label,*a,**k)
    finally:
     if label=='api-0':
      row=runner.records[-1];row.update(exit_code=-9,expected_exit=0,elapsed_seconds=120.04,refusal='Command exceeded its time budget')
      for stream in ('stdout','stderr'):(runner.output/(label+'.'+stream+'.txt')).write_bytes(b'');row[stream+'_sha256']=subject.sha(b'')
  self.context['driver']=SimpleNamespace(Runner=TimeoutRunner);return self.perform()
 def return_case(self):
  calls=[];real=importlib.util.spec_from_file_location
  def prepared(name,path,*a,**k):
   spec=real(name,path,*a,**k)
   if Path(path)==ROOT/'api_provider.py':
    execute=spec.loader.exec_module
    def load(module):
     execute(module)
     def admit(*a,**k):
      self.assertEqual(k,dict(returning=True,maximum_seconds=60));calls.append('fresh');return dict(admitted=self.admission,check=lambda:calls.append('check'))
     module.admit=admit
    spec.loader.exec_module=load
   return spec
  with patch.object(importlib.util,'spec_from_file_location',side_effect=prepared):code=launch_api.main(SimpleNamespace(operation='return',source=self.args.output,packet_sha256=self.args.packet_sha256))
  self.assertEqual(calls,['fresh','check']);return code
 def test_v104_exact_full_compiler_entry_and_original_roster(self):
  project=self.root/'canonical';before=subject.extract_project(project,time.monotonic()+60);expected={k:{x:v for x,v in row.items() if x!='physical_identity'} for k,row in before['files'].items()};self.assertEqual(len(expected),3190);self.assertEqual(subject.sha((project/subject.DOCS_ENTRY).read_bytes()),subject.DOCS_ENTRY_SHA);data=subject.configure_docs(project,expected);self.assertEqual(len(expected),3193);self.assertEqual(data['docs_entry'],'src/compiler/requires.cr');self.assertEqual(data['configuration_path'],'.amber-lsp/api/compiler-census.yml');self.assertEqual((project/subject.DOCS_CARD_PATH).read_bytes(),(ROOT/'inputs/CENSUS_DOCS_CARD.yml').read_bytes());after=subject.physical_tree(project,expected,time.monotonic()+60)
  for path,row in before['files'].items():self.assertEqual(after['files'][path],row)
 def test_v104_config_input_corrupt_restore(self):
  source=self.root/'config source';(source/'inputs').mkdir(parents=True);p=source/'inputs/CENSUS_DOCS_CARD.yml';raw=(ROOT/'inputs/CENSUS_DOCS_CARD.yml').read_bytes();p.write_bytes(raw.replace(b'compiler/requires.cr',b'compiler/changed.cr'));project=self.root/'project';project.mkdir()
  with patch.object(subject,'ROOT',source),self.assertRaisesRegex(RuntimeError,'source-pinned full-compiler docs'):subject.configure_docs(project,{})
  self.assertEqual(list(project.iterdir()),[]);p.write_bytes(raw)
  with patch.object(subject,'ROOT',source):self.assertEqual(subject.configure_docs(project,{})['configuration_sha256'],subject.sha(raw))
 def test_v104_config_return_changed_then_restored(self):
  project=self.root/'project';project.mkdir();expected={};subject.configure_docs(project,expected);p=project/subject.DOCS_CARD_PATH;raw=p.read_bytes();p.write_bytes(raw[:-1]+b'x')
  with self.assertRaisesRegex(RuntimeError,'source hash'):subject.physical_tree(project,expected,time.monotonic()+10)
  p.write_bytes(raw);self.assertEqual(set(subject.physical_tree(project,expected,time.monotonic()+10)['files']),set(expected))
 def test_v104_order_protocol_exact_horizons(self):
  rows=subject.command_roster();self.assertEqual(len(rows),123);self.assertEqual(sum(x[1] for x in rows),2280);self.assertEqual([r[0] for r in rows[:11]],['llvm-config-version','amber-lsp-version','ameba-version']+['format-'+n for n in subject.PROBES]+['compatibility-'+n for n in subject.PROBES]);self.assertEqual(rows[11],('api-0',120));self.assertEqual((subject.OUTER_SECONDS,subject.PREPARATION_SECONDS,subject.RETURN_SECONDS),(2700,120,180));self.assertIn('formatter and concrete receiver probes',subject.CONTEXT['execution_order'])
 def test_v104_positive_command_order_and_public_reader(self):
  code,result=self.perform(real_archive=True);self.assertEqual(code,0);rows=[json.loads(x) for x in (self.args.output/'COMMAND_EVIDENCE.jsonl').read_bytes().splitlines()];self.assertEqual([r['record']['label'] for r in rows[:12]],[r[0] for r in subject.command_roster()[:12]]);self.assertTrue(result['command_contracts_accepted']);self.assertEqual(result['command_failures'],[]);public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256);self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
 def test_v104_timeout_keeps_original_failure_and_completed_probes(self):
  code,result=self.timeout();self.assertEqual(code,2);self.assertFalse(result['passed']);self.assertFalse(result['diagnostic_collection_complete']);self.assertTrue(result['compatibility_collection_complete']);self.assertEqual(result['compiler_color'],'GREEN');self.assertEqual(result['commands'],12);self.assertEqual(len(result['command_failures']),1);kept=result['command_failures'][0];self.assertEqual(kept['label'],'api-0');self.assertEqual(kept['original_record']['exit_code'],-9);self.assertEqual(kept['original_record']['expected_exit'],0);self.assertEqual(kept['original_record']['refusal'],'Command exceeded its time budget');self.assertIn('Command exceeded its time budget',result['error']);self.assertNotIn('Known released lookup status',result['error']);self.assertTrue(result['writers_confirmed_retired']);self.assertTrue(result['source_provider_return_accepted']);self.assertTrue(result['private_removed']);self.assertEqual(result['finalization_errors'],[]);self.assertEqual(json.loads((self.args.output/'API_CARDS.json').read_bytes()),[])
 def test_v104_timeout_public_reader_keeps_full_census_refused(self):
  self.timeout();public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256)
  with self.assertRaisesRegex(RuntimeError,'Actual successful complete GREEN'):artifact.replay(public,self.args.packet_sha256)
 def test_v104_timeout_returns_providers_before_transfer_cleanup(self):
  self.timeout();self.assertEqual(self.return_case(),0)
 def test_v104_timeout_missing_private_return_stops_transfer_cleanup(self):
  self.timeout();p=self.args.output/'RESULT.json';v=json.loads(p.read_bytes());v['private_removed']=False;p.write_bytes(subject.canonical(v))
  with self.assertRaisesRegex(RuntimeError,'before transferred tool retirement'):self.return_case()
 def test_v104_timeout_missing_source_return_stops_transfer_cleanup(self):
  self.timeout();p=self.args.output/'RESULT.json';v=json.loads(p.read_bytes());v['source_provider_return_accepted']=False;p.write_bytes(subject.canonical(v))
  with self.assertRaisesRegex(RuntimeError,'before transferred tool retirement'):self.return_case()
 def test_v104_original_writer_return_rejects_changed_raw(self):
  self.timeout();row=self.runners[-1].records[-1];p=self.args.output/'api-0.stdout.txt';p.write_bytes(b'x');contract=subject.load(ROOT/'vendor/command_contract.py',subject.CONTRACT_SHA,'v104_actual_return_reader')
  with self.assertRaisesRegex(RuntimeError,'stream hash'):subject.validate_writer_return(contract,row,120,self.args.output,row['terminal_group_observation'])
 def test_v104_original_writer_return_rejects_missing_group(self):
  self.timeout();row=copy.deepcopy(self.runners[-1].records[-1]);row['terminal_group_observation']['status']='present';contract=subject.load(ROOT/'vendor/command_contract.py',subject.CONTRACT_SHA,'v104_missing_group_reader')
  with self.assertRaisesRegex(RuntimeError,'group return'):subject.validate_writer_return(contract,row,120,self.args.output,row['terminal_group_observation'])
 def test_v104_original_writer_return_rejects_expected_change(self):
  self.timeout();row=copy.deepcopy(self.runners[-1].records[-1]);row['expected_exit']=-9;contract=subject.load(ROOT/'vendor/command_contract.py',subject.CONTRACT_SHA,'v104_expected_return_reader')
  with self.assertRaisesRegex(RuntimeError,'expected/actual'):subject.validate_writer_return(contract,row,120,self.args.output,row['terminal_group_observation'])
 def test_v104_exact_original_assertion_bodies(self):
  # Original test modules are byte-bound as independent ancestry in the review packet.
  self.assertEqual(subject.sha((ROOT/'test_census.py').read_bytes()),'51ada1e68769af7a3ec0f3032e4b7af9ce2128240c1f745f844ab3092b9b45b9')
 def test_v104_public_resealed_docs_selector_change_refuses(self):
  self.perform(real_archive=True);public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256);p=public/'DOCS_CONFIGURATION.json';v=json.loads(p.read_bytes());v['docs_entry']='src/gc.cr';p.write_bytes(subject.canonical(v));v=json.loads((public/'PUBLIC_STAGE.json').read_bytes())
  for row in v['files']:p=public/row['path'];row.update(bytes=p.stat().st_size,sha256=subject.sha(p.read_bytes()))
  (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(v))
  with self.assertRaisesRegex(RuntimeError,'full-compiler docs configuration'):artifact.replay(public,self.args.packet_sha256)
 def test_v104_resealed_docs_physical_kind_refuses(self):
  self.perform(real_archive=True);public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256);p=public/'SOURCE_RETURN.json';v=json.loads(p.read_bytes());v['files'][subject.DOCS_CARD_PATH]['physical_identity'][2]=0o040644;p.write_bytes(subject.canonical(v));v=json.loads((public/'PUBLIC_STAGE.json').read_bytes())
  for row in v['files']:p=public/row['path'];row.update(bytes=p.stat().st_size,sha256=subject.sha(p.read_bytes()))
  (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(v))
  with self.assertRaisesRegex(RuntimeError,'configuration node kind/mode'):artifact.replay(public,self.args.packet_sha256)
 def test_v104_observed_selected_root_and_broad_root_discriminate(self):
  row=dict(cwd='/canonical',original_arguments=['docs','--format=json',subject.DOCS_ENTRY],project_role='canonical-project',source_resolutions={subject.DOCS_ENTRY:'/canonical/'+subject.DOCS_ENTRY})
  selected=subject.docs_selection_evidence([row],'/canonical');self.assertTrue(selected['matches']);self.assertTrue(selected['observed']);self.assertEqual(selected['canonical_docs_pre_exec_count'],1)
  row['original_arguments'].append('src/gc.cr');row['source_resolutions']['src/gc.cr']='/canonical/src/gc.cr';self.assertFalse(subject.docs_selection_evidence([row],'/canonical')['matches'])
 def test_v104_configuration_only_selection_remains_unobserved(self):
  value=subject.docs_selection_evidence([], '/canonical');self.assertTrue(value['matches']);self.assertFalse(value['observed']);self.assertEqual(value['canonical_docs_pre_exec_count'],0)
 def test_v104_resealed_observed_wrong_docs_root_refuses_reader(self):
  self.perform(real_archive=True);public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256);config=json.loads((public/'PROXY_CONFIG.json').read_bytes());journal=[json.loads(x) for x in (public/'PROXY_COMMANDS.jsonl').read_bytes().splitlines()];row=copy.deepcopy(journal[0]);row.update(original_arguments=['docs','--format=json',subject.DOCS_ENTRY],source_resolutions={subject.DOCS_ENTRY:config['project']+'/'+subject.DOCS_ENTRY},pid=999999,process_group=self.runners[-1].records[11]['original_group']);row['executed_arguments']=[config['backend'],*original.proxy.derive(row['original_arguments'],config['project'],config['stdlib'],config['project'])];journal.append(row)
  def seal():
   (public/'PROXY_COMMANDS.jsonl').write_bytes(b''.join(subject.canonical(row)+b'\n' for row in journal));selection=subject.docs_selection_evidence(journal,config['project']);(public/'DOCS_SELECTION.json').write_bytes(subject.canonical(selection));v=json.loads((public/'RESULT.json').read_bytes());v.update(docs_selection_matches=selection['matches'],docs_selection_observed=selection['observed']);(public/'RESULT.json').write_bytes(subject.canonical(v));stage=json.loads((public/'PUBLIC_STAGE.json').read_bytes())
   for value in stage['files']:p=public/value['path'];value.update(bytes=p.stat().st_size,sha256=subject.sha(p.read_bytes()))
   (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(stage))
  seal();self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed']);row['original_arguments'][-1]='src/gc.cr';row['source_resolutions']={'src/gc.cr':config['project']+'/src/gc.cr'};row['executed_arguments']=[config['backend'],*original.proxy.derive(row['original_arguments'],config['project'],config['stdlib'],config['project'])];seal()
  with self.assertRaisesRegex(RuntimeError,'Every observed canonical docs'):artifact.replay(public,self.args.packet_sha256)
 def test_v104_role_cwd_join_precedes_selected_root_and_restores(self):
  self.perform(real_archive=True);public=self.root/'public';artifact.stage(self.args.output,public,self.args.packet_sha256);config=json.loads((public/'PROXY_CONFIG.json').read_bytes());journal=[json.loads(x) for x in (public/'PROXY_COMMANDS.jsonl').read_bytes().splitlines()];row=copy.deepcopy(journal[0]);row.update(original_arguments=['docs','--format=json','src/gc.cr'],source_resolutions={'src/gc.cr':config['project']+'/src/gc.cr'},project_role='released-library-docs-workspace',pid=999999,process_group=self.runners[-1].records[11]['original_group']);row['executed_arguments']=[config['backend'],*original.proxy.derive(row['original_arguments'],config['project'],config['stdlib'],config['project'])];journal.append(row)
  def write(selection):
   (public/'PROXY_COMMANDS.jsonl').write_bytes(b''.join(subject.canonical(item)+b'\n' for item in journal));(public/'DOCS_SELECTION.json').write_bytes(subject.canonical(selection));result=json.loads((public/'RESULT.json').read_bytes());result.update(docs_selection_matches=selection['matches'],docs_selection_observed=selection['observed']);(public/'RESULT.json').write_bytes(subject.canonical(result));projection=json.loads((public/'PUBLIC_STAGE.json').read_bytes())
   for item in projection['files']:p=public/item['path'];item.update(bytes=p.stat().st_size,sha256=subject.sha(p.read_bytes()))
   (public/'PUBLIC_STAGE.json').write_bytes(subject.canonical(projection))
  write(subject.docs_selection_evidence([],config['project']))
  with self.assertRaisesRegex(RuntimeError,'cwd/role join'):artifact.replay(public,self.args.packet_sha256)
  row.update(project_role='canonical-project',original_arguments=['docs','--format=json',subject.DOCS_ENTRY],source_resolutions={subject.DOCS_ENTRY:config['project']+'/'+subject.DOCS_ENTRY});row['executed_arguments']=[config['backend'],*original.proxy.derive(row['original_arguments'],config['project'],config['stdlib'],config['project'])];write(subject.docs_selection_evidence(journal,config['project']));self.assertTrue(artifact.replay(public,self.args.packet_sha256)['passed'])
 def test_v104_probes_and_all_original_questions_preserved(self):
  roster=json.loads((ROOT/'API_ROSTER.json').read_bytes());self.assertEqual(len(roster['queries']),56);self.assertEqual(len(subject.PROBES),4);self.assertEqual(subject.CANONICAL_GC_SHA,'526f1819cfc10f3a97a62da8c0dab11116c4e48bcc07c59903ee562a2f7ed307')
def load_tests(loader,tests,pattern):return unittest.TestSuite(V104Controls(n) for n in sorted(V104Controls.__dict__) if n.startswith('test_v104_'))
if __name__=='__main__':unittest.main(verbosity=2)
