from pathlib import Path
import argparse,copy,importlib.util,json
HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();args.output.mkdir()
spec=importlib.util.spec_from_file_location('peer_native_cases',HERE/'packet/test_probe.py');cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
findings=[]
for mutation in ['native_after','source_return','stdlib_after','source_feedback','source_gate']:
 case=cases.ProbeTests();case.setUp()
 try:
  code,settings=case.execute()
  if code!=0:raise RuntimeError('Complete modeled positive fixture required')
  source=settings.output
  if mutation=='native_after':cases.probe.write(source/'NATIVE_AFTER.json',{'SYNTHETIC_CHANGED_NATIVE_PROVIDER':True})
  elif mutation=='source_return':cases.probe.write(source/'SOURCE_RETURN.json',{'source_inputs_restored_exact':False})
  elif mutation=='stdlib_after':cases.probe.write(source/'STDLIB_AFTER.json',{'SYNTHETIC_CHANGED_STDLIB':True})
  elif mutation=='source_feedback':(source/'source_feedback/feedback.txt').write_text('SYNTHETIC altered actual feedback bytes\n')
  else:
   p=source/'SOURCE_GATES.json';v=cases.probe.read(p);v['source_sha256']['buffer_probe.cr.txt']='0'*64;cases.probe.write(p,v)
  receipt=cases.stage_module.stage(source,case.root/'public',cases.probe.digest(HERE/'packet/SOURCE_PINS.json'))
  findings.append(dict(case=mutation,accepted=True,native_probe_complete=receipt['native_probe_complete'],staged_files=len(receipt['files'])))
 finally:case.tearDown()
v=cases.native_result('fixed','counts','SYNTHETIC LLVM')
for row in v['snapshots']:row['counters'][cases.probe.COUNTERS.index('peak_caller_owned_bytes')]=0
accepted=cases.probe.validate_result(v,'fixed','counts','SYNTHETIC LLVM')
findings.append(dict(case='zero_peak_with_known64MiB_outstanding',accepted=bool(accepted)))
value=dict(format='atlas-native-buffer-independent-sensitivities-v1',findings=findings,guard_calls=cases.GUARD_CALLS,actual_compiler_C_LLVMI_native_calls=0)
cases.probe.write(args.output/'SENSITIVITIES.json',value);print(json.dumps(value))
