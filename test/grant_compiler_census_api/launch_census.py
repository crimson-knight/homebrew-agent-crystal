"""Installed-layout entry point after externally pinned census source preflight."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent

def need(value,message):
    if not value:raise RuntimeError(message)

def protect(expected):
    raw = (ROOT/'SOURCE_PINS.json').read_bytes(); need(hashlib.sha256(raw).hexdigest() == expected, 'Exact externally selected census manifest required before every import')
    rows = json.loads(raw)['files']; need(0 < len(rows) <= 128 and len({row['path'] for row in rows}) == len(rows), 'Finite complete execution roster required')
    for row in rows:
        rel = PurePosixPath(row['path']); need(str(rel) == row['path'] and not rel.is_absolute() and '..' not in rel.parts, 'Contained exact executable member required')
        path = ROOT/rel; need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'Physical source required before import'); value = path.read_bytes()
        need(len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'], 'Exact executable source bytes required')
        if 'mode' in row:need(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'Exact executable source mode required')
    return {row['path']:row['sha256'] for row in rows}

def metadata_return(model, args, values):
    need(args.source.is_absolute() and args.source.resolve(strict=True) == args.source, 'Physical original census evidence root required before return')
    artifact = model.load(ROOT/'artifact.py',protect(args.packet_sha256)['artifact.py'],'installed_census_metadata_return_validator')
    candidate_raw = model.stable(args.source/'CENSUS_PROVIDER_CANDIDATE.json',2**20); metadata_raw = model.stable(args.source/'METADATA_ADMISSION.json',4*2**20)
    candidate = model.decode(candidate_raw); admitted = artifact.validate_metadata_candidate(model,candidate,metadata_raw,args.packet_sha256)
    values.operation = 'observe'; context = model.admit_observation(values); context['check']()
    need(admitted['SDK'] == context['admitted'] and admitted['native_receipt'] == context['metadata_native_receipt'], 'Retained metadata SDK/native source receipt must equal fresh same-job admission')
    need(candidate['llvm_config'] == context['llvm_config'] and candidate['llvm_config_physical'] == context['llvm_config_physical'] and candidate['native_stable_view_sha256'] == context['native_materialization']['stable_view_sha256'], 'Retained descriptor/physical/stable view must equal actual current inputs')
    need(model.stable(args.source/'CENSUS_PROVIDER_CANDIDATE.json',2**20) == candidate_raw and model.stable(args.source/'METADATA_ADMISSION.json',4*2**20) == metadata_raw, 'Complete retained metadata return bytes required')
    protect(args.packet_sha256); return 0

def main(args):
    started = time.monotonic(); protect(args.packet_sha256)
    spec = importlib.util.spec_from_file_location('installed_census_source_authority',ROOT/'run_census.py'); model = importlib.util.module_from_spec(spec); spec.loader.exec_module(model)
    model.manifest(ROOT,args.packet_sha256)
    if args.operation == 'stage':
        artifact = model.load(ROOT/'artifact.py',protect(args.packet_sha256)['artifact.py'],'installed_census_safe_stager')
        artifact.stage(args.source,args.output,args.packet_sha256); protect(args.packet_sha256); return 0
    values = argparse.Namespace(**vars(args)); values.python_sha256 = model.sha(model.stable(Path(sys.executable).resolve(),32*2**20))
    values.provider_packet = ROOT/'dependencies/provider_v101'; values.feedback_packet = ROOT/'dependencies/feedback_v101'; values.native_observation = args.sdk_evidence.parent/'native-provider-observation'
    if args.operation == 'observe':return model.main(values)
    if args.operation == 'return' and (args.source/'CENSUS_PROVIDER_CANDIDATE.json').exists():
        code = metadata_return(model,args,values); model.clock(started+60); return code
    material = model.decode(model.stable(args.policies/'POLICY_RESULT.json',2**20))
    need(material['passed'] is True and material['execution_admitted'] is True and material['finalization_errors'] == [], 'Actual fresh native materializer must finish before this separate lane')
    values.policy_result = args.policies/'POLICY_RESULT.json'; values.policy_result_sha256 = model.sha(model.stable(values.policy_result))
    for field,name in [('native_policy','NATIVE_POLICY.json'),('tool_policy','TOOL_POLICY.json'),('proof_tools','PROOF_TOOLS.json')]:
        path = args.policies/name; expected = material['policies'][name]; need(model.sha(model.stable(path,2**20)) == expected, 'Exact fresh materialized policy/registry input required'); setattr(values,field,path); setattr(values,field+'_sha256',expected)
    if args.operation == 'return':
        result = model.decode(model.stable(args.source/'RESULT.json',2**20)) if (args.source/'RESULT.json').exists() else model.decode(model.stable(args.source/'CENSUS_PROVIDER_CANDIDATE.json',2**20))
        need(result['source_provider_return_accepted'] is True, 'Complete census source/provider return required before tool retirement')
        if result['format'] == 'atlas-compiler-census-api-result-v1':
            need(result['writers_confirmed_retired'] is True and result['private_removed'] is True and result['finalization_errors'] == [], 'Every census compiler/API writer and private projection must retire before tool cleanup')
        else:need(result['format'] == 'atlas-census-provider-candidate-v1' and result['execution_admitted'] is False and result['actual_compiler_commands'] == 0, 'Metadata-only census candidate return required')
        values.operation = 'execute'; context = model.admit(values); context['check'](); model.clock(started+60); protect(args.packet_sha256); return 0
    return model.main(values)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('operation',choices=('observe','execute','stage','return'))
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','feedback-packet','policies','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--packet-sha256',required=True); parser.add_argument('--decision',type=Path); parser.add_argument('--decision-sha256'); parser.add_argument('--source',type=Path)
    raise SystemExit(main(parser.parse_args()))
