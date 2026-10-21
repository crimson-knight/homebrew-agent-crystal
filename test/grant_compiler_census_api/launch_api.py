"""Manifest-first API-only observe, reviewed execute, stage, and return entry point."""
import argparse
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent


def main(args):
    # This module is delegated only after the workflow's full physical source
    # preflight. Its own admission repeats that complete roster before imports.
    import importlib.util
    import hashlib
    import json
    import stat
    raw = (ROOT/'SOURCE_PINS.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.packet_sha256:raise RuntimeError('Exact API-only source manifest required before imports')
    rows = json.loads(raw)['files']
    if not 0 < len(rows) <= 128 or len({r['path'] for r in rows}) != len(rows):raise RuntimeError('Finite complete API source roster required')
    for row in rows:
        relative = Path(row['path']); path = ROOT/relative
        if relative.is_absolute() or '..' in relative.parts or str(relative) != row['path'] or path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode):raise RuntimeError('Contained physical API source required')
        body = path.read_bytes()
        if len(body) != row['bytes'] or hashlib.sha256(body).hexdigest() != row['sha256'] or stat.S_IMODE(path.stat().st_mode) != row['mode']:raise RuntimeError('Exact complete API source bytes/modes required')
    def load(name):
        spec = importlib.util.spec_from_file_location('api_only_'+name,ROOT/(name+'.py')); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
    model = load('run_census'); model.manifest(ROOT,args.packet_sha256); helper = load('api_provider')
    if args.operation == 'stage':
        artifact = load('artifact'); artifact.stage(args.source,args.output,args.packet_sha256); model.manifest(ROOT,args.packet_sha256); return 0
    args.python_sha256 = model.sha(model.stable(Path(sys.executable).resolve(),32*2**20))
    started = time.monotonic()
    if args.operation == 'return':
        model.need(args.source.resolve(strict=True) == args.source, 'Physical original API-only evidence root required')
        if (args.source/'CENSUS_PROVIDER_CANDIDATE.json').exists():
            artifact = load('artifact'); candidate_raw = model.stable(args.source/'CENSUS_PROVIDER_CANDIDATE.json',2**20); metadata_raw = model.stable(args.source/'METADATA_ADMISSION.json',4*2**20); static_raw = model.stable(args.source/'LLVM_STATIC_INPUTS.json',16*2**20)
            candidate = model.decode(candidate_raw); metadata = artifact.validate_metadata_candidate(model,candidate,metadata_raw,args.packet_sha256); observation = helper.validate_observation(model,model.decode(static_raw),args.packet_sha256)
            model.need(model.sha(static_raw) == metadata['native_receipt']['receipt_sha256'], 'Exact source-bound additional LLVM observation receipt required')
            _,_,context = helper.fresh(model,args,60); context['check']()
            model.need(observation['SDK'] == context['admitted'] and observation['inputs'] == context['static_inputs'] and candidate['llvm_config'] == context['llvm_config'] and candidate['llvm_config_physical'] == context['llvm_config_physical'], 'Retained API-only provider/source/job/SDK/native facts must equal fresh exact return')
            for name,body in [('CENSUS_PROVIDER_CANDIDATE.json',candidate_raw),('METADATA_ADMISSION.json',metadata_raw),('LLVM_STATIC_INPUTS.json',static_raw)]:model.need(model.stable(args.source/name,16*2**20) == body, 'Original source-bound static observation bytes must return')
        else:
            result = model.decode(model.stable(args.source/'RESULT.json'))
            model.need(all(result[k] is True for k in ('source_provider_return_accepted','writers_confirmed_retired','private_removed')) and result['finalization_errors'] == [], 'All API/compiler writers, source/providers and private projection must return before transferred tool retirement')
            context = helper.admit(model,args,returning=True,maximum_seconds=60); context['check']()
            model.need(result['job_identity'] == context['admitted']['job_identity'] and result['compiler_profile_sha256'] == context['admitted']['observed_profile_sha256'], 'Exact API result/current SDK return join required')
        model.manifest(ROOT,args.packet_sha256); model.clock(started+60); return 0
    owned = model.Owned(args.output)
    if args.operation == 'cleanup':return helper.cleanup(model,args,owned)
    if args.operation == 'observe':return helper.observe(model,args,owned)
    try:
        context = helper.admit(model,args); context['phase_deadline'] = started+model.OUTER_SECONDS
        static_receipt = helper.observation_record(model,args,context,started); helper.validate_observation(model,static_receipt,args.packet_sha256)
        owned.json('LLVM_STATIC_INPUTS.json',static_receipt); context['protected'][owned.root/'LLVM_STATIC_INPUTS.json'] = model.sha(model.stable(owned.root/'LLVM_STATIC_INPUTS.json',16*2**20))
        code = model.execute(args,context,owned,started)
        model.manifest(ROOT,args.packet_sha256)
        return code
    except BaseException as error:
        owned.json('ADMISSION_REFUSAL.json',dict(format='atlas-census-api-only-admission-refusal-v1',passed=False,error=type(error).__name__+': '+str(error),elapsed_seconds=time.monotonic()-started,actual_target_cells_accepted=0))
        return 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('operation',choices=('observe','execute','stage','return','cleanup'))
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','policies','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--packet-sha256',required=True); parser.add_argument('--decision',type=Path); parser.add_argument('--decision-sha256'); parser.add_argument('--source',type=Path)
    raise SystemExit(main(parser.parse_args()))
