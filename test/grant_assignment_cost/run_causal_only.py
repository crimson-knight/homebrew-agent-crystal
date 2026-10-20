"""Run one rich10 causal triplet with an explicit absolute4800-second outer deadline."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from same_job_policy import digest, metadata, need, protect_packet
from stage_grant_sources import stage
from prepare_comparison import prepare
from run_hosted_contrast import qualify, save
from run_serial import complete_return

TOTAL_SECONDS = 4800


def run(args):
    started = time.monotonic()
    absolute_deadline = started + TOTAL_SECONDS
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), 'Fresh absolute owned causal output required')
    args.output.mkdir(parents=True)
    result = dict(format='atlas-grant-causal-only-diagnostic-v104', passed=False, diagnostic_complete=False,
                  maximum_seconds=TOTAL_SECONDS, absolute_deadline=absolute_deadline, model_count=10, repetition=1,
                  ordered_arms=['original', 'candidate', 'restored'],
                  full_arm_seconds=1500, build_limit_seconds=900, same_binary_control_limit_seconds=120,
                  current_300_baseline=dict(executed=False, reason='This separately named causal-only diagnostic executes the rich10 triplet'),
                  historical_300_failure_run_id='39493843606',
                  historical_300_failure_scope='Original300 build reached900 seconds; original group was unverifiable/EPERM and raw build streams were empty; serial rich10 remained unexecuted',
                  full_target_model_counts=[300, 500], actual_target_cells_accepted=0, required_target_cells=144,
                  whole_build_provider_qualified=False, native_loader_closure_qualified=False,
                  shipping_compatibility_accepted=False, memory_savings_accepted=False,
                  causal_launch_admitted=False,
                  scope='Darwin waited-command causal diagnostic; full300/500 acceptance remains separate',
                  supplied_provider_hashes=dict(python_sha256=args.python_sha256, time_sha256=args.time_sha256),
                  outcomes=[])
    protected = {}
    admission = None
    observation = None
    output = args.output / 'results/triplet10'
    save(args.output / 'CAUSAL_ONLY_RESULT.json', result)
    try:
        protected = protect_packet(args.packet_sha256)
        for value in (args.python_sha256, args.time_sha256):
            need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None, 'Exact supplied Python/timing SHA-256 required')
        providers = {'python': dict(path=str(Path(sys.executable).resolve()), supplied_sha256=args.python_sha256),
                     'timing': dict(path='/usr/bin/time', supplied_sha256=args.time_sha256)}
        result['provider_identities'] = providers
        for row in providers.values():
            row['observed_sha256'] = digest(Path(row['path']))
            need(row['observed_sha256'] == row['supplied_sha256'], 'Exact supplied and observed causal provider join required')
            protected[Path(row['path'])] = row['supplied_sha256']
        historical = json.loads((ROOT / 'HISTORICAL_300_FAILURE.json').read_bytes())
        need(historical['run_id'] == '39493843606' and historical['build_limit_seconds'] == 900 and
             historical['serial_rich10_executed'] is False and historical['peak_memory_available'] is False and
             historical['actual_target_cells_accepted'] == 0, 'Exact retained historical300 failure scope required')
        result['historical_300_failure'] = historical
        save(args.output / 'HISTORICAL_300_FAILURE.json', historical)
        admission = metadata(args.sdk_evidence, os.environ)
        result['admitted_same_job'] = admission
        source = args.output / 'private-source'
        result['source_projection'] = stage(ROOT / 'inputs/grant-source-and-frozen-dependencies.tar.gz', source)
        wrapper = Path(admission['providers']['compiler_wrapper']['path'])
        plan = args.output / 'triplet-plan'
        prepare(plan, source / 'grant', wrapper, 'cost-isolation')
        settings = SimpleNamespace(driver=args.driver, plan=plan / 'COMPARISON_PLAN.json', sdk_evidence=args.sdk_evidence,
                                   output=output, source_sha256=digest(ROOT / 'run_hosted_contrast.py'),
                                   plan_sha256=digest(plan / 'COMPARISON_PLAN.json'), python_sha256=args.python_sha256,
                                   time_sha256=args.time_sha256, packet_sha256=args.packet_sha256, models=10, repetition=1)
        need(absolute_deadline - time.monotonic() >= 3 * 1500, 'Three complete original1500-second arm horizons required before launch')
        result['causal_launch_admitted'] = True
        save(args.output / 'CAUSAL_ONLY_RESULT.json', result)
        code = qualify(settings, absolute_deadline=absolute_deadline)
        observation = json.loads((output / 'COMPARISON_RESULT.json').read_bytes())
        result['outcomes'].append(dict(experiment='cost-isolation-rich10-original-candidate-restored', exit_code=code,
                                       diagnostic_complete=observation['diagnostic_complete']))
        save(args.output / 'CAUSAL_ONLY_RESULT.json', result)
        complete_return(observation)
        need(code == 0 and observation['diagnostic_complete'] is True and observation.get('owner_shape_accepted') is True,
             'Complete successful causal diagnostic and assignment owner evidence required')
        need([row['arm'] for row in observation['samples']] == ['original', 'candidate', 'restored'], 'Exactly one original/candidate/restored triplet required')
        result['diagnostic_complete'] = True
        result['passed'] = True
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__, error)
        if observation is None and (output / 'COMPARISON_RESULT.json').is_file():
            try:
                observation = json.loads((output / 'COMPARISON_RESULT.json').read_bytes())
                result['exceptional_comparison_result_retained'] = True
            except Exception as return_error:
                result['exceptional_comparison_return_error'] = '%s: %s' % (type(return_error).__name__, return_error)
    finally:
        errors = []
        if admission is not None:
            try:
                need(metadata(args.sdk_evidence, os.environ) == admission, 'Exact initial same-job SDK admission required at causal return')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        if observation is not None:
            try:
                complete_return(observation)
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        for path, expected in protected.items():
            try:
                need(digest(path) == expected, 'Exact causal executable packet/provider bytes required at return: ' + str(path))
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic() - started
        if errors or result['elapsed_seconds'] > TOTAL_SECONDS:
            result['passed'] = False
            result['diagnostic_complete'] = False
        save(args.output / 'CAUSAL_ONLY_RESULT.json', result)
    return 0 if result['passed'] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'sdk-evidence', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('packet-sha256', 'python-sha256', 'time-sha256'):
        parser.add_argument('--' + name, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
