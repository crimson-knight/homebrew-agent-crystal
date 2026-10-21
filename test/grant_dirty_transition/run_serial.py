"""Run original300 then one rich10 triplet within a finite6600-second diagnostic."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from same_job_policy import digest, metadata, need, protect_packet
from stage_grant_sources import stage
from prepare_comparison import prepare
from prepare_baseline import prepare_baseline
from run_hosted_contrast import qualify, save

TOTAL_SECONDS = 6600


def complete_return(result):
    need(not result['finalization_errors'], 'Exact source/provider restoration required before the next experiment')
    for sample in result['samples']:
        terminal = sample['terminal_runner_state']
        need(terminal['writers_confirmed_retired'] is True and all(row['status'] == 'absent' for row in terminal['original_group_observations']), 'Actual Runner terminal writers and original groups must be verified absent before the next experiment')
        need(all(row['writers_confirmed_retired'] is True and row['terminal_group_observation']['status'] == 'absent' for row in sample['commands']), 'Every prior actual command original group must be absent before the next experiment')


def run(args):
    started = time.monotonic()
    protected = protect_packet(args.packet_sha256)
    admission = metadata(args.sdk_evidence, os.environ)
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), 'Fresh absolute owned serial output required')
    args.output.mkdir(parents=True)
    result = dict(format='atlas-grant-serial-diagnostic-v1', passed=False, maximum_seconds=TOTAL_SECONDS,
                  ordered_experiments=['original300-feasibility-baseline', 'cost-isolation-rich10-original-candidate-restored'],
                  actual_target_cells_accepted=0, required_target_cells=144,
                  whole_build_provider_qualified=False, native_loader_closure_qualified=False, outcomes=[])
    try:
        source = args.output / 'private-source'
        result['source_projection'] = stage(ROOT / 'inputs/grant-source-and-frozen-dependencies.tar.gz', source)
        wrapper = Path(admission['providers']['compiler_wrapper']['path'])
        baseline = args.output / 'baseline-plan'
        triplet = args.output / 'triplet-plan'
        prepare_baseline(baseline, source / 'grant', wrapper)
        prepare(triplet, source / 'grant', wrapper)
        for name, plan, models, horizon in [('baseline300', baseline, 300, 1500), ('triplet10', triplet, 10, 4800)]:
            remaining = TOTAL_SECONDS - (time.monotonic() - started)
            need(remaining >= horizon + (4800 if name == 'baseline300' else 0), 'Complete unchanged experiment horizons required before launch')
            output = args.output / 'results' / name
            settings = SimpleNamespace(driver=args.driver, plan=plan / 'COMPARISON_PLAN.json', sdk_evidence=args.sdk_evidence, output=output,
                                       source_sha256=digest(ROOT / 'run_hosted_contrast.py'), plan_sha256=digest(plan / 'COMPARISON_PLAN.json'),
                                       python_sha256=args.python_sha256, time_sha256=args.time_sha256, packet_sha256=args.packet_sha256,
                                       models=models, repetition=1)
            code = qualify(settings)
            observation = json.loads((output / 'COMPARISON_RESULT.json').read_bytes())
            result['outcomes'].append(dict(experiment=name, exit_code=code, diagnostic_complete=observation['diagnostic_complete']))
            save(args.output / 'SERIAL_RESULT.json', result)
            complete_return(observation)
        result['passed'] = all(row['exit_code'] == 0 for row in result['outcomes'])
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__, error)
    finally:
        errors = []
        try:
            need(metadata(args.sdk_evidence, os.environ) == admission, 'Exact initial same-job SDK admission required at serial return')
        except Exception as error:
            errors.append('%s: %s' % (type(error).__name__, error))
        for path, expected in protected.items():
            try:
                need(digest(path) == expected, 'Exact serial executable packet source required at return')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic() - started
        if errors or result['elapsed_seconds'] > TOTAL_SECONDS:
            result['passed'] = False
        save(args.output / 'SERIAL_RESULT.json', result)
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
