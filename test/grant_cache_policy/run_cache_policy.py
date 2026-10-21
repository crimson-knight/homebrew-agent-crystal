"""Execute one finite same-source rich10 compiler-cache contrast."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'grant_assignment_cost'
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(ROOT))
from cache_evidence import BASE_PACKET, digest, need, protect
from same_job_policy import metadata, protect_packet
from stage_grant_sources import stage
from timing_profile import calibrate, complete_return as calibration_return, canonical_sha
from prepare_cache_comparison import prepare
from cache_contrast import qualify, save
from run_serial import complete_return


def run(args):
    started = time.monotonic()
    deadline = started + 4800
    protected = protect(args.cache_packet_sha256)
    protected.update(protect_packet(BASE_PACKET))
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), 'Fresh absolute cache-policy output required')
    args.output.mkdir(parents=True)
    result = dict(format='atlas-grant-cache-policy-v1', passed=False, diagnostic_complete=False,
                  maximum_seconds=4800, absolute_deadline=deadline, ordered_arms=['original', 'candidate', 'restored'],
                  model_count=10, repetition=1, unchanged_source=True, target_cells_accepted=0, required_target_cells=144,
                  memory_savings_accepted=False, whole_build_provider_qualified=False, isolated_compiler_peak_qualified=False,
                  finalization_errors=[], scope='One cold default/disabled/default cache-policy diagnostic')
    admission = calibration = comparison = None
    comparison_path = args.output / 'comparison/COMPARISON_RESULT.json'
    save(args.output / 'CACHE_POLICY_RESULT.json', result)
    try:
        for path, expected in [(Path(sys.executable).resolve(), args.python_sha256), (Path('/usr/bin/time'), args.time_sha256), (Path('/usr/bin/true'), args.timing_true_sha256)]:
            need(digest(path) == expected, 'Exact supplied observation provider required')
            protected[path] = expected
        admission = metadata(args.sdk_evidence, os.environ)
        result['admitted_same_job'] = admission
        source = args.output / 'private-source'
        result['source_projection'] = stage(BASE / 'inputs/grant-source-and-frozen-dependencies.tar.gz', source)
        plan = args.output / 'plan'
        prepare(plan, source / 'grant', Path(admission['providers']['compiler_wrapper']['path']))
        calibration = calibrate(args.output / 'timing-calibration', args.driver, args.time_sha256,
                                args.timing_true_sha256, admission['job_identity'], deadline)
        calibration_return(calibration, args.output / 'timing-calibration')
        result['timing_calibration'] = calibration
        result['timing_profile_sha256'] = canonical_sha(calibration['profile'])
        result['timing_calibration_files'] = {}
        for name in ('CALIBRATION_RESULT.json', 'TIMING_PROFILE.json', 'COMMANDS.json', 'probe.stdout.txt', 'probe.stderr.txt'):
            path = args.output / 'timing-calibration' / name
            result['timing_calibration_files'][name] = dict(bytes=path.stat().st_size, sha256=digest(path))
            protected[path] = digest(path)
        need(deadline - time.monotonic() >= 4500, 'Three complete original1500-second arms required')
        settings = SimpleNamespace(driver=args.driver, plan=plan / 'COMPARISON_PLAN.json', sdk_evidence=args.sdk_evidence,
            output=args.output / 'comparison', source_sha256=digest(ROOT / 'cache_contrast.py'), plan_sha256=digest(plan / 'COMPARISON_PLAN.json'),
            python_sha256=args.python_sha256, time_sha256=args.time_sha256, timing_true_sha256=args.timing_true_sha256,
            packet_sha256=BASE_PACKET, cache_packet_sha256=args.cache_packet_sha256, models=10, repetition=1)
        code = qualify(settings, absolute_deadline=deadline, timing_profile=calibration['profile'])
        comparison = json.loads(comparison_path.read_bytes())
        complete_return(comparison)
        need(code == 0 and comparison['diagnostic_complete'] is True and comparison['owner_shape_accepted'] is True
             and comparison['cache_policy_mechanism_accepted'] is True and comparison['assignment_owner_parity']['passed'] is True,
             'Complete source/owner/behavior/cache-policy contrast required')
        result['comparison_sha256'] = digest(comparison_path)
        result['diagnostic_complete'] = result['passed'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if comparison is None and comparison_path.is_file():
            try:
                comparison = json.loads(comparison_path.read_bytes())
            except Exception as error:
                result['finalization_errors'].append('Comparison return: ' + str(error))
        checks = []
        if comparison is not None:
            checks.append(lambda: complete_return(comparison))
        if calibration is not None:
            checks.append(lambda: calibration_return(calibration, args.output / 'timing-calibration'))
        if admission is not None:
            checks.append(lambda: need(metadata(args.sdk_evidence, os.environ) == admission, 'Same-job SDK admission changed'))
        for check in checks:
            try:
                check()
            except Exception as error:
                result['finalization_errors'].append(type(error).__name__ + ': ' + str(error))
        for path, expected in protected.items():
            try:
                need(digest(path) == expected, 'Protected cache source/provider changed: ' + str(path))
            except Exception as error:
                result['finalization_errors'].append(type(error).__name__ + ': ' + str(error))
        result['elapsed_seconds'] = time.monotonic() - started
        if result['finalization_errors'] or result['elapsed_seconds'] > 4800:
            result['passed'] = result['diagnostic_complete'] = False
        save(args.output / 'CACHE_POLICY_RESULT.json', result)
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['driver', 'sdk-evidence', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['cache-packet-sha256', 'python-sha256', 'time-sha256', 'timing-true-sha256']:
        parser.add_argument('--' + name, required=True)
    raise SystemExit(run(parser.parse_args()))
