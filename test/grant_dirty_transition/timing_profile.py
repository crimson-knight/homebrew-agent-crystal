"""Calibrate one exact Darwin timing roster with a bounded same-job positive probe."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from gc_contract import TIME_FIELDS

HARDWARE_FIELDS = ('instructions retired', 'cycles elapsed')
COMMON_FIELDS = tuple(label for label in TIME_FIELDS if label not in HARDWARE_FIELDS)
FORMAT = 'atlas-darwin-timing-field-profile-v1'
DRIVER_SHA256 = 'dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
CALIBRATION_SECONDS = 30
PROBE_SECONDS = 10
RAW_BYTES = 4 * 2**20
PROBE_ARGV = ['/usr/bin/time', '-l', '/usr/bin/true']


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    path = Path(path)
    need(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Regular exact timing provider/source required: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def exact_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_profile(profile, time_sha256=None, true_sha256=None, job_identity=None):
    need(type(profile) is dict and set(profile) == {'format', 'timing_provider', 'probe_provider', 'job_identity',
         'ordered_fields', 'unavailable_hardware_fields', 'calibration_evidence_sha256'}, 'Exact timing profile structure required')
    need(profile['format'] == FORMAT, 'Exact timing profile version required')
    for name, path, expected in [('timing_provider', '/usr/bin/time', time_sha256), ('probe_provider', '/usr/bin/true', true_sha256)]:
        row = profile[name]
        need(type(row) is dict and set(row) == {'path', 'sha256'} and row['path'] == path and exact_sha(row['sha256']),
             'Exact timing profile provider identity required: ' + name)
        if expected is not None:
            need(row['sha256'] == expected, 'Timing profile differs from the supplied provider: ' + name)
    need(type(profile['job_identity']) is dict and bool(profile['job_identity']), 'Same-job timing profile identity required')
    if job_identity is not None:
        need(profile['job_identity'] == job_identity, 'Timing profile differs from the admitted same-job identity')
    fields = profile['ordered_fields']
    need(type(fields) is list and (fields == list(TIME_FIELDS) or fields == list(COMMON_FIELDS)),
         'Complete exact ordered common timing roster and joint optional hardware pair required')
    unavailable = [] if fields == list(TIME_FIELDS) else list(HARDWARE_FIELDS)
    need(profile['unavailable_hardware_fields'] == unavailable and exact_sha(profile['calibration_evidence_sha256']),
         'Explicit exact unavailable hardware fields and calibration evidence digest required')
    return tuple(fields)


def parse_exact(raw, fields):
    lines = raw.splitlines()
    need(len(lines) == 1 + len(fields), 'Complete calibrated Darwin timing line count required')
    duration = re.fullmatch(r' *(\d+\.\d{2}) real +(\d+\.\d{2}) user +(\d+\.\d{2}) sys', lines[0])
    need(duration is not None, 'Exact Darwin timing duration grammar required')
    values = {label: None for label in TIME_FIELDS}
    for label, line in zip(fields, lines[1:]):
        match = re.fullmatch(r' *(\d+)  ' + re.escape(label), line)
        need(match is not None, 'Exact calibrated Darwin timing field required: ' + label)
        values[label] = int(match[1])
    need(values['maximum resident set size'] > 0, 'Positive waited-command maximum RSS required')
    return dict(fields=values, wall_seconds_rounded_0_01=float(duration[1]),
                user_seconds_rounded_0_01=float(duration[2]), system_seconds_rounded_0_01=float(duration[3]),
                metric='Darwin waited-command maximum including reaped-descendant maxima',
                unavailable_hardware_fields=[label for label in HARDWARE_FIELDS if values[label] is None],
                isolated_compiler_peak_qualified=False, audited_whole_build_peak_qualified=False)


def calibrated_footer(raw, profile):
    value = parse_exact(raw, validate_profile(profile))
    value['timing_profile_sha256'] = canonical_sha(profile)
    return value


def raw_identity(output, name):
    path = output / name
    need(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1 and path.stat().st_size <= RAW_BYTES,
         'Bounded regular original calibration output required: ' + name)
    return dict(bytes=path.stat().st_size, sha256=digest(path))


def complete_return(result, output, require_passed=True):
    """Replay original-group absence, raw hashes, provider return, and profile joins."""
    need(result.get('finalization_errors') == [], 'Exact timing calibration source/provider finalization required')
    terminal = result.get('terminal_runner_state', {})
    groups = terminal.get('original_group_observations', [])
    need(terminal.get('writers_confirmed_retired') is True and len(groups) == 1 and groups[0].get('status') == 'absent',
         'Timing calibration original group absence and writer retirement required')
    commands = result.get('commands', [])
    need(len(commands) == 1, 'Exactly one positive timing calibration command required')
    row = commands[0]
    need(row.get('label') == 'probe' and row.get('arguments') == PROBE_ARGV and type(row.get('exit_code')) is int and row['exit_code'] == 0 and
         type(row.get('expected_exit')) is int and row['expected_exit'] == 0 and row.get('refusal') is None and row.get('writers_confirmed_retired') is True and
         row.get('terminal_group_observation', {}).get('status') == 'absent', 'Complete successful original timing calibration command required')
    terminal_group = row['terminal_group_observation']
    need(all(type(value) is int and value > 0 for value in (row.get('pid'), row.get('original_group'), terminal_group.get('group'))) and
         row['pid'] == row['original_group'] == terminal_group['group'] and terminal_group == groups[0],
         'Exact timing calibration direct-child/original-group identity join required')
    need(terminal_group.get('scope') == 'original POSIX process group' and terminal_group.get('phase') == 'direct_child_returned' and
         terminal_group.get('bounded_drain_exhausted') is False and terminal_group.get('maximum_drain_seconds') == 5.0,
         'Original bounded timing calibration group-retirement scope required')
    group_elapsed = terminal_group.get('elapsed_seconds')
    need(type(group_elapsed) in (int, float) and math.isfinite(group_elapsed) and 0 <= group_elapsed <= 5.0,
         'Finite original timing calibration group-return duration required')
    command_deadline, drain_deadline = terminal_group.get('original_command_deadline'), terminal_group.get('drain_deadline')
    need(type(command_deadline) in (int, float) and math.isfinite(command_deadline) and
         type(drain_deadline) in (int, float) and math.isfinite(drain_deadline) and 0 <= drain_deadline <= command_deadline,
         'Original timing calibration command/drain deadline join required')
    samples = terminal_group.get('samples')
    need(type(samples) is list and 1 <= len(samples) <= 128 and terminal_group.get('initial_sample') == samples[0] and
         terminal_group.get('terminal_sample') == samples[-1] and samples[-1].get('status') == 'absent',
         'Complete bounded timing calibration group sample roster required')
    for sample in samples:
        value = sample.get('elapsed_seconds')
        need(sample.get('status') in ('present', 'absent') and type(value) in (int, float) and math.isfinite(value) and 0 <= value <= group_elapsed,
             'Finite original timing calibration group samples required')
    need(type(row.get('maximum_seconds')) in (int, float) and 1 <= row['maximum_seconds'] <= PROBE_SECONDS and
         type(row.get('elapsed_seconds')) in (int, float) and 0 <= row['elapsed_seconds'] <= row['maximum_seconds'],
         'Original bounded timing probe horizon required')
    need(json.loads((output / 'COMMANDS.json').read_bytes()) == commands, 'Exact persisted timing calibration command roster required')
    identities = {stream: raw_identity(output, 'probe.' + stream + '.txt') for stream in ('stdout', 'stderr')}
    need(sum(value['bytes'] for value in identities.values()) <= RAW_BYTES and identities['stdout']['bytes'] == 0,
         'Empty positive timing probe stdout and bounded complete raw output required')
    need(identities == result.get('raw_output'), 'Exact retained timing calibration raw identities required')
    for stream in identities:
        need(row.get(stream + '_sha256') == identities[stream]['sha256'], 'Retired timing calibration raw output hash required')
    for name in ('timing_provider', 'probe_provider'):
        provider = result['providers'][name]
        need(provider['before_sha256'] == provider['supplied_sha256'] == provider['after_sha256'] and
             digest(Path(provider['path'])) == provider['supplied_sha256'], 'Exact timing calibration provider before/after/return required')
    need(type(result.get('elapsed_seconds')) in (int, float) and 0 <= result['elapsed_seconds'] <= CALIBRATION_SECONDS,
         'Complete calibration return within its original thirty-second horizon required')
    if require_passed:
        need(result.get('passed') is True, 'Successful timing calibration required before causal launch')
        profile = result['profile']
        validate_profile(profile, result['providers']['timing_provider']['supplied_sha256'],
                         result['providers']['probe_provider']['supplied_sha256'], result['job_identity'])
        need(canonical_sha(profile) == result['profile_sha256'] and
             json.loads((output / 'TIMING_PROFILE.json').read_bytes()) == profile, 'Exact retained calibrated timing profile required')
        evidence = dict(command=row, raw_output=identities)
        need(profile['calibration_evidence_sha256'] == canonical_sha(evidence), 'Exact timing profile raw command evidence join required')
        calibrated_footer((output / 'probe.stderr.txt').read_text(), profile)


def calibrate(output, driver_path, time_sha256, true_sha256, job_identity, absolute_deadline):
    started = time.monotonic()
    need(output.is_absolute() and not output.exists() and not output.is_symlink(), 'Fresh absolute owned timing calibration output required')
    output.mkdir(parents=True)
    retained_deadline = absolute_deadline if type(absolute_deadline) in (int, float) and math.isfinite(absolute_deadline) else None
    result = dict(format='atlas-same-job-timing-calibration-v1', passed=False, maximum_seconds=CALIBRATION_SECONDS,
                  probe_limit_seconds=PROBE_SECONDS, absolute_outer_deadline=retained_deadline,
                  supplied_outer_deadline_repr=repr(absolute_deadline), job_identity=job_identity,
                  commands=[], actual_target_cells_accepted=0, scope='Positive timing-format probe; compiler and native workload acceptance remain separate')
    runner = None
    protected = {Path(__file__): digest(__file__), Path(driver_path): DRIVER_SHA256}
    providers = result['providers'] = {
        'timing_provider': dict(path='/usr/bin/time', supplied_sha256=time_sha256),
        'probe_provider': dict(path='/usr/bin/true', supplied_sha256=true_sha256)}
    save(output / 'CALIBRATION_RESULT.json', result)
    try:
        need(type(absolute_deadline) in (int, float) and math.isfinite(absolute_deadline) and absolute_deadline - started >= CALIBRATION_SECONDS,
             'Complete thirty-second calibration horizon inside the original outer deadline required')
        need(type(job_identity) is dict and bool(job_identity), 'Exact admitted same-job identity required for calibration')
        for provider in providers.values():
            need(exact_sha(provider['supplied_sha256']), 'Exact supplied timing calibration provider hash required')
            provider['before_sha256'] = digest(Path(provider['path']))
            need(provider['before_sha256'] == provider['supplied_sha256'], 'Exact timing calibration provider required before probe')
            protected[Path(provider['path'])] = provider['supplied_sha256']
        need(digest(driver_path) == DRIVER_SHA256, 'Exact reviewed original-group Runner required for timing calibration')
        spec = importlib.util.spec_from_file_location('grant_timing_reviewed_runner', driver_path)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        runner = driver.Runner(output)
        runner.deadline = min(absolute_deadline, started + CALIBRATION_SECONDS)
        result['commands'] = runner.records
        environment = {key: value for key, value in os.environ.items() if key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL')}
        environment['LC_ALL'] = 'C'
        stdout, stderr = runner.run('probe', PROBE_ARGV, cwd=output, environment=environment, seconds=PROBE_SECONDS)
        need(not stdout, 'Empty positive timing calibration stdout required')
        fields = TIME_FIELDS if len(stderr.splitlines()) == 18 else COMMON_FIELDS
        parse_exact(stderr, fields)
        result['raw_output'] = {stream: raw_identity(output, 'probe.' + stream + '.txt') for stream in ('stdout', 'stderr')}
        profile = dict(format=FORMAT, timing_provider=dict(path='/usr/bin/time', sha256=time_sha256),
                       probe_provider=dict(path='/usr/bin/true', sha256=true_sha256), job_identity=job_identity,
                       ordered_fields=list(fields), unavailable_hardware_fields=[] if fields == TIME_FIELDS else list(HARDWARE_FIELDS),
                       calibration_evidence_sha256=canonical_sha(dict(command=runner.records[0], raw_output=result['raw_output'])))
        validate_profile(profile, time_sha256, true_sha256, job_identity)
        result.update(profile=profile, profile_sha256=canonical_sha(profile), passed=True)
        save(output / 'TIMING_PROFILE.json', profile)
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__, error)
        result['passed'] = False
    finally:
        errors = []
        result['terminal_runner_state'] = dict(writers_confirmed_retired=runner.writers_confirmed_retired if runner else True,
            original_group_observations=json.loads(json.dumps(runner.group_observations)) if runner else [])
        for name, provider in providers.items():
            try:
                provider['after_sha256'] = digest(Path(provider['path']))
                need(provider['after_sha256'] == provider['supplied_sha256'], 'Exact timing provider required after calibration: ' + name)
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        for path, expected in protected.items():
            try:
                need(digest(path) == expected, 'Exact timing calibration source/provider required at return: ' + str(path))
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic() - started
        if result['passed']:
            try:
                complete_return(result, output)
            except Exception as error:
                result['return_error'] = '%s: %s' % (type(error).__name__, error)
                result['passed'] = False
        save(output / 'CALIBRATION_RESULT.json', result)
    return result
