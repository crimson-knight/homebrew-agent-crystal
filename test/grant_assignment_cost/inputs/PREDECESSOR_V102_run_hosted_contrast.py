"""Finite hosted Mac original/candidate/restored diagnostic through the reviewed Runner."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys
import time
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'vendor'))
from retained_symbols import need, sha, read_macho, family_rows
from verify_assignment_owners import verify as verify_owners
from compile_acceptance_contract import parse_json_text, verify_behavior
from verify_compile_acceptance import source_input_inventory
from gc_contract import TIME_FIELDS
from same_job_policy import metadata as admit_sdk_metadata, protect_packet
from prepare_comparison import prepare
from prepare_baseline import prepare_baseline

DRIVER_SHA256 = 'dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
PREDECESSOR_PROFILE_SHA256 = 'd40f7514f2a98d406482ddc24ec29729158f61ca2cf0da9be46b094ccc9d3def'
GLOBAL_SECONDS = 4800
ARM_SECONDS = 1500
RAW_BYTES = 64 * 2**20


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def save_bounded_symbols(path, value, maximum_bytes=20 * 2**20):
    count = 0
    with path.open('wb') as stream:
        for chunk in json.JSONEncoder(sort_keys=True, allow_nan=False, separators=(',', ':')).iterencode(value):
            raw = chunk.encode()
            need(count + len(raw) <= maximum_bytes, 'Complete linked owner roster exceeded its finite20-MiB JSON budget')
            stream.write(raw)
            count += len(raw)
    return count


def digest(path):
    return sha(Path(path).read_bytes())


@contextmanager
def overlay(path, original, requested):
    need(not path.is_symlink() and path.read_bytes() == original, 'Exact original ordinary column source required before overlay')
    try:
        path.write_bytes(requested)
        need(path.read_bytes() == requested, 'Exact requested source overlay required')
        yield
    finally:
        need(not path.is_symlink(), 'Ordinary owned source path required for restoration')
        path.write_bytes(original)
        need(path.read_bytes() == original, 'Exact source restoration required')


def timed_footer(raw):
    lines = raw.splitlines()
    need(len(lines) == 18, 'Only the complete original Darwin timing footer may accompany GREEN compilation')
    duration = re.fullmatch(r' *(\d+\.\d{2}) real +(\d+\.\d{2}) user +(\d+\.\d{2}) sys', lines[0])
    need(duration is not None, 'Exact Darwin timing duration grammar required')
    fields = {}
    for label, line in zip(TIME_FIELDS, lines[1:]):
        match = re.fullmatch(r' *(\d+)  ' + re.escape(label), line)
        need(match is not None, 'Exact Darwin timing field required: ' + label)
        fields[label] = int(match[1])
    need(fields['maximum resident set size'] > 0, 'Positive waited-command maximum RSS required')
    return dict(fields=fields, wall_seconds_rounded_0_01=float(duration[1]),
                user_seconds_rounded_0_01=float(duration[2]), system_seconds_rounded_0_01=float(duration[3]),
                metric='Darwin waited-command maximum including reaped-descendant maxima',
                isolated_compiler_peak_qualified=False, audited_whole_build_peak_qualified=False)


def behavior(stdout, count):
    markers = [line.split('=', 1)[1] for line in stdout.splitlines() if line.startswith('GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=')]
    need(len(markers) == 1, 'One complete executed behavior marker required')
    value = parse_json_text(markers[0])
    verify_behavior(value, count, 'all_model_queries_and_associations')
    return value


def qualify(args):
    started = time.monotonic()
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64' and os.environ.get('GITHUB_ACTIONS') == 'true', 'Actual comparison belongs to GitHub-hosted Darwin ARM64')
    need(digest(__file__) == args.source_sha256 and digest(Path(sys.executable).resolve()) == args.python_sha256, 'Exact comparison source and Python provider required')
    need(digest(args.driver) == DRIVER_SHA256 and digest(args.plan) == args.plan_sha256, 'Exact reviewed Runner and comparison plan required')
    plan = json.loads(args.plan.read_bytes())
    baseline = plan.get('experiment_kind') == 'original300-feasibility-baseline'
    need((args.models == 300 if baseline else args.models in (2, 10)) and args.repetition in (1, 2, 3), 'One bounded source-plan diagnostic required')
    need(plan['execution_admitted'] is False and plan['required_target_matrix_size'] == 144, 'Original source-plan boundaries required')
    protected = protect_packet(args.packet_sha256)
    admitted = admit_sdk_metadata(args.sdk_evidence, os.environ)
    profile, providers, job = admitted['profile'], admitted['providers'], admitted['runner']
    need(job['python_sha256'] == args.python_sha256 and Path(job['python_path']).resolve() == Path(sys.executable).resolve(), 'Same exact Python provider as the actual SDK call required')
    protected.update({Path(row['path']): row['sha256'] for row in providers.values()})
    protected.update({args.driver: DRIVER_SHA256, args.plan: args.plan_sha256, Path(__file__): args.source_sha256,
                      Path(sys.executable).resolve(): args.python_sha256, Path('/usr/bin/time'): args.time_sha256})
    for path in args.sdk_evidence.rglob('*'):
        if path.is_file():
            protected[path] = digest(path)
    for path, expected in protected.items():
        need(digest(path) == expected, 'Exact protected provider/source bytes required: ' + str(path))
    spec = importlib.util.spec_from_file_location('grant_reviewed_sdk_runner', args.driver)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    wrapper = Path(providers['compiler_wrapper']['path'])
    need(digest(wrapper) == profile['wrapper_sha256'], 'Exact ordinary wrapper profile required')
    prefix = wrapper.parent.parent
    stdlib = prefix / 'share/agent-crystal/src'
    need(wrapper == Path((args.sdk_evidence / 'brew-prefix.stdout.txt').read_text().strip()).resolve() / 'bin/crystal-alpha', 'Exact ordinary installed prefix/wrapper join required')
    backend = Path(providers['compiler_backend']['path'])
    need(backend == prefix / 'libexec/agent-crystal-bin', 'Exact static wrapper/backend path join required')
    driver.verify_wrapper(wrapper.read_text(), backend, stdlib, Path((args.sdk_evidence / 'brew-root.stdout.txt').read_text().strip()), 'Darwin')
    for name, relative in [('INSTALLED_FORMULA.rb', '.brew/agent-crystal.rb'), ('INSTALL_RECEIPT.json', 'INSTALL_RECEIPT.json')]:
        path = prefix / relative
        need(digest(path) == digest(args.sdk_evidence / name), 'Exact live installed formula/receipt required')
        protected[path] = digest(path)
    before_stdlib = driver.tree_identity(stdlib)
    need(before_stdlib == admitted['stdlib'], 'Exact full installed standard-library source required')
    grant = Path(plan['runs'][0]['working_directory'])
    with tempfile.TemporaryDirectory(prefix='atlas-grant-plan-recompute-') as temporary:
        destination = Path(temporary) / 'expected'
        expected_plan = prepare_baseline(destination, grant, wrapper) if baseline else prepare(destination, grant, wrapper, plan['variant'])
    need(json.dumps(plan, sort_keys=True) == json.dumps(expected_plan, sort_keys=True), 'Exact regenerated complete plan/compile argv/normal-field-association controls required')
    original_rows, original_fingerprint = source_input_inventory(grant)
    need(len(original_rows) == 1554 and original_fingerprint == plan['source_fingerprints']['original'], 'Exact original1554 frozen source inputs required')
    original = (args.plan.parent / 'original.columns.cr.txt').read_bytes()
    candidate = (args.plan.parent / 'candidate.columns.cr.txt').read_bytes()
    need(sha(original) == plan['candidate_delta']['original_sha256'] and sha(candidate) == plan['candidate_delta']['candidate_sha256'], 'Exact proposed one-file overlay required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    maximum_seconds = ARM_SECONDS if baseline else GLOBAL_SECONDS
    deadline = started + maximum_seconds
    result = dict(format='atlas-grant-hosted-assignment-triplet-diagnostic-v1', diagnostic_complete=False, samples=[],
                  variant=plan['variant'], shipping_compatibility_accepted=False,
                  experiment_kind=plan.get('experiment_kind', 'rich2-10-causal-triplet'), maximum_seconds=maximum_seconds,
                  ordinary_compiler_profile_sha256=admitted['observed_profile_sha256'], admitted_same_job=admitted, driver_sha256=DRIVER_SHA256,
                  whole_build_provider_qualified=False, native_loader_closure_qualified=False,
                  candidate_feature_compatibility_accepted=False, memory_savings_accepted=False,
                  required_target_cells=144, target_cells_accepted=0)
    try:
        for arm in (('original',) if baseline else ('original', 'candidate', 'restored')):
            if not baseline:
                need(deadline - time.monotonic() >= ARM_SECONDS, 'Complete original1500-second arm horizon required before launch')
            selected = [row for row in plan['runs'] if (row['arm'], row['models'], row['repetition']) == (arm, args.models, args.repetition)]
            need(len(selected) == 1, 'Exact source-plan arm required')
            selected = selected[0]
            command_output = output / arm
            command_output.mkdir()
            arm_started = time.monotonic()
            runner = driver.Runner(command_output)
            runner.deadline = min(deadline, time.monotonic() + ARM_SECONDS)
            arm_result = dict(arm=arm, passed=False, commands=runner.records, groups=runner.group_observations)
            result['samples'].append(arm_result)
            try:
                with overlay(grant / 'src/grant/columns.cr', original, candidate if arm == 'candidate' else original):
                    need(source_input_inventory(grant)[1] == selected['expected_source_tree_sha256'], 'Exact arm source closure required')
                    directory = Path(selected['output_directory'])
                    directory.mkdir(parents=True, exist_ok=False)
                    fixture = (args.plan.parent / ('FIXTURE_%d.cr.txt' % args.models)).read_bytes()
                    need(sha(fixture) == selected['unchanged_fixture_source_sha256'], 'Unchanged complete rich fixture required')
                    (directory / 'fixture.cr').write_bytes(fixture)
                    env = {key: value for key, value in os.environ.items() if key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SDKROOT', 'DEVELOPER_DIR')}
                    env.update(CRYSTAL_WORKERS='1', CRYSTAL_CACHE_DIR=str(directory / 'cache'), NO_COLOR='1', LC_ALL='C')
                    need(not (directory / 'cache').exists(), 'Actually cold private compiler cache required')
                    runner.run('format', [wrapper, 'tool', 'format', '--check', '--no-color', grant / 'src/grant/columns.cr', directory / 'fixture.cr'], cwd=grant, environment=env, seconds=30)
                    compile_argv = list(selected['compile_argv'])
                    need(compile_argv[0] == str(wrapper), 'Plan selects the actually accepted ordinary compiler wrapper')
                    need(runner.deadline - time.monotonic() >= 900 + 3 * 120 + 60, 'Full original compile/runtime limits plus finite metadata reserve required')
                    try:
                        stdout, stderr = runner.run('build', ['/usr/bin/time', '-l', *compile_argv], cwd=grant, environment=env, seconds=900)
                    except Exception:
                        path = command_output / 'build.stderr.txt'
                        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 2**20:
                            lines = path.read_text().splitlines()
                            try:
                                value = timed_footer('\n'.join(lines[-18:]) + '\n')
                                value['scope'] = 'Failed or refused build waited-command timing; incomplete workload, zero target acceptance'
                                value['command_record'] = dict(runner.records[-1]) if runner.records else None
                                arm_result['failed_build_time'] = value
                            except Exception as timing_error:
                                arm_result['failed_build_timing_refusal'] = '%s: %s' % (type(timing_error).__name__, timing_error)
                        raise
                    need(not stdout, 'GREEN ordinary build stdout required')
                    arm_result['time'] = timed_footer(stderr)
                    binary = directory / 'fixture'
                    need(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= (512 if baseline else 64) * 2**20, 'Finite ordinary generated binary required')
                    binary_sha = digest(binary)
                    arm_result['binary_sha256'] = binary_sha
                    if baseline:
                        arm_result['owner_predicate_scope'] = 'Unchanged300-model feasibility baseline; causal assignment-shape hypothesis is separate'
                    else:
                        symbols = read_macho(binary.read_bytes())
                        arm_result['defined_text_symbols_bytes'] = save_bounded_symbols(command_output / 'DEFINED_TEXT_SYMBOLS.json', symbols)
                        arm_result['defined_text_symbols_sha256'] = digest(command_output / 'DEFINED_TEXT_SYMBOLS.json')
                        arm_result['binary_artifact_replay_qualified'] = False
                        arm_result['emitted_families'] = family_rows(symbols)
                        try:
                            arm_result['owner_predicate'] = verify_owners(symbols['definitions'], args.models, arm)
                        except Exception as owner_error:
                            arm_result['owner_predicate_error'] = '%s: %s' % (type(owner_error).__name__, owner_error)
                    for control in selected['same_binary_controls']:
                        need(runner.deadline - time.monotonic() >= 120, 'Full original runtime command limit required')
                        runtime = dict(env, GRANT_COMPILE_ACCEPTANCE_DATABASE_URL='sqlite3:' + str(directory / (control['label'] + '.sqlite3')),
                                       GRANT_COMPILE_ACCEPTANCE_INJECT_INVALID_FIRST_NAME=control['field_canary'],
                                       GRANT_COMPILE_ACCEPTANCE_INJECT_INVALID_ASSOCIATION_FIRST_NAME=control['association_canary'])
                        stdout, stderr = runner.run(control['label'], selected['runtime_argv'], cwd=grant, environment=runtime, seconds=120, expected_exit=control['expected_exit'])
                        if control['label'] == 'normal':
                            arm_result['behavior'] = behavior(stdout, args.models)
                        else:
                            need(control['required_assertion'] in stdout + stderr, 'Exact same-binary corruption assertion required')
                        need(digest(binary) == binary_sha, 'Exact same binary across every control required')
                    need(source_input_inventory(grant)[1] == selected['expected_source_tree_sha256'], 'Arm source changed during build/runtime')
                    arm_result['passed'] = 'owner_predicate_error' not in arm_result
            finally:
                arm_result['terminal_runner_state'] = dict(writers_confirmed_retired=runner.writers_confirmed_retired, original_group_observations=json.loads(json.dumps(runner.group_observations)))
            need(source_input_inventory(grant) == (original_rows, original_fingerprint), 'Exact complete original closure restored between arms')
            save(output / 'COMPARISON_RESULT.json', result)
            arm_result['terminal_elapsed_seconds'] = time.monotonic() - arm_started
            need(arm_result['terminal_elapsed_seconds'] <= ARM_SECONDS, 'Complete arm metadata/return exceeded its original1500-second horizon')
        result['diagnostic_complete'] = True
        result['owner_shape_accepted'] = False if baseline else all(row['passed'] for row in result['samples'])
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__, error)
        result['error_context'] = []
        previous = error.__context__
        while previous is not None and len(result['error_context']) < 8:
            result['error_context'].append('%s: %s' % (type(previous).__name__, previous))
            previous = previous.__context__
    finally:
        finalization_errors = []
        for label, observation in [('source', lambda: source_input_inventory(grant) == (original_rows, original_fingerprint)),
                                   ('stdlib', lambda: driver.tree_identity(stdlib) == before_stdlib)]:
            try:
                need(observation(), 'Exact final ' + label + ' identity required')
            except Exception as error:
                finalization_errors.append('%s: %s' % (type(error).__name__, error))
        try:
            need(admit_sdk_metadata(args.sdk_evidence, os.environ) == admitted, 'Exact same-job compiler/provider admission remains unchanged at final return')
        except Exception as error:
            finalization_errors.append('%s: %s' % (type(error).__name__, error))
        for path, expected in protected.items():
            try:
                need(digest(path) == expected, 'Protected input changed: ' + str(path))
            except Exception as error:
                finalization_errors.append('%s: %s' % (type(error).__name__, error))
        result['finalization_errors'] = finalization_errors
        result['raw_output_bytes'] = sum(path.stat().st_size for path in output.rglob('*.txt'))
        if result['raw_output_bytes'] > RAW_BYTES:
            result['diagnostic_complete'] = False
            result['output_budget_exceeded'] = True
        result['elapsed_seconds'] = time.monotonic() - started
        if finalization_errors or result['elapsed_seconds'] > maximum_seconds:
            result['diagnostic_complete'] = False
        save(output / 'COMPARISON_RESULT.json', result)
    return 0 if result['diagnostic_complete'] and (baseline or result.get('owner_shape_accepted') is True) else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'plan', 'sdk-evidence', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha256', 'plan-sha256', 'python-sha256', 'time-sha256', 'packet-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--models', type=int, choices=(2, 10, 300), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3), required=True)
    return qualify(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
