"""Admit observed Mac compiler bytes through one exact-source SDK call in this job."""
import hashlib
import json
import os
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
DRIVER_SHA256 = 'dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
LOCK_SHA256 = 'eeb10f483941f761898c86e0869c69a948d5d83136a7f3d2b1231a37bfa6a1b4'
FORMULA_SHA256 = 'dfb16338b328960bd0e822c2d98eac8b7774d1303e972a5dba09ba1ddf9ab7df'
RUBY_SHA256 = 'a53f08545808a4588c9f7f6ac2f865ea4ba852a64f71f45bf8d61e114428f42d'
WRAPPER_SHA256 = '5597f8891468ec305a55c8d7a910c392c4cd5b923fba475ba061b0221b8763a0'
PREDECESSOR_PROFILE_SHA256 = 'd40f7514f2a98d406482ddc24ec29729158f61ca2cf0da9be46b094ccc9d3def'
JOB_KEYS = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_JOB', 'RUNNER_NAME', 'RUNNER_OS', 'RUNNER_ARCH')
COMMAND_LIMITS = dict(zip(('brew-prefix', 'brew-root', 'brew-receipt', 'alpha-version', 'ruby-identity', 'install-bundle', 'default-specs', 'without-mt-specs', 'tutorial-build', 'tutorial-normal', 'tutorial-regression'), (45, 45, 45, 30, 30, 30, 300, 300, 300, 30, 30)))
LABELS = ('brew-prefix', 'brew-root', 'brew-receipt', 'alpha-version', 'ruby-identity', 'install-bundle', 'default-specs', 'without-mt-specs', 'tutorial-build', 'tutorial-normal', 'tutorial-regression')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def identity(environment):
    value = {key: environment.get(key) for key in JOB_KEYS}
    need(all(isinstance(v, str) and v and '\n' not in v and '\r' not in v for v in value.values()), 'Complete literal run/attempt/job/runner identity required')
    need(value['RUNNER_OS'] == 'macOS' and value['RUNNER_ARCH'] == 'ARM64', 'Hosted Mac ARM64 job identity required')
    return value


def roster(evidence):
    rows = []
    for path in sorted(evidence.rglob('*')):
        need(not path.is_symlink(), 'Ordinary SDK evidence paths required')
        if path.is_file() and path.name != 'SAME_JOB_BINDING.json':
            rows.append(dict(path=path.relative_to(evidence).as_posix(), bytes=path.stat().st_size, sha256=digest(path)))
    need(len(rows) <= 256 and sum(r['bytes'] for r in rows) <= 16 * 2**20, 'Bounded complete SDK evidence roster required')
    return rows


def metadata(evidence, environment, check_binding=True):
    job_identity = identity(environment)
    lock = read(evidence / 'SOURCE_LOCK.json')
    need(digest(evidence / 'SOURCE_LOCK.json') == LOCK_SHA256, 'Exact SDK/Alpha source lock required')
    need(digest(evidence / 'INSTALLED_FORMULA.rb') == FORMULA_SHA256, 'Exact reviewed revision1 formula source required')
    runner, result = read(evidence / 'RUNNER.json'), read(evidence / 'READINESS_RESULT.json')
    for key, field in [('GITHUB_RUN_ID', 'run_id'), ('GITHUB_RUN_ATTEMPT', 'run_attempt'), ('GITHUB_SHA', 'source_commit')]:
        need(runner[field] == job_identity[key], 'SDK run/attempt/source differs from this job')
    need(runner['system'] == 'Darwin' and runner['machine'] == 'arm64' and runner['qualification_script_sha256'] == DRIVER_SHA256 and runner['source_lock_sha256'] == LOCK_SHA256, 'Exact SDK platform/driver/source-lock identity required')
    for field in ('passed', 'private_cache_removed', 'writers_confirmed_retired'):
        need(result[field] is True, 'Actual successful SDK readiness and complete original-group return required: ' + field)
    for field, expected in [('default_examples', 39), ('without_mt_examples', 39), ('installed_bundle_files', 68), ('command_count', 11), ('tutorial_normal_exit', 0), ('tutorial_regression_exit', 1)]:
        need(type(result[field]) is int and result[field] == expected, 'Exact successful SDK count/status required: ' + field)
    need(result['compiler_color'] == 'GREEN' and result['sdk_commit'] == lock['sdk']['commit'], 'GREEN exact-source SDK readiness required')
    for field in ('full_native_provider_acceptance', 'frozen_dependency_installation_accepted', 'customer_device_accepted', 'actual_group_recovery_qualified', 'detached_session_coverage_qualified'):
        need(result[field] is False, 'Separate platform/installation boundaries required: ' + field)
    commands = read(evidence / 'COMMANDS.json')
    need([row['label'] for row in commands] == list(LABELS), 'Exact eleven actual SDK commands required')
    observations = result['owned_group_observations']
    need(isinstance(observations, list) and len(observations) == len(commands), 'Exact SDK command/group observation roster required')
    for index, row in enumerate(commands):
        expected = 1 if row['label'] == 'tutorial-regression' else 0
        need(type(row['exit_code']) is int and row['exit_code'] == expected and row['refusal'] is None and row['writers_confirmed_retired'] is True and row['terminal_group_observation']['status'] == 'absent', 'Successful actual SDK command and absent original group required')
        terminal = row['terminal_group_observation']
        for value in (row['pid'], row['original_group'], terminal['group'], observations[index]['group']):
            need(type(value) is int and value > 0, 'Exact positive integer SDK PID/original-group identity required')
        need(row['pid'] == row['original_group'] == terminal['group'] == observations[index]['group'], 'SDK direct-child/original-group identity join required')
        need(json.dumps(terminal, sort_keys=True) == json.dumps(observations[index], sort_keys=True), 'Exact command/result terminal original-group observation join required')
        need(type(row['expected_exit']) is int and row['expected_exit'] == expected, 'Exact SDK expected exit status required')
        maximum, elapsed = row['maximum_seconds'], row['elapsed_seconds']
        need(type(maximum) in (int, float) and math.isfinite(maximum) and 0 < maximum <= COMMAND_LIMITS[row['label']], 'Original finite per-label SDK command maximum required')
        need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= maximum, 'Finite SDK terminal elapsed within the original command maximum required')
        need(terminal['scope'] == 'original POSIX process group' and terminal['phase'] == 'direct_child_returned' and terminal['bounded_drain_exhausted'] is False, 'Returned original SDK group scope required')
        need(type(terminal['maximum_drain_seconds']) in (int, float) and terminal['maximum_drain_seconds'] == 5.0, 'Original finite five-second SDK drain maximum required')
        need(type(terminal['elapsed_seconds']) in (int, float) and math.isfinite(terminal['elapsed_seconds']) and 0 <= terminal['elapsed_seconds'] <= 5.0, 'Finite SDK original-group terminal duration required')
        need(type(terminal['original_command_deadline']) in (int, float) and math.isfinite(terminal['original_command_deadline']) and type(terminal['drain_deadline']) in (int, float) and math.isfinite(terminal['drain_deadline']) and 0 <= terminal['drain_deadline'] <= terminal['original_command_deadline'], 'Original SDK absolute command/drain deadline join required')
        samples = terminal['samples']
        need(isinstance(samples, list) and 1 <= len(samples) <= 128 and terminal['initial_sample'] == samples[0] and terminal['terminal_sample'] == samples[-1] and samples[-1]['status'] == 'absent', 'Complete bounded original SDK group terminal sample roster required')
        for sample in samples:
            need(sample['status'] in ('present', 'absent') and type(sample['elapsed_seconds']) in (int, float) and math.isfinite(sample['elapsed_seconds']) and 0 <= sample['elapsed_seconds'] <= terminal['elapsed_seconds'], 'Finite original SDK group sample duration required')
        for stream in ('stdout', 'stderr'):
            need(digest(evidence / (row['label'] + '.' + stream + '.txt')) == row[stream + '_sha256'], 'Exact raw SDK command stream required')
    need(len(result['owned_group_observations']) == 11 and all(row['status'] == 'absent' for row in result['owned_group_observations']), 'All eleven SDK original groups absent required')
    alpha = lock['alpha']
    formulae = read(evidence / 'brew-receipt.stdout.txt')['formulae']
    need(len(formulae) == 1, 'One exact Alpha formula receipt required')
    formula = formulae[0]
    need(formula['versions']['stable'] == alpha['source_version'] and type(formula['revision']) is int and formula['revision'] == alpha['formula_revision'] and formula['urls']['stable']['checksum'] == alpha['source_archive_sha256'], 'Exact ordinary Alpha version/revision/source checksum required')
    installed = formula['installed']
    need(len(installed) == 1 and installed[0]['version'] == alpha['installed_package_version'] and installed[0]['poured_from_bottle'] is False, 'Same-job ordinary formula source build required')
    need((evidence / 'alpha-version.stdout.txt').read_text() == alpha['full_versions']['Darwin'] and not (evidence / 'alpha-version.stderr.txt').read_bytes(), 'Exact full installed compiler version required')
    before, after = read(evidence / 'STDLIB_BEFORE.json'), read(evidence / 'STDLIB_AFTER.json')
    need(before == after and before['sha256'] == alpha['stdlib_sha256'] and len(before['files']) == alpha['stdlib_file_count'] and before['directory_aliases'] == alpha['stdlib_directory_aliases'], 'Exact unchanged complete source-derived standard library required')
    bundle = read(evidence / 'INSTALLED_BUNDLE_BEFORE.json')
    need(len(bundle['files']) == 68 and bundle['directory_aliases'] == {}, 'Exact installed SDK bundle roster required; successful SDK call separately verifies final parity')
    profile, providers = read(evidence / 'REVIEWED_COMPILER_PROFILE.json'), read(evidence / 'PROVIDER_IDENTITIES.json')
    need(type(profile['schema_version']) is int and profile['schema_version'] == 1 and type(profile['counter_protocol']) is int and profile['counter_protocol'] == 1 and profile['profile'] == 'ordinary-alpha-sdk-readiness-darwin', 'Exact SDK profile schema required')
    need(set(profile) == {'schema_version', 'profile', 'counter_protocol', 'compiler_sha256', 'wrapper_sha256', 'stdlib_sha256', 'ruby_sha256', 'ruby_launcher_sha256'}, 'Exact accepted profile key roster required')
    need(profile['wrapper_sha256'] == WRAPPER_SHA256 and profile['stdlib_sha256'] == alpha['stdlib_sha256'] and profile['ruby_sha256'] == RUBY_SHA256 and profile['ruby_launcher_sha256'] == RUBY_SHA256, 'Exact source-derived wrapper/stdlib and accepted Ruby prerequisites required; compiler bytes alone are freshly observed')
    need(set(providers) == {'compiler_backend', 'compiler_wrapper', 'ruby_backend', 'ruby_launcher'}, 'Exact observed provider roster required')
    for name, field in [('compiler_backend', 'compiler_sha256'), ('compiler_wrapper', 'wrapper_sha256'), ('ruby_backend', 'ruby_sha256'), ('ruby_launcher', 'ruby_launcher_sha256')]:
        row = providers[name]
        need(re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None and row['sha256'] == profile[field] and type(row['bytes']) is int and 0 < row['bytes'] <= 512 * 2**20 and Path(row['path']).is_absolute(), 'Exact individually observed provider bytes required: ' + name)
    derivation = read(evidence / 'PROFILE_DERIVATION.json')
    need(derivation['profile_sha256'] == digest(evidence / 'REVIEWED_COMPILER_PROFILE.json') and derivation['alpha_source_commit'] == alpha['source_commit'], 'Exact source/profile derivation join required')
    need(digest(evidence / 'sdk-source.tar.gz') == lock['sdk']['archive_sha256'] and (evidence / 'sdk-source.tar.gz').stat().st_size == lock['sdk']['archive_bytes'], 'Exact SDK archive source provenance required')
    if check_binding:
        binding = read(evidence / 'SAME_JOB_BINDING.json')
        need(binding['job_identity'] == job_identity and binding['nonce'] == environment.get('ATLAS_GRANT_JOB_NONCE') and re.fullmatch('[0-9a-f]{64}', binding['nonce']) is not None, 'Fresh SDK-call nonce and exact current job/runner required')
        need(binding['driver_sha256'] == DRIVER_SHA256 and binding['policy_sha256'] == digest(__file__) and binding['wrapper_sha256'] == digest(ROOT / 'qualify_same_job_sdk.py'), 'Exact reviewed same-job SDK admission sources required')
        need(binding['sdk_call_returned'] is True and binding['sdk_return_code'] == 0 and type(binding['sdk_return_code']) is int and binding['evidence'] == roster(evidence), 'Exact complete readiness bytes produced by the bounded in-process SDK call required')
    return dict(profile=profile, providers=providers, runner=runner, stdlib=before, job_identity=job_identity,
                observed_profile_sha256=digest(evidence / 'REVIEWED_COMPILER_PROFILE.json'), observed_provider_sha256=digest(evidence / 'PROVIDER_IDENTITIES.json'),
                predecessor_literal_profile_sha256=PREDECESSOR_PROFILE_SHA256, dynamic_backend_policy='Individually observed exact bytes under reviewed same-job ordinary source-build readiness', target_cells_accepted=0)


def protect_packet(expected_manifest_sha256):
    manifest = ROOT / 'SOURCE_PINS.json'
    need(digest(manifest) == expected_manifest_sha256, 'Exact externally reviewed executable packet manifest required')
    rows = read(manifest)['files']
    need(len(rows) <= 256 and len({row['path'] for row in rows}) == len(rows), 'Bounded unique executable packet roster required')
    protected = {manifest: expected_manifest_sha256}
    for row in rows:
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'Contained exact executable packet path required')
        path = ROOT / relative
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'], 'Exact executable packet dependency required: ' + row['path'])
        protected[path] = row['sha256']
    return protected
