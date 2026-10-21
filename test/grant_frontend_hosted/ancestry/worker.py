"""Draft six-route semantic worker; final execution requires materialized producer pins."""
from pathlib import Path
import contextlib
import datetime
import hashlib
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parent
ROOT = PROJECT.parent
sys.path.insert(0, str(PROJECT))
import frontend_boundary as boundary
import qualified_helpers as qualified
from prepared_stdlib import audit_prepared_stdlib
from parse_semantic_stats import parse as parse_semantic_stats
from parse_stage_stats import associate_observed_intervals
import process_supervision as durable

JOB = 'memory-budget-experiment-grant-frontend-six-routes-mini-20261019-v102'
CONTROL = Path('/Users/ci/.local/share/agentc-scheduler/control-1.0.6')
ATLAS_CONTROL = Path('/Users/ci/.local/share/agentc-scheduler/atlas-grant-frontend-six-routes-registration-v102')


def interrupted(number, _frame):
    raise InterruptedError('Semantic worker received signal ' + str(number))


def save(name, value):
    durable.atomic_json(ROOT / name, value)


def processes():
    output = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,rss=,lstart=,command='],
        timeout=4, env={'LC_ALL': 'C', 'TZ': 'UTC', 'PATH': '/usr/bin:/bin'})
    rows = {}
    for line in output.decode('utf-8').splitlines():
        fields = line.split(None, 10)
        if len(fields) == 11 and all(value.isdigit() for value in fields[:5]):
            rows[int(fields[0])] = {'parent': int(fields[1]), 'group': int(fields[2]),
                'uid': int(fields[3]), 'rss': int(fields[4]) * 1024,
                'birth': ' '.join(fields[5:10]), 'command': fields[10]}
    boundary.need(os.getpid() in rows, 'Fresh actual semantic-worker identity required')
    return rows


class Runtime:
    def __init__(self):
        self.clock = boundary.Clock()
        self.checks = []
        self.owners = set()
        self.groups = set()
        self.minimum_free = 2**63
        self.peak = 0
        self.last_tree = -1.0
        self.observations = {}

    def guard(self):
        self.clock.check()
        filesystem = os.statvfs(ROOT)
        free = filesystem.f_bavail * filesystem.f_frsize
        self.minimum_free = min(self.minimum_free, free)
        boundary.need(free > 10 * 2**30, 'Semantic worker reaches10GiB filesystem floor')
        if time.monotonic() - self.last_tree >= 2:
            paths = list(ROOT.rglob('*'))
            boundary.need(len(paths) < 60000, 'Finite semantic job-root entry allowance reached')
            total = sum(path.lstat().st_size for path in paths if path.is_file() and not path.is_symlink())
            boundary.need(total < boundary.JOB_ROOT_LIMIT, 'Semantic job-root reaches1GiB projection')
            streams = [path for path in ROOT.iterdir() if path.name.endswith(('.stdout.txt', '.stderr.txt'))]
            boundary.need(all(path.stat().st_size < 2**20 for path in streams)
                          and sum(path.stat().st_size for path in streams) < 32 * 2**20,
                          'Semantic per-stream1MiB/aggregate32MiB raw cap reached')
            for profile in boundary.PROFILES:
                cache = ROOT / 'caches' / profile
                if cache.exists():
                    boundary.need(not cache.is_symlink() and cache.resolve() == cache,
                                  'Exact ordinary profile cache root required')
                    amount = sum(path.lstat().st_size for path in cache.rglob('*')
                                 if path.is_file() and not path.is_symlink())
                    boundary.need(amount < boundary.CACHE_LIMIT, 'Private profile cache reaches64MiB fence')
            self.last_tree = time.monotonic()

    def run(self, label, argv, environment, cwd, category=None, compiler_source=None):
        boundary.need(label and '/' not in label and not any(row['label'] == label for row in self.checks),
                      'One unique bounded command label required')
        self.guard()
        stdout, stderr = ROOT / (label + '.stdout.txt'), ROOT / (label + '.stderr.txt')
        row = {'label': label, 'command': argv, 'environment': environment, 'cwd': str(cwd),
               'category': category or 'audit', 'source_argument': str(compiler_source) if compiler_source else None}
        self.checks.append(row)
        save('CHECKS.json', self.checks)
        runtime = self

        class Command(durable.OwnedCommand):
            def monitor(self):
                while self.child.poll() is None:
                    self.sample()
                    boundary.need(time.monotonic() - self.began < self.seconds, 'Finite native command deadline reached')
                    self.disk_check()
                    time.sleep(0.2)
                self.sample()
                status = self.child.wait()
                self.persist('semantic_child_terminal', exit_status=status)
                boundary.need(status == 0, 'Actual semantic prerequisite refused; raw streams retained')

            def sample(self):
                before = time.monotonic()
                current, matched = self.observe('semantic_native_sample')
                after = time.monotonic()
                amount = sum(current[pid]['rss'] for pid in matched) + current.get(os.getpid(), {}).get('rss', 0)
                runtime.peak = max(runtime.peak, amount)
                self.peak = max(self.peak, sum(current[pid]['rss'] for pid in matched))
                boundary.need(amount < 6 * 2**30, 'Actual worker/owned descendant RSS reaches6GiB scheduling fence')
                for pid in matched:
                    runtime.owners.add((pid, current[pid]['birth']))
                    runtime.groups.add(current[pid]['group'])
                if compiler_source is not None:
                    direct = current.get(self.child.pid)
                    identity = self.initial
                    boundary.need(identity is not None, 'Owned exact compiler birth required')
                    runtime.observations.setdefault(label, []).append({'monotonic_before': before,
                        'monotonic_after': after, 'stdout_bytes': stdout.stat().st_size,
                        'pid': self.child.pid, 'birth': identity['birth'],
                        'direct_rss_bytes': direct['rss'] if direct and direct['birth'] == identity['birth'] else 0,
                        'is_live': bool(direct and direct['birth'] == identity['birth']),
                        'sampled_owned_commands': [{'pid': pid, 'birth': current[pid]['birth'],
                            'command': current[pid]['command']} for pid in sorted(matched)]})

        seconds = 15 if category == 'sdk' else 120 if category == 'compiler' else 10
        owner = Command(ROOT / (label + '.ownership.json'), processes, 6 * 2**30, seconds,
                        self.guard, cleanup_wait=3)
        previous_environment, previous_directory = dict(os.environ), Path.cwd()
        phase = self.clock.phase(category, seconds) if category else contextlib.nullcontext()
        try:
            with phase:
                os.environ.clear()
                os.environ.update(environment)
                os.chdir(cwd)
                with stdout.open('xb') as out, stderr.open('xb') as err:
                    outcome = owner.execute(argv, out, err)
        finally:
            os.environ.clear()
            os.environ.update(previous_environment)
            os.chdir(previous_directory)
            if owner.initial:
                self.owners.update(owner.owned_history)
                self.groups.add(owner.initial['group'])
            row.update(process_result=outcome if 'outcome' in locals() else None,
                stdout_sha256=boundary.sha(stdout) if stdout.exists() else None,
                stderr_sha256=boundary.sha(stderr) if stderr.exists() else None)
            if owner.initial:
                row.update(direct_pid=owner.initial['pid'], direct_birth=owner.initial['birth'])
            save('CHECKS.json', self.checks)
            if compiler_source is not None:
                save('IMMEDIATE_' + label + '.json', {'build': row,
                    'raw_observations': self.observations.get(label, []),
                    'source_sha256': boundary.sha(compiler_source),
                    'compiler_only_peak_qualified': False, 'whole_build_provider_qualified': False})
        boundary.need(outcome['passed'] and outcome['terminal_qualified'], 'Native command refused: ' + label)
        boundary.need(not stderr.read_bytes(), 'GREEN native prerequisite requires empty stderr: ' + label)
        return stdout.read_bytes(), row

    def terminal(self):
        current = processes()
        remaining = [{'pid': pid, 'birth': birth} for pid, birth in sorted(self.owners)
                     if current.get(pid, {}).get('birth') == birth]
        groups = [{'pid': pid, **row} for pid, row in current.items() if row['group'] in self.groups]
        boundary.need(not remaining and not groups
             and all(type(row.get('process_result')) is dict
                     and row['process_result'].get('terminal_qualified') for row in self.checks),
             'Exact native command/owned PID-birth/groups must be terminal')
        return {'passed': True, 'owned_pid_births': [{'pid': pid, 'birth': birth} for pid, birth in sorted(self.owners)],
                'owned_process_groups': sorted(self.groups), 'terminal_owned_processes': remaining,
                'terminal_owned_groups': groups}


def main():
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    runtime = Runtime()
    result = {'passed': False, 'job_id': JOB, 'source_commit': boundary.COMMIT,
              'target_accepted': False, 'canonical_cells_accepted': 0,
              'scope': 'Six distinct source-bound semantic-only two-model route diagnostics'}
    caches = []
    try:
        boundary.need(ROOT.name == JOB and os.getuid() == 503 and Path.home() == Path('/Users/ci'),
                      'Exact reviewed Mini job/ci503 source root required')
        pins_sha = sys.argv[1]
        boundary.need(boundary.is_sha(pins_sha) and boundary.sha(PROJECT / 'INPUT_PINS.json') == pins_sha,
                      'Actual outer-reviewed payload manifest pin required')
        pins = json.loads((PROJECT / 'INPUT_PINS.json').read_bytes())
        qualified.verify_rows(PROJECT, pins['files'])
        filesystem = os.statvfs(ROOT)
        boundary.require_initial_disk(filesystem.f_bavail * filesystem.f_frsize)
        materialized = json.loads((PROJECT / 'FRONTEND_MATERIALIZATION.json').read_bytes())
        boundary.verify_products(PROJECT, materialized)
        result['producer_prerequisite'] = boundary.verify_producer_evidence(PROJECT, materialized)
        context = json.loads((PROJECT / 'HOST_CONTEXT.json').read_bytes())
        toolchain = Path(context['toolchain']['release_root'])
        qualified.__dict__.update(ROOT=ROOT, PROJECT=PROJECT, CONTEXT=context, TOOLCHAIN=toolchain,
            CONTROL=CONTROL, ATLAS_CONTROL=ATLAS_CONTROL, JOB=JOB, COMMIT=boundary.COMMIT,
            NATIVE_GIT='/Applications/Xcode.app/Contents/Developer/usr/bin/git')
        result['scheduler_pin'] = qualified.verify_context()
        boundary.need(boundary.sha(sys.executable) == '271143990bc83af0fb2404a255038f5faafb96df1584ed7f085e5018c0f33ffb'
            and boundary.sha(PROJECT / 'toolchain.mini-ci.json') == boundary.PROFILE_PIN
            and boundary.sha(toolchain / 'native/agent-crystal-bin') == boundary.BACKEND,
            'Exact existing Alpha/Python/profile cohort required')
        component = qualified.verify_native_component(PROJECT / 'NATIVE_COMPONENT.json')
        boundary.need(boundary.sha(PROJECT / 'GIT_PROVIDER.json') == boundary.GIT_PIN, 'Exact native Git manifest required')
        provider = qualified.verify_git_provider(PROJECT / 'GIT_PROVIDER.json')
        environment = json.loads((PROJECT / 'NATIVE_RECIPE.json').read_bytes())['environment']
        environment.update(component['environment'])
        environment.update(TMPDIR=str(ROOT), CRYSTAL_WORKERS='1',
            MEMORY_BUDGET_TOOLCHAIN_LOCK=str(PROJECT / 'toolchain.mini-ci.json'))
        environment = qualified.configure_git_environment(environment, provider)
        for label, argv, expected in [('git-version', [provider['git_path'], '--version'], provider['version']),
                                      ('git-exec-path', [provider['git_path'], '--exec-path'], provider['exec_path'])]:
            raw, _row = runtime.run(label, argv, environment, ROOT)
            boundary.need(raw.decode().strip() == expected, 'Actual Git metadata differs')
        grant = ROOT / 'grant'
        runtime.run('clone-grant', [provider['git_path'], '-c', 'advice.detachedHead=false', 'clone', '--quiet', str(PROJECT / 'grant.bundle'), str(grant)], environment, ROOT)
        head, _row = runtime.run('grant-head', [provider['git_path'], 'rev-parse', 'HEAD'], environment, grant)
        boundary.need(head.decode().strip() == boundary.COMMIT, 'Exact original Grant commit required')
        qualified.extract_source_archive(PROJECT / 'dependencies.tar', grant)
        sys.path.insert(0, str(grant / 'scripts'))
        from verify_compile_acceptance import source_input_inventory
        from run_compile_acceptance import verify_embedded_bundle
        verify_embedded_bundle(grant)
        before, fingerprint = source_input_inventory(grant)
        expected = json.loads((PROJECT / 'EXPECTED_SOURCE.json').read_bytes())
        save('SOURCE_INPUTS_BEFORE.json', {'inputs': before, 'source_tree_sha256': fingerprint})
        boundary.source_rows_equal(expected['inputs'], before)
        boundary.need(fingerprint == boundary.SOURCE and len(before) == 1554, 'Full original1554-source identity required')
        (ROOT / 'caches').mkdir()
        samples = []
        for profile in boundary.PROFILES:
            runtime.guard()
            output = grant / 'performance/results/frontend-diagnostic' / profile
            output.mkdir(parents=True)
            source, absent_binary = output / 'fixture.cr', output / 'absent-output'
            source.write_bytes((PROJECT / (profile + '.cr.txt')).read_bytes())
            (output / 'fixture.json').write_bytes((PROJECT / (profile + '.json')).read_bytes())
            boundary.require_source_paths(grant, source, profile)
            cache = ROOT / 'caches' / profile
            cache.mkdir()
            caches.append(cache)
            env = dict(environment, CRYSTAL_CACHE_DIR=str(cache))
            sdk = grant / 'performance/vendor/memory_budget/scripts/budget.rb'
            raw, _row = runtime.run(profile + '-prepare', ['/usr/bin/ruby', str(sdk), '--version'], env, grant, 'sdk')
            boundary.need(bool(raw.strip()), 'Actual SDK preparation version output required')
            def stdlib(label):
                return audit_prepared_stdlib(toolchain / 'stdlib', cache / 'budget-stdlib',
                    grant / 'performance/vendor/memory_budget/runtime_overlay',
                    grant / 'performance/vendor/memory_budget/runtime_overlay/manifest.json',
                    ROOT / ('STDLIB_' + profile + '_' + label + '.json'))
            prepared = stdlib('before')
            cache_before = boundary.cache_inventory(cache, runtime.guard)
            save('CACHE_' + profile + '_before.json', cache_before)
            env.update(CRYSTAL_PATH='lib:' + str(cache / 'budget-stdlib'), MEMORY_BUDGET_REQUIRE_ALLOCATION='1')
            backend = toolchain / 'native/agent-crystal-bin'
            runtime.run(profile + '-format', [str(backend), 'tool', 'format', '--check', '--no-color', str(source)], env, grant)
            command = boundary.compiler_argv(backend, source, absent_binary)
            boundary.require_command(command, backend, source, absent_binary)
            raw, build = runtime.run(profile + '-compile', command, env, grant, 'compiler', source)
            parsed = parse_semantic_stats(raw)
            observations = runtime.observations[profile + '-compile']
            association = associate_observed_intervals(parsed, observations)
            boundary.need((association['compiler_pid'], association['compiler_birth']) ==
                          (build['direct_pid'], build['direct_birth']), 'Direct compiler observer identity differs')
            immediate = {'profile': profile, 'build': build, 'source_sha256': boundary.sha(source),
                'manifest_sha256': boundary.sha(output / 'fixture.json'), 'stats': parsed,
                'compiler_rss_phase_observations': association, 'raw_observations': observations,
                'prepared_stdlib_sha256': prepared['sha256'], 'target_accepted': False}
            save('SEMANTIC_COMPILE_' + profile + '.json', immediate)
            boundary.need(not absent_binary.exists() and not absent_binary.is_symlink(), 'Top-level semantic output must remain absent')
            after_cache = boundary.cache_inventory(cache, runtime.guard)
            save('CACHE_' + profile + '_after.json', after_cache)
            boundary.require_semantic_cache(cache_before, after_cache)
            boundary.need(stdlib('after') == prepared, 'Complete prepared stdlib changed')
            current, current_sha = source_input_inventory(grant)
            boundary.source_rows_equal(before, current)
            boundary.need(current_sha == fingerprint, 'Original source identity changed during route')
            samples.append(immediate)
        after, after_sha = source_input_inventory(grant)
        save('SOURCE_INPUTS_AFTER.json', {'inputs': after, 'source_tree_sha256': after_sha})
        boundary.source_rows_equal(before, after)
        boundary.need(after_sha == fingerprint, 'Complete original source parity required')
        boundary.need(qualified.verify_native_component(PROJECT / 'NATIVE_COMPONENT.json') == component
                      and qualified.verify_git_provider(PROJECT / 'GIT_PROVIDER.json') == provider
                      and qualified.verify_context() == result['scheduler_pin'], 'Source/tool/provider context changed')
        qualified.verify_rows(PROJECT, pins['files'])
        boundary.need(runtime.clock.counts == {'sdk': 6, 'compiler': 6}
                      and [row['profile'] for row in samples] == list(boundary.PROFILES),
                      'All six ordered source routes and six distinct SDK/compiler commands required')
        result.update(passed=True, samples=samples, clock=runtime.clock.check(), source_before_after_equal=True,
            compiler_color='GREEN', requested_top_level_semantic_builds=6,
            internal_native_execution_absence_qualified=False, whole_build_provider_qualified=False,
            frontend_reached_census_qualified=False, retained_live_frontend_bytes_qualified=False)
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        cleanup_started = time.monotonic()
        try:
            terminal = runtime.terminal()
            save('COMMAND_TERMINAL.json', terminal)
            if result['passed']:
                inventories = []
                for cache in caches:
                    boundary.need(time.monotonic() - cleanup_started < 25, 'Finite30second cleanup/receipt reserve required')
                    inventories.append({'cache': str(cache), 'inventory': boundary.cache_inventory(cache)})
                save('CACHES_TERMINAL_BEFORE_RETIREMENT.json', {'inventories': inventories, 'terminal': terminal})
                for cache in caches:
                    boundary.need(cache.parent == ROOT / 'caches' and cache.resolve() == cache and not cache.is_symlink(),
                                  'Retire exact owned successful profile cache only')
                    shutil.rmtree(cache)
                boundary.need(all(not path.exists() for path in caches), 'All six successful private caches must be absent')
                result['private_caches_absent'] = True
            else:
                result['failed_caches_retained_for_bounded_recovery'] = [str(path) for path in caches if path.exists()]
            result['terminal'] = terminal
        except BaseException as error:
            result.update(passed=False, cleanup_error={'type': type(error).__name__, 'message': str(error)})
        result.update(checks=runtime.checks, sampled_process_tree_rss_lower_bound_bytes=runtime.peak,
            minimum_observed_disk_free_bytes=runtime.minimum_free, cleanup_seconds=time.monotonic()-cleanup_started,
            worker_pid=os.getpid(), worker_birth=processes()[os.getpid()]['birth'],
            resource_release_owner='root after fresh process/controller/cache readback', resources_automatically_released=False)
        save('GRANT_RESULT.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
