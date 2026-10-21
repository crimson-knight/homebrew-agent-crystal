"""Guarded metadata controls: real retained SDK bytes with synthetic job seals."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import same_job_policy as policy
import run_serial as serial
import qualify_same_job_sdk as sdk_call
from stage_result_artifact import stage as stage_artifact


def environment(evidence):
    job = policy.read(evidence / 'RUNNER.json')
    return dict(GITHUB_RUN_ID=job['run_id'], GITHUB_RUN_ATTEMPT=job['run_attempt'], GITHUB_SHA=job['source_commit'],
                GITHUB_JOB='synthetic-job', RUNNER_NAME='synthetic-runner', RUNNER_OS='macOS', RUNNER_ARCH='ARM64',
                ATLAS_GRANT_JOB_NONCE='0' * 64)


def synthetic_seal(evidence, env):
    value = dict(job_identity=policy.identity(env), nonce=env['ATLAS_GRANT_JOB_NONCE'], sdk_call_returned=True, sdk_return_code=0,
                 driver_sha256=policy.DRIVER_SHA256, policy_sha256=policy.digest(policy.__file__),
                 wrapper_sha256=policy.digest(ROOT / 'qualify_same_job_sdk.py'), evidence=policy.roster(evidence))
    (evidence / 'SAME_JOB_BINDING.json').write_text(json.dumps(value))


class SameJobPolicyControls(unittest.TestCase):
    def fixture(self, directory):
        evidence = Path(directory) / 'synthetic-sealed-retained-readiness'
        shutil.copytree(ROOT / 'inputs/accepted_b562', evidence)
        env = environment(evidence)
        synthetic_seal(evidence, env)
        return evidence, env

    def test_retained_real_changed_compiler_profile_admitted_as_metadata_only(self):
        old, new = ROOT / 'inputs/accepted_d40f', ROOT / 'inputs/accepted_b562'
        a = policy.metadata(old, environment(old), check_binding=False)
        b = policy.metadata(new, environment(new), check_binding=False)
        self.assertEqual(a['observed_profile_sha256'], policy.PREDECESSOR_PROFILE_SHA256)
        self.assertEqual(b['observed_profile_sha256'], 'b562503cee1262e222b545771510f5c60b7f018b2720be17f1c53654fc4ce715')
        self.assertNotEqual(a['profile']['compiler_sha256'], b['profile']['compiler_sha256'])
        aa, bb = dict(a['profile']), dict(b['profile'])
        aa.pop('compiler_sha256'); bb.pop('compiler_sha256')
        self.assertEqual(aa, bb)
        self.assertEqual(b['target_cells_accepted'], 0)

    def test_synthetic_same_call_seal_accepts_and_every_sibling_identity_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence, env = self.fixture(temporary)
            policy.metadata(evidence, env)
            for key in policy.JOB_KEYS + ('ATLAS_GRANT_JOB_NONCE',):
                changed = dict(env, **{key: 'changed'})
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, changed)

    def test_changed_profile_ruby_or_unreviewed_key_refuses_even_after_reseal(self):
        for change in ('ruby_sha256', 'ruby_launcher_sha256', 'extra'):
            with tempfile.TemporaryDirectory() as temporary:
                evidence, env = self.fixture(temporary)
                profile_path = evidence / 'REVIEWED_COMPILER_PROFILE.json'
                value = policy.read(profile_path)
                value[change] = '1' * 64
                profile_path.write_text(json.dumps(value))
                synthetic_seal(evidence, env)
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, env)

    def test_changed_readiness_formula_stdlib_provider_raw_or_sdk_source_refuses(self):
        changes = [('READINESS_RESULT.json', 'passed', False), ('READINESS_RESULT.json', 'default_examples', True),
                   ('RUNNER.json', 'qualification_script_sha256', '1' * 64), ('STDLIB_AFTER.json', 'sha256', '1' * 64)]
        for filename, field, value in changes:
            with tempfile.TemporaryDirectory() as temporary:
                evidence, env = self.fixture(temporary)
                data = policy.read(evidence / filename); data[field] = value
                (evidence / filename).write_text(json.dumps(data)); synthetic_seal(evidence, env)
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, env)
        for filename in ('INSTALLED_FORMULA.rb', 'sdk-source.tar.gz', 'alpha-version.stdout.txt', 'default-specs.stdout.txt'):
            with tempfile.TemporaryDirectory() as temporary:
                evidence, env = self.fixture(temporary)
                path = evidence / filename; path.write_bytes(path.read_bytes() + b'changed')
                synthetic_seal(evidence, env)
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, env)

    def test_changed_provider_join_and_post_run_seal_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence, env = self.fixture(temporary)
            first = policy.metadata(evidence, env)
            path = evidence / 'PROVIDER_IDENTITIES.json'
            data = policy.read(path); data['compiler_backend']['sha256'] = '1' * 64
            path.write_text(json.dumps(data)); synthetic_seal(evidence, env)
            with self.assertRaises(RuntimeError):
                policy.metadata(evidence, env)
        with tempfile.TemporaryDirectory() as temporary:
            evidence, env = self.fixture(temporary)
            (evidence / 'unexpected.txt').write_text('changed after SDK return')
            with self.assertRaisesRegex(RuntimeError, 'complete readiness bytes'):
                policy.metadata(evidence, env)

    def test_exact_peer_command_pid_and_timeout_substitutions_refuse(self):
        for field, value in [('pid', False), ('pid', -1), ('maximum_seconds', 999999), ('elapsed_seconds', 999999),
                             ('original_group', 0.0), ('expected_exit', False), ('elapsed_seconds', -1),
                             ('maximum_seconds', True), ('elapsed_seconds', float('nan'))]:
            with tempfile.TemporaryDirectory() as temporary:
                evidence, env = self.fixture(temporary)
                rows = policy.read(evidence / 'COMMANDS.json')
                rows[0][field] = value
                (evidence / 'COMMANDS.json').write_text(json.dumps(rows))
                synthetic_seal(evidence, env)
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, env)

    def test_command_and_result_group_identity_deadline_and_sample_joins_refuse(self):
        for field, value in [('group', False), ('group', -1), ('maximum_drain_seconds', True),
                             ('elapsed_seconds', 6), ('drain_deadline', 999999999), ('bounded_drain_exhausted', True)]:
            with tempfile.TemporaryDirectory() as temporary:
                evidence, env = self.fixture(temporary)
                rows = policy.read(evidence / 'COMMANDS.json')
                result = policy.read(evidence / 'READINESS_RESULT.json')
                rows[0]['terminal_group_observation'][field] = value
                result['owned_group_observations'][0][field] = value
                (evidence / 'COMMANDS.json').write_text(json.dumps(rows))
                (evidence / 'READINESS_RESULT.json').write_text(json.dumps(result))
                synthetic_seal(evidence, env)
                with self.assertRaises(RuntimeError):
                    policy.metadata(evidence, env)

    def test_packet_refuses_changed_import_before_delegation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'imported.py'; source.write_text('value = 1\n')
            (root / 'SOURCE_PINS.json').write_text(json.dumps(dict(files=[dict(path='imported.py', bytes=source.stat().st_size, sha256=policy.digest(source))])))
            expected = policy.digest(root / 'SOURCE_PINS.json')
            with mock.patch.object(policy, 'ROOT', root):
                policy.protect_packet(expected)
                source.write_text('value = 2\n')
                with self.assertRaisesRegex(RuntimeError, 'dependency'):
                    policy.protect_packet(expected)

    def test_mocked_sdk_in_process_call_seals_one_fresh_nonce_and_retains_failure(self):
        for returned in (0, 1):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = SimpleNamespace(driver=ROOT / 'vendor/sdk_install_qualification.py', output=root / 'sdk',
                                       packet_sha256='synthetic', python_sha256=policy.digest(Path(sys.executable).resolve()))
                env = environment(ROOT / 'inputs/accepted_b562')
                env.update(GITHUB_ACTIONS='true', GITHUB_ENV=str(root / 'github_env'))
                calls = []
                def qualify(output, lock):
                    calls.append((output, lock['sdk']['commit']))
                    shutil.copytree(ROOT / 'inputs/accepted_b562', output)
                    return returned
                spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
                module = SimpleNamespace(qualify=qualify)
                with mock.patch.dict(os.environ, env), mock.patch.object(sdk_call.platform, 'system', return_value='Darwin'), mock.patch.object(sdk_call.platform, 'machine', return_value='arm64'), mock.patch.object(sdk_call, 'protect_packet', return_value={}), mock.patch.object(sdk_call.importlib.util, 'spec_from_file_location', return_value=spec), mock.patch.object(sdk_call.importlib.util, 'module_from_spec', return_value=module):
                    if returned:
                        with self.assertRaisesRegex(RuntimeError, 'qualification failed'):
                            sdk_call.qualify(args)
                    else:
                        self.assertEqual(sdk_call.qualify(args), 0)
                    seal = policy.read(args.output / 'SAME_JOB_BINDING.json')
                    self.assertEqual(seal['nonce'], os.environ['ATLAS_GRANT_JOB_NONCE'])
                    self.assertIn(seal['nonce'], (root / 'github_env').read_text())
                    self.assertEqual(seal['sdk_return_code'], returned)
                    self.assertEqual(len(calls), 1)

    def test_serial_complete_return_requires_all_original_groups_absent(self):
        value = dict(finalization_errors=[], samples=[dict(terminal_runner_state=dict(writers_confirmed_retired=True, original_group_observations=[dict(status='absent')]), commands=[dict(writers_confirmed_retired=True, terminal_group_observation=dict(status='absent'))])])
        serial.complete_return(value)
        for status in ('present', 'unverifiable'):
            changed = copy.deepcopy(value); changed['samples'][0]['commands'][0]['terminal_group_observation']['status'] = status
            with self.assertRaises(RuntimeError):
                serial.complete_return(changed)
        value['finalization_errors'] = ['changed source']
        with self.assertRaises(RuntimeError):
            serial.complete_return(value)

    def mocked_serial(self, first_code=0, alive=False, exhausted=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = SimpleNamespace(output=root / 'serial', sdk_evidence=root / 'sdk', packet_sha256='synthetic',
                                   python_sha256='synthetic', time_sha256='synthetic', driver=root / 'driver.py')
            admission = dict(providers=dict(compiler_wrapper=dict(path='/ordinary/bin/crystal-alpha')))
            order = []
            def prepare(output, *unused):
                output.mkdir(); (output / 'COMPARISON_PLAN.json').write_text('{}')
            def qualify(settings):
                order.append(settings.models)
                settings.output.mkdir(parents=True)
                observation = dict(diagnostic_complete=first_code == 0 if settings.models == 300 else True, finalization_errors=[],
                                   samples=[dict(terminal_runner_state=dict(writers_confirmed_retired=not alive, original_group_observations=[dict(status='present' if alive else 'absent')]), commands=[dict(writers_confirmed_retired=not alive,
                                               terminal_group_observation=dict(status='present' if alive else 'absent'))])])
                (settings.output / 'COMPARISON_RESULT.json').write_text(json.dumps(observation))
                return first_code if settings.models == 300 else 0
            clock = [0.0, 1.0, 2000.0, 2001.0] if exhausted else [0.0, 1.0, 2.0, 3.0]
            with mock.patch.object(serial, 'protect_packet', return_value={}), mock.patch.object(serial, 'metadata', return_value=admission), mock.patch.object(serial, 'stage', return_value=dict(synthetic=True)), mock.patch.object(serial, 'prepare', side_effect=prepare), mock.patch.object(serial, 'prepare_baseline', side_effect=prepare), mock.patch.object(serial, 'qualify', side_effect=qualify), mock.patch.object(serial.time, 'monotonic', side_effect=clock):
                code = serial.run(args)
            return code, order, policy.read(args.output / 'SERIAL_RESULT.json')

    def test_mocked_serial_orders_300_then_one10_triplet(self):
        code, order, result = self.mocked_serial()
        self.assertEqual((code, order), (0, [300, 10]))
        self.assertEqual(result['maximum_seconds'], 6600)
        self.assertEqual(result['actual_target_cells_accepted'], 0)

    def test_mocked_failed_baseline_continues_only_after_verified_return(self):
        code, order, result = self.mocked_serial(first_code=2)
        self.assertEqual((code, order), (2, [300, 10]))
        code, order, result = self.mocked_serial(first_code=2, alive=True)
        self.assertEqual((code, order), (2, [300]))
        self.assertIn('original groups must be verified absent', result['error'])

    def test_mocked_serial_refuses_shortened_full_triplet_horizon(self):
        code, order, result = self.mocked_serial(exhausted=True)
        self.assertEqual((code, order), (2, [300]))
        self.assertIn('Complete unchanged experiment horizons', result['error'])

    def test_physical_artifact_projects_only_explicit_results_and_refuses_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'serial'; source.mkdir()
            (source / 'SERIAL_RESULT.json').write_text('{}')
            (source / 'private-source').mkdir()
            (source / 'private-source/sensitive-metadata.txt').write_text('source tree metadata')
            result = source / 'results/baseline300/original'; result.mkdir(parents=True)
            (result / 'build.stderr.txt').write_text('raw failed build')
            observed = stage_artifact(source, root / 'artifact')
            self.assertEqual([row['path'] for row in observed['files'] if not row['path'].startswith('packet/')], ['SERIAL_RESULT.json', 'results/baseline300/original/build.stderr.txt'])
            hidden = source / 'results/.git'; hidden.mkdir()
            (hidden / 'config.json').write_text('synthetic checkout metadata')
            observed = stage_artifact(source, root / 'metadata-filtered')
            self.assertFalse(any('.git' in row['path'] for row in observed['files']))
            (result / 'build.stderr.txt').unlink()
            (result / 'build.stderr.txt').symlink_to(source / 'private-source/sensitive-metadata.txt')
            with self.assertRaisesRegex(ValueError, 'regular evidence file'):
                stage_artifact(source, root / 'refused')
            (result / 'build.stderr.txt').unlink()
            (result / 'build.stderr.txt').write_bytes(b'Authorization: Bearer ' + b'x' * 32)
            with self.assertRaisesRegex(ValueError, 'credential-shaped'):
                stage_artifact(source, root / 'credential-refused')


if __name__ == '__main__':
    with mock.patch('subprocess.Popen', side_effect=AssertionError('source-only subprocess guard')), mock.patch('os.kill', side_effect=AssertionError('source-only signal guard')), mock.patch('os.killpg', side_effect=AssertionError('source-only signal guard')):
        unittest.main(verbosity=2)
