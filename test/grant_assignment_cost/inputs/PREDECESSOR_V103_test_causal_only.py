"""Mocked causal-controller and physical fixed-roster controls; workload calls remain intercepted."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import run_causal_only as causal
import stage_causal_result_artifact as artifact


def returned_observation():
    return dict(diagnostic_complete=True, owner_shape_accepted=True, finalization_errors=[],
                samples=[dict(arm=arm, terminal_runner_state=dict(writers_confirmed_retired=True,
                             original_group_observations=[dict(status='absent')]),
                             commands=[dict(writers_confirmed_retired=True, terminal_group_observation=dict(status='absent'))])
                         for arm in ('original', 'candidate', 'restored')])


class CausalOnlyControls(unittest.TestCase):
    def execute(self, code=0, observation=None, mutate=None, time_hash=None, clock=(0.0, 1.0, 2.0), admission_changed=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            watched = root / 'protected-source.py'; watched.write_text('value = 1\n')
            expected = causal.digest(watched)
            args = SimpleNamespace(output=root / 'causal', sdk_evidence=root / 'sdk', driver=ROOT / 'vendor/sdk_install_qualification.py',
                                   packet_sha256='synthetic-mocked-packet', python_sha256=causal.digest(Path(sys.executable).resolve()),
                                   time_sha256=time_hash or causal.digest(Path('/usr/bin/time')))
            admission = dict(providers=dict(compiler_wrapper=dict(path='/ordinary/bin/crystal-alpha')))
            observed = copy.deepcopy(observation if observation is not None else returned_observation())
            calls = []
            def prepare(destination, grant, compiler, variant):
                calls.append(('prepare', str(grant), str(compiler), variant))
                destination.mkdir()
                (destination / 'COMPARISON_PLAN.json').write_text('{}')
            def qualify(settings):
                calls.append(('qualify', settings.models, settings.repetition, settings.python_sha256, settings.time_sha256))
                settings.output.mkdir(parents=True)
                (settings.output / 'COMPARISON_RESULT.json').write_text(json.dumps(observed))
                if mutate:
                    mutate(watched)
                return code
            admissions = [admission, dict(changed=True) if admission_changed else admission]
            with mock.patch.object(causal, 'protect_packet', return_value={watched: expected}), \
                 mock.patch.object(causal, 'metadata', side_effect=admissions), \
                 mock.patch.object(causal, 'stage', return_value=dict(synthetic=True)), \
                 mock.patch.object(causal, 'prepare', side_effect=prepare), \
                 mock.patch.object(causal, 'qualify', side_effect=qualify), \
                 mock.patch.object(causal.time, 'monotonic', side_effect=clock):
                outcome = causal.run(args)
            result = json.loads((args.output / 'CAUSAL_ONLY_RESULT.json').read_bytes())
            return outcome, calls, result

    def test_exactly_one_rich10_triplet_and_provider_hashes_are_serialized(self):
        code, calls, result = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual([row[1:3] for row in calls if row[0] == 'qualify'], [(10, 1)])
        self.assertEqual(calls[0][-1], 'cost-isolation')
        self.assertEqual(result['maximum_seconds'], 4800)
        self.assertEqual((result['full_arm_seconds'], result['build_limit_seconds'], result['same_binary_control_limit_seconds']), (1500, 900, 120))
        self.assertEqual(result['historical_300_failure']['run_id'], '39493843606')
        self.assertFalse(result['current_300_baseline']['executed'])
        self.assertEqual(result['actual_target_cells_accepted'], 0)
        self.assertEqual(result['required_target_cells'], 144)
        self.assertTrue(result['triplet_budget']['original_constant_restored'])
        self.assertEqual(result['triplet_budget']['admitted_remaining_triplet_seconds'], 4799.0)
        self.assertEqual(causal.contrast.GLOBAL_SECONDS, 4800)
        for name, supplied in [('python', 'python_sha256'), ('timing', 'time_sha256')]:
            row = result['provider_identities'][name]
            self.assertEqual(row['supplied_sha256'], result['supplied_provider_hashes'][supplied])
            self.assertEqual(row['observed_sha256'], row['supplied_sha256'])

    def test_independent_failed_build_with_verified_return_stays_failed(self):
        observation = returned_observation(); observation.update(diagnostic_complete=False, owner_shape_accepted=False)
        observation['samples'] = observation['samples'][:1]
        code, calls, result = self.execute(code=2, observation=observation)
        self.assertEqual(code, 2)
        self.assertFalse(result['passed'])
        self.assertEqual(result['outcomes'][0]['exit_code'], 2)
        self.assertEqual(result['finalization_errors'], [])

    def test_unverifiable_live_writer_return_refuses_causal_acceptance(self):
        observation = returned_observation()
        observation['samples'][0]['terminal_runner_state']['writers_confirmed_retired'] = False
        observation['samples'][0]['terminal_runner_state']['original_group_observations'][0]['status'] = 'unverifiable'
        code, _, result = self.execute(observation=observation)
        self.assertEqual(code, 2)
        self.assertTrue(result['finalization_errors'])

    def test_changed_source_finalization_refuses_success(self):
        code, _, result = self.execute(mutate=lambda path: path.write_text('value = 2\n'))
        self.assertEqual(code, 2)
        self.assertIn('packet/provider bytes', result['finalization_errors'][0])

    def test_changed_same_job_admission_refuses_success(self):
        code, _, result = self.execute(admission_changed=True)
        self.assertEqual(code, 2)
        self.assertIn('same-job SDK admission', result['finalization_errors'][0])

    def test_supplied_timing_hash_mismatch_refuses_before_launch(self):
        code, calls, result = self.execute(time_hash='0' * 64, clock=(0.0, 1.0))
        self.assertEqual((code, calls), (2, []))
        self.assertEqual(result['historical_300_failure_run_id'], '39493843606')
        self.assertEqual(result['provider_identities']['timing']['supplied_sha256'], '0' * 64)
        self.assertNotEqual(result['provider_identities']['timing']['observed_sha256'], '0' * 64)

    def test_required_arm_horizon_refuses_before_launch(self):
        code, calls, result = self.execute(clock=(0.0, 301.0, 302.0))
        self.assertEqual(code, 2)
        self.assertEqual([row for row in calls if row[0] == 'qualify'], [])
        self.assertIn('Three complete original1500', result['error'])

    def test_terminal_total_horizon_refuses_success(self):
        code, _, result = self.execute(clock=(0.0, 1.0, 4800.1))
        self.assertEqual(code, 2)
        self.assertFalse(result['diagnostic_complete'])

    def test_budget_constant_restores_after_exceptional_qualifier_return(self):
        def refuse(_):
            raise RuntimeError('synthetic exceptional qualifier return')
        code, _, result = self.execute(mutate=refuse)
        self.assertEqual(code, 2)
        self.assertTrue(result['triplet_budget']['original_constant_restored'])
        self.assertEqual(causal.contrast.GLOBAL_SECONDS, 4800)
        self.assertTrue(result['exceptional_comparison_result_retained'])
        self.assertIn('exceptional qualifier return', result['error'])

    def test_budget_context_preserves_required_arm_and_command_limits(self):
        with mock.patch.object(causal.time, 'monotonic', return_value=299.0):
            with causal.triplet_budget(4800.0) as budget:
                self.assertEqual(causal.contrast.GLOBAL_SECONDS, 4501.0)
                self.assertEqual((causal.contrast.ARM_SECONDS, budget['build_limit_seconds'], budget['same_binary_control_limit_seconds']), (1500, 900, 120))
        self.assertEqual(causal.contrast.GLOBAL_SECONDS, 4800)
        self.assertTrue(budget['original_constant_restored'])

    def test_budget_context_exhausted_overhead_refuses_and_retains_constant(self):
        with mock.patch.object(causal.time, 'monotonic', return_value=4800.1):
            with self.assertRaisesRegex(RuntimeError, 'Three complete'):
                with causal.triplet_budget(4800.0):
                    self.fail('Exhausted overhead must refuse admission')
        self.assertEqual(causal.contrast.GLOBAL_SECONDS, 4800)

    def test_wrong_ordered_arm_roster_refuses_success(self):
        observation = returned_observation(); observation['samples'].reverse()
        code, _, result = self.execute(observation=observation)
        self.assertEqual(code, 2)
        self.assertIn('Exactly one', result['error'])

    def test_incomplete_final_source_restoration_refuses(self):
        observation = returned_observation(); observation['finalization_errors'] = ['synthetic unrestored source']
        code, _, result = self.execute(observation=observation)
        self.assertEqual(code, 2)
        self.assertTrue(result['finalization_errors'])

    def test_physical_artifact_selects_new_result_and_fixed_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'result'; source.mkdir()
            (source / 'CAUSAL_ONLY_RESULT.json').write_text('{"passed":false}\n')
            (source / 'HISTORICAL_300_FAILURE.json').write_text('{"run_id":"39493843606"}\n')
            (source / 'private-source').mkdir(); (source / 'private-source/private.json').write_text('{"private":true}')
            observation = source / 'results/triplet10/original'; observation.mkdir(parents=True)
            (observation / 'build.stderr.txt').write_text('retained raw failed build\n')
            artifact.stage(source, root / 'artifact')
            self.assertEqual((root / 'artifact/CAUSAL_ONLY_RESULT.json').read_bytes(), (source / 'CAUSAL_ONLY_RESULT.json').read_bytes())
            self.assertTrue((root / 'artifact/results/triplet10/original/build.stderr.txt').is_file())
            self.assertFalse((root / 'artifact/private-source').exists())
            self.assertIs(artifact.original.expected_roster, artifact.ORIGINAL_ROSTER)

    def test_physical_artifact_refuses_credential_content_and_restores_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'result'; source.mkdir()
            (source / 'CAUSAL_ONLY_RESULT.json').write_text('{"secret":"ghp_' + 'a' * 36 + '"}\n')
            with self.assertRaisesRegex(ValueError, 'credential-shaped'):
                artifact.stage(source, root / 'artifact')
            self.assertIs(artifact.original.expected_roster, artifact.ORIGINAL_ROSTER)

    def test_physical_artifact_refuses_selected_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'result'; source.mkdir()
            target = root / 'outside.json'; target.write_text('{}')
            (source / 'CAUSAL_ONLY_RESULT.json').symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'single-link regular'):
                artifact.stage(source, root / 'artifact')

    def test_all140_predecessor_rows_remain_exact(self):
        rows = json.loads((ROOT / 'inputs/PREDECESSOR_V102_SOURCE_PINS.json').read_bytes())['files']
        self.assertEqual(len(rows), 140)
        for row in rows:
            path = ROOT / row['path']; raw = path.read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (row['bytes'], row['sha256']))


if __name__ == '__main__':
    unittest.main()
