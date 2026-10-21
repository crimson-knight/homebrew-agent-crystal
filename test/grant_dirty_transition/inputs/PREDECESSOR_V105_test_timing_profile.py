"""Physical retained-footer and mocked calibration/return controls; workload creation is intercepted."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import timing_profile as timing
import run_hosted_contrast as contrast
import run_causal_only as causal
import stage_causal_result_artifact as artifact
import test_assignment_cost as inherited
from test_causal_only import returned_observation

ACTUAL = (ROOT / 'fixtures/timing/actual16.stderr.txt').read_text()
HISTORICAL = (ROOT / 'fixtures/timing/historical18.stderr.txt').read_text()
JOB = dict(run_id='synthetic-source-only-job', run_attempt='1', source_commit='synthetic-reviewed-source', job='grant-installed-mac')
TIME_SHA = timing.digest('/usr/bin/time')
TRUE_SHA = timing.digest('/usr/bin/true')


def profile(raw=ACTUAL):
    fields = list(timing.TIME_FIELDS if raw == HISTORICAL else timing.COMMON_FIELDS)
    return dict(format=timing.FORMAT, timing_provider=dict(path='/usr/bin/time', sha256=TIME_SHA),
                probe_provider=dict(path='/usr/bin/true', sha256=TRUE_SHA), job_identity=copy.deepcopy(JOB),
                ordered_fields=fields, unavailable_hardware_fields=[] if raw == HISTORICAL else list(timing.HARDWARE_FIELDS),
                calibration_evidence_sha256='a' * 64)


@contextmanager
def calibration_fixture(raw=ACTUAL, stdout='', exit_code=0, group='absent', unrecorded=False, after_changed=False,
                        before_wrong=False, elapsed=1.0, record_mutation=None, outer_deadline=4800.0, source_changed=False,
                        true_wrong=False):
    with tempfile.TemporaryDirectory(prefix='atlas timing source controls ') as temporary:
        output = Path(temporary).resolve() / 'calibration'
        calls = []
        class SyntheticRunner:
            def __init__(self, directory):
                self.output = directory
                self.records, self.group_observations = [], []
                self.writers_confirmed_retired = True
            def run(self, label, arguments, **settings):
                calls.append(dict(label=label, arguments=arguments, settings=settings, deadline=self.deadline))
                for name, value in [('stdout', stdout), ('stderr', raw)]:
                    (self.output / ('probe.' + name + '.txt')).write_text(value)
                self.writers_confirmed_retired = group == 'absent'
                sample = dict(status=group, elapsed_seconds=0.01)
                observation = dict(group=12345, status=group, scope='original POSIX process group', phase='direct_child_returned',
                                   bounded_drain_exhausted=False, maximum_drain_seconds=5.0, elapsed_seconds=0.01,
                                   original_command_deadline=10.0, drain_deadline=5.0,
                                   samples=[sample], initial_sample=sample.copy(), terminal_sample=sample.copy())
                self.group_observations.append(observation)
                if unrecorded:
                    raise RuntimeError('synthetic original command exception before record')
                row = dict(label=label, arguments=list(arguments), pid=12345, exit_code=exit_code, expected_exit=0, refusal=None,
                           elapsed_seconds=0.25, maximum_seconds=settings['seconds'], original_group=12345,
                           terminal_group_observation=observation, writers_confirmed_retired=self.writers_confirmed_retired,
                           stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest() if self.writers_confirmed_retired else None,
                           stderr_sha256=hashlib.sha256(raw.encode()).hexdigest() if self.writers_confirmed_retired else None)
                if record_mutation:
                    record_mutation(row)
                self.records.append(row)
                timing.save(self.output / 'COMMANDS.json', self.records)
                if exit_code:
                    raise RuntimeError('synthetic positive probe exited ' + str(exit_code))
                return stdout, raw
        driver = SimpleNamespace(Runner=SyntheticRunner)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        original_digest = timing.digest
        def observed_digest(path):
            if after_changed and str(path) == '/usr/bin/time' and calls:
                return 'f' * 64
            if source_changed and Path(path) == Path(timing.__file__) and calls:
                return 'e' * 64
            return original_digest(path)
        with mock.patch.object(timing.importlib.util, 'spec_from_file_location', return_value=spec), \
             mock.patch.object(timing.importlib.util, 'module_from_spec', return_value=driver), \
             mock.patch.object(timing.time, 'monotonic', side_effect=(0.0, elapsed)), \
             mock.patch.object(timing, 'digest', side_effect=observed_digest):
            result = timing.calibrate(output, ROOT / 'vendor/sdk_install_qualification.py',
                                      '0' * 64 if before_wrong else TIME_SHA, '0' * 64 if true_wrong else TRUE_SHA, JOB, outer_deadline)
            yield output, result, calls


class FooterProfileControls(unittest.TestCase):
    def test_actual16_has_exact_retained_rss_footprint_and_explicit_unavailable_pair(self):
        result = contrast.timed_footer(ACTUAL, profile())
        self.assertEqual(result['fields']['maximum resident set size'], 2257960960)
        self.assertEqual(result['fields']['peak memory footprint'], 2222036352)
        self.assertEqual(result['wall_seconds_rounded_0_01'], 32.43)
        self.assertEqual(result['unavailable_hardware_fields'], list(timing.HARDWARE_FIELDS))
        self.assertTrue(all(result['fields'][key] is None for key in timing.HARDWARE_FIELDS))
        self.assertFalse(result['isolated_compiler_peak_qualified'])
        self.assertFalse(result['audited_whole_build_peak_qualified'])

    def test_strict_default_retains_original18_acceptance_and16_refusal(self):
        with self.assertRaisesRegex(RuntimeError, 'complete original Darwin'):
            contrast.timed_footer(ACTUAL)
        result = contrast.timed_footer(HISTORICAL)
        self.assertEqual(result['fields']['instructions retired'], 126328325475)
        self.assertNotIn('timing_profile_sha256', result)

    def test_historical18_calibrated_mode_retains_both_hardware_values(self):
        result = contrast.timed_footer(HISTORICAL, profile(HISTORICAL))
        self.assertEqual(result['unavailable_hardware_fields'], [])
        self.assertEqual(result['fields']['cycles elapsed'], 44710542240)

    def test_each_truncated_required_field_refuses(self):
        for raw in (ACTUAL, HISTORICAL):
            for index in range(len(raw.splitlines())):
                with self.subTest(lines=len(raw.splitlines()), index=index), self.assertRaises(RuntimeError):
                    contrast.timed_footer('\n'.join(raw.splitlines()[:index]) + '\n', profile(raw))

    def test_duplicate_unknown_and_reordered_fields_refuse(self):
        lines = ACTUAL.splitlines()
        duplicate = lines.copy(); duplicate[2] = duplicate[1]
        swapped = lines.copy(); swapped[1], swapped[2] = swapped[2], swapped[1]
        for raw in ('\n'.join(duplicate), '\n'.join(swapped), ACTUAL.replace('page faults', 'unknown field')):
            with self.subTest(raw=raw[:40]), self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, profile())

    def test_single_hardware_field_refuses_both_possible_labels(self):
        for label in timing.HARDWARE_FIELDS:
            raw = ACTUAL.replace(ACTUAL.splitlines()[-1], ' 123  ' + label + '\n' + ACTUAL.splitlines()[-1])
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, profile())
            changed = profile(); changed['ordered_fields'].insert(-1, label)
            with self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, changed)

    def test_warning_extra_output_blank_line_and_extra_duration_refuse(self):
        for raw in ('Warning: source changed\n' + ACTUAL, ACTUAL + 'extra output\n', ACTUAL + '\n',
                    ACTUAL.splitlines()[0] + '\n' + ACTUAL):
            with self.subTest(raw=raw[-40:]), self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, profile())

    def test_numeric_grammar_stays_exact_and_rss_stays_positive(self):
        for raw in (ACTUAL.replace('32.43 real', '32.4 real'), ACTUAL.replace('32.43 real', '-1.00 real'),
                    ACTUAL.replace('2257960960', '0'), ACTUAL.replace('2257960960', '-2'),
                    ACTUAL.replace('2257960960', '2.2'), ACTUAL.replace('  page faults', ' page faults')):
            with self.subTest(raw=raw[:80]), self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, profile())

    def test_profile16_and18_shape_drift_refuses_both_directions(self):
        for raw, selected in ((ACTUAL, profile(HISTORICAL)), (HISTORICAL, profile())):
            with self.assertRaises(RuntimeError):
                contrast.timed_footer(raw, selected)

    def test_wrong_profile_version_roster_availability_and_unknown_key_refuse(self):
        for key, value in [('format', 'different-version'), ('ordered_fields', list(reversed(timing.COMMON_FIELDS))),
                           ('unavailable_hardware_fields', []), ('calibration_evidence_sha256', 'unbound'), ('extra', True)]:
            selected = profile(); selected[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                contrast.timed_footer(ACTUAL, selected)

    def test_exact_provider_and_same_job_profile_join_refuses_wrong_context(self):
        for kwargs in (dict(time_sha256='0' * 64), dict(true_sha256='0' * 64), dict(job_identity=dict(run_id='different-job'))):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                timing.validate_profile(profile(), **kwargs)
        for key in ('timing_provider', 'probe_provider'):
            selected = profile(); selected[key]['path'] = '/other/provider'
            with self.assertRaises(RuntimeError):
                timing.validate_profile(selected)

    def test_fixture_provenance_replays_actual_and_historical_byte_hashes(self):
        rows = json.loads((ROOT / 'fixtures/timing/PROVENANCE.json').read_bytes())['fixtures']
        self.assertEqual([row['lines'] for row in rows], [16, 18])
        for row in rows:
            raw = (ROOT / 'fixtures/timing' / row['path']).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (row['bytes'], row['sha256']))
        actual = json.loads((ROOT / 'ACTUAL_FOOTER_FAILURE.json').read_bytes())
        self.assertEqual(actual['run_id'], '39501577847')


class CalibrationControls(unittest.TestCase):
    def test_positive16_and18_probe_records_exact_argv_limits_hashes_and_groups(self):
        for raw in (ACTUAL, HISTORICAL):
            with self.subTest(lines=len(raw.splitlines())), calibration_fixture(raw=raw) as (output, result, calls):
                self.assertTrue(result['passed'], result)
                timing.complete_return(result, output)
                self.assertEqual(calls[0]['arguments'], ['/usr/bin/time', '-l', '/usr/bin/true'])
                self.assertEqual((calls[0]['settings']['seconds'], calls[0]['deadline']), (10, 30.0))
                self.assertEqual(calls[0]['settings']['environment']['LC_ALL'], 'C')
                self.assertNotIn('CRYSTAL_OPTS', calls[0]['settings']['environment'])
                self.assertEqual(result['providers']['timing_provider']['before_sha256'], TIME_SHA)
                self.assertEqual(result['providers']['probe_provider']['after_sha256'], TRUE_SHA)
                self.assertEqual(result['actual_target_cells_accepted'], 0)

    def test_failed_probe_exit_preserves_original_error_and_command(self):
        with calibration_fixture(exit_code=7) as (output, result, _):
            self.assertFalse(result['passed'])
            self.assertIn('positive probe exited 7', result['error'])
            self.assertEqual(result['commands'][0]['exit_code'], 7)
            self.assertTrue((output / 'probe.stderr.txt').is_file())

    def test_probe_warning_and_stdout_refuse_positive_calibration(self):
        for settings in (dict(raw='warning\n' + ACTUAL), dict(stdout='extra\n'), dict(raw=HISTORICAL.replace('cycles elapsed', 'unknown'))):
            with self.subTest(settings=settings), calibration_fixture(**settings) as (_, result, _):
                self.assertFalse(result['passed'])

    def test_live_and_unverifiable_original_groups_refuse_hash_admission(self):
        for state in ('present', 'unverifiable'):
            with self.subTest(state=state), calibration_fixture(group=state) as (output, result, _):
                self.assertFalse(result['passed'])
                self.assertIsNone(result['commands'][0]['stderr_sha256'])
                self.assertIn('group absence', result['return_error'])
                self.assertTrue((output / 'probe.stderr.txt').is_file())

    def test_unrecorded_probe_exception_retains_terminal_original_group(self):
        with calibration_fixture(group='unverifiable', unrecorded=True) as (output, result, _):
            self.assertFalse(result['passed'])
            self.assertEqual(result['commands'], [])
            self.assertIn('before record', result['error'])
            self.assertFalse(result['terminal_runner_state']['writers_confirmed_retired'])
            self.assertTrue((output / 'CALIBRATION_RESULT.json').is_file())

    def test_wrong_provider_before_probe_executes_zero_commands(self):
        for settings in (dict(before_wrong=True), dict(true_wrong=True)):
            with self.subTest(settings=settings), calibration_fixture(**settings) as (_, result, calls):
                self.assertFalse(result['passed'])
                self.assertEqual(calls, [])
                self.assertIn('provider required before', result['error'])

    def test_changed_provider_after_probe_refuses_and_retains_finalization_error(self):
        with calibration_fixture(after_changed=True) as (_, result, _):
            self.assertFalse(result['passed'])
            self.assertTrue(result['finalization_errors'])
            self.assertEqual(result['providers']['timing_provider']['after_sha256'], 'f' * 64)

    def test_changed_calibration_source_after_probe_refuses_complete_return(self):
        with calibration_fixture(source_changed=True) as (_, result, _):
            self.assertFalse(result['passed'])
            self.assertTrue(result['finalization_errors'])
            self.assertIn('source/provider required at return', result['finalization_errors'][0])

    def test_original_group_identity_deadline_and_terminal_sample_joins_refuse(self):
        for mutation in (lambda row: row.update(pid=99), lambda row: row.update(original_group=True),
                         lambda row: row['terminal_group_observation'].update(scope='separate process scope'),
                         lambda row: row['terminal_group_observation'].update(drain_deadline=11.0),
                         lambda row: row['terminal_group_observation'].update(terminal_sample=dict(status='present', elapsed_seconds=0.01))):
            with calibration_fixture(record_mutation=mutation) as (_, result, _):
                self.assertFalse(result['passed'])
                self.assertIn('return_error', result)

    def test_probe_return_requires_raw_command_hashes_and_exact_argv(self):
        for mutation in (lambda row: row.update(stderr_sha256='0' * 64),
                         lambda row: row.update(arguments=['/usr/bin/true']),
                         lambda row: row.update(refusal='synthetic retirement refusal'),
                         lambda row: row.update(maximum_seconds=11), lambda row: row.update(elapsed_seconds=10.1)):
            with calibration_fixture(record_mutation=mutation) as (_, result, _):
                self.assertFalse(result['passed'])
                self.assertIn('return_error', result)

    def test_changed_raw_profile_and_persisted_command_refuse_complete_return(self):
        for name in ('probe.stderr.txt', 'TIMING_PROFILE.json', 'COMMANDS.json'):
            with self.subTest(name=name), calibration_fixture() as (output, result, _):
                self.assertTrue(result['passed'])
                (output / name).write_text('changed\n')
                with self.assertRaises((RuntimeError, ValueError)):
                    timing.complete_return(result, output)

    def test_original_calibration_and_outer_horizons_are_finite(self):
        with calibration_fixture(elapsed=30.1) as (_, result, _):
            self.assertFalse(result['passed'])
            self.assertIn('thirty-second horizon', result['return_error'])
        for value in (29.9, float('nan'), float('inf'), True):
            with self.subTest(value=value), calibration_fixture(outer_deadline=value) as (_, result, calls):
                self.assertFalse(result['passed'])
                self.assertEqual(calls, [])


class CalibratedQualifierControls(unittest.TestCase):
    def execute(self, raw=ACTUAL, drift_arm=None, warning=False, mutate_profile=False, wrong_context=None, **settings):
        original = contrast.qualify
        selected = profile(raw)
        def supplied(args):
            contrast.admit_sdk_metadata.return_value['job_identity'] = copy.deepcopy(JOB)
            args.timing_true_sha256 = TRUE_SHA
            if wrong_context == 'time':
                args.time_sha256 = '0' * 64
            elif wrong_context == 'true':
                args.timing_true_sha256 = '0' * 64
            elif wrong_context == 'job':
                contrast.admit_sdk_metadata.return_value['job_identity'] = dict(run_id='other-source-only-job')
            driver = contrast.importlib.util.module_from_spec.return_value
            inherited_run = driver.Runner.run
            def observed_run(runner, label, arguments, **options):
                stdout, stderr = inherited_run(runner, label, arguments, **options)
                if label == 'build':
                    stderr = HISTORICAL if runner.output.name == drift_arm and raw == ACTUAL else ACTUAL if runner.output.name == drift_arm else raw
                    if warning:
                        stderr = 'Warning: synthetic compiler warning\n' + stderr
                    if mutate_profile:
                        selected['calibration_evidence_sha256'] = 'b' * 64
                return stdout, stderr
            driver.Runner.run = observed_run
            return original(args, absolute_deadline=4800.0, timing_profile=selected)
        with mock.patch.object(contrast, 'qualify', side_effect=supplied), mock.patch.object(contrast.time, 'monotonic', return_value=200.0):
            return inherited.AssignmentCostControls().mocked_hosted_triplet(**settings)

    def test_real_qualifier_calibrated16_and18_preserve_three_arms_and_behavior_controls(self):
        for raw in (ACTUAL, HISTORICAL):
            with self.subTest(lines=len(raw.splitlines())):
                code, result, calls = self.execute(raw=raw)
                self.assertEqual(code, 0, result)
                self.assertEqual(len(calls), 15)
                self.assertEqual([row['arm'] for row in result['samples']], ['original', 'candidate', 'restored'])
                self.assertEqual(result['effective_absolute_deadline'], 4800.0)
                self.assertEqual(result['original_maximum_seconds'], 4800)
                self.assertEqual(result['target_cells_accepted'], 0)
                self.assertTrue(all(row['time']['timing_profile_sha256'] == result['timing_profile_sha256'] for row in result['samples']))

    def test_real_qualifier_candidate_shape_drift_retains_original_and_restores_source(self):
        code, result, calls = self.execute(drift_arm='candidate')
        self.assertEqual(code, 2)
        self.assertEqual([row['arm'] for row in result['samples']], ['original', 'candidate'])
        self.assertTrue(result['samples'][0]['passed'])
        self.assertEqual(len(calls), 7)
        self.assertIn('calibrated Darwin timing line count', result['error'])
        self.assertEqual(result['finalization_errors'], [])

    def test_real_qualifier_warning_refuses_before_owner_and_runtime_controls(self):
        code, result, calls = self.execute(warning=True)
        self.assertEqual(code, 2)
        self.assertEqual(len(calls), 2)
        self.assertNotIn('time', result['samples'][0])

    def test_real_qualifier_profile_mutation_refuses_complete_return(self):
        code, result, _ = self.execute(mutate_profile=True)
        self.assertEqual(code, 2)
        self.assertTrue(result['finalization_errors'])
        self.assertIn('calibrated timing profile', result['finalization_errors'][0])

    def test_real_qualifier_failure_keeps_original_exception_and_restores_source(self):
        code, result, _ = self.execute(failing_arm='candidate')
        self.assertEqual(code, 2)
        self.assertIn('synthetic failed build candidate', result['error'])
        self.assertEqual(result['finalization_errors'], [])

    def test_real_qualifier_refuses_wrong_profile_provider_and_job_before_commands(self):
        for context in ('time', 'true', 'job'):
            with self.subTest(context=context), self.assertRaisesRegex(RuntimeError, 'Timing profile differs'):
                self.execute(wrong_context=context)


class CausalCalibrationControls(unittest.TestCase):
    def execute(self, calibration_failed=False, returned_calibration=False, clock=(0.0, 1.0, 2.0), mutate=None):
        with tempfile.TemporaryDirectory(prefix='atlas causal calibration controls ') as temporary:
            root = Path(temporary).resolve()
            args = SimpleNamespace(output=root / 'causal', sdk_evidence=root / 'sdk', driver=ROOT / 'vendor/sdk_install_qualification.py',
                packet_sha256='synthetic-mocked-packet', python_sha256=causal.digest(Path(sys.executable).resolve()),
                time_sha256=TIME_SHA, timing_true_sha256=TRUE_SHA)
            admission = dict(providers=dict(compiler_wrapper=dict(path='/ordinary/bin/crystal-alpha')), job_identity=copy.deepcopy(JOB))
            calls = []
            observed = returned_observation()
            def prepare(destination, *unused):
                destination.mkdir(); (destination / 'COMPARISON_PLAN.json').write_text('{}')
            def calibrate(output, driver, time_sha, true_sha, job, deadline):
                calls.append(('calibrate', deadline, job, time_sha, true_sha))
                output.mkdir()
                receipt = dict(passed=not calibration_failed, profile=profile())
                for name, value in [('CALIBRATION_RESULT.json', receipt), ('TIMING_PROFILE.json', receipt['profile']), ('COMMANDS.json', [])]:
                    timing.save(output / name, value)
                for stream in ('stdout', 'stderr'):
                    (output / ('probe.' + stream + '.txt')).write_text('' if stream == 'stdout' else ACTUAL)
                return receipt
            def calibration_return(receipt, output):
                calls.append(('calibration_return',))
                if not receipt['passed'] or (returned_calibration and sum(row[0] == 'calibration_return' for row in calls) > 1):
                    raise RuntimeError('synthetic original calibration return refusal')
            def qualify(settings, absolute_deadline=None, timing_profile=None):
                calls.append(('qualify', absolute_deadline, timing_profile, settings.timing_true_sha256))
                settings.output.mkdir(parents=True)
                timing.save(settings.output / 'COMPARISON_RESULT.json', observed)
                if mutate:
                    mutate(args.output)
                return 0
            with mock.patch.object(causal, 'protect_packet', return_value={}), \
                 mock.patch.object(causal, 'metadata', return_value=admission), \
                 mock.patch.object(causal, 'stage', return_value=dict(synthetic=True)), \
                 mock.patch.object(causal, 'prepare', side_effect=prepare), \
                 mock.patch.object(causal, 'calibrate', side_effect=calibrate), \
                 mock.patch.object(causal, 'calibration_return', side_effect=calibration_return), \
                 mock.patch.object(causal, 'qualify', side_effect=qualify), \
                 mock.patch.object(causal.time, 'monotonic', side_effect=clock):
                code = causal.run(args)
            return code, json.loads((args.output / 'CAUSAL_ONLY_RESULT.json').read_bytes()), calls

    def test_calibration_is_inside_outer_horizon_before4500_admission_and_all_three_arms(self):
        code, result, calls = self.execute()
        self.assertEqual(code, 0, result)
        self.assertEqual([row[0] for row in calls], ['calibrate', 'calibration_return', 'qualify', 'calibration_return'])
        self.assertEqual(calls[0][1], 4800.0)
        self.assertEqual(calls[2][1], 4800.0)
        self.assertEqual(calls[2][2], profile())
        self.assertEqual((result['maximum_seconds'], result['full_arm_seconds'], result['build_limit_seconds'], result['same_binary_control_limit_seconds']), (4800, 1500, 900, 120))
        self.assertEqual(result['actual_target_cells_accepted'], 0)

    def test_calibration_failure_preserves_refusal_and_executes_zero_arms(self):
        code, result, calls = self.execute(calibration_failed=True)
        self.assertEqual(code, 2)
        self.assertFalse(result['causal_launch_admitted'])
        self.assertFalse(any(row[0] == 'qualify' for row in calls))
        self.assertIn('original calibration return refusal', result['error'])
        self.assertTrue(result['finalization_errors'])

    def test_calibration_overhead_does_not_extend_original4500_admission(self):
        code, result, calls = self.execute(clock=(0.0, 301.0, 302.0))
        self.assertEqual(code, 2)
        self.assertFalse(any(row[0] == 'qualify' for row in calls))
        self.assertIn('Three complete original1500', result['error'])

    def test_calibration_late_return_refusal_overrides_successful_mocked_triplet(self):
        code, result, _ = self.execute(returned_calibration=True)
        self.assertEqual(code, 2)
        self.assertFalse(result['diagnostic_complete'])
        self.assertTrue(result['finalization_errors'])

    def test_calibration_artifact_mutation_refuses_complete_causal_return(self):
        code, result, _ = self.execute(mutate=lambda output: (output / 'timing-calibration/probe.stderr.txt').write_text('changed\n'))
        self.assertEqual(code, 2)
        self.assertTrue(result['finalization_errors'])

    def test_outer4800_return_stays_authoritative_after_calibration(self):
        code, result, _ = self.execute(clock=(0.0, 1.0, 4800.1))
        self.assertEqual(code, 2)
        self.assertFalse(result['diagnostic_complete'])

    def test_positive_artifact_roster_retains_exact_calibration_outputs_and_refusal(self):
        with calibration_fixture(exit_code=7) as (output, result, _):
            source = output.parent / 'result'
            source.mkdir()
            output.rename(source / 'timing-calibration')
            snapshot = artifact.stage(source, output.parent / 'artifact')
            names = {row['path'] for row in snapshot['files']}
            for name in ('CALIBRATION_RESULT.json', 'COMMANDS.json', 'probe.stdout.txt', 'probe.stderr.txt'):
                self.assertIn('timing-calibration/' + name, names)
            self.assertIn('timing-calibration/TIMING_PROFILE.json', snapshot['missing_failure_evidence'])
            self.assertEqual(json.loads((output.parent / 'artifact/timing-calibration/CALIBRATION_RESULT.json').read_bytes())['error'], result['error'])

    def test_active_workflow_opt_in_and_exact_original_deadlines_remain_explicit(self):
        raw = (ROOT / 'grant-causal-mac.proposed.yml').read_text()
        self.assertIn('"--timing-true-sha256", hashlib.sha256(pathlib.Path("/usr/bin/true").read_bytes()).hexdigest()', raw)
        self.assertIn('timeout-minutes: 82', raw)
        self.assertIn('python3 -O -I -S -B test/grant_assignment_cost/test_timing_profile.py', raw)
        self.assertEqual((causal.TOTAL_SECONDS, contrast.GLOBAL_SECONDS, contrast.ARM_SECONDS, timing.CALIBRATION_SECONDS, timing.PROBE_SECONDS), (4800, 4800, 1500, 30, 10))


if __name__ == '__main__':
    with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('Source-only tests intercept workload creation')), \
         mock.patch.object(os, 'kill', side_effect=AssertionError('Source-only tests intercept process signals')), \
         mock.patch.object(os, 'killpg', side_effect=AssertionError('Source-only tests intercept group signals')):
        unittest.main(verbosity=2)
