"""Exercise actual cache planner/runner/stager with guarded workload providers."""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'grant_assignment_cost'
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(ROOT))
import cache_evidence as evidence
import cache_contrast as contrast
import prepare_cache_comparison as planner
import run_cache_policy as controller
import stage_cache_results as staging
import test_assignment_cost as inherited

GUARD_CALLS = []


class CachePolicyControls(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        def guard(*args, **kwargs):
            GUARD_CALLS.append('external workload')
            raise AssertionError('Guarded source fixtures require authored workload providers')
        for target in ['subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn', 'os.posix_spawnp', 'os.kill', 'os.killpg']:
            self.guards.enter_context(mock.patch(target, side_effect=guard))
        self.addCleanup(lambda: self.assertEqual(GUARD_CALLS, []))

    def triplet(self, **settings):
        actual = contrast.qualify
        def invoke(args):
            args.cache_packet_sha256 = 'SYNTHETIC separately guarded manifest'
            return actual(args)
        disk = [dict(bitcode_files=value, bitcode_disk_bytes=value * 256, files=[], cache_root_present=True, object_files=1, cache_metadata_files=1) for value in [1, 0, 1]]
        with mock.patch.object(inherited, 'hosted', contrast), mock.patch.object(inherited, 'prepare', planner.prepare), \
             mock.patch.object(contrast, 'qualify', side_effect=invoke), mock.patch.object(contrast, 'protect_cache', return_value={}), \
             mock.patch.object(contrast, 'cache_inventory', side_effect=disk):
            return inherited.AssignmentCostControls().mocked_hosted_triplet(**settings)

    def test_exact_useful_fixture_and_single_flag_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan = planner.prepare(root / 'plan', root / 'grant', root / 'compiler')
            self.assertEqual(len(plan['runs']), 18)
            self.assertEqual(plan['candidate_delta']['changed_library_files'], [])
            self.assertEqual(len(set(plan['source_fingerprints'].values())), 1)
            for count in [2, 10]:
                self.assertEqual((root / ('plan/FIXTURE_%d.cr.txt' % count)).read_bytes(), (BASE / ('inputs/FIXTURE_%d.cr.txt' % count)).read_bytes())
            self.assertEqual([(x['fields'], x['operations'], x['associations']) for x in plan['fixtures']], [(32, 6, 6), (160, 30, 30)])
            for row in plan['runs']:
                argv = row['compile_argv']
                self.assertEqual(argv.count('--no-cache'), int(row['arm'] == 'candidate'))
                self.assertEqual(argv[argv.index('--threads') + 1], '1')
                self.assertNotIn('--incremental', argv)
                self.assertEqual([x['expected_exit'] for x in row['same_binary_controls']], [0, 1, 1])
            self.assertEqual((root / 'plan/original.columns.cr.txt').read_bytes(), (root / 'plan/candidate.columns.cr.txt').read_bytes())

    def test_actual_runner_preserves_all_three_arms_and_original_owner_shape(self):
        code, result, calls = self.triplet()
        self.assertEqual(code, 0)
        self.assertTrue(result['cache_policy_mechanism_accepted'])
        self.assertTrue(result['owner_shape_accepted'])
        self.assertEqual(len(calls), 15)
        for row in result['samples']:
            self.assertTrue(row['ambient_no_cache_absent'])
            self.assertEqual(row['compile_argv'].count('--no-cache'), int(row['arm'] == 'candidate'))
        self.assertFalse(result['memory_savings_accepted'])
        self.assertEqual(result['target_cells_accepted'], 0)

    def test_actual_runner_refuses_an_altered_warning_flag(self):
        def change(plan):
            for row in plan['runs']:
                row['compile_argv'].remove('--error-on-warnings')
        self.triplet(plan_mutation=change)

    def test_actual_runner_refuses_a_missing_canary(self):
        def change(plan):
            for row in plan['runs']:
                row['same_binary_controls'] = row['same_binary_controls'][:2]
        self.triplet(plan_mutation=change)

    def test_actual_runner_refuses_a_changed_thread_count(self):
        def change(plan):
            for row in plan['runs']:
                row['compile_argv'][row['compile_argv'].index('--threads') + 1] = '2'
        self.triplet(plan_mutation=change)

    def test_actual_runner_retains_failed_build_and_original_source(self):
        code, result, calls = self.triplet(failing_arm='candidate')
        self.assertEqual(code, 2)
        self.assertFalse(result['diagnostic_complete'])
        self.assertIn('synthetic failed build candidate', result['error'])

    def test_actual_runner_retains_unknown_writer(self):
        code, result, calls = self.triplet(unrecorded_live_writer=True)
        self.assertEqual(code, 2)
        self.assertFalse(result['samples'][0]['terminal_runner_state']['writers_confirmed_retired'])

    def test_actual_runner_refuses_changed_final_provider(self):
        code, result, calls = self.triplet(final_provider_failure=True)
        self.assertEqual(code, 2)
        self.assertTrue(result['finalization_errors'])

    def test_cache_inventory_counts_bitcode_separately_from_object_and_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'module.o').write_bytes(b'OBJECT')
            (root / 'bc_flags.o0').write_bytes(b'FLAGS')
            self.assertEqual(evidence.cache_inventory(root)['bitcode_files'], 0)
            (root / 'module.bc').write_bytes(b'BITCODE')
            value = evidence.cache_inventory(root)
            self.assertEqual((value['file_count'], value['total_disk_bytes'], value['bitcode_files'], value['bitcode_disk_bytes']), (3, 18, 1, 7))
            self.assertEqual((value['object_files'], value['cache_metadata_files'], value['cache_root_present']), (1, 1, True))

    def test_cache_inventory_refuses_an_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'physical.bc').write_bytes(b'BITCODE')
            (root / 'alias.bc').symlink_to(root / 'physical.bc')
            with self.assertRaisesRegex(RuntimeError, 'ordinary entries'):
                evidence.cache_inventory(root)

    def test_cache_mechanism_requires_real_default_bitcode_and_none_when_disabled(self):
        rows = [dict(arm=arm, cache_inventory=dict(bitcode_files=count, bitcode_disk_bytes=count * 7, cache_root_present=True, object_files=1, cache_metadata_files=1)) for arm, count in [('original', 1), ('candidate', 0), ('restored', 1)]]
        self.assertTrue(evidence.verify_mechanism(rows))
        for index, count in [(0, 0), (1, 1), (2, 0)]:
            altered = copy.deepcopy(rows)
            altered[index]['cache_inventory'].update(bitcode_files=count, bitcode_disk_bytes=count * 7)
            with self.assertRaises(RuntimeError):
                evidence.verify_mechanism(altered)

    def test_missing_private_cache_and_object_metadata_refuse_mechanism(self):
        rows = [dict(arm=arm, cache_inventory=dict(bitcode_files=count, bitcode_disk_bytes=count * 7,
            cache_root_present=True, object_files=1, cache_metadata_files=1)) for arm, count in [('original', 1), ('candidate', 0), ('restored', 1)]]
        for key, value in [('cache_root_present', False), ('object_files', 0), ('cache_metadata_files', 0)]:
            with self.subTest(key=key):
                changed = copy.deepcopy(rows)
                changed[1]['cache_inventory'][key] = value
                with self.assertRaisesRegex(RuntimeError, 'Actual private cache'):
                    evidence.verify_mechanism(changed)

    def test_owner_parity_refuses_changed_types_with_equal_owner_counts(self):
        predicate = dict(source_shape_predicate_passed=True, rows=[dict(model='AcceptancePerson0000',
            public_assignment_symbols=['SYNTHETIC String', 'SYNTHETIC broad Array(BigDecimal)'], canonical_heavy_symbols=[])])
        samples = [dict(owner_predicate=copy.deepcopy(predicate)) for unused in range(3)]
        self.assertTrue(evidence.verify_owner_parity(samples)['passed'])
        samples[1]['owner_predicate']['rows'][0]['public_assignment_symbols'][0] = 'SYNTHETIC Symbol'
        with self.assertRaisesRegex(RuntimeError, 'Exact typed assignment owner identities'):
            evidence.verify_owner_parity(samples)

    def test_failed_early_result_has_a_finite_single_file_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=False, error='SYNTHETIC preparation refusal')))
            result = staging.stage(root, root / 'public')
            self.assertEqual([x['path'] for x in result['files']], ['CACHE_POLICY_RESULT.json'])

    def test_positive_result_with_unknown_writers_refuses_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=True)))
            (root / 'comparison').mkdir()
            (root / 'comparison/COMPARISON_RESULT.json').write_text(json.dumps(dict(finalization_errors=['SYNTHETIC source drift'], samples=[])))
            with self.assertRaisesRegex(RuntimeError, 'complete writer return'):
                staging.stage(root, root / 'public')

    def comparison_fixture(self, root):
        samples = []
        profile = self._complete_calibration['profile']
        for arm, count in [('original', 1), ('candidate', 0), ('restored', 1)]:
            directory = root / arm
            directory.mkdir(parents=True)
            commands = []
            groups = []
            for index, label in enumerate(['format', 'build', 'normal', 'field-canary', 'association-canary']):
                maximum = 30 if label == 'format' else 900 if label == 'build' else 120
                expected = 1 if label in ('field-canary', 'association-canary') else 0
                sample = dict(status='absent', elapsed_seconds=0.01)
                group = dict(group=12345+index, status='absent', scope='original POSIX process group',
                    phase='direct_child_returned', bounded_drain_exhausted=False, maximum_drain_seconds=5.0,
                    elapsed_seconds=0.01, original_command_deadline=float(maximum), drain_deadline=5.0,
                    samples=[sample], initial_sample=sample.copy(), terminal_sample=sample.copy())
                groups.append(group)
                command = dict(label=label, arguments=['SYNTHETIC unexecuted provider'], pid=12345+index,
                    original_group=12345+index, exit_code=expected, expected_exit=expected, refusal=None,
                    maximum_seconds=maximum, elapsed_seconds=0.25,
                    writers_confirmed_retired=True, terminal_group_observation=group)
                for stream in ['stdout', 'stderr']:
                    raw = ''
                    if label == 'build' and stream == 'stderr':
                        raw = (BASE / 'fixtures/timing/actual16.stderr.txt').read_text()
                    if label == 'normal' and stream == 'stdout':
                        raw = 'GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=' + json.dumps(json.loads((BASE / 'inputs/FIXTURE_10.json').read_bytes())['expected_behavior']) + '\n'
                    if label == 'field-canary' and stream == 'stderr':
                        raw = 'AcceptancePerson0000 field first_name\n'
                    if label == 'association-canary' and stream == 'stderr':
                        raw = 'AcceptancePerson0000 parent model identity\n'
                    path = directory / (label + '.' + stream + '.txt')
                    path.write_text(raw)
                    command[stream + '_sha256'] = evidence.digest(path)
                commands.append(command)
            owner = contrast.verify_owners(inherited.original_symbols(10), 10, 'original')
            symbols = directory / 'DEFINED_TEXT_SYMBOLS.json'
            symbols.write_text(json.dumps(dict(synthetic=True, definitions=inherited.original_symbols(10))))
            files = [dict(path='module.o',bytes=6,sha256=hashlib.sha256(b'OBJECT').hexdigest()),
                     dict(path='bc_flags.o0',bytes=5,sha256=hashlib.sha256(b'FLAGS').hexdigest())]
            if count:
                files.append(dict(path='module.bc',bytes=7,sha256=hashlib.sha256(b'BITCODE').hexdigest()))
            cache = dict(synthetic=True, bitcode_files=count, bitcode_disk_bytes=count*7, files=files,
                         cache_root_present=True, object_files=1, cache_metadata_files=1,
                         file_count=len(files), total_disk_bytes=sum(row['bytes'] for row in files))
            (directory / 'CACHE_INVENTORY.json').write_text(json.dumps(cache))
            (directory / 'COMMANDS.json').write_text(json.dumps(commands))
            samples.append(dict(arm=arm, passed=True, commands=commands, cache_inventory=cache,
                owner_predicate=owner, defined_text_symbols_sha256=evidence.digest(symbols),
                terminal_runner_state=dict(writers_confirmed_retired=True, original_group_observations=groups)))
        result = dict(diagnostic_complete=True, owner_shape_accepted=True, cache_policy_mechanism_accepted=True,
                      assignment_owner_parity=evidence.verify_owner_parity(samples), samples=samples, finalization_errors=[],
                      timing_profile=profile, timing_profile_sha256=controller.canonical_sha(profile), synthetic=True)
        controller.save(root / 'COMPARISON_RESULT.json', result)
        return result

    def controller_fixture(self, root, change=None, final_time=101.0, admission_change=False):
        wrapper = root / 'wrapper'
        wrapper.write_text('SYNTHETIC compiler wrapper')
        args = SimpleNamespace(driver=BASE / 'qualify_same_job_sdk.py', sdk_evidence=root / 'sdk', output=root / 'result',
            cache_packet_sha256='SYNTHETIC separately guarded manifest',
            python_sha256=evidence.digest(Path(sys.executable).resolve()), time_sha256=evidence.digest('/usr/bin/time'),
            timing_true_sha256=evidence.digest('/usr/bin/true'))
        admission = dict(providers=dict(compiler_wrapper=dict(path=str(wrapper))), job_identity=dict(synthetic=True))
        calls = []
        def calibration(output, driver, time_sha, true_sha, job, deadline):
            import test_timing_profile as calibrated
            calls.append(('calibration', deadline))
            with mock.patch.object(calibrated, 'JOB', job), calibrated.calibration_fixture(outer_deadline=deadline) as (prepared, value, probe_calls):
                shutil.copytree(prepared, output)
                self._complete_calibration = copy.deepcopy(value)
            return self._complete_calibration
        def qualification(settings, **keywords):
            calls.append(('comparison', keywords['absolute_deadline']))
            self.assertEqual((settings.models, settings.repetition), (10, 1))
            result = self.comparison_fixture(settings.output)
            if change:
                change(result)
                controller.save(settings.output / 'COMPARISON_RESULT.json', result)
            return 0
        clocks = [100.0, 100.0, final_time]
        admission_sequence = [admission, dict(admission, synthetic_drift=True)] if admission_change else [admission, admission]
        with mock.patch.object(controller, 'protect', return_value={}), mock.patch.object(controller, 'protect_packet', return_value={}), \
             mock.patch.object(controller, 'metadata', side_effect=admission_sequence), mock.patch.object(controller, 'calibrate', side_effect=calibration), \
             mock.patch.object(controller, 'calibration_return'), mock.patch.object(controller, 'qualify', side_effect=qualification), \
             mock.patch.object(controller.time, 'monotonic', side_effect=clocks):
            code = controller.run(args)
        return code, json.loads((args.output / 'CACHE_POLICY_RESULT.json').read_bytes()), calls

    def test_actual_outer_controller_preserves_one_deadline_and_full_useful_triplet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code, result, calls = self.controller_fixture(root)
            self.assertEqual(code, 0)
            self.assertEqual(calls, [('calibration', 4900.0), ('comparison', 4900.0)])
            self.assertTrue(result['diagnostic_complete'])
            self.assertEqual(result['target_cells_accepted'], 0)
            self.assertFalse(result['whole_build_provider_qualified'])
            staged = staging.stage(root / 'result', root / 'public')
            self.assertEqual(len(staged['files']), 46)
            self.assertEqual(len(list((root / 'public/comparison').glob('*/normal.stdout.txt'))), 3)
            self.assertEqual(len(list((root / 'public/comparison').glob('*/association-canary.stderr.txt'))), 3)

    def test_actual_outer_controller_refuses_unknown_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            def change(result):
                result['samples'][1]['terminal_runner_state']['writers_confirmed_retired'] = False
            code, result, calls = self.controller_fixture(Path(temporary).resolve(), change=change)
            self.assertEqual(code, 2)
            self.assertFalse(result['passed'])
            self.assertTrue(result['finalization_errors'])

    def test_actual_outer_controller_refuses_source_provider_admission_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, result, calls = self.controller_fixture(Path(temporary).resolve(), admission_change=True)
            self.assertEqual(code, 2)
            self.assertIn('Same-job SDK admission changed', result['finalization_errors'][0])

    def test_actual_outer_controller_refuses_overdue_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, result, calls = self.controller_fixture(Path(temporary).resolve(), final_time=4900.001)
            self.assertEqual(code, 2)
            self.assertFalse(result['diagnostic_complete'])

    def test_positive_stage_refuses_missing_canary_and_changed_comparison(self):
        for mutation in ['missing_canary', 'changed_comparison', 'changed_symbols', 'changed_cache']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self.controller_fixture(root)
                source = root / 'result'
                comparison = source / 'comparison/COMPARISON_RESULT.json'
                value = json.loads(comparison.read_bytes())
                if mutation == 'missing_canary':
                    value['samples'][0]['commands'].pop()
                    controller.save(comparison, value)
                    outer = json.loads((source / 'CACHE_POLICY_RESULT.json').read_bytes())
                    outer['comparison_sha256'] = evidence.digest(comparison)
                    controller.save(source / 'CACHE_POLICY_RESULT.json', outer)
                elif mutation == 'changed_comparison':
                    comparison.write_bytes(comparison.read_bytes() + b'\n')
                elif mutation == 'changed_symbols':
                    (source / 'comparison/candidate/DEFINED_TEXT_SYMBOLS.json').write_text('{}\n')
                else:
                    (source / 'comparison/candidate/CACHE_INVENTORY.json').write_text('{}\n')
                with self.assertRaises(RuntimeError):
                    staging.stage(source, root / 'public')
                self.assertFalse((root / 'public').exists())

    def test_result_credential_content_refuses_before_public_directory_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=False, error='authorization: bearer ' + 'a' * 32)))
            with self.assertRaisesRegex(ValueError, 'credential-shaped'):
                staging.stage(root, root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_preserved_absolute_deadline_and_invalid_inputs(self):
        self.assertEqual(contrast.execution_deadline(200.0, 4800, 4800.0), 4800.0)
        for value in [True, False, '4800', float('nan'), float('inf'), 0, -1]:
            with self.assertRaises(RuntimeError):
                contrast.execution_deadline(1, 4800, value)
        self.assertEqual((contrast.GLOBAL_SECONDS, contrast.ARM_SECONDS), (4800, 1500))

    def source_gate_fixture(self, root):
        for origin, folder in [(BASE, 'grant_assignment_cost'), (ROOT, 'grant_cache_policy')]:
            target = root / 'test' / folder
            target.mkdir(parents=True)
            manifest = json.loads((origin / 'SOURCE_PINS.json').read_bytes())
            for row in manifest['files']:
                path = target / row['path']
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((origin / row['path']).read_bytes())
            (target / 'SOURCE_PINS.json').write_bytes((origin / 'SOURCE_PINS.json').read_bytes())
        path = ROOT.parent / 'grant-cache-mac.proposed.yml'
        if not path.is_file():
            path = ROOT.parents[1] / '.github/workflows/grant-installed-mac.yml'
        lines = path.read_text().splitlines()
        blocks = []
        for index, line in enumerate(lines):
            if "<<'PYTHON'" in line:
                end = next(i for i in range(index+1, len(lines)) if lines[i].strip() == 'PYTHON')
                blocks.append('\n'.join(row[10:] for row in lines[index+1:end])+'\n')
        self.assertEqual(len(blocks), 12)
        return blocks

    def exercise_source_gate(self, root, blocks, refused):
        import runpy
        cwd, module_paths = Path.cwd(), list(sys.path)
        calls = []
        try:
            os.chdir(root)
            environment = dict(ATLAS_CACHE_PACKET_SHA256=evidence.digest(ROOT / 'SOURCE_PINS.json'),
                ATLAS_GRANT_PACKET_SHA256=evidence.BASE_PACKET, RUNNER_TEMP=str(root))
            with mock.patch.dict(os.environ, environment), mock.patch.object(sys, 'argv', list(sys.argv)), \
                 mock.patch.object(runpy, 'run_path', side_effect=lambda *a, **k: calls.append(str(a[0]))):
                for code in blocks:
                    before = len(calls)
                    if refused:
                        with self.assertRaises((SystemExit, OSError)):
                            exec(compile(code, '<exact source-bound workflow>', 'exec'), {})
                        self.assertEqual(len(calls), before)
                    else:
                        exec(compile(code, '<exact source-bound workflow>', 'exec'), {})
                        self.assertEqual(len(calls), before+1)
        finally:
            os.chdir(cwd)
            sys.path[:] = module_paths
        return calls

    def test_every_workflow_boundary_refuses_changed_core_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blocks = self.source_gate_fixture(root)
            path = root / 'test/grant_assignment_cost/same_job_policy.py'
            original = path.read_bytes()
            path.write_bytes(b'raise RuntimeError("PEER_CHANGED_CORE_IMPORTED_BEFORE_ADMISSION")\n'+original)
            self.assertEqual(self.exercise_source_gate(root, blocks, True), [])
            path.write_bytes(original)
            self.assertEqual(len(self.exercise_source_gate(root, blocks, False)), 12)

    def test_every_workflow_boundary_refuses_missing_alias_and_changed_new_member(self):
        for mutation in ('missing', 'alias', 'changed'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                blocks = self.source_gate_fixture(root)
                path = root / 'test/grant_cache_policy/cache_evidence.py'
                if mutation == 'missing':
                    path.unlink()
                elif mutation == 'alias':
                    path.unlink()
                    path.symlink_to(ROOT / 'cache_evidence.py')
                else:
                    path.write_bytes(path.read_bytes()+b'\n')
                self.assertEqual(self.exercise_source_gate(root, blocks, True), [])

    def test_positive_missing_comparison_refuses_before_public_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=True, diagnostic_complete=True)))
            with self.assertRaisesRegex(RuntimeError, 'complete comparison evidence'):
                staging.stage(root, root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_positive_changed_command_journal_refuses_before_public_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.controller_fixture(root)
            (root / 'result/comparison/candidate/COMMANDS.json').write_text('[]\n')
            with self.assertRaisesRegex(RuntimeError, 'persisted cache command roster'):
                staging.stage(root / 'result', root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_positive_changed_calibration_raw_refuses_before_public_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.controller_fixture(root)
            (root / 'result/timing-calibration/probe.stderr.txt').write_text('SYNTHETIC changed calibration footer\n')
            with self.assertRaises(RuntimeError):
                staging.stage(root / 'result', root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_positive_missing_calibration_refuses_before_public_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.controller_fixture(root)
            shutil.rmtree(root / 'result/timing-calibration')
            with self.assertRaisesRegex(RuntimeError, 'complete calibration evidence'):
                staging.stage(root / 'result', root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_positive_calibration_profile_probe_result_missing_alias_changed_refuse(self):
        for name in ('TIMING_PROFILE.json', 'CALIBRATION_RESULT.json', 'COMMANDS.json', 'probe.stdout.txt', 'probe.stderr.txt'):
            for mutation in ('missing', 'alias', 'changed'):
                with self.subTest(name=name, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    self.controller_fixture(root)
                    path = root / 'result/timing-calibration' / name
                    raw = path.read_bytes()
                    if mutation == 'missing':
                        path.unlink()
                    elif mutation == 'alias':
                        preserved = root / 'retained-original'
                        preserved.write_bytes(raw)
                        path.unlink()
                        path.symlink_to(preserved)
                    else:
                        path.write_bytes(b'{}\n' if name.endswith('.json') else b'SYNTHETIC changed raw\n')
                    with self.assertRaises((RuntimeError, OSError, ValueError)):
                        staging.stage(root / 'result', root / 'public')
                    self.assertFalse((root / 'public').exists())

    def test_positive_calibration_byte_change_refuses_even_when_json_values_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.controller_fixture(root)
            path = root / 'result/timing-calibration/CALIBRATION_RESULT.json'
            path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(RuntimeError, 'sealed calibration'):
                staging.stage(root / 'result', root / 'public')
            self.assertFalse((root / 'public').exists())

    def test_outer_completion_requires_an_exact_json_boolean(self):
        for value in (1, 1.0, 0, None, 'true'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / 'CACHE_POLICY_RESULT.json').write_text(json.dumps(dict(passed=value)))
                with self.assertRaisesRegex(RuntimeError, 'boolean outer completion'):
                    staging.stage(root, root / 'public')
                self.assertFalse((root / 'public').exists())

    def test_positive_command_journal_missing_alias_and_changed_refuse(self):
        for mutation in ('missing', 'alias', 'changed'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self.controller_fixture(root)
                path = root / 'result/comparison/candidate/COMMANDS.json'
                if mutation == 'missing':
                    path.unlink()
                elif mutation == 'alias':
                    preserved = root / 'retained-command-journal'
                    preserved.write_bytes(path.read_bytes())
                    path.unlink()
                    path.symlink_to(preserved)
                else:
                    path.write_text('[]\n')
                with self.assertRaises((RuntimeError, OSError, ValueError)):
                    staging.stage(root / 'result', root / 'public')
                self.assertFalse((root / 'public').exists())


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CachePolicyControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped), guard_calls=len(GUARD_CALLS))))
    raise SystemExit(0 if result.wasSuccessful() and not GUARD_CALLS else 2)
