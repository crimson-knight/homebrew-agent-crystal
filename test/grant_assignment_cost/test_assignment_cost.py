"""Synthetic reader, physical retained-input, and source-proposal behavior controls."""
import copy
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'vendor'))
from retained_symbols import read_macho, decode_starts, family_rows
from propose_container import derive, verify
from prepare_comparison import prepare
from run_hosted_contrast import overlay, timed_footer, TIME_FIELDS, behavior
from verify_assignment_owners import verify as verify_owners
from owner_census import census_stream
from project_ir import project
import run_hosted_contrast as hosted
from verify_runtime_contrast import compare as compare_runtime, SCENARIOS
from verify_narrow_error_parity import compare as compare_errors, CASES
from propose_compatible_container import derive as derive_compatible


def synthetic_binary():
    names = b'\0_*Example#one:Nil\0_alias_of_one\0_*Example#two:Nil\0'
    offsets = [names.index(name) for name in (b'_*Example#one:Nil', b'_alias_of_one', b'_*Example#two:Nil')]
    base = 0x100000000
    segment = struct.pack('<II16sQQQQiiII', 0x19, 152, b'__TEXT', base, 4096, 0, 4096, 7, 5, 1, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', base + 512, 32, 512, 2, 0, 0, 0x80000400, 0, 0, 0)
    symbol_table = struct.pack('<IIIIII', 2, 24, 1024, 3, 1100, len(names))
    starts = b'\x80\x04\x10\0'
    function_command = struct.pack('<IIII', 0x26, 16, 1200, len(starts))
    commands = segment + section + symbol_table + function_command
    result = bytearray(4096)
    result[:32] = struct.pack('<IiiIIIII', 0xfeedfacf, 0x100000c, 0, 2, 3, len(commands), 0, 0)
    result[32:32 + len(commands)] = commands
    for index, address in enumerate((base + 512, base + 512, base + 528)):
        struct.pack_into('<IBBHQ', result, 1024 + 16 * index, offsets[index], 0xf, 1, 0, address)
    result[1100:1100 + len(names)] = names
    result[1200:1200 + len(starts)] = starts
    return bytes(result)


def original_symbols(models=2):
    rows = []
    for index in range(models):
        for value in ('(Array(BigDecimal) | String | Nil)', '(Bool | String | Nil)'):
            rows.append(dict(symbol='*AcceptancePerson%04d@Grant::Columns#assign_mass_assignment_column<String, %s>:Nil' % (index, value)))
    return rows


class AssignmentCostControls(unittest.TestCase):
    def test_synthetic_aliases_share_exact_function_intervals(self):
        value = read_macho(synthetic_binary())
        self.assertEqual(value['defined_text_symbols'], 3)
        self.assertEqual([row['next_function_extent_bytes'] for row in value['definitions']], [16, 16, 16])
        self.assertEqual(value['definitions'][0]['address'], value['definitions'][1]['address'])

    def test_synthetic_truncated_and_wrong_architecture_refuse(self):
        with self.assertRaises(RuntimeError):
            read_macho(synthetic_binary()[:100])
        damaged = bytearray(synthetic_binary())
        struct.pack_into('<i', damaged, 4, 0x1000007)
        with self.assertRaisesRegex(RuntimeError, 'ARM64'):
            read_macho(bytes(damaged))

    def test_synthetic_outside_string_or_symbol_table_refuses(self):
        damaged = bytearray(synthetic_binary())
        struct.pack_into('<I', damaged, 1024, 999)
        with self.assertRaisesRegex(RuntimeError, 'symbol string'):
            read_macho(bytes(damaged))

    def test_function_starts_require_termination_and_zero_padding(self):
        for raw in (b'\x81', b'\x01', b'\x01\0\x01'):
            with self.assertRaises(RuntimeError):
                decode_starts(raw, 100)
        self.assertEqual(decode_starts(b'\x01\x02\0\0', 100), [101, 103])

    def test_selected_interior_label_refuses_body_extent_claim(self):
        value = read_macho(synthetic_binary())
        row = value['definitions'][0]
        row.update(symbol='*AcceptancePerson0000@Grant::Columns#assign_mass_assignment_column<String, String>:Nil', function_start=False)
        with self.assertRaisesRegex(RuntimeError, 'function-start interval'):
            family_rows(value)

    def test_proposal_preserves_entire_original_body_and_restoration(self):
        original = (ROOT / 'source/columns.original.cr.txt').read_bytes()
        candidate = derive(original)
        result = verify(original, candidate)
        self.assertTrue(result['assignment_body_byte_identical'])
        self.assertEqual(candidate.count(b'struct MassAssignmentValue'), 1)
        self.assertEqual(candidate.count(b'private def assign_canonical_mass_assignment_column'), 1)
        with self.assertRaises(RuntimeError):
            derive(original + b'\n')
        with self.assertRaises(RuntimeError):
            verify(original, candidate.replace(b'encrypted_attribute.assign(self, nil)', b'encrypted_attribute.assign(self, "")'))

    def test_overlay_restores_exact_original_after_normal_and_failed_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'columns.cr'
            path.write_bytes(b'original')
            with overlay(path, b'original', b'candidate'):
                self.assertEqual(path.read_bytes(), b'candidate')
            self.assertEqual(path.read_bytes(), b'original')
            with self.assertRaisesRegex(RuntimeError, 'failed build'):
                with overlay(path, b'original', b'candidate'):
                    raise RuntimeError('failed build')
            self.assertEqual(path.read_bytes(), b'original')

    def test_overlay_refuses_unexpected_original_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'columns.cr'
            path.write_bytes(b'unexpected')
            with self.assertRaisesRegex(RuntimeError, 'Exact original'):
                with overlay(path, b'original', b'candidate'):
                    pass
            self.assertEqual(path.read_bytes(), b'unexpected')

    def test_physical_source_plan_preserves_all18_rich_source_canary_rosters(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = prepare(Path(directory) / 'plan', Path('/admitted/grant'), Path('/ordinary/bin/crystal-alpha'))
            self.assertEqual(len(plan['runs']), 18)
            self.assertEqual(plan['required_target_matrix_size'], 144)
            self.assertEqual(plan['target_cells_accepted'], 0)
            self.assertEqual(plan['source_fingerprints']['original'], plan['source_fingerprints']['restored'])
            self.assertNotEqual(plan['source_fingerprints']['original'], plan['source_fingerprints']['candidate'])
            self.assertEqual({row['source_rows'] for row in plan['runs']}, {1554})
            for row in plan['runs']:
                self.assertEqual([control['expected_exit'] for control in row['same_binary_controls']], [0, 1, 1])
                self.assertEqual(len(row['same_binary_controls']), 3)
                self.assertIn('--error-on-warnings', row['compile_argv'])
            with self.assertRaises(RuntimeError):
                prepare(Path(directory) / 'plan', Path('/admitted/grant'), Path('/ordinary/bin/crystal-alpha'))

    def test_heavy_owner_predicate_requires_one_container_shape_for_every_model(self):
        original = original_symbols()
        self.assertTrue(verify_owners(original, 2, 'original')['source_shape_predicate_passed'])
        with self.assertRaisesRegex(RuntimeError, 'Exactly one container'):
            verify_owners(original, 2, 'candidate')
        candidate = copy.deepcopy(original)
        for index in range(2):
            candidate.append(dict(symbol='*AcceptancePerson%04d@Grant::Columns#assign_canonical_mass_assignment_column<String, Grant::Columns::MassAssignmentValue>:Nil' % index))
        verify_owners(candidate, 2, 'candidate')
        with self.assertRaises(RuntimeError):
            verify_owners(candidate + [candidate[-1]], 2, 'candidate')
        with self.assertRaises(RuntimeError):
            verify_owners(candidate[:-1], 2, 'candidate')

    def test_timing_footer_preserves_scope_and_refuses_compiler_warnings(self):
        raw = ' 1.25 real 0.50 user 0.25 sys\n' + ''.join(' %d  %s\n' % (index + 1, label) for index, label in enumerate(TIME_FIELDS))
        result = timed_footer(raw)
        self.assertFalse(result['isolated_compiler_peak_qualified'])
        with self.assertRaises(RuntimeError):
            timed_footer('Warning: changed behavior\n' + raw)
        with self.assertRaises(RuntimeError):
            timed_footer(raw.replace('maximum resident set size', 'unknown metric'))

    def test_complete_linked_owner_roster_has_a_finite_streamed_json_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'owners.json'
            value = dict(definitions=original_symbols())
            size = hosted.save_bounded_symbols(path, value)
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assertEqual(size, path.stat().st_size)
            with self.assertRaisesRegex(RuntimeError, 'finite20-MiB'):
                hosted.save_bounded_symbols(path, value, maximum_bytes=16)
            self.assertLessEqual(path.stat().st_size, 16)

    def test_complete_ir_projection_keeps_unclassified_definitions(self):
        raw = b'define void @"*AcceptancePerson0000@Grant::Columns#assign_mass_assignment_column<String, String>:Nil"() {\n ret void\n}\ndefine void @"plain_c"() {\n ret void\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / 'retained.ll').resolve()
            path.write_bytes(raw)
            result = project(path)
            self.assertEqual(result['complete_owner_census']['definition_count'], 2)
            self.assertEqual(result['families']['assignment_conversion']['definition_count'], 1)
            self.assertEqual(result['complete_owner_census']['definitions'][-1]['symbol'], 'plain_c')

    def mocked_hosted_triplet(self, failing_arm=None, final_provider_failure=False, baseline=False, plan_mutation=None, unrecorded_live_writer=False):
        """Synthetic subprocess/provider outputs; source mutation/restoration is physical."""
        from retained_symbols import sha
        from prepare_comparison import fingerprint
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            grant = base / 'grant'
            columns = grant / 'src/grant/columns.cr'
            columns.parent.mkdir(parents=True)
            original = (ROOT / 'source/columns.original.cr.txt').read_bytes()
            candidate = derive(original)
            columns.write_bytes(original)
            prefix = base / 'ordinary'
            wrapper = prefix / 'bin/crystal-alpha'
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text('synthetic ordinary wrapper\n')
            plan_directory = base / 'plan'
            if baseline:
                from prepare_baseline import prepare_baseline
                fixture_root = ROOT / 'inputs'
                plan = prepare_baseline(plan_directory, grant, wrapper,
                                        fixture_root / 'FIXTURE_300.cr.txt',
                                        fixture_root / 'FIXTURE_300.json')
            else:
                plan = prepare(plan_directory, grant, wrapper)
            if plan_mutation is not None:
                plan_mutation(plan)
                (plan_directory / 'COMPARISON_PLAN.json').write_text(json.dumps(plan))
            evidence = base / 'sdk'
            evidence.mkdir()
            fake_stdlib = dict(synthetic=True)
            profile = dict(wrapper_sha256=sha(wrapper.read_bytes()))
            for name, raw in [('INSTALLED_FORMULA.rb', b'synthetic formula'), ('INSTALL_RECEIPT.json', b'synthetic receipt')]:
                (evidence_path := prefix / ('.brew/agent-crystal.rb' if name == 'INSTALLED_FORMULA.rb' else name)).parent.mkdir(parents=True, exist_ok=True)
                evidence_path.write_bytes(raw)
            backend = prefix / 'libexec/agent-crystal-bin'
            backend.parent.mkdir(parents=True)
            backend.write_bytes(b'synthetic backend')
            providers = dict(compiler_wrapper=dict(path=str(wrapper), sha256=sha(wrapper.read_bytes())), compiler_backend=dict(path=str(backend), sha256=sha(backend.read_bytes())))
            for name, value in [('READINESS_RESULT.json', dict(passed=True)), ('REVIEWED_COMPILER_PROFILE.json', profile),
                                ('PROVIDER_IDENTITIES.json', providers), ('STDLIB_BEFORE.json', fake_stdlib)]:
                (evidence / name).write_text(json.dumps(value))
            (evidence / 'brew-prefix.stdout.txt').write_text(str(prefix) + '\n')
            (evidence / 'brew-root.stdout.txt').write_text(str(prefix.parent) + '\n')
            for name, relative in [('INSTALLED_FORMULA.rb', '.brew/agent-crystal.rb'), ('INSTALL_RECEIPT.json', 'INSTALL_RECEIPT.json')]:
                (evidence / name).write_bytes((prefix / relative).read_bytes())
            runner_source = base / 'synthetic_runner.py'
            runner_source.write_text('# Synthetic module fixture; import execution is mocked.\n')
            (evidence / 'RUNNER.json').write_text(json.dumps(dict(run_id='synthetic-job', source_commit='synthetic-source', qualification_script_sha256=sha(runner_source.read_bytes()), python_path=sys.executable, python_sha256=hosted.digest(Path(sys.executable).resolve()))))
            original_rows = json.loads((ROOT / 'inputs/SOURCE_INPUTS.json').read_bytes())['inputs']
            def inventory(unused):
                rows = copy.deepcopy(original_rows)
                next(row for row in rows if row['path'] == 'src/grant/columns.cr')['sha256'] = sha(columns.read_bytes())
                return rows, fingerprint(rows)
            timer = ' 1.25 real 0.50 user 0.25 sys\n' + ''.join(' %d  %s\n' % (index + 1, label) for index, label in enumerate(TIME_FIELDS))
            expected = json.loads((plan_directory / ('FIXTURE_300.json' if baseline else 'FIXTURE_2.json')).read_bytes())['expected_behavior']
            calls = []
            class SyntheticRunner:
                def __init__(self, output):
                    self.output = output
                    self.records, self.group_observations = [], []
                    self.writers_confirmed_retired = True
                def run(self, label, arguments, **settings):
                    calls.append((self.output.name, label))
                    if unrecorded_live_writer and label == 'build':
                        self.writers_confirmed_retired = False
                        self.group_observations.append(dict(status='unverifiable', synthetic=True))
                        raise RuntimeError('synthetic unrecorded live writer')
                    self.records.append(dict(label=label, synthetic=True, writers_confirmed_retired=True))
                    self.group_observations.append(dict(synthetic=True, status='absent'))
                    if label == 'build':
                        if self.output.name == failing_arm:
                            (self.output / 'build.stderr.txt').write_text('synthetic compiler error\n' + timer)
                            raise RuntimeError('synthetic failed build ' + failing_arm)
                        Path(arguments[-1]).write_bytes(b'synthetic binary bytes')
                        return '', timer
                    if label == 'normal':
                        return 'GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=' + json.dumps(expected) + '\n', ''
                    if label == 'field-canary':
                        return '', 'AcceptancePerson0000 field first_name'
                    if label == 'association-canary':
                        return '', 'AcceptancePerson0000 parent model identity'
                    return '', ''
            observations = []
            def tree_identity(unused):
                observations.append(True)
                if final_provider_failure and len(observations) > 1:
                    raise OSError('synthetic final provider unreadable')
                return fake_stdlib
            driver = SimpleNamespace(Runner=SyntheticRunner, tree_identity=tree_identity, verify_wrapper=lambda *unused: None)
            admitted = dict(profile=profile, providers=providers, runner=json.loads((evidence / 'RUNNER.json').read_bytes()), stdlib=fake_stdlib, observed_profile_sha256=hosted.digest(evidence / 'REVIEWED_COMPILER_PROFILE.json'))
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
            args = SimpleNamespace(source_sha256=hosted.digest(hosted.__file__), python_sha256=hosted.digest(Path(sys.executable).resolve()),
                                   driver=runner_source, plan=plan_directory / 'COMPARISON_PLAN.json', sdk_evidence=evidence,
                                   output=base / 'result', models=300 if baseline else 2, repetition=1,
                                   plan_sha256=hosted.digest(plan_directory / 'COMPARISON_PLAN.json'), time_sha256=hosted.digest('/usr/bin/time'), packet_sha256='synthetic-manifest')
            def symbols(unused):
                rows = original_symbols()
                if columns.read_bytes() == candidate:
                    rows += [dict(symbol='*AcceptancePerson%04d@Grant::Columns#assign_canonical_mass_assignment_column<String, Grant::Columns::MassAssignmentValue>:Nil' % index) for index in range(2)]
                return dict(definitions=rows)
            with mock.patch.object(hosted.platform, 'system', return_value='Darwin'), mock.patch.object(hosted.platform, 'machine', return_value='arm64'), mock.patch.dict(hosted.os.environ, GITHUB_ACTIONS='true', GITHUB_RUN_ID='synthetic-job', GITHUB_SHA='synthetic-source'), mock.patch.object(hosted, 'DRIVER_SHA256', hosted.digest(runner_source)), mock.patch.object(hosted, 'protect_packet', return_value={}), mock.patch.object(hosted, 'admit_sdk_metadata', return_value=admitted), mock.patch.object(hosted.importlib.util, 'spec_from_file_location', return_value=spec), mock.patch.object(hosted.importlib.util, 'module_from_spec', return_value=driver), mock.patch.object(hosted, 'source_input_inventory', side_effect=inventory), mock.patch.object(hosted, 'read_macho', side_effect=symbols), mock.patch.object(hosted, 'family_rows', return_value={'synthetic': True}):
                if plan_mutation is not None:
                    with self.assertRaisesRegex(RuntimeError, 'Exact regenerated complete plan'):
                        hosted.qualify(args)
                    self.assertEqual(calls, [])
                    self.assertEqual(columns.read_bytes(), original)
                    return
                code = hosted.qualify(args)
            self.assertEqual(columns.read_bytes(), original)
            return code, json.loads((args.output / 'COMPARISON_RESULT.json').read_bytes()), calls

    def test_mocked_fresh_plan_hash_refuses_missing_canary_and_changed_compile_flags(self):
        def missing_control(plan):
            for row in plan['runs']:
                row['same_binary_controls'] = [control for control in row['same_binary_controls'] if control['label'] != 'field-canary']
        def missing_flag(plan):
            for row in plan['runs']:
                row['compile_argv'].remove('--error-on-warnings')
        def changed_cpu(plan):
            for row in plan['runs']:
                row['compile_argv'][2:2] = ['--mcpu', 'generic']
        for mutation in (missing_control, missing_flag, changed_cpu):
            self.mocked_hosted_triplet(plan_mutation=mutation)
        self.mocked_hosted_triplet(baseline=True, plan_mutation=missing_control)

    def test_mocked_complete_hosted_triplet_restores_all_three_arms(self):
        code, result, calls = self.mocked_hosted_triplet()
        self.assertEqual(code, 0)
        self.assertTrue(result['diagnostic_complete'])
        self.assertEqual([row['arm'] for row in result['samples']], ['original', 'candidate', 'restored'])
        self.assertEqual(len(calls), 15)
        self.assertEqual(result['target_cells_accepted'], 0)

    def test_mocked_hosted_candidate_build_failure_preserves_return_and_restores_source(self):
        code, result, calls = self.mocked_hosted_triplet(failing_arm='candidate')
        self.assertEqual(code, 2)
        self.assertIn('synthetic failed build candidate', result['error'])
        self.assertEqual(result['samples'][-1]['commands'][-1]['label'], 'build')
        self.assertFalse(result['diagnostic_complete'])
        self.assertIn('Failed or refused build', result['samples'][-1]['failed_build_time']['scope'])

    def test_mocked_exceptional_live_writer_is_retained_before_any_command_record(self):
        code, result, calls = self.mocked_hosted_triplet(unrecorded_live_writer=True)
        self.assertEqual(code, 2)
        self.assertIn('synthetic unrecorded live writer', result['error'])
        terminal = result['samples'][-1]['terminal_runner_state']
        self.assertFalse(terminal['writers_confirmed_retired'])
        self.assertEqual(terminal['original_group_observations'][-1]['status'], 'unverifiable')
        from run_serial import complete_return
        with self.assertRaisesRegex(RuntimeError, 'Actual Runner terminal'):
            complete_return(result)

    def test_mocked_hosted_final_provider_failure_preserves_original_failure(self):
        code, result, calls = self.mocked_hosted_triplet(failing_arm='candidate', final_provider_failure=True)
        self.assertEqual(code, 2)
        self.assertIn('synthetic failed build candidate', result['error'])
        self.assertIn('synthetic final provider unreadable', result['finalization_errors'][0])

    def test_mocked_unchanged300_feasibility_retains_entire_behavior_and_horizon(self):
        code, result, calls = self.mocked_hosted_triplet(baseline=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['diagnostic_complete'])
        self.assertFalse(result['owner_shape_accepted'])
        self.assertEqual(result['maximum_seconds'], 1500)
        self.assertEqual(len(calls), 5)
        value = result['samples'][0]['behavior']
        self.assertEqual([len(value[key]) for key in ('list_of_models', 'list_of_field_checks', 'list_of_operations', 'list_of_association_edges')], [300, 4800, 900, 900])
        self.assertEqual(result['target_cells_accepted'], 0)

    def test_physical_frozen_archive_projection_and_changed_archive_refusal(self):
        from stage_grant_sources import stage
        archive = ROOT / 'inputs/grant-source-and-frozen-dependencies.tar.gz'
        with tempfile.TemporaryDirectory() as directory:
            result = stage(archive, (Path(directory) / 'projection').resolve())
            self.assertEqual((result['source_rows'], result['aliases']), (1554, 5))
            damaged = Path(directory) / 'changed.tar.gz'
            raw = bytearray(archive.read_bytes())
            raw[-10] ^= 1
            damaged.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, 'SHA'):
                stage(damaged, (Path(directory) / 'refused').resolve())

    def test_compatible_successor_preserves_body_except_original_rejection_type_interpolation(self):
        original = (ROOT / 'source/columns.original.cr.txt').read_bytes()
        candidate = derive_compatible(original)
        self.assertIn(b'typeof(begin', candidate)
        self.assertIn(b'if converted_value.is_a?({{setter_type}})', candidate)
        self.assertIn(b'else\n                converted_value', candidate)
        from propose_compatible_container import HEADER, WRAPPER
        start = original.index(HEADER.encode()) + len(HEADER)
        end = original.index(b'\n  def read_attribute(', start)
        after = candidate.index(WRAPPER.encode()) + len(WRAPPER)
        after_end = candidate.index(b'\n  def read_attribute(', after)
        restored_body = candidate[after:after_end].replace(b'#{assignment_value.converted_type_name({{column.name.stringify}})}', b'#{typeof(converted_value)}')
        self.assertEqual(original[start:end], restored_body)

    def test_direct_runtime_guard_refuses_extra_calls_bytes_and_elapsed(self):
        def report(container):
            return dict(schema_version=1, compiled_stack_peak_qualified=False, has_value_container=container,
                        value_container_size_bytes=32 if container else 0, broad_input_value_size_bytes=32,
                        narrow_input_value_size_bytes=16,
                        list_of_observations=[dict(scenario=label, iterations=10000, checksum=420000,
                                                   allocation_calls=100, requested_bytes=4096, elapsed_seconds=1.0) for label in SCENARIOS])
        original, candidate, restored = report(False), report(True), report(False)
        self.assertTrue(compare_runtime(original, candidate, restored)['passed'])
        for metric, value in [('allocation_calls', 101), ('requested_bytes', 4097), ('elapsed_seconds', 1.500001)]:
            changed = copy.deepcopy(candidate)
            changed['list_of_observations'][3][metric] = value
            self.assertFalse(compare_runtime(original, changed, restored)['passed'])
        changed = copy.deepcopy(candidate)
        changed['list_of_observations'][0]['allocation_calls'] = True
        with self.assertRaises(RuntimeError):
            compare_runtime(original, changed, restored)

    def test_narrow_error_gate_separates_cost_diagnostics_from_compatibility(self):
        def report():
            return dict(schema_version=1, list_of_observations=[dict(case_id=label, first_name=None, age=None,
                        active=None, raw_age=False, age_change=None,
                        list_of_errors=[dict(field='age', error_class='Grant::ConversionError', message='original rejection type', error_type=None)]) for label in CASES])
        original, candidate, restored = report(), report(), report()
        self.assertTrue(compare_errors(original, candidate, restored, True)['passed'])
        candidate['list_of_observations'][0]['list_of_errors'][0]['message'] = 'changed rejection type'
        self.assertFalse(compare_errors(original, candidate, restored, True)['passed'])
        self.assertEqual(compare_errors(original, candidate, restored, False)['changed_error_message_cases'], ['narrow_bool_string'])
        candidate['list_of_observations'][0]['raw_age'] = 0
        with self.assertRaises(RuntimeError):
            compare_errors(original, candidate, restored, False)


if __name__ == '__main__':
    with mock.patch('subprocess.Popen', side_effect=AssertionError('source-only subprocess guard')), mock.patch('os.kill', side_effect=AssertionError('source-only signal guard')), mock.patch('os.killpg', side_effect=AssertionError('source-only signal guard')):
        unittest.main(verbosity=2)
