"""Guarded transfer/native-policy controls; accepted bytes remain data-only fixtures."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import proof_tool_transfer as transfer
import stage_tool_admission
import run_admitted_dirty

VALIDATION = ROOT.parent / (ROOT.name + '_validation')
VALIDATION.mkdir(exist_ok=True)
FIXTURE = None


def macho(paths=()):
    commands = []
    for name in paths:
        raw = name.encode() + b'\0'
        size = (24 + len(raw) + 7) // 8 * 8
        commands.append(struct.pack('<IIIIII', 0xC, size, 24, 0, 0, 0) + raw + b'\0' * (size - 24 - len(raw)))
    body = b''.join(commands)
    return struct.pack('<IIIIIIII', 0xFEEDFACF, 0x100000C, 0, 6, len(commands), len(body), 0, 0) + body


def temporary():
    return tempfile.TemporaryDirectory(prefix='tool source with spaces ', dir=str(VALIDATION))


def fixture(root):
    source = root / 'download'
    source.mkdir()
    if FIXTURE.is_dir():
        values = transfer.verify_artifact(FIXTURE, transfer.Budget(time.monotonic() + 30))
    else:
        with zipfile.ZipFile(FIXTURE) as archive:
            values = {row.filename: archive.read(row) for row in archive.infolist()}
    for name, raw in values.items():
        path = source / transfer.contained(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
    return source


def native_fixture(root):
    prefix = root / 'brew'
    (prefix / 'opt').mkdir(parents=True)
    dependencies = []
    direct = []
    for name, version in transfer.PACKAGES.items():
        pkg = prefix / 'Cellar' / name / version
        (pkg / '.brew').mkdir(parents=True)
        (pkg / 'lib').mkdir()
        (pkg / '.brew' / (name + '.rb')).write_text('class Formula; end\n')
        (pkg / 'INSTALL_RECEIPT.json').write_text(json.dumps(dict(arch='arm64', source=dict(versions=dict(stable=version)))))
        (prefix / 'opt' / name).symlink_to(Path('../Cellar') / name / version)
        (pkg / 'lib/dependency.dylib').write_bytes(macho(transfer.SYSTEM_IMPORTS))
        direct.append(str(prefix / 'opt' / name / 'lib/dependency.dylib'))
        dependencies.append(dict(full_name=name, version=version, revision=0, pkg_version=version))
    compiler = root / 'compiler'
    (compiler / 'bin').mkdir(parents=True)
    (compiler / 'INSTALL_RECEIPT.json').write_text(json.dumps(dict(runtime_dependencies=dependencies)))
    admission = dict(job_identity=dict(RUNNER_OS='macOS', RUNNER_ARCH='ARM64'),
        providers=dict(compiler_wrapper=dict(path=str(compiler / 'bin/crystal-alpha'))),
        observed_profile_sha256='a' * 64, runner=dict(image_version='fixture-image'))
    return prefix, direct, admission


class ToolTransferControls(unittest.TestCase):
    def test_real_complete_artifact_is_verified_without_execution(self):
        with temporary() as directory:
            source = fixture(Path(directory))
            self.assertEqual(len(transfer.verify_artifact(source, transfer.Budget(time.monotonic() + 30))), 37)

    def test_canonical_materialization_restores_executable_and_corpus_modes(self):
        with temporary() as directory:
            root = Path(directory)
            rows = transfer.materialize(fixture(root), root / 'canonical', transfer.Budget(time.monotonic() + 30))
            self.assertEqual([row['mode'] for row in rows], [0o755, 0o755, 0o644])
            self.assertEqual((root / 'canonical/share/amber_cli/api/crystal.yml').stat().st_size, 9858)

    def test_changed_tool_refuses(self):
        self.changed_member('tools/ameba')

    def test_changed_corpus_refuses(self):
        self.changed_member('tools/crystal.yml')

    def test_changed_source_refuses(self):
        self.changed_member('source/bootstrap_tools.py')

    def test_changed_job_provenance_refuses(self):
        self.changed_member('BOOTSTRAP_RESULT.json')

    def test_changed_archive_refuses(self):
        self.changed_member('inputs/cli.tar.gz')

    def changed_member(self, name):
        with temporary() as directory:
            root = fixture(Path(directory))
            path = root / name
            path.write_bytes(path.read_bytes() + b'changed')
            with self.assertRaisesRegex(RuntimeError, 'member bytes'):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_missing_member_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            (root / 'tools/ameba').unlink()
            with self.assertRaises(RuntimeError):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_extra_member_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            (root / 'extra').write_text('extra')
            with self.assertRaises(RuntimeError):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_extra_empty_directory_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            (root / 'extra').mkdir()
            with self.assertRaisesRegex(RuntimeError, 'directory roster'):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_symlink_member_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            (root / 'tools/ameba').unlink()
            (root / 'tools/ameba').symlink_to('amber-lsp')
            with self.assertRaises(RuntimeError):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_hardlink_member_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            os.link(root / 'tools/ameba', root.parent / 'extra-link')
            with self.assertRaisesRegex(RuntimeError, 'single-link'):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_unsupported_mode_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            (root / 'tools/ameba').chmod(0o777)
            with self.assertRaisesRegex(RuntimeError, 'mode'):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() + 30))

    def test_unsafe_paths_and_json_types_refuse(self):
        for name in ('../escape', '/absolute', 'nested/.git/config', 'a\\b', './name'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                transfer.contained(name)
        for raw in (b'{"key":1,"key":2}', b'{"x":NaN}'):
            with self.assertRaises(RuntimeError):
                transfer.decode(raw)

    def test_late_transfer_deadline_refuses(self):
        with temporary() as directory:
            root = fixture(Path(directory))
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                transfer.verify_artifact(root, transfer.Budget(time.monotonic() - 1))

    def test_full_initialize_transfer_clock_and_provider_return(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            result = transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            self.assertTrue(result['passed'])
            self.assertFalse(result['execution_admitted'])
            self.assertLess(result['elapsed_seconds'], 180)

    def test_changed_original_transfer_clock_refuses(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            path = root / 'TRANSFER_CLOCK.json'
            value = transfer.decode(path.read_bytes())
            value['deadline'] += 1
            path.write_bytes(transfer.canonical(value))
            with self.assertRaisesRegex(RuntimeError, 'clock'):
                transfer.verify_transfer(root, transfer.sha(path.read_bytes()))

    def test_changed_transfer_python_refuses(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            path = root / 'TRANSFER_CLOCK.json'
            value = transfer.decode(path.read_bytes())
            value['python_sha256'] = '0' * 64
            path.write_bytes(transfer.canonical(value))
            with self.assertRaisesRegex(RuntimeError, 'Python'):
                transfer.verify_transfer(root, transfer.sha(path.read_bytes()))

    def test_native_complete_closure_and_physical_return(self):
        with temporary() as directory:
            prefix, direct, admission = native_fixture(Path(directory))
            with mock.patch.object(transfer, 'DIRECT', direct):
                first = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
                second = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            self.assertEqual(first, second)
            self.assertEqual(len(first['packages']), 4)
            self.assertEqual(len(first['libraries']), 4)
            self.assertFalse(first['dyld_cache_bytes_qualified'])

    def test_native_missing_dependency_refuses(self):
        self.native_change('missing')

    def test_native_changed_version_refuses(self):
        self.native_change('version')

    def test_native_changed_alias_refuses(self):
        self.native_change('alias')

    def test_native_extra_transitive_frontier_refuses(self):
        self.native_change('extra')

    def native_change(self, mode):
        with temporary() as directory:
            root = Path(directory)
            prefix, direct, admission = native_fixture(root)
            receipt = root / 'compiler/INSTALL_RECEIPT.json'
            value = transfer.decode(receipt.read_bytes())
            if mode == 'missing':
                value['runtime_dependencies'].pop()
            if mode == 'version':
                value['runtime_dependencies'][0]['version'] = 'changed'
            receipt.write_bytes(transfer.canonical(value))
            if mode == 'alias':
                (prefix / 'opt/libyaml').unlink()
                (prefix / 'opt/libyaml').mkdir()
            if mode == 'extra':
                (Path(direct[0]).resolve()).write_bytes(macho(['/outside/dependency.dylib']))
            with mock.patch.object(transfer, 'DIRECT', direct), self.assertRaises(RuntimeError):
                transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)

    def test_native_changed_byte_is_visible_to_review_policy(self):
        with temporary() as directory:
            prefix, direct, admission = native_fixture(Path(directory))
            with mock.patch.object(transfer, 'DIRECT', direct):
                before = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
                path = Path(direct[0]).resolve()
                path.write_bytes(path.read_bytes() + b'changed')
                after = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            self.assertNotEqual(transfer.policy_view(before), transfer.policy_view(after))

    def test_bounded_native_header_corruption_refuses(self):
        for raw in (b'', macho()[:10], struct.pack('<IIIIIIII', 0xFEEDFACF, 0x100000C, 0, 6, 257, 8, 0, 0)):
            with self.assertRaises(RuntimeError):
                transfer.native_imports(raw)

    def test_pending_policy_retains_false_execution(self):
        with temporary() as directory:
            root = Path(directory)
            prefix, direct, admission = native_fixture(root)
            with mock.patch.object(transfer, 'DIRECT', direct):
                native = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            policy = transfer.decode((ROOT / 'ANALYSIS_NATIVE_POLICY.json').read_bytes())
            self.assertFalse(transfer.registry(root, policy, native)['execution_admitted'])

    def test_reviewed_exact_policy_accepts_and_changed_policy_refuses(self):
        with temporary() as directory:
            root = Path(directory)
            prefix, direct, admission = native_fixture(root)
            with mock.patch.object(transfer, 'DIRECT', direct):
                native = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            policy = dict(format='atlas-grant-analysis-native-policy-v1', execution_admitted=True,
                independent_review_sha256='a' * 64, Apple_platform_code_loading_reviewed=True,
                expected_native=transfer.policy_view(native))
            self.assertTrue(transfer.registry(root, policy, native)['execution_admitted'])
            for key, value in [('independent_review_sha256', None), ('Apple_platform_code_loading_reviewed', False),
                               ('expected_native', {})]:
                changed = dict(policy, **{key: value})
                with self.assertRaises(RuntimeError):
                    transfer.registry(root, changed, native)

    def test_safe_canceled_stage_keeps_missing_metadata_explicit(self):
        with temporary() as directory:
            root = Path(directory)
            source = root / 'private'
            source.mkdir()
            (source / 'unapproved').write_text('private')
            result = stage_tool_admission.stage(source, root / 'stage')
            self.assertEqual(result['files'], [])
            self.assertEqual(len(result['missing']), 7)
            self.assertEqual(list((root / 'stage').iterdir()), [root / 'stage/PUBLIC_STAGE.json'])

    def test_credential_shaped_receipt_refuses_public_stage(self):
        with temporary() as directory:
            root = Path(directory)
            source = root / 'private'
            source.mkdir()
            (source / 'TRANSFER_RESULT.json').write_text('authorization: Bearer ' + 'A' * 40)
            with self.assertRaises(Exception):
                stage_tool_admission.stage(source, root / 'stage')

    def test_original_pending_registry_still_refuses_before_tool_use(self):
        import dirty_proof
        path = ROOT / 'PROOF_TOOLS_PENDING.json'
        with self.assertRaisesRegex(RuntimeError, 'explicit prerequisite'):
            dirty_proof.admit_tools(path, transfer.sha(path.read_bytes()))

    def test_transfer_clock_replacement_refuses_even_with_valid_duration(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            path = root / 'TRANSFER_CLOCK.json'
            original = transfer.sha(path.read_bytes())
            value = transfer.decode(path.read_bytes())
            value['started'] += 60
            value['deadline'] += 60
            path.write_bytes(transfer.canonical(value))
            with self.assertRaisesRegex(RuntimeError, 'clock hash'):
                transfer.verify_transfer(root, original)

    def test_tool_copy_replaced_same_bytes_refuses_physical_return(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            tool = root / 'tools/ameba'
            data = tool.read_bytes()
            tool.unlink()
            tool.write_bytes(data)
            tool.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, 'physical identities'):
                transfer.tool_return(root, transfer.Budget(time.monotonic() + 30))

    def test_pending_observation_keeps_executable_registry_unadmitted(self):
        import same_job_policy
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            prefix, direct, admission = native_fixture(root)
            with mock.patch.object(transfer, 'DIRECT', direct):
                native = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            with mock.patch.object(same_job_policy, 'metadata', return_value=admission), \
                 mock.patch.object(transfer, 'collect_native', return_value=native):
                result = transfer.observe(root, root / 'sdk', ROOT / 'ANALYSIS_NATIVE_POLICY.json')
            self.assertTrue(result['passed'])
            self.assertFalse(result['execution_admitted'])
            self.assertFalse(transfer.decode((root / 'PROOF_TOOLS.json').read_bytes())['execution_admitted'])

    def test_selected_native_snapshot_replays_complete_positive_artifact(self):
        with temporary() as directory:
            root, native = self.observed_fixture(Path(directory))
            result = stage_tool_admission.stage(root, Path(directory) / 'public stage')
            rows = {row['path']: row for row in result['files']}
            self.assertTrue(result['selected_native_library_payload_uploaded'])
            self.assertTrue(all(row['path'] in rows for row in native['native_evidence_files']))
            self.assertNotIn('tools/ameba', rows)

    def test_changed_selected_native_snapshot_refuses_artifact(self):
        with temporary() as directory:
            root, native = self.observed_fixture(Path(directory))
            path = root / native['native_evidence_files'][0]['path']
            path.write_bytes(path.read_bytes() + b'changed')
            with self.assertRaisesRegex(RuntimeError, 'snapshot digest'):
                stage_tool_admission.stage(root, Path(directory) / 'public stage')

    def test_missing_selected_native_snapshot_refuses_artifact(self):
        with temporary() as directory:
            root, native = self.observed_fixture(Path(directory))
            (root / native['native_evidence_files'][0]['path']).unlink()
            with self.assertRaises(FileNotFoundError):
                stage_tool_admission.stage(root, Path(directory) / 'public stage')

    def observed_fixture(self, directory):
        import same_job_policy
        root = transfer.initialize(directory)
        fixture(root)
        transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
        prefix, direct, admission = native_fixture(root)
        with mock.patch.object(transfer, 'DIRECT', direct):
            native = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
        with mock.patch.object(same_job_policy, 'metadata', return_value=admission), \
             mock.patch.object(transfer, 'collect_native', return_value=native):
            result = transfer.observe(root, root / 'sdk', ROOT / 'ANALYSIS_NATIVE_POLICY.json')
        return root, result

    def test_recreated_same_target_alias_changes_physical_return(self):
        with temporary() as directory:
            prefix, direct, admission = native_fixture(Path(directory))
            with mock.patch.object(transfer, 'DIRECT', direct):
                first = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
                alias = prefix / 'opt/libyaml'
                target = os.readlink(alias)
                alias.unlink()
                alias.symlink_to(target)
                second = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            self.assertNotEqual(first, second)
            self.assertEqual(transfer.policy_view(first), transfer.policy_view(second))

    def test_observation_failure_is_retained(self):
        import same_job_policy
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            with mock.patch.object(same_job_policy, 'metadata', side_effect=RuntimeError('Changed same-job authority')):
                with self.assertRaisesRegex(RuntimeError, 'Retained failed'):
                    transfer.observe(root, root / 'sdk', ROOT / 'ANALYSIS_NATIVE_POLICY.json')
            result = transfer.decode((root / 'NATIVE_OBSERVATION.json').read_bytes())
            self.assertFalse(result['passed'])
            self.assertIn('Changed same-job authority', result['error'])

    def test_verified_unexecuted_transfer_cleans_its_private_payload(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            result = transfer.cleanup(root)
            self.assertTrue(result['complete'])
            self.assertEqual(result['removed'], ['download', 'tools'])
            self.assertTrue((root / 'TRANSFER_RESULT.json').is_file())

    def test_canceled_transfer_keeps_unverified_private_payload(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            result = transfer.cleanup(root)
            self.assertFalse(result['complete'])
            self.assertEqual(result['preserved'], ['download'])

    def test_unreturned_executed_tool_group_preserves_private_payload(self):
        with temporary() as directory:
            root = transfer.initialize(Path(directory))
            fixture(root)
            transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            (root / 'PROOF_TOOLS.json').write_text('{"execution_admitted": true}')
            result = transfer.cleanup(root)
            self.assertFalse(result['complete'])
            self.assertEqual(result['preserved'], ['download', 'tools'])

    def guarded_controller(self, root, mode):
        for name in ('amber-lsp', 'ameba', 'crystal.yml'):
            (root / name).write_text('synthetic guarded provider')
        tools = dict(amber_lsp=dict(path=str(root / 'amber-lsp'), sha256=transfer.sha((root / 'amber-lsp').read_bytes()),
            api_corpus_path=str(root / 'crystal.yml'), api_corpus_sha256=transfer.sha((root / 'crystal.yml').read_bytes())),
            ameba=dict(path=str(root / 'ameba'), sha256=transfer.sha((root / 'ameba').read_bytes())))
        value = dict(tools=tools)
        registry = root / 'PROOF_TOOLS.json'
        registry.write_bytes(transfer.canonical(value))
        (root / 'ANALYSIS_NATIVE_POLICY.json').write_text('{}')
        native = {'guarded': 'native-before', 'libraries': []}
        (root / 'NATIVE_OBSERVATION.json').write_bytes(transfer.canonical(dict(passed=True, execution_admitted=True,
            registry_sha256=transfer.sha(registry.read_bytes()), native=native)))
        args = SimpleNamespace(tool_workspace=root, sdk_evidence=root / 'sdk', proof_tools=registry,
            proof_tools_sha256=transfer.sha(registry.read_bytes()), transfer_packet_sha256='a' * 64)
        observed = []
        clock = SimpleNamespace(value=1000.0)
        def invoke(supplied, absolute_deadline=None):
            self.assertIs(supplied, args)
            self.assertEqual(absolute_deadline, 16060.0)
            observed.append('original controller')
            if mode == 'exception':
                raise RuntimeError('Original controller failure')
            if mode == 'cancel':
                raise KeyboardInterrupt('Original cancellation')
            if mode == 'late':
                clock.value += 15121
            if mode == 'changed':
                (root / 'ameba').write_text('changed during experiment')
            return 0
        def protect(expected):
            if mode == 'admission-late':
                clock.value += 61
            return {}
        with mock.patch.object(run_admitted_dirty, 'ROOT', root), \
             mock.patch.object(run_admitted_dirty, 'metadata', return_value={'same_job': 'guarded'}), \
             mock.patch.object(transfer, 'protect_transfer', side_effect=protect), \
             mock.patch.object(transfer, 'collect_native', return_value=native), \
             mock.patch.object(transfer, 'tool_return', return_value=True), \
             mock.patch.object(transfer, 'registry', return_value=value), \
             mock.patch.object(time, 'monotonic', side_effect=lambda: clock.value):
            code = run_admitted_dirty.run(args, invoke)
        return code, transfer.decode((root / 'EXPERIMENT_TOOL_RETURN.json').read_bytes()), observed

    def test_guard_delegates_original_and_returns_every_provider(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'normal')
            self.assertEqual((code, calls), (0, ['original controller']))
            self.assertTrue(result['passed'])
            self.assertEqual(result['controller_maximum_seconds'], 15000)

    def test_guard_retains_original_failure_and_return(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'exception')
            self.assertEqual(code, 2)
            self.assertIn('Original controller failure', result['error'])
            self.assertEqual(result['finalization_errors'], [])

    def test_guard_retains_cancellation_and_return(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'cancel')
            self.assertEqual(code, 2)
            self.assertIn('KeyboardInterrupt', result['error'])

    def test_guard_changed_provider_refuses_complete_success(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'changed')
            self.assertEqual(code, 2)
            self.assertFalse(result['passed'])
            self.assertTrue(result['finalization_errors'])

    def test_guard_late_completion_refuses_complete_success(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'late')
            self.assertEqual(code, 2)
            self.assertFalse(result['passed'])

    def test_guard_requires_full_original_horizon_before_delegation(self):
        with temporary() as directory:
            code, result, calls = self.guarded_controller(Path(directory), 'admission-late')
            self.assertEqual(code, 2)
            self.assertEqual(calls, [])

    def test_delayed_actual_controller_entry_refuses_before_output_or_work(self):
        import run_dirty_experiment_with_deadline as bounded
        with mock.patch.object(time, 'monotonic', return_value=1100.0):
            with self.assertRaisesRegex(RuntimeError, 'Complete15000-second actual-entry'):
                bounded.run(SimpleNamespace(), absolute_deadline=16060.0)

    def test_bounded_controller_retains_original_behavior_fixture(self):
        import run_dirty_experiment_with_deadline as bounded
        import test_dirty_transition as predecessor
        with temporary() as directory, mock.patch.object(predecessor, 'controller', bounded):
            case = predecessor.DirtySourceControls()
            code, value, proved, measured = case.controller_fixture(Path(directory))
        self.assertEqual(code, 0)
        self.assertTrue(value['diagnostic_complete'])
        self.assertEqual(value['maximum_seconds'], 15000)

    def test_bounded_controller_requires_finite_exact_supplied_deadline(self):
        import run_dirty_experiment_with_deadline as bounded
        for deadline in (True, float('inf'), float('nan'), '15000'):
            with mock.patch.object(time, 'monotonic', return_value=1000.0), self.assertRaisesRegex(RuntimeError, 'Finite supplied'):
                bounded.run(SimpleNamespace(), absolute_deadline=deadline)

    def test_revisited_native_alias_retarget_changes_both_return_and_policy(self):
        with temporary() as directory:
            prefix, direct, admission = native_fixture(Path(directory))
            library = prefix / 'Cellar/libyaml' / transfer.PACKAGES['libyaml'] / 'lib'
            for name in ('X', 'Y'):
                (library / (name + '.dylib')).write_bytes(macho(transfer.SYSTEM_IMPORTS) + name.encode())
            selected = library / 'selected.dylib'
            selected.symlink_to('X.dylib')
            imports = [*transfer.SYSTEM_IMPORTS, *[str(prefix / 'opt/libyaml/lib' / name)
                       for name in ('X.dylib', 'Y.dylib', 'selected.dylib')]]
            Path(direct[0]).write_bytes(macho(imports))
            with mock.patch.object(transfer, 'DIRECT', direct):
                before = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
                selected.unlink()
                selected.symlink_to('Y.dylib')
                after = transfer.collect_native(transfer.Budget(time.monotonic() + 30), admission, prefix)
            self.assertNotEqual(before, after)
            self.assertNotEqual(transfer.policy_view(before), transfer.policy_view(after))
            self.assertEqual(len(before['libraries']), len(after['libraries']))

    def test_native_resolution_preserves_parent_semantics_after_symlink(self):
        with temporary() as directory:
            root = Path(directory)
            (root / 'branch/deeper').mkdir(parents=True)
            (root / 'branch/Y').write_bytes(b'actual target')
            (root / 'Y').write_bytes(b'different normalized target')
            (root / 'mid').symlink_to('branch/deeper')
            (root / 'selected').symlink_to('mid/../Y')
            value = transfer.resolve_native(str(root / 'selected'))
            self.assertEqual(value['resolved_path'], str((root / 'selected').resolve(strict=True)))
            self.assertEqual(value['resolved_path'], str(root / 'branch/Y'))
            self.assertEqual(len(value['links']), 2)

    def test_incomplete_cleanup_operation_refuses_and_preserves_receipt(self):
        with temporary() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / 'tools').mkdir()
            (root / 'tools/ameba').write_bytes(b'guarded private payload')
            (root / 'TRANSFER_RESULT.json').write_text('{"passed":true}')
            (root / 'PROOF_TOOLS.json').write_text('{"execution_admitted":false}')
            original = Path.unlink
            def refused(path, *args, **kwargs):
                if path == root / 'tools/ameba':
                    raise PermissionError('Guarded cleanup permission refusal')
                return original(path, *args, **kwargs)
            with mock.patch.object(Path, 'unlink', refused), self.assertRaisesRegex(RuntimeError, 'Complete private tool payload'):
                transfer.operation(SimpleNamespace(operation='cleanup', root=root))
            value = transfer.decode((root / 'CLEANUP.json').read_bytes())
            self.assertFalse(value['complete'])
            self.assertTrue((root / 'tools/ameba').is_file())


    def test_shared_lease_accepts_valid_interval_across_local_clock_reset(self):
        with temporary() as directory:
            with mock.patch.object(time, 'clock_gettime', return_value=1000.0), mock.patch.object(time, 'monotonic', return_value=10.0):
                root = transfer.initialize(Path(directory))
            fixture(root)
            with mock.patch.object(time, 'clock_gettime', return_value=1100.0), mock.patch.object(time, 'monotonic', return_value=1.0):
                result = transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            self.assertTrue(result['passed'])
            self.assertEqual(result['elapsed_seconds'], 100.0)
            self.assertEqual(result['clock_protocol'], transfer.SHARED_CLOCK)
            self.assertEqual(result['local_verifier_deadline'], 81.0)

    def test_shared_lease_refuses_expired_interval_despite_local_clock_reset(self):
        with temporary() as directory:
            with mock.patch.object(time, 'clock_gettime', return_value=1000.0), mock.patch.object(time, 'monotonic', return_value=10.0):
                root = transfer.initialize(Path(directory))
            fixture(root)
            with mock.patch.object(time, 'clock_gettime', return_value=1200.0), mock.patch.object(time, 'monotonic', return_value=1.0):
                with self.assertRaisesRegex(RuntimeError, 'original180-second shared-clock lease'):
                    transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            self.assertFalse((root / 'TRANSFER_RESULT.json').exists())
            self.assertFalse((root / 'tools').exists())
            self.assertTrue((root / 'download').is_dir())

    def test_shared_lease_refuses_negative_and_nonfinite_samples(self):
        for sample in (999.0, float('nan'), float('inf'), True):
            with temporary() as directory:
                with mock.patch.object(time, 'clock_gettime', return_value=1000.0):
                    root = transfer.initialize(Path(directory))
                with mock.patch.object(time, 'clock_gettime', return_value=sample), self.assertRaisesRegex(RuntimeError, 'nonnegative'):
                    transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
                self.assertFalse((root / 'TRANSFER_RESULT.json').exists())

    def test_shared_lease_refuses_expiration_after_materialization(self):
        with temporary() as directory:
            current = SimpleNamespace(value=1000.0)
            with mock.patch.object(time, 'clock_gettime', side_effect=lambda *args: current.value):
                root = transfer.initialize(Path(directory))
                fixture(root)
                original = transfer.materialize
                def materialize(*args):
                    rows = original(*args)
                    current.value = 1181.0
                    return rows
                with mock.patch.object(transfer, 'materialize', side_effect=materialize), self.assertRaisesRegex(RuntimeError, 'shared-clock lease'):
                    transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            self.assertFalse((root / 'TRANSFER_RESULT.json').exists())
            self.assertTrue((root / 'tools/ameba').is_file())

    def test_shared_lease_requires_explicit_protocol_and_typed_values(self):
        for field, value in (('clock_protocol', 'process-local.time.monotonic'), ('started', True), ('deadline', '1180')):
            with temporary() as directory:
                root = transfer.initialize(Path(directory))
                path = root / 'TRANSFER_CLOCK.json'
                state = transfer.decode(path.read_bytes())
                state[field] = value
                path.write_bytes(transfer.canonical(state))
                with self.assertRaises(RuntimeError):
                    transfer.verify_transfer(root, transfer.sha(path.read_bytes()))

    def test_shared_lease_refuses_terminal_clock_regression(self):
        with temporary() as directory:
            current = SimpleNamespace(value=1000.0)
            with mock.patch.object(time, 'clock_gettime', side_effect=lambda *args: current.value):
                root = transfer.initialize(Path(directory))
                fixture(root)
                current.value = 1100.0
                original = transfer.materialize
                def materialize(*args):
                    rows = original(*args)
                    current.value = 1050.0
                    return rows
                with mock.patch.object(transfer, 'materialize', side_effect=materialize), self.assertRaisesRegex(RuntimeError, 'Nondecreasing'):
                    transfer.verify_transfer(root, transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes()))
            self.assertFalse((root / 'TRANSFER_RESULT.json').exists())

    def test_final_source_return_expiration_marks_transfer_failed(self):
        with temporary() as directory:
            with mock.patch.object(time, 'clock_gettime', return_value=1000.0):
                root = transfer.initialize(Path(directory))
            fixture(root)
            expected = transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes())
            with mock.patch.object(time, 'clock_gettime', return_value=1100.0):
                transfer.verify_transfer(root, expected)
            with mock.patch.object(time, 'clock_gettime', return_value=1200.0), self.assertRaisesRegex(RuntimeError, 'shared-clock lease'):
                transfer.final_transfer_lease(root, expected)
            result = transfer.decode((root / 'TRANSFER_RESULT.json').read_bytes())
            self.assertFalse(result['passed'])
            self.assertFalse(result['execution_source_return_inside_lease'])
            self.assertIn('final_lease_error', result)
            self.assertTrue((root / 'tools/ameba').is_file())

    def test_main_checks_shared_lease_after_final_source_readback(self):
        with temporary() as directory:
            with mock.patch.object(time, 'clock_gettime', return_value=1000.0):
                root = transfer.initialize(Path(directory))
            fixture(root)
            expected = transfer.sha((root / 'TRANSFER_CLOCK.json').read_bytes())
            with mock.patch.object(time, 'clock_gettime', return_value=1100.0):
                transfer.verify_transfer(root, expected)
            calls = []
            def protect(value):
                calls.append('source-return')
                return {}
            with mock.patch.object(sys, 'argv', ['transfer.py', 'transfer', '--root', str(root), '--transfer-sha256', 'a'*64, '--clock-sha256', expected]), \
                 mock.patch.object(transfer, 'protect_transfer', side_effect=protect), \
                 mock.patch.object(transfer, 'operation', side_effect=lambda args: calls.append('operation')), \
                 mock.patch.object(time, 'clock_gettime', return_value=1110.0):
                transfer.main()
            result = transfer.decode((root / 'TRANSFER_RESULT.json').read_bytes())
            self.assertEqual(calls, ['source-return', 'operation', 'source-return'])
            self.assertEqual(result['elapsed_seconds'], 110.0)
            self.assertTrue(result['execution_source_return_inside_lease'])

    def test_shared_to_local_translation_is_conservative(self):
        with mock.patch.object(time, 'monotonic', return_value=1.0), mock.patch.object(time, 'clock_gettime', return_value=1100.0):
            self.assertEqual(transfer.local_deadline(1180.0), 81.0)
        with mock.patch.object(time, 'monotonic', return_value=10.0), mock.patch.object(time, 'clock_gettime', return_value=1000.0):
            self.assertEqual(transfer.shared_deadline(190.0), 1180.0)
        for value in (-1, True, float('inf'), float('nan')):
            with self.assertRaises(RuntimeError):
                transfer.local_deadline(value)
        with mock.patch.object(time, 'clock_gettime', return_value=1200.0), self.assertRaisesRegex(RuntimeError, 'shared-clock deadline'):
            transfer.local_deadline(1180.0)

    def test_controller_translates_shared_deadline_at_actual_entry(self):
        import run_dirty_experiment_with_deadline as bounded
        with mock.patch.object(time, 'monotonic', return_value=1.0), mock.patch.object(time, 'clock_gettime', return_value=1200.0):
            with self.assertRaisesRegex(RuntimeError, 'Complete15000-second actual-entry'):
                bounded.run(SimpleNamespace(), absolute_deadline=16100.0, deadline_clock=transfer.SHARED_CLOCK)
        with mock.patch.object(time, 'monotonic', return_value=1.0), self.assertRaisesRegex(RuntimeError, 'clock protocol'):
            bounded.run(SimpleNamespace(), absolute_deadline=16000.0, deadline_clock='unspecified')

    def test_production_guard_passes_explicit_shared_controller_deadline(self):
        import run_dirty_experiment_with_deadline as bounded
        original = run_admitted_dirty.run
        observed = []
        def actual_entry(args, absolute_deadline=None, deadline_clock=None):
            observed.append((absolute_deadline, deadline_clock, transfer.local_deadline(absolute_deadline)))
            return 0
        def production(args, invoke):
            return original(args)
        with temporary() as directory, mock.patch.object(time, 'clock_gettime', return_value=10000.0), \
             mock.patch.object(run_admitted_dirty, 'run', side_effect=production), mock.patch.object(bounded, 'run', side_effect=actual_entry):
            code, result, calls = self.guarded_controller(Path(directory), 'normal')
        self.assertEqual(code, 0)
        self.assertEqual(observed, [(25060.0, transfer.SHARED_CLOCK, 16060.0)])
        self.assertEqual(result['supplied_controller_clock'], transfer.SHARED_CLOCK)


def main():
    global FIXTURE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-zip', type=Path)
    parser.add_argument('--artifact-directory', type=Path)
    args = parser.parse_args()
    transfer.need(bool(args.artifact_zip) != bool(args.artifact_directory), 'One exact data fixture interface required')
    FIXTURE = args.artifact_zip if args.artifact_zip else args.artifact_directory
    if args.artifact_zip:
        transfer.need(transfer.sha(FIXTURE.read_bytes()) == 'b92262e930c0dfdc5c47ba51c310f1fe0590e7e1a7e72c7a401bcd8bd3fad31a',
                      'Exact accepted data-only artifact fixture required')
    else:
        transfer.verify_artifact(FIXTURE, transfer.Budget(time.monotonic() + 30))
    calls = []
    def guarded(*a, **k):
        calls.append('external')
        raise AssertionError('Guarded source fixture scope')
    with mock.patch.object(subprocess, 'Popen', side_effect=guarded), mock.patch.object(os, 'system', side_effect=guarded), \
         mock.patch.object(os, 'kill', side_effect=guarded), mock.patch.object(os, 'killpg', side_effect=guarded), \
         mock.patch.object(os, 'fork', side_effect=guarded), mock.patch.object(os, 'posix_spawn', side_effect=guarded), \
         mock.patch.object(os, 'posix_spawnp', side_effect=guarded):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ToolTransferControls))
    print(json.dumps(dict(passed=result.wasSuccessful(), tests=result.testsRun, failures=len(result.failures),
        errors=len(result.errors), external_guard_calls=len(calls), optimization=sys.flags.optimize,
        actual_local_compiler_native_container_ssh_jobs=0), sort_keys=True))
    return 0 if result.wasSuccessful() and not calls else 2


if __name__ == '__main__':
    raise SystemExit(main())
