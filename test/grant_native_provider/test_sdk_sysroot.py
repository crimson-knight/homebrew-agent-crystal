"""Guarded SDK selection, real producer/reader/policy and return controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import test_provider_observation as base
import provider_observation as subject

spec = importlib.util.spec_from_file_location('observed_sdk_control_contract', ROOT / 'sdk_sysroot.py')
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class SDKSysrootControls(unittest.TestCase):
    def setUp(self):
        self.fixture = base.ProviderControls('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def binding(self):
        return sdk.capture(str(self.fixture.sdk), '26.0', 'SYNTHETIC-26', time.monotonic() + 10)

    def positive(self):
        code, value = self.fixture.perform()
        self.assertEqual(code, 0)
        self.assertTrue(value['passed'])
        return value

    def reseal(self, value):
        value['stable_view'] = subject.stable_view(value)
        value['stable_view_sha256'] = subject.sha(subject.canonical(value['stable_view']))
        subject.write(self.fixture.args.output / 'COMMANDS.json', value['commands'])
        subject.write(self.fixture.args.output / 'OBSERVATION.json', value)
        return subject.digest(self.fixture.args.output / 'OBSERVATION.json', 1e30)

    def test_observed_sdk_reaches_header_compile_and_link_commands(self):
        value = self.positive()
        binding = value['sdk_sysroot']
        self.assertEqual(binding['path'], str(self.fixture.sdk))
        self.assertEqual((binding['version'], binding['build']), ('26.0', 'SYNTHETIC-26'))
        self.assertEqual(value['shim_compile_context']['sdk_sysroot'], binding)
        for label in ('headers', 'cc-search', 'link-search'):
            argv = next(row['arguments'] for row in value['commands'] if row['label'] == label)
            self.assertEqual(argv[1:3], ['-isysroot', str(self.fixture.sdk)])
        self.assertEqual(sum(row['maximum_seconds'] for row in value['commands']), 180)
        self.assertEqual(len(value['commands']), 20)

    def test_original_header_tuple_refuses_modeled_sdk_lookup_and_corrected_tuple_resolves(self):
        self.fixture.write(self.fixture.sdk / 'usr/include/dlfcn.h', b'SYNTHETIC SDK dlopen declaration')
        binding = self.binding()
        original = [str(self.fixture.cc), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                    str(self.fixture.probe_root / 'buffer_shim.c'), '-E', '-M']
        corrected = sdk.compile_argv(original, binding)
        def selected_header(argv):
            if argv[1:3] != ['-isysroot', str(self.fixture.sdk)]:
                raise RuntimeError("SYNTHETIC original direct-clang dlfcn.h lookup refusal")
            header = self.fixture.sdk / 'usr/include/dlfcn.h'
            self.assertEqual(header.read_bytes(), b'SYNTHETIC SDK dlopen declaration')
            return header
        with self.assertRaisesRegex(RuntimeError, 'dlfcn.h'):
            selected_header(original)
        self.assertEqual(selected_header(corrected), self.fixture.sdk / 'usr/include/dlfcn.h')
        self.assertEqual(corrected[:1] + corrected[3:], original)

    def test_native_policy_and_actual_compile_context_share_sdk(self):
        value = self.positive()
        args = self.fixture.policy_args(value)
        with patch.object(base.transfer, 'registry', return_value=dict(execution_admitted=True, SYNTHETIC='separately admitted tool fixture')):
            self.assertEqual(subject.materialize(args, self.fixture.context, time.monotonic()), 0)
        policy = json.loads((args.output / 'NATIVE_POLICY.json').read_bytes())
        self.assertEqual(policy['sdk_sysroot'], value['sdk_sysroot'])
        base.probe.native_policy(args.output / 'NATIVE_POLICY.json',
                                 subject.digest(args.output / 'NATIVE_POLICY.json', 1e30),
                                 self.fixture.admitted, absolute_deadline=time.monotonic() + 30)
        context = policy['shim_compile_context']
        base.probe.verify_shim_context(policy, context['original_argv'], context['environment'],
                                       Path(context['planned_private']), time.monotonic() + 10)

    def test_native_reader_refuses_missing_top_level_sdk_binding(self):
        value = self.positive()
        args = self.fixture.policy_args(value)
        with patch.object(base.transfer, 'registry', return_value=dict(execution_admitted=True)):
            self.assertEqual(subject.materialize(args, self.fixture.context, time.monotonic()), 0)
        path = args.output / 'NATIVE_POLICY.json'
        original = path.read_bytes()
        policy = json.loads(original)
        del policy['sdk_sysroot']
        path.write_text(json.dumps(policy))
        with self.assertRaisesRegex(RuntimeError, 'SDK native policy binding'):
            base.probe.native_policy(path, subject.digest(path, 1e30), self.fixture.admitted)
        path.write_bytes(original)
        base.probe.native_policy(path, subject.digest(path, 1e30), self.fixture.admitted)

    def test_missing_sdk_refuses_before_capture(self):
        with self.assertRaises(FileNotFoundError):
            sdk.capture(str(self.fixture.root / 'absent.sdk'), '26', 'BUILD', time.monotonic() + 10)

    def test_relative_and_root_sdk_paths_refuse(self):
        for path in ('relative.sdk', '/', str(self.fixture.sdk / '..')):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                sdk.capture(path, '26', 'BUILD', time.monotonic() + 10)

    def test_invalid_sdk_version_and_build_types_refuse(self):
        for version, build in ((False, 'B'), ('26', 1), ('', 'B'), ('26', '')):
            with self.subTest(version=version, build=build), self.assertRaises(RuntimeError):
                sdk.capture(str(self.fixture.sdk), version, build, time.monotonic() + 10)

    def test_changed_same_byte_sdk_directory_identity_refuses(self):
        value = self.binding()
        saved = self.fixture.sdk.with_name('SDK.saved')
        self.fixture.sdk.rename(saved)
        self.fixture.sdk.mkdir()
        (self.fixture.sdk / 'SDKSettings.json').write_bytes((saved / 'SDKSettings.json').read_bytes())
        with self.assertRaises(RuntimeError):
            sdk.verify(value, time.monotonic() + 10)

    def test_changed_same_byte_settings_inode_refuses_and_restoration_passes(self):
        value = self.binding()
        path = self.fixture.sdk / 'SDKSettings.json'
        saved = path.with_suffix('.saved')
        path.rename(saved)
        path.write_bytes(saved.read_bytes())
        with self.assertRaises(RuntimeError):
            sdk.verify(value, time.monotonic() + 10)
        path.unlink()
        saved.rename(path)
        # The metadata bytes are restored; the directory timestamps still changed and require a fresh observation.
        restored = self.binding()
        self.assertEqual(restored['settings']['sha256'], value['settings']['sha256'])
        self.assertEqual(sdk.verify(restored, time.monotonic() + 10), restored)

    def test_sdk_alias_retarget_refuses(self):
        alias = self.fixture.root / 'Selected.sdk'
        alias.symlink_to(self.fixture.sdk)
        value = sdk.capture(str(alias), '26', 'B', time.monotonic() + 10)
        other = self.fixture.root / 'Other.sdk'
        other.mkdir()
        (other / 'SDKSettings.json').write_bytes((self.fixture.sdk / 'SDKSettings.json').read_bytes())
        alias.unlink()
        alias.symlink_to(other)
        with self.assertRaises(RuntimeError):
            sdk.verify(value, time.monotonic() + 10)

    def test_external_sdk_settings_alias_refuses(self):
        path = self.fixture.sdk / 'SDKSettings.json'
        path.unlink()
        external = self.fixture.root / 'external-settings.json'
        external.write_text('{}')
        path.symlink_to(external)
        with self.assertRaisesRegex(RuntimeError, 'belong'):
            self.binding()

    def test_directory_or_oversized_settings_refuse(self):
        path = self.fixture.sdk / 'SDKSettings.json'
        path.unlink()
        path.mkdir()
        with self.assertRaises(RuntimeError):
            self.binding()
        path.rmdir()
        with path.open('wb') as stream:
            stream.truncate(sdk.MAX_SETTINGS + 1)
        with self.assertRaises(RuntimeError):
            self.binding()

    def test_conflicting_or_duplicate_sysroot_flags_refuse(self):
        for flag in ('-isysroot', '-isysroot/another', '--sysroot', '--sysroot=/another'):
            with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                sdk.compile_argv([str(self.fixture.cc), flag, '-c', 'source.c'], self.binding())

    def test_changed_resealed_sdk_version_refuses_raw_reader(self):
        value = self.positive()
        value['sdk_sysroot']['version'] = '26.1'
        receipt = self.reseal(value)
        with self.assertRaisesRegex(RuntimeError, 'raw observed SDK'):
            subject.admit_observation(self.fixture.args.output, receipt)

    def test_changed_resealed_settings_hash_refuses_census_join(self):
        value = self.positive()
        value['sdk_sysroot']['settings']['sha256'] = '0' * 64
        receipt = self.reseal(value)
        with self.assertRaisesRegex(RuntimeError, 'settings census'):
            subject.admit_observation(self.fixture.args.output, receipt)

    def test_changed_resealed_header_argv_refuses_and_restored_reader_passes(self):
        original = self.positive()
        value = copy.deepcopy(original)
        record = next(row for row in value['commands'] if row['label'] == 'headers')
        del record['arguments'][1:3]
        with self.assertRaisesRegex(RuntimeError, 'header/compile/link-search'):
            subject.admit_observation(self.fixture.args.output, self.reseal(value))
        self.assertTrue(subject.admit_observation(self.fixture.args.output, self.reseal(original))['passed'])

    def test_changed_resealed_link_sysroot_refuses(self):
        value = self.positive()
        record = next(row for row in value['commands'] if row['label'] == 'link-search')
        record['arguments'][2] = '/SYNTHETIC/other.sdk'
        with self.assertRaisesRegex(RuntimeError, 'header/compile/link-search'):
            subject.admit_observation(self.fixture.args.output, self.reseal(value))

    def test_sdk_settings_change_at_final_return_stays_failed(self):
        original = self.fixture.context['check']
        def changed(deadline):
            original(deadline)
            (self.fixture.sdk / 'SDKSettings.json').write_text('{"SYNTHETIC":"changed after commands"}')
        self.fixture.context['check'] = changed
        code, value = self.fixture.perform()
        self.assertEqual(code, 2)
        self.assertFalse(value['passed'])
        self.assertTrue(any('SDK' in error or 'native/header' in error for error in value['finalization_errors']))
        self.assertTrue(value['writers_confirmed_retired'])

    def test_expired_and_nonfinite_deadlines_refuse(self):
        for deadline in (-1, float('inf'), float('nan'), False):
            with self.subTest(deadline=deadline), self.assertRaises(RuntimeError):
                sdk.capture(str(self.fixture.sdk), '26', 'B', deadline)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SDKSysrootControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(tests=result.testsRun, passed=result.wasSuccessful(),
                          external_workload_guard_calls=base.CALLS)))
    raise SystemExit(0 if result.wasSuccessful() and not base.CALLS else 1)
