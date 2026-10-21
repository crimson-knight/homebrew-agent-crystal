"""Guarded mechanical compile/header joins across producer, reader, and execution."""
from pathlib import Path
import copy
import json
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import test_sdk_sysroot as original

subject = original.subject
sdk = original.sdk


class MechanicalDerivationControls(unittest.TestCase):
    def setUp(self):
        self.control = original.SDKSysrootControls('runTest')
        self.control.setUp()
        self.addCleanup(self.control.doCleanups)

    def argv(self):
        fixture = self.control.fixture
        return [str(fixture.cc), '-isysroot', str(fixture.sdk), '-std=c11',
                '-Wall', '-Wextra', '-Werror', '-O2', '-c',
                str(fixture.probe_root / 'buffer_shim.c'), '-o', str(fixture.root / 'buffer_shim.o')]

    def test_complete_derivation_is_pure_and_preserves_all_original_flags(self):
        value = self.argv()
        before = copy.deepcopy(value)
        self.assertEqual(sdk.preprocessing_argv(value), value[:-4] + [value[-3], '-E', '-M'])
        self.assertEqual(value, before)
        self.assertEqual(sdk.preprocessing_argv(value).count('-isysroot'), 1)
        self.assertIn('-O2', sdk.preprocessing_argv(value))

    def test_bounded_typed_arguments_refuse_before_derivation(self):
        values = [None, tuple(self.argv()), [False] + self.argv()[1:],
                  ['x' * 4097] + self.argv()[1:], ['x'] * 129,
                  [self.argv()[0] + '\0'] + self.argv()[1:],
                  [self.argv()[0] + '\n'] + self.argv()[1:],
                  ['/' + 'x' * 4095] * 17 + self.argv()[1:]]
        for value in values:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(RuntimeError):
                sdk.preprocessing_argv(value)

    def test_incomplete_duplicate_or_reordered_compile_tail_refuses(self):
        value = self.argv()
        values = [value[:-2], value[:-4] + ['-o', value[-1], '-c', value[-3]],
                  value[:1] + ['-c'] + value[1:], value[:1] + ['-o'] + value[1:],
                  value[:-3] + ['relative/buffer_shim.c', '-o', value[-1]],
                  value[:-1] + ['relative.o'], value[:1] + ['-E'] + value[1:],
                  value[:1] + ['-M'] + value[1:]]
        for changed in values:
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                sdk.preprocessing_argv(changed)

    def refuse_changed(self, alter):
        value = self.control.positive()
        output = self.control.fixture.args.output
        self.assertTrue(subject.admit_observation(output, self.control.reseal(value))['passed'])
        changed = copy.deepcopy(value)
        alter(changed['shim_compile_context']['preprocessing_argv'])
        next(row for row in changed['commands'] if row['label'] == 'headers')['arguments'] = copy.deepcopy(changed['shim_compile_context']['preprocessing_argv'])
        changed_sha = self.control.reseal(changed)
        with self.assertRaisesRegex(RuntimeError, 'mechanically derived observed header argv'):
            subject.admit_observation(output, changed_sha)
        context = changed['shim_compile_context']
        policy = dict(shim_compile_context=context, sdk_sysroot=changed['sdk_sysroot'])
        with self.assertRaisesRegex(RuntimeError, 'transformed header observation'):
            original.base.probe.verify_shim_context(policy, context['original_argv'], context['environment'],
                Path(context['planned_private']), time.monotonic() + 10)
        self.assertTrue(subject.admit_observation(output, self.control.reseal(value))['passed'])

    def test_coordinated_header_sysroot_omission_refuses_and_restores(self):
        self.refuse_changed(lambda argv: argv.__delitem__(slice(1, 3)))

    def test_coordinated_header_sdk_replacement_refuses_and_restores(self):
        self.refuse_changed(lambda argv: argv.__setitem__(2, '/SYNTHETIC/unobserved.sdk'))

    def test_coordinated_header_optimization_omission_refuses_and_restores(self):
        self.refuse_changed(lambda argv: argv.remove('-O2'))

    def test_all_three_actual_boundaries_call_the_same_shared_derivation(self):
        calls = []
        def tracked(module):
            derive = module.preprocessing_argv
            def invoke(argv):
                calls.append(tuple(argv))
                return derive(argv)
            module.preprocessing_argv = invoke
            return module
        original_load = subject.load
        def load(path, *args, **kwargs):
            module = original_load(path, *args, **kwargs)
            return tracked(module) if Path(path).name == 'sdk_sysroot.py' else module
        native = original.base.probe
        native_load = native.observed_sdk_contract
        with patch.object(subject, 'load', side_effect=load):
            value = self.control.positive()
            self.assertGreater(len(calls), 0)
            count = len(calls)
            subject.admit_observation(self.control.fixture.args.output, self.control.reseal(value))
            self.assertGreater(len(calls), count)
            count = len(calls)
            context = value['shim_compile_context']
            with patch.object(native, 'observed_sdk_contract', side_effect=lambda: tracked(native_load())):
                native.verify_shim_context(dict(shim_compile_context=context, sdk_sysroot=value['sdk_sysroot']),
                    context['original_argv'], context['environment'], Path(context['planned_private']), time.monotonic() + 10)
            self.assertGreater(len(calls), count)
        self.assertTrue(all(list(argv) == value['shim_compile_context']['original_argv'] for argv in calls))

    def test_additional_pic_and_define_context_is_preserved_by_the_pure_transform(self):
        value = self.argv()
        value[-4:-4] = ['-fPIC', '-DSYNTHETIC=1']
        transformed = sdk.preprocessing_argv(value)
        self.assertIn('-fPIC', transformed)
        self.assertIn('-DSYNTHETIC=1', transformed)
        self.assertIn('-O2', transformed)
        self.assertEqual(transformed, [argument for argument in value[:-2] if argument != '-c'] + ['-E', '-M'])


if __name__ == '__main__':
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(MechanicalDerivationControls))
    print(json.dumps(dict(passed=result.wasSuccessful(), tests=result.testsRun,
                          external_workload_guard_calls=original.base.CALLS)))
    raise SystemExit(0 if result.wasSuccessful() else 1)
