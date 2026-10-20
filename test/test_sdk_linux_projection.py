"""Source-only physical and mocked controls; actual hosted collection stays pending."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
COLLECTOR = ROOT / ('collect_projection.py' if (ROOT / 'collect_projection.py').exists() else 'linux_native_projection.py')
READER = ROOT / ('record_linux_runner.py' if (ROOT / 'record_linux_runner.py').exists() else 'linux_projection_identity.py')
spec = importlib.util.spec_from_file_location('projection', COLLECTOR)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
spec2 = importlib.util.spec_from_file_location('linux_reader', READER)
reader = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(reader)


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.root = Path(self.private.name).resolve()
        self.roster = module.Roster(reader.file_identity, time.monotonic() + 15)

    def tearDown(self):
        self.private.cleanup()

    def test_physical_file_alias_and_changed_bytes(self):
        file = self.root / 'actual'; file.write_text('native')
        alias = self.root / 'selected'; alias.symlink_to('actual')
        self.assertEqual(self.roster.add(alias, required=True), str(file))
        self.assertEqual(self.roster.entries[str(alias)]['target'], 'actual')
        self.roster.verify()
        file.write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'changed'): self.roster.verify()

    def test_empty_stdlib_member_retains_original_digest(self):
        root = self.root / 'src'; root.mkdir()
        (root / 'empty.cr').write_bytes(b'')
        (root / 'value.cr').write_text('value')
        (root / 'alias').symlink_to('value.cr')
        actual = module.stdlib_identity(root, self.roster)
        self.assertEqual(actual['files']['empty.cr'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(actual['directory_aliases'], {'alias': 'value.cr'})
        self.roster.verify()

    def test_stdlib_alias_escape_refuses(self):
        root = self.root / 'src'; root.mkdir()
        (self.root / 'outside').write_text('outside')
        (root / 'alias').symlink_to('../outside')
        with self.assertRaisesRegex(RuntimeError, 'inside'): module.stdlib_identity(root, self.roster)

    def test_ancestor_alias_exposes_additional_mount(self):
        actual = self.root / 'usr'; actual.mkdir(); (actual / 'cc').write_text('cc')
        alternatives = self.root / 'alternatives'; alternatives.symlink_to('usr', target_is_directory=True)
        selected = self.root / 'cc'; selected.symlink_to('alternatives/cc')
        self.roster.add(selected, required=True)
        self.assertIn(str(alternatives), self.roster.entries)
        self.assertIn(str(actual / 'cc'), self.roster.gaps())
        self.assertFalse(module.covered('/etc/alternatives/cc'))
        self.assertTrue(module.covered('/usr/bin/cc'))

    def test_missing_required_and_alias_cycle_refuse(self):
        with self.assertRaisesRegex(RuntimeError, 'absent'): self.roster.add(self.root / 'missing', required=True)
        (self.root / 'cycle').symlink_to('cycle')
        with self.assertRaisesRegex(RuntimeError, 'depth'): self.roster.add(self.root / 'cycle', required=True)

    def test_deadline_entry_and_byte_budgets_refuse(self):
        file = self.root / 'input'; file.write_text('abc')
        self.roster.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(RuntimeError, 'deadline'): self.roster.add(file)
        self.roster.deadline = time.monotonic() + 15
        with patch.object(module, 'MAX_HASH_BYTES', 2):
            with self.assertRaisesRegex(RuntimeError, 'hash-byte'): self.roster.add(file)
        with patch.object(module, 'MAX_FILES', 0):
            with self.assertRaisesRegex(RuntimeError, 'entry budget'): self.roster.add(file)

    def test_static_loader_parsers_keep_exact_paths(self):
        raw = '\tlibgmp.so.10 (libc6,x86-64) => /lib/x86_64-linux-gnu/libgmp.so.10\n'
        self.assertEqual(module.cache_paths(raw), {'libgmp.so.10': ['/lib/x86_64-linux-gnu/libgmp.so.10']})
        self.assertEqual(module.elf_needed('0x1 (NEEDED) Shared library: [libgmp.so.10]\n'), ['libgmp.so.10'])
        self.assertEqual(module.elf_search_directories('0x1 (RUNPATH) Library runpath: [$ORIGIN/../lib:/usr/lib]', ['/opt/tool/bin/compiler']), ['/opt/tool/lib', '/usr/lib'])
        self.assertIn('/lib64/ld-linux-x86-64.so.2', module.extract_absolute_paths('Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]'))

    def test_retired_record_and_bool_float_and_live_refusals(self):
        good = {'exit_code': 0, 'pid': 123, 'original_group': 123, 'terminal_group_observation': {'group': 123, 'status': 'absent'}, 'writers_confirmed_retired': True, 'refusal': None, 'elapsed_seconds': 0.1, 'stdout_sha256': 'a'*64, 'stderr_sha256': 'b'*64}
        module.validate_command(good)
        changes = [('exit_code', False), ('exit_code', 0.0), ('pid', True), ('original_group', 123.0), ('writers_confirmed_retired', False), ('elapsed_seconds', 46), ('stdout_sha256', None), ('refusal', 'Original owned process group is present')]
        for key, value in changes:
            bad = copy.deepcopy(good); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError): module.validate_command(bad)
        bad = copy.deepcopy(good); bad['terminal_group_observation']['group'] = 123.0
        with self.assertRaises(RuntimeError): module.validate_command(bad)
        bad = copy.deepcopy(good); bad['terminal_group_observation']['status'] = 'present'
        with self.assertRaises(RuntimeError): module.validate_command(bad)

    def test_mocked_runner_keeps_raw_hashes_and_original_return(self):
        binary = self.root / 'metadata-tool'; binary.write_text('identified tool')
        class MockedRunner:
            records = []
            def run(inner, label, arguments, **kwargs):
                stdout = b'actual metadata output\n'; stderr = b''
                (self.root / (label + '.stdout.txt')).write_bytes(stdout)
                (self.root / (label + '.stderr.txt')).write_bytes(stderr)
                inner.records.append({'label': label, 'arguments': arguments, 'exit_code': 0, 'pid': 101, 'original_group': 101, 'terminal_group_observation': {'group': 101, 'status': 'absent'}, 'writers_confirmed_retired': True, 'refusal': None, 'elapsed_seconds': 0.1, 'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()})
                return stdout.decode(), stderr.decode()
        runner = MockedRunner(); commands = module.Commands(runner, self.roster, self.root)
        self.assertEqual(commands.run('mocked', [str(binary), '--version'])[0], 'actual metadata output\n')
        self.assertEqual(runner.records[0]['original_group'], 101)
        commands.count = module.MAX_COMMANDS
        with self.assertRaisesRegex(RuntimeError, 'roster/deadline'): commands.run('again', [str(binary)])

    def test_mocked_live_group_refusal_retains_raw_and_return_evidence(self):
        import types
        binary = self.root / 'brew'; binary.write_text('mocked metadata provider')
        lock = self.root / 'lock.json'; lock.write_text('{"alpha": {}}')
        driver_path = self.root / 'driver.py'; driver_path.write_text('mocked reviewed driver')
        reader_path = self.root / 'reader.py'; reader_path.write_text('mocked reader')
        class MockedLiveRunner:
            def __init__(inner, output):
                inner.output = output; inner.deadline = time.monotonic() + 150
                inner.records = []; inner.group_observations = []
                inner.writers_confirmed_retired = False
            def run(inner, label, arguments, **kwargs):
                (inner.output / (label + '.stdout.txt')).write_text('leader returned; descendant live\n')
                (inner.output / (label + '.stderr.txt')).write_text('')
                observation = {'group': 51, 'status': 'present', 'phase': 'direct_child_returned'}
                inner.group_observations.append(observation)
                inner.records.append({'label': label, 'arguments': arguments, 'pid': 51, 'exit_code': 0, 'original_group': 51, 'terminal_group_observation': observation, 'writers_confirmed_retired': False, 'stdout_sha256': None, 'stderr_sha256': None, 'refusal': 'Original owned process group is present'})
                module.dump(inner.output / 'COMMANDS.json', inner.records)
                raise RuntimeError('Original owned process group is present')
        args = types.SimpleNamespace(output=self.root / 'refusal', source_sha256=module.sha(module.__file__), python_sha256=module.sha(Path(module.sys.executable).resolve()), driver=driver_path, driver_sha256=module.sha(driver_path), linux_reader=reader_path, linux_reader_sha256=module.sha(reader_path), source_lock=lock, source_lock_sha256=module.sha(lock))
        with patch.object(module.sys, 'platform', 'linux'), patch.dict(module.os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '123'}), patch.object(module, 'load', side_effect=[types.SimpleNamespace(Runner=MockedLiveRunner), reader]), patch.object(module.shutil, 'which', return_value=str(binary)):
            self.assertEqual(module.collect(args), 2)
        result = json.loads((args.output / 'PROJECTION_RESULT.json').read_text())
        self.assertFalse(result['metadata_collection_passed'])
        self.assertFalse(result['writers_confirmed_retired'])
        self.assertEqual(result['original_group_observations'][0]['status'], 'present')
        self.assertEqual((args.output / 'brew-prefix.stdout.txt').read_text(), 'leader returned; descendant live\n')
        self.assertIsNone(json.loads((args.output / 'COMMANDS.json').read_text())[0]['stdout_sha256'])

    def test_mocked_changed_command_argv_refuses(self):
        binary = self.root / 'tool'; binary.write_text('tool')
        class MockedWrongArgv:
            records = []
            def run(inner, label, arguments, **kwargs):
                for suffix in ('stdout.txt', 'stderr.txt'): (self.root / (label + '.' + suffix)).write_bytes(b'')
                inner.records.append({'label': label, 'arguments': ['different'], 'exit_code': 0, 'pid': 61, 'original_group': 61, 'terminal_group_observation': {'group': 61, 'status': 'absent'}, 'writers_confirmed_retired': True, 'refusal': None, 'elapsed_seconds': 0.1, 'stdout_sha256': hashlib.sha256(b'').hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest()})
                return '', ''
        commands = module.Commands(MockedWrongArgv(), self.roster, self.root)
        with self.assertRaisesRegex(RuntimeError, 'label/argv'): commands.run('changed', [str(binary), '--version'])

    def test_reviewed_source_pin_refuses_changed_source(self):
        source = self.root / 'source.py'; source.write_text('reviewed source')
        digest = module.sha(source); module.pin(source, digest)
        source.write_text('changed source')
        with self.assertRaisesRegex(RuntimeError, 'mismatch'): module.pin(source, digest)

    def test_hosted_guard_preserves_refusal_artifact(self):
        class Args: output = self.root / 'result'
        with patch.dict(module.os.environ, {'GITHUB_ACTIONS': 'false'}, clear=False):
            self.assertEqual(module.collect(Args()), 2)
        result = json.loads((Args.output / 'PROJECTION_RESULT.json').read_text())
        self.assertFalse(result['execution_admitted']); self.assertEqual(result['container_jobs'], 0)
        self.assertEqual(result['state'], 'metadata-collection-refused')


    def test_regular_file_mode_change_refuses_stale_candidate(self):
        native = self.root / 'native'; native.write_text('same bytes'); native.chmod(0o600)
        physical = self.roster.add(native, required=True)
        native.chmod(0o644)
        with self.assertRaises(RuntimeError): self.roster.verify()
        self.assertEqual(self.roster.entries[physical]['mode'], 0o600)
        self.assertEqual(native.read_text(), 'same bytes')

    def test_physical_file_replaced_with_alias_refuses(self):
        native = self.root / 'native'; native.write_text('same bytes')
        self.roster.add(native, required=True)
        target = self.root / 'target'; target.write_text('same bytes')
        native.unlink(); native.symlink_to('target')
        with self.assertRaises(RuntimeError): self.roster.verify()

    def test_new_file_capacity_refuses_before_insertion_and_hash_read(self):
        native = self.root / 'native'; native.write_text('first')
        self.roster.add(native, required=True)
        extra = self.root / 'extra'; extra.write_text('second')
        original_bytes = self.roster.total_bytes
        with patch.object(module, 'MAX_FILES', 1), patch.object(self.roster, 'read_file', wraps=self.roster.read_file) as read:
            with self.assertRaises(RuntimeError): self.roster.add(extra, required=True)
            read.assert_not_called()
        self.assertEqual(len(self.roster.entries), 1)
        self.assertNotIn(str(extra), self.roster.entries)
        self.assertEqual(self.roster.total_bytes, original_bytes)

    def test_new_directory_capacity_refuses_before_insertion(self):
        first = self.root / 'first'; first.mkdir(); self.roster.add(first, required=True)
        extra = self.root / 'extra'; extra.mkdir()
        with patch.object(module, 'MAX_FILES', 1):
            with self.assertRaises(RuntimeError): self.roster.add(extra, required=True)
        self.assertEqual(len(self.roster.entries), 1)
        self.assertNotIn(str(extra), self.roster.entries)

    def test_new_alias_capacity_refuses_before_insertion(self):
        native = self.root / 'native'; native.write_text('first'); self.roster.add(native, required=True)
        extra = self.root / 'selected'; extra.symlink_to('native')
        with patch.object(module, 'MAX_FILES', 1):
            with self.assertRaises(RuntimeError): self.roster.add(extra, required=True)
        self.assertEqual(len(self.roster.entries), 1)
        self.assertNotIn(str(extra), self.roster.entries)

    def test_known_alias_at_capacity_keeps_existing_roster(self):
        native = self.root / 'native'; native.write_text('first')
        selected = self.root / 'selected'; selected.symlink_to('native')
        self.roster.add(selected, required=True)
        original = copy.deepcopy(self.roster.entries)
        with patch.object(module, 'MAX_FILES', len(original)):
            self.assertEqual(self.roster.add(selected, required=True), str(native))
            self.roster.verify()
        self.assertEqual(self.roster.entries, original)

    def test_changed_load_source_refuses_before_module_execution_and_restores(self):
        candidate = self.root / 'candidate.py'; original = 'value = 7\n'; candidate.write_text(original)
        digest = module.sha(candidate)
        self.assertEqual(module.load(candidate, digest, 'reviewed_test_candidate').value, 7)
        candidate.write_text("raise AssertionError('changed source was executed')\n")
        with self.assertRaisesRegex(RuntimeError, 'mismatch'):
            module.load(candidate, digest, 'changed_test_candidate')
        candidate.write_text(original)
        self.assertEqual(module.load(candidate, digest, 'restored_test_candidate').value, 7)

    def test_successor_source_requires_a_new_reviewed_pin(self):
        predecessor = '106bea008d99050e69710f798cee6a89cbe4e111058c5418db5cbcc3d9722826'
        self.assertNotEqual(module.sha(COLLECTOR), predecessor)
        with self.assertRaisesRegex(RuntimeError, 'mismatch'): module.pin(COLLECTOR, predecessor)
        module.pin(COLLECTOR, module.sha(COLLECTOR))


    def test_missing_final_prefix_retains_own_refusal_and_raw_command(self):
        import types
        binary = self.root / 'brew'; binary.write_text('mocked identified provider')
        lock = self.root / 'lock.json'; lock.write_text('{"alpha": {}}')
        driver_path = self.root / 'driver.py'; driver_path.write_text('mocked reviewed driver')
        reader_path = self.root / 'reader.py'; reader_path.write_text('mocked identity reader')
        missing = str(self.root / 'missing installed prefix') + '\n'
        class MockedAbsentRunner:
            def __init__(inner, output):
                inner.output = output; inner.deadline = time.monotonic() + 150
                inner.records = []; inner.group_observations = []; inner.writers_confirmed_retired = True
            def run(inner, label, arguments, **kwargs):
                stdout = missing.encode(); stderr = b''
                (inner.output / (label + '.stdout.txt')).write_bytes(stdout)
                (inner.output / (label + '.stderr.txt')).write_bytes(stderr)
                observation = {'group': 52, 'status': 'absent', 'phase': 'direct_child_returned'}
                inner.group_observations.append(observation)
                inner.records.append({'label': label, 'arguments': arguments, 'pid': 52, 'exit_code': 0,
                    'original_group': 52, 'terminal_group_observation': observation, 'writers_confirmed_retired': True,
                    'elapsed_seconds': 0.1, 'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
                    'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'refusal': None})
                module.dump(inner.output / 'COMMANDS.json', inner.records)
                return missing, ''
        args = types.SimpleNamespace(output=self.root / 'prefix-refusal', source_sha256=module.sha(module.__file__),
            python_sha256=module.sha(Path(module.sys.executable).resolve()), driver=driver_path,
            driver_sha256=module.sha(driver_path), linux_reader=reader_path, linux_reader_sha256=module.sha(reader_path),
            source_lock=lock, source_lock_sha256=module.sha(lock))
        with patch.object(module.sys, 'platform', 'linux'), patch.dict(module.os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '123'}), \
                patch.object(module, 'load', side_effect=[types.SimpleNamespace(Runner=MockedAbsentRunner), reader]), \
                patch.object(module.shutil, 'which', return_value=str(binary)):
            self.assertEqual(module.collect(args), 2)
        result = json.loads((args.output / 'PROJECTION_RESULT.json').read_text())
        self.assertFalse(result['metadata_collection_passed'])
        self.assertIn('FileNotFoundError', result['error'])
        self.assertFalse(result['execution_admitted']); self.assertFalse(result['native_manifest_accepted'])
        self.assertEqual(result['compiler_jobs'], 0); self.assertEqual(result['container_jobs'], 0)
        self.assertEqual((args.output / 'brew-prefix.stdout.txt').read_text(), missing)
        commands = json.loads((args.output / 'COMMANDS.json').read_text())
        self.assertEqual(commands[0]['terminal_group_observation']['status'], 'absent')
        self.assertEqual(commands[0]['stdout_sha256'], hashlib.sha256(missing.encode()).hexdigest())
        self.assertTrue((args.output / 'NATIVE_PATH_ROSTER.json').is_file())


if __name__ == '__main__': unittest.main()
