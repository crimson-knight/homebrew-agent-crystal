"""Guarded physical-fixture controls for the finite candidate ELF discovery."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
native = load('physical_elf_closure_candidate', ROOT / 'linux_native_projection.py')
reader = load('physical_elf_closure_reader', ROOT / 'linux_projection_identity.py')


class ELFClosureControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix='synthetic ELF closure with spaces ')
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()
        self.roster = native.Roster(reader.file_identity, time.monotonic() + 15)

    def binary(self, name):
        path = self.root / name
        path.write_bytes(b'\x7fELF synthetic source fixture ' + name.encode())
        return str(path)

    def alias(self, name, target):
        path = self.root / name
        path.symlink_to(Path(target).name)
        return str(path)

    def discovery(self, nodes, edges, *, final_alias=None, callback=None):
        outer = self
        class SyntheticCommands:
            def __init__(self):
                self.calls = []
            def run(self, label, argv):
                self.calls.append((label, list(argv)))
                if callback:
                    callback(label, argv)
                lines = []
                for physical in argv[4:]:
                    for soname in edges.get(physical, []):
                        lines.append('0x1 (NEEDED) Shared library: [' + soname + ']')
                return '\n'.join(lines), ''
        commands = SyntheticCommands()
        result = {}
        cache = {'libnode' + str(i) + '.so': [path] for i, path in enumerate(nodes)}
        if final_alias:
            cache['libalias.so'] = [final_alias]
        value = native.discover_elf_closure(self.roster, commands, '/synthetic/readelf',
            [nodes[0]], cache, [str(self.root)], result)
        return value, result, commands

    def chain(self, size):
        nodes = [self.binary('node' + str(i)) for i in range(size)]
        edges = {nodes[i]: ['libnode' + str(i + 1) + '.so'] for i in range(size - 1)}
        return nodes, edges

    def test_reviewed_protocol_keeps_full_horizon_and_original_caps(self):
        self.assertEqual(len(native.BASE_COMMAND_LABELS), 28)
        self.assertEqual(native.MAX_ELF_WAVES, 8)
        self.assertEqual(native.MAX_COMMANDS, 36)
        self.assertEqual(native.COMMAND_LABELS[28:], tuple('elf-wave-' + str(i) for i in range(8)))
        self.assertEqual((native.MAX_SECONDS, native.MAX_FILES), (150, 8192))
        self.assertEqual((native.MAX_HASH_BYTES, native.MAX_FILE_BYTES, native.MAX_METADATA_BYTES),
                         (2 * 1024**3, 256 * 1024**2, 32 * 1024**2))

    def test_alias_in_later_wave_keeps_lexical_identity_and_skips_same_physical(self):
        original = self.binary('physical')
        first = self.alias('first alias', original)
        later = self.alias('later alias', original)
        seen, result, identities = set(), {}, {}
        self.assertEqual(native.classify_elf_candidates(self.roster, [first], seen, result, identities), [original])
        self.assertEqual(native.classify_elf_candidates(self.roster, [later], seen, result, identities), [])
        self.assertIn(later, self.roster.entries)
        self.assertEqual(result['ELF_candidate_classifications'][-1]['physical_duplicate_of'], original)
        self.assertIn(later, self.roster.gaps())
        self.roster.verify()

    def test_original_classifier_interface_also_skips_a_previously_seen_physical_path(self):
        original = self.binary('physical')
        seen, result = set(), {}
        native.classify_elf_candidates(self.roster, [original], seen, result)
        later = self.alias('later alias', original)
        self.assertEqual(native.classify_elf_candidates(self.roster, [later], seen, result), [])

    def test_hardlink_identity_converges_across_waves(self):
        original = self.binary('physical')
        hardlink = self.root / 'hard linked provider'
        os.link(original, hardlink)
        seen, result, identities = set(), {}, {}
        self.assertEqual(native.classify_elf_candidates(self.roster, [original], seen, result, identities), [original])
        self.assertEqual(native.classify_elf_candidates(self.roster, [str(hardlink)], seen, result, identities), [])
        self.assertEqual(result['ELF_candidate_classifications'][-1]['physical_identity']['inode'], Path(original).stat().st_ino)
        self.assertIn(str(hardlink), self.roster.entries)

    def retained(self):
        physical = self.binary('physical')
        seen, result, identities = set(), {}, {}
        native.classify_elf_candidates(self.roster, [physical], seen, result, identities)
        alias = self.alias('fresh alias', physical)
        return physical, alias, seen, result, identities

    def test_same_inode_changed_bytes_refuses_and_exact_restoration_succeeds(self):
        physical, alias, seen, result, identities = self.retained()
        original = Path(physical).read_bytes()
        Path(physical).write_bytes(original[:-1] + b'X')
        with self.assertRaisesRegex(RuntimeError, 'bytes changed'):
            native.classify_elf_candidates(self.roster, [alias], seen, result, identities)
        Path(physical).write_bytes(original)
        self.assertEqual(native.classify_elf_candidates(self.roster, [alias], seen, result, identities), [])
        self.roster.verify()

    def test_changed_mode_refuses_and_exact_restoration_succeeds(self):
        physical, alias, seen, result, identities = self.retained()
        mode = Path(physical).stat().st_mode & 0o777
        Path(physical).chmod(mode ^ 0o100)
        with self.assertRaisesRegex(RuntimeError, 'regular-file kind and mode'):
            native.classify_elf_candidates(self.roster, [alias], seen, result, identities)
        Path(physical).chmod(mode)
        self.assertEqual(native.classify_elf_candidates(self.roster, [alias], seen, result, identities), [])
        self.roster.verify()

    def test_changed_inode_same_bytes_refuses(self):
        physical, alias, seen, result, identities = self.retained()
        backup = self.root / 'original inode preserved'
        Path(physical).rename(backup)
        Path(physical).write_bytes(backup.read_bytes())
        self.assertNotEqual(Path(physical).stat().st_ino, backup.stat().st_ino)
        with self.assertRaisesRegex(RuntimeError, 'inode/hash/mode identity'):
            native.classify_elf_candidates(self.roster, [alias], seen, result, identities)
        Path(physical).unlink()
        backup.rename(physical)
        self.assertEqual(native.classify_elf_candidates(self.roster, [alias], seen, result, identities), [])

    def test_same_inode_new_hardlink_changed_hash_refuses(self):
        physical, alias, seen, result, identities = self.retained()
        raw = Path(physical).read_bytes()
        Path(physical).write_bytes(raw[:-1] + b'X')
        hardlink = self.root / 'changed hardlink'
        os.link(physical, hardlink)
        with self.assertRaisesRegex(RuntimeError, 'alias identity changed'):
            native.classify_elf_candidates(self.roster, [str(hardlink)], seen, result, identities)

    def test_six_deep_waves_collect_beyond_the_original_three(self):
        nodes, edges = self.chain(6)
        value, result, commands = self.discovery(nodes, edges)
        self.assertTrue(value)
        self.assertTrue(result['ELF_closure_complete'])
        self.assertEqual(result['static_elf_waves'], 6)
        self.assertEqual(len(commands.calls), 6)
        self.assertEqual(result['unvisited_elf_candidates'], [])
        self.roster.verify()

    def test_eight_waves_and_ninth_alias_only_pass_complete_without_extra_command(self):
        nodes, edges = self.chain(8)
        alias = self.alias('new final alias', nodes[0])
        edges[nodes[-1]] = ['libalias.so']
        value, result, commands = self.discovery(nodes, edges, final_alias=alias)
        self.assertTrue(value)
        self.assertEqual(len(commands.calls), 8)
        self.assertEqual(result['ELF_candidate_waves_considered'], 9)
        self.assertTrue(result['ELF_discovery_waves'][-1]['classification_only'])
        self.assertEqual(result['ELF_discovery_waves'][-1]['requested_paths'], [alias])
        self.assertFalse(result['ELF_frontier_exhausted'])
        self.assertEqual(result['uninspected_physical_ELF_frontier'], [])
        self.assertIn(alias, self.roster.entries)

    def test_ninth_genuine_physical_frontier_is_retained_and_incomplete(self):
        nodes, edges = self.chain(9)
        value, result, commands = self.discovery(nodes, edges)
        self.assertFalse(value)
        self.assertEqual(len(commands.calls), 8)
        self.assertTrue(result['ELF_frontier_exhausted'])
        self.assertEqual(result['unvisited_elf_candidates'], [nodes[-1]])
        self.assertEqual(result['uninspected_physical_ELF_frontier'], [nodes[-1]])
        self.assertIn(nodes[-1], self.roster.entries)
        self.assertEqual(result['ELF_discovery_waves'][-1]['physical_readelf_inputs'], [nodes[-1]])
        self.roster.verify()

    def test_unresolved_soname_is_retained_as_incomplete(self):
        nodes, edges = self.chain(1)
        edges[nodes[0]] = ['libMissing.so.9']
        value, result, commands = self.discovery(nodes, edges)
        self.assertFalse(value)
        self.assertEqual(result['unresolved_needed'], ['libMissing.so.9'])
        self.assertFalse(result['ELF_frontier_exhausted'])
        self.assertEqual(result['ELF_discovery_waves'][0]['dependencies'],
                         [{'soname': 'libMissing.so.9', 'candidate_paths': []}])

    def test_cycle_converges_without_a_duplicate_command(self):
        nodes, edges = self.chain(2)
        edges[nodes[-1]] = ['libnode0.so']
        value, result, commands = self.discovery(nodes, edges)
        self.assertTrue(value)
        self.assertEqual(len(commands.calls), 2)

    def test_unwritten_FIFO_refuses_before_readelf_and_preserves_frontier(self):
        fifo = self.root / 'special node'
        os.mkfifo(fifo)
        commands = types.SimpleNamespace(run=mock.Mock(side_effect=AssertionError('unexpected command')))
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'ordinary files, directories, or aliases'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', [str(fifo)], {}, [], result)
        commands.run.assert_not_called()
        self.assertEqual(result['unvisited_elf_candidates'], [str(fifo)])
        self.assertFalse(result['ELF_closure_complete'])

    def test_missing_frontier_refuses_and_keeps_completed_wave(self):
        nodes, edges = self.chain(1)
        missing = str(self.root / 'absent dependency')
        commands = types.SimpleNamespace(run=mock.Mock(return_value=('0x1 (NEEDED) Shared library: [libAbsent.so]', '')))
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'Required native path is absent'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', nodes,
                                       {'libAbsent.so': [missing]}, [], result)
        self.assertEqual(result['static_elf_waves'], 1)
        self.assertEqual(result['unvisited_elf_candidates'], [missing])

    def test_retained_timeout_keeps_uncompleted_physical_command_inputs(self):
        nodes, edges = self.chain(1)
        commands = types.SimpleNamespace(run=mock.Mock(side_effect=RuntimeError('synthetic retained timeout')))
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'retained timeout'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', nodes, {}, [], result)
        self.assertEqual(result['unvisited_elf_candidates'], nodes)
        self.assertEqual(result['uninspected_physical_ELF_frontier'], nodes)
        self.assertEqual(result['static_elf_waves'], 0)
        self.assertFalse(result['ELF_discovery_waves'][0]['readelf_completed'])

    def test_expired_total_deadline_refuses_before_any_command(self):
        nodes, edges = self.chain(1)
        commands = types.SimpleNamespace(run=mock.Mock(side_effect=AssertionError('unexpected command')))
        self.roster.deadline = time.monotonic() - 1
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'total deadline'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', nodes, {}, [], result)
        commands.run.assert_not_called()
        self.assertEqual(result['static_elf_waves'], 0)
        self.assertEqual(result['unvisited_elf_candidates'], nodes)

    def test_invalid_soname_keeps_completed_raw_wave_scope(self):
        nodes, edges = self.chain(1)
        commands = types.SimpleNamespace(run=mock.Mock(return_value=('0x1 (NEEDED) Shared library: [../bad.so]', '')))
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'simple soname'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', nodes, {}, [], result)
        self.assertEqual(result['static_elf_waves'], 1)
        self.assertTrue(result['ELF_discovery_waves'][0]['readelf_completed'])
        self.assertFalse(result['ELF_closure_complete'])

    def test_command_protocol_refuses_a_changed_label_before_runner(self):
        runner = types.SimpleNamespace(run=mock.Mock(), records=[])
        commands = native.Commands(runner, self.roster, self.root, expected_labels=native.COMMAND_LABELS)
        with self.assertRaisesRegex(RuntimeError, 'sequence differs'):
            commands.run('brew-root', ['/synthetic/provider'])
        runner.run.assert_not_called()
        self.assertEqual(commands.count, 0)

    def test_command_protocol_preserves_each_original_deadline(self):
        runner = types.SimpleNamespace(run=mock.Mock(), records=[])
        commands = native.Commands(runner, self.roster, self.root, expected_labels=native.COMMAND_LABELS)
        with self.assertRaisesRegex(RuntimeError, 'per-command deadline'):
            commands.run('brew-prefix', ['/synthetic/provider'], seconds=45)
        commands.count = 3
        with self.assertRaisesRegex(RuntimeError, 'per-command deadline'):
            commands.run('runtime-dependency-metadata', ['/synthetic/provider'], seconds=30)
        runner.run.assert_not_called()

    def test_command_protocol_refuses_a_ninth_readelf_label(self):
        runner = types.SimpleNamespace(run=mock.Mock(), records=[])
        commands = native.Commands(runner, self.roster, self.root, expected_labels=native.COMMAND_LABELS)
        commands.count = 36
        with self.assertRaisesRegex(RuntimeError, 'roster/deadline'):
            commands.run('elf-wave-8', ['/synthetic/provider'])
        runner.run.assert_not_called()

    def test_complete_terminal_deadline_is_observed_on_a_failed_return(self):
        result_path = self.root / 'terminal horizon refusal'
        args = types.SimpleNamespace(output=result_path)
        with mock.patch.dict(native.os.environ, {'GITHUB_ACTIONS': 'false'}), \
                mock.patch.object(native.time, 'monotonic', side_effect=[1, 152]):
            self.assertEqual(native.collect(args), 2)
        result = json.loads((result_path / 'PROJECTION_RESULT.json').read_text())
        self.assertEqual(result['terminal_elapsed_seconds'], 151)
        self.assertIn('Complete metadata terminal time budget exceeded', result['finalization_errors'])
        self.assertFalse(result['execution_admitted'])
        self.assertFalse(result['native_manifest_accepted'])

    def test_final_source_change_retains_original_failure_and_exact_restoration(self):
        driver_path = self.root / 'driver.py'
        driver_path.write_bytes(b'modeled immutable Runner source')
        original = driver_path.read_bytes()
        reader_path = self.root / 'reader.py'
        reader_path.write_bytes(b'modeled immutable reader source')
        lock = self.root / 'lock.json'
        lock.write_text('{"alpha":{}}')
        tool = self.root / 'brew'
        tool.write_bytes(b'modeled identified metadata provider')
        missing = str(self.root / 'missing installed prefix') + '\n'
        class SyntheticRunner:
            def __init__(inner, output):
                inner.output = output
                inner.deadline = time.monotonic() + 150
                inner.records = []
                inner.group_observations = []
                inner.writers_confirmed_retired = True
            def run(inner, label, argv, **options):
                raw = missing.encode()
                (inner.output / (label + '.stdout.txt')).write_bytes(raw)
                (inner.output / (label + '.stderr.txt')).write_bytes(b'')
                observation = {'group': 71, 'status': 'absent'}
                inner.group_observations.append(observation)
                inner.records.append({'label': label, 'arguments': [str(v) for v in argv],
                    'pid': 71, 'original_group': 71, 'exit_code': 0,
                    'terminal_group_observation': observation, 'writers_confirmed_retired': True,
                    'refusal': None, 'elapsed_seconds': .1, 'stdout_sha256': hashlib.sha256(raw).hexdigest(),
                    'stderr_sha256': hashlib.sha256(b'').hexdigest()})
                driver_path.write_bytes(original + b' changed during command')
                return missing, ''
        args = types.SimpleNamespace(output=self.root / 'source failure',
            source_sha256=native.sha(native.__file__), python_sha256=native.sha(Path(native.sys.executable).resolve()),
            driver=driver_path, driver_sha256=native.sha(driver_path), linux_reader=reader_path,
            linux_reader_sha256=native.sha(reader_path), source_lock=lock, source_lock_sha256=native.sha(lock))
        try:
            with mock.patch.object(native.sys, 'platform', 'linux'), \
                    mock.patch.dict(native.os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '123'}), \
                    mock.patch.object(native, 'load', side_effect=[types.SimpleNamespace(Runner=SyntheticRunner), reader]), \
                    mock.patch.object(native.shutil, 'which', return_value=str(tool)):
                self.assertEqual(native.collect(args), 2)
            result = json.loads((args.output / 'PROJECTION_RESULT.json').read_text())
            self.assertIn('FileNotFoundError', result['error'])
            self.assertTrue(any('Final driver:' in error for error in result['finalization_errors']))
            self.assertTrue(result['writers_confirmed_retired'])
            self.assertEqual((args.output / 'brew-prefix.stdout.txt').read_text(), missing)
        finally:
            driver_path.write_bytes(original)
        native.pin(driver_path, args.driver_sha256)

    def test_final_physical_return_refuses_replaced_inode_and_exact_restoration(self):
        physical, alias, seen, result, identities = self.retained()
        native.verify_elf_physical_identities(self.roster, result)
        self.assertTrue(result['ELF_physical_identities_verified_on_return'])
        before = Path(physical).stat()
        backup = self.root / 'original inode for terminal restoration'
        Path(physical).rename(backup)
        Path(physical).write_bytes(backup.read_bytes())
        Path(physical).chmod(before.st_mode & 0o777)
        try:
            self.assertNotEqual(Path(physical).stat().st_ino, before.st_ino)
            with self.assertRaisesRegex(RuntimeError, 'physical provider identity changed on final return'):
                native.verify_elf_physical_identities(self.roster, result)
            self.assertFalse(result['ELF_physical_identities_verified_on_return'])
            self.assertFalse(result['ELF_physical_return_observations'][0]['verified'])
        finally:
            Path(physical).unlink()
            backup.rename(physical)
        native.verify_elf_physical_identities(self.roster, result)
        self.assertTrue(result['ELF_physical_identities_verified_on_return'])
        self.assertTrue(all(row['verified'] for row in result['ELF_physical_return_observations']))
        self.roster.verify()

    def test_missing_interpreter_retains_unresolved_frontier_and_restored_control(self):
        physical = self.binary('main ELF fixture')
        interpreter = self.root / 'required interpreter with spaces'
        text = '[Requesting program interpreter: ' + str(interpreter) + ']\n'
        commands = types.SimpleNamespace(run=mock.Mock(return_value=(text, '')))
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'Required native path is absent'):
            native.discover_elf_closure(self.roster, commands, '/synthetic/readelf', [physical], {}, [], result)
        self.assertFalse(result['ELF_closure_complete'])
        self.assertEqual(result['unresolved_interpreters'], [str(interpreter)])
        self.assertEqual(result['unvisited_elf_candidates'], [str(interpreter)])
        self.assertEqual(result['ELF_discovery_waves'][0]['program_interpreters'],
                         [{'path': str(interpreter), 'present': False}])
        self.assertEqual(commands.run.call_count, 1)
        interpreter.write_bytes(b'\x7fELF restored synthetic interpreter')
        roster = native.Roster(reader.file_identity, time.monotonic() + 15)
        def restored_metadata(label, argv):
            return (text if physical in argv[4:] else ''), ''
        restored = types.SimpleNamespace(run=mock.Mock(side_effect=restored_metadata))
        restored_result = {}
        self.assertTrue(native.discover_elf_closure(roster, restored, '/synthetic/readelf', [physical], {}, [], restored_result))
        self.assertEqual(restored_result['unresolved_interpreters'], [])
        self.assertEqual(restored.run.call_count, 2)
        native.verify_elf_physical_identities(roster, restored_result)
        self.assertTrue(restored_result['ELF_physical_identities_verified_on_return'])
        roster.verify()


if __name__ == '__main__':
    unittest.main()
