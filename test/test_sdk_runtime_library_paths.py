"""Source-only runtime-manifest and cryptographic-consumer behavior controls."""
import copy
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location('runtime_path_sdk_source', Path(__file__).with_name('sdk_install_qualification.py'))
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class RuntimePathControls(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary).resolve()
        prefix = root / 'Cellar/agent-crystal/1.21.0-incremental-1_2'
        (root / 'lib').mkdir(); (root / 'opt').mkdir()
        prefix.mkdir(parents=True)
        rows = []
        graph = {'agent-crystal': ['libevent', 'openssl@3', 'pkgconf'], 'libevent': ['openssl@4'],
                 'openssl@3': ['ca-certificates'], 'openssl@4': ['ca-certificates'],
                 'pkgconf': [], 'ca-certificates': [], 'libffi': []}
        for name, dependencies in graph.items():
            version = '1.21.0-incremental-1_2' if name == 'agent-crystal' else '1.0_1'
            directory = root / 'Cellar' / name / version
            directory.mkdir(parents=True, exist_ok=True)
            (directory / '.brew').mkdir()
            (directory / 'INSTALL_RECEIPT.json').write_text('{"fixture":true}')
            (directory / '.brew' / (name + '.rb')).write_text('# synthetic formula\n')
            (root / 'opt' / name).symlink_to('../Cellar/' + name + '/' + version)
            if name not in ('agent-crystal', 'ca-certificates'):
                (directory / 'lib').mkdir()
            rows.append(dict(name=name, dependencies=dependencies, installed=[dict(version=version, used_options=[])],
                             optional_dependencies=[], recommended_dependencies=[], build_dependencies=['m4'],
                             uses_from_macos=['libffi'] if name == 'agent-crystal' else []))
        paths = sorted([str(root / 'lib')] + [str(root / 'opt' / name / 'lib') for name in graph if name not in ('agent-crystal', 'ca-certificates')])
        manifest = prefix / 'share/agent-crystal/runtime_library_paths.txt'
        manifest.parent.mkdir(parents=True); manifest.write_text('\n'.join(paths) + '\n')
        return root, prefix, dict(formulae=rows), manifest, paths

    def test_physical_manifest_derives_recursive_ssl3_ssl4_and_linux_libffi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            value = SDK.runtime_dependency_identity(metadata, prefix, root)
            self.assertEqual(value['library_paths'], paths)
            self.assertEqual([row['name'] for row in value['dependencies']], ['ca-certificates', 'libevent', 'libffi', 'openssl@3', 'openssl@4', 'pkgconf'])
            SDK.verify_runtime_dependency_identity(value)

    def test_modified_manifest_missing_extra_reordered_or_duplicate_paths_refuse(self):
        for mutation in (lambda rows: rows[:-1], lambda rows: rows + ['/external/lib'], lambda rows: list(reversed(rows)), lambda rows: rows + [rows[0]]):
            with tempfile.TemporaryDirectory() as temporary:
                root, prefix, metadata, manifest, paths = self.fixture(temporary)
                manifest.write_text('\n'.join(mutation(paths)) + '\n')
                with self.assertRaisesRegex(SDK.QualificationError, 'independently derived'):
                    SDK.runtime_dependency_identity(metadata, prefix, root)

    def test_current_receipt_formula_alias_and_library_presence_are_revalidated(self):
        for part in ('receipt', 'formula', 'alias', 'library', 'manifest'):
            with tempfile.TemporaryDirectory() as temporary:
                root, prefix, metadata, manifest, paths = self.fixture(temporary)
                value = SDK.runtime_dependency_identity(metadata, prefix, root)
                row = next(row for row in value['dependencies'] if row['name'] == 'libevent')
                if part in ('receipt', 'formula'):
                    path = Path(row['identities'][0 if part == 'receipt' else 1]['path']); path.write_text('changed')
                elif part == 'alias':
                    path = root / 'opt/libevent'; path.unlink(); path.symlink_to('../Cellar/openssl@3/1.0_1')
                elif part == 'library':
                    Path(row['opt_library']).rmdir()
                else:
                    manifest.write_text('changed')
                with self.assertRaises(SDK.QualificationError):
                    SDK.verify_runtime_dependency_identity(value)

    def test_contained_library_replaced_with_external_directory_alias_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            value = SDK.runtime_dependency_identity(metadata, prefix, root)
            library = root / 'opt/libevent/lib'; library.rmdir()
            outside = root / 'external-library'; outside.mkdir()
            library.symlink_to(outside)
            with self.assertRaisesRegex(SDK.QualificationError, 'escaped'):
                SDK.verify_runtime_dependency_identity(value)

    def test_mandatory_prefix_library_alias_and_resolved_identity_are_revalidated(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as external:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            value = SDK.runtime_dependency_identity(metadata, prefix, root)
            (root / 'lib').rmdir(); (root / 'lib').symlink_to(Path(external).resolve())
            with self.assertRaisesRegex(SDK.QualificationError, 'escaped'):
                SDK.verify_runtime_dependency_identity(value)

    def test_public_alias_lexical_target_and_physical_wrapper_are_revalidated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); physical = root / 'Cellar/bin/crystal-alpha'; physical.parent.mkdir(parents=True)
            physical.write_bytes(b'synthetic ordinary wrapper')
            public = root / 'bin/crystal-alpha'; public.parent.mkdir(); public.symlink_to('../Cellar/bin/crystal-alpha')
            value = SDK.installed_alias_identity(public, physical)
            SDK.verify_installed_alias_identity(value)
            public.unlink(); public.symlink_to(physical)
            with self.assertRaisesRegex(SDK.QualificationError, 'resolution'):
                SDK.verify_installed_alias_identity(value)

    def test_missing_cycle_duplicate_ambiguous_version_and_path_injection_refuse(self):
        for kind in ('missing', 'cycle', 'duplicate', 'ambiguous', 'version', 'name'):
            with tempfile.TemporaryDirectory() as temporary:
                root, prefix, metadata, manifest, paths = self.fixture(temporary)
                if kind == 'missing': metadata['formulae'] = [row for row in metadata['formulae'] if row['name'] != 'libevent']
                elif kind == 'cycle': metadata['formulae'][1]['dependencies'].append('agent-crystal')
                elif kind == 'duplicate': metadata['formulae'].append(metadata['formulae'][0])
                elif kind == 'ambiguous': metadata['formulae'][1]['installed'].append(dict(version='2', used_options=[]))
                elif kind == 'version': metadata['formulae'][1]['installed'][0]['version'] = '../outside'
                else: metadata['formulae'][1]['name'] = 'path:injection'
                with self.assertRaises(SDK.QualificationError):
                    SDK.derive_runtime_dependencies(metadata, root)

    def test_fresh_root_metadata_version_must_match_the_actual_package_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            metadata['formulae'][0]['installed'][0]['version'] = '0.0.1'
            with self.assertRaisesRegex(SDK.QualificationError, 'Fresh Alpha root metadata'):
                SDK.runtime_dependency_identity(metadata, prefix, root)

    def test_build_only_uses_from_macos_and_unselected_optional_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            metadata['formulae'][0]['uses_from_macos'].append(dict(m4='build'))
            metadata['formulae'][0]['optional_dependencies'] = ['optional-uninstalled']
            metadata['formulae'][0]['recommended_dependencies'] = ['recommended-disabled']
            metadata['formulae'][0]['installed'][0]['used_options'] = ['--without-recommended-disabled']
            value = SDK.runtime_dependency_identity(metadata, prefix, root)
            self.assertEqual(value['library_paths'], paths)
            metadata['formulae'][0]['installed'][0]['used_options'].append('--with-optional-uninstalled')
            with self.assertRaises(SDK.QualificationError):
                SDK.derive_runtime_dependencies(metadata, root)

    def test_all_three_aliases_require_the_identical_derived_static_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            value = SDK.runtime_dependency_identity(metadata, prefix, root)
            compiler, stdlib = prefix / 'libexec/agent-crystal-bin', prefix / 'share/agent-crystal/src'
            wrapper = '#!/bin/bash\nCRYSTAL_PATH="lib:' + str(stdlib) + '" LD_RUN_PATH="${LD_RUN_PATH:+${LD_RUN_PATH}:}' + ':'.join(paths) + '" exec "' + str(compiler) + '"  "$@"\n'
            for alias in ('acrystal', 'agent-crystal', 'crystal-alpha'):
                SDK.verify_wrapper(wrapper, compiler, stdlib, root, 'Linux', lambda: value)
                with self.assertRaises(SDK.QualificationError):
                    SDK.verify_wrapper(wrapper.replace(':'.join(paths), str(root / 'lib')), compiler, stdlib, root, 'Linux', value)

    def test_metadata_collection_uses_original_runner_with_45_second_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            calls = []
            class Runner:
                def run(self, label, argv, **settings):
                    calls.append((label, argv, settings)); return json.dumps(metadata), ''
            value = SDK.collect_runtime_dependency_identity(Runner(), '/ordinary/brew', prefix, root, root, root)
            self.assertEqual(value['library_paths'], paths)
            self.assertEqual(calls[0][1], ['/ordinary/brew', 'info', '--json=v2', '--installed'])
            self.assertEqual(calls[0][2]['seconds'], 45)
            self.assertEqual(json.loads((root / 'RUNTIME_LIBRARY_PATHS.json').read_text()), value)

    def test_qualified_revision2_linux_wrapper_refuses_absent_runtime_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            compiler, stdlib = prefix / 'libexec/agent-crystal-bin', prefix / 'share/agent-crystal/src'
            wrapper = '#!/bin/bash\nCRYSTAL_PATH="lib:' + str(stdlib) + '" LD_RUN_PATH="${LD_RUN_PATH:+${LD_RUN_PATH}:}' + str(root / 'lib') + '" exec "' + str(compiler) + '"  "$@"\n'
            for context in (None, lambda: None):
                with self.assertRaisesRegex(SDK.QualificationError, 'Qualified revision2'):
                    SDK.verify_wrapper(wrapper, compiler, stdlib, root, 'Linux', context)

    def test_original_sdk_deadline_and_new16_command_ceiling_refuse_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(SDK.time, 'monotonic', return_value=100.0):
                runner = SDK.make_readiness_runner(root)
            self.assertEqual(runner.deadline, 940.0)
            runner.maximum_command_count = 16
            runner.records = [{} for _ in range(16)]
            with mock.patch.object(SDK.subprocess, 'Popen', side_effect=AssertionError('source-only process guard')) as launch:
                with self.assertRaisesRegex(SDK.QualificationError, 'command roster'):
                    runner.run('seventeenth', ['ordinary-command'], cwd=root)
                launch.assert_not_called()
                runner.records = []
                with mock.patch.object(SDK.time, 'monotonic', return_value=940.0), self.assertRaisesRegex(SDK.QualificationError, 'complete time budget'):
                    runner.run('expired', ['ordinary-command'], cwd=root)
                launch.assert_not_called()

    def consumer(self, failure=False, mutate_provider=False, live_writer=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); private = root / 'private'; private.mkdir(); output = root / 'output'; output.mkdir()
            readelf = root / 'readelf'; readelf.write_bytes(b'synthetic metadata provider')
            calls = []
            class Runner:
                writers_confirmed_retired = True
                def run(self, label, argv, **settings):
                    calls.append((label, settings['seconds']))
                    if label == 'crypto-consumer-build':
                        Path(argv[-1]).write_bytes(b'\x7fELFsynthetic')
                    if label == 'crypto-consumer-runtime':
                        if live_writer: self.writers_confirmed_retired = False
                        if failure: raise SDK.QualificationError('synthetic original loader failure')
                        if mutate_provider: readelf.write_bytes(b'changed provider')
                        return SDK.CRYPTO_EXPECTED, ''
                    return '', ''
            with mock.patch.object(SDK.shutil, 'which', return_value=str(readelf)):
                if failure or mutate_provider or live_writer:
                    with self.assertRaises(SDK.QualificationError):
                        SDK.exercise_crypto_consumer(Runner(), root / 'crystal-alpha', private, output, {})
                else:
                    SDK.exercise_crypto_consumer(Runner(), root / 'crystal-alpha', private, output, {})
            value = json.loads((output / 'CRYPTO_CONSUMER.json').read_text())
            if live_writer:
                self.assertFalse((output / 'CRYPTO_CONSUMER.bin').exists())
            else:
                self.assertEqual(hashlib.sha256((output / 'CRYPTO_CONSUMER.bin').read_bytes()).hexdigest(), value['retained_binary']['sha256'])
            return value, calls

    def test_mocked_ordinary_crypto_format_build_elf_and_runtime_are_bounded(self):
        value, calls = self.consumer()
        self.assertTrue(value['passed'])
        self.assertEqual(calls, [('crypto-consumer-format', 15), ('crypto-consumer-build', 120), ('crypto-consumer-elf', 10), ('crypto-consumer-runtime', 10)])

    def test_mocked_original_crypto_loader_failure_retains_exact_binary_and_error(self):
        value, calls = self.consumer(failure=True)
        self.assertFalse(value['passed'])
        self.assertIn('synthetic original loader failure', value['error'])

    def test_mocked_crypto_metadata_provider_change_refuses(self):
        value, calls = self.consumer(mutate_provider=True)
        self.assertFalse(value['passed'])
        self.assertIn('changed', value['error'])

    def test_unconfirmed_crypto_writer_retains_original_and_retention_refusal(self):
        value, calls = self.consumer(failure=True, live_writer=True)
        self.assertFalse(value['passed'])
        self.assertIn('synthetic original loader failure', value['error'])
        self.assertIn('confirmed original writer retirement', value['retention_error'])
        self.assertNotIn('retained_binary', value)

    def test_failed_spec_binary_retention_requires_confirmed_group_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); private = root / 'private'; output = root / 'output'; output.mkdir()
            binary = private / 'default-specs/cache/crystal-run-spec.tmp'; binary.parent.mkdir(parents=True)
            binary.write_bytes(b'\x7fELFsynthetic failed spec')
            self.assertEqual(SDK.retain_failed_spec_binaries(private, output, False)['retained'], [])
            value = SDK.retain_failed_spec_binaries(private, output, True)
            self.assertEqual(len(value['retained']), 1)
            self.assertEqual((output / value['retained'][0]['path']).read_bytes(), binary.read_bytes())

    def test_failed_spec_alias_and_oversize_binary_retention_refuse(self):
        for alias in (True, False):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); private = root / 'private'; output = root / 'output'; output.mkdir()
                binary = private / 'default-specs/cache/crystal-run-spec.tmp'; binary.parent.mkdir(parents=True)
                if alias:
                    target = root / 'outside'; target.write_bytes(b'synthetic ELF'); binary.symlink_to(target)
                else:
                    with binary.open('wb') as stream: stream.truncate(20 * 2**20 + 1)
                with self.assertRaises(SDK.QualificationError):
                    SDK.retain_failed_spec_binaries(private, output, True)

    def test_mocked_failed_qualification_revalidates_package_manifest_and_public_alias(self):
        """The exact qualifier runs with synthetic providers and zero subprocesses."""
        with tempfile.TemporaryDirectory() as temporary:
            root, prefix, metadata, manifest, paths = self.fixture(temporary)
            output = root / 'output'; private = root / 'private'; private.mkdir()
            lock = json.loads(Path(SDK.__file__).with_name('sdk_source_lock.json').read_text())
            formula = Path(SDK.__file__).parent.parent / 'Formula/agent-crystal.rb'
            (prefix / '.brew/agent-crystal.rb').write_bytes(formula.read_bytes())
            alpha = metadata['formulae'][0]
            alpha.update(versions=dict(stable=lock['alpha']['source_version']), revision=2,
                         urls=dict(stable=dict(checksum=lock['alpha']['source_archive_sha256'])))
            alpha['installed'][0].update(version=lock['alpha']['installed_package_version'], poured_from_bottle=False)
            compiler = prefix / 'libexec/agent-crystal-bin'; compiler.parent.mkdir(); compiler.write_bytes(b'synthetic compiler')
            (prefix / 'bin').mkdir(); (root / 'bin').mkdir()
            stdlib = prefix / 'share/agent-crystal/src'; stdlib.mkdir()
            wrapper = '#!/bin/bash\nCRYSTAL_PATH="lib:' + str(stdlib) + '" LD_RUN_PATH="${LD_RUN_PATH:+${LD_RUN_PATH}:}' + ':'.join(paths) + '" exec "' + str(compiler) + '"  "$@"\n'
            mapping = {}
            for alias in ('acrystal', 'agent-crystal', 'crystal-alpha'):
                actual = prefix / 'bin' / alias; actual.write_text(wrapper)
                public = root / 'bin' / alias; public.symlink_to(actual)
                mapping[alias] = str(public)
            for tool in ('brew', 'ruby'):
                actual = root / 'bin' / tool; actual.write_bytes(b'synthetic provider'); mapping[tool] = str(actual)
            class Runner:
                def __init__(self, destination):
                    self.records, self.group_observations = [], []
                    self.writers_confirmed_retired = True
                    self.deadline = SDK.time.monotonic() + 840
                def run(self, label, argv, **settings):
                    self.records.append(dict(label=label, synthetic=True))
                    self.group_observations.append(dict(status='absent', synthetic=True))
                    text = ''
                    if label == 'brew-prefix': text = str(prefix) + '\n'
                    elif label == 'brew-root': text = str(root) + '\n'
                    elif label == 'brew-receipt': text = json.dumps(dict(formulae=[alpha]))
                    elif label == 'runtime-dependency-metadata': text = json.dumps(metadata)
                    elif label == 'alpha-version': text = lock['alpha']['full_versions']['Linux']
                    elif label == 'ruby-identity': text = json.dumps(dict(path=mapping['ruby'], version='synthetic Ruby'))
                    elif label == 'install-bundle':
                        (prefix / '.brew/agent-crystal.rb').write_text('synthetic changed installed formula')
                        manifest.write_text('synthetic changed manifest')
                        alias = root / 'bin/acrystal'; alias.unlink(); alias.symlink_to('../Cellar/agent-crystal/' + prefix.name + '/bin/acrystal')
                        raise SDK.QualificationError('synthetic original consumer failure')
                    return text, ''
            with mock.patch.object(SDK, 'Runner', Runner), mock.patch.object(SDK.platform, 'system', return_value='Linux'), mock.patch.object(SDK.shutil, 'which', side_effect=lambda tool: mapping.get(tool)), mock.patch.object(SDK.shutil, 'disk_usage', return_value=SimpleNamespace(free=100 * 2**30)), mock.patch.object(SDK.tempfile, 'mkdtemp', return_value=str(private)), mock.patch.object(SDK.urllib.request, 'urlopen', return_value=io.BytesIO(b'synthetic source archive')), mock.patch.object(SDK, 'extract_sdk'), mock.patch.object(SDK, 'verify_source'), mock.patch.object(SDK, 'tree_identity', return_value=dict(synthetic=True)), mock.patch.object(SDK, 'verify_stdlib'):
                self.assertEqual(SDK.qualify(output, lock), 1)
            result = json.loads((output / 'READINESS_RESULT.json').read_text())
            self.assertIn('synthetic original consumer failure', result['error'])
            self.assertTrue(any(value.startswith('Package ') for value in result['finalization_errors']))
            self.assertTrue(any(value.startswith('Runtime identity:') for value in result['finalization_errors']))
            self.assertTrue(any(value.startswith('Alias ') for value in result['finalization_errors']))
            self.assertTrue(result['private_cache_removed'])
            self.assertEqual(result['maximum_command_count'], 16)
            self.assertEqual(result['maximum_seconds'], 840)
