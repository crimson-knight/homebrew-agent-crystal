"""Authored production-function controls; execution follows producer materialization."""
from pathlib import Path
import copy
import json
import shutil
import tempfile
import unittest

import frontend_boundary as boundary


class FrontendBoundary(unittest.TestCase):
    def materialization(self):
        names = [name for profile in boundary.PROFILES for name in (profile + '.cr.txt', profile + '.json')] + ['PRODUCTION.json']
        rows = [{'path': name, 'kind': 'file', 'mode': 0o644, 'bytes': 20, 'sha256': 'a' * 64} for name in names]
        rows[-3]['sha256'] = boundary.CANONICAL
        return {'state': 'accepted_producer_products_materialized', 'producer_accepted': True,
                'producer_source_request_sha256': 'b' * 64, 'producer_qualification_sha256': 'c' * 64,
                'producer_root_release_sha256': 'd' * 64, 'profiles': list(boundary.PROFILES),
                'product_files': rows, 'canonical_cells_accepted': 0, 'producer_controls_per_mode': 12}

    def test_pending_materialization_refuses_and_actual_shape_restores(self):
        value = self.materialization()
        self.assertEqual(len(boundary.require_materialization(value)), 13)
        for field, changed in (('state', 'pending_materialization'), ('producer_accepted', False),
                               ('producer_qualification_sha256', None), ('producer_root_release_sha256', 'pending')):
            damaged = copy.deepcopy(value)
            damaged[field] = changed
            with self.assertRaisesRegex(RuntimeError, 'Actual accepted producer products'):
                boundary.require_materialization(damaged)
        self.assertEqual(len(boundary.require_materialization(value)), 13)

    def test_missing_duplicate_reordered_route_refusals_and_restoration(self):
        value = self.materialization()
        for names in (value['profiles'][:-1], value['profiles'] + [value['profiles'][0]], list(reversed(value['profiles']))):
            damaged = copy.deepcopy(value)
            damaged['profiles'] = names
            with self.assertRaisesRegex(RuntimeError, 'ordered six'):
                boundary.require_materialization(damaged)
        for rows in (value['product_files'][:-1], value['product_files'] + [value['product_files'][0]],
                     list(reversed(value['product_files']))):
            damaged = copy.deepcopy(value)
            damaged['product_files'] = rows
            with self.assertRaisesRegex(RuntimeError, 'thirteen materialized'):
                boundary.require_materialization(damaged)
        self.assertEqual(len(boundary.require_materialization(value)), 13)

    def test_product_row_kind_mode_hash_and_canonical_refusals(self):
        value = self.materialization()
        for field, changed in (('kind', 'symlink'), ('mode', 0o755), ('bytes', True), ('sha256', 'pending')):
            damaged = copy.deepcopy(value)
            damaged['product_files'][0][field] = changed
            with self.assertRaisesRegex(RuntimeError, 'materialized product bytes/modes'):
                boundary.require_materialization(damaged)
        damaged = copy.deepcopy(value)
        damaged['product_files'][-3]['sha256'] = 'e' * 64
        with self.assertRaisesRegex(RuntimeError, 'unchanged canonical'):
            boundary.require_materialization(damaged)
        self.assertEqual(len(boundary.require_materialization(value)), 13)

    def test_exact_thread_no_codegen_stats_argv_and_damaged_restored(self):
        backend, source, output = '/backend', '/grant/fixture.cr', '/grant/absent'
        argv = boundary.compiler_argv(backend, source, output)
        boundary.require_command(argv, backend, source, output)
        for changed in (argv[:argv.index('--threads')] + argv[argv.index('--threads')+2:],
                        [value for value in argv if value != '--no-codegen'],
                        [value for value in argv if value != '--error-on-warnings'], argv + ['--release']):
            with self.assertRaisesRegex(RuntimeError, 'explicit-thread semantic'):
                boundary.require_command(changed, backend, source, output)
        boundary.require_command(argv, backend, source, output)

    def test_four_parent_source_path_header_and_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            grant = Path(temporary).resolve() / 'grant'
            source = grant / 'performance/results/frontend-diagnostic/new_empty/fixture.cr'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'require "../../../../src/grant"\nrequire "../../../../src/adapter/sqlite"\nrequire "json"\n\n')
            boundary.require_source_paths(grant, source, 'new_empty')
            with self.assertRaisesRegex(RuntimeError, 'profile fixture path'):
                boundary.require_source_paths(grant, source, 'new_keywords')
            original = source.read_bytes()
            source.write_bytes(original.replace(b'../../../../src/grant', b'../../../src/grant'))
            with self.assertRaisesRegex(RuntimeError, 'require header'):
                boundary.require_source_paths(grant, source, 'new_empty')
            source.write_bytes(original)
            boundary.require_source_paths(grant, source, 'new_empty')

    def test_logical_path_kind_identity_full_row_and_restoration(self):
        rows = [{'path': 'lib/db/lib', 'kind': 'symlink', 'target': '..'},
                {'path': 'lib/db/lib', 'kind': 'directory_reference', 'target': 'lib'}]
        boundary.source_rows_equal(rows, rows)
        for changed in ([rows[0]], rows + [rows[0]], [dict(rows[0], target='../..'), rows[1]]):
            with self.assertRaisesRegex(RuntimeError, 'source identity|Unique logical'):
                boundary.source_rows_equal(rows, changed)
        boundary.source_rows_equal(rows, rows)

    def cache(self, parent):
        cache = parent / 'cache'
        cache.mkdir()
        (cache / 'data.cr').write_bytes(b'qualified source')
        (cache / 'alias.cr').symlink_to('data.cr')
        return cache

    def test_cache_byte_and_native_object_growth_refusal_restoration(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = self.cache(Path(temporary).resolve())
            before = boundary.cache_inventory(cache)
            native = cache / 'unexpected.o'
            native.write_bytes(b'\xcf\xfa\xed\xfe')
            after = boundary.cache_inventory(cache)
            with self.assertRaisesRegex(RuntimeError, 'Unexpected semantic cache'):
                boundary.require_semantic_cache(before, after)
            native.unlink()
            target = cache / 'data.cr'
            target.write_bytes(b'changed source!!')
            with self.assertRaisesRegex(RuntimeError, 'Unexpected semantic cache'):
                boundary.require_semantic_cache(before, boundary.cache_inventory(cache))
            target.write_bytes(b'qualified source')
            boundary.require_semantic_cache(before, boundary.cache_inventory(cache))

    def test_cache_link_text_mode_and_escape_refusal_restoration(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            cache = self.cache(parent)
            before = boundary.cache_inventory(cache)
            alias = cache / 'alias.cr'
            alias.unlink()
            alias.symlink_to('./data.cr')
            with self.assertRaisesRegex(RuntimeError, 'Unexpected semantic cache'):
                boundary.require_semantic_cache(before, boundary.cache_inventory(cache))
            alias.unlink()
            alias.symlink_to('../foreign.cr')
            (parent / 'foreign.cr').write_bytes(b'qualified source')
            with self.assertRaisesRegex(RuntimeError, 'escapes'):
                boundary.cache_inventory(cache)
            alias.unlink()
            alias.symlink_to('data.cr')
            mode = (cache / 'data.cr').stat().st_mode & 0o7777
            (cache / 'data.cr').chmod(0o600 if mode != 0o600 else 0o644)
            with self.assertRaisesRegex(RuntimeError, 'Unexpected semantic cache'):
                boundary.require_semantic_cache(before, boundary.cache_inventory(cache))
            (cache / 'data.cr').chmod(mode)
            boundary.require_semantic_cache(before, boundary.cache_inventory(cache))

    def test_clock_serial_categories_and_per_command_boundaries(self):
        current = [0.0]
        clock = boundary.Clock(lambda: current[0])
        with clock.phase('sdk', 15):
            current[0] = 1
        with clock.phase('compiler', 120):
            current[0] = 3
        self.assertEqual(clock.check()['counts'], {'sdk': 1, 'compiler': 1})
        with self.assertRaisesRegex(RuntimeError, 'command clock'):
            with clock.phase('compiler', 15):
                pass
        with self.assertRaisesRegex(RuntimeError, 'serialized'):
            with clock.phase('sdk', 15):
                with clock.phase('compiler', 120):
                    pass

    def test_clock_audit_aggregate_and_whole_horizon_refuse(self):
        for seconds, message in ((60, 'aggregate clocks'), (870, 'native work horizon')):
            current = [0.0]
            clock = boundary.Clock(lambda: current[0])
            current[0] = seconds
            with self.assertRaisesRegex(RuntimeError, message):
                clock.check()
        current = [0.0]
        clock = boundary.Clock(lambda: current[0])
        with self.assertRaisesRegex(RuntimeError, 'category deadline'):
            with clock.phase('sdk', 15):
                current[0] = 15
        self.assertEqual(clock.counts['sdk'], 1)

    def test_complete_projection_floor_and_typed_boundary(self):
        exact = 10 * 2**30 + boundary.COMPLETE_MINI_PROJECTION
        for value in (exact, exact - 1, True, float(exact + 1)):
            with self.assertRaisesRegex(RuntimeError, 'complete1259339776'):
                boundary.require_initial_disk(value)
        boundary.require_initial_disk(exact + 1)

    def test_actual_produced_payload_requires_materialized_gate(self):
        root = Path(__file__).resolve().parent
        marker = root / 'FRONTEND_MATERIALIZATION.json'
        self.assertTrue(marker.is_file(), 'Actual producer materialization precedes this payload control')
        value = json.loads(marker.read_bytes())
        rows = boundary.verify_products(root, value)
        self.assertEqual(len(rows), 13)
        self.assertEqual(rows[-3]['sha256'], boundary.CANONICAL)
        self.assertTrue(boundary.verify_producer_evidence(root, value)['passed'])
        with tempfile.TemporaryDirectory() as temporary:
            copy_root = Path(temporary).resolve()
            for name in ('PRODUCER_SOURCE_REQUEST.json', 'PRODUCER_QUALIFICATION.json', 'PRODUCER_ROOT_RELEASE.json'):
                shutil.copyfile(root / name, copy_root / name)
            target = copy_root / 'PRODUCER_QUALIFICATION.json'
            original = target.read_bytes()
            for damaged in ('failure', 'missing-command', 'missing-title-count', 'unrestored-source'):
                qualification = json.loads(original)
                if damaged == 'failure':
                    qualification['passed'] = False
                elif damaged == 'missing-command':
                    qualification['commands'].pop()
                elif damaged == 'missing-title-count':
                    qualification['commands'][-1]['unittest']['example_count'] = 11
                else:
                    qualification['source_inputs_unchanged'] = False
                target.write_text(json.dumps(qualification, indent=2) + '\n')
                changed = copy.deepcopy(value)
                changed['producer_qualification_sha256'] = boundary.sha(target)
                with self.subTest(damaged=damaged), self.assertRaisesRegex(RuntimeError,
                        'Accepted unchanged-source|five source-stage|unique source-control'):
                    boundary.verify_producer_evidence(copy_root, changed)
                target.write_bytes(original)
                self.assertTrue(boundary.verify_producer_evidence(copy_root, value)['passed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
