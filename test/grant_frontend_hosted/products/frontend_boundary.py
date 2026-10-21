"""Source-bound route, argv, inventory, and clock contracts for semantic diagnostics."""
from pathlib import Path
import contextlib
import hashlib
import json
import os
import re
import stat
import time

PROFILES = ('library_floor', 'declarations', 'new_empty', 'new_keywords', 'new_broad_hash', 'canonical_create')
COMMIT = 'd78418566d90e61d6876a4a2a8abd93bb74f1ba1'
SOURCE = 'edeb868d76119f67dacdd829a0113ba0b0637583f0ee2fcbd87078a6cbee9d8a'
CANONICAL = 'a2fc694a59408b369fd96a9f62245879102287ace178a5de4d261bdd488b92c3'
BACKEND = '7809e9cd9174a651818bcba5e6206f038089716d72746f5e425a2c1829943dfe'
PROFILE_PIN = '4d2acc5fa95190379a838b5c9dd5ab6f666656daa8861df766de37266ecde629'
NATIVE_PIN = 'ec68eb431dbb86efb55edf48feb9865d8d83c6efaa96af089ee3d49dc922cae7'
GIT_PIN = 'e356a4561e9b0e10ba2d5f954183d2577303c90243cd15dab21e0f77dd07d531'
COMPLETE_MINI_PROJECTION = 1259339776
JOB_ROOT_LIMIT = 2**30
CACHE_LIMIT = 64 * 2**20


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def is_sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def source_rows_equal(expected, observed):
    def keyed(rows):
        value = {(row['path'], row['kind']): row for row in rows}
        need(len(value) == len(rows), 'Unique logical path/kind source rows required')
        return value
    need(keyed(expected) == keyed(observed), 'Full logical path/kind source identity differs')


def require_materialization(value):
    need(value.get('state') == 'accepted_producer_products_materialized'
         and value.get('producer_accepted') is True
         and is_sha(value.get('producer_source_request_sha256'))
         and is_sha(value.get('producer_qualification_sha256'))
         and is_sha(value.get('producer_root_release_sha256')),
         'Actual accepted producer products and terminal/release authorities required')
    need(value.get('profiles') == list(PROFILES), 'Exact ordered six materialized routes required')
    rows = value.get('product_files')
    names = [name for profile in PROFILES for name in (profile + '.cr.txt', profile + '.json')] + ['PRODUCTION.json']
    need(type(rows) is list and [row.get('path') for row in rows] == names,
         'Exact thirteen materialized product rows required')
    for row in rows:
        need(set(row) == {'path', 'kind', 'mode', 'bytes', 'sha256'} and row['kind'] == 'file'
             and type(row['mode']) is int and row['mode'] == 0o644
             and type(row['bytes']) is int and 0 <= row['bytes'] < 2**20 and is_sha(row['sha256']),
             'Exact bounded materialized product bytes/modes required')
    need(rows[-3]['path'] == 'canonical_create.cr.txt' and rows[-3]['sha256'] == CANONICAL,
         'Exact unchanged canonical rich source required')
    need(value.get('canonical_cells_accepted') == 0 and value.get('producer_controls_per_mode') == 12,
         'Producer scope and complete original twelve controls required')
    return rows


def verify_products(payload, materialized):
    rows = require_materialization(materialized)
    payload = Path(payload)
    for row in rows:
        path = payload / row['path']
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes']
             and stat.S_IMODE(path.stat().st_mode) == row['mode'] and sha(path) == row['sha256'],
             'Exact accepted product payload differs: ' + row['path'])
    production = json.loads((payload / 'PRODUCTION.json').read_bytes())
    need(production['profiles'] == list(PROFILES) and production['files'] == rows[:-1]
         and production['compiler_jobs'] == production['runtime_jobs'] == 0,
         'Complete original production manifest differs')
    need(production['verification']['passed'] is True
         and production['verification']['canonical_source_sha256'] == CANONICAL,
         'Accepted source projection authority differs')
    for profile in PROFILES:
        metadata = json.loads((payload / (profile + '.json')).read_bytes())
        source = payload / (profile + '.cr.txt')
        need(metadata['profile'] == profile and metadata['source_sha256'] == sha(source)
             and metadata['seed_sha256'] == CANONICAL and metadata['semantic_only'] is True
             and metadata['model_count'] == (0 if profile == 'library_floor' else 2),
             'Source-bound profile/seed/model metadata differs')
        if profile != 'library_floor':
            need(metadata['declared_counts']['columns'] == 32
                 and metadata['declared_counts']['named_scope_macros'] == 2
                 and metadata['declared_counts']['association_macros'] == 4,
                 'Complete rich two-model declarations required')
    return rows


def verify_producer_evidence(payload, materialized):
    payload = Path(payload)
    names = (('PRODUCER_SOURCE_REQUEST.json', 'producer_source_request_sha256'),
             ('PRODUCER_QUALIFICATION.json', 'producer_qualification_sha256'),
             ('PRODUCER_ROOT_RELEASE.json', 'producer_root_release_sha256'))
    for filename, key in names:
        path = payload / filename
        need(is_sha(materialized.get(key)) and path.is_file() and not path.is_symlink()
             and path.stat().st_size < 4 * 2**20 and sha(path) == materialized[key],
             'Exact retained producer source/result/root-review evidence required: ' + filename)
    request = json.loads((payload / 'PRODUCER_SOURCE_REQUEST.json').read_bytes())
    qualification = json.loads((payload / 'PRODUCER_QUALIFICATION.json').read_bytes())
    labels = ['perimeter-ordinary', 'perimeter-optimized', 'produce', 'producer-ordinary', 'producer-optimized']
    need([row['label'] for row in request['commands']] == labels
         and [row['label'] for row in qualification['commands']] == labels,
         'Exact five source-stage production commands required')
    need(qualification['passed'] is True and qualification['all_attempted_processes_terminal'] is True
         and qualification['source_inputs_unchanged'] is True
         and qualification['qualified_complete_build_cells'] == 0
         and qualification['actual_new_compiler_jobs'] == 0
         and qualification['actual_new_native_jobs'] == 0,
         'Accepted unchanged-source producer-only result required')
    for row in qualification['commands']:
        need(row['terminal_qualified'] is True and row['process_result']['passed'] is True,
             'Every source-stage command must retain successful terminal ownership')
        if row['label'] != 'produce':
            unit = row['unittest']
            count = 12 if row['label'].startswith('producer-') else 8
            need(unit['passed'] is True and unit['example_count'] == count
                 and len(unit['list_of_titles']) == len(set(unit['list_of_titles'])) == count
                 and unit['failures'] == unit['errors'] == unit['skipped'] == 0,
                 'Complete unique source-control titles and zero failure/error/skip required')
    return {'passed': True, 'actual_source_only_commands': 5, 'producer_controls_per_mode': 12,
            'perimeter_controls_per_mode': 8,
            'root_release_scope': 'Exact root-reviewed terminal/release artifact bytes; fresh native admission remains external'}


def require_source_paths(grant, source, profile):
    grant, source = Path(grant), Path(source)
    need(profile in PROFILES and source == grant / 'performance/results/frontend-diagnostic' / profile / 'fixture.cr',
         'Exact source-derived profile fixture path required')
    need(source.resolve() == source and source.is_file() and not source.is_symlink(), 'Ordinary exact fixture source required')
    need((source.parent / '../../../../src/grant.cr').resolve() == grant / 'src/grant.cr'
         and (source.parent / '../../../../src/adapter/sqlite.cr').resolve() == grant / 'src/adapter/sqlite.cr',
         'Four-parent Grant/SQLite requires must resolve into this checkout')
    need(source.read_bytes().startswith(b'require "../../../../src/grant"\nrequire "../../../../src/adapter/sqlite"\nrequire "json"\n\n'),
         'Exact original Grant/SQLite/JSON require header required')


def compiler_argv(backend, source, output):
    return [str(backend), 'build', '--no-color', '--error-on-warnings', '-Dwithout_mt',
            '--threads', '1', '--no-codegen', '--stats', str(source), '-o', str(output)]


def require_command(actual, backend, source, output):
    need(actual == compiler_argv(backend, source, output), 'Exact explicit-thread semantic build argv required')


def require_initial_disk(free_bytes):
    need(type(free_bytes) is int and free_bytes > 10 * 2**30 + COMPLETE_MINI_PROJECTION,
         '10GiB reserve plus complete1259339776-byte Mini projection required')


def cache_inventory(root, tick=lambda: None):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink() and root.resolve() == root, 'Ordinary exact private cache root required')
    rows, total = [], 0
    for path in sorted(root.rglob('*'), key=lambda item: item.as_posix()):
        if len(rows) % 64 == 0:
            tick()
        need(len(rows) < 4096, 'Finite4096-entry private cache inventory reached')
        info = path.lstat()
        row = {'path': path.relative_to(root).as_posix(), 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            resolved = path.resolve(strict=True)
            need(resolved.is_relative_to(root), 'Private cache link target escapes its exact owned root')
            row.update(kind='symlink', target=target, resolved_relative_path=resolved.relative_to(root).as_posix())
        elif stat.S_ISREG(info.st_mode):
            need(info.st_size < 16 * 2**20, 'Finite16MiB private cache file cap reached')
            total += info.st_size
            need(total < CACHE_LIMIT, 'Private profile cache reaches64MiB refusal fence')
            row.update(kind='file', bytes=info.st_size, sha256=sha(path))
            after = path.lstat()
            need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 'Cache content changed during inventory')
        elif stat.S_ISDIR(info.st_mode):
            row['kind'] = 'directory'
        else:
            raise RuntimeError('Ordinary cache file/link/directory required')
        rows.append(row)
    return {'rows': rows, 'regular_bytes': total, 'entry_count': len(rows),
            'scope': 'Observed complete cache inventory at this boundary; transient peak and actor attribution remain unqualified'}


def require_semantic_cache(before, after):
    def content(value):
        return {(row['path'], row['kind']): row for row in value['rows'] if row['kind'] != 'directory'}
    need(content(before) == content(after),
         'Unexpected semantic cache file/link/native output; preserved full cache for bounded recovery')


class Clock:
    def __init__(self, now=time.monotonic):
        self.now = now
        self.started = now()
        self.completed = {'sdk': 0.0, 'compiler': 0.0}
        self.active = None
        self.counts = {'sdk': 0, 'compiler': 0}

    def check(self):
        current = self.now()
        elapsed = current - self.started
        need(0 <= elapsed < 870, 'Finite870second native work horizon reached')
        spent = dict(self.completed)
        if self.active:
            category, began, limit = self.active
            need(current - began < limit, 'Finite per-command category deadline reached')
            spent[category] += current - began
        audit = elapsed - sum(spent.values())
        need(audit < 60 and spent['sdk'] < 90 and spent['compiler'] < 720,
             'Separate60audit/90SDK/720compiler aggregate clocks reached')
        return {'elapsed_seconds': elapsed, 'audit_seconds': audit, **spent, 'counts': dict(self.counts)}

    @contextlib.contextmanager
    def phase(self, category, limit):
        need(category in self.completed and self.active is None,
             'One exact serialized SDK/compiler clock category required')
        need(limit == (15 if category == 'sdk' else 120), 'Exact SDK15/compiler120 command clock required')
        self.check()
        self.active = (category, self.now(), limit)
        try:
            yield
            self.check()
        finally:
            self.completed[category] += self.now() - self.active[1]
            self.counts[category] += 1
            self.active = None
