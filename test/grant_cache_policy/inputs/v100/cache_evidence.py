"""Keep the cache-policy source and disk evidence separate from process memory."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'grant_assignment_cost'
BASE_PACKET = '9dca430312103538460af4176fceef93f7744ea1e32572474f36ef73bbc25a09'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protect(expected):
    manifest = ROOT / 'SOURCE_PINS.json'
    need(not manifest.is_symlink() and digest(manifest) == expected, 'Exact externally selected cache source manifest required')
    rows = json.loads(manifest.read_bytes())['files']
    need(1 <= len(rows) <= 16 and len({row['path'] for row in rows}) == len(rows), 'Finite unique cache source roster required')
    protected = {manifest: expected}
    for row in rows:
        relative = PurePosixPath(row['path'])
        need(str(relative) == row['path'] and not relative.is_absolute() and '..' not in relative.parts, 'Contained cache source required')
        path = ROOT / relative
        need(not path.is_symlink() and path.is_file() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'], 'Exact cache source member required')
        protected[path] = row['sha256']
    return protected


def cache_inventory(root):
    root = Path(root)
    rows = []
    total = 0
    need(not root.is_symlink(), 'Ordinary private cache root required')
    if root.exists():
        need(root.is_dir(), 'Private cache directory required')
        for path in sorted(root.rglob('*')):
            need(not path.is_symlink(), 'Cache evidence requires ordinary entries')
            before = path.lstat()
            if stat.S_ISDIR(before.st_mode):
                continue
            need(stat.S_ISREG(before.st_mode) and len(rows) < 10000 and before.st_size <= 64 * 2**20, 'Finite ordinary cache file roster required')
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                opened = os.fstat(stream.fileno())
                raw = stream.read(64 * 2**20 + 1)
                after = os.fstat(stream.fileno())
            fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            need(fields(before) == fields(opened) == fields(after) == fields(path.lstat()) and len(raw) == before.st_size, 'Stable complete retired cache file required')
            total += len(raw)
            need(total <= 512 * 2**20, 'Complete cache disk-byte budget exceeded')
            rows.append(dict(path=path.relative_to(root).as_posix(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    bitcode = [row for row in rows if row['path'].endswith('.bc')]
    return dict(files=rows, file_count=len(rows), total_disk_bytes=total,
                cache_root_present=root.is_dir(), object_files=sum(row['path'].endswith('.o') for row in rows),
                cache_metadata_files=sum(Path(row['path']).name.startswith('bc_flags.') for row in rows),
                bitcode_files=len(bitcode), bitcode_disk_bytes=sum(row['bytes'] for row in bitcode),
                scope='Retired private cache files and serialized bytes; native allocations and process RSS are separate')


def verify_mechanism(samples):
    need([row['arm'] for row in samples] == ['original', 'candidate', 'restored'], 'Exact ordered cold-cache comparison required')
    for row in samples:
        inventory = row['cache_inventory']
        need(inventory['cache_root_present'] is True and type(inventory['object_files']) is int and inventory['object_files'] > 0
             and type(inventory['cache_metadata_files']) is int and inventory['cache_metadata_files'] > 0,
             'Actual private cache with object and cache-flag metadata evidence required')
        need(type(inventory['bitcode_files']) is int and type(inventory['bitcode_disk_bytes']) is int, 'Exact cache evidence integers required')
        if row['arm'] == 'candidate':
            need(inventory['bitcode_files'] == 0 and inventory['bitcode_disk_bytes'] == 0, 'Disabled cache must create no serialized bitcode files')
        else:
            need(inventory['bitcode_files'] > 0 and inventory['bitcode_disk_bytes'] > 0, 'Cold default compilation must reach serialized bitcode cache writing')
    return True


def verify_owner_parity(samples):
    rosters = []
    for sample in samples:
        predicate = sample['owner_predicate']
        need(predicate['source_shape_predicate_passed'] is True, 'Original assignment ownership predicate required')
        rows = [dict(model=row['model'], public_assignment_symbols=sorted(row['public_assignment_symbols']),
                     canonical_heavy_symbols=sorted(row['canonical_heavy_symbols'])) for row in predicate['rows']]
        rosters.append(sorted(rows, key=lambda row: row['model']))
    need(len(rosters) == 3 and rosters[0] == rosters[1] == rosters[2], 'Exact typed assignment owner identities required across cache arms')
    return dict(passed=True, rows=rosters[0], scope='Exact reached public and heavy assignment symbol identities across all three arms')
