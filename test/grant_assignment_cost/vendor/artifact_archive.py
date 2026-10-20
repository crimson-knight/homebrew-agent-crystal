"""Bounded deterministic regular-file archives with full uncompressed byte identities."""
from pathlib import Path
import gzip
import hashlib
import re
import stat
import tarfile

CHUNK = 65536
MAX_MEMBERS = 64
DEFAULT_COMPRESSED_CAP = 16 * 2**20
DEFAULT_CONTENT_CAP = 128 * 2**20
TAR_OVERHEAD_CAP = 2 * 2**20


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk := source.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


class CountBytesAndHash:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.count = stream, maximum, 0
        self.digest = hashlib.sha256()

    def write(self, value):
        require(self.count + len(value) <= self.maximum, 'Artifact stream exceeds its declared byte cap')
        written = self.stream.write(value)
        require(written == len(value), 'Artifact stream write was incomplete')
        self.count += len(value)
        self.digest.update(value)
        return written

    def read(self, size=-1):
        require(0 <= size <= CHUNK, 'Artifact stream reads use bounded chunks')
        value = self.stream.read(size)
        require(self.count + len(value) <= self.maximum, 'Artifact stream exceeds its declared byte cap')
        self.count += len(value)
        self.digest.update(value)
        return value

    def flush(self):
        self.stream.flush()


def checked_name(name):
    require(type(name) is str and name and name not in ('.', '..') and
            '/' not in name and '\\' not in name and '\x00' not in name and
            len(name.encode('utf-8')) <= 100, 'Artifact member uses one ordinary flat filename')
    return name


def pack_artifacts(list_of_files, destination, compressed_cap=DEFAULT_COMPRESSED_CAP,
                   content_cap=DEFAULT_CONTENT_CAP):
    require(0 < len(list_of_files) <= MAX_MEMBERS, 'Artifact member count differs')
    destination = Path(destination)
    roster, total = [], 0
    for name, path in sorted(list_of_files.items()):
        checked_name(name)
        path = Path(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'Artifact source requires an ordinary file')
        mode = stat.S_IMODE(info.st_mode)
        require(mode in (0o644, 0o755), 'Artifact source mode is outside the admitted file modes')
        total += info.st_size
        require(total <= content_cap, 'Artifact uncompressed contents exceed their declared byte cap')
        roster.append({'path': name, 'source': str(path), 'bytes': info.st_size, 'mode': mode,
                       'sha256': file_sha(path)})
    with destination.open('xb') as output:
        compressed = CountBytesAndHash(output, compressed_cap)
        with gzip.GzipFile(fileobj=compressed, filename='', mode='wb', compresslevel=6, mtime=0) as codec:
            uncompressed = CountBytesAndHash(codec, content_cap + TAR_OVERHEAD_CAP)
            with tarfile.open(fileobj=uncompressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                for row in roster:
                    path = Path(row['source'])
                    info = tarfile.TarInfo(row['path'])
                    info.size, info.mode, info.mtime = row['bytes'], row['mode'], 0
                    info.uid, info.gid, info.uname, info.gname = 0, 0, '', ''
                    with path.open('rb') as source:
                        archive.addfile(info, source)
                    require(not path.is_symlink() and path.stat().st_size == row['bytes'] and
                            stat.S_IMODE(path.stat().st_mode) == row['mode'] and file_sha(path) == row['sha256'],
                            'Artifact source changed during compression')
    result = {'schema_version': 1, 'codec': 'gzip6-mtime0-ustar-regular-files-v1',
        'compressed_bytes': compressed.count, 'compressed_sha256': compressed.digest.hexdigest(),
        'uncompressed_tar_bytes': uncompressed.count,
        'uncompressed_tar_sha256': uncompressed.digest.hexdigest(),
        'uncompressed_content_bytes': total,
        'list_of_members': [{key: value for key, value in row.items() if key != 'source'} for row in roster],
        'compressed_cap_bytes': compressed_cap, 'content_cap_bytes': content_cap}
    verify_artifacts(destination, result, compressed_cap, content_cap)
    return result


def verify_artifacts(path, expected, compressed_cap=DEFAULT_COMPRESSED_CAP,
                     content_cap=DEFAULT_CONTENT_CAP):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Compressed artifact requires an ordinary file')
    require(expected['schema_version'] == 1 and expected['codec'] == 'gzip6-mtime0-ustar-regular-files-v1',
            'Artifact codec identity differs')
    require(type(expected['compressed_bytes']) is int and
            0 < expected['compressed_bytes'] == path.stat().st_size <= compressed_cap,
            'Compressed artifact byte count/cap differs')
    require(expected['compressed_sha256'] == file_sha(path), 'Compressed artifact SHA differs')
    rows = expected['list_of_members']
    require(expected['compressed_cap_bytes'] == compressed_cap and expected['content_cap_bytes'] == content_cap,
            'Artifact codec cap profile differs')
    require(0 < len(rows) <= MAX_MEMBERS and len({row['path'] for row in rows}) == len(rows),
            'Unique artifact member roster is required')
    for row in rows:
        require(set(row) == {'path', 'bytes', 'mode', 'sha256'} and
                type(row['bytes']) is int and 0 <= row['bytes'] <= content_cap and
                type(row['mode']) is int and row['mode'] in (0o644, 0o755) and
                re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None,
                'Artifact member typed metadata differs')
    require([row['path'] for row in rows] == sorted(checked_name(row['path']) for row in rows),
            'Artifact member order differs')
    require(type(expected['uncompressed_content_bytes']) is int and
            0 <= expected['uncompressed_content_bytes'] <= content_cap and
            expected['uncompressed_content_bytes'] == sum(row['bytes'] for row in rows),
            'Artifact declared uncompressed content total differs')
    total, observed = 0, []
    with path.open('rb') as source:
        with gzip.GzipFile(fileobj=source, mode='rb') as codec:
            uncompressed = CountBytesAndHash(codec, content_cap + TAR_OVERHEAD_CAP)
            with tarfile.open(fileobj=uncompressed, mode='r|') as archive:
                for index, member in enumerate(archive):
                    require(index < len(rows), 'Compressed artifact has an unexpected member')
                    row = rows[index]
                    require(member.type == tarfile.REGTYPE and not member.pax_headers and
                            member.name == row['path'] and member.size == row['bytes'] and
                            member.mode == row['mode'] and member.mode in (0o644, 0o755) and
                            member.uid == member.gid == member.mtime == 0 and
                            member.uname == member.gname == '', 'Artifact member metadata/identity differs')
                    require(type(member.size) is int and 0 <= member.size <= content_cap - total,
                            'Artifact member exceeds its uncompressed byte cap')
                    extracted = archive.extractfile(member)
                    require(extracted is not None, 'Artifact member bytes are unavailable')
                    digest, count = hashlib.sha256(), 0
                    while chunk := extracted.read(CHUNK):
                        digest.update(chunk)
                        count += len(chunk)
                        require(count <= member.size, 'Artifact member exceeds its declared size')
                    require(count == member.size and digest.hexdigest() == row['sha256'],
                            'Artifact uncompressed member SHA/size differs')
                    total += count
                    observed.append(member.name)
            # Finish the gzip stream to verify its CRC/footer and full tar byte identity.
            while uncompressed.read(CHUNK):
                pass
    require(len(observed) == len(rows) and total == expected['uncompressed_content_bytes'],
            'Compressed artifact member coverage differs')
    require(uncompressed.count == expected['uncompressed_tar_bytes'] and
            uncompressed.digest.hexdigest() == expected['uncompressed_tar_sha256'],
            'Full uncompressed tar byte identity differs')
    return {'passed': True, 'members': len(observed), 'compressed_bytes': path.stat().st_size,
            'uncompressed_content_bytes': total, 'verification': 'streamed SHA/size/metadata/CRC; extracted file writes0'}
