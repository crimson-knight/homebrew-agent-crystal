"""Bind one freshly observed macOS SDK to the exact C compile/header argv."""
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

FORMAT = 'atlas-observed-macos-sdk-sysroot-v1'
MAX_SETTINGS = 2**20


def need(value, message):
    if not value:
        raise RuntimeError(message)


def clock(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline)
         and time.monotonic() <= deadline, 'Complete SDK context deadline required')


def identity(path):
    value = Path(path).lstat()
    return [value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns]


def capture(path, version, build, deadline):
    clock(deadline)
    lexical = Path(path)
    need(type(path) is str and lexical.is_absolute() and str(lexical) == path
         and '..' not in lexical.parts and lexical != Path('/'),
         'Exact absolute observed SDK path required')
    need(type(version) is str and 0 < len(version) <= 128
         and type(build) is str and 0 < len(build) <= 128,
         'Fresh observed SDK version and build required')
    before = identity(lexical)
    physical = lexical.resolve(strict=True)
    root_before = identity(physical)
    need(stat.S_ISDIR(root_before[2]), 'Physical selected SDK directory required')
    settings = (lexical / 'SDKSettings.json').resolve(strict=True)
    need(settings.is_relative_to(physical), 'SDK settings must belong to the observed SDK root')
    settings_before = identity(settings)
    need(stat.S_ISREG(settings_before[2]) and 0 < settings_before[3] <= MAX_SETTINGS,
         'Bounded ordinary selected SDK settings required')
    with os.fdopen(os.open(settings, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need([opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size,
              opened.st_mtime_ns, opened.st_ctime_ns] == settings_before,
             'Exact opened SDK settings identity required')
        raw = stream.read(MAX_SETTINGS + 1)
    clock(deadline)
    need(len(raw) == settings_before[3] and identity(settings) == settings_before
         and lexical.resolve(strict=True) == physical and identity(lexical) == before
         and identity(physical) == root_before, 'Complete selected SDK capture return required')
    return dict(format=FORMAT, path=path, resolved_path=str(physical),
                lexical_identity=before, physical_identity=root_before,
                version=version, build=build,
                settings=dict(path=str(settings), bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest(),
                              mode=stat.S_IMODE(settings_before[2]),
                              physical_identity=settings_before))


def verify(value, deadline):
    metadata(value)
    need(capture(value['path'], value['version'], value['build'], deadline) == value,
         'Original SDK path/version/build/settings/directory return required')
    return value


def metadata(value):
    need(type(value) is dict and set(value) == {'format', 'path', 'resolved_path',
         'lexical_identity', 'physical_identity', 'version', 'build', 'settings'}
         and value['format'] == FORMAT, 'Exact selected SDK binding schema required')
    for key in ('lexical_identity', 'physical_identity'):
        row = value[key]
        need(type(row) is list and len(row) == 6
             and all(type(number) is int and number >= 0 for number in row),
             'Exact typed SDK physical identities required')
    need(stat.S_ISDIR(value['physical_identity'][2]) and (stat.S_ISDIR(value['lexical_identity'][2]) or stat.S_ISLNK(value['lexical_identity'][2])), 'Selected SDK directory/alias kind required')
    for key in ('path', 'resolved_path'):
        path = value[key]
        need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
             and '..' not in Path(path).parts and path != '/', 'Absolute SDK metadata path required')
    for key in ('version', 'build'):
        need(type(value[key]) is str and 0 < len(value[key]) <= 128, 'SDK version/build metadata required')
    row = value['settings']
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode', 'physical_identity'}
         and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_SETTINGS
         and type(row['mode']) is int and 0 <= row['mode'] <= 0o7777
         and type(row['sha256']) is str and len(row['sha256']) == 64
         and all(character in '0123456789abcdef' for character in row['sha256'])
         and type(row['physical_identity']) is list and len(row['physical_identity']) == 6
         and all(type(number) is int and number >= 0 for number in row['physical_identity'])
         and stat.S_ISREG(row['physical_identity'][2])
         and row['physical_identity'][3] == row['bytes']
         and stat.S_IMODE(row['physical_identity'][2]) == row['mode']
         and Path(row['path']).is_absolute()
         and Path(row['path']).is_relative_to(Path(value['resolved_path'])),
         'Exact selected SDK settings metadata/containment required')
    return dict(format=FORMAT, path=value['path'], resolved_path=value['resolved_path'],
                lexical_kind=stat.S_IFMT(value['lexical_identity'][2]),
                directory_mode=stat.S_IMODE(value['physical_identity'][2]),
                version=value['version'], build=value['build'],
                settings={key: row[key] for key in ('path', 'bytes', 'sha256', 'mode')})


def compile_argv(argv, value):
    metadata(value)
    need(type(argv) is list and len(argv) >= 2
         and all(type(argument) is str for argument in argv)
         and not any(argument.startswith(('-isysroot', '--sysroot')) for argument in argv),
         'One explicit observed SDK sysroot tuple required')
    return [argv[0], '-isysroot', value['path'], *argv[1:]]


def preprocessing_argv(original):
    """Derive the dependency command from one complete bounded C compile tuple."""
    need(type(original) is list and 5 <= len(original) <= 128
         and all(type(argument) is str and 0 < len(argument) <= 4096
                 and not any(character in argument for character in ('\0', '\r', '\n'))
                 for argument in original)
         and sum(len(argument) for argument in original) <= 65536,
         'Bounded complete typed C compile argv required')
    need(Path(original[0]).is_absolute()
         and original.count('-c') == 1 and original.count('-o') == 1
         and original[-4] == '-c' and original[-2] == '-o'
         and Path(original[-3]).is_absolute() and Path(original[-3]).name == 'buffer_shim.c'
         and Path(original[-1]).is_absolute() and Path(original[-1]).suffix == '.o'
         and '-E' not in original and '-M' not in original,
         'Exact original C compiler/source/output tuple required')
    return [argument for argument in original[:-2] if argument != '-c'] + ['-E', '-M']
