"""Transparent, finite compiler-argv derivation for the separately admitted API lane."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_CALLS = 1024
MAX_JOURNAL = 4 * 2**20
FLAGS = ['--threads','1','--release','--no-debug','-Dstrict_multi_assign','-Dpreview_overload_order','-Dwithout_libxml2','-Dwithout_openssl','-Dwithout_zlib','--error-on-warnings','--no-color']
DOCS_DEFINES = ['strict_multi_assign','preview_overload_order','without_libxml2','without_openssl','without_zlib','release']

def need(value, message):
    if not value:
        raise RuntimeError(message)

def read(path, maximum):
    p = Path(path); before = p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'Bounded single-link physical proxy input required')
    fields = lambda s: [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        opened = os.fstat(f.fileno()); raw = f.read(maximum + 1); after = os.fstat(f.fileno())
    need(fields(before) == fields(opened) == fields(after) == fields(p.lstat()) and len(raw) == before.st_size, 'Stable complete proxy input required')
    return raw

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def derive(arguments, project, stdlib, cwd=None):
    cwd = Path(project if cwd is None else cwd)
    need(0 < len(arguments) <= 128 and all(type(a) is str and len(a) <= 4096 and '\x00' not in a for a in arguments), 'Finite original compiler argv required')
    command = arguments[0]
    if arguments == ['--version'] or arguments == ['env'] or (len(arguments) == 2 and command == 'env' and arguments[1] in ('CRYSTAL_PATH','CRYSTAL_VERSION','CRYSTAL_LIBRARY_PATH')):
        return list(arguments)
    if command == 'build':
        need(arguments.count('--no-codegen') == 1, 'Only explicitly requested target no-codegen verification is admitted')
        need(all(a not in arguments for a in ('-o','--output','--release','--static','--single-module','--prelude')), 'Exact target compatibility build contract required')
        sources = [a for a in arguments[1:] if a.endswith('.cr')]
        need(len(sources) == 1 and Path(sources[0]).is_absolute() and Path(sources[0]).resolve().is_relative_to(Path(project)), 'One contained actual-project verification source required')
        need('--threads' not in arguments and not any(a.startswith('--threads=') or a.startswith('-D') for a in arguments), 'Original LSP verifier argv requires an explicit reviewed flag derivation')
        need(all(a == sources[0] or a == '--no-codegen' for a in arguments[1:]), 'Exact original build verifier syntax required')
        return arguments + FLAGS
    need(command == 'docs' and '--format=json' in arguments, 'Supported metadata/docs/no-codegen compiler entrypoint required')
    sources = []; normalized = [command]; index = 1
    while index < len(arguments):
        value = arguments[index]
        if value == '-D':
            need(index + 1 < len(arguments) and arguments[index + 1] in ('without_mt','without_libxml2','without_openssl','without_zlib'), 'Reviewed docs feature context required'); index += 2; continue
        if value == '--format=json' or value.startswith('--project-name=') or value.startswith('--project-version='):
            normalized.append(value); index += 1; continue
        path = Path(value)
        need(value.endswith('.cr') and ((cwd/path).resolve().is_relative_to(Path(project)) or (cwd/path).resolve().is_relative_to(Path(stdlib))), 'Contained project or admitted installed stdlib docs entrypoint required')
        sources.append(value); normalized.append(value); index += 1
    need(sources, 'Actual docs source entrypoint required')
    return normalized + [part for flag in DOCS_DEFINES for part in ('-D',flag)] + ['--error-on-warnings','--no-color']

def launch(arguments, environment=None):
    environment = dict(os.environ if environment is None else environment)
    config_path = Path(environment['ATLAS_CENSUS_PROXY_CONFIG'])
    raw = read(config_path, 64 * 1024)
    need(digest(raw) == environment['ATLAS_CENSUS_PROXY_CONFIG_SHA256'], 'Exact same-job proxy configuration required')
    config = json.loads(raw)
    need(config['format'] == 'atlas-census-compiler-proxy-v1', 'Versioned proxy source contract required')
    private_state = Path(config['private']).lstat()
    need([private_state.st_dev,private_state.st_ino,private_state.st_mode] == config['private_identity'] and stat.S_ISDIR(private_state.st_mode), 'Original owned private compiler workspace required')
    for row in config['providers']:
        need(digest(read(row['path'], 256 * 2**20)) == row['sha256'], 'Original admitted compiler/Python/proxy provider required')
    current = Path.cwd(); project = Path(config['project'])
    if current != project:
        need(current.is_relative_to(Path(config['private'])/'home/.cache/amber-lsp/index/docs-workspaces') and current.parent.resolve() == current.parent, 'Owned released-LSP docs workspace role required')
        need((current/'src').is_symlink() and (current/'src').resolve(strict=True).is_relative_to(project/'lib') and (current/'lib').is_symlink() and (current/'lib').resolve(strict=True) == project/'lib', 'Exact complete-project docs workspace alias roles required')
    for key, value in config['environment'].items():
        need(environment.get(key) == value, 'Exact compiler source and native environment context required: ' + key)
    # LSP intentionally creates a per-verification cache. It stays in the owned root.
    cache = Path(environment['CRYSTAL_CACHE_DIR'])
    need(cache.is_absolute() and cache.is_relative_to(Path(config['private'])) and cache.resolve() == cache, 'Physical owned verification cache required')
    actual = derive(arguments, config['project'], config['stdlib'], current)
    path = Path(config['journal']); info = path.lstat()
    need([info.st_dev,info.st_ino,info.st_mode] == config['journal_identity'], 'Original physical compiler journal required')
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_JOURNAL, 'Physical bounded original proxy journal required')
    existing = read(path, MAX_JOURNAL)
    need(len(existing.splitlines()) < MAX_CALLS, 'Finite compiler invocation journal required')
    source_resolutions = {value:str((current/value).resolve(strict=True)) for value in arguments if value.endswith('.cr')}
    row = dict(original_arguments=arguments, executed_arguments=[config['backend'], *actual], cwd=os.getcwd(), project_role='canonical-project' if current == project else 'released-library-docs-workspace', source_resolutions=source_resolutions, pid=os.getpid(), process_group=os.getpgrp(), configuration_sha256=digest(raw), environment={k:environment.get(k) for k in sorted(set(config['environment']) | {'CRYSTAL_CACHE_DIR'})})
    record = (json.dumps(row, sort_keys=True, allow_nan=False) + '\n').encode()
    need(len(existing) + len(record) <= MAX_JOURNAL, 'Complete compiler journal byte ceiling required')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW), 'ab') as stream:
        opened = os.fstat(stream.fileno()); need((opened.st_dev,opened.st_ino,opened.st_mode) == (info.st_dev,info.st_ino,info.st_mode), 'Original compiler journal inode required'); stream.write(record); stream.flush()
    os.execve(config['backend'], [config['backend'], *actual], environment)

if __name__ == '__main__':
    try:
        launch(sys.argv[1:])
    except BaseException as error:
        sys.stderr.write('Census compiler proxy refusal: ' + type(error).__name__ + ': ' + str(error) + '\n')
        raise SystemExit(78)
