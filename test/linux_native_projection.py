#!/usr/bin/env python3
"""Record a bounded, unreviewed Ubuntu host-to-container native projection."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import time

MAX_FILES = 8192
MAX_HASH_BYTES = 2 * 1024**3
MAX_FILE_BYTES = 256 * 1024**2
MAX_METADATA_BYTES = 32 * 1024**2
MAX_COMMANDS = 32
MAX_SECONDS = 150
ORIGINAL_MOUNTS = ('/usr', '/home/linuxbrew/.linuxbrew', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d')
LOADER_ENV = ('CRYSTAL_LIBRARY_PATH', 'LD_LIBRARY_PATH', 'LD_RUN_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'CC', 'CXX', 'LIBRARY_PATH', 'CPATH')
SYSTEM_PKG_CONFIG = '/usr/bin/pkg-config'
SYSTEM_PKG_CONFIG_DIRECTORIES = ('/usr/lib/x86_64-linux-gnu/pkgconfig', '/usr/lib/pkgconfig', '/usr/share/pkgconfig')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def pin(path, expected):
    need(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected), 'A complete reviewed source SHA-256 is required')
    need(Path(path).is_file() and sha(path) == expected, 'Source/provider SHA-256 mismatch: ' + str(path))


def load(path, expected, name):
    pin(path, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pin(path, expected)
    return module


def covered(path, roots=ORIGINAL_MOUNTS):
    return any(path == root or path.startswith(root + '/') for root in roots)


class Roster:
    """Keep lexical alias and physical file identities with the existing stable reader."""
    def __init__(self, file_identity, deadline):
        self.identity = file_identity
        self.deadline = deadline
        self.entries = {}
        self.total_bytes = 0
        self.missing = []

    def check(self):
        need(time.monotonic() < self.deadline, 'Native metadata collection exceeded its total deadline')
        need(len(self.entries) <= MAX_FILES, 'Native metadata entry budget exceeded')
        need(self.total_bytes <= MAX_HASH_BYTES, 'Native metadata hash-byte budget exceeded')

    def store_entry(self, path, row):
        if path not in self.entries:
            need(len(self.entries) < MAX_FILES, 'Native metadata entry budget exceeded before insertion')
        self.entries[path] = row

    def add(self, value, required=False):
        self.check()
        path = os.path.normpath(str(value))
        need(path.startswith('/') and '\n' not in path and '\r' not in path and '\x00' not in path, 'A normalized absolute native path is required')
        current = Path(path)
        aliases = 0
        while True:
            self.check()
            parts = current.parts
            changed = False
            for index in range(1, len(parts)):
                prefix = Path(*parts[:index + 1])
                if prefix.is_symlink():
                    aliases += 1
                    need(aliases <= 48, 'Native alias depth exceeded')
                    target = os.readlink(prefix)
                    row = {'kind': 'symlink', 'target': target, 'mode': stat.S_IMODE(prefix.lstat().st_mode)}
                    previous = self.entries.get(str(prefix))
                    need(previous is None or previous == row, 'Native alias changed during collection')
                    self.store_entry(str(prefix), row)
                    tail = parts[index + 1:]
                    base = Path(target) if target.startswith('/') else prefix.parent / target
                    current = Path(os.path.normpath(str(base.joinpath(*tail))))
                    changed = True
                    break
            if not changed:
                break
        if not current.exists():
            self.missing.append({'path': path, 'resolved_path': str(current), 'required': required})
            need(not required, 'Required native path is absent: ' + path)
            return None
        physical = str(current)
        if physical not in self.entries:
            need(len(self.entries) < MAX_FILES, 'Native metadata entry budget exceeded before read')
            observed = current.lstat()
            if stat.S_ISREG(observed.st_mode):
                need(0 <= observed.st_size <= MAX_FILE_BYTES, 'Native file exceeds stable-reader bound: ' + physical)
                need(self.total_bytes + observed.st_size <= MAX_HASH_BYTES, 'Native hash-byte budget exceeded before read')
                row = self.read_file(physical)
                after = current.lstat()
                need(stat.S_ISREG(after.st_mode) and stat.S_IMODE(after.st_mode) == stat.S_IMODE(observed.st_mode), 'Native physical file kind or mode changed during collection: ' + physical)
                self.store_entry(physical, dict(row, kind='file', mode=stat.S_IMODE(observed.st_mode)))
                self.total_bytes += row['bytes']
            else:
                need(stat.S_ISDIR(observed.st_mode), 'Native entries require ordinary files, directories, or aliases')
                self.store_entry(physical, {'kind': 'directory', 'mode': stat.S_IMODE(observed.st_mode)})
        self.check()
        return physical

    def read_file(self, path):
        before = Path(path).stat()
        if before.st_size:
            return self.identity(path)
        need(stat.S_ISREG(before.st_mode), 'Empty native input must be an ordinary file')
        digest = sha(path)
        after = Path(path).stat()
        fields = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        need(fields(before) == fields(after) and after.st_size == 0, 'Empty native file changed during read')
        return {'path': str(path), 'bytes': 0, 'sha256': digest}

    def directory(self, value):
        root = self.add(value, required=True)
        need(self.entries[root]['kind'] == 'directory', 'Native roster root must be a directory')
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs.sort(); files.sort()
            for name in dirs + files:
                self.add(Path(directory) / name, required=True)
        return root

    def verify(self):
        for path, row in self.entries.items():
            self.check()
            if row['kind'] == 'file':
                before = Path(path).lstat()
                need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == row['mode'], 'Native physical file kind or mode changed: ' + path)
                need(self.read_file(path) == {key: row[key] for key in ('path', 'bytes', 'sha256')}, 'Native physical file changed: ' + path)
                after = Path(path).lstat()
                need(stat.S_ISREG(after.st_mode) and stat.S_IMODE(after.st_mode) == row['mode'], 'Native physical file kind or mode changed during verification: ' + path)
            elif row['kind'] == 'symlink':
                need(Path(path).is_symlink() and os.readlink(path) == row['target'] and stat.S_IMODE(Path(path).lstat().st_mode) == row['mode'], 'Native alias changed: ' + path)
            else:
                need(Path(path).is_dir() and not Path(path).is_symlink() and stat.S_IMODE(Path(path).stat().st_mode) == row['mode'], 'Native directory changed: ' + path)

    def gaps(self):
        return sorted(path for path in self.entries if not covered(path))


def stdlib_identity(root, roster):
    root = Path(root)
    files, aliases = {}, {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs.sort(); names.sort()
        for name in dirs + names:
            roster.check()
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            physical = roster.add(path, required=True)
            if path.is_symlink():
                need(Path(physical).is_relative_to(root.resolve()), 'Standard-library aliases must remain inside the source tree')
                aliases[relative] = os.readlink(path)
            elif path.is_file():
                files[relative] = roster.read_file(physical)['sha256']
    data = ''.join(files[path] + '  ' + path + '\n' for path in sorted(files)).encode()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'files': files, 'directory_aliases': aliases}


def validate_command(record, require_success=True):
    need(type(record) is dict and type(record.get('exit_code')) is int and (not require_success or record['exit_code'] == 0), 'Metadata command must return zero or be an explicit diagnostic observation')
    need(type(record.get('pid')) is int and record['pid'] > 0 and type(record.get('original_group')) is int and record['original_group'] == record['pid'], 'Metadata command requires its exact original process group')
    observation = record.get('terminal_group_observation', {})
    need(observation.get('status') == 'absent' and type(observation.get('group')) is int and observation['group'] == record['pid'] and record.get('writers_confirmed_retired') is True and record.get('refusal') is None, 'Metadata command original group must be observed absent')
    need(type(record.get('elapsed_seconds')) in (int, float) and 0 <= record['elapsed_seconds'] <= 45, 'Metadata command elapsed deadline exceeded')
    for key in ('stdout_sha256', 'stderr_sha256'):
        need(type(record.get(key)) is str and re.fullmatch('[a-f0-9]{64}', record[key]), 'Metadata command needs retired raw-stream hashes')


class Commands:
    def __init__(self, runner, roster, output):
        self.runner, self.roster, self.output = runner, roster, output
        self.identities = {}
        self.count = 0

    def run(self, label, arguments, seconds=30, *, environment=None, observe_nonzero=False):
        self.roster.check()
        need(self.count < MAX_COMMANDS and type(seconds) is int and 1 <= seconds <= 45, 'Metadata command roster/deadline exceeded')
        executable = self.roster.add(arguments[0], required=True)
        need(self.roster.entries[executable]['kind'] == 'file', 'Metadata command requires an identified executable')
        expected_identity = {key: self.roster.entries[executable][key] for key in ('path', 'bytes', 'sha256')}
        need(self.roster.read_file(executable) == expected_identity, 'Metadata executable changed before command')
        self.count += 1
        previous = len(self.runner.records)
        try:
            self.runner.run(label, arguments, cwd=self.output,
                environment=environment if environment is not None else dict(os.environ, HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_ANALYTICS='1'), seconds=seconds)
        except Exception as error:
            if not observe_nonzero or len(self.runner.records) != previous + 1:
                raise
            observed = self.runner.records[-1]
            if (type(error).__name__ != 'QualificationError'
                    or str(error) != f"{label} exited {observed['exit_code']}; expected 0"
                    or type(observed['exit_code']) is not int or observed['exit_code'] == 0
                    or observed.get('refusal') is not None or observed.get('writers_confirmed_retired') is not True):
                raise
        need(len(self.runner.records) == previous + 1, 'Exactly one metadata command observation required')
        record = self.runner.records[-1]
        validate_command(record, require_success=not observe_nonzero)
        need(record.get('label') == label and record.get('arguments') == [str(value) for value in arguments], 'Actual metadata command label/argv differs')
        need(self.roster.read_file(executable) == expected_identity, 'Metadata executable changed during command')
        combined = sum((self.output / (label + '.' + suffix)).stat().st_size for suffix in ('stdout.txt', 'stderr.txt'))
        need(combined <= 4 * 1024**2, 'Metadata command combined raw-output budget exceeded')
        for suffix, key in (('stdout.txt', 'stdout_sha256'), ('stderr.txt', 'stderr_sha256')):
            need(sha(self.output / (label + '.' + suffix)) == record[key], 'Metadata raw command output changed')
        raw_bytes = sum(p.stat().st_size for p in self.output.glob('*.txt'))
        need(raw_bytes <= MAX_METADATA_BYTES, 'Aggregate raw metadata output budget exceeded')
        self.roster.check()
        return ((self.output / (label + '.stdout.txt')).read_text(),
                (self.output / (label + '.stderr.txt')).read_text())


def sqlite_metadata_environment():
    """Query the installed distro SQLite through its explicit reviewed PC roots."""
    return dict(os.environ, PKG_CONFIG_LIBDIR=':'.join(SYSTEM_PKG_CONFIG_DIRECTORIES),
                PKG_CONFIG_PATH='', PKG_CONFIG_SYSROOT_DIR='')


def sqlite_metadata_provider(commands, roster, homebrew_pkgconfig):
    """Retain the original Homebrew search result and identify the distro provider."""
    commands.run('sqlite3-homebrew-libdir-control', [homebrew_pkgconfig, '--variable=libdir', 'sqlite3'],
                 observe_nonzero=True)
    control = dict(commands.runner.records[-1])
    physical = roster.add(SYSTEM_PKG_CONFIG, required=True)
    need(roster.entries[physical]['kind'] == 'file', 'Distro pkg-config needs an identified regular provider')
    environment = sqlite_metadata_environment()
    commands.run('system-pkg-config-version', [physical, '--version'], environment=environment)
    commands.run('system-pkg-config-search-path', [physical, '--variable=pc_path', 'pkg-config'], environment=environment)
    for directory in SYSTEM_PKG_CONFIG_DIRECTORIES:
        roster.add(directory)
    return physical, environment, control


def cache_paths(raw):
    result = {}
    for line in raw.splitlines():
        match = re.match(r'\s*(\S+)\s+\([^\n]*\)\s+=>\s+(/\S+)\s*$', line)
        if match:
            result.setdefault(match[1], []).append(match[2])
    return result


def elf_needed(raw):
    return sorted(set(re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]\r\n]+)\]', raw)))


def elf_search_directories(raw, physical):
    directories = set()
    for value in re.findall(r'\((?:RPATH|RUNPATH)\)\s+(?:Library rpath|Library runpath): \[([^\]\r\n]*)\]', raw):
        for item in value.split(':'):
            if item.startswith('/'):
                directories.add(os.path.normpath(item))
            elif '$ORIGIN' in item or '${ORIGIN}' in item:
                for origin in {str(Path(path).parent) for path in physical}:
                    directories.add(os.path.normpath(item.replace('${ORIGIN}', origin).replace('$ORIGIN', origin)))
    return sorted(directories)


def extract_absolute_paths(raw):
    return sorted(set(re.findall(r'(?<![A-Za-z0-9])(/[^\s\[\]()<>;,:]+)', raw)))


def collect(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'format': 'atlas-linux-native-projection-candidate-v1', 'admitted': False, 'native_manifest_accepted': False, 'execution_admitted': False, 'compiler_jobs': 0, 'container_jobs': 0, 'actual_Grant_cells': 0, 'state': 'collecting-unreviewed-metadata', 'pending': ['independent exact native roster/profile review', 'complete header/link-input closure', 'actual proposed-container loader/link/GMP/SQLite canaries', 'SDK readiness and complete Grant build admission']}
    roster = runner = None
    try:
        need(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true' and re.fullmatch('[1-9][0-9]*', os.environ.get('GITHUB_RUN_ID', '')), 'Actual projection collection requires the hosted Linux job')
        pin(__file__, args.source_sha256)
        pin(Path(sys.executable).resolve(), args.python_sha256)
        driver = load(args.driver, args.driver_sha256, 'reviewed_projection_runner')
        reader = load(args.linux_reader, args.linux_reader_sha256, 'reviewed_linux_identity')
        pin(args.source_lock, args.source_lock_sha256)
        lock = json.loads(args.source_lock.read_text())
        need(type(lock) is dict and type(lock.get('alpha')) is dict, 'The reviewed SDK source lock is required')
        runner = driver.Runner(output)
        runner.deadline = min(runner.deadline, time.monotonic() + MAX_SECONDS)
        roster = Roster(reader.file_identity, runner.deadline)
        commands = Commands(runner, roster, output)
        result['inputs'] = {key: {'path': str(path.resolve()), 'sha256': sha(path)} for key, path in [('collector', Path(__file__)), ('driver', args.driver), ('linux_reader', args.linux_reader), ('source_lock', args.source_lock), ('python', Path(sys.executable))]}
        result['host'] = {'uname': list(os.uname()), 'image_os': os.environ.get('ImageOS'), 'image_version': os.environ.get('ImageVersion'), 'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'source_commit': os.environ.get('GITHUB_SHA'), 'python_version': platform.python_version(), 'loader_environment': {key: os.environ.get(key) for key in LOADER_ENV}}
        brew = shutil.which('brew'); need(brew, 'Ordinary Homebrew installation is required')
        prefix = Path(commands.run('brew-prefix', [brew, '--prefix', 'agent-crystal'])[0].strip()).resolve(strict=True)
        brew_root = Path(commands.run('brew-root', [brew, '--prefix'])[0].strip()).resolve(strict=True)
        need(str(brew_root) == '/home/linuxbrew/.linuxbrew' and prefix.is_relative_to(brew_root), 'The proposed projection requires ordinary Linuxbrew')
        receipt = commands.run('brew-alpha-info', [brew, 'info', '--json=v2', 'agent-crystal'])[0]
        driver.verify_formula_receipt(json.loads(receipt)['formulae'], lock['alpha'])
        for source in (args.repository / 'Formula/agent-crystal.rb', prefix / '.brew/agent-crystal.rb'):
            pin(source, lock['alpha']['formula_sha256']); roster.add(source, required=True)
        for name in ('INSTALL_RECEIPT.json', '.brew/agent-crystal.rb'):
            roster.add(prefix / name, required=True)
            shutil.copyfile(prefix / name, output / Path(name).name)
        wrapper = Path(shutil.which('crystal-alpha') or '').resolve(strict=True)
        compiler, stdlib = prefix / 'libexec/agent-crystal-bin', prefix / 'share/agent-crystal/src'
        need(wrapper == prefix / 'bin/crystal-alpha', 'The ordinary formula wrapper must be selected')
        driver.verify_wrapper(wrapper.read_text(), compiler, stdlib, brew_root, 'Linux')
        stdlib_before = stdlib_identity(stdlib, roster)
        driver.verify_stdlib(stdlib_before, lock['alpha'])
        dump(output / 'STDLIB_BEFORE.json', stdlib_before)
        for path in (wrapper, compiler, sys.executable, '/usr/bin/bash', '/usr/bin/env', '/bin/sh', '/lib64/ld-linux-x86-64.so.2', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/alternatives'):
            roster.add(path, required=True)
        for root in ('/etc/ld.so.conf.d',):
            if Path(root).is_dir(): roster.directory(root)
        version, errors = commands.run('alpha-version', [str(wrapper), '--version'])
        need(version == lock['alpha']['full_versions']['Linux'] and not errors, 'Actual Alpha full version differs')
        commands.run('brew-installed-origins', [brew, 'info', '--json=v2', '--installed'])
        tools = {}
        for name in ('cc', 'gcc', 'clang', 'ld', 'as', 'ar', 'readelf', 'pkg-config', 'ldconfig'):
            tool = shutil.which(name)
            if tool: tools[name] = roster.add(tool, required=True)
            else: result.setdefault('missing_tools', []).append(name)
        need(all(name in tools for name in ('cc', 'ld', 'as', 'ar', 'readelf', 'pkg-config', 'ldconfig')), 'Required metadata tools must be available')
        dpkg = shutil.which('dpkg-query')
        need(dpkg, 'Ubuntu package receipt metadata is required')
        commands.run('ubuntu-package-origins', [dpkg, '--show', '--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'])
        roster.add('/var/lib/dpkg/status', required=True)
        result['tools'] = tools
        for name in ('cc', 'ld', 'readelf', 'pkg-config'):
            commands.run(name + '-version', [tools[name], '--version'])
        search = commands.run('cc-search-dirs', [tools['cc'], '-print-search-dirs'])[0]
        result['compiler_search_directories_raw'] = search
        for kind in ('include', 'libgcc.a', 'libgcc_s.so.1', 'crtbegin.o'):
            raw = commands.run('cc-' + kind.replace('.', '-'), [tools['cc'], '-print-file-name=' + kind])[0].strip()
            need(raw.startswith('/'), 'Compiler metadata must resolve its native input: ' + kind)
            if kind == 'include': roster.directory(raw)
            else: roster.add(raw, required=True)
        cache = commands.run('loader-cache', [tools['ldconfig'], '-p'])[0]
        cache_map = cache_paths(cache)
        result['loader_cache_entries'] = cache_map
        for header in ('/usr/include/stdio.h', '/usr/include/stdlib.h', '/usr/include/string.h', '/usr/include/limits.h', '/usr/include/stdint.h', '/usr/include/x86_64-linux-gnu/bits/libc-header-start.h', '/usr/include/x86_64-linux-gnu/sys/types.h'):
            roster.add(header, required=True)
        native = {}
        result['required_native_packages'] = native
        for name in ('gmp', 'sqlite3'):
            native[name] = {}
            package_tool, package_environment = tools['pkg-config'], None
            if name == 'sqlite3':
                package_tool, package_environment, control = sqlite_metadata_provider(commands, roster, tools['pkg-config'])
                result['sqlite3_homebrew_metadata_control'] = control
                result['sqlite3_distro_metadata_context'] = {key: package_environment[key]
                    for key in ('PKG_CONFIG_LIBDIR', 'PKG_CONFIG_PATH', 'PKG_CONFIG_SYSROOT_DIR')}
                tools['system-pkg-config'] = package_tool
            native[name]['metadata_provider'] = package_tool
            for kind in ('libdir', 'includedir', 'pcfiledir'):
                value = commands.run(name + '-' + kind, [package_tool, '--variable=' + kind, name], environment=package_environment)[0].strip()
                need(value.startswith('/'), 'Required package search directory is absent: ' + name + '/' + kind)
                if name == 'sqlite3' and kind == 'pcfiledir':
                    need(os.path.normpath(value) in SYSTEM_PKG_CONFIG_DIRECTORIES,
                         'SQLite PC source must come from the explicit distro search roots')
                native[name][kind] = value
                roster.add(value, required=True)
            commands.run(name + '-version', [package_tool, '--modversion', name], environment=package_environment)
            for header in (('gmp.h', 'gmpxx.h') if name == 'gmp' else ('sqlite3.h', 'sqlite3ext.h')):
                roster.add(Path(native[name]['includedir']) / header, required=header in ('gmp.h', 'sqlite3.h'))
            for member in sorted(Path(native[name]['libdir']).glob('lib' + ('gmp' if name == 'gmp' else 'sqlite3') + '*')):
                if member.is_file() or member.is_symlink(): roster.add(member, required=True)
            for member in sorted(Path(native[name]['pcfiledir']).glob(name + '.pc')):
                roster.add(member, required=True)
        result['required_native_packages'] = native
        pending = [str(compiler), str(Path(sys.executable).resolve())] + list(tools.values())
        pending += [path for path, row in roster.entries.items() if row['kind'] == 'file' and ('.so' in Path(path).name or Path(path).name.startswith('ld-linux'))]
        seen = set()
        for wave in range(3):
            physical = []
            for path in sorted(set(pending) - seen):
                resolved = roster.add(path, required=True)
                with Path(resolved).open('rb') as stream: is_elf = stream.read(4) == b'\x7fELF'
                if is_elf: physical.append(resolved)
                seen.add(path)
            need(len(physical) <= 96, 'Static ELF discovery wave exceeds its input budget')
            if not physical: break
            raw = commands.run('elf-wave-' + str(wave), [tools['readelf'], '-W', '-d', '-l', *physical])[0]
            pending = []
            search_directories = [str(brew_root / 'lib'), str(prefix / 'lib')] + elf_search_directories(raw, physical)
            result.setdefault('observed_elf_search_directories', []).extend(search_directories)
            for needed in elf_needed(raw):
                need('/' not in needed and needed not in ('.', '..'), 'ELF dependency names require a simple soname')
                paths = list(cache_map.get(needed, []))
                paths += [str(Path(directory) / needed) for directory in search_directories if (Path(directory) / needed).exists()]
                if not paths: result.setdefault('unresolved_needed', []).append(needed)
                pending.extend(paths)
            for path in extract_absolute_paths(raw):
                if Path(path).exists(): pending.append(path)
        result['static_elf_waves'] = wave + 1
        result['static_resolution_scope'] = 'Union of observed cache, RUNPATH/RPATH and Linuxbrew search candidates; actual loader choice remains unqualified'
        result['observed_elf_search_directories'] = sorted(set(result.get('observed_elf_search_directories', [])))
        result['unvisited_elf_candidates'] = sorted(set(pending) - seen)
        stdlib_after = stdlib_identity(stdlib, roster)
        driver.verify_stdlib(stdlib_after, lock['alpha'])
        need(stdlib_before == stdlib_after, 'Installed standard library changed during metadata collection')
        dump(output / 'STDLIB_AFTER.json', stdlib_after)
        roster.verify()
        pin(Path(sys.executable).resolve(), args.python_sha256)
        pin(__file__, args.source_sha256); pin(args.driver, args.driver_sha256); pin(args.linux_reader, args.linux_reader_sha256); pin(args.source_lock, args.source_lock_sha256)
        result.update(state='candidate-recorded-unreviewed', metadata_collection_passed=True)
    except Exception as error:
        result.update(state='metadata-collection-refused', metadata_collection_passed=False, error=type(error).__name__ + ': ' + str(error))
    finally:
        if roster:
            dump(output / 'NATIVE_PATH_ROSTER.json', {'entries': roster.entries, 'missing': roster.missing, 'hashed_bytes': roster.total_bytes, 'entry_count': len(roster.entries)})
            result['proposed_original_read_only_mounts'] = list(ORIGINAL_MOUNTS)
            result['paths_outside_original_mounts'] = roster.gaps()
            result['candidate_additional_read_only_roots'] = sorted({('/' + path.split('/')[1] if path.startswith(('/lib/', '/lib64/')) else '/etc/alternatives' if path.startswith('/etc/alternatives') else path) for path in roster.gaps()})
        if runner:
            result['original_group_observations'] = runner.group_observations
            result['writers_confirmed_retired'] = runner.writers_confirmed_retired
            result['command_count'] = len(runner.records)
        result['limits'] = {'seconds': MAX_SECONDS, 'commands': MAX_COMMANDS, 'entries': MAX_FILES, 'hashed_bytes': MAX_HASH_BYTES, 'individual_file_bytes': MAX_FILE_BYTES, 'raw_output_bytes': MAX_METADATA_BYTES, 'per_command_seconds': 45, 'per_command_combined_output_bytes': 4 * 1024**2}
        dump(output / 'PROJECTION_RESULT.json', result)
    return 0 if result.get('metadata_collection_passed') else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'linux-reader', 'source-lock', 'repository', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source', 'driver', 'linux-reader', 'source-lock', 'python'):
        parser.add_argument('--' + name + '-sha256', required=True)
    return collect(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
