"""Prepare returned proof-tool bytes; executable admission belongs to a later review."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
MAX_SECONDS = 840
BUILD_SECONDS = 600
MAX_BINARY = 20 * 2**20
MAX_RAW = 16 * 2**20
LABELS = ('curl-version', 'git-version', 'download-cli', 'download-ameba', 'archive-git-probe', 'build-ameba')

def need(value, message):
    if not value:
        raise RuntimeError(message)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):
    return json.loads(Path(path).read_bytes())

def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def regular(path, maximum=MAX_BINARY):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
         'Bounded regular input required: ' + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(fields(before) == fields(opened) == fields(after) == fields(path.lstat()) and len(raw) == before.st_size,
         'Stable regular input identity required')
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}, raw

def protect_packet(expected):
    manifest = ROOT / 'BOOTSTRAP_SOURCE_PINS.json'
    need(digest(manifest) == expected, 'Exact externally pinned bootstrap packet required')
    rows = read(manifest)['files']
    need(1 <= len(rows) <= 32 and len({r['path'] for r in rows}) == len(rows), 'Bounded unique source packet required')
    protected = {manifest: expected}
    for row in rows:
        relative = PurePosixPath(row['path'])
        need(str(relative) == row['path'] and not relative.is_absolute() and '..' not in relative.parts, 'Canonical packet member required')
        path = ROOT / relative
        observed, raw = regular(path)
        need(observed['bytes'] == row['bytes'] and observed['sha256'] == row['sha256'], 'Bootstrap packet source differs')
        protected[path] = row['sha256']
    return protected

def load(path, expected, name):
    need(digest(path) == expected, 'Imported executable source differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(digest(path) == expected, 'Imported executable source changed during import')
    return module

def extract_exact(archive_path, destination, expected_rows, expected_sha, expected_bytes, prefix=''):
    observed, raw = regular(archive_path, 4 * 2**20)
    need(observed['sha256'] == expected_sha and observed['bytes'] == expected_bytes, 'Exact public archive bytes required')
    expected = {r['path']: r for r in expected_rows}
    need(len(expected) == len(expected_rows), 'Distinct archive members required')
    files, directories, total = {}, set(), 0
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        need(len(members) <= 512, 'Finite public archive header roster required')
        seen = set()
        for member in members:
            name = member.name.rstrip('/')
            need(name not in seen, 'Distinct physical archive header required')
            seen.add(name)
            need(member.isfile() or member.isdir(), 'Archive admits regular files/directories')
            need(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts, 'Contained archive member required')
            if prefix:
                need(name == prefix or name.startswith(prefix + '/'), 'Exact archive source prefix required')
                name = name[len(prefix):].lstrip('/')
            if not name:
                need(member.isdir(), 'Archive source root must be a directory')
                continue
            need(str(PurePosixPath(name)) == name and '.' not in PurePosixPath(name).parts, 'Canonical archive path required')
            if member.isdir():
                if not prefix:
                    need(name in expected and expected[name].get('kind') == 'directory' and member.size == 0 and
                         stat.S_IMODE(member.mode) == int(expected[name]['mode'],8), 'Exact CLI directory metadata required')
                directories.add(name)
                continue
            need(name in expected and member.size == expected[name]['bytes'] and member.size <= MAX_BINARY, 'Exact bounded source/member size required')
            data = archive.extractfile(member).read(MAX_BINARY + 1)
            row = expected[name]
            need(hashlib.sha256(data).hexdigest() == row['sha256'], 'Archive member SHA-256 differs')
            if 'git_blob_sha1' in row:
                need(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob_sha1'], 'Archive Git blob differs')
                mode = 0o755 if member.mode & 0o111 else 0o644
                need(('100755' if mode == 0o755 else '100644') == row['git_mode'], 'Archive source executable mode differs')
            else:
                mode = int(row['mode'], 8)
                need(stat.S_IMODE(member.mode) == mode, 'CLI member mode differs')
            total += len(data)
            need(total <= 24 * 2**20, 'Finite expanded public source bytes required')
            files[name] = (data, mode)
    expected_files = {n for n,r in expected.items() if r.get('kind', 'regular') != 'directory'}
    need(set(files) == expected_files, 'Complete source/member file roster required')
    allowed_dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
    need(directories == allowed_dirs, 'Complete archive directory roster belongs to exact source files')
    destination.mkdir()
    for name, (data, mode) in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    return inventory(destination)

def inventory(root):
    rows = []
    for path in sorted(Path(root).rglob('*')):
        need(not path.is_symlink(), 'Physical source/member tree required')
        if path.is_dir():
            continue
        row, _ = regular(path)
        rows.append({'path': path.relative_to(root).as_posix(), **{k:row[k] for k in ('bytes', 'sha256', 'mode')}})
    need(len(rows) <= 512, 'Bounded full source tree required')
    return rows

def macho(path):
    row, raw = regular(path)
    need(len(raw) >= 32 and raw[:4] == b'\xcf\xfa\xed\xfe' and
         struct.unpack_from('<I', raw, 4)[0] == 0x100000c and struct.unpack_from('<I', raw, 12)[0] == 2 and
         row['mode'] & 0o100, 'Returned native ARM64 Mach-O executable bytes required')
    return row

def build_environment(private, git):
    bindir = private / 'tool-bin'
    bindir.mkdir()
    alias = bindir / 'git'
    alias.symlink_to(git)
    home = private / 'home'
    home.mkdir()
    environment = {k:v for k,v in os.environ.items() if k in ('PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'SDKROOT', 'DEVELOPER_DIR')}
    environment.update(HOME=str(home), PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''),
        CRYSTAL_WORKERS='1', CRYSTAL_CACHE_DIR=str(private / 'cache'), AMEBA_BUILD_VERSION='1.7.0-dev',
        NO_COLOR='1', LC_ALL='C', GIT_CEILING_DIRECTORIES=str(private), GIT_CONFIG_NOSYSTEM='1',
        GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_COUNT='0', GIT_OPTIONAL_LOCKS='0')
    return environment, {'path':str(alias), 'target':os.readlink(alias), 'resolved_path':str(alias.resolve(strict=True))}

def compiler_color(record, stdout, stderr):
    warnings = bool(re.search(r'\bwarning\s*:', stdout + stderr, re.I))
    return ('RED' if record['exit_code'] != 0 else 'YELLOW' if warnings else 'GREEN'), warnings

def execute(args, driver, context, protected):
    started = context.get('started_monotonic', time.monotonic())
    need(args.output.parent.resolve(strict=True) == args.output.parent and not args.output.exists() and not args.output.is_symlink(), 'Fresh physical owned output required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = output / 'private'
    private.mkdir()
    (output / 'inputs').mkdir()
    (output / 'tools').mkdir()
    runner = driver.Runner(output)
    runner.deadline = min(runner.deadline, started + MAX_SECONDS)
    result = {'format':'grant-proof-tool-bootstrap-v1', 'preparation_complete':False, 'execution_admitted':False,
        'compiler_color':'UNEXECUTED', 'maximum_seconds':MAX_SECONDS, 'build_seconds':BUILD_SECONDS,
        'job_identity':context['job_identity'], 'same_job_profile_sha256':context['observed_profile_sha256'],
        'actual_tool_executions':0, 'lint_execution_accepted':False, 'API_lookup_accepted':False,
        'feedback_hook_accepted':False, 'whole_build_qualification':False, 'Grant_target_cells_accepted':0,
        'finalization_errors':[], 'pending':['Independent returned binary/provider admission',
            'Actual Ameba lint behavior', 'Actual-project Amber LSP lookup/diagnostics', 'Genuine feedback hook/format/spec gates']}
    write(output/'SDK_ADMISSION.json',context.get('admitted_receipt',{
        'job_identity':context['job_identity'],'observed_profile_sha256':context['observed_profile_sha256']}))
    providers = {}
    before_ameba = before_cli = None
    environment = alias = None
    try:
        providers = {k:regular(Path(v))[0] for k,v in context['paths'].items()}
        write(output / 'PROVIDERS_BEFORE.json', providers)
        for name, row in providers.items():
            need(row['sha256'] == context['hashes'][name], 'Exact admitted/observed provider bytes required: ' + name)
        before_stdlib = driver.tree_identity(context['stdlib'])
        need(before_stdlib == context['stdlib_identity'], 'Same admitted ordinary installed stdlib required')
        write(output / 'STDLIB_BEFORE.json', before_stdlib)
        runner.run('curl-version', [context['paths']['curl'], '--version'], cwd=private, seconds=15)
        runner.run('git-version', [context['paths']['git'], '--version'], cwd=private, seconds=15)
        need((output/'git-version.stdout.txt').read_text().startswith('git version '), 'Real Git version metadata required')
        cli = read(ROOT / 'inputs/CLI_ARCHIVE_IDENTITY.json')
        ameba = read(ROOT / 'inputs/AMEBA_ARCHIVE_IDENTITY.json')
        full = read(ROOT / 'inputs/AMEBA_COMPLETE_TREE_READBACK.json')
        need(full['passed'] is True and full['row_count'] == len(full['rows']) == 372 and
             full['git_tree_sha1'] == ameba['expected_git_tree'] == '5fe9fbff073fc9a41923f19d8a43b9b35a528ac8', 'Exact complete reviewed372-member Ameba source required')
        for label, url, size, filename in [('download-cli', cli['archive']['url'], cli['archive']['size'], 'cli.tar.gz'),
             ('download-ameba', ameba['archive_url'], ameba['archive_bytes'], 'ameba.tar.gz')]:
            runner.run(label, [context['paths']['curl'], '--fail', '--location', '--silent', '--show-error',
                '--proto', '=https', '--tlsv1.2', '--connect-timeout', '15', '--max-time', '30',
                '--max-filesize', str(size), '--output', str(output / 'inputs' / filename), url], cwd=private, seconds=45)
        before_cli = extract_exact(output/'inputs/cli.tar.gz', private/'cli', cli['rows'], cli['archive']['digest'].split(':')[1], cli['archive']['size'])
        before_ameba = extract_exact(output/'inputs/ameba.tar.gz', private/'ameba', full['rows'], ameba['archive_sha256'], ameba['archive_bytes'], 'ameba-'+ameba['source_commit'])
        write(output/'SOURCE_BEFORE.json', {'cli':before_cli,'ameba':before_ameba})
        environment, alias = build_environment(private, context['paths']['git'])
        result['build_environment'] = {k:v for k,v in environment.items() if k not in ('PATH', 'TMPDIR', 'SDKROOT', 'DEVELOPER_DIR')}
        result['Git_alias'] = alias
        runner.run('archive-git-probe', [context['paths']['git'], 'rev-parse', '--short', 'HEAD'],
                   cwd=private/'ameba', environment=environment, expected_exit=128, seconds=15)
        need(not (output/'archive-git-probe.stdout.txt').read_bytes() and
             'not a git repository' in (output/'archive-git-probe.stderr.txt').read_text().lower(), 'Actual archive-only Git fallback refusal required')
        need(runner.deadline - time.monotonic() >= BUILD_SECONDS + 5, 'Complete600-second build budget plus finite launch reserve required before compilation')
        command = [context['paths']['compiler_wrapper'], 'build', 'src/cli.cr', '--release', '--threads', '1', '--error-on-warnings', '-Dwithout_mt', '-o', str(output/'tools/ameba')]
        result['compile_argv'] = [str(v) for v in command]
        try:
            runner.run('build-ameba', command, cwd=private/'ameba', environment=environment, seconds=BUILD_SECONDS)
        finally:
            if runner.records and runner.records[-1]['label'] == 'build-ameba' and runner.writers_confirmed_retired:
                stdout, stderr = [(output/('build-ameba.'+s+'.txt')).read_text() for s in ('stdout','stderr')]
                result['compiler_color'], result['warnings_present'] = compiler_color(runner.records[-1], stdout, stderr)
        need(result['compiler_color'] == 'GREEN', 'GREEN complete Ameba build required')
        need([r['label'] for r in runner.records] == list(LABELS), 'Exact six-command preparation roster required')
        need(runner.records[-1]['maximum_seconds'] == BUILD_SECONDS, 'Original600-second build maximum required without shortening')
        returned_ameba = macho(output/'tools/ameba')
        for original, destination in [(private/'cli/amber-lsp',output/'tools/amber-lsp'),
                (private/'cli/share/amber_cli/api/crystal.yml',output/'tools/crystal.yml')]:
            shutil.copyfile(original, destination)
            destination.chmod(original.stat().st_mode & 0o777)
        returned_lsp = macho(output/'tools/amber-lsp')
        card = regular(output/'tools/crystal.yml')[0]
        result['returned_tools'] = {'ameba':returned_ameba, 'amber_lsp':returned_lsp, 'api_card':card}
        result['preparation_complete'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        for name, check in [('sources/providers',lambda: [need(digest(p)==h,'Protected source/provider changed: '+str(p)) for p,h in protected.items()]),
             ('SDK source metadata', context['revalidate']),
             ('stdlib',lambda: need(driver.tree_identity(context['stdlib']) == context['stdlib_identity'], 'Installed stdlib changed'))]:
            try:
                check()
            except Exception as error:
                result['preparation_complete'] = False
                result['finalization_errors'].append(name+': '+type(error).__name__+': '+str(error))
        try:
            after = {k:regular(Path(v))[0] for k,v in context['paths'].items()}
            need(after == providers, 'Exact provider fingerprints required on return')
            write(output/'PROVIDERS_AFTER.json',after)
            write(output/'STDLIB_AFTER.json',driver.tree_identity(context['stdlib']))
            if before_ameba is not None:
                need(inventory(private/'ameba') == before_ameba and inventory(private/'cli') == before_cli, 'Exact source/member fingerprints required on return')
                write(output/'SOURCE_AFTER.json', {'cli':before_cli,'ameba':before_ameba})
            if alias is not None:
                need((private/'tool-bin/git').is_symlink() and os.readlink(private/'tool-bin/git') == alias['target'] and
                     str((private/'tool-bin/git').resolve(strict=True)) == alias['resolved_path'], 'Real pinned Git alias changed')
        except Exception as error:
            result['preparation_complete'] = False
            result['finalization_errors'].append('Return fingerprints: '+type(error).__name__+': '+str(error))
        result['writers_confirmed_retired'] = runner.writers_confirmed_retired
        result['original_group_observations'] = runner.group_observations
        if runner.writers_confirmed_retired:
            try:
                shutil.rmtree(private)
            except Exception as error:
                result['preparation_complete'] = False
                result['finalization_errors'].append('Private cleanup: '+type(error).__name__+': '+str(error))
        else:
            result['preparation_complete'] = False
            result['finalization_errors'].append('Original writers remain unverified; private working files preserved')
        result['private_working_directory_removed'] = not private.exists()
        result['terminal_elapsed_seconds'] = time.monotonic()-started
        if result['terminal_elapsed_seconds'] > MAX_SECONDS:
            result['preparation_complete'] = False
            result['finalization_errors'].append('Complete preparation terminal deadline exceeded')
        result['command_count'] = len(runner.records)
        raw_size = sum(p.stat().st_size for p in output.glob('*.txt'))
        if raw_size > MAX_RAW:
            result['preparation_complete'] = False
            result['finalization_errors'].append('Aggregate raw output budget exceeded')
        write(output/'BOOTSTRAP_RESULT.json',result)
        registry = {'format':'atlas-proof-tool-registry-draft-v1', 'execution_admitted':False,
            'preparation_complete':result['preparation_complete'], 'compiler_color':result['compiler_color'],
            'actual_tool_executions':0, 'AMEBA_BUILD_VERSION':'1.7.0-dev',
            'ameba_source_commit':'cdd58b34b0d8a9c785d67183a7a8f07541549e55',
            'ameba_source_tree':'5fe9fbff073fc9a41923f19d8a43b9b35a528ac8',
            'ameba_archive_sha256':'a0e91d582e0617b15c1bd3448c2d0db60c86454aa4d19887fcb6ee08d4ddf259',
            'cli_source_commit':'faed4b205063a84650b00e2dc02f01793f373527', 'cli_release':'v2.0.7',
            'sdk_profile_sha256':context['observed_profile_sha256'], 'job_identity':context['job_identity'],
            'providers':{k:dict(v,execution_admitted=False) for k,v in result.get('returned_tools',{}).items()},
            'required_next_step':'Independent binary/source/provider review and separately admitted successor before any tool execution'}
        write(output/'DRAFT_TOOL_REGISTRY.json',registry)
    return 0 if result['preparation_complete'] else 2

def prepare(args):
    started = time.monotonic()
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64' and os.environ.get('GITHUB_ACTIONS') == 'true', 'Actual bootstrap belongs to hosted Mac ARM64')
    protected = protect_packet(args.packet_sha256)
    inputs = read(ROOT/'BOOTSTRAP_INPUT_PINS.json')
    for row in inputs['base_files']:
        path = args.repository/row['path']
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'], 'Exact accepted public base dependency required')
        protected[path] = row['sha256']
    policy_path = args.repository/'test/grant_assignment_cost/same_job_policy.py'
    policy = load(policy_path, protected[policy_path], 'bootstrap_reviewed_same_job_policy')
    protected.update(policy.protect_packet(inputs['base_files'][4]['sha256']))
    admitted = policy.metadata(args.sdk_evidence, os.environ)
    driver_path = args.repository/'test/sdk_install_qualification.py'
    driver = load(driver_path, policy.DRIVER_SHA256, 'bootstrap_reviewed_sdk_runner')
    need(admitted['runner']['python_sha256'] == args.python_sha256 and digest(Path(sys.executable).resolve()) == args.python_sha256, 'Same actual SDK Python provider required')
    paths = {k:v['path'] for k,v in admitted['providers'].items()}
    paths.update(curl=str(args.curl.resolve(strict=True)), git=str(args.git.resolve(strict=True)), python=str(Path(sys.executable).resolve()))
    hashes = {k:v['sha256'] for k,v in admitted['providers'].items()}
    hashes.update(curl=args.curl_sha256, git=args.git_sha256, python=args.python_sha256)
    for key,path in paths.items():
        need(digest(path) == hashes[key], 'Exact actual installed provider hash required: '+key)
        protected[Path(path)] = hashes[key]
    wrapper = Path(paths['compiler_wrapper'])
    prefix = Path((args.sdk_evidence/'brew-prefix.stdout.txt').read_text().strip()).resolve(strict=True)
    stdlib = prefix/'share/agent-crystal/src'
    need(wrapper == prefix/'bin/crystal-alpha' and Path(paths['compiler_backend']) == prefix/'libexec/agent-crystal-bin', 'Exact ordinary installed Alpha wrapper/backend join required')
    driver.verify_wrapper(wrapper.read_text(),Path(paths['compiler_backend']),stdlib,
        Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip()),'Darwin')
    for name,relative in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
        path=prefix/relative
        need(digest(path)==digest(args.sdk_evidence/name),'Exact current installed package source/receipt required')
        protected[path]=digest(path)
    sdk_before=policy.roster(args.sdk_evidence)
    def revalidate():
        policy.metadata(args.sdk_evidence,os.environ)
        need(policy.roster(args.sdk_evidence)==sdk_before,'Original same-job SDK evidence changed')
    context={'paths':paths,'hashes':hashes,'stdlib':stdlib,'stdlib_identity':admitted['stdlib'],
        'job_identity':admitted['job_identity'],'observed_profile_sha256':admitted['observed_profile_sha256'],
        'revalidate':revalidate,'started_monotonic':started,'admitted_receipt':admitted}
    return execute(args,driver,context,protected)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','sdk-evidence','output','curl','git'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python','curl','git'):
        parser.add_argument('--'+name+'-sha256',required=True)
    raise SystemExit(prepare(parser.parse_args()))
