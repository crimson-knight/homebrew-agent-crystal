"""Verify finite hosted analysis-tool transfer and collect pinned runtime admission inputs."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
TRANSFER_SECONDS = 180
OBSERVATION_SECONDS = 120
SHARED_CLOCK = 'POSIX.CLOCK_MONOTONIC'
LOCAL_CLOCK = 'process-local.time.monotonic'
MAX_FILES = 37
MAX_FILE_BYTES = 32 * 2**20
MAX_TOTAL_BYTES = 96 * 2**20
MAX_NATIVE_FILES = 24
MAX_NATIVE_PATHS = 96
PREPARATION = dict(GITHUB_RUN_ID='39518892906', GITHUB_RUN_ATTEMPT='1',
    GITHUB_SHA='104d2c253614ee969ba2f9284ca9a4ee4f20c192', GITHUB_JOB='grant-installed-mac',
    RUNNER_NAME='GitHub Actions 1000019248', RUNNER_OS='macOS', RUNNER_ARCH='ARM64')
PACKAGES = {'openssl@3': '3.5.9', 'libyaml': '0.2.5', 'pcre2': '10.49', 'bdw-gc': '8.2.12'}
SYSTEM_IMPORTS = ('/usr/lib/libSystem.B.dylib', '/usr/lib/libiconv.2.dylib')
DIRECT = ('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib',
          '/opt/homebrew/opt/libyaml/lib/libyaml-0.2.dylib',
          '/opt/homebrew/opt/pcre2/lib/libpcre2-8.0.dylib',
          '/opt/homebrew/opt/bdw-gc/lib/libgc.1.dylib')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Unique metadata fields required')
            result[key] = value
        return result
    def finite(token):
        raise RuntimeError('Finite metadata values required: ' + token)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite)


def clock(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() <= deadline,
         'Complete finite transfer/observation deadline required')


def finite_clock(value):
    need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
         'Finite nonnegative clock value required')
    return value


def shared_monotonic():
    need(hasattr(time, 'CLOCK_MONOTONIC') and hasattr(time, 'clock_gettime'),
         'POSIX CLOCK_MONOTONIC provider required for cross-process deadlines')
    return finite_clock(time.clock_gettime(time.CLOCK_MONOTONIC))


def local_deadline(shared_deadline):
    """Conservatively translate a shared deadline at its consuming process entry."""
    finite_clock(shared_deadline)
    local = finite_clock(time.monotonic())
    remaining = shared_deadline - shared_monotonic()
    need(math.isfinite(remaining) and remaining >= 0, 'Complete shared-clock deadline required')
    return local + remaining


def shared_deadline(local_limit):
    """Sample shared first so conversion preserves the original local upper bound."""
    finite_clock(local_limit)
    shared = shared_monotonic()
    remaining = local_limit - finite_clock(time.monotonic())
    need(math.isfinite(remaining) and remaining >= 0, 'Complete local-clock deadline required')
    return shared + remaining


def lease_sample(state):
    need(state.get('clock_protocol') == SHARED_CLOCK,
         'Explicit POSIX CLOCK_MONOTONIC transfer lease required')
    started, deadline = finite_clock(state['started']), finite_clock(state['deadline'])
    need(deadline == started + TRANSFER_SECONDS, 'Original fixed transfer clock interval required')
    observed = shared_monotonic()
    elapsed = observed - started
    need(math.isfinite(elapsed) and 0 <= elapsed <= TRANSFER_SECONDS,
         'Finite nonnegative elapsed inside original180-second shared-clock lease required')
    return observed, elapsed


def physical(path, directory=False):
    path = Path(path)
    need(path.is_absolute(), 'Absolute physical path required')
    for parent in reversed((path, *path.parents)[:-1]):
        current = parent.lstat()
        need(stat.S_ISDIR(current.st_mode) if parent != path or directory else stat.S_ISREG(current.st_mode),
             'Ordinary physical directory/file required: ' + str(parent))
    return path


def identity(path):
    value = path.lstat()
    return [value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def protect_transfer(expected):
    path = ROOT / 'TRANSFER_SOURCE_PINS.json'
    raw = path.read_bytes()
    need(sha(raw) == expected, 'Exact externally pinned transfer source manifest required')
    rows = decode(raw)['files']
    need(0 < len(rows) <= 48 and len({row['path'] for row in rows}) == len(rows),
         'Finite unique additive transfer source roster required')
    budget = Budget(time.monotonic() + 30)
    protected = {path: expected}
    for row in rows:
        current = ROOT / contained(row['path'])
        value = budget.read(current, 8 * 2**20)
        need(type(row['bytes']) is int and len(value) == row['bytes'] and sha(value) == row['sha256'],
             'Exact additive transfer execution source required: ' + row['path'])
        protected[current] = row['sha256']
    return protected


class Budget:
    def __init__(self, deadline):
        self.deadline = deadline
        self.bytes = 0

    def read(self, path, maximum=MAX_FILE_BYTES):
        clock(self.deadline)
        path = physical(path)
        before = identity(path)
        need(0 <= before[3] <= maximum, 'Bounded ordinary metadata/tool file required')
        self.bytes += before[3]
        need(self.bytes <= MAX_TOTAL_BYTES, 'Finite aggregate metadata/tool read bound required')
        value = bytearray()
        need(path.stat().st_nlink == 1, 'Private ordinary single-link file required')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            need([getattr(os.fstat(stream.fileno()), name) for name in
                  ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')] == before,
                 'Exact opened physical file identity required')
            while len(value) <= maximum:
                clock(self.deadline)
                block = stream.read(min(1024 * 1024, maximum + 1 - len(value)))
                if not block:
                    break
                value.extend(block)
        need(identity(path) == before and len(value) == before[3], 'Stable complete physical file required')
        clock(self.deadline)
        return bytes(value)


def contained(name):
    value = PurePosixPath(name)
    need(str(value) == name and not value.is_absolute() and value.parts and
         all(part not in ('.', '..', '.git') for part in value.parts) and '\\' not in name,
         'Canonical contained artifact path required')
    return value


def files_in(root, maximum):
    physical(root, directory=True)
    result = []
    def failed(error):
        raise RuntimeError('Complete physical artifact traversal required') from error
    for directory, directories, files in os.walk(root, followlinks=False, onerror=failed):
        need(len(directories) + len(files) <= 128, 'Finite directory entries required')
        for name in directories:
            physical(Path(directory) / name, directory=True)
        for name in files:
            path = physical(Path(directory) / name)
            result.append(str(path.relative_to(root)))
            need(len(result) <= maximum, 'Finite exact artifact file roster required')
    return sorted(result)


def verify_artifact(root, budget):
    accepted_raw = budget.read(ROOT / 'transfer_inputs/ACTUAL_PREPARATION_ACCEPTANCE.json')
    need(sha(accepted_raw) == '4746c10993e99cdadcdcfe4c082fa615b53040db9c97a32653cfb8c93e7089c5',
         'Exact independent actual tool preparation acceptance required')
    accepted = decode(accepted_raw)
    need(accepted['accepted'] is True and type(accepted['run_id']) is int and accepted['run_id'] == 39518892906 and
         type(accepted['job_id']) is int and accepted['job_id'] == 118957638252 and
         accepted['head_sha'] == PREPARATION['GITHUB_SHA'] and accepted['artifact_files'] == 37 and
         accepted['returned_tools_execution_admitted'] is False and accepted['selected_native_loader_closure_accepted'] is False,
         'Exact independently accepted source/job/artifact and pending native scope required')
    roster = decode(budget.read(ROOT / 'transfer_inputs/ARTIFACT_MEMBERS.json'))
    rows = roster['files']
    need(len(rows) == MAX_FILES and len({row['path'] for row in rows}) == MAX_FILES,
         'Exact unique37-member preparation artifact roster required')
    need(files_in(root, MAX_FILES) == sorted(row['path'] for row in rows),
         'Complete exact37-member artifact required')
    expected_directories = {str(parent) for row in rows for parent in contained(row['path']).parents if str(parent) != '.'}
    observed_directories = {str((Path(directory) / name).relative_to(root))
                            for directory, directories, files in os.walk(root) for name in directories}
    need(expected_directories == observed_directories, 'Exact artifact directory roster required')
    values = {}
    for row in rows:
        path = root / contained(row['path'])
        raw = budget.read(path)
        # The supported transfer can canonicalize executable modes to0644.
        # Canonical destination modes come from the accepted source roster.
        mode = stat.S_IMODE(path.stat().st_mode)
        need(mode in ({0o644, 0o755} if row['path'] in ('tools/ameba', 'tools/amber-lsp') else {0o644}),
             'Expected transferred regular-file mode required')
        need(type(row['bytes']) is int and len(raw) == row['bytes'] and sha(raw) == row['sha256'],
             'Exact accepted artifact member bytes required: ' + row['path'])
        values[row['path']] = raw
    result = decode(values['BOOTSTRAP_RESULT.json'])
    registry = decode(values['DRAFT_TOOL_REGISTRY.json'])
    need(result['preparation_complete'] is True and result['compiler_color'] == 'GREEN' and
         result['execution_admitted'] is False and result['writers_confirmed_retired'] is True and
         result['private_working_directory_removed'] is True and result['finalization_errors'] == [] and
         result['job_identity'] == registry['job_identity'] == PREPARATION,
         'Exact retired GREEN preparation source/job with separate execution admission required')
    pins_raw = values['source/BOOTSTRAP_SOURCE_PINS.json']
    need(pins_raw == budget.read(ROOT / 'transfer_inputs/BOOTSTRAP_SOURCE_PINS.json'),
         'Exact independently reviewed preparation source manifest required')
    for row in decode(pins_raw)['files']:
        raw = values['source/' + str(contained(row['path']))]
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'Complete preparation source ancestry required')
    need(result['actual_tool_executions'] == 0 and registry['actual_tool_executions'] == 0,
         'Preparation retains its actual tool-execution boundary')
    return values


def native_imports(raw):
    need(len(raw) >= 32 and struct.unpack_from('<II', raw) == (0xFEEDFACF, 0x100000C),
         'Native ARM64 little-endian Mach-O required')
    count, size = struct.unpack_from('<II', raw, 16)
    need(0 < count <= 256 and 0 < size <= 1024 * 1024 and 32 + size <= len(raw),
         'Finite complete Mach-O command table required')
    offset = 32
    paths = []
    for _ in range(count):
        need(offset + 8 <= 32 + size, 'Complete native load-command header required')
        command, length = struct.unpack_from('<II', raw, offset)
        need(length >= 8 and length % 4 == 0 and offset + length <= 32 + size,
             'Bounded native load command required')
        if command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            need(length >= 24, 'Complete dylib command required')
            name = struct.unpack_from('<I', raw, offset + 8)[0]
            need(24 <= name < length, 'Contained dylib string required')
            value = raw[offset + name:offset + length]
            need(b'\0' in value, 'Terminated native dependency required')
            paths.append(value.split(b'\0', 1)[0].decode('utf-8'))
        offset += length
    need(offset == 32 + size and len(paths) == len(set(paths)), 'Complete unique native import table required')
    return sorted(paths)


def materialize(root, output, budget):
    values = verify_artifact(root, budget)
    need(not output.exists() and not output.is_symlink(), 'Fresh private canonical tool directory required')
    physical(output.parent, directory=True)
    output.mkdir(mode=0o700)
    mapping = {'tools/amber-lsp': 'amber-lsp', 'tools/ameba': 'ameba',
               'tools/crystal.yml': 'share/amber_cli/api/crystal.yml'}
    rows = []
    for source, destination in mapping.items():
        path = output / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(values[source])
        path.chmod(0o644 if source.endswith('.yml') else 0o755)
        raw = budget.read(path)
        need(raw == values[source], 'Exact canonical copied tool/corpus bytes required')
        rows.append(dict(path=str(path), bytes=len(raw), sha256=sha(raw),
                         mode=stat.S_IMODE(path.stat().st_mode), physical_identity=identity(path)))
    declared = decode(budget.read(ROOT / 'transfer_inputs/STATIC_TOOL_LOAD_COMMANDS.json'))
    for row in declared:
        raw = budget.read(output / mapping[row['member']])
        need(sha(raw) == row['sha256'] and native_imports(raw) == sorted(item['path'] for item in row['load_commands']),
             'Exact accepted tool and complete static direct native imports required')
    return rows


def resolve_native(lexical):
    path = Path(lexical)
    need(path.is_absolute() and str(path) == lexical and '..' not in path.parts,
         'Canonical absolute native lexical path required')
    pending = list(path.parts[1:])
    current = Path('/')
    links = []
    while pending:
        component = pending.pop(0)
        if component == '..':
            current = current.parent
            continue
        if component == '.':
            continue
        current = current / component
        before = identity(current)
        if stat.S_ISLNK(before[2]):
            need(len(links) < 32, 'Finite32-link native resolution required')
            target = os.readlink(current)
            need(0 < len(target) <= 4096 and identity(current) == before,
                 'Stable bounded native symlink target required')
            links.append(dict(path=str(current), target=target, physical_identity=before))
            target_path = Path(target)
            if target_path.is_absolute():
                pending = list(target_path.parts[1:]) + pending
                current = Path('/')
            else:
                pending = list(target_path.parts) + pending
                current = current.parent
        else:
            need(stat.S_ISDIR(before[2]) if pending else stat.S_ISREG(before[2]),
                 'Physical native directory/regular library required')
    physical(current)
    for link in links:
        alias = Path(link['path'])
        need(identity(alias) == link['physical_identity'] and os.readlink(alias) == link['target'],
             'Complete native lexical alias identity/target return required')
    return dict(declared_path=lexical, resolved_path=str(current), links=links,
                resolved_physical_identity=identity(current))


def tool_return(root, budget):
    value = decode(budget.read(root / 'TRANSFER_RESULT.json'))
    need(value['passed'] is True and len(value['tools']) == 3, 'Complete successful original tool transfer required')
    expected = [('amber-lsp', 0o755), ('ameba', 0o755), ('share/amber_cli/api/crystal.yml', 0o644)]
    for row, (relative, mode) in zip(value['tools'], expected):
        path = root / 'tools' / relative
        raw = budget.read(path)
        need(row['path'] == str(path) and row['mode'] == mode == stat.S_IMODE(path.stat().st_mode) and
             row['physical_identity'] == identity(path) and row['bytes'] == len(raw) and row['sha256'] == sha(raw),
             'Exact original copied tool/corpus bytes/modes/physical identities required')
    return value


def collect_native(budget, admission, prefix=Path('/opt/homebrew')):
    need(admission['job_identity']['RUNNER_OS'] == 'macOS' and admission['job_identity']['RUNNER_ARCH'] == 'ARM64',
         'Exact same-job ARM64 Mac SDK authority required')
    packages = []
    all_dependencies = decode(budget.read(Path(admission['providers']['compiler_wrapper']['path']).parent.parent / 'INSTALL_RECEIPT.json'))['runtime_dependencies']
    for name, version in PACKAGES.items():
        current = [row for row in all_dependencies if row['full_name'] == name]
        need(len(current) == 1 and current[0]['version'] == version and type(current[0]['revision']) is int,
             'Exact preparation-declared same-job native dependency version required: ' + name)
        alias = prefix / 'opt' / name
        alias_stat = alias.lstat()
        need(stat.S_ISLNK(alias_stat.st_mode), 'Physical Homebrew opt alias required')
        target = alias.resolve(strict=True)
        need(target.parent == prefix / 'Cellar' / name and target.name == current[0]['pkg_version'],
             'Exact installed package version and contained opt alias required')
        physical(target, directory=True)
        receipt_path = target / 'INSTALL_RECEIPT.json'
        formula_path = target / '.brew' / (name + '.rb')
        receipt_raw = budget.read(receipt_path, 2**20)
        formula_raw = budget.read(formula_path, 2**20)
        receipt = decode(receipt_raw)
        need(receipt['source']['versions']['stable'] == version and receipt['arch'] == 'arm64',
             'Exact physical installed native receipt version/architecture required')
        packages.append(dict(name=name, declared=current[0], opt_path=str(alias),
            opt_target=os.readlink(alias), opt_identity=identity(alias), physical_prefix=str(target),
            prefix_identity=identity(target), receipt_sha256=sha(receipt_raw), receipt_identity=identity(receipt_path),
            formula_sha256=sha(formula_raw), formula_identity=identity(formula_path)))
    pending = list(DIRECT)
    rows = []
    systems = set()
    visited = {}
    resolutions = {}
    while pending:
        clock(budget.deadline)
        lexical = pending.pop(0)
        if lexical in SYSTEM_IMPORTS:
            systems.add(lexical)
            continue
        need(lexical.startswith(str(prefix / 'opt') + '/') and '..' not in PurePosixPath(lexical).parts,
             'Reviewed absolute Homebrew or Apple native dependency path required')
        resolved = resolve_native(lexical)
        path = Path(resolved['resolved_path'])
        if lexical in resolutions:
            need(resolutions[lexical] == resolved, 'One stable lexical native resolution within observation required')
        else:
            resolutions[lexical] = resolved
            need(len(resolutions) <= MAX_NATIVE_PATHS, 'Finite96-path lexical native frontier required')
        need(any(str(path).startswith(row['physical_prefix'] + '/') for row in packages),
             'Selected native dependency remains inside the four declared exact packages')
        if str(path) in visited:
            need(resolved['resolved_physical_identity'] == visited[str(path)],
                 'Exact previously observed physical native provider required')
            continue
        visited[str(path)] = resolved['resolved_physical_identity']
        need(len(visited) <= MAX_NATIVE_FILES, 'Finite24-file transitive native frontier required')
        raw = budget.read(path)
        imports = native_imports(raw)
        pending.extend(imports)
        rows.append(dict(declared_path=lexical, path=str(path), sha256=sha(raw), bytes=len(raw),
                         mode=stat.S_IMODE(path.stat().st_mode), physical_identity=identity(path), imports=imports))
        need(identity(path) == resolved['resolved_physical_identity'], 'Stable resolved native file identity required')
    need(systems == set(SYSTEM_IMPORTS), 'Complete accepted Apple import names required')
    system_rows = []
    unresolved_system = []
    for name in ('/System/Library/CoreServices/SystemVersion.plist', '/usr/lib/dyld'):
        path = Path(name)
        if path.exists() and not path.is_symlink():
            raw = budget.read(path)
            system_rows.append(dict(path=name, sha256=sha(raw), bytes=len(raw), physical_identity=identity(path)))
        else:
            unresolved_system.append(name)
    return dict(format='atlas-grant-analysis-tool-native-observation-v1', packages=packages,
        libraries=sorted(rows, key=lambda row: row['path']), Apple_imports=sorted(systems),
        lexical_resolutions=sorted(resolutions.values(), key=lambda row: row['declared_path']),
        system_files=system_rows, unresolved_system=unresolved_system, same_job=admission['job_identity'],
        SDK_profile_sha256=admission['observed_profile_sha256'], image_version=admission['runner']['image_version'],
        dyld_cache_bytes_qualified=False, full_native_memory_qualified=False)


def policy_view(value):
    """Keep reviewed identities while per-job physical IDs join before/after."""
    return dict(packages=[{key: row[key] for key in ('name', 'declared', 'opt_path', 'opt_target', 'physical_prefix', 'formula_sha256')}
                          for row in value['packages']],
                libraries=[{key: row[key] for key in ('declared_path', 'path', 'sha256', 'bytes', 'mode', 'imports')}
                           for row in value['libraries']],
                lexical_resolutions=[dict(declared_path=row['declared_path'], resolved_path=row['resolved_path'],
                    links=[dict(path=link['path'], target=link['target']) for link in row['links']])
                    for row in value['lexical_resolutions']],
                Apple_imports=value['Apple_imports'], unresolved_system=value['unresolved_system'],
                system_files=[{key: row[key] for key in ('path', 'sha256', 'bytes')} for row in value['system_files']],
                image_version=value['image_version'])


def native_snapshot(root, value, budget):
    """Retain only the finite selected bytes needed for an independent identity readback."""
    selected = []
    for index, row in enumerate(value['libraries']):
        selected.append((Path(row['path']), 'native-data/libraries/%02d.dylib' % index,
                         row['sha256'], row['physical_identity']))
    for row in value['packages']:
        prefix = Path(row['physical_prefix'])
        selected.extend([(prefix / 'INSTALL_RECEIPT.json', 'native-data/packages/' + row['name'] + '/INSTALL_RECEIPT.json',
                          row['receipt_sha256'], row['receipt_identity']),
                         (prefix / '.brew' / (row['name'] + '.rb'), 'native-data/packages/' + row['name'] + '/FORMULA.rb',
                          row['formula_sha256'], row['formula_identity'])])
    for index, row in enumerate(value['system_files']):
        selected.append((Path(row['path']), 'native-data/system/%02d.bin' % index,
                         row['sha256'], row['physical_identity']))
    need(len(selected) <= 34 and not (root / 'native-data').exists(), 'Fresh finite native identity snapshot required')
    result = []
    for source, name, expected, physical_identity in selected:
        raw = budget.read(source, 20 * 2**20)
        need(sha(raw) == expected and identity(source) == physical_identity,
             'Exact original selected native provider bytes/physical identity required')
        destination = root / contained(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o644)
        result.append(dict(path=name, bytes=len(raw), sha256=expected, original_path=str(source)))
    return result


def registry(output, policy, native):
    need(policy['format'] == 'atlas-grant-analysis-native-policy-v1' and type(policy['execution_admitted']) is bool,
         'Exact source-pinned native policy format required')
    admitted = policy['execution_admitted'] is True
    if admitted:
        import re
        need(type(policy['independent_review_sha256']) is str and
             re.fullmatch('[0-9a-f]{64}', policy['independent_review_sha256']) and
             policy['expected_native'] == policy_view(native) and
             policy['Apple_platform_code_loading_reviewed'] is True,
             'Exact independently reviewed native-input and scoped Apple platform admission required')
    else:
        need(policy['expected_native'] is None, 'First native observation stays explicitly unadmitted')
    original = decode((ROOT / 'PROOF_PROVIDER_ARGUMENTS.json').read_bytes())['tool_fields']
    tools = json.loads(json.dumps(original))
    tools['amber_lsp']['path'] = str(output / 'amber-lsp')
    tools['amber_lsp']['api_corpus_path'] = str(output / 'share/amber_cli/api/crystal.yml')
    tools['ameba']['path'] = str(output / 'ameba')
    tools['ameba']['sha256'] = '107c91a841e5e8ddef95f4bc6b1bc40ff365741eb51b17828844f3a2864ffd3b'
    return dict(format='atlas-grant-hosted-proof-tools-v1', execution_admitted=admitted, tools=tools,
        analysis_tool_source_and_bytes_admitted=True, native_input_policy_sha256=sha(canonical(policy)),
        same_job=native['same_job'], full_native_memory_qualified=False,
        actual_API_lint_compatibility_accepted=False, local_Codex_callback_verified=False)


def initialize(parent):
    parent = physical(parent, directory=True)
    root = Path(tempfile.mkdtemp(prefix='grant-proof-transfer-', dir=str(parent)))
    root.chmod(0o700)
    started = shared_monotonic()
    state = dict(clock_protocol=SHARED_CLOCK, started=started, deadline=started + TRANSFER_SECONDS, root=str(root),
                 python_path=str(Path(sys.executable).resolve()),
                 python_sha256=sha(Path(sys.executable).resolve().read_bytes()))
    (root / 'TRANSFER_CLOCK.json').write_bytes(canonical(state) + b'\n')
    return root


def verify_transfer(root, expected_clock_sha256):
    root = physical(root, directory=True)
    need(stat.S_IMODE(root.stat().st_mode) == 0o700, 'Private owned transfer directory mode0700 required')
    raw = (root / 'TRANSFER_CLOCK.json').read_bytes()
    need(sha(raw) == expected_clock_sha256, 'Exact initialization clock hash from original workflow step required')
    state = decode(raw)
    need(state['root'] == str(root),
         'Original fixed transfer clock/root required')
    initial_sample, initial_elapsed = lease_sample(state)
    need(state['python_path'] == str(Path(sys.executable).resolve()) and
         state['python_sha256'] == sha(Path(sys.executable).resolve().read_bytes()),
         'Exact transfer Python before/after required')
    budget = Budget(local_deadline(state['deadline']))
    rows = materialize(root / 'download', root / 'tools', budget)
    need((root / 'TRANSFER_CLOCK.json').read_bytes() == raw, 'Original transfer clock return required')
    clock(budget.deadline)
    terminal_sample, elapsed = lease_sample(state)
    need(terminal_sample >= initial_sample, 'Nondecreasing shared-clock verification interval required')
    result = dict(format='atlas-grant-proof-tool-transfer-v1', passed=True, actual_tool_executions=0,
        elapsed_seconds=elapsed, maximum_seconds=TRANSFER_SECONDS, clock_protocol=SHARED_CLOCK,
        initial_sample=initial_sample, initial_elapsed_seconds=initial_elapsed,
        terminal_sample=terminal_sample, local_verifier_deadline=budget.deadline,
        artifact_id=12310618101, artifact_archive_sha256='b92262e930c0dfdc5c47ba51c310f1fe0590e7e1a7e72c7a401bcd8bd3fad31a',
        transport_scope='Pinned supported download-artifact interface; all37 member hashes independently enforced; ZIP digest retained from reviewed preparation authority',
        tools=rows, execution_admitted=False, full_native_memory_qualified=False)
    (root / 'TRANSFER_RESULT.json').write_bytes(canonical(result) + b'\n')
    return result


def final_transfer_lease(root, expected_clock_sha256):
    """Include the final execution-source readback inside the original lease."""
    path = root / 'TRANSFER_RESULT.json'
    if not path.exists():
        return
    result = decode(path.read_bytes())
    try:
        raw = (root / 'TRANSFER_CLOCK.json').read_bytes()
        need(sha(raw) == expected_clock_sha256, 'Original transfer clock hash at operation return required')
        observed, elapsed = lease_sample(decode(raw))
        need(observed >= result['terminal_sample'], 'Nondecreasing shared-clock final return required')
        result.update(terminal_sample=observed, elapsed_seconds=elapsed, execution_source_return_inside_lease=True)
    except BaseException as error:
        result.update(passed=False, final_lease_error=type(error).__name__ + ': ' + str(error),
                      execution_source_return_inside_lease=False)
        raise
    finally:
        path.write_bytes(canonical(result) + b'\n')


def observe(root, sdk, policy_path):
    from same_job_policy import metadata
    started = time.monotonic()
    budget = Budget(started + OBSERVATION_SECONDS)
    root = physical(root, directory=True)
    result = dict(format='atlas-grant-proof-tool-runtime-return-v1', passed=False, execution_admitted=False,
                  actual_tool_executions=0, maximum_seconds=OBSERVATION_SECONDS)
    try:
        transfer_raw = budget.read(root / 'TRANSFER_RESULT.json')
        need(decode(transfer_raw)['passed'] is True, 'Successful complete original tool transfer required')
        tool_return(root, budget)
        policy_raw = budget.read(policy_path)
        admission = metadata(sdk, os.environ)
        before = collect_native(budget, admission)
        result['native'] = before
        result['native_policy_view'] = policy_view(before)
        value = registry(root / 'tools', decode(policy_raw), before)
        path = root / 'PROOF_TOOLS.json'
        path.write_bytes(canonical(value) + b'\n')
        # The original proof reader checks exact executable/corpus hash and mode.
        if value['execution_admitted']:
            from dirty_proof import admit_tools
            admit_tools(path, sha(path.read_bytes()))
        need(metadata(sdk, os.environ) == admission and collect_native(budget, admission) == before,
             'Complete same-job SDK/native physical identity return required')
        need(budget.read(policy_path) == policy_raw and budget.read(root / 'TRANSFER_RESULT.json') == transfer_raw,
             'Exact source policy and original transfer evidence return required')
        tool_return(root, budget)
        result['native_evidence_files'] = native_snapshot(root, before, budget)
        result.update(passed=True, execution_admitted=value['execution_admitted'],
                      registry_sha256=sha(path.read_bytes()), same_job=admission['job_identity'])
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        if result['elapsed_seconds'] > OBSERVATION_SECONDS:
            result['passed'] = result['execution_admitted'] = False
            result['deadline_failure'] = True
        (root / 'NATIVE_OBSERVATION.json').write_bytes(canonical(result) + b'\n')
    need(result['passed'], 'Retained failed tool runtime observation')
    return result


def cleanup(root):
    """Retire only the verified private transfer payload; retain every small receipt."""
    started = time.monotonic()
    budget = Budget(started + 30)
    root = physical(root, directory=True)
    need(stat.S_IMODE(root.stat().st_mode) == 0o700 and root.stat().st_uid == os.getuid(),
         'Exact privately owned transfer workspace required for cleanup')
    result = dict(format='atlas-grant-tool-private-cleanup-v1', complete=False, removed=[], preserved=[],
                  actual_tool_recovery_qualified=False, maximum_seconds=30)
    try:
        need(decode(budget.read(root / 'TRANSFER_RESULT.json'))['passed'] is True,
             'Completed supported transfer and verified payload required before cleanup')
        registry_path = root / 'PROOF_TOOLS.json'
        if registry_path.exists() and decode(budget.read(registry_path))['execution_admitted'] is True:
            final = decode(budget.read(root / 'EXPERIMENT_TOOL_RETURN.json'))
            need(final['passed'] is True and final['finalization_errors'] == [],
                 'Completed successful original-group/provider experiment return required before tool cleanup')
        for name, maximum in (('download', 37), ('tools', 3)):
            current = root / name
            if not current.exists():
                continue
            files = files_in(current, maximum)
            for relative in files:
                clock(budget.deadline)
                path = current / contained(relative)
                physical(path)
                path.unlink()
            directories = sorted((Path(directory) / item for directory, names, _ in os.walk(current)
                                  for item in names), key=lambda path: len(path.parts), reverse=True)
            for path in directories:
                clock(budget.deadline)
                path.rmdir()
            current.rmdir()
            result['removed'].append(name)
        result['complete'] = True
    except BaseException as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        result['preserved'] = [name for name in ('download', 'tools') if (root / name).exists()]
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        if result['elapsed_seconds'] > 30:
            result['complete'] = False
        (root / 'CLEANUP.json').write_bytes(canonical(result) + b'\n')
    return result


def operation(args):
    if args.operation == 'initialize':
        root = initialize(args.root)
        print(str(root))
        output = os.environ.get('GITHUB_OUTPUT')
        if output:
            with open(output, 'a') as stream:
                stream.write('workspace=' + str(root) + '\n')
                stream.write('clock_sha256=' + sha((root / 'TRANSFER_CLOCK.json').read_bytes()) + '\n')
    elif args.operation == 'transfer':
        verify_transfer(args.root, args.clock_sha256)
    elif args.operation == 'observe':
        value = observe(args.root, args.sdk_evidence, ROOT / 'ANALYSIS_NATIVE_POLICY.json')
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('execution_admitted=' + str(value['execution_admitted']).lower() + '\n')
    else:
        need(cleanup(args.root)['complete'] is True,
             'Complete private tool payload cleanup required; incomplete return remains a failed operation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('initialize', 'transfer', 'observe', 'cleanup'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--sdk-evidence', type=Path)
    parser.add_argument('--transfer-sha256', required=True)
    parser.add_argument('--clock-sha256')
    args = parser.parse_args()
    protect_transfer(args.transfer_sha256)
    try:
        operation(args)
    finally:
        protect_transfer(args.transfer_sha256)
        if args.operation == 'transfer':
            final_transfer_lease(args.root, args.clock_sha256)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # A canceled/failed action is retained by CI. A started Python operation
        # also retains its original error before propagating the failed status.
        if '--root' in sys.argv:
            root = Path(sys.argv[sys.argv.index('--root') + 1])
            try:
                if root.name.startswith('grant-proof-transfer-') and root.is_dir() and not root.is_symlink():
                    (root / 'OPERATION_FAILURE.json').write_bytes(canonical(dict(
                        format='atlas-grant-tool-operation-failure-v1', operation=sys.argv[1],
                        error=type(error).__name__ + ': ' + str(error), execution_qualified=False)) + b'\n')
            except Exception:
                pass
        raise
