"""Finite metadata admission and return for the unchanged frontend source replay.

The externally selected profile and policy are prerequisites. This module reads
source/runtime metadata; the outer owner selects transport, execution and limits.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import importlib.util
import json
import os
import stat
import time

ROLES = ('qualified_python', 'system_python', 'ruby_launcher', 'ruby_backend',
         'bash', 'sh', 'chmod', 'uname')
STARTUPS = ('qualified_python_isolated', 'system_python_ordinary', 'system_python_sdk_unittest',
            'ruby_yaml_without_gems', 'ruby_installer_ordinary', 'ruby_fixture_backend')
STARTUP_ROLE = dict(zip(STARTUPS, ('qualified_python', 'system_python', 'system_python', 'ruby_launcher',
                                 'ruby_launcher', 'ruby_backend')))
TOTAL_BYTES = 128 * 2**20
RESULT_BYTES = 8 * 2**20
MAX_ROWS = 32768
MAX_RUNTIME_BYTES = 2 * 2**30
MAX_FILE_BYTES = 512 * 2**20
MAX_JSON_BYTES = 4 * 2**20
MAX_SECONDS = 60
SOURCE_SHA = '74a780c27a3abaaa5b2ca92f1b9fe8d56136ef733d8700f2b949e94b430151e8'
IMAGE_SHA = 'ea299e6ec8789d0251d79b8af9364946a628679f11c8081a78988881df56308f'
STARTUP_SOURCE_SHA = '8dad2f3241a35ce2c57629ae1022cf559c027041d23a9594c2cfac132b7f1a8d'
MAX_PLATFORM_AGE_SECONDS = 120


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def state(path):
    s = Path(path).lstat()
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def clock(deadline):
    need(time.monotonic() <= deadline, 'Complete metadata deadline required')


def regular(path, deadline, maximum=MAX_FILE_BYTES):
    clock(deadline)
    p = Path(path)
    before = state(p)
    need(stat.S_ISREG(before[2]) and 0 <= before[3] <= maximum,
         'Finite physical regular file required: ' + str(p))
    value = hashlib.sha256()
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        need(state(p) == before and list_state(os.fstat(stream.fileno())) == before,
             'Exact opened physical identity required')
        remaining = before[3]
        while remaining:
            clock(deadline)
            raw = stream.read(min(65536, remaining))
            need(raw, 'Complete finite file required')
            value.update(raw)
            remaining -= len(raw)
        need(not stream.read(1) and state(p) == before
             and list_state(os.fstat(stream.fileno())) == before,
             'Complete physical file return required')
    return dict(path=str(p), bytes=before[3], mode=stat.S_IMODE(before[2]),
                sha256=value.hexdigest(), physical_identity=before)


def list_state(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_json(path, expected, deadline):
    row = regular(path, deadline, MAX_JSON_BYTES)
    need(row['sha256'] == expected, 'Exact externally selected JSON bytes required')
    raw = Path(path).read_bytes()
    need(digest(raw) == expected and state(path) == row['physical_identity'],
         'Selected JSON read/physical return required')
    return json.loads(raw), row


def relative(value):
    p = PurePosixPath(value)
    need(type(value) is str and str(p) == value and not p.is_absolute()
         and '..' not in p.parts and value not in ('', '.'), 'Contained exact relative path required')
    return value


def lexical(path, deadline):
    """Retain all lexical aliases and every physical ancestor identity."""
    path = Path(path)
    need(path.is_absolute(), 'Absolute runtime provider path required')
    pending = list(path.parts[1:])
    current = Path('/')
    seen = set()
    rows = []
    while pending:
        clock(deadline)
        part = pending.pop(0)
        need(part not in ('.', '..'), 'Normalized provider path required')
        current = current / part
        info = state(current)
        if stat.S_ISLNK(info[2]):
            need(str(current) not in seen and len(seen) < 32, 'Finite acyclic alias chain required')
            seen.add(str(current))
            target = os.readlink(current)
            rows.append(dict(path=str(current), target=target, physical_identity=info))
            resolved = Path(os.path.normpath(str(current.parent / target)))
            pending = list(resolved.parts[1:]) + pending
            current = Path('/')
        elif pending:
            need(stat.S_ISDIR(info[2]), 'Physical directory ancestor required')
            rows.append(dict(path=str(current), directory_identity=info[:3]))
    need(stat.S_ISREG(state(current)[2]), 'Alias must select a physical regular file')
    return str(current), rows


def match(row, actual):
    need(all(row.get(key) == actual[key] for key in ('path', 'bytes', 'mode', 'sha256')),
         'Exact current runtime bytes/mode/path required')


def complete_inventory(root, expected, deadline):
    """Inspect physical root entries before allowing any runtime startup."""
    root = Path(root)
    need(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode),
         'Physical startup root and ancestor chain required')
    need(type(expected) is list and len(expected) <= MAX_ROWS, 'Finite closed startup roster required')
    wanted = {relative(row['path']): row for row in expected}
    need(len(wanted) == len(expected), 'Unique startup paths required')
    found = {}
    stack = [root]
    logical = 0
    while stack:
        directory = stack.pop()
        clock(deadline)
        for entry in sorted(directory.iterdir()):
            need(len(found) < MAX_ROWS, 'Entry capacity required before insertion')
            name = str(entry.relative_to(root))
            info = state(entry)
            if stat.S_ISDIR(info[2]):
                row = dict(path=name, kind='directory', mode=stat.S_IMODE(info[2]))
                stack.append(entry)
            elif stat.S_ISLNK(info[2]):
                target = os.readlink(entry)
                need(not Path(target).is_absolute() and root in entry.resolve().parents,
                     'Contained startup alias required')
                row = dict(path=name, kind='alias', mode=stat.S_IMODE(info[2]), target=target)
            else:
                current = regular(entry, deadline)
                logical += current['bytes']
                need(logical <= MAX_RUNTIME_BYTES, 'Finite startup input byte capacity required')
                row = dict(path=name, kind='file', **{k: current[k] for k in ('bytes', 'mode', 'sha256')})
            need(row == wanted.get(name), 'Exact complete startup root member required: ' + name)
            found[name] = dict(row, physical_identity=info)
    need(set(found) == set(wanted), 'Complete startup inventory coverage required')
    return found


def source_projection(path, expected, owned_root, deadline, in_place=False):
    value, selected = read_json(path, expected, deadline)
    need(len(value['files']) == value['regular_files'] == 707
         and value['logical_bytes'] == 35697410, 'Exact unchanged707 source contract required')
    result = {}
    total = 0
    for row in value['files']:
        name = relative(row['destination'])
        need(name not in result, 'Unique source destination required')
        p = Path(row['source']) if in_place else Path(owned_root) / name
        actual = regular(p, deadline)
        need(all(actual[key] == row[key] for key in ('bytes', 'mode', 'sha256')),
             'Every original source body/mode required')
        if not in_place:
            need(p.resolve() == p and Path(owned_root) in p.parents, 'Physical contained owned source required')
        result[name] = actual
        total += actual['bytes']
    need(total == 35697410, 'Exact unchanged source byte sum required')
    if not in_place:
        projection_tree(owned_root, set(result), deadline)
    return dict(manifest=selected, files=result)


def projection_tree(owned_root, names, deadline):
    """Every projected source top-level tree has exactly its original files."""
    root = Path(owned_root)
    need(root.is_absolute() and root.resolve() == root, 'Physical owned source root required')
    top = {relative(name).split('/')[0] for name in names}
    allowed_directories = set()
    for name in names:
        allowed_directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
    found = set()
    stack = [root / name for name in sorted(top)]
    count = 0
    while stack:
        clock(deadline)
        p = stack.pop()
        count += 1
        need(count <= MAX_ROWS, 'Finite projected source directory capacity required')
        name = str(p.relative_to(root))
        mode = p.lstat().st_mode
        if stat.S_ISDIR(mode):
            need(name in allowed_directories, 'Exact projected source ancestor directory required')
            for child in p.iterdir():
                need(count + len(stack) < MAX_ROWS, 'Source traversal capacity required before insertion')
                stack.append(child)
        else:
            need(stat.S_ISREG(mode) and name in names, 'Exact projected source regular-file roster required')
            found.add(name)
    need(found == names, 'Complete closed projected source tree required')


def accounting(total, results, overlay):
    need(all(type(n) is int and n >= 0 for n in (total, results, overlay)), 'Positive integer accounting required')
    need(total <= TOTAL_BYTES and results <= RESULT_BYTES and results + overlay <= total,
         'Results and overlay are included within128MiB; results stay within8MiB')
    return dict(total_bytes=total, results_bytes=results, overlay_bytes=overlay,
                total_limit_bytes=TOTAL_BYTES, results_limit_bytes=RESULT_BYTES)


def storage(owned_root, results_root, overlay_root, deadline, replay_output=None):
    """Bound current logical and allocated occupancy; peak enforcement is external."""
    root, results, overlay = map(Path, (owned_root, results_root, overlay_root))
    need(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode)
         and results != overlay and root in results.parents and root in overlay.parents
         and results.resolve() == results and overlay.resolve() == overlay,
         'Physical owned tree with separate contained results/overlay roots required')
    need(all(stat.S_ISDIR(p.lstat().st_mode) for p in (results, overlay)),
         'Physical existing results and overlay directories required')
    need(results not in overlay.parents and overlay not in results.parents,
         'Results/overlay budget subsets have distinct contained roots')
    output = None if replay_output is None else Path(replay_output)
    if output is not None:
        need(root in output.parents and output.resolve() == output,
             'Actual replay output is a physical contained budget role')
    excluded = [] if output is None else [output / name for name in
        ('packet source with spaces', 'installed source with spaces', 'private fixtures')]
    stack = [root]
    count = 0
    logical = allocated = result_logical = result_allocated = overlay_logical = overlay_allocated = 0
    while stack:
        p = stack.pop()
        clock(deadline)
        count += 1
        need(count <= MAX_ROWS, 'Finite total projection entry capacity required before reading')
        s = p.lstat()
        need(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode),
             'Finite ordinary projection entry kinds required')
        size = s.st_size if not stat.S_ISDIR(s.st_mode) else 0
        blocks = s.st_blocks * 512
        logical += size
        allocated += blocks
        in_replay = output is not None and (p == output or output in p.parents)
        source_fixture = any(p == prefix or prefix in p.parents for prefix in excluded)
        if p == results or results in p.parents or (in_replay and not source_fixture):
            result_logical += size
            result_allocated += blocks
        if p == overlay or overlay in p.parents:
            overlay_logical += size
            overlay_allocated += blocks
        accounting(logical, result_logical, overlay_logical)
        accounting(allocated, result_allocated, overlay_allocated)
        if stat.S_ISDIR(s.st_mode):
            for child in p.iterdir():
                need(count + len(stack) < MAX_ROWS, 'Traversal capacity required before queue insertion')
                stack.append(child)
    return dict(entries=count, logical=accounting(logical, result_logical, overlay_logical),
                allocated=accounting(allocated, result_allocated, overlay_allocated),
                observer_is_a_hard_quota=False, continuous_peak_enforcement_qualified=False)


def closed_startups(context, providers):
    path = Path(__file__).with_name('startup_contracts.py')
    need(digest(path.read_bytes()) == STARTUP_SOURCE_SHA, 'Exact closed startup derivation source required')
    spec = importlib.util.spec_from_file_location('frontend_closed_startups', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.contracts(context, providers)


def platform_context(observed, policy, nonce, now):
    need(type(observed) is dict and type(nonce) is str and len(nonce) >= 32,
         'Fresh externally selected current platform observation and invocation nonce required')
    need(set(observed) == {'format', 'observation_source_sha256', 'invocation_nonce', 'platform_identity',
         'observed_unix', 'expires_unix', 'outer_admission_passed'}, 'Closed current platform observation required')
    need(observed['format'] == 'atlas-frontend-outer-platform-admission-v103'
         and observed['outer_admission_passed'] is True
         and observed['observation_source_sha256'] == policy['outer_admission_source_sha256']
         and observed['invocation_nonce'] == policy['invocation_nonce'] == nonce,
         'Exact reviewed outer source/current invocation platform join required')
    identity = observed['platform_identity']
    need(type(identity) is dict and set(identity) == {'host_id', 'boot_id', 'OS_build', 'kernel_release',
         'architecture', 'code_loading_identity'} and all(type(v) is str and v for v in identity.values())
         and identity == policy['platform_identity'], 'Fresh host/boot/OS/code-loading identity must match selected policy')
    start, end = observed['observed_unix'], observed['expires_unix']
    need(type(start) in (float, int) and type(end) in (float, int)
         and start <= now <= end <= start + MAX_PLATFORM_AGE_SECONDS,
         'Fresh bounded120-second platform evidence required; each return needs a fresh observation')
    return observed


def check_profile(profile, policy, deadline, image_reader, platform=None, nonce=None, now=None):
    need(profile['format'] == 'atlas-frontend-runtime-profile-v103'
         and policy['format'] == 'atlas-frontend-reviewed-runtime-policy-v103', 'Exact runtime policy formats required')
    need(policy['selected_for_source_replay'] is True
         and profile['platform_identity'] == policy['platform_identity'], 'Externally reviewed exact platform profile required')
    need(policy['admission_source_sha256'] == digest(Path(__file__).read_bytes())
         and policy['source_projection_sha256'] == SOURCE_SHA,
         'Selected policy binds exact admission code and unchanged source projection')
    platform_context(platform, policy, nonce, time.time() if now is None else now)
    providers = profile['providers']
    need(set(providers) == set(ROLES) and set(policy['providers']) == set(ROLES), 'All eight invoked providers required')
    runtime = {}
    aliases = {}
    total = 0
    for role in ROLES:
        row = providers[role]
        need(row == policy['providers'][role], 'Exact selected role/path/provider pin required')
        selected, chain = lexical(row['lexical_path'], deadline)
        need(selected == row['path'], 'Exact lexical alias and physical selection required')
        need([{k: item[k] for k in item if k != 'physical_identity'} for item in chain if 'target' in item]
             == row['aliases'], 'Exact reviewed lexical alias targets required')
        actual = regular(selected, deadline)
        match(row, actual)
        need(actual['mode'] & 0o111 and not actual['mode'] & 0o6022,
             'Executable, non-set-ID and safe write-mode provider required')
        runtime[selected] = actual
        aliases[role] = chain
        total += actual['bytes']
    roots = profile['startup_roots']
    need(roots == policy['startup_roots'] and set(roots) == {'qualified_python', 'system_python', 'ruby'},
         'Complete selected Python/Ruby startup-root profiles required')
    inventory = {}
    entry_count = sum(len(root['files']) for rows in roots.values() for root in rows)
    need(entry_count <= MAX_ROWS, 'Aggregate complete startup entry capacity required before traversal')
    for family, roots_for_family in roots.items():
        need(type(roots_for_family) is list and 1 <= len(roots_for_family) <= 8, 'Finite startup roots per runtime required')
        for root in roots_for_family:
            found = complete_inventory(root['root'], root['files'], deadline)
            if root['root'] in inventory:
                need(inventory[root['root']] == found, 'Reused startup roots retain the same exact closed inventory')
                continue
            inventory[root['root']] = found
            for name, row in found.items():
                if row['kind'] == 'file':
                    p = str(Path(root['root']) / name)
                    runtime[p] = dict(path=p, **{k: row[k] for k in ('bytes', 'mode', 'sha256', 'physical_identity')})
                    total += row['bytes']
    need(len(runtime) <= MAX_ROWS and total <= MAX_RUNTIME_BYTES, 'Finite complete runtime input budget required')
    need(set(profile['startup_observations']) == set(STARTUPS)
         and profile['startup_observations'] == policy['startup_observations'], 'Every normal and isolated startup observation must be reviewed')
    need(profile['execution_context'] == policy['execution_context'], 'Exact selected owned startup context required')
    contracts = closed_startups(profile['execution_context'], providers)
    home = Path(profile['execution_context']['home'])
    home_state = home.lstat()
    need(home.resolve() == home and stat.S_ISDIR(home_state.st_mode) and home_state.st_uid == os.geteuid()
         and not stat.S_IMODE(home_state.st_mode) & 0o022 and not list(home.iterdir()),
         'Controlled startup HOME remains an empty physical owned safe-mode directory')
    for name, startup in profile['startup_observations'].items():
        role = STARTUP_ROLE[name]
        need(all(startup.get(key) == value for key, value in contracts[name].items()),
             'Closed startup argv/flags/environment/cwd/script and selected entrypoint required')
        need(type(startup['exit_code']) is int and startup['exit_code'] == 0
             and type(startup['stderr_bytes']) is int and startup['stderr_bytes'] == 0
             and startup['writers_confirmed_retired'] is True
             and type(startup['loaded_files']) is list and len(startup['loaded_files']) == len(set(startup['loaded_files'])) <= MAX_ROWS
             and providers[role]['path'] in startup['loaded_files']
             and set(startup['loaded_files']) <= set(runtime),
             'Positive returned startup observation and closed loaded-file roster required')
        need(type(startup['raw_receipt_sha256']) is str and len(startup['raw_receipt_sha256']) == 64,
             'Exact source-attested raw startup receipt pin required')
    images = {}
    for path in sorted(runtime):
        current, evidence, unused = image_reader(Path(path), deadline)
        match(runtime[path], current)
        if evidence is not None:
            images[path] = dict(imports=evidence['imports'], rpaths=evidence['rpaths'])
    need(images == profile['native_images'] == policy['native_images'], 'Complete native image/header inventory required')
    need({row['path'] for row in providers.values()} <= set(images),
         'Every actual invoked provider must have inspected native-image evidence')
    edges = profile['native_edges']
    need(edges == policy['native_edges'] and set(edges) == set(images), 'Complete reviewed native import resolution required')
    for path, image in images.items():
        need(set(edges[path]) == set(image['imports']), 'Every native import needs a reviewed resolution')
        for imported, resolution in edges[path].items():
            if resolution['kind'] == 'physical':
                need(resolution['path'] in runtime, 'Resolved native file belongs to complete hashed closure')
            else:
                need(resolution['kind'] == 'platform-shared-cache'
                     and imported.startswith(('/usr/lib/', '/System/Library/'))
                     and resolution['platform_identity'] == policy['platform_identity']
                     and resolution['review_sha256'] == policy['platform_code_loading_review_sha256']
                     and len(resolution['review_sha256']) == 64, 'Explicit exact reviewed Apple shared-cache boundary required')
    return dict(runtime=runtime, aliases=aliases, inventories=inventory)


def image_reader():
    p = Path(__file__).with_name('native_image_evidence.py')
    need(digest(p.read_bytes()) == IMAGE_SHA, 'Exact source-reviewed image metadata parser required')
    spec = importlib.util.spec_from_file_location('frontend_runtime_image_metadata', p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fingerprint


def admission(profile_path, profile_sha, policy_path, policy_sha, projection_path,
              owned_root, deadline, platform_path, platform_sha, nonce, in_place=False):
    need(deadline - time.monotonic() <= MAX_SECONDS, 'Admission metadata horizon is at most60 seconds')
    if not in_place:
        need(all(Path(owned_root) in Path(p).parents for p in
             (profile_path, policy_path, platform_path, projection_path)),
             'Every selected metadata input belongs to the inclusive owned projection')
    profile, profile_file = read_json(profile_path, profile_sha, deadline)
    policy, policy_file = read_json(policy_path, policy_sha, deadline)
    platform, platform_file = read_json(platform_path, platform_sha, deadline)
    source = source_projection(projection_path, SOURCE_SHA, owned_root, deadline, in_place)
    if not in_place:
        need(profile['execution_context']['source_root'] == str(owned_root), 'Startup and physical source root join required')
    runtime = check_profile(profile, policy, deadline, image_reader(), platform, nonce)
    return dict(profile=profile_file, policy=policy_file, source=source, runtime=runtime,
                platform_observation=dict(file=platform_file, observed=platform),
                execution_context=profile['execution_context'],
                provider_source_metadata_admission_passed=True, full_818_replay_passed=False, complete_outer_execution_ready=False, execution_selected=False,
                local_compiler_API_native_formatter_browser_container_SSH_jobs=0)


def returned(original, profile_path, profile_sha, policy_path, policy_sha,
             projection_path, owned_root, deadline, platform_path, platform_sha, nonce, in_place=False):
    current = admission(profile_path, profile_sha, policy_path, policy_sha,
                        projection_path, owned_root, deadline, platform_path, platform_sha, nonce, in_place)
    compare_return(original, current, deadline)
    return current


def compare_return(original, current, deadline):
    before = original['platform_observation']
    need(regular(before['file']['path'], deadline, MAX_JSON_BYTES) == before['file'],
         'Original platform observation bytes/physical identity remain retained')
    need(before['observed']['platform_identity'] == current['platform_observation']['observed']['platform_identity'],
         'Original and fresh return platform identities remain exact')
    need({k: v for k, v in current.items() if k != 'platform_observation'} ==
         {k: v for k, v in original.items() if k != 'platform_observation'},
         'Exact original physical provider/alias/startup/source return required')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('admit', 'return'))
    for option in ('profile', 'policy', 'projection', 'owned-root', 'results-root', 'overlay-root', 'receipt', 'platform-observation'):
        parser.add_argument('--' + option, type=Path, required=True)
    for option in ('profile-sha256', 'policy-sha256', 'platform-sha256', 'invocation-nonce'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--receipt-sha256')
    args = parser.parse_args()
    deadline = time.monotonic() + MAX_SECONDS
    need(args.results_root in args.receipt.parents and args.receipt.parent.resolve() == args.receipt.parent,
         'Original admission receipt remains within the declared physical results subset')
    need(all(args.results_root in p.parents for p in (args.profile, args.policy, args.platform_observation))
         and args.overlay_root in args.projection.parents,
         'Runtime/platform metadata belongs to retained results; source projection belongs to the pinned overlay')
    value = admission(args.profile, args.profile_sha256, args.policy, args.policy_sha256,
                      args.projection, args.owned_root, deadline, args.platform_observation,
                      args.platform_sha256, args.invocation_nonce)
    if args.phase == 'return':
        need(args.receipt_sha256 is not None, 'Externally retained original admission receipt digest required')
        original, unused = read_json(args.receipt, args.receipt_sha256, deadline)
        compare_return(original, value, deadline)
    else:
        need(not args.receipt.exists(), 'Fresh owned admission receipt required')
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        need(len(raw) <= RESULT_BYTES, 'Admission receipt belongs inside retained8MiB result budget')
        observed = storage(args.owned_root, args.results_root, args.overlay_root, deadline,
                           value['execution_context']['output_root'])
        need(observed['logical']['total_bytes'] + len(raw) <= TOTAL_BYTES
             and observed['logical']['results_bytes'] + len(raw) <= RESULT_BYTES,
             'Admission receipt capacity reserved before writing')
        with args.receipt.open('xb') as stream:
            stream.write(raw)
    observed = storage(args.owned_root, args.results_root, args.overlay_root, deadline,
                       value['execution_context']['output_root'])
    print(json.dumps(dict(provider_source_metadata_admission_passed=True, full_818_replay_passed=False, complete_outer_execution_ready=False, execution_selected=False,
                          phase=args.phase, observed_storage=observed,
                          platform_observation=value['platform_observation'])))


if __name__ == '__main__':
    main()
