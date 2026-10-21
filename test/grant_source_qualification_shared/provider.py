"""Shared observed runtime/provider admission for finite source qualifications.

The outer owner selects metadata calibration separately from full source replay.
Route source/entrypoint/cohort contracts are explicit inputs to this mechanism.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time

FORMAT = 'atlas-source-provider-observation-v1'
POLICY = 'atlas-source-provider-decision-v1'
ROLES = ('qualified_python', 'system_python', 'ruby_launcher', 'ruby_backend', 'bash', 'sh', 'chmod', 'uname')
MODES = ('python-isolated', 'python-ordinary', 'ruby-ordinary', 'ruby-no-gems')
MAX_ENTRIES = 32768
MAX_BYTES = 2 * 2**30
MAX_FILE = 512 * 2**20
MAX_PROFILE = 8 * 2**20
SOURCE_PHYSICAL_SHA = 'b844cd259a9c646ab608d9ef8060ca84b05d860b11a97eb4e0a95f279fe48bba'
IMAGE_SHA = 'ea299e6ec8789d0251d79b8af9364946a628679f11c8081a78988881df56308f'
PYTHON_PROBE = '''import sys,os,json,sysconfig,hashlib,ast,base64,collections,contextlib,dataclasses,decimal,functools,gzip,importlib,io,math,pathlib,re,resource,runpy,shutil,signal,stat,struct,subprocess,tarfile,tempfile,textwrap,time,types,unittest,zipfile,zlib
print(json.dumps(dict(executable=os.path.realpath(sys.executable),version=sys.version,flags=dict(isolated=sys.flags.isolated,no_site=sys.flags.no_site,no_user_site=sys.flags.no_user_site,dont_write_bytecode=sys.flags.dont_write_bytecode),load_paths=[os.path.realpath(p or os.getcwd()) for p in sys.path],loaded_files=sorted(set(os.path.realpath(m.__file__) for m in sys.modules.values() if getattr(m,"__file__",None) and os.path.isfile(m.__file__)))),sort_keys=True))
'''
RUBY_PROBE = '''require "json";require "rbconfig";require "digest";require "fileutils";require "open3";require "shellwords";require "tmpdir";require "securerandom";require "psych";puts JSON.generate(executable: File.realpath(RbConfig.ruby),version: RUBY_DESCRIPTION,load_paths: $LOAD_PATH.select{|p| File.directory?(p)}.map{|p| File.realpath(p)},loaded_files: $LOADED_FEATURES.select{|p| File.file?(p)}.map{|p| File.realpath(p)}.uniq.sort)
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_physical():
    p = Path(__file__).with_name('physical.py')
    need(sha(p.read_bytes()) == SOURCE_PHYSICAL_SHA, 'Exact reviewed physical reader source required')
    spec = importlib.util.spec_from_file_location('source_qualification_physical', p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image_reader(path, deadline):
    p = Path(__file__).with_name('native_image_evidence.py')
    need(sha(p.read_bytes()) == IMAGE_SHA, 'Exact reviewed native image reader source required')
    spec = importlib.util.spec_from_file_location('source_qualification_images', p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fingerprint(path, deadline)


def calibration_plan(config):
    providers = config['providers']
    need(set(providers) == set(ROLES), 'All eight declared provider roles required')
    context = config['execution_context']
    root, home, cwd = (Path(context[k]) for k in ('owned_root', 'home', 'calibration_cwd'))
    need(root.is_absolute() and root.resolve() == root and root in home.parents and root in cwd.parents,
         'Exact physical owned source qualification context required')
    environment = dict(HOME=str(home), PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    return [dict(mode=mode, argv=[providers[role], *flags, '-c' if role.endswith('python') else '-e', source],
                 cwd=str(cwd), environment=environment, seconds=15, probe_sha256=sha(source.encode()),
                 scope='stdlib/runtime calibration; original source behavior remains separate')
            for mode, role, flags, source in (
                ('python-isolated', 'qualified_python', ['-I', '-S', '-B'], PYTHON_PROBE),
                ('python-ordinary', 'system_python', [], PYTHON_PROBE),
                ('ruby-ordinary', 'ruby_launcher', [], RUBY_PROBE),
                ('ruby-no-gems', 'ruby_launcher', ['--disable-gems'], RUBY_PROBE))]


class FileInventory(dict):
    """O(1) byte accounting for every insertion or replacement."""
    def __init__(self):
        super().__init__()
        self.total_bytes = 0
        self.accounting_operations = 0

    def __setitem__(self, key, row):
        self.accounting_operations += 1
        total = self.total_bytes - self.get(key, {}).get('bytes', 0) + row['bytes']
        need(0 <= total <= MAX_BYTES, 'Aggregate runtime byte capacity required before insertion')
        super().__setitem__(key, row)
        self.total_bytes = total


def file_admission(path, reader, deadline, files):
    info = reader.state(path)
    need(stat.S_ISREG(info[2]) and 0 <= info[3] <= MAX_FILE,
         'Finite physical runtime file required before reading')
    need(isinstance(files, FileInventory), 'Explicit linear runtime byte accountant required')
    files.accounting_operations += 1
    need(files.total_bytes - files.get(str(path), {}).get('bytes', 0) + info[3] <= MAX_BYTES,
         'Aggregate runtime byte capacity required before reading')
    return reader.regular(path, deadline, MAX_FILE)


def clean_aliases(chain):
    return [{k: v for k, v in row.items() if k not in ('physical_identity', 'directory_identity')} for row in chain]


def enumerate_root(root, reader, deadline, entries, files):
    root = Path(root)
    need(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode), 'Physical runtime inventory root required')
    stack = [root]
    while stack:
        p = stack.pop()
        reader.clock(deadline)
        if str(p) in entries:
            continue
        need(len(entries) < MAX_ENTRIES, 'Runtime entry capacity required before insertion')
        info = reader.state(p)
        if stat.S_ISDIR(info[2]):
            entries[str(p)] = dict(kind='directory', mode=stat.S_IMODE(info[2]), physical_identity=info)
            for child in sorted(p.iterdir()):
                need(len(entries) + len(stack) < MAX_ENTRIES, 'Runtime queue admission required before insertion')
                stack.append(child)
        elif stat.S_ISLNK(info[2]):
            target = os.readlink(p)
            entries[str(p)] = dict(kind='alias', target=target, physical_identity=info)
            selected = p.resolve(strict=True)
            need(selected != p, 'Finite resolved runtime alias required')
            need(len(entries) + len(stack) < MAX_ENTRIES, 'Runtime alias queue capacity required before insertion')
            stack.append(selected)
        else:
            row = file_admission(p, reader, deadline, files)
            files[str(p)] = row
            entries[str(p)] = dict(kind='file', physical_identity=info)


def static_inputs(config, roots, deadline, images=image_reader):
    reader = load_physical()
    files, entries, providers, aliases = FileInventory(), {}, {}, {}
    for role in ROLES:
        lexical = config['providers'][role]
        selected, chain = reader.lexical(lexical, deadline)
        row = file_admission(selected, reader, deadline, files)
        need(row['mode'] & 0o111 and not row['mode'] & 0o6022, 'Safe-mode physical executable provider required')
        files[selected] = row
        providers[role] = dict(lexical_path=lexical, **{k: row[k] for k in ('path', 'bytes', 'mode', 'sha256')})
        aliases[role] = chain
    owned = Path(config['execution_context']['owned_root'])
    selected_roots = sorted(set(str(Path(p).resolve()) for p in roots if Path(p).is_dir() and not (Path(p) == owned or owned in Path(p).parents)))
    need(0 < len(selected_roots) <= 32, 'Finite complete observed runtime root set required')
    for root in selected_roots:
        enumerate_root(root, reader, deadline, entries, files)
    native, edges, unresolved = {}, {}, []
    retained_bytes = 0
    pending = list(files)
    seen = set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        current, evidence, raw = images(Path(path), deadline)
        need(all(current[k] == files[path][k] for k in ('path', 'bytes', 'mode', 'sha256')), 'Native header and complete runtime file join required')
        if evidence is None:
            continue
        need(len(native) < 256, 'Finite selected native image count required')
        retained_bytes += len(raw)
        need(retained_bytes <= 2**20, 'Aggregate retained native header capacity required before insertion')
        native[path] = dict(imports=evidence['imports'], rpaths=evidence['rpaths'], evidence=evidence, raw_hex=raw.hex())
        edges[path] = {}
        for imported in evidence['imports']:
            if imported.startswith(('/usr/lib/', '/System/Library/')):
                edges[path][imported] = dict(kind='Apple-platform', import_name=imported, shared_cache_bytes_qualified=False)
                continue
            candidates = []
            if imported.startswith('/'):
                candidates = [imported]
            elif imported.startswith('@loader_path/'):
                candidates = [str(Path(path).parent / imported[13:])]
            elif imported.startswith('@rpath/'):
                candidates = [str(Path(r.replace('@loader_path', str(Path(path).parent))) / imported[7:]) for r in evidence['rpaths']
                              if Path(r.replace('@loader_path', str(Path(path).parent))).is_absolute()]
            candidates = sorted(set(p for p in candidates if Path(p).is_file()))
            physical_candidates = {str(Path(p).resolve()) for p in candidates}
            if len(physical_candidates) != 1:
                unresolved.append(dict(image=path, imported=imported, candidates=candidates))
                continue
            chosen = candidates[0]
            selected, chain = reader.lexical(chosen, deadline)
            if selected not in files:
                need(len(files) < MAX_ENTRIES, 'Native closure entry capacity required before insertion')
                row = file_admission(selected, reader, deadline, files)
                files[selected] = row
                pending.append(selected)
            aliases['native:' + path + ':' + imported] = chain
            edges[path][imported] = dict(kind='physical', path=selected, aliases=clean_aliases(chain))
    need({row['path'] for row in providers.values()} <= set(native), 'Every invoked provider requires inspected native image evidence')
    stable_files = [{k: row[k] for k in ('path', 'bytes', 'mode', 'sha256')} for path, row in sorted(files.items())]
    stable_entries = {path: {k: v for k, v in row.items() if k != 'physical_identity'} for path, row in sorted(entries.items())}
    stable_aliases = {role: clean_aliases(chain)
                      for role, chain in aliases.items()}
    stable = dict(providers=providers, roots=selected_roots, files=stable_files, entries=stable_entries,
                  aliases=stable_aliases, native_images=native, native_edges=edges, unresolved=unresolved)
    return dict(stable_view=stable, stable_view_sha256=sha(canonical(stable)),
                physical=dict(files=files, entries=entries, aliases=aliases), complete=not unresolved)


def validate_record(plan, record):
    need(record['argv'] == plan['argv'] and record['cwd'] == plan['cwd'] and record['environment'] == plan['environment']
         and record['probe_sha256'] == plan['probe_sha256'] and record['mode'] == plan['mode'], 'Exact observed calibration flags/environment/cwd/source contract required')
    need(type(record['exit_code']) is int and record['exit_code'] == 0 and record['stderr_bytes'] == 0
         and record['writers_confirmed_retired'] is True and record['group']['status'] == 'absent'
         and 0 <= record['elapsed_seconds'] <= plan['seconds'], 'Positive bounded original calibration command/group/raw return required')
    need(len(record['stdout'].encode()) == record['stdout_bytes'] <= 256 * 2**10
         and sha(record['stdout'].encode()) == record['stdout_sha256'] and sha(record['stderr'].encode()) == record['stderr_sha256']
         and record['stderr'] == '', 'Complete original calibration raw stream hashes required')
    value = json.loads(record['stdout'])
    need(type(value['loaded_files']) is list and type(value['load_paths']) is list and type(value['executable']) is str,
         'Typed observed runtime provider/module/load-path metadata required')
    return value


def startup_value(value, mode, config, providers, covered):
    role = 'qualified_python' if mode == 'python-isolated' else 'system_python' if mode == 'python-ordinary' else 'ruby_backend'
    need(value['executable'] == providers[role]['path'] and value['executable'] in covered,
         'Actual startup executable joins its declared physical provider role')
    need(type(value.get('version')) is str and value['version']
         and len(value['loaded_files']) <= MAX_ENTRIES and len(value['load_paths']) <= 32
         and all(type(p) is str and Path(p).is_absolute() for p in value['loaded_files'] + value['load_paths'])
         and all(p in covered for p in value['loaded_files']),
         'Every typed loaded module joins the complete exact runtime closure')
    if mode.startswith('python-'):
        flags = dict(isolated=1, no_site=1, no_user_site=1, dont_write_bytecode=1) if mode == 'python-isolated' else dict(isolated=0, no_site=0, no_user_site=0, dont_write_bytecode=1)
        need(value['flags'] == flags, 'Actual Python startup flags join the declared invocation class')
    root = config['execution_context']['owned_root']
    normalized = json.loads(canonical(value))
    normalized['load_paths'] = ['$OWNED_ROOT' + p[len(root):] if p == root or p.startswith(root + '/') else p for p in value['load_paths']]
    return dict(mode=mode, probe_sha256=sha((PYTHON_PROBE if mode.startswith('python-') else RUBY_PROBE).encode()), observed=normalized)


def platform_identity(platform, config, nonce):
    now = time.time()
    need(platform['format'] == 'atlas-source-qualification-platform-v1' and platform['nonce'] == nonce
         and platform['job'] == config['job'] and platform['route'] == config['route']
         and platform['observer_source_sha256'] == config['platform_observer_source_sha256']
         and platform['outer_metadata_admission_passed'] is True, 'Fresh source/job/nonce-bound selected platform observation required')
    need(type(platform['observed_unix']) in (int, float) and platform['observed_unix'] <= now <= platform['expires_unix'] <= platform['observed_unix'] + 120,
         'Fresh at-most120-second host/boot/OS observation required')
    identity = platform['identity']
    need(set(identity) == {'host', 'boot', 'OS_build', 'image_version', 'architecture', 'code_loading_identity'}
         and all(type(v) is str and v for v in identity.values()), 'Complete actual platform identity required')
    return identity


def bootstrap(config, platform, deadline):
    """The outer owner separately selects the finite metadata probe authority."""
    reader = load_physical()
    admission = config['metadata_bootstrap_admission']
    need(admission['format'] == 'atlas-source-metadata-bootstrap-admission-v1'
         and admission['metadata_calibration_admitted'] is True
         and admission['full_source_execution_admitted'] is False
         and admission['route'] == config['route'] and admission['job'] == config['job']
         and admission['nonce'] == config['nonce']
         and admission['observer_source_sha256'] == sha(Path(__file__).read_bytes())
         and admission['platform_identity'] == platform['identity']
         and type(admission['outer_receipt_sha256']) is str and len(admission['outer_receipt_sha256']) == 64
         and type(admission['lease_receipt_sha256']) is str and len(admission['lease_receipt_sha256']) == 64
         and admission['window']['start_unix'] <= time.time() <= admission['expires_unix'] <= admission['window']['end_unix'],
         'Separately selected source/job/provider-bound metadata calibration authority required')
    providers, aliases = {}, {}
    for role in ROLES:
        selected, chain = reader.lexical(config['providers'][role], deadline)
        row = reader.regular(selected, deadline, MAX_FILE)
        need(row['mode'] & 0o111 and not row['mode'] & 0o6022, 'Safe selected calibration provider mode required')
        providers[role] = dict(lexical_path=config['providers'][role], **{k: row[k] for k in ('path', 'bytes', 'mode', 'sha256')})
        aliases[role] = clean_aliases(chain)
    need(admission['providers'] == providers and admission['aliases'] == aliases,
         'All eight exact lexical/physical providers join the selected metadata authority before launch')
    return dict(providers=providers, aliases=aliases)


def observe(config, services, deadline):
    """services provides separately admitted run(plan), platform(), and image_reader."""
    reader = load_physical()
    reader.clock(deadline)
    need(config['format'] == 'atlas-source-provider-config-v1' and config['route']['actual_compiler_API_native_jobs'] == 0,
         'Explicit source-fixture-only route configuration required')
    home = Path(config['execution_context']['home'])
    need(home.resolve() == home and stat.S_ISDIR(home.lstat().st_mode) and not list(home.iterdir()), 'Fresh empty physical controlled HOME required')
    platform = services.platform()
    identity = platform_identity(platform, config, config['nonce'])
    before = bootstrap(config, platform, deadline)
    calibrations, values = [], []
    for plan in calibration_plan(config):
        record = services.run(plan)
        value = validate_record(plan, record)
        values.append(value)
        calibrations.append(record)
        need(bootstrap(config, platform, deadline) == before, 'All calibration provider bytes and lexical aliases return after every original group')
    roots = list(config.get('runtime_roots', [])) + [path for value in values for path in value['load_paths']]
    result = static_inputs(config, roots, deadline, services.image_reader)
    owned = Path(config['execution_context']['owned_root'])
    covered = set(result['physical']['files'])
    result['stable_view']['startup'] = [startup_value(value, plan['mode'], config, result['stable_view']['providers'], covered)
                                       for value, plan in zip(values, calibration_plan(config))]
    result['stable_view_sha256'] = sha(canonical(result['stable_view']))
    need(result['stable_view']['providers'] == before['providers'], 'Observed complete providers join pre-launch authority')
    final_platform = services.platform()
    need(platform_identity(final_platform, config, config['nonce']) == identity,
         'Fresh final host/boot/OS identity returns after runtime inventory')
    bootstrap(config, final_platform, deadline)
    result.update(format=FORMAT, config=config, platform=final_platform, platform_identity=identity,
                  calibrations=calibrations, execution_admitted=False, actual_compiler_API_native_jobs=0)
    need(len(canonical(result)) <= MAX_PROFILE, 'Finite complete observed provider receipt required')
    reader.clock(deadline)
    return result


def check_profile(profile, decision, deadline, image_reader, platform, nonce, execution_context=None):
    reader = load_physical()
    config = profile['config']
    identity = platform_identity(platform, config, nonce)
    need(profile['format'] == FORMAT and decision['format'] == POLICY
         and decision['source_fixture_execution_admitted'] is True
         and decision['actual_compiler_API_native_execution_admitted'] is False,
         'Distinct independently selected source-only provider decision required')
    need(decision['observer_source_sha256'] == sha(Path(__file__).read_bytes())
         and decision['route'] == config['route'] and decision['reviewed_stable_view_sha256'] == profile['stable_view_sha256']
         and profile['stable_view_sha256'] == sha(canonical(profile['stable_view']))
         and decision['reviewed_platform'] == {k: identity[k] for k in ('OS_build', 'image_version', 'architecture', 'code_loading_identity')}
         and decision['Apple_platform_code_loading_reviewed'] is True, 'Exact independently reviewed route/static runtime/platform authority required')
    need(identity == profile['platform_identity'] and (execution_context is None or execution_context == config['execution_context']),
         'Current observed host/boot and owned execution context remain exact')
    need(set(record['mode'] for record in profile['calibrations']) == set(MODES) and len(profile['calibrations']) == 4,
         'Complete isolated/ordinary Python and normal/no-gems Ruby calibration required')
    startup = [startup_value(validate_record(plan, record), plan['mode'], config, profile['stable_view']['providers'], set(profile['physical']['files']))
               for plan, record in zip(calibration_plan(config), profile['calibrations'])]
    need(startup == profile['stable_view']['startup'], 'Retained original startup streams join the reviewed stable view')
    bootstrap(config, platform, deadline)
    current = static_inputs(config, profile['stable_view']['roots'], deadline, image_reader)
    current['stable_view']['startup'] = startup
    current['stable_view_sha256'] = sha(canonical(current['stable_view']))
    need(profile['complete'] is True and current['complete'] is True and current['stable_view'] == profile['stable_view']
         and current['physical'] == profile['physical'], 'Complete original provider/stdlib/extension/native/alias physical return required')
    reader.clock(deadline)
    return dict(providers=current['stable_view']['providers'], execution_context=config['execution_context'],
                controlled_environment=calibration_plan(config)[0]['environment'], physical=current['physical'],
                source_fixture_provider_admitted=True, full_source_behavior_accepted=False,
                actual_compiler_API_native_execution_admitted=False)


def compare_return(before, after, deadline):
    load_physical().clock(deadline)
    need(before['config'] == after['config'] and before['stable_view'] == after['stable_view']
         and before['physical'] == after['physical'] and before['platform_identity'] == after['platform_identity'],
         'Original route/source/job/provider/alias/host/boot identities return exact')
    return True
