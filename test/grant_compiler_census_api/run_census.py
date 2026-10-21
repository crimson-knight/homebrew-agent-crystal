"""Collect actual compiler API cards and concrete-receiver compatibility on canonical9c1."""
import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
OUTER_SECONDS = 2700
RETURN_SECONDS = 180
PREPARATION_SECONDS = 120
ARCHIVE_SHA = '2c85084ce5ed4973d7f1f73987ba990b7b16381f60dd8ccc8a92b2bec1203b05'
COMPILER_COMMIT = '9c1e8ec64f6be6343e90d3979bc9536c4b050292'
CANONICAL_GC_SHA = '526f1819cfc10f3a97a62da8c0dab11116c4e48bcc07c59903ee562a2f7ed307'
STABLE_TOOLS_SHA = '41e88da63e122233426ff376cb048f36f1df319e59f841fba335fa1f59923805'
CONTRACT_SHA = '33418b91a8ed01e0d3b442781fb5c7ebdbfbb32927e5caecb9747251d9dd52c9'
CONTEXT = dict(compiler_flags=['without_mt','without_libxml2','without_openssl','without_zlib'], LLVM_VERSION='21.1.8', LLVM_TARGETS='AArch64', LLVM_LDFLAGS='selected-reviewed-shared-LLVM-image', interpreter=True, target_scope='no-codegen compatibility only')
PROBES = ('gc_stats','initialized_graph','source_origins','gc_stats_wrong_type')
MAX_RAW = 4 * 2**20
MAX_PUBLIC = 128 * 2**20

def need(value, message):
    if not value:
        raise RuntimeError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'), allow_nan=False).encode()

def decode(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'Unique JSON object fields required'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda value:need(False, 'Finite JSON numeric values required'))

def finite(value, low, high):
    return type(value) in (float,int) and math.isfinite(value) and low <= value <= high

def clock(deadline):
    need(finite(deadline,0,float('inf')) and time.monotonic() <= deadline, 'Complete finite phase deadline required')

def identity(path):
    state = Path(path).lstat()
    return [state.st_dev,state.st_ino,state.st_mode,state.st_size,state.st_mtime_ns,state.st_ctime_ns]

def stable(path, maximum=16 * 2**20):
    path = Path(path); before = identity(path)
    need(stat.S_ISREG(before[2]) and path.lstat().st_nlink == 1 and 0 <= before[3] <= maximum, 'Bounded ordinary single-link physical input required: ' + str(path))
    with os.fdopen(os.open(path,os.O_RDONLY | os.O_NOFOLLOW),'rb') as stream:
        opened = os.fstat(stream.fileno()); raw = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    fields = lambda state:[state.st_dev,state.st_ino,state.st_mode,state.st_size,state.st_mtime_ns,state.st_ctime_ns]
    need(before == fields(opened) == fields(after) == identity(path) and len(raw) == before[3], 'Complete stable physical read required')
    return raw

def manifest(root, expected, maximum=128):
    root = Path(root); raw = stable(root/'SOURCE_PINS.json',2**20)
    need(sha(raw) == expected, 'Externally pinned complete executable manifest required')
    rows = decode(raw)['files']; need(0 < len(rows) <= maximum and len({r['path'] for r in rows}) == len(rows), 'Finite unique exact source roster required')
    protected = {root/'SOURCE_PINS.json':expected}
    for row in rows:
        rel = PurePosixPath(row['path']); need(str(rel) == row['path'] and not rel.is_absolute() and '..' not in rel.parts, 'Canonical contained source row required')
        path = root/rel; need(path.resolve(strict=True) == path, 'Physical executable source parents required')
        value = stable(path); need(len(value) == row['bytes'] and sha(value) == row['sha256'], 'Exact executable source bytes required: ' + row['path'])
        if 'mode' in row:need(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'Exact executable source mode required')
        protected[path] = row['sha256']
    return protected

def load(path, expected, name):
    need(sha(stable(path)) == expected, 'Hash-verified executable import required')
    spec = importlib.util.spec_from_file_location(name,path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    need(sha(stable(path)) == expected, 'Imported executable source return required')
    return module

class Owned:
    def __init__(self, path):
        self.root = Path(path)
        need(self.root.is_absolute() and self.root.parent.resolve(strict=True) == self.root.parent and not self.root.exists() and not self.root.is_symlink(), 'Fresh physical owned output required before admission')
        self.root.mkdir(mode=0o700); self.directories = {self.root:identity(self.root)[:3]}; self.files = {}
    def check(self):
        for path, original in self.directories.items():
            need(identity(path)[:3] == original and stat.S_ISDIR(path.lstat().st_mode), 'Original physical owned directory return required')
    def directory(self, path):
        path = Path(path); need(path.is_relative_to(self.root), 'Contained owned output directory required'); self.check()
        current = self.root
        for name in path.relative_to(self.root).parts:
            current = current/name
            if current not in self.directories:
                need(not current.exists() and not current.is_symlink(), 'Fresh physical owned output child required'); current.mkdir(mode=0o700); self.directories[current] = identity(current)[:3]
        self.check()
    def write(self, name, raw):
        rel = PurePosixPath(name); need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts, 'Contained fixed output name required')
        path = self.root/rel; self.directory(path.parent)
        if path in self.files:need(identity(path)[:3] == self.files[path], 'Original owned output file required')
        else:need(not path.exists() and not path.is_symlink(), 'Fresh owned output file required')
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_TRUNC if path in self.files else os.O_EXCL)
        with os.fdopen(os.open(path,flags,0o644),'wb') as stream:
            state = os.fstat(stream.fileno()); need(stat.S_ISREG(state.st_mode) and state.st_nlink == 1, 'Ordinary single-link output required'); stream.write(raw); stream.flush(); state = os.fstat(stream.fileno())
        self.check(); need(identity(path)[:3] == [state.st_dev,state.st_ino,state.st_mode] and state.st_size == len(raw), 'Complete owned output write return required'); self.files[path] = identity(path)[:3]
    def json(self, name, value):
        self.write(name,(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode())

def archive_rows():
    return decode(stable(ROOT/'inputs/COMPILER_ARCHIVE_ROSTER.json',2**20))

def extract_project(project, deadline):
    """Materialize ordinary nodes before contained lexical aliases; follow no archive links."""
    clock(deadline); roster = archive_rows(); raw = stable(ROOT/'inputs/compiler-source.tar.gz',8*2**20)
    need(sha(raw) == roster['archive_sha256'] == ARCHIVE_SHA and len(raw) == roster['archive_bytes'] == 4435186, 'Exact complete canonical compiler distribution required')
    need(not project.exists() and not project.is_symlink() and project.parent.resolve(strict=True) == project.parent, 'Fresh complete compiler source root required'); project.mkdir()
    rows = roster['files']; expected = {row['path']:row for row in rows}; need(len(rows) == len(expected) == 3190, 'Complete3190 compiler distribution members required')
    def target(name):
        rel = PurePosixPath(name); need(str(rel) == name and not rel.is_absolute() and '..' not in rel.parts, 'Canonical contained archive source member required'); path = project/rel
        current = project
        for part in rel.parts[:-1]:
            current = current/part; need(current.is_dir() and not current.is_symlink(), 'Ordinary existing archive parent required')
        return path
    with tarfile.open(ROOT/'inputs/compiler-source.tar.gz','r:gz') as archive:
        members = archive.getmembers(); need(len(members) == 3191, 'Exact original archive member count required')
        actual = {}
        for member in members:
            path = PurePosixPath(member.name); need(path.parts[0] == roster['prefix'] and not path.is_absolute() and '..' not in path.parts, 'Exact safe archive prefix required')
            name = '/'.join(path.parts[1:])
            if not name:need(member.isdir(), 'Original archive root must be ordinary'); continue
            need(name in expected and name not in actual, 'Exact unique original archive member required'); actual[name] = member
        need(set(actual) == set(expected), 'Complete original member roster required')
        for kind in ('directory','file','symlink'):
            selected = [row for row in rows if row['kind'] == kind]
            if kind == 'directory':selected.sort(key=lambda row:(len(PurePosixPath(row['path']).parts),row['path']))
            for row in selected:
                clock(deadline); member = actual[row['path']]; path = target(row['path']); need(member.mode == row['mode'], 'Exact archive source mode required')
                need(not path.exists() and not path.is_symlink(), 'Fresh ordinary archive node required')
                if kind == 'directory':need(member.isdir(), 'Ordinary source directory required'); path.mkdir(mode=row['mode']); path.chmod(row['mode'])
                elif kind == 'file':
                    need(member.isfile() and member.size == row['bytes'] <= 2**20, 'Bounded original regular source required'); body = archive.extractfile(member).read(2**20+1)
                    need(len(body) == row['bytes'] and sha(body) == row['sha256'], 'Complete original archive source hash required'); path.write_bytes(body); path.chmod(row['mode'])
                else:
                    need(member.issym() and member.linkname == row['target'], 'Original contained lexical source alias required')
                    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(row['path']),member.linkname))
                    need(not member.linkname.startswith('/') and normalized != '..' and not normalized.startswith('../'), 'Contained source alias target required'); path.symlink_to(member.linkname)
                    if hasattr(os,'lchmod'):os.lchmod(path,row['mode'])
    clock(deadline)
    need(sha(stable(project/'src/gc/boehm.cr')) == CANONICAL_GC_SHA, 'Canonical526f1819 GC source required')
    return physical_tree(project,expected,deadline)

def physical_tree(root, expected, deadline):
    observed = {}; total = 0; stack = [root]
    while stack:
        current = stack.pop(); need(stat.S_ISDIR(current.lstat().st_mode), 'Physical source traversal directory required')
        for path in sorted(current.iterdir()):
            clock(deadline); name = str(path.relative_to(root)); need(name in expected, 'Exact complete project roster required: ' + name); row = expected[name]; state = path.lstat(); kind = row['kind']
            need(stat.S_IMODE(state.st_mode) == row['mode'], 'Exact source node mode required')
            value = dict(row,physical_identity=identity(path))
            if kind == 'directory':need(stat.S_ISDIR(state.st_mode), 'Original physical source directory required'); stack.append(path)
            elif kind == 'file':
                body = stable(path,2**20); need(len(body) == row['bytes'] and sha(body) == row['sha256'], 'Original project source hash required'); total += len(body)
            else:need(kind == 'symlink' and stat.S_ISLNK(state.st_mode) and os.readlink(path) == row['target'] and path.resolve(strict=True).is_relative_to(root), 'Original contained source alias required')
            observed[name] = value; need(len(observed) <= 3210 and total <= 64*2**20, 'Finite complete source project required')
    need(set(observed) == set(expected), 'All original source members must return')
    return dict(root_identity=identity(root)[:3],files=observed,hashed_bytes=total)

def working_bound(private):
    total = 0; count = 0; stack = [private]
    while stack:
        directory = stack.pop()
        for path in directory.iterdir():
            state = path.lstat(); count += 1; need(count <= 16384, 'Finite source/cache working-file bound required')
            if stat.S_ISDIR(state.st_mode):stack.append(path)
            elif stat.S_ISREG(state.st_mode):need(state.st_size <= 32*2**20 and state.st_nlink == 1, 'Bounded ordinary private source/cache file required'); total += state.st_size
            else:need(stat.S_ISLNK(state.st_mode) and path.resolve(strict=True).is_relative_to(private), 'Contained original source alias required')
            need(total <= 512*2**20, 'Finite complete private source/cache byte bound required')
    return dict(files=count,bytes=total)

def command_roster():
    rows = [('llvm-config-version',10),('amber-lsp-version',10),('ameba-version',10)]
    for index in range(56):rows += [('api-'+str(index),120 if index == 0 else 10),('api-verify-'+str(index),10)]
    rows += [('format-'+name,15) for name in PROBES]
    rows += [('compatibility-'+name,60 if name == 'gc_stats_wrong_type' else 300) for name in PROBES]
    need(len(rows) == 123 and sum(seconds for _,seconds in rows) == 2280, 'Exact finite123-command2280-second worst-case roster required')
    need(PREPARATION_SECONDS + sum(s for _,s in rows) + RETURN_SECONDS <= OUTER_SECONDS, 'Composed API phase must fit the unchanged complete horizon')
    return rows

def admit_decision(args, context, protected):
    raw = stable(args.decision,2**20); need(sha(raw) == args.decision_sha256, 'Independently selected census decision SHA required'); decision = decode(raw)
    need(decision['format'] == 'atlas-compiler-census-api-review-decision-v1' and decision['execution_admitted'] is True and decision['scope'] == 'compiler-census-api-and-concrete-receiver-only', 'Distinct positive census scope decision required')
    required = dict(source_manifest_sha256=args.packet_sha256, api_roster_sha256=sha(stable(ROOT/'API_ROSTER.json')), compiler_distribution_sha256=ARCHIVE_SHA, compiler_commit=COMPILER_COMMIT, canonical_gc_sha256=CANONICAL_GC_SHA, accepted_analysis_stable_sha256=STABLE_TOOLS_SHA, context=CONTEXT, maximum_seconds=OUTER_SECONDS, command_roster=command_roster())
    need(canonical(decision['protocol']) == canonical(required), 'Exact separately reviewed API source/context/command protocol required')
    need(re.fullmatch('[0-9a-f]{64}',decision['independent_review_sha256']) is not None, 'Independent census source/protocol review receipt required')
    need(decision['reviewed_llvm_config'] == llvm_config_identity(args,context), 'Additional LLVM-config bytes/imports/aliases must equal the independently reviewed stable provider')
    need(decision['LLVM_config_code_loading_reviewed'] is True, 'Explicit additional metadata-provider loading scope required')
    need(context['llvm_config']['unresolved_imports'] == [] and context['llvm_config']['native_file_closure_covered'] is True and decision['Apple_platform_code_loading_reviewed'] is True, 'Every extra provider import must join the admitted file closure or explicit Apple platform scope')
    protected[args.decision] = sha(raw)
    return decision


def llvm_config_identity(args, context):
    prefix = Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip()); lexical = prefix/'opt/llvm@21/bin/llvm-config'
    resolved = context['transfer'].resolve_native(str(lexical)); path = Path(resolved['resolved_path']); raw = stable(path,32*2**20)
    need(stat.S_IMODE(path.lstat().st_mode) & 0o111, 'Executable selected LLVM config required')
    image = context['provider_parser'].macho(raw,context['transfer']); covered = context['covered_native_files']; dependencies = []; unresolved = []; total = len(raw); deadline = time.monotonic()+45
    need(len(image['imports']) <= 128 and len(image['rpaths']) <= 64, 'Finite additional provider import/rpath roster required')
    library = Path(context['selected_llvm_library']); need(path.parent.parent == library.parent.parent and path.parent.name == 'bin' and library.parent.name == 'lib', 'Exact selected LLVM config/library package prefix join required')
    for imported in image['imports']:
        clock(deadline)
        if imported.startswith('/usr/lib/') or imported.startswith('/System/Library/Frameworks/'):
            dependencies.append(dict(imported=imported,scope='Apple-platform',shared_cache_body_qualified=False)); continue
        candidates = []
        if imported.startswith('@loader_path/'):candidates = [str(path.parent/imported[len('@loader_path/'):])]
        elif imported.startswith('@rpath/'):
            for rpath in image['rpaths']:
                base = rpath.replace('@loader_path',str(path.parent))
                if Path(base).is_absolute() and (Path(base)/imported[len('@rpath/'):]).exists():candidates.append(str(Path(base)/imported[len('@rpath/'):]))
        elif imported.startswith('/'):candidates = [imported]
        if len(set(candidates)) != 1:
            unresolved.append(dict(imported=imported,candidates=candidates,reason='one unambiguous reviewed file resolution required')); continue
        resolution = context['provider_parser'].resolve_input(candidates[0],context['transfer']); physical = Path(resolution['resolved_path']); body = stable(physical,256*2**20); total += len(body); need(total <= 2**30 and len(dependencies) < 64, 'Original finite native file/aggregate ceiling required'); clock(deadline)
        identity_row = dict(path=str(physical),bytes=len(body),sha256=sha(body),mode=stat.S_IMODE(physical.lstat().st_mode))
        entry = dict(imported=imported,declared_path=candidates[0],resolved=identity_row,links=[{k:row[k] for k in ('path','target')} for row in resolution['links']],scope='admitted-native-file' if str(physical) in covered and all(covered[str(physical)][k] == value for k,value in identity_row.items() if k!='path') else 'uncovered-native-file')
        dependencies.append(entry)
        if entry['scope'] != 'admitted-native-file':unresolved.append(dict(imported=imported,candidates=candidates,reason='resolved bytes outside the independently admitted prior file closure'))
    clock(deadline)
    return dict(format='atlas-census-llvm-config-stable-v1',declared_path=str(lexical),resolved_path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(path.lstat().st_mode),imports=image['imports'],rpaths=image['rpaths'],links=[{k:row[k] for k in ('path','target')} for row in resolved['links']],package_version='21.1.8',selected_llvm_library=str(library),dependencies=dependencies,unresolved_imports=unresolved,native_file_closure_covered=not unresolved,dyld_shared_cache_bytes_qualified=False)

def llvm_config_physical(args, context):
    prefix = Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip())
    main = context['transfer'].resolve_native(str(prefix/'opt/llvm@21/bin/llvm-config')); logical = llvm_config_identity(args,context)
    dependencies = [context['provider_parser'].resolve_input(row['declared_path'],context['transfer']) for row in logical['dependencies'] if 'declared_path' in row]
    return dict(executable=main,dependencies=dependencies)


def native_inputs(args, context, protected):
    material = decode(stable(args.policy_result,2**20)); need(sha(stable(args.policy_result,2**20)) == args.policy_result_sha256, 'Externally pinned fresh native policy return required')
    admission = context['admitted']; need(material['format'] == 'atlas-native-buffer-policy-materialization-v1' and material['passed'] is True and material['execution_admitted'] is True and material['finalization_errors'] == [], 'Successful complete fresh native policy materialization required')
    need(material['job_identity'] == admission['job_identity'] and material['compiler_profile_sha256'] == admission['observed_profile_sha256'] and material['compiler_backend_sha256'] == admission['providers']['compiler_backend']['sha256'], 'Fresh native/source/tool/compiler job join required')
    need(material['policies']['PROOF_TOOLS.json'] == args.proof_tools_sha256 and material['policies']['TOOL_POLICY.json'] == args.tool_policy_sha256 and material['policies']['NATIVE_POLICY.json'] == args.native_policy_sha256, 'Exact independently materialized native/tool/registry policy roster required')
    need(sha(stable(args.native_policy,2**20)) == args.native_policy_sha256, 'Exact current native policy required')
    policy, native, aliases = context['probe'].native_policy(args.native_policy,args.native_policy_sha256,admission)
    for path in (args.policy_result,args.native_policy):protected[path] = sha(stable(path,2**20))
    return policy, native, aliases, material

def admit_observation(args):
    """Static input discovery uses the original execution-unadmitted observer."""
    deadline = time.monotonic()+PREPARATION_SECONDS
    protected = manifest(ROOT,args.packet_sha256)
    dependency = decode(stable(ROOT/'inputs/PROVIDER_DEPENDENCY.json',2**20)); protected.update(manifest(args.provider_packet,dependency['manifest_sha256'],32))
    provider = load(args.provider_packet/'provider_observation.py',dependency['controller_sha256'],'census_existing_static_provider_admission')
    values = argparse.Namespace(**vars(args)); values.packet_sha256 = dependency['manifest_sha256']
    context = provider.admit(values,deadline)
    raw = stable(args.native_observation/'OBSERVATION.json',8*2**20); current = provider.admit_observation(args.native_observation,sha(raw),deadline)
    need(current['job_identity'] == context['admitted']['job_identity'] and current['compiler_profile_sha256'] == context['admitted']['observed_profile_sha256'], 'Current native observation and fresh census metadata job/profile must match')
    context.update(provider_parser=provider,covered_native_files={row['path']:row for row in current['census']['files']},selected_llvm_library=current['selected']['llvm_library'])
    context['llvm_config'] = llvm_config_identity(args,context); context['llvm_config_physical'] = llvm_config_physical(args,context)
    original_check = context['check']
    def check():
        original_check(deadline); clock(deadline)
        need(llvm_config_identity(args,context) == context['llvm_config'] and llvm_config_physical(args,context) == context['llvm_config_physical'], 'Complete static LLVM config physical/alias/import/byte return required')
        need(stable(args.native_observation/'OBSERVATION.json',8*2**20) == raw, 'Original native metadata receipt return required')
        for path,expected in protected.items():need(sha(stable(path)) == expected, 'Census static observation executable source return required')
    context.update(check=check,native_materialization=dict(stable_view_sha256=current['stable_view_sha256']),metadata_native_receipt=dict(format=current['format'],passed=current['passed'],complete=current['complete'],source_provider_return_accepted=current['source_provider_return_accepted'],job_identity=current['job_identity'],compiler_profile_sha256=current['compiler_profile_sha256'],stable_view_sha256=current['stable_view_sha256'],source_manifest_sha256=current['sources']['observer'],receipt_sha256=sha(raw)))
    return context


def admit(args):
    protected = manifest(ROOT,args.packet_sha256)
    dependency = decode(stable(ROOT/'inputs/FEEDBACK_DEPENDENCY.json',2**20)); protected.update(manifest(args.feedback_packet,dependency['manifest_sha256']))
    feedback = load(args.feedback_packet/'run_source_feedback.py',dependency['controller_sha256'],'census_original_feedback_admission')
    values = argparse.Namespace(**vars(args)); values.packet_sha256 = dependency['manifest_sha256']; context = feedback.admit(values); protected.update(context['protected'])
    need(context['transfer'].sha(context['transfer'].canonical(context['transfer'].policy_view(context['native']))) == STABLE_TOOLS_SHA, 'Exact actual8855/rootc422 restricted native input authority required')
    policy, native, aliases, material = native_inputs(args,context,protected)
    provider_dependency = decode(stable(ROOT/'inputs/PROVIDER_DEPENDENCY.json',2**20)); provider_path = ROOT/'dependencies/provider_v101/provider_observation.py'
    provider = load(provider_path,provider_dependency['controller_sha256'],'census_existing_native_import_resolver')
    context.update(provider_parser=provider,covered_native_files=native,selected_llvm_library=policy['llvm_library'])
    context['llvm_config'] = llvm_config_identity(args,context)
    context['llvm_config_physical'] = llvm_config_physical(args,context)
    context['native_materialization'] = material
    decision = admit_decision(args,context,protected) if args.operation == 'execute' else None
    if decision is not None:need(decision['reviewed_native_stable_view_sha256'] == material['stable_view_sha256'], 'Separately reviewed compiler/native stable view required')
    original_check = context['check']
    def check():
        original_check(); need(llvm_config_identity(args,context) == context['llvm_config'] and llvm_config_physical(args,context) == context['llvm_config_physical'], 'Complete selected LLVM config physical/alias/import/byte return required'); context['probe'].native_policy(args.native_policy,args.native_policy_sha256,context['admitted'])
        for path, expected in protected.items():need(sha(stable(path,256*2**20)) == expected, 'Complete protected API source/provider/decision return required')
    context.update(check=check,protected=protected,decision=decision,native_policy=policy,native_files=native,native_aliases=aliases)
    return context

def validate_terminal(contract, row, seconds, output, group, lookup=False, expected=0):
    need(type(row['exit_code']) is int and type(row['expected_exit']) is int and row['expected_exit'] == expected, 'Original expected/actual command statuses required')
    # Research retains genuine absent/unavailable cards. Only this explicit status
    # projection relaxes exit equality; every original resource/stream/group field
    # stays exact and the unaltered Runner record is preserved in the JSONL.
    projection = copy.deepcopy(row)
    if lookup:
        need(expected == 0 and row['exit_code'] in (0,2,3,4,5), 'Known released lookup status required'); projection['expected_exit'] = row['exit_code']; expected = row['exit_code']
    need(row['maximum_seconds'] == seconds, 'Original per-command horizon required')
    return contract.terminal(projection,seconds,expected=expected,output=output,observation=group)

def card(raw, query, exit_code, verification=False):
    try:
        value = decode(raw.encode()); need(type(value) is dict and value['query'] == query, 'Exact queried API card required')
        status = value['status']; exits = {'found':0,'present':0,'candidates':3,'unknown':4,'absent':5}
        need(exit_code == exits.get(status,2), 'Released API status/exit equality required')
        need(type(value['entries']) is list and all(type(entry) is dict for entry in value['entries']), 'Typed complete API entry roster required')
        accepted = exit_code == 0 and status in ('found','present') and value['freshness'] == 'fresh' and bool(value['entries']) and value['api_card_errors'] == [] and value['failure_reason'] is None
        if verification:accepted = accepted and value['verification_status'] == 'present'
        return dict(query=query,card=value,accepted=bool(accepted),verification=verification,error=None)
    except BaseException as error:
        return dict(query=query,card=None,accepted=False,verification=verification,error=type(error).__name__+': '+str(error))

def execute(args, context, owned, started):
    deadline = started + OUTER_SECONDS; run_deadline = deadline - RETURN_SECONDS; output = owned.root
    contract = load(ROOT/'vendor/command_contract.py',CONTRACT_SHA,'census_original_terminal_reader')
    runner = context['driver'].Runner(output); runner.deadline = run_deadline
    allowed = dict(command_roster()); roster = decode(stable(ROOT/'API_ROSTER.json')); queries = roster['queries']; need(len(queries) == len({q['query'] for q in queries}) == 56, 'Complete56 API question roster required')
    result = dict(format='atlas-compiler-census-api-result-v1',passed=False,diagnostic_collection_complete=False,compiler_color='UNEXECUTED',maximum_seconds=OUTER_SECONDS,return_seconds=RETURN_SECONDS,command_seconds_worst_case=2280,job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'],compiler_backend_sha256=context['admitted']['providers']['compiler_backend']['sha256'],source_manifest_sha256=args.packet_sha256,scope_decision_sha256=args.decision_sha256,actual_target_cells_accepted=0,whole_build_memory_qualified=False,retained_owner_attribution_implemented=False,source_provider_return_accepted=False,private_removed=False,finalization_errors=[])
    private = None; original = None; expected = {}; cards = []; evidence = []; complete = False; admitted_commands = {}; proxy_config = None; working = None; private_identity = None
    def run(label, argv, env, *, expected_exit=0, lookup=False):
        seconds = allowed[label]; owned.check(); clock(run_deadline)
        need(label not in admitted_commands and len(runner.records) < 123 and run_deadline-time.monotonic() >= seconds+1, 'Full unchanged command ceiling and return reserve required before launch')
        count = len(runner.records); caught = None
        try:runner.run(label,list(map(str,argv)),cwd=project,environment=env,expected_exit=expected_exit,seconds=seconds)
        except BaseException as error:caught = error
        need(len(runner.records) == count+1 and len(runner.group_observations) == len(runner.records), 'Exactly one complete retained Runner/group observation required')
        row = runner.records[-1]; group = runner.group_observations[-1]; admitted_commands[label] = copy.deepcopy(row)
        need(row['label'] == label and row['arguments'] == list(map(str,argv)), 'Exact planned compiler/API argv required')
        stdout,stderr = validate_terminal(contract,row,seconds,output,group,lookup=lookup,expected=expected_exit)
        evidence.append(dict(record=row,stdout=stdout,stderr=stderr,status_projection='released-lookup-exit-only' if lookup else 'original-terminal-contract'))
        if caught is not None and not lookup:raise caught
        owned.check(); working_bound(private); return row,stdout,stderr
    try:
        need(time.monotonic()-started <= PREPARATION_SECONDS and run_deadline-time.monotonic() >= 2280, 'Full2280 command seconds at entry plus180 return seconds required')
        private = output/'private'; private.mkdir(mode=0o700); private_identity = identity(private)[:3]; project = private/'compiler'; original = extract_project(project,min(started+PREPARATION_SECONDS,run_deadline)); expected = {k:{a:b for a,b in row.items() if a != 'physical_identity'} for k,row in original['files'].items()}
        (private/'home').mkdir(); (private/'cache').mkdir(); (private/'bin').mkdir(); (project/'census_probes').mkdir(); expected['census_probes'] = dict(path='census_probes',kind='directory',mode=stat.S_IMODE((project/'census_probes').lstat().st_mode))
        for name in PROBES:
            raw = stable(ROOT/'inputs'/(name+'.cr.txt')); rel = 'census_probes/'+name+'.cr'; path = project/rel; path.write_bytes(raw); expected[rel] = dict(path=rel,kind='file',mode=0o644,bytes=len(raw),sha256=sha(raw)); owned.write('probe_sources/'+name+'.cr.txt',raw)
        original = physical_tree(project,expected,run_deadline)
        wrapper = context['paths']['compiler_wrapper']; backend = context['paths']['compiler_backend']; python = Path(sys.executable).resolve(); stdlib = Path((args.sdk_evidence/'brew-prefix.stdout.txt').read_text().strip())/'share/agent-crystal/src'
        env = {k:v for k,v in os.environ.items() if k in ('TMPDIR','SDKROOT','DEVELOPER_DIR')}
        env.update(HOME=str(private/'home'),PATH=str(private/'bin')+os.pathsep+'/usr/bin:/bin',CRYSTAL_PATH=str(project/'lib')+os.pathsep+str(project/'src'),CRYSTAL_WORKERS='1',CRYSTAL_CACHE_DIR=str(private/'cache'),CRYSTAL_HAS_WRAPPER='1',CRYSTAL_CONFIG_BUILD_COMMIT=COMPILER_COMMIT,LLVM_CONFIG=context['llvm_config']['declared_path'],LLVM_VERSION='21.1.8',LLVM_TARGETS='AArch64',LLVM_LDFLAGS=context['native_policy']['llvm_library'],LC_ALL='C',NO_COLOR='1',PYTHONDONTWRITEBYTECODE='1')
        proxy = private/'bin/crystal-alpha'; proxy_raw = ('#!'+str(python)+'\n').encode()+stable(ROOT/'compiler_proxy.py'); need(' ' not in str(python), 'Exact shebang-compatible admitted Python path required'); proxy.write_bytes(proxy_raw); proxy.chmod(0o755)
        journal = private/'PROXY_COMMANDS.jsonl'; journal.write_bytes(b'')
        fixed_environment = {k:v for k,v in env.items() if k != 'CRYSTAL_CACHE_DIR'}
        providers = [dict(path=str(path),sha256=sha(stable(path,256*2**20))) for path in (python,wrapper,backend,proxy)]
        config = dict(format='atlas-census-compiler-proxy-v1',backend=str(backend),project=str(project),private=str(private),private_identity=private_identity,stdlib=str(stdlib),environment=fixed_environment,providers=providers,journal=str(journal),journal_identity=identity(journal)[:3])
        proxy_config = private/'PROXY_CONFIG.json'; proxy_config.write_bytes(canonical(config)); env.update(ATLAS_CENSUS_PROXY_CONFIG=str(proxy_config),ATLAS_CENSUS_PROXY_CONFIG_SHA256=sha(stable(proxy_config)))
        proxy_before = {path:sha(stable(path,256*2**20)) for path in (proxy,proxy_config)}
        owned.json('ADMISSION.json',dict(SDK=context['admitted'],tools=context['tools'],native_policy=context['native_policy'],decision=context['decision'],proxy=config,source_archive_sha256=ARCHIVE_SHA,source_commit=COMPILER_COMMIT,context=CONTEXT,llvm_config=context['llvm_config']))
        for name,path in [('SCOPE_DECISION.json',args.decision),('NATIVE_POLICY.json',args.native_policy),('POLICY_RESULT.json',args.policy_result),('TOOL_POLICY.json',args.tool_policy),('PROOF_TOOLS.json',args.proof_tools)]:owned.write(name,stable(path,2**20))
        owned.write('API_ROSTER.json',stable(ROOT/'API_ROSTER.json'))
        need(time.monotonic()-started <= PREPARATION_SECONDS and run_deadline-time.monotonic() >= 2280, 'All original command seconds must remain after complete source projection')
        row,stdout,stderr = run('llvm-config-version',[context['llvm_config']['declared_path'],'--version'],env); need(stdout == '21.1.8\n' and not stderr, 'Actual selected reviewed LLVM config version required')
        for label,key,version in [('amber-lsp-version','amber_lsp','2.0.7'),('ameba-version','ameba','1.7.0-dev')]:
            row,stdout,stderr = run(label,[context['tools']['tools'][key]['path'],'--version'],env); need(version in stdout and not stderr, 'Admitted released analysis-tool version required')
        for index,query in enumerate(queries):
            method = query['query']; argv = [context['tools']['tools']['amber_lsp']['path'],'lookup',method,'--root',str(project),'--json']
            row,stdout,stderr = run('api-'+str(index),argv,env,lookup=True); answer = card(stdout,method,row['exit_code']); answer['stderr'] = stderr
            entries = [answer]
            if row['exit_code'] == 4 and answer['card'] is not None and answer['card']['status'] == 'unknown':
                row,stdout,stderr = run('api-verify-'+str(index),argv+['--verify'],env,lookup=True); answer = card(stdout,method,row['exit_code'],True); answer['stderr'] = stderr; entries.append(answer)
            cards.append(dict(query=method,required=query['required'],attempts=entries,accepted=answer['accepted']))
        for name in PROBES:
            row,stdout,stderr = run('format-'+name,[wrapper,'tool','format','--check',str(project/'census_probes'/(name+'.cr'))],env)
            need(not stdout and not stderr, 'Actual formatter acceptance remains required')
        colors = []
        for name in PROBES:
            expected_exit = 1 if name == 'gc_stats_wrong_type' else 0
            row,stdout,stderr = run('compatibility-'+name,[proxy,'build','--no-codegen',str(project/'census_probes'/(name+'.cr'))],env,expected_exit=expected_exit)
            if expected_exit == 1:
                need('UInt64' in stderr and 'String' in stderr and 'Error' in stderr, 'Actual discriminating wrong-type compiler refusal required')
            else:colors.append('GREEN' if not stdout and not stderr else 'YELLOW')
        result['compiler_color'] = 'GREEN' if colors == ['GREEN']*3 else 'YELLOW'; complete = True
    except BaseException as error:
        result['error'] = type(error).__name__+': '+str(error)
        if runner.records and runner.records[-1]['label'].startswith('compatibility-') and runner.records[-1]['exit_code'] != runner.records[-1]['expected_exit']:result['compiler_color'] = 'RED'
    finally:
        def returned(action):
            try:action()
            except BaseException as error:result['finalization_errors'].append(type(error).__name__+': '+str(error))
        returned(lambda:(owned.check(),clock(deadline),context['check']()))
        evidence = []
        for row,group in zip(runner.records,runner.group_observations):
            def record_return():
                need(row == admitted_commands.get(row['label']), 'Original command records must return unchanged')
                validate_terminal(contract,row,allowed[row['label']],output,group,lookup=row['label'].startswith('api-'),expected=row['expected_exit'])
            returned(record_return)
            def retain_record():
                stdout = stable(output/(row['label']+'.stdout.txt'),MAX_RAW).decode('utf-8'); stderr = stable(output/(row['label']+'.stderr.txt'),MAX_RAW).decode('utf-8')
                evidence.append(dict(record=row,stdout=stdout,stderr=stderr,status_projection='released-lookup-exit-only' if row['label'].startswith('api-') else 'original-terminal-contract'))
            returned(retain_record)
        def all_writers_return():
            need(runner.writers_confirmed_retired and len(runner.records) == len(runner.group_observations), 'All original API/compiler writers must return before source readback')
        returned(all_writers_return)
        if runner.writers_confirmed_retired:
            if original is not None:
                def source_return():
                    need(physical_tree(project,expected,deadline) == original, 'Complete canonical source/alias/fixture physical return required'); owned.json('SOURCE_RETURN.json',original)
                returned(source_return)
            if proxy_config is not None:
                def proxy_return():
                    for path, expected_sha in proxy_before.items():need(sha(stable(path)) == expected_sha, 'Transparent compiler proxy/configuration return required')
                    owned.write('PROXY_CONFIG.json',stable(proxy_config)); owned.write('PROXY_COMMANDS.jsonl',stable(journal,4*2**20))
                returned(proxy_return)
            if private is not None:
                def cleanup():
                    nonlocal working
                    need(identity(private)[:3] == private_identity and stat.S_ISDIR(private.lstat().st_mode), 'Original private source/cache root required before cleanup'); working = working_bound(private); shutil.rmtree(private); need(not private.exists(), 'Owned canonical source/cache workspace must be removed'); result['private_removed'] = True
                returned(cleanup)
        result['source_provider_return_accepted'] = not result['finalization_errors']
        result.update(commands=len(runner.records),original_groups=runner.group_observations,writers_confirmed_retired=runner.writers_confirmed_retired,working_bound=working,elapsed_seconds=time.monotonic()-started,diagnostic_collection_complete=complete,required_API_cards_accepted=len(cards) == 56 and all(row['accepted'] or not row['required'] for row in cards))
        result['passed'] = complete and result['required_API_cards_accepted'] and result['compiler_color'] == 'GREEN' and result['source_provider_return_accepted'] and result['private_removed'] and not result['finalization_errors'] and finite(result['elapsed_seconds'],0,OUTER_SECONDS)
        owned.json('API_CARDS.json',cards); owned.write('COMMAND_EVIDENCE.jsonl',b''.join(canonical(row)+b'\n' for row in evidence)); owned.json('RESULT.json',result)
        result['elapsed_seconds'] = time.monotonic()-started
        if not finite(result['elapsed_seconds'],0,OUTER_SECONDS):result['passed'] = False; result['finalization_errors'].append('Complete API receipt write exceeded the original2700-second horizon')
        owned.json('RESULT.json',result)
    return 0 if result['passed'] else 2

def main(args):
    started = time.monotonic(); owned = Owned(args.output)
    try:
        context = admit_observation(args) if args.operation == 'observe' else admit(args)
        if args.operation == 'observe':
            metadata_admission = dict(format='atlas-census-metadata-admission-v1',SDK=context['admitted'],native_receipt=context['metadata_native_receipt'],llvm_config_before=context['llvm_config'],llvm_config_physical_before=context['llvm_config_physical'])
            owned.json('METADATA_ADMISSION.json',metadata_admission)
            candidate = dict(format='atlas-census-provider-candidate-v1',execution_admitted=False,llvm_config=context['llvm_config'],llvm_config_physical=context['llvm_config_physical'],job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'],compiler_backend_sha256=context['admitted']['providers']['compiler_backend']['sha256'],native_stable_view_sha256=context['native_materialization']['stable_view_sha256'],source_manifest_sha256=args.packet_sha256,compiler_archive_sha256=ARCHIVE_SHA,API_roster_sha256=sha(stable(ROOT/'API_ROSTER.json')),context=CONTEXT,actual_compiler_commands=0,maximum_seconds=PREPARATION_SECONDS,metadata_admission_sha256=sha(stable(owned.root/'METADATA_ADMISSION.json')))
            context['check'](); need(time.monotonic()-started <= PREPARATION_SECONDS, 'Bounded120-second metadata-only census observation required'); candidate.update(source_provider_return_accepted=True,elapsed_seconds=time.monotonic()-started)
            owned.json('CENSUS_PROVIDER_CANDIDATE.json',candidate); return 0
        return execute(args,context,owned,started)
    except BaseException as error:
        owned.json('ADMISSION_REFUSAL.json',dict(format='atlas-compiler-census-api-admission-refusal-v1',passed=False,error=type(error).__name__+': '+str(error),elapsed_seconds=time.monotonic()-started,actual_target_cells_accepted=0))
        return 2

def arguments():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('operation',choices=('observe','execute'))
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','feedback-packet','output'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('provider-packet','native-observation','proof-tools','tool-policy','native-policy','policy-result'):parser.add_argument('--'+name,type=Path)
    for name in ('packet','python'):parser.add_argument('--'+name+'-sha256',required=True)
    for name in ('proof-tools','tool-policy','native-policy','policy-result'):parser.add_argument('--'+name+'-sha256')
    parser.add_argument('--decision',type=Path); parser.add_argument('--decision-sha256')
    return parser.parse_args()

if __name__ == '__main__':
    raise SystemExit(main(arguments()))
