"""Separate static LLVM provider admission for compiler API and no-codegen research."""
import argparse
import copy
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent
OBSERVATION_SECONDS = 180
POLICY_SECONDS = 120
MAX_FILE = 256 * 2**20
MAX_TOTAL = 2**30
MAX_IMAGES = 64
MAX_ALIASES = 128
SCOPE = 'compiler-census-api-and-concrete-receiver-only'


def need(value, message):
    if not value:raise RuntimeError(message)


def pkg_helper(model):
    rows=model.decode(model.stable(ROOT/'SOURCE_PINS.json',2**20))['files']
    expected=next(row['sha256'] for row in rows if row['path']=='pkgconf_provider.py')
    return model.load(ROOT/'pkgconf_provider.py',expected,'census_source_bound_pkgconf_metadata')


def provider(model):
    dependency = model.decode(model.stable(ROOT/'inputs/PROVIDER_DEPENDENCY.json'))
    path = ROOT/'dependencies/provider_v101'
    model.manifest(path,dependency['manifest_sha256'],32)
    return model.load(path/'provider_observation.py',dependency['controller_sha256'],'api_only_original_provider_admission'), dependency


def base(model, args, deadline):
    model.manifest(ROOT,args.packet_sha256)
    original, dependency = provider(model)
    values = argparse.Namespace(**vars(args)); values.packet_sha256 = dependency['manifest_sha256']
    context = original.admit(values,deadline)
    need(model.sha(model.canonical(context['transfer'].policy_view(context['tool_native']))) == model.STABLE_TOOLS_SHA, 'Exact8855/rootc422 analysis-tool stable native authority required')
    context['provider_parser'] = original
    return context


def collect(model, args, context, deadline):
    """Read selected LLVM package images and aliases; subprocess count remains zero."""
    original = context['provider_parser']; transfer = context['transfer']
    prefix = Path(model.stable(args.sdk_evidence/'brew-root.stdout.txt').decode().strip())
    need(prefix.is_absolute() and prefix.resolve(strict=True) == prefix, 'Physical ordinary Homebrew root required')
    config = prefix/'opt/llvm@21/bin/llvm-config'; library = prefix/'opt/llvm@21/lib/libLLVM.dylib'
    rows = {}; resolutions = {}; packages = {}; images = []; apple = set(); unresolved = []; total = 0
    context['partial_static'] = dict(files=rows,resolutions=resolutions,packages=packages,images=images,unresolved=unresolved)
    def read(lexical, kind):
        nonlocal total
        model.clock(deadline); resolution = original.resolve_input(str(lexical),transfer)
        need(str(lexical) not in resolutions or resolutions[str(lexical)] == resolution, 'Exact revisited lexical identity required')
        resolutions[str(lexical)] = resolution; need(len(resolutions) <= MAX_ALIASES, 'Finite128 lexical provider input bound required')
        path = Path(resolution['resolved_path'])
        need(path.is_relative_to(prefix/'Cellar'), 'Selected open-source LLVM inputs remain inside ordinary Homebrew Cellar')
        if str(path) in rows:
            need(model.identity(path) == rows[str(path)]['physical_identity'], 'Revisited original physical provider identity required')
            return rows[str(path)], model.stable(path,MAX_FILE)
        raw = model.stable(path,MAX_FILE); total += len(raw)
        need(total <= MAX_TOTAL and len(rows) < 3*MAX_IMAGES, 'Finite1-GiB/192-file selected provider census required')
        row = dict(path=str(path),bytes=len(raw),sha256=model.sha(raw),mode=stat.S_IMODE(path.lstat().st_mode),physical_identity=model.identity(path),kind=kind)
        need(row['physical_identity'] == resolution['resolved_physical_identity'], 'Exact lexical/physical provider file join required')
        rows[str(path)] = row; model.clock(deadline)
        return row, raw
    def package(path):
        relative = Path(path).relative_to(prefix/'Cellar'); need(len(relative.parts) >= 3, 'Exact selected installed package prefix required')
        name, version = relative.parts[:2]; physical = prefix/'Cellar'/name/version
        if str(physical) in packages:return
        receipt, raw = read(physical/'INSTALL_RECEIPT.json','package-receipt'); value = model.decode(raw)
        formula, _ = read(physical/'.brew'/(name+'.rb'),'package-formula')
        need(value['arch'] == 'arm64' and value['source']['spec'] == 'stable' and value['source']['versions']['stable'], 'Actual installed ARM64 stable source receipt required')
        if name == 'llvm@21':need(value['source']['versions']['stable'] == '21.1.8' and re.fullmatch(r'21\.1\.8(?:_[0-9]+)?',version) is not None, 'Exact reviewed LLVM21.1.8 installed package required')
        opt = original.resolve_input(str(prefix/'opt'/name/'INSTALL_RECEIPT.json'),transfer)
        need(Path(opt['resolved_path']) == physical/'INSTALL_RECEIPT.json', 'Actual selected package/opt alias join required')
        read(prefix/'opt'/name/'INSTALL_RECEIPT.json','package-receipt')
        stable_receipt = dict(source={k:v for k,v in value['source'].items() if k in ('versions','spec','tap','tap_git_head')},arch=value['arch'],compiler=value.get('compiler'),poured_from_bottle=value.get('poured_from_bottle'),runtime_dependencies=value.get('runtime_dependencies',[]))
        packages[str(physical)] = dict(name=name,version=version,physical_prefix=str(physical),formula_sha256=formula['sha256'],receipt_sha256=receipt['sha256'],stable_receipt=stable_receipt)
    pkg_executable=prefix/'bin/pkg-config'; pcfile=prefix/'opt/bdw-gc/lib/pkgconfig/bdw-gc.pc'; gc_library=prefix/'opt/bdw-gc/lib/libgc.1.dylib'
    pc_row,pc_raw=read(pcfile,'pkg-config-metadata'); need(len(pc_raw)<=65536,'Finite selected GC pcfile metadata required'); package(pc_row['path'])
    pending = [str(config),str(library),str(pkg_executable),str(gc_library)]; visited = set()
    while pending:
        lexical = pending.pop(0); row, raw = read(lexical,'native-image'); physical = row['path']; package(physical)
        if physical in visited:continue
        need(len(visited) < MAX_IMAGES, 'Finite64-image actual LLVM metadata closure required'); visited.add(physical)
        image = original.macho(raw,transfer); need(len(image['imports']) <= 128 and len(image['rpaths']) <= 64, 'Finite complete image import/rpath roster required')
        images.append(dict(row,imports=image['imports'],rpaths=image['rpaths']))
        for imported in image['imports']:
            if imported.startswith('/usr/lib/') or imported.startswith('/System/Library/Frameworks/'):
                apple.add(imported); continue
            candidates = []
            if imported.startswith('@loader_path/'):candidates = [str(Path(physical).parent/imported[len('@loader_path/'):])]
            elif imported.startswith('/') :candidates = [imported]
            elif imported.startswith('@rpath/'):
                for rpath in image['rpaths']:
                    base_path = rpath.replace('@loader_path',str(Path(physical).parent))
                    if Path(base_path).is_absolute():
                        candidate = Path(base_path)/imported[len('@rpath/'):]
                        if candidate.exists() or candidate.is_symlink():candidates.append(str(candidate))
            if len(set(candidates)) != 1:
                unresolved.append(dict(image=physical,imported=imported,candidates=candidates,reason='one direct unambiguous static package resolution required')); continue
            candidate = Path(candidates[0])
            if not candidate.exists():
                unresolved.append(dict(image=physical,imported=imported,candidates=candidates,reason='selected import is absent')); continue
            pending.extend(candidates)
    configuration = original.resolve_input(str(config),transfer); selected_library = original.resolve_input(str(library),transfer)
    need(Path(configuration['resolved_path']).parent.parent == Path(selected_library['resolved_path']).parent.parent, 'Exact selected LLVM config/shared-library package join required')
    need(rows[configuration['resolved_path']]['mode'] & 0o111, 'Executable actual LLVM-config input required')
    context.update(covered_native_files=rows,selected_llvm_library=selected_library['resolved_path'])
    try:
        descriptor = model.llvm_config_identity(args,context); physical_descriptor = model.llvm_config_physical(args,context)
    except FileNotFoundError:
        need(bool(unresolved), 'Missing selected input must have retained unresolved evidence')
        current = rows[configuration['resolved_path']]; parsed = next(row for row in images if row['path'] == current['path'])
        descriptor = dict(format='atlas-census-llvm-config-stable-v1',declared_path=str(config),resolved_path=current['path'],bytes=current['bytes'],sha256=current['sha256'],mode=current['mode'],imports=parsed['imports'],rpaths=parsed['rpaths'],links=[dict(path=r['path'],target=r['target']) for r in configuration['links']],package_version='21.1.8',selected_llvm_library=selected_library['resolved_path'],dependencies=[],unresolved_imports=copy.deepcopy(unresolved),native_file_closure_covered=False,dyld_shared_cache_bytes_qualified=False)
        physical_descriptor = dict(executable=configuration,dependencies=[])
    stable_files = [{k:r[k] for k in ('path','bytes','sha256','mode','kind')} for _,r in sorted(rows.items())]
    stable_packages = [{k:v for k,v in p.items() if k != 'receipt_sha256'} for _,p in sorted(packages.items())]
    # INSTALL_RECEIPT includes per-install timestamps. Its exact bytes return in
    # this job; the reviewed cross-job role uses its complete selected source fields.
    for row in stable_files:
        if row['kind'] == 'package-receipt':
            receipt = model.decode(model.stable(row['path'],MAX_FILE))
            row.pop('sha256'); row.pop('bytes'); row['stable_receipt'] = dict(source={k:v for k,v in receipt['source'].items() if k in ('versions','spec','tap','tap_git_head')},arch=receipt['arch'],compiler=receipt.get('compiler'),poured_from_bottle=receipt.get('poured_from_bottle'),runtime_dependencies=receipt.get('runtime_dependencies',[]))
    pkg=pkg_helper(model).descriptor(model,prefix,list(rows.values()),list(resolutions.values()),list(packages.values()),images,pc_raw,unresolved)
    view = dict(pkgconf=pkg,format='atlas-census-api-only-stable-inputs-v1',source_manifest_sha256=args.packet_sha256,analysis_stable_sha256=model.STABLE_TOOLS_SHA,tool_native=context['transfer'].policy_view(context['tool_native']),selected=dict(llvm_config=str(config),llvm_library=selected_library['resolved_path']),packages=stable_packages,files=stable_files,lexical=[dict(declared_path=r['declared_path'],resolved_path=r['resolved_path'],links=[dict(path=x['path'],target=x['target']) for x in r['links']]) for _,r in sorted(resolutions.items())],images=[{k:r[k] for k in ('path','bytes','sha256','mode','imports','rpaths')} for r in images],Apple_imports=sorted(apple),unresolved=unresolved,frontier=pending,llvm_config=descriptor,dyld_shared_cache_bytes_qualified=False,C_shim_and_headers_qualified=False,whole_build_memory_qualified=False)
    physical = dict(files=[r for _,r in sorted(rows.items())],resolutions=[r for _,r in sorted(resolutions.items())],packages=[r for _,r in sorted(packages.items())],total_bytes=total,llvm_config=physical_descriptor)
    model.clock(deadline)
    return dict(stable_view=view,stable_view_sha256=model.sha(model.canonical(view)),physical=physical,llvm_config=descriptor,llvm_config_physical=physical_descriptor,complete=not unresolved and not pending and descriptor['native_file_closure_covered'])


def validate_observation(model, observation, expected):
    need(observation['format'] == 'atlas-census-api-only-static-observation-v1' and observation['source_manifest_sha256'] == expected, 'Exact separate API-only static observation source required')
    need(observation['execution_admitted'] is False and type(observation['actual_compiler_API_native_commands']) is int and observation['actual_compiler_API_native_commands'] == 0, 'Static provider observation retains zero executed compiler/API/native commands')
    need(observation['maximum_seconds'] == OBSERVATION_SECONDS and type(observation['maximum_seconds']) is int and model.finite(observation['elapsed_seconds'],0,OBSERVATION_SECONDS), 'Finite180-second complete static metadata observation required')
    need(observation['source_provider_return_accepted'] is True and observation['private_removed'] is True and observation['finalization_errors'] == [], 'Complete static source/provider/private return required')
    observed = observation['inputs']; view = observed['stable_view']
    need(observed['stable_view_sha256'] == model.sha(model.canonical(view)) and view['source_manifest_sha256'] == expected and view['analysis_stable_sha256'] == model.STABLE_TOOLS_SHA, 'Exact source-bound stable provider projection required')
    need(view['llvm_config'] == observed['llvm_config'] and observed['llvm_config_physical'] == observed['physical']['llvm_config'] and view['dyld_shared_cache_bytes_qualified'] is False and view['C_shim_and_headers_qualified'] is False and view['whole_build_memory_qualified'] is False, 'Exact separate static provider/physical/scope joins required')
    need(observation['passed'] is observed['complete'] and observation['complete'] is observed['complete'] and type(observed['complete']) is bool, 'Explicit complete or unresolved observation result required')
    need(observed['complete'] is (not view['unresolved'] and not view['frontier'] and observed['llvm_config']['native_file_closure_covered']), 'Actual retained unresolved/frontier status must determine static closure')
    physical = observed['physical']; files = physical['files']; resolutions = physical['resolutions']
    need(type(files) is list and 0 < len(files) <= 3*MAX_IMAGES and len({r['path'] for r in files}) == len(files), 'Complete unique physical provider file roster required')
    need(type(resolutions) is list and len({r['declared_path'] for r in resolutions}) == len(resolutions), 'Complete unique lexical provider roster required')
    by_path = {r['path']:r for r in files}; stable_files = {r['path']:r for r in view['files']}
    need(set(by_path) == set(stable_files) and type(physical['total_bytes']) is int and physical['total_bytes'] == sum(r['bytes'] for r in files), 'Exact stable/physical complete file and byte roster required')
    for path,row in by_path.items():
        need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE and type(row['mode']) is int and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None and Path(path).is_absolute(), 'Exact bounded physical provider bytes/mode/path/hash required')
        stable_row = stable_files[path]
        need(all(stable_row[k] == row[k] for k in ('path','mode','kind')), 'Exact stable provider role/path/mode join required')
        if row['kind'] != 'package-receipt':need(all(stable_row[k] == row[k] for k in ('bytes','sha256')), 'Exact stable provider file bytes required')
    need(view['lexical'] == [dict(declared_path=r['declared_path'],resolved_path=r['resolved_path'],links=[dict(path=x['path'],target=x['target']) for x in r['links']]) for r in resolutions] and all(r['resolved_path'] in by_path and r['resolved_physical_identity'] == by_path[r['resolved_path']]['physical_identity'] for r in resolutions), 'Complete stable/physical lexical alias resolution join required')
    need({r['path'] for r in view['images']} == {r['path'] for r in files if r['kind'] == 'native-image'}, 'Complete selected native image roster required')
    for row in view['images']:need(all(row[k] == by_path[row['path']][k] for k in ('bytes','sha256','mode')) and len(row['imports']) <= 128 and len(row['rpaths']) <= 64, 'Exact finite image/physical import metadata join required')
    need(model.sha(model.canonical(view['tool_native'])) == model.STABLE_TOOLS_SHA, 'Exact independently accepted8855/rootc422 tool-native static authority required')
    pkg_helper(model).validate(model,view['pkgconf'],by_path)
    need(view['pkgconf']['native_file_closure_covered'] is (not view['unresolved'] and not view['frontier']),'Exact pkgconf loading closure status required')
    sdk = observation['SDK']; need(observation['job_identity'] == sdk['job_identity'] and observation['compiler_profile_sha256'] == sdk['observed_profile_sha256'] and observation['compiler_backend_sha256'] == sdk['providers']['compiler_backend']['sha256'], 'Fresh actual metadata SDK/job/profile/backend join required')
    need(0 < len(view['images']) <= MAX_IMAGES and 0 < len(observed['physical']['resolutions']) <= MAX_ALIASES and observed['physical']['total_bytes'] <= MAX_TOTAL, 'Exact finite provider-image/alias/byte bounds required')
    return observation


def fresh(model, args, seconds):
    started = time.monotonic(); deadline = started+seconds; context = base(model,args,deadline); args._api_observation_context = context; context['phase_deadline'] = deadline; context['base_check'] = context['check']
    observed = collect(model,args,context,deadline)
    retained_pkg = None if args.operation=='observe-pkgconf' else pkg_helper(model).retained(model,args,context,observed,validate_observation)
    original_check = context['check']
    def check():
        end = min(time.monotonic()+60,context['phase_deadline']); model.clock(end); original_check(end)
        need(collect(model,args,context,end) == observed, 'Complete original LLVM/native/package/alias/physical source return required')
        if retained_pkg is not None:need(model.stable(args.pkgconf_observation,16*2**20)==retained_pkg,'Original separately observed pkgconf receipt must return')
        model.manifest(ROOT,args.packet_sha256); model.clock(end)
    context.update(pkgconf=observed['stable_view']['pkgconf'],pkgconf_observation_raw=retained_pkg,check=check,llvm_config=observed['llvm_config'],llvm_config_physical=observed['llvm_config_physical'],static_inputs=observed,paths={k:Path(v['path']) for k,v in context['admitted']['providers'].items()})
    return started,deadline,context


def observation_record(model, args, context, started):
    sdk = context['admitted']
    return dict(format='atlas-census-api-only-static-observation-v1',passed=context['static_inputs']['complete'],complete=context['static_inputs']['complete'],execution_admitted=False,SDK=sdk,job_identity=sdk['job_identity'],compiler_profile_sha256=sdk['observed_profile_sha256'],compiler_backend_sha256=sdk['providers']['compiler_backend']['sha256'],source_manifest_sha256=args.packet_sha256,inputs=context['static_inputs'],maximum_seconds=OBSERVATION_SECONDS,actual_compiler_API_native_commands=0,source_provider_return_accepted=True,private_removed=True,finalization_errors=[],elapsed_seconds=time.monotonic()-started)


def observe(model, args, owned):
    started = time.monotonic(); context = None
    try:
        _, deadline, context = fresh(model,args,OBSERVATION_SECONDS)
        context['check'](); model.clock(deadline)
        sdk = context['admitted']; value = observation_record(model,args,context,started)
        validate_observation(model,value,args.packet_sha256); owned.json('LLVM_STATIC_INPUTS.json',value)
        receipt = dict(format=value['format'],passed=True,complete=True,source_provider_return_accepted=True,job_identity=sdk['job_identity'],compiler_profile_sha256=sdk['observed_profile_sha256'],stable_view_sha256=value['inputs']['stable_view_sha256'],source_manifest_sha256=args.packet_sha256,receipt_sha256=model.sha(model.stable(owned.root/'LLVM_STATIC_INPUTS.json')))
        need(value['passed'] is True, 'Unresolved static LLVM inputs retained; positive closure review remains pending')
        metadata = dict(format='atlas-census-metadata-admission-v1',SDK=sdk,native_receipt=receipt,llvm_config_before=context['llvm_config'],llvm_config_physical_before=context['llvm_config_physical'])
        owned.json('METADATA_ADMISSION.json',metadata)
        candidate = dict(format='atlas-census-provider-candidate-v1',execution_admitted=False,llvm_config=context['llvm_config'],llvm_config_physical=context['llvm_config_physical'],job_identity=sdk['job_identity'],compiler_profile_sha256=sdk['observed_profile_sha256'],compiler_backend_sha256=sdk['providers']['compiler_backend']['sha256'],native_stable_view_sha256=receipt['stable_view_sha256'],source_manifest_sha256=args.packet_sha256,compiler_archive_sha256=model.ARCHIVE_SHA,API_roster_sha256=model.sha(model.stable(ROOT/'API_ROSTER.json')),context=model.CONTEXT,actual_compiler_commands=0,maximum_seconds=OBSERVATION_SECONDS,metadata_admission_sha256=model.sha(model.stable(owned.root/'METADATA_ADMISSION.json')),source_provider_return_accepted=True,elapsed_seconds=time.monotonic()-started)
        model.clock(deadline); owned.json('CENSUS_PROVIDER_CANDIDATE.json',candidate); model.clock(deadline); model.manifest(ROOT,args.packet_sha256)
        return 0
    except BaseException as error:
        context = getattr(args,'_api_observation_context',context); finalization_errors = []
        if context is not None:
            try:context['base_check'](min(started+OBSERVATION_SECONDS,time.monotonic()+60)); model.manifest(ROOT,args.packet_sha256)
            except BaseException as final:finalization_errors.append(type(final).__name__+': '+str(final))
            owned.json('LLVM_STATIC_PARTIAL.json',dict(format='atlas-census-api-only-partial-static-inputs-v1',passed=False,inputs=context.get('partial_static',{}),source_provider_return_accepted=not finalization_errors,finalization_errors=finalization_errors))
        owned.json('ADMISSION_REFUSAL.json',dict(format='atlas-census-api-only-static-refusal-v1',passed=False,error=type(error).__name__+': '+str(error),elapsed_seconds=time.monotonic()-started,finalization_errors=finalization_errors,actual_target_cells_accepted=0,actual_compiler_API_native_commands=0))
        return 2


def admit(model, args, *, returning=False, maximum_seconds=POLICY_SECONDS):
    started,deadline,context = fresh(model,args,maximum_seconds)
    need(context['static_inputs']['complete'] is True, 'Complete separately reviewed LLVM static scope required before any execution')
    raw = model.stable(args.decision,2**20); need(model.sha(raw) == args.decision_sha256, 'Externally selected distinct census-only scope decision SHA required'); decision = model.decode(raw)
    need(decision['reviewed_api_only_static_view'] == context['static_inputs']['stable_view'] and decision['reviewed_native_stable_view_sha256'] == context['static_inputs']['stable_view_sha256'], 'Exact reviewed stable provider metadata must equal this fresh run')
    context['native_materialization'] = dict(stable_view_sha256=context['static_inputs']['stable_view_sha256'])
    context['decision'] = model.admit_decision(args,context,context['protected'])
    tool_policy = dict(format='atlas-grant-analysis-native-policy-v1',execution_admitted=True,independent_review_sha256='c422d3625f7efe657d3c2dbdd575ed3b0f60bfe3ee7f8fde57b3462de9355a4f',expected_native=context['transfer'].policy_view(context['tool_native']),Apple_platform_code_loading_reviewed=True)
    tools = context['transfer'].registry(args.tool_workspace/'tools',tool_policy,context['tool_native'])
    proof_path = args.transfer_packet/'dirty_proof.py'; proof_sha = context['protected'][proof_path]
    proof = model.load(proof_path,proof_sha,'census_api_only_original_proof_tool_reader')
    native_policy = dict(pkgconf=context['pkgconf'],format='atlas-census-api-only-provider-policy-v1',scope=SCOPE,execution_admitted=True,llvm_library=context['selected_llvm_library'],llvm_config=context['llvm_config'],stable_view_sha256=context['static_inputs']['stable_view_sha256'],job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'],compiler_backend_sha256=context['admitted']['providers']['compiler_backend']['sha256'],scope_decision_sha256=args.decision_sha256,C_shim_and_headers_qualified=False,whole_build_memory_qualified=False,actual_target_cells_accepted=0)
    values = {'PROOF_TOOLS.json':tools,'TOOL_POLICY.json':tool_policy,'NATIVE_POLICY.json':native_policy}
    encoded = {name:model.canonical(value) for name,value in values.items()}
    material = dict(format='atlas-census-api-only-policy-materialization-v1',passed=True,execution_admitted=True,scope=SCOPE,finalization_errors=[],job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'],compiler_backend_sha256=context['admitted']['providers']['compiler_backend']['sha256'],stable_view_sha256=context['static_inputs']['stable_view_sha256'],policies={name:model.sha(body) for name,body in encoded.items()},scope_decision_sha256=args.decision_sha256,source_manifest_sha256=args.packet_sha256)
    encoded['POLICY_RESULT.json'] = model.canonical(material)
    if returning:
        for name,body in encoded.items():need(model.stable(args.policies/name,2**20) == body, 'Exact current-job census-only policy/registry source return required')
    else:
        destination = model.Owned(args.policies)
        for name,body in encoded.items():destination.write(name,body)
    for field,name in [('proof_tools','PROOF_TOOLS.json'),('tool_policy','TOOL_POLICY.json'),('native_policy','NATIVE_POLICY.json'),('policy_result','POLICY_RESULT.json')]:
        path = args.policies/name; setattr(args,field,path); setattr(args,field+'_sha256',model.sha(encoded[name])); context['protected'][path] = model.sha(encoded[name])
    need(proof.admit_tools(args.proof_tools,args.proof_tools_sha256) == tools, 'Original actual tool-source/bytes reader must admit this fresh scoped registry')
    context.update(tools=tools,native_policy=native_policy,native_files=context['covered_native_files'],native_aliases=context['static_inputs']['physical']['resolutions'])
    current_check = context['check']
    def check():
        current_check()
        for name,body in encoded.items():need(model.stable(args.policies/name,2**20) == body, 'Current scoped materialization must return unchanged')
        need(proof.admit_tools(args.proof_tools,args.proof_tools_sha256) == tools, 'Admitted analysis tool and API corpus return required')
        need(model.sha(model.stable(args.decision,2**20)) == args.decision_sha256, 'Original external census decision bytes must return')
    context['check'] = check; model.clock(deadline)
    return context


def cleanup(model, args, owned):
    started = time.monotonic(); result = dict(format='atlas-census-api-only-transfer-cleanup-v1',passed=False,complete=False,private_payload_preserved=True,source_manifest_sha256=args.packet_sha256,maximum_seconds=60,original_cleanup_seconds=30,finalization_errors=[])
    try:
        model.manifest(args.transfer_packet,'e186b50c45c15da64ede2801b41e1b05112222dd25cc969ca628c1a1007a8d0e',256)
        raw = model.stable(args.transfer_packet/'TRANSFER_SOURCE_PINS.json',2**20); need(model.sha(raw) == '439df1016cdfdfa237521eccf1f47f9fc72827a4990c3c35b2ec4d8371e4cd92', 'Exact transferred source admission required before retirement')
        for row in model.decode(raw)['files']:need(model.sha(model.stable(args.transfer_packet/row['path'])) == row['sha256'], 'Complete transfer source bytes required before retirement')
        transfer = model.load(args.transfer_packet/'proof_tool_transfer.py','8db41f1a4c4829dee29f2e3d7f28e038bcf3d6e402d66067432e87091f74e097','api_only_original_tool_cleanup')
        model.need(started+60-time.monotonic() >= 30, 'Full original30-second cleanup horizon must remain after source admission')
        result['original_cleanup'] = transfer.cleanup(args.tool_workspace)
        result['private_payload_preserved'] = result['original_cleanup']['complete'] is not True
        need(result['original_cleanup']['complete'] is True, 'Original finite tool cleanup must report complete')
        model.manifest(ROOT,args.packet_sha256); model.clock(started+60)
        result.update(passed=True,complete=True,private_payload_preserved=False)
    except BaseException as error:result['error'] = type(error).__name__+': '+str(error)
    result['elapsed_seconds'] = time.monotonic()-started
    if not model.finite(result['elapsed_seconds'],0,60):result.update(passed=False,complete=False); result['finalization_errors'].append('Complete cleanup wrapper exceeded60 seconds with original30-second tool limit')
    public = model.load(ROOT/'vendor/public_bytes.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','api_only_cleanup_public_policy')
    public.inspect_public_bytes('TRANSFER_CLEANUP.json',model.canonical(result)); owned.json('TRANSFER_CLEANUP.json',result); model.manifest(ROOT,args.packet_sha256); model.clock(started+60)
    return 0 if result['passed'] else 2
