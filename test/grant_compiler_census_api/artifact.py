"""Positive public evidence projection and independent source-bound metadata replay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).resolve().parent
PUBLIC_HELPER_SHA = 'eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed'
FIXED = ('DOCS_SELECTION.json','DOCS_CONFIGURATION.json','TRANSFER_CLEANUP.json','LLVM_STATIC_PARTIAL.json','LLVM_STATIC_INPUTS.json','METADATA_ADMISSION.json','SCOPE_DECISION.json','NATIVE_POLICY.json','POLICY_RESULT.json','TOOL_POLICY.json','PROOF_TOOLS.json','API_ROSTER.json','ADMISSION_REFUSAL.json','CENSUS_PROVIDER_CANDIDATE.json','ADMISSION.json','API_CARDS.json','COMMAND_EVIDENCE.jsonl','SOURCE_RETURN.json','PROXY_CONFIG.json','PROXY_COMMANDS.jsonl','RESULT.json')

def need(value, message):
    if not value:raise RuntimeError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def authority(expected):
    raw = (ROOT/'SOURCE_PINS.json').read_bytes(); need(sha(raw) == expected, 'Exact source manifest required before artifact imports')
    rows = json.loads(raw)['files']; need(0 < len(rows) <= 128 and len({r['path'] for r in rows}) == len(rows), 'Finite complete executable roster required')
    for row in rows:
        rel = PurePosixPath(row['path']); need(str(rel) == row['path'] and not rel.is_absolute() and '..' not in rel.parts, 'Contained exact executable source required')
        path = ROOT/rel; need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'Physical source file required before import')
        value = path.read_bytes(); need(len(value) == row['bytes'] and sha(value) == row['sha256'], 'Exact imported source bytes required')
    spec = importlib.util.spec_from_file_location('census_artifact_source_authority',ROOT/'run_census.py'); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.manifest(ROOT,expected)
    return module

def physical(root, maximum=512):
    root = Path(root); need(root.is_absolute() and root.resolve(strict=True) == root and stat.S_ISDIR(root.lstat().st_mode), 'Physical public projection root required')
    root_id = [root.lstat().st_dev,root.lstat().st_ino,root.lstat().st_mode]; stack = [root]; result = {}; count = 0; directories = {root:root_id}
    while stack:
        directory = stack.pop()
        for path in directory.iterdir():
            state = path.lstat(); count += 1; need(count <= maximum and (stat.S_ISDIR(state.st_mode) or (stat.S_ISREG(state.st_mode) and state.st_nlink == 1)), 'Finite ordinary public directories/files required')
            if stat.S_ISDIR(state.st_mode):
                need(any(path.iterdir()), 'Every public directory must contain selected regular evidence'); directories[path] = [state.st_dev,state.st_ino,state.st_mode]; stack.append(path)
            else:result[str(path.relative_to(root))] = path
    need(root_id == [root.lstat().st_dev,root.lstat().st_ino,root.lstat().st_mode], 'Original public root identity required')
    for path,original in directories.items():need([path.lstat().st_dev,path.lstat().st_ino,path.lstat().st_mode] == original, 'Complete physical public directory return required')
    return result

def selection(source, model):
    names = [name for name in FIXED if (source/name).exists()]
    names += ['probe_sources/'+name+'.cr.txt' for name in model.PROBES if (source/'probe_sources'/(name+'.cr.txt')).exists()]
    commands = source/'COMMAND_EVIDENCE.jsonl'
    if commands.exists():
        rows = [model.decode(raw) for raw in model.stable(commands,64*2**20).splitlines()]
        need(len(rows) <= 123, 'Original bounded command roster required')
        for row in rows:
            label = row['record']['label']; need(label in dict(model.command_roster()), 'Explicit command source roster required')
            names += [label+'.stdout.txt',label+'.stderr.txt']
    need(names and len(names) == len(set(names)) <= 512, 'Positive unique selected evidence roster required')
    return names

def stage(source, destination, expected):
    model = authority(expected); owned = model.Owned(destination); helper = model.load(ROOT/'vendor/public_bytes.py',PUBLIC_HELPER_SHA,'census_public_content_policy')
    before_root = model.identity(source)[:3]; names = selection(source,model); total = 0; rows = []
    need(Path(source).resolve(strict=True) == Path(source), 'Physical actual evidence source root required')
    for name in names:
        path = source/name; need(path.resolve(strict=True) == path, 'Physical selected evidence parents required'); value = model.stable(path,64*2**20); total += len(value); need(total <= model.MAX_PUBLIC, 'Complete128-MiB public evidence ceiling required')
        helper.inspect_public_bytes(name,value); owned.write(name,value); rows.append(dict(path=name,bytes=len(value),sha256=sha(value)))
    need(model.identity(source)[:3] == before_root, 'Original selected source root return required')
    for row in rows:need(sha(model.stable(source/row['path'],64*2**20)) == row['sha256'], 'Exact public projection source return required')
    owned.json('PUBLIC_STAGE.json',dict(format='atlas-compiler-census-api-public-stage-v1',files=rows,source_manifest_sha256=expected,source_archive_sha256=model.ARCHIVE_SHA,full_native_memory_qualified=False,actual_target_cells_accepted=0,source_return_accepted=True))
    need(set(physical(destination)) == {row['path'] for row in rows}|{'PUBLIC_STAGE.json'}, 'Exact complete public physical roster required')
    model.manifest(ROOT,expected)
    return dict(passed=True,files=len(rows),bytes=total,actual_target_cells_accepted=0)

def validate_metadata_candidate(model, candidate, raw_admission, expected):
    admitted = model.decode(raw_admission)
    need(admitted['format'] == 'atlas-census-metadata-admission-v1' and sha(raw_admission) == candidate['metadata_admission_sha256'], 'Exact separately retained metadata admission required')
    sdk = admitted['SDK']; native = admitted['native_receipt']; descriptor = candidate['llvm_config']; before = admitted['llvm_config_before']
    need(type(candidate['job_identity']) is dict and bool(candidate['job_identity']) and candidate['job_identity'] == sdk['job_identity'] == native['job_identity'], 'Exact fresh SDK/native/candidate metadata job join required')
    need(candidate['compiler_profile_sha256'] == sdk['observed_profile_sha256'] == native['compiler_profile_sha256'] and candidate['compiler_backend_sha256'] == sdk['providers']['compiler_backend']['sha256'], 'Exact fresh metadata profile/backend join required')
    api_only = native['format'] == 'atlas-census-api-only-static-observation-v1'
    need(native['format'] in ('atlas-native-buffer-provider-observation-v1','atlas-census-api-only-static-observation-v1') and all(native[key] is True for key in ('passed','complete','source_provider_return_accepted')) and candidate['native_stable_view_sha256'] == native['stable_view_sha256'], 'Complete separately scoped native metadata return/stable-view join required')
    dependency = model.decode(model.stable(ROOT/'inputs/PROVIDER_DEPENDENCY.json',2**20)); need(native['source_manifest_sha256'] == (expected if api_only else dependency['manifest_sha256']), 'Exact independently reviewed native observer cohort required')
    for value in (candidate['compiler_profile_sha256'],candidate['compiler_backend_sha256'],candidate['native_stable_view_sha256'],native['receipt_sha256']):need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None, 'Exact bounded metadata authority SHA required')
    required_descriptor = {'format','declared_path','resolved_path','bytes','sha256','mode','imports','rpaths','links','package_version','selected_llvm_library','dependencies','unresolved_imports','native_file_closure_covered','dyld_shared_cache_bytes_qualified'}
    need(type(descriptor) is dict and set(descriptor) == required_descriptor and descriptor == before, 'Complete original LLVM-config descriptor required')
    need(descriptor['format'] == 'atlas-census-llvm-config-stable-v1' and descriptor['package_version'] == '21.1.8' and type(descriptor['bytes']) is int and 0 < descriptor['bytes'] <= 32*2**20 and type(descriptor['mode']) is int and descriptor['mode'] & 0o111, 'Exact bounded executable LLVM config metadata required')
    need(type(descriptor['sha256']) is str and re.fullmatch('[0-9a-f]{64}',descriptor['sha256']) is not None and all(type(descriptor[key]) is str and Path(descriptor[key]).is_absolute() for key in ('declared_path','resolved_path','selected_llvm_library')), 'Exact provider path/bytes identity required')
    need(all(type(descriptor[key]) is list for key in ('imports','rpaths','links','dependencies','unresolved_imports')) and len(descriptor['imports']) <= 128 and len(descriptor['rpaths']) <= 64 and descriptor['native_file_closure_covered'] is (not descriptor['unresolved_imports']) and descriptor['dyld_shared_cache_bytes_qualified'] is False, 'Complete explicit covered/unresolved metadata scope required')
    need(type(candidate['llvm_config_physical']) is dict and bool(candidate['llvm_config_physical']) and candidate['llvm_config_physical'] == admitted['llvm_config_physical_before'], 'Exact original physical config/alias return metadata required')
    need(candidate['format'] == 'atlas-census-provider-candidate-v1' and candidate['execution_admitted'] is False and candidate['source_provider_return_accepted'] is True and type(candidate['actual_compiler_commands']) is int and candidate['actual_compiler_commands'] == 0, 'Explicit metadata-only compiler-provider candidate required')
    need(candidate['source_manifest_sha256'] == expected and candidate['compiler_archive_sha256'] == model.ARCHIVE_SHA and candidate['API_roster_sha256'] == sha(model.stable(ROOT/'API_ROSTER.json')) and candidate['context'] == model.CONTEXT and type(candidate['maximum_seconds']) is int and candidate['maximum_seconds'] == (180 if api_only else 120) and model.finite(candidate['elapsed_seconds'],0,180 if api_only else 120), 'Exact source/API/context and finite observation return required')
    return admitted

def replay(root, expected):
    model = authority(expected); paths = physical(root); stage_raw = model.stable(root/'PUBLIC_STAGE.json',2**20); projection = model.decode(stage_raw)
    need(projection['format'] == 'atlas-compiler-census-api-public-stage-v1' and projection['source_manifest_sha256'] == expected and projection['source_archive_sha256'] == model.ARCHIVE_SHA and projection['source_return_accepted'] is True, 'Exact positively staged source archive/protocol required')
    rows = projection['files']; need(type(rows) is list and 0 < len(rows) <= 512 and len({row['path'] for row in rows}) == len(rows), 'Finite unique positive public roster required')
    need(set(paths) == {row['path'] for row in rows}|{'PUBLIC_STAGE.json'}, 'Exact ordinary public evidence roster required')
    need({row['path'] for row in rows} == set(selection(root,model)), 'Exact fixed source-selected public file roster required')
    helper = model.load(ROOT/'vendor/public_bytes.py',PUBLIC_HELPER_SHA,'census_reader_public_content_policy')
    total = 0
    for row in rows:
        raw = model.stable(paths[row['path']],64*2**20); total += len(raw); need(total <= model.MAX_PUBLIC and len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'Exact source-bound public evidence bytes required')
        helper.inspect_public_bytes(row['path'],raw)
    def byte_return():
        for row in rows:
            value = model.stable(root/row['path'],64*2**20); need(len(value) == row['bytes'] and sha(value) == row['sha256'], 'Complete original public file bytes must return')
    if 'TRANSFER_CLEANUP.json' in paths:
        need(set(paths) == {'TRANSFER_CLEANUP.json','PUBLIC_STAGE.json'}, 'Exact cleanup-only positive public roster required')
        value = model.decode(model.stable(root/'TRANSFER_CLEANUP.json'))
        need(value['format'] == 'atlas-census-api-only-transfer-cleanup-v1' and value['source_manifest_sha256'] == expected and all(value[k] is True for k in ('passed','complete')) and value['private_payload_preserved'] is False and value['original_cleanup']['complete'] is True and value['maximum_seconds'] == 60 and value['original_cleanup_seconds'] == value['original_cleanup']['maximum_seconds'] == 30 and model.finite(value['elapsed_seconds'],0,60) and value['finalization_errors'] == [], 'Successful original bounded transfer cleanup return required')
        need(set(physical(root)) == set(paths), 'Exact cleanup public physical return required'); byte_return(); model.manifest(ROOT,expected)
        return dict(passed=True,scope='original transferred-tool private retirement',actual_target_cells_accepted=0)
    if 'CENSUS_PROVIDER_CANDIDATE.json' in paths and 'RESULT.json' not in paths:
        need('ADMISSION_REFUSAL.json' not in paths, 'Metadata admission refusal must remain a failed observation')
        candidate = model.decode(model.stable(root/'CENSUS_PROVIDER_CANDIDATE.json',2**20))
        metadata = validate_metadata_candidate(model,candidate,model.stable(root/'METADATA_ADMISSION.json',4*2**20),expected)
        if metadata['native_receipt']['format'] == 'atlas-census-api-only-static-observation-v1':
            raw_static = model.stable(root/'LLVM_STATIC_INPUTS.json',16*2**20)
            helper_api = model.load(ROOT/'api_provider.py',model.sha(model.stable(ROOT/'api_provider.py')),'independent_census_api_static_reader')
            observed = helper_api.validate_observation(model,model.decode(raw_static),expected)
            need(sha(raw_static) == metadata['native_receipt']['receipt_sha256'] and observed['SDK'] == metadata['SDK'] and observed['inputs']['stable_view_sha256'] == candidate['native_stable_view_sha256'] and observed['inputs']['llvm_config'] == candidate['llvm_config'] and observed['inputs']['llvm_config_physical'] == candidate['llvm_config_physical'], 'Complete exact additional LLVM observation/metadata/SDK/provider join required')
        need(set(physical(root)) == set(paths), 'Exact physical metadata projection return required'); byte_return(); model.manifest(ROOT,expected)
        return dict(passed=True,scope='read-only additional LLVM-config input observation',execution_admitted=False,actual_target_cells_accepted=0)
    result = model.decode(model.stable(root/'RESULT.json',2**20)); admission = model.decode(model.stable(root/'ADMISSION.json',4*2**20)); cards = model.decode(model.stable(root/'API_CARDS.json',16*2**20))
    need(result['format'] == 'atlas-compiler-census-api-result-v1' and result['source_manifest_sha256'] == expected and result['passed'] is True and result['diagnostic_collection_complete'] is True and result['compiler_color'] == 'GREEN' and result['finalization_errors'] == [], 'Actual successful complete GREEN API compatibility result required')
    for key in ('writers_confirmed_retired','source_provider_return_accepted','private_removed','required_API_cards_accepted'):need(result[key] is True, 'Complete source/provider/return/API acceptance required')
    need(all(type(result[key]) is int for key in ('maximum_seconds','return_seconds','command_seconds_worst_case')) and result['maximum_seconds'] == model.OUTER_SECONDS and result['return_seconds'] == model.RETURN_SECONDS and result['command_seconds_worst_case'] == 2280 and model.finite(result['elapsed_seconds'],0,model.OUTER_SECONDS), 'Exact complete finite API horizon required')
    need(result['actual_target_cells_accepted'] == 0 and type(result['actual_target_cells_accepted']) is int and result['whole_build_memory_qualified'] is False and result['retained_owner_attribution_implemented'] is False, 'API proof and retained-memory/full Grant boundaries remain separate')
    need(result['job_identity'] == admission['SDK']['job_identity'] and result['compiler_profile_sha256'] == admission['SDK']['observed_profile_sha256'] and result['compiler_backend_sha256'] == admission['SDK']['providers']['compiler_backend']['sha256'], 'Fresh actual SDK/job/backend joins required')
    decision_raw = model.stable(root/'SCOPE_DECISION.json',2**20); need(sha(decision_raw) == result['scope_decision_sha256'], 'Exact externally selected census decision bytes required'); decision = model.decode(decision_raw)
    need(decision == admission['decision'] and decision['execution_admitted'] is True and decision['scope'] == 'compiler-census-api-and-concrete-receiver-only', 'Distinct actual census scope decision required')
    material = model.decode(model.stable(root/'POLICY_RESULT.json',2**20)); need(material['format'] in ('atlas-native-buffer-policy-materialization-v1','atlas-census-api-only-policy-materialization-v1') and material['passed'] is True and material['execution_admitted'] is True and material['finalization_errors'] == [] and material['job_identity'] == result['job_identity'] and material['compiler_profile_sha256'] == result['compiler_profile_sha256'] and material['stable_view_sha256'] == decision['reviewed_native_stable_view_sha256'], 'Successful fresh native materialization/SDK/source join required')
    if material['format'] == 'atlas-census-api-only-policy-materialization-v1':
        helper_api = model.load(ROOT/'api_provider.py',model.sha(model.stable(ROOT/'api_provider.py')),'independent_executed_census_static_inputs')
        static_receipt = helper_api.validate_observation(model,model.decode(model.stable(root/'LLVM_STATIC_INPUTS.json',16*2**20)),expected)
        need(static_receipt['passed'] is True and static_receipt['SDK'] == admission['SDK'] and static_receipt['inputs']['stable_view'] == decision['reviewed_api_only_static_view'], 'Every fresh executed provider/physical/SDK input must join the complete independently reviewed stable metadata')
        policy = model.decode(model.stable(root/'NATIVE_POLICY.json',2**20))
        need(material['scope'] == policy['scope'] == decision['scope'] == 'compiler-census-api-and-concrete-receiver-only' and material['source_manifest_sha256'] == expected and material['compiler_backend_sha256'] == result['compiler_backend_sha256'] and material['scope_decision_sha256'] == policy['scope_decision_sha256'] == result['scope_decision_sha256'], 'Exact separate current-job API-only provider materialization required')
        need(policy['format'] == 'atlas-census-api-only-provider-policy-v1' and policy['execution_admitted'] is True and policy['C_shim_and_headers_qualified'] is False and policy['whole_build_memory_qualified'] is False and policy['actual_target_cells_accepted'] == 0, 'Census provider policy preserves separate C/native/whole-build boundaries')
        need(policy['job_identity'] == result['job_identity'] and policy['compiler_profile_sha256'] == result['compiler_profile_sha256'] and policy['compiler_backend_sha256'] == result['compiler_backend_sha256'] and policy['stable_view_sha256'] == material['stable_view_sha256'] == sha(model.canonical(decision['reviewed_api_only_static_view'])), 'Full reviewed LLVM stable view and fresh SDK/source joins required')
        need(policy['llvm_config'] == admission['llvm_config'] == decision['reviewed_api_only_static_view']['llvm_config'] and policy['llvm_library'] == decision['reviewed_api_only_static_view']['selected']['llvm_library'], 'Exact separately admitted static LLVM provider/library source required')
    for name in ('PROOF_TOOLS.json','TOOL_POLICY.json','NATIVE_POLICY.json'):need(sha(model.stable(root/name,2**20)) == material['policies'][name], 'Exact returned native/tool/registry source policy required')
    need(model.decode(model.stable(root/'PROOF_TOOLS.json',2**20)) == admission['tools'] and model.decode(model.stable(root/'NATIVE_POLICY.json',2**20)) == admission['native_policy'], 'Actual admitted tool/native policies must be retained unchanged')
    protocol = dict(source_manifest_sha256=expected,api_roster_sha256=sha(model.stable(ROOT/'API_ROSTER.json')),compiler_distribution_sha256=model.ARCHIVE_SHA,compiler_commit=model.COMPILER_COMMIT,canonical_gc_sha256=model.CANONICAL_GC_SHA,accepted_analysis_stable_sha256=model.STABLE_TOOLS_SHA,context=model.CONTEXT,maximum_seconds=model.OUTER_SECONDS,command_roster=model.command_roster())
    need(model.canonical(decision['protocol']) == model.canonical(protocol) and decision['reviewed_llvm_config'] == admission['llvm_config'] and decision['LLVM_config_code_loading_reviewed'] is True, 'Exact reviewed census/proxy/LLVM provider protocol required')
    need(admission['llvm_config']['unresolved_imports'] == [] and admission['llvm_config']['native_file_closure_covered'] is True and decision['Apple_platform_code_loading_reviewed'] is True, 'Exact covered file closure and explicit Apple code-loading scope required')
    need(model.stable(root/'API_ROSTER.json') == model.stable(ROOT/'API_ROSTER.json'), 'Exact executed API question roster required')
    query_rows = model.decode(model.stable(ROOT/'API_ROSTER.json'))['queries']; need(len(cards) == len(query_rows) == 56, 'All56 API questions must be retained')
    contract = model.load(ROOT/'vendor/command_contract.py',model.CONTRACT_SHA,'census_public_original_terminal')
    commands = [model.decode(raw) for raw in model.stable(root/'COMMAND_EVIDENCE.jsonl',64*2**20).splitlines()]
    need(type(result['commands']) is int and result['commands'] == len(commands) == len(result['original_groups']) and 67 <= len(commands) <= 123, 'Complete67..123 actual original command/group roster required')
    position = 0; planned = dict(model.command_roster()); project = admission['proxy']['project']; wrapper = admission['SDK']['providers']['compiler_wrapper']['path']; tools = admission['tools']['tools']; executable = str(Path(admission['proxy']['private'])/'bin/crystal-alpha')
    def take(label, argv, lookup=False, expected_exit=0):
        nonlocal position
        need(position < len(commands), 'Complete exact actual command prefix required'); item = commands[position]; group = result['original_groups'][position]; position += 1; row = item['record']
        need(row['label'] == label and row['arguments'] == list(map(str,argv)), 'Exact source-generated actual argv required')
        stdout,stderr = model.validate_terminal(contract,row,planned[label],root,group,lookup=lookup,expected=expected_exit)
        need(stdout == item['stdout'] and stderr == item['stderr'], 'Exact lossless command/raw output join required')
        return row,stdout,stderr
    row,stdout,stderr = take('llvm-config-version',[admission['proxy']['environment']['LLVM_CONFIG'],'--version']); need(stdout == '21.1.8\n' and not stderr, 'Exact actual reviewed LLVM version required')
    row,stdout,stderr = take('amber-lsp-version',[tools['amber_lsp']['path'],'--version']); need('2.0.7' in stdout and not stderr, 'Exact actual Amber LSP version behavior required')
    row,stdout,stderr = take('ameba-version',[tools['ameba']['path'],'--version']); need('1.7.0-dev' in stdout and not stderr, 'Exact actual Ameba version behavior required')
    for name in model.PROBES:
        raw = model.stable(root/'probe_sources'/(name+'.cr.txt')); need(raw == model.stable(ROOT/'inputs'/(name+'.cr.txt')), 'Exact concrete receiver fixture source required')
        row,stdout,stderr = take('format-'+name,[wrapper,'tool','format','--check',str(Path(project)/'census_probes'/(name+'.cr'))]); need(not stdout and not stderr, 'Actual formatter GREEN required')
    for name in model.PROBES:
        expected_exit = 1 if name == 'gc_stats_wrong_type' else 0
        row,stdout,stderr = take('compatibility-'+name,[executable,'build','--no-codegen',str(Path(project)/'census_probes'/(name+'.cr'))],expected_exit=expected_exit)
        if expected_exit:need('UInt64' in stderr and 'String' in stderr and 'Error' in stderr, 'Actual discriminating wrong-type refusal required')
        else:need(not stdout and not stderr, 'Actual concrete receiver compiler GREEN required')
    for index,(question,kept) in enumerate(zip(query_rows,cards)):
        method = question['query']; argv = [tools['amber_lsp']['path'],'lookup',method,'--root',project,'--json']; row,stdout,stderr = take('api-'+str(index),argv,True); answer = model.card(stdout,method,row['exit_code']); answer['stderr'] = stderr; attempts = [answer]
        if row['exit_code'] == 4 and answer['card'] is not None and answer['card']['status'] == 'unknown':
            row,stdout,stderr = take('api-verify-'+str(index),argv+['--verify'],True); answer = model.card(stdout,method,row['exit_code'],True); answer['stderr'] = stderr; attempts.append(answer)
        need(kept == dict(query=method,required=question['required'],attempts=attempts,accepted=answer['accepted']), 'Exact raw API card/unknown/verification replay required')
        need(answer['accepted'] or not question['required'], 'Every required API card must be actually resolved')
    need(position == len(commands), 'Exact complete123-ceiling command sequence required')
    returned = model.decode(model.stable(root/'SOURCE_RETURN.json',4*2**20)); original = model.archive_rows()['files']; need(set(returned['files']) == {row['path'] for row in original}|{'census_probes'}|{'census_probes/'+name+'.cr' for name in model.PROBES}|{'.amber-lsp','.amber-lsp/api',model.DOCS_CARD_PATH}, 'Complete canonical3190-source return with exact four probes required')
    docs = model.decode(model.stable(root/'DOCS_CONFIGURATION.json',4096)); expected_docs = dict(format='atlas-full-compiler-docs-selection-v1',configuration_path=model.DOCS_CARD_PATH,configuration_sha256=model.CONTEXT['docs_selection']['card_sha256'],docs_entry=model.DOCS_ENTRY,docs_entry_sha256=model.DOCS_ENTRY_SHA,CLI_source_commit='faed4b205063a84650b00e2dc02f01793f373527',selection_scope='one canonical full-compiler entrypoint',actual_hosted_completion_qualified=False)
    need(docs == expected_docs and returned['files'][model.DOCS_CARD_PATH]['sha256'] == docs['configuration_sha256'] and returned['files'][model.DOCS_CARD_PATH]['bytes'] == len(model.stable(ROOT/'inputs/CENSUS_DOCS_CARD.yml',4096)), 'Exact full-compiler docs configuration source and final return required')
    for path,kind in [('.amber-lsp','directory'),('.amber-lsp/api','directory'),(model.DOCS_CARD_PATH,'file')]:
        row = returned['files'][path]; mode = 0o644 if kind == 'file' else 0o755; state = row['physical_identity']
        need(row['path'] == path and row['kind'] == kind and row['mode'] == mode and type(state) is list and len(state) == 6 and stat.S_IMODE(state[2]) == mode and (stat.S_ISREG(state[2]) if kind == 'file' else stat.S_ISDIR(state[2])), 'Exact ordinary generated docs configuration node kind/mode/physical return required')
        if kind == 'file':need(row['bytes'] == state[3] == len(model.stable(ROOT/'inputs/CENSUS_DOCS_CARD.yml',4096)), 'Exact generated docs configuration physical length required')
    need(result['command_contracts_accepted'] is True and result['command_failures'] == [] and result['compatibility_collection_complete'] is True, 'Complete successful diagnostic and independently returned resources required')
    for row in original:need(all(returned['files'][row['path']][key] == value for key,value in row.items()), 'Exact canonical source mode/hash/alias return required')
    need(sha(model.stable(root/'PROXY_CONFIG.json')) == sha(model.canonical(admission['proxy'])), 'Exact executed compiler proxy source/context required')
    proxy = model.load(ROOT/'compiler_proxy.py',model.sha(model.stable(ROOT/'compiler_proxy.py')),'census_source_argv_derivation_reader')
    journal = [model.decode(line) for line in model.stable(root/'PROXY_COMMANDS.jsonl',4*2**20).splitlines()]
    need(4 <= len(journal) <= proxy.MAX_CALLS, 'Complete bounded actual compiler invocation journal required')
    observed_selection = model.decode(model.stable(root/'DOCS_SELECTION.json',2**20)); expected_selection = model.docs_selection_evidence(journal,project)
    need(observed_selection == expected_selection and observed_selection['matches'] is True and result['docs_selection_matches'] is observed_selection['matches'] and result['docs_selection_observed'] is observed_selection['observed'], 'Every observed canonical docs pre-exec invocation must use the configured full-compiler entry and exact source resolution')

    groups = {row['record']['original_group'] for row in commands}; config_sha = sha(model.stable(root/'PROXY_CONFIG.json')); concrete = []
    for item in journal:
        need(type(item['pid']) is int and item['pid'] > 0 and type(item['process_group']) is int and item['process_group'] in groups and item['configuration_sha256'] == config_sha, 'Actual proxy PID/original group/configuration join required')
        cwd = Path(item['cwd']); original_arguments = item['original_arguments']
        need((cwd == Path(project) and item['project_role'] == 'canonical-project') or (cwd != Path(project) and item['project_role'] == 'released-library-docs-workspace' and cwd.is_relative_to(Path(admission['proxy']['private'])/'home/.cache/amber-lsp/index/docs-workspaces')), 'Exact canonical project or released docs-workspace role required')
        expected_environment = dict(admission['proxy']['environment']); expected_environment['CRYSTAL_CACHE_DIR'] = item['environment']['CRYSTAL_CACHE_DIR']
        need(item['environment'] == expected_environment and Path(expected_environment['CRYSTAL_CACHE_DIR']).is_relative_to(Path(admission['proxy']['private'])), 'Exact actual compiler source/feature/native environment required')
        for source,resolved in item['source_resolutions'].items():need(source in original_arguments and (Path(resolved).is_relative_to(Path(project)) or Path(resolved).is_relative_to(Path(admission['proxy']['stdlib']))), 'Original contained actual compiler source resolution required')
        if original_arguments[0] == 'docs':
            # Workspace aliases have retired. Replay the unchanged string grammar
            # and retained actual resolution roles without dereferencing them.
            values = list(original_arguments)
            for index,value in enumerate(values):
                if value.endswith('.cr'):values[index] = item['source_resolutions'][value]
            derived = proxy.derive(values,project,admission['proxy']['stdlib'],project)
            derived = [original_arguments[values.index(value)] if value in values and value.endswith('.cr') else value for value in derived]
        else:derived = proxy.derive(original_arguments,project,admission['proxy']['stdlib'],cwd)
        need(item['executed_arguments'] == [admission['proxy']['backend'],*derived], 'Exact reviewed original-to-executed compiler argv transformation required')
        if original_arguments[0] == 'build' and original_arguments[-1].startswith(str(Path(project)/'census_probes')):concrete.append(original_arguments[-1])
    need(concrete == [str(Path(project)/'census_probes'/(name+'.cr')) for name in model.PROBES], 'Every exact concrete receiver command must reach the admitted backend')
    need(set(physical(root)) == set(paths) and model.stable(root/'PUBLIC_STAGE.json',2**20) == stage_raw, 'Complete public root/roster/source return required'); byte_return(); model.manifest(ROOT,expected)
    return dict(passed=True,API_queries=56,commands=len(commands),scope='actual API and concrete receiver compatibility',actual_target_cells_accepted=0,retained_owner_attribution_implemented=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('operation',choices=('stage','read')); parser.add_argument('--source',type=Path,required=True); parser.add_argument('--packet-sha256',required=True); parser.add_argument('--output',type=Path); args = parser.parse_args()
    print(json.dumps(stage(args.source,args.output,args.packet_sha256) if args.operation == 'stage' else replay(args.source,args.packet_sha256),sort_keys=True))
