"""Bound API, type, lint, existing behavior, and carrier semantics before four-arm timing."""
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from proof_command import terminal, finite
import hook_callback
import execution_context
from dirty_overlay import apply
from prepare_dirty_plan import ARMS, PROOF_SECONDS, source_rows
from propose_dirty_transition import PATHS, ROOT, need, sha
from run_hosted_contrast import save, digest, DRIVER_SHA256, behavior
from same_job_policy import metadata
from vendor.verify_compile_acceptance import source_input_inventory
from prepare_comparison import fingerprint

API_METHODS = ('Hash.new', 'Hash#has_key?', 'Hash#[]', 'Hash#[]=', 'Hash#delete', 'Reference#same?',
               'Int32#!=', 'Int64#==', 'Float64#!=', 'Array#==', 'Slice#==', 'Time#==', 'UUID#==', 'GC.collect','GC.stats','GC::Stats#total_bytes',
               'Grant::Dirty::CapturedColumnAssignment.new', 'Grant::Dirty::CapturedColumnAssignment#previous_database_value',
               'Grant::Dirty::CapturedColumnAssignment#current_database_value',
               'Grant::Dirty::RecordedColumnAssignment.new', 'Grant::Dirty.record_column_assignment',
               'Grant::Dirty::CapturedColumnAssignment#attribute_name',
               'Grant::Dirty::CapturedColumnAssignment#collection_of_original_attribute_values',
               'Grant::Dirty::CapturedColumnAssignment#collection_of_pending_attribute_changes',
               'Grant::Dirty::RecordedColumnAssignment#collection_of_original_attribute_values',
               'Grant::Dirty::RecordedColumnAssignment#collection_of_pending_attribute_changes',
               'Time.utc','UUID.empty','Int32#to_i32','Int32#to_i64','Fiber.current','Fiber#allocation_tally',
               'Fiber::AllocationTally#-','Fiber::AllocationTally#calls','Fiber::AllocationTally#requested_bytes',
               'Time.monotonic','Time::Span#total_nanoseconds','Int32#even?','String#bytesize')
SPEC_GROUPS = (
    ('spec/grant/dirty/dirty_tracking_spec.cr','spec/grant/dirty/dirty_control_spec.cr',
     'spec/grant/dirty/changes_to_save_spec.cr','spec/grant/dirty/saved_changes_spec.cr',
     'spec/grant/dirty/mutation_detection_spec.cr','spec/grant/dirty/w6_mutation_watch_spec.cr','spec/grant/perf/w6_lazy_dirty_spec.cr'),
    ('spec/grant/normalization_spec.cr','spec/grant/attributes/normalizes_spec.cr','spec/grant/attributes/before_type_cast_spec.cr',
     'spec/grant/persistence/readonly_attribute_spec.cr','spec/grant/persistence/w6_dirty_typed_spec.cr','spec/grant/serialized_column_spec.cr'),
    ('spec/grant/sti/sti_personas_spec.cr','spec/grant/sti/sti_behavior_spec.cr','spec/grant/sti/sti_validation_callback_inheritance_spec.cr',
     'spec/grant/transaction_atomicity_spec.cr','spec/grant/persistence/transaction_lifecycle_spec.cr'),
)
# Unique cards preserve the exact standard/helper call roster; both literal
# comparison helper cards are shared only under exact source identity.
API_METHODS += ('Grant::Dirty.has_different_assignment_values?', 'Grant::Dirty.has_equal_assignment_values?')
# Captured/Recorded type methods use ::, so classify by explicit owner prefix.
STANDARD_API = tuple(method for method in API_METHODS if not method.startswith('Grant::Dirty'))
COMPARISON_API = tuple(method for method in API_METHODS if 'CapturedColumnAssignment' in method or 'assignment_values?' in method)
TRANSITION_API = tuple(method for method in API_METHODS if method not in STANDARD_API + COMPARISON_API)
MAX_COMMANDS = 113
WORST_CASE_COMMAND_SECONDS = 6540


def api_sequence(phase):
    return STANDARD_API if phase == 'standard' else COMPARISON_API if phase == 'comparison' else TRANSITION_API


def expected_commands():
    result = [('amber_lsp-version',10,0),('ameba-version',10,0)]
    def cards(phase):
        for method in api_sequence(phase):
            result.append(('api-'+str(API_METHODS.index(method)),10,0))
    cards('standard')
    for arm in ARMS:
        if arm in ('comparison','transition'):
            cards(arm)
        result.extend([(arm+'-format',30,0),(arm+'-lint',120,0)])
        result.extend((arm+'-spec-'+str(index),300,0) for index in range(len(SPEC_GROUPS)))
        result.extend([(arm+'-probe-build',300,0),(arm+'-probe-run',60,0)])
        if arm == 'transition':
            result.append(('transition-probe-baseline-canary',60,1))
    return result


def lookup_phase(result, runner, tools, phase, grant, env, output):
    cards = result.setdefault('api_cards',[])
    for method in api_sequence(phase):
        cards.append(dict(phase=phase,method=method,card=lookup(runner,tools['tools']['amber_lsp']['path'],
                          method,API_METHODS.index(method),grant,env,output)))
    result.setdefault('api_phases',[]).append(phase)


def shared_comparison_source(grant):
    from propose_dirty_transition import COMPARATORS
    # Exact fixed carrier and both shared helper implementations are unchanged
    # between candidate arms. Their successful actual-root cards are reused only
    # under this equality, before either candidate's behavior compilation.
    carrier = grant / PATHS[2]
    dirty = (grant / PATHS[1]).read_bytes()
    helpers = COMPARATORS.encode()
    need(dirty.count(helpers) == 1, 'Exact unique shared comparator implementations required')
    return dict(carrier_sha256=digest(carrier), comparator_sha256=sha(helpers))


def admit_tools(path, expected):
    need(path.is_absolute() and not path.is_symlink() and path.is_file() and path.stat().st_size <= 32 * 2**10,
         'Exact bounded reviewed hosted proof-tool registry required')
    need(digest(path) == expected, 'Exact reviewed hosted proof-tool registry SHA-256 required')
    value = json.loads(path.read_bytes())
    need(value.get('format') == 'atlas-grant-hosted-proof-tools-v1' and value.get('execution_admitted') is True,
         'Hosted Amber LSP and Ameba provider admission remains an explicit prerequisite')
    need(set(value['tools']) == {'amber_lsp','ameba'}, 'Complete exact hosted API/lint provider roster required')
    for name,row in value['tools'].items():
        tool = Path(row['path'])
        need(tool.is_absolute() and tool.resolve(strict=True) == tool and tool.is_file() and 0 < tool.stat().st_size <= 64*2**20 and os.access(tool, os.X_OK),
             'Exact executable hosted proof-tool path required: ' + name)
        need(re.fullmatch('[0-9a-f]{64}', row['sha256']) and digest(tool) == row['sha256'] and
             re.fullmatch('[0-9a-f]{40}', row['source_commit']) and row['version'],
             'Exact reviewed proof-tool version/source/binary identity required: ' + name)
        if name == 'amber_lsp':
            need(row['version'] == '2.0.7' and row['source_commit'] == 'faed4b205063a84650b00e2dc02f01793f373527' and
                 row['sha256'] == '3691c7fdb6d489b44973c5f76493db83d32ad50fc3932fb2aabfa21062a1de4a' and tool.stat().st_size == 3590088 and stat.S_IMODE(tool.stat().st_mode) == 0o755 and
                 row['release_archive_url'] == 'https://github.com/amberframework/amber_cli/releases/download/v2.0.7/amber_cli-darwin-arm64.tar.gz' and row['release_archive_bytes'] == 2933426 and
                 row['release_archive_sha256'] == '0a9fb1227af6574c689eae3d2f4d83281cc3edfab3d40799079d470bb2c7ce61' and
                 row['source_archive_sha256'] == '6e90f3cdba3ed87cefbf7443ab93da627af314fac5960a4b9288ae80e31f591f',
                 'Exact reviewed released Amber LSP source/binary archive provenance required')
            corpus = Path(row['api_corpus_path'])
            need(corpus == tool.parent/'share/amber_cli/api/crystal.yml' and corpus.resolve(strict=True) == corpus and
                 corpus.is_file() and corpus.stat().st_size == 9858 and stat.S_IMODE(corpus.stat().st_mode) == 0o644 and
                 row['api_corpus_sha256'] == '80bf5dff1c453a94d91da83c0f99a093a2997f8070b6a04af4b02b8c03cd454d' and digest(corpus) == row['api_corpus_sha256'],
                 'Exact packaged released API corpus layout/bytes required')
        else:
            need(row['version'] == '1.7.0-dev' and row['source_commit'] == 'cdd58b34b0d8a9c785d67183a7a8f07541549e55' and
                 row['source_git_tree_sha1'] == '5fe9fbff073fc9a41923f19d8a43b9b35a528ac8' and row['source_archive_bytes'] == 200372 and
                 row['source_archive_sha256'] == 'a0e91d582e0617b15c1bd3448c2d0db60c86454aa4d19887fcb6ee08d4ddf259',
                 'Exact standing Ameba version/source/Git-tree provenance required')
    return value


def lookup(runner,tool,method,index,grant,environment,output):
    label = 'api-'+str(index)
    arguments = [str(item) for item in (tool,'lookup',method,'--root',grant,'--json')]
    count = len(runner.records)
    try:
        runner.run(label,arguments,cwd=grant,environment=environment,seconds=10)
    except Exception:
        # The original Runner raises on expected0/actual4. A resource refusal,
        # deadline overrun, unresolved group or unqualified output remains failed.
        need(len(runner.records) == count+1, 'One retained actual unknown-card command required')
        terminal(runner.records[-1],10,unknown=True,output=output)
    need(len(runner.records) == count+1 and runner.records[-1]['label'] == label and
         runner.records[-1]['arguments'] == arguments and runner.records[-1]['maximum_seconds'] == 10,
         'Exact requested actual-project API command/ten-second horizon required')
    row = runner.records[-1]
    stdout,stderr = terminal(row,10,unknown=row['exit_code'] == 4,output=output)
    value = json.loads(stdout)
    need(value['query'] == method and value['api_card_errors'] == [] and not stderr,
         'Exact actual-project API card query and diagnostics required')
    need(type(row['exit_code']) is int and row['exit_code'] == (4 if value['status'] == 'unknown' else 0),
         'Exact released API-card status/exit join required')
    if value['status'] == 'unknown':
        need(value['failure_reason'] is None and not value['entries'], 'Genuine explicit unknown card required before verification')
        label = 'api-verify-'+str(index)
        count = len(runner.records)
        runner.run(label,[*arguments,'--verify'],cwd=grant,environment=environment,seconds=10)
        need(len(runner.records) == count+1 and runner.records[-1]['label'] == label and
             runner.records[-1]['arguments'] == [*arguments,'--verify'] and runner.records[-1]['maximum_seconds'] == 10,
             'One exact requested unknown-card compiler verification required')
        stdout,stderr = terminal(runner.records[-1],10,output=output)
        value = json.loads(stdout)
        need(value['query'] == method and value['verification_status'] == 'present',
             'Exact successful unknown-card compiler verification required')
    need(not stderr and value['api_card_errors'] == [] and value['failure_reason'] is None and
         value['status'] in ('found','present') and value['freshness'] == 'fresh' and value['entries'],
         'Fresh resolved API signatures/card notes required: '+method)
    return value


def spec_counts(raw):
    matches = re.findall(r'^(\d+) examples?, (\d+) failures?, (\d+) errors?, (\d+) pending', raw, re.M)
    need(len(matches) == 1, 'One complete original Crystal spec result roster required')
    examples, failures, errors, pending = map(int, matches[0])
    need(examples > 0 and (failures, errors, pending) == (0,0,0), 'Positive complete original spec coverage with zero failures/errors/pending required')
    return dict(examples=examples,failures=failures,errors=errors,pending=pending)


def probe_observation(stdout,arm):
    behavior(stdout,2)
    lines = stdout.splitlines()
    expected = 5 if arm == 'transition' else 4 if arm == 'comparison' else 3
    need(len(lines) == expected and lines[0].startswith('GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=') and lines[-1] == 'GRANT_DIRTY_CONTRACT=PASS',
         'Exact complete supplemental behavior/layout/setter output roster required')
    setter = re.fullmatch(r'GRANT_DIRTY_SETTERS allocation_calls=(\d+) requested_bytes=(\d+) elapsed_nanoseconds=(\d+) iterations=10000 checksum=60000',lines[-2])
    need(setter is not None and int(setter[3]) > 0,'Exact warmed original setter allocation/time/work counters required')
    result = dict(allocation_calls=int(setter[1]),requested_bytes=int(setter[2]),elapsed_nanoseconds=int(setter[3]),iterations=10000,
                  scope='Supplemental warmed two-model setter sequence; fiber allocation protocol1, separate from default rich2 timed build')
    if arm in ('comparison','transition'):
        layout = re.fullmatch(r'GRANT_DIRTY_LAYOUT captured_size_bytes=(\d+) literal_allocated_bytes=(\d+) carrier_allocated_bytes=(\d+) iterations=100000',lines[1])
        need(layout is not None and int(layout[1]) > 0,'Exact executed carrier layout/allocation counter observation required')
        result['layout'] = dict(captured_size_bytes=int(layout[1]),literal_allocated_bytes=int(layout[2]),carrier_allocated_bytes=int(layout[3]),iterations=100000,
            scope='Same-process GC allocation deltas around comparison loops; sizeof is ABI layout; dynamic stack-copy cost remains unqualified')
        if arm == 'transition':
            recorded = re.fullmatch(r'GRANT_DIRTY_RESULT_LAYOUT recorded_size_bytes=(\d+)',lines[2])
            need(recorded is not None and int(recorded[1]) > 0,'Exact executed result-value layout required')
            result['layout']['recorded_size_bytes'] = int(recorded[1])
    return result


def runtime_budget(observations):
    need(set(observations) == set(ARMS),'Both original baselines and both candidate runtime observations required')
    original = [observations[arm] for arm in ('original','restored')]
    limits = {name:max(row[name] for row in original) for name in ('allocation_calls','requested_bytes')}
    limits['elapsed_nanoseconds'] = 2 * max(row['elapsed_nanoseconds'] for row in original) + 1000000
    for arm in ('comparison','transition'):
        for name,maximum in limits.items():
            need(observations[arm][name] <= maximum,'Supplemental warmed-setter calibrated original budget exceeded: '+arm+'/'+name)
    return dict(passed=True,limits=limits,allocation_policy='Maximum original/restored observed calls and requested bytes',
                time_policy='Twice the maximum original/restored observed elapsed time plus one millisecond',
                stable_runtime_improvement_accepted=False,dynamic_stack_copy_cost_qualified=False)


def complete_return(value,output=None):
    need(value.get('passed') is True and value.get('finalization_errors') == [] and finite(value['elapsed_seconds'],0,PROOF_SECONDS),
         'Complete bounded API/behavior proof and exact source/provider return required')
    execution_context.complete(value['execution_context'],Path(value['actual_project']),value['same_job_admission'])
    need(value['api_phases'] == ['standard','comparison','transition'] and value['api_lookup_accepted'] is True,
         'Exact execution context and all pre-compile API phases required')
    need(value['commands'] and len(value['commands']) <= MAX_COMMANDS, 'Bounded complete proof-command roster required')
    need(value['writers_confirmed_retired'] is True and len(value['overlays']) == 4 and
         all(row['restored'] is True for row in value['overlays']),
         'All original proof groups absent and all four source overlays restored before timing required')
    need(len(value['groups']) == len(value['commands']), 'Complete separate proof-group roster required')
    rows = value['commands']
    method_order = [(phase,method) for phase in ('standard','comparison','transition') for method in api_sequence(phase)]
    need([(row['phase'],row['method']) for row in value['api_cards']] == method_order,
         'Complete exact pre-compile API evidence roster required')
    from propose_dirty_transition import COMPARATORS
    need(value['shared_comparison_api_source'] == dict(carrier_sha256=digest(ROOT/'source/captured_column_assignment.cr.txt'),
         comparator_sha256=sha(COMPARATORS.encode())) and value['shared_comparison_api_cards_sha256'] ==
         sha(json.dumps([row for row in value['api_cards'] if row['phase'] != 'transition'],sort_keys=True,allow_nan=False).encode()),
         'Exact shared carrier/comparator source and successful API evidence return required')
    card_rows = {row['method']:row['card'] for row in value['api_cards']}
    position = 0
    for label,maximum,expected in expected_commands():
        need(position < len(rows) and rows[position]['label'] == label, 'Exact pre-compile API/behavior command order required: '+label)
        row = rows[position]
        unknown = label.startswith('api-') and not label.startswith('api-verify-') and row['exit_code'] == 4
        streams = terminal(row,maximum,expected=expected,unknown=unknown,output=output,observation=value['groups'][position])
        if label.startswith('api-'):
            index = int(label[4:])
            args = row['arguments']
            need(args == [value['reviewed_tools']['tools']['amber_lsp']['path'],'lookup',API_METHODS[index],
                          '--root',value['actual_project'],'--json'] and row['maximum_seconds'] == 10,
                 'Exact retained actual-project API method/arguments/horizon required')
            if streams is not None:
                card = json.loads(streams[0])
                need(not streams[1] and card['query'] == API_METHODS[index] and card['api_card_errors'] == [] and
                     card['failure_reason'] is None and (card['status'] == 'unknown' and not card['entries'] if unknown else
                     card['status'] in ('found','present') and card['freshness'] == 'fresh' and card['entries'] and card == card_rows[API_METHODS[index]]),
                     'Exact successful retained API card required')
        position += 1
        if unknown:
            need(position < len(rows) and rows[position]['label'] == 'api-verify-'+label[4:] and
                 rows[position]['arguments'] == [*row['arguments'],'--verify'] and rows[position]['maximum_seconds'] == 10,
                 'Every bounded unknown card requires its next exact successful verification')
            verified = terminal(rows[position],10,output=output,observation=value['groups'][position])
            if verified is not None:
                card = json.loads(verified[0])
                need(not verified[1] and card['query'] == API_METHODS[index] and card['api_card_errors'] == [] and
                     card['failure_reason'] is None and card['status'] in ('found','present') and card['freshness'] == 'fresh' and
                     card['verification_status'] == 'present' and card['entries'] and card == card_rows[API_METHODS[index]],
                     'Exact successful retained compiler-verified card required')
            position += 1
    need(position == len(rows), 'Complete finite exact proof-command roster required')
    if output is not None:
        need(json.loads((output/'COMMANDS.json').read_bytes()) == rows,'Exact persisted proof command roster required at return')
        if value['execution_context']['kind'] == 'local-codex-application-edit':
            callback_path = output/'CALLBACK_RECEIPT.json'
            expected = value['execution_context']['callback_receipt_sha256']
            need(not callback_path.is_symlink() and callback_path.is_file() and callback_path.stat().st_size <= 64*2**10 and
                 digest(callback_path) == expected, 'Exact real local callback receipt required at proof return')
            callback = json.loads(callback_path.read_bytes())
            need(callback['callback_verified'] is True and callback['project'] == value['actual_project'] and
                 callback['proof_tools'] == value['reviewed_tools']['tools'], 'Successful exact-project/provider retained callback required')



def run(output, grant, wrapper, driver_path, tools_path, tools_sha256, sdk_evidence, absolute_deadline,
        callback_path=None, callback_sha256=None):
    started = time.monotonic()
    deadline = min(started + PROOF_SECONDS, absolute_deadline)
    need(deadline - started >= PROOF_SECONDS, 'Complete6600-second hosted proof reservation required')
    need(not output.exists() and output.is_absolute(), 'Fresh owned hosted proof output required')
    output.mkdir(parents=True)
    result = dict(format='atlas-grant-dirty-api-behavior-proof-v1',passed=False,commands=[],groups=[],overlays=[],
                  maximum_seconds=PROOF_SECONDS,effective_absolute_deadline=deadline,original_specs={},actual_project=str(grant),
                  compiler_color='UNEXECUTED',api_lookup_accepted=False,allocation_improvement_accepted=False,
                  target_cells_accepted=0)
    save(output/'PROOF_RESULT.json',result)
    runner = None
    protected = {driver_path:digest(driver_path), tools_path:tools_sha256}
    original = source_input_inventory(grant)
    driver,stdlib,before_stdlib = None,None,None
    try:
        tools = admit_tools(tools_path,tools_sha256)
        result['reviewed_tools'] = tools
        protected.update({Path(row['path']):row['sha256'] for row in tools['tools'].values()})
        protected[Path(tools['tools']['amber_lsp']['api_corpus_path'])] = tools['tools']['amber_lsp']['api_corpus_sha256']
        need(digest(driver_path) == DRIVER_SHA256,'Exact reviewed original-group Runner required before import')
        spec = importlib.util.spec_from_file_location('dirty_proof_reviewed_runner',driver_path)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        # The ordinary wrapper/backend/stdlib joins are repeated before proof execution.
        admission = metadata(sdk_evidence,os.environ)
        result['same_job_admission'] = admission
        need(str(wrapper) == admission['providers']['compiler_wrapper']['path'],'Exact same-job wrapper selection required for proof')
        protected.update({Path(row['path']):row['sha256'] for row in admission['providers'].values()})
        for path,expected in protected.items():
            need(digest(path) == expected,'Exact protected proof provider before launch required: '+str(path))
        prefix = wrapper.parent.parent
        stdlib = prefix/'share/agent-crystal/src'
        backend = Path(admission['providers']['compiler_backend']['path'])
        need(backend == prefix/'libexec/agent-crystal-bin','Exact ordinary backend path required')
        driver.verify_wrapper(wrapper.read_text(),backend,stdlib,Path((sdk_evidence/'brew-root.stdout.txt').read_text().strip()),'Darwin')
        for retained,relative in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
            path = prefix/relative
            need(digest(path) == digest(sdk_evidence/retained),'Exact live ordinary formula/install receipt before proof required')
            protected[path] = digest(path)
        before_stdlib = driver.tree_identity(stdlib)
        need(before_stdlib == admission['stdlib'],'Exact source-derived standard library before proof required')
        runner = driver.Runner(output)
        runner.deadline = deadline
        result['commands'],result['groups'] = runner.records,runner.group_observations
        env = {key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR')}
        env.update(CRYSTAL_WORKERS='1',NO_COLOR='1',LC_ALL='C',CURRENT_ADAPTER='sqlite')
        env['PATH'] = str(wrapper.parent)+os.pathsep+env.get('PATH','')
        context = execution_context.admit(grant,admission,tools,callback_path,callback_sha256)
        protected.update(context['protected'])
        result['execution_context'] = context['value']
        if context['value']['kind'] == 'local-codex-application-edit':
            (output/'CALLBACK_RECEIPT.json').write_bytes(callback_path.read_bytes())
            need(digest(output/'CALLBACK_RECEIPT.json') == callback_sha256,'Exact admitted local callback evidence snapshot required')
        for name in ('amber_lsp','ameba'):
            stdout,stderr = runner.run(name+'-version',[tools['tools'][name]['path'],'--version'],cwd=grant,environment=env,seconds=10)
            need(not stderr and len(stdout.splitlines()) == 1 and tools['tools'][name]['version'] in stdout,
                 'Exact pinned tool version in one retained actual version line required: '+name)
            result.setdefault('actual_tool_versions',{})[name] = stdout
        # Standard-library calls are resolved on the untouched actual Grant root,
        # before the first arm materialization, formatter, linter or compiler call.
        lookup_phase(result,runner,tools,'standard',grant,env,output)
        shared = None
        for arm in ARMS:
            observation = {}
            result['overlays'].append(observation)
            with apply(grant,arm,lambda: runner.writers_confirmed_retired,observation):
                need(source_input_inventory(grant)[1] == fingerprint(source_rows(arm)), 'Exact proof-arm complete source closure required')
                if arm == 'comparison':
                    shared = shared_comparison_source(grant)
                    lookup_phase(result,runner,tools,'comparison',grant,env,output)
                    result['shared_comparison_api_source'] = shared
                    result['shared_comparison_api_cards_sha256'] = sha(json.dumps(result['api_cards'],sort_keys=True,allow_nan=False).encode())
                elif arm == 'transition':
                    need(shared is not None and shared_comparison_source(grant) == shared,
                         'Exact carrier/comparator source binding before reusing actual successful cards required')
                    need(sha(json.dumps(result['api_cards'],sort_keys=True,allow_nan=False).encode()) == result['shared_comparison_api_cards_sha256'],
                         'Exact successful standard/comparator card evidence required before transition reuse')
                    lookup_phase(result,runner,tools,'transition',grant,env,output)
                    result['api_lookup_accepted'] = True
                active = [grant/name for name in PATHS if (grant/name).is_file()]
                directory = grant/'performance/results/compile-acceptance'/('dirty-proof-'+arm)
                directory.mkdir(parents=True,exist_ok=False)
                probe = directory/'probe.cr'
                probe.write_bytes((ROOT/'source/dirty_contract_probe.cr.txt').read_bytes())
                (directory/'fixture.cr').write_bytes((ROOT/'inputs/FIXTURE_2.cr.txt').read_bytes())
                stdout,stderr = runner.run(arm+'-format',[wrapper,'tool','format','--check','--no-color',*active,probe,directory/'fixture.cr'],cwd=grant,environment=env,seconds=30)
                need(not stdout and not stderr, 'Exact GREEN formatter output required')
                stdout,stderr = runner.run(arm+'-lint',[tools['tools']['ameba']['path'],'--no-color','--format','dot','--config',ROOT/'inputs/AMEBA_D784.yml',*active,probe],cwd=grant,environment=env,seconds=120)
                need(not stderr and re.search(r'^'+str(len(active)+1)+r' inspected, 0 failures?$',stdout,re.M) is not None and re.search(r'\b(?:error|warning)\b',stdout,re.I) is None,
                     'GREEN complete changed-source lint output required')
                counts = []
                for index,group in enumerate(SPEC_GROUPS):
                    for relative in group:
                        need((grant/relative).is_file() and not (grant/relative).is_symlink(), 'Complete preserved original behavior spec required')
                    spec_directory = grant/'performance/results'/('dirty-proof-'+arm+'-'+str(index))
                    spec_directory.mkdir(parents=True,exist_ok=False)
                    current = dict(env,CRYSTAL_CACHE_DIR=str(spec_directory/'cache'),SQLITE_DATABASE_URL='sqlite3:'+str(spec_directory/'spec.sqlite3'))
                    stdout,stderr = runner.run(arm+'-spec-'+str(index),[wrapper,'spec','--no-color','--error-on-warnings','-Dwithout_mt','--threads','1',*group],
                                              cwd=grant,environment=current,seconds=300)
                    need(not stderr and re.search(r'^Warning:',stdout,re.M) is None, 'GREEN original behavior specs required')
                    counts.append(spec_counts(stdout))
                result['original_specs'][arm] = counts
                if arm != 'original':
                    need(counts == result['original_specs']['original'], 'Exact original example coverage across every arm required')
                current = dict(env,CRYSTAL_CACHE_DIR=str(directory/'cache'),GRANT_COMPILE_ACCEPTANCE_DATABASE_URL='sqlite3:'+str(directory/'normal.sqlite3'))
                arguments = [wrapper,'build','--no-color','--error-on-warnings','-Dwithout_mt','-Dfiber_allocation_tally','--threads','1']
                if arm in ('comparison','transition'):
                    arguments.append('-Ddirty_carrier')
                if arm == 'transition':
                    arguments.append('-Ddirty_full_transition')
                stdout,stderr = runner.run(arm+'-probe-build',[*arguments,probe,'-o',directory/'probe'],cwd=grant,environment=current,seconds=300)
                need(not stdout and not stderr, 'GREEN fixed-getter/equality/hash-identity and original warmed-setter compile proof required')
                probe_sha256 = digest(directory/'probe')
                result.setdefault('probe_binary_sha256',{})[arm] = probe_sha256
                stdout,stderr = runner.run(arm+'-probe-run',[directory/'probe'],cwd=grant,environment=current,seconds=60)
                need(not stderr,'GREEN supplemental probe stderr required')
                observed = probe_observation(stdout,arm)
                result.setdefault('carrier_tradeoff_observations',{})[arm] = observed
                if arm == 'transition':
                    stdout,stderr = runner.run('transition-probe-baseline-canary',[directory/'probe'],cwd=grant,
                        environment=dict(current,GRANT_DIRTY_INJECT_INVALID_BASELINE='1',GRANT_COMPILE_ACCEPTANCE_DATABASE_URL='sqlite3:'+str(directory/'baseline-canary.sqlite3')),seconds=60,expected_exit=1)
                    need('Dirty contract: present nil baseline' in stdout+stderr,'Same-binary present-nil baseline regression must reach the real assertion')
                need(digest(directory/'probe') == probe_sha256,'Exact probe binary retained across normal and corruption controls required')
                need(source_input_inventory(grant)[1] == fingerprint(source_rows(arm)), 'Exact complete proof-arm source identity required at return')
            need(source_input_inventory(grant) == original, 'Complete1554 original rows restored after proof arm')
            save(output/'PROOF_RESULT.json',result)
        need(len(runner.records) <= MAX_COMMANDS,'Complete finite113-command proof budget required')
        result['runtime_budget'] = runtime_budget(result['carrier_tradeoff_observations'])
        result['compiler_color'] = 'GREEN'
        result['passed'] = True
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__,error)
        result['error_context'] = []
        previous = error.__context__
        while previous is not None and len(result['error_context']) < 8:
            result['error_context'].append('%s: %s' % (type(previous).__name__,previous))
            previous = previous.__context__
    finally:
        errors = []
        for label,check in [('source',lambda: source_input_inventory(grant) == original),
                            ('tools',lambda: admit_tools(tools_path,tools_sha256) == result.get('reviewed_tools'))]:
            try:
                need(check(),'Exact final proof '+label+' required')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__,error))
        if before_stdlib is not None:
            try:
                need(driver.tree_identity(stdlib) == before_stdlib,'Exact complete standard-library return after proof required')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__,error))
        for path,expected in protected.items():
            try:
                need(digest(path) == expected,'Exact proof provider/source return required: '+str(path))
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__,error))
        result['writers_confirmed_retired'] = runner.writers_confirmed_retired if runner is not None else True
        result['raw_output_bytes'] = sum(path.stat().st_size for path in output.glob('*.txt'))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic()-started
        if errors or result['elapsed_seconds'] > PROOF_SECONDS or not result['writers_confirmed_retired'] or result['raw_output_bytes'] > 64 * 2**20:
            result['passed'] = False
        if time.monotonic() > deadline:
            result['passed'] = False
            result['finalization_errors'].append('Proof absolute deadline exceeded at return')
        save(output/'PROOF_RESULT.json',result)
    try:
        complete_return(result,output)
        result['elapsed_seconds'] = time.monotonic()-started
        need(finite(result['elapsed_seconds'],0,PROOF_SECONDS) and time.monotonic() <= deadline,
             'Complete raw/API/context readback must finish inside the original proof deadline')
        save(output/'PROOF_RESULT.json',result)
    except Exception as error:
        result['passed'] = False
        result['completion_error'] = '%s: %s' % (type(error).__name__,error)
        result['elapsed_seconds'] = time.monotonic()-started
        save(output/'PROOF_RESULT.json',result)
        raise
    return result
