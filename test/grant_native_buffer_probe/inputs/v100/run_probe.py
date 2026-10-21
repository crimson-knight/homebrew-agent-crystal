"""Finite hosted native-buffer proof; independent source/native admission is explicit."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import shlex
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
OUTER_SECONDS = 900
BUILD_SECONDS = 180
RUN_SECONDS = 30
RETURN_SECONDS = 60
MAX_OUTPUT = 8 * 2**20
MAX_INPUT = 2**30
ARMS = ('original', 'fixed', 'restored')
MODES = ('counts', 'memory')
LABELS = ('start', 'allocated64', 'explicit_dispose64', 'manual_finalizer_twice',
          'borrowed_bitcode', 'consuming_ir', 'deliberate_omission', 'natural_gc_finalizer', 'native_cleanup')
COUNTERS = ('allocations', 'total_requested_payload_bytes', 'caller_owned_outstanding_bytes',
    'peak_caller_owned_bytes', 'wrapper_dispose_attempts', 'real_disposer_entered',
    'intercepted_nonowned_release_attempts', 'real_disposer_completed',
    'bytes_retired_by_disposer', 'shim_errors', 'bytes_transferred_to_consuming_ir',
    'consuming_ir_entered', 'consuming_ir_completed', 'borrowed_bitcode_calls',
    'file_errors', 'native_diagnostics', 'verified_answer_modules', 'contexts_created', 'contexts_disposed', 'active_modules')

def need(value, message):
    if not value:
        raise RuntimeError(message)

def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def read(path):
    return json.loads(stable(path, 2**20)[1])

def stable(path, maximum=256 * 2**20):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, 'Bounded physical regular file required: ' + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(fields(before) == fields(opened) == fields(after) == fields(path.lstat()) and len(raw) == before.st_size,
         'Stable regular-file identity required')
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}, raw

def digest(path):
    return stable(path)[0]['sha256']

def packet(expected):
    manifest = ROOT/'SOURCE_PINS.json'
    need(digest(manifest) == expected, 'Exact externally pinned probe manifest required')
    rows = read(manifest)['files']
    need(1 <= len(rows) <= 64 and len({r['path'] for r in rows}) == len(rows), 'Finite unique source roster required')
    protected = {manifest: expected}
    for row in rows:
        name = PurePosixPath(row['path'])
        need(str(name) == row['path'] and not name.is_absolute() and '..' not in name.parts, 'Canonical contained source required')
        path = ROOT/name
        observed, _ = stable(path)
        need(all(observed[k] == row[k] for k in ('bytes', 'sha256', 'mode')), 'Exact source bytes and mode required: ' + row['path'])
        protected[path] = row['sha256']
    return protected

def load(path, expected, name):
    need(digest(path) == expected, 'Exact imported source required')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(digest(path) == expected, 'Imported source changed')
    return module

def aliases(rows):
    need(isinstance(rows, list) and len(rows) <= 128, 'Finite alias roster required')
    result = []
    seen = set()
    for row in rows:
        path = Path(row['path'])
        need(str(path) not in seen and path.is_absolute(), 'Distinct absolute alias required')
        seen.add(str(path))
        before = path.lstat()
        need(stat.S_ISLNK(before.st_mode) and os.readlink(path) == row['target'] and
             str(path.resolve(strict=True)) == row['resolved_path'], 'Exact lexical native alias required')
        result.append(dict(row))
    return result

def native_policy(path, expected, admitted):
    need(digest(path) == expected, 'Exact independently reviewed native policy required')
    policy = read(path)
    need(policy['format'] == 'atlas-native-buffer-provider-policy-v1' and
         policy['execution_admitted'] is True and policy['scope'] == 'native-buffer-ownership-probe-only',
         'Explicit scoped native execution admission required')
    need(policy['compiler_profile_sha256'] == admitted['observed_profile_sha256'], 'Fresh same-job compiler profile differs from admitted native policy')
    need(policy['compiler_wrapper_sha256'] == admitted['providers']['compiler_wrapper']['sha256'] and
         policy['compiler_backend_sha256'] == admitted['providers']['compiler_backend']['sha256'],
         'Exact compiler/native policy join required')
    need(policy['llvm_version'] == '21.1.8' and policy['llvm_source_commit'] == '2078da43e25a4623cab2d0d60decddf709aaea28', 'Exact reviewed LLVM source/version required')
    need(policy['selected_native_closure_reviewed'] is True, 'Selected native image/alias closure review required')
    need(policy['compiler_driver_search_policy_reviewed'] is True, 'Compiler driver/header/linker/native search review required')
    rows = policy['native_files']
    need(1 <= len(rows) <= 64 and len({r['path'] for r in rows}) == len(rows), 'Finite unique native file roster required')
    total, observed = 0, {}
    for row in rows:
        physical = Path(row['path'])
        need(physical.is_absolute() and str(physical.resolve(strict=True)) == str(physical), 'Physical absolute native provider required')
        current, _ = stable(physical)
        need(all(current[k] == row[k] for k in ('bytes', 'sha256', 'mode')), 'Exact native provider bytes/mode required')
        total += current['bytes']
        need(total <= MAX_INPUT, 'Aggregate native input bound exceeded')
        observed[str(physical)] = current
    for key in ('cc', 'llvm_library'):
        need(policy[key] in observed, 'Named native provider missing from reviewed closure: ' + key)
    need(observed[policy['cc']]['mode'] & 0o100, 'Executable reviewed C compiler required')
    return policy, observed, aliases(policy['aliases'])

def source_gates(path, expected, native, job_identity):
    need(digest(path) == expected, 'Exact source/API feedback receipt required')
    gates = read(path)
    need(gates['format'] == 'atlas-native-buffer-source-gates-v1' and gates['job_identity'] == job_identity,
         'Same actual hosted job/source feedback required')
    need(gates['compiler_profile_sha256'] == native['compiler_profile_sha256'], 'Feedback/compiler policy join differs')
    for name in ('lookup_accepted', 'diagnostics_accepted', 'lint_accepted', 'no_codegen_accepted', 'baseline_sdk_specs_accepted'):
        need(gates[name] is True, 'Actual source feedback remains required: ' + name)
    for name in ('buffer_probe.cr.txt', 'inputs/memory_buffer.original.cr.txt', 'inputs/memory_buffer.fixed.cr.txt'):
        need(gates['source_sha256'][name] == digest(ROOT/name), 'Feedback source bytes differ')
    need(gates['compiler_color'] == 'GREEN' and gates['tool_provider_review_accepted'] is True,
         'GREEN and separately reviewed actual tool providers required')
    need(1 <= len(gates['raw_evidence']) <= 128, 'Positive finite feedback evidence roster required')
    total=0
    for row in gates['raw_evidence']:
        relative=PurePosixPath(row['path'])
        need(str(relative)==row['path'] and not relative.is_absolute() and '..' not in relative.parts,
             'Contained source feedback raw path required')
        need(re.fullmatch('[0-9a-f]{64}', row['sha256']) and 0 <= row['bytes'] <= MAX_OUTPUT,
             'Exact bounded feedback raw identity required')
        raw_path=path.parent/relative
        need(raw_path.resolve(strict=True)==raw_path,'Physical source feedback path required')
        actual,_=stable(raw_path,MAX_OUTPUT)
        need(all(actual[k]==row[k] for k in ('bytes','sha256')),'Physical source feedback bytes differ')
        total+=row['bytes']
        need(total<=MAX_OUTPUT,'Aggregate source feedback output bound exceeded')
    return gates

def validate_command(record,label,seconds,output):
    contract=load(ROOT/'vendor/command_contract.py','33418b91a8ed01e0d3b442781fb5c7ebdbfbb32927e5caecb9747251d9dd52c9','native_probe_command_contract')
    contract.terminal(record,seconds,output=output)
    need(record['label'] == label and record['exit_code'] == 0 and record.get('refusal') is None and
         type(record['elapsed_seconds']) in (int,float) and math.isfinite(record['elapsed_seconds']) and
         record['maximum_seconds'] == seconds and 0 <= record['elapsed_seconds'] <= seconds and
         record['writers_confirmed_retired'] is True, 'Complete successful original command return required')
    terminal=record['terminal_group_observation']
    need(terminal['status']=='absent' and terminal['scope']=='original POSIX process group' and
         record['pid']==record['original_group']==terminal['group'] and
         terminal['bounded_drain_exhausted'] is False and terminal['drain_deadline']<=terminal['original_command_deadline'],
         'Exact retired original group/deadline join required')
    for channel in ('stdout', 'stderr'):
        row, _ = stable(output/(label+'.'+channel+'.txt'), MAX_OUTPUT)
        need(row['sha256'] == record[channel+'_sha256'], 'Retired original stream hash differs')
    return record

def command(runner, label, argv, cwd, environment, seconds, output):
    runner.run(label, argv, cwd=cwd, environment=environment, seconds=seconds)
    result=validate_command(runner.records[-1],label,seconds,output)
    working_bound(output/'private')
    return result

def working_bound(root):
    """Finite metadata scan between commands; the Runner owns command time/output."""
    count=total=0
    for path in root.rglob('*'):
        count+=1
        need(count<=8192,'Finite8192-entry private projection required')
        info=path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),'Physical regular/directory working entries required')
        if stat.S_ISREG(info.st_mode):
            need(info.st_size<=128*2**20,'Bounded128-MiB private regular file required')
            total+=info.st_size
            need(total<=512*2**20,'Finite512-MiB private projection required')
    return {'entries':count,'regular_bytes':total,'scope':'between-command metadata observation'}

def compile_argv(compiler, main, object_path, binary, arm):
    argv = [compiler, 'build', str(main), '--no-color', '--error-on-warnings', '-Dwithout_mt',
            '--threads', '1', '--link-flags', shlex.quote(str(object_path)), '-o', str(binary)]
    if arm == 'fixed':
        argv.append('-Datlas_fixed_buffer')
    return argv

def validate_result(value, arm, mode, library):
    need(value['format'] == 'atlas-native-buffer-probe-v1' and value['arm'] == arm and value['mode'] == mode,
         'Exact arm/mode native result identity required')
    need(value['loaded_llvm_image'] == library, 'Actual loaded LLVM image differs')
    need(value['consumed_native_destructor_observed'] is False, 'Consuming-call ownership must remain separate from native destructor observation')
    need(type(value['native_refusal_messages']) is list and len(value['native_refusal_messages'])==3 and all(type(v) is str and 0<len(v.encode())<=4096 for v in value['native_refusal_messages']),
         'Three bounded actual native refusal messages required')
    need(value['gc_finalizer_observed'] is True and type(value['finalizer_rounds']) is int and 1 <= value['finalizer_rounds'] <= 4,
         'Bounded actual GC finalizer positive control required')
    snapshots = value['snapshots']
    need([v['label'] for v in snapshots] == list(LABELS), 'Complete ordered snapshot roster required')
    for entry in snapshots:
        need(len(entry['counters']) == len(COUNTERS) and all(type(v) is int and 0 <= v <= 2**64-1 for v in entry['counters']), 'Exact unsigned native counter roster required')
        need(type(entry['monotonic_ns']) is int and entry['monotonic_ns'] > 0, 'Positive native monotonic clock required')
        for key in ('user_cpu_ns','system_cpu_ns'):
            need(type(entry[key]) is int and entry[key]>=0,'Unsigned self CPU observations required')
        for key in ('current_rss_bytes', 'self_peak_rss_bytes', 'physical_footprint_bytes'):
            need((entry[key] is None) if mode == 'counts' else (type(entry[key]) is int and entry[key] > 0), 'Explicit process-memory availability required')
        values=dict(zip(COUNTERS,entry['counters']))
        need(values['total_requested_payload_bytes']==values['caller_owned_outstanding_bytes']+
             values['bytes_retired_by_disposer']+values['bytes_transferred_to_consuming_ir'],
             'Every snapshot must account for complete caller-owned requested bytes')
        need(values['real_disposer_entered']==values['real_disposer_completed'] and
             values['wrapper_dispose_attempts']==values['real_disposer_entered']+values['intercepted_nonowned_release_attempts'],
             'Every snapshot must join real native disposer completion and intercepted attempts')
    need(all(a['monotonic_ns'] <= b['monotonic_ns'] for a,b in zip(snapshots, snapshots[1:])), 'Ordered native snapshots required')
    named = {row['label']:dict(zip(COUNTERS,row['counters'])) for row in snapshots}
    start, allocated, disposed, end = [named[n] for n in ('start','allocated64','explicit_dispose64','native_cleanup')]
    need(all(v == 0 for v in start.values()), 'Clean shim counter baseline required')
    need(allocated['allocations'] == 64 and allocated['caller_owned_outstanding_bytes'] == 64*2**20 and
         allocated['total_requested_payload_bytes'] == 64*2**20, 'Known64-MiB native copied-buffer allocation required')
    fixed = arm == 'fixed'
    need(disposed['real_disposer_entered'] == disposed['real_disposer_completed'] == (64 if fixed else 0) and
         disposed['caller_owned_outstanding_bytes'] == (0 if fixed else 64*2**20), 'Actual original/fixed disposal sensitivity differs')
    need(end['caller_owned_outstanding_bytes'] == 0 and end['shim_errors'] == 0 and
         end['allocations'] == 73 and end['consuming_ir_entered'] == end['consuming_ir_completed'] == 3 and
         end['borrowed_bitcode_calls'] == 2 and end['file_errors'] == 1 and end['verified_answer_modules'] == 3 and
         end['contexts_created'] == end['contexts_disposed'] == 5 and end['active_modules'] == 0 and
         end['real_disposer_entered'] == end['real_disposer_completed'] == 70 and
         end['wrapper_dispose_attempts']==(70 if fixed else 73) and
         end['intercepted_nonowned_release_attempts'] == (0 if fixed else 3), 'Complete native behavior/ownership/control roster required')
    need(end['total_requested_payload_bytes'] == end['bytes_retired_by_disposer'] + end['bytes_transferred_to_consuming_ir'],
         'Complete requested-payload ownership accounting required')
    consumed=named['consuming_ir'];before_gc=named['deliberate_omission'];after_gc=named['natural_gc_finalizer']
    need(before_gc['caller_owned_outstanding_bytes']==consumed['caller_owned_outstanding_bytes']+2**20 and
         before_gc['real_disposer_completed']==consumed['real_disposer_completed'],
         'Deliberately omitted native release must expose an additional1-MiB caller-owned payload')
    need(after_gc['real_disposer_completed']==before_gc['real_disposer_completed']+1,
         'Natural finalizer must complete exactly one actual disposer call')
    return {'counters':named, 'raw_native_result':value, 'process_memory_is_separate':True,
            'consumed_native_heap_live_bytes':None, 'actual_compiler_retained_rss_savings_accepted':False}

def environment(private, cc):
    result = {k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR')}
    result.update(HOME=str(private/'home'), CRYSTAL_CACHE_DIR=str(private/'cache'),
                  CRYSTAL_WORKERS='1', LC_ALL='C', NO_COLOR='1', CC=shlex.quote(cc))
    return result

def macho(path):
    row,raw=stable(path,32*2**20)
    need(len(raw)>=32 and raw[:4]==b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I',raw,4)[0]==0x100000c and
         struct.unpack_from('<I',raw,12)[0]==2 and row['mode']&0o100,'Returned physical ARM64 Mach-O executable required')
    return row

def execute(args, driver, context, protected):
    started = context['started']
    need(args.output.parent.resolve(strict=True) == args.output.parent and not args.output.exists(), 'Fresh owned physical output required')
    output = args.output
    output.mkdir()
    private = output/'private'; private.mkdir(); (private/'home').mkdir()
    runner = driver.Runner(output)
    runner.deadline = started + OUTER_SECONDS - RETURN_SECONDS
    result = {'format':'atlas-native-buffer-controller-v1', 'complete':False,
        'job_identity':context['admitted']['job_identity'], 'compiler_profile_sha256':context['admitted']['observed_profile_sha256'],
        'local_workload_jobs':0, 'full_target_cells_accepted':0, 'actual_compiler_memory_savings_accepted':False,
        'maximum_seconds':OUTER_SECONDS, 'return_reserve_seconds':RETURN_SECONDS, 'errors':[], 'arms':{}}
    write(output/'SDK_ADMISSION.json',context['admitted'])
    native_before = aliases_before = policy = None
    expected_working = {}
    try:
        policy, native_before, aliases_before = native_policy(args.native_policy,args.native_policy_sha256,context['admitted'])
        write(output/'NATIVE_BEFORE.json',{'files':native_before,'aliases':aliases_before,'policy':policy})
        gates = source_gates(args.source_gates,args.source_gates_sha256,policy,context['admitted']['job_identity'])
        write(output/'SOURCE_GATES.json',gates)
        (output/'source_feedback').mkdir()
        for row in gates['raw_evidence']:
            path=output/'source_feedback'/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(stable(args.source_gates.parent/row['path'],MAX_OUTPUT)[1])
        env = environment(private,policy['cc'])
        fixture = private/'known.bin'; fixture.write_bytes(b'Q'*262144)
        object_path = output/'buffer_shim.o'
        cc_argv = [policy['cc'],'-std=c11','-Wall','-Wextra','-Werror','-O2','-c',str(ROOT/'buffer_shim.c'),'-o',str(object_path)]
        command(runner,'build-shim',cc_argv,private,env,30,output)
        result['shim_object']=stable(object_path,8*2**20)[0]
        need(not (output/'build-shim.stdout.txt').read_bytes() and not (output/'build-shim.stderr.txt').read_bytes(), 'GREEN C shim build required')
        remaining = 3*BUILD_SECONDS + 6*RUN_SECONDS + 45
        need(runner.deadline-time.monotonic() >= remaining, 'Complete three-build/six-run and format reserve required')
        for arm in ARMS:
            work = private/arm; work.mkdir()
            arm_env=dict(env,CRYSTAL_CACHE_DIR=str(work/'cache'))
            wrapper = ROOT/('inputs/memory_buffer.fixed.cr.txt' if arm=='fixed' else 'inputs/memory_buffer.original.cr.txt')
            (work/'memory_buffer.cr').write_bytes(wrapper.read_bytes())
            (work/'main.cr').write_bytes((ROOT/'buffer_probe.cr.txt').read_bytes())
            expected_working[arm] = {name:digest(work/name) for name in ('memory_buffer.cr','main.cr')}
            command(runner,'format-'+arm,[context['paths']['compiler_wrapper'],'tool','format','--check',str(work/'main.cr'),str(work/'memory_buffer.cr')],work,arm_env,15,output)
            binary = output/(arm+'.probe')
            argv = compile_argv(context['paths']['compiler_wrapper'],work/'main.cr',object_path,binary,arm)
            command(runner,'build-'+arm,argv,work,arm_env,BUILD_SECONDS,output)
            need(not (output/('build-'+arm+'.stdout.txt')).read_bytes() and not (output/('build-'+arm+'.stderr.txt')).read_bytes(), 'GREEN Crystal native probe build required')
            row = macho(binary)
            result['arms'][arm]={'build_argv':argv,'binary':row,'modes':{}}
            for mode in MODES:
                label=arm+'-'+mode
                command(runner,label,[str(binary),policy['llvm_library'],arm,mode,str(fixture),str(private/'absent.bin')],work,arm_env,RUN_SECONDS,output)
                raw=(output/(label+'.stdout.txt')).read_bytes()
                need(len(raw)<=MAX_OUTPUT,'Finite positive native result required')
                value=json.loads(raw)
                result['arms'][arm]['modes'][mode]=validate_result(value,arm,mode,policy['llvm_library'])
        for mode in MODES:
            a=result['arms']['original']['modes'][mode]['counters']
            b=result['arms']['restored']['modes'][mode]['counters']
            need(a==b,'Restored original native counters differ')
        result['observer_contrasts']={}
        for arm in ARMS:
            observations={}
            for mode in MODES:
                snapshots=result['arms'][arm]['modes'][mode]['raw_native_result']['snapshots']
                observations[mode]={'elapsed_ns':snapshots[-1]['monotonic_ns']-snapshots[0]['monotonic_ns'],
                    'user_cpu_ns':snapshots[-1]['user_cpu_ns']-snapshots[0]['user_cpu_ns'],
                    'system_cpu_ns':snapshots[-1]['system_cpu_ns']-snapshots[0]['system_cpu_ns']}
            result['observer_contrasts'][arm]={'order':list(MODES),'raw_observations':observations,
                'causal_overhead_accepted':False,'note':'One ordered pair with the same mandatory safety registry; process/GC variation remains observable'}
        result['complete']=True
    except Exception as error:
        result['errors'].append(type(error).__name__+': '+str(error))
    finally:
        for label,check in [('source/provider',lambda:[need(digest(p)==h,'Protected source/provider changed') for p,h in protected.items()]),
                ('same-job SDK',context['revalidate']),
                ('stdlib',lambda:need(driver.tree_identity(context['stdlib'])==context['admitted']['stdlib'],'Installed stdlib changed'))]:
            try: check()
            except Exception as error: result['errors'].append(label+': '+str(error))
        try:
            if policy is not None:
                _,after,alias_after=native_policy(args.native_policy,args.native_policy_sha256,context['admitted'])
                need(after==native_before and alias_after==aliases_before,'Exact native input/alias return required')
                write(output/'NATIVE_AFTER.json',{'files':after,'aliases':alias_after})
                if (output/'SOURCE_GATES.json').exists():
                    source_gates(args.source_gates,args.source_gates_sha256,policy,context['admitted']['job_identity'])
            for arm,rows in expected_working.items():
                need({n:digest(private/arm/n) for n in rows}==rows,'Working multi-file wrapper/harness changed')
            write(output/'SOURCE_RETURN.json',{'working_files':expected_working,
                'protected_source_provider_sha256':{str(p):digest(p) for p in protected},
                'working_projection':working_bound(private),
                'source_inputs_restored_exact':True})
            write(output/'STDLIB_AFTER.json',driver.tree_identity(context['stdlib']))
        except Exception as error: result['errors'].append('Final identities: '+str(error))
        result['writers_confirmed_retired']=runner.writers_confirmed_retired
        result['original_group_observations']=runner.group_observations
        if runner.writers_confirmed_retired:
            try: shutil.rmtree(private)
            except Exception as error: result['errors'].append('Private cleanup: '+str(error))
        else: result['errors'].append('Unresolved original writers; private inputs preserved')
        result['private_removed']=not private.exists()
        result['elapsed_seconds']=time.monotonic()-started
        if not (math.isfinite(result['elapsed_seconds']) and 0<=result['elapsed_seconds']<=OUTER_SECONDS):
            result['errors'].append('Complete terminal deadline exceeded or clock invalid')
        result['command_count']=len(runner.records)
        write(output/'COMMANDS.json',runner.records)
        expected=['build-shim']+[label for a in ARMS for label in ('format-'+a,'build-'+a,a+'-counts',a+'-memory')]
        if result['complete'] and [r['label'] for r in runner.records]!=expected: result['errors'].append('Complete13-command roster differs')
        if result['complete']:
            try:
                for record in runner.records:
                    seconds=BUILD_SECONDS if record['label'].startswith('build-') and record['label']!='build-shim' else 15 if record['label'].startswith('format-') else 30
                    validate_command(record,record['label'],seconds,output)
                need(len(runner.group_observations)==13 and
                     all(r['terminal_group_observation']==o for r,o in zip(runner.records,runner.group_observations)),
                     'Complete exact original command/group observation return required')
                for arm in ARMS:
                    need(macho(output/(arm+'.probe'))==result['arms'][arm]['binary'],'Compiled probe bytes changed on final return')
                need(stable(output/'buffer_shim.o')[0]==result['shim_object'],'Shim object changed on final return')
            except Exception as error: result['errors'].append('Final raw/group/native artifact checks: '+str(error))
        if sum(p.stat().st_size for p in output.glob('*.txt'))>MAX_OUTPUT: result['errors'].append('Aggregate output bound exceeded')
        result['complete']=result['complete'] and not result['errors'] and runner.writers_confirmed_retired and result['private_removed']
        write(output/'RESULT.json',result)
    return 0 if result['complete'] else 2

def main(args):
    started=time.monotonic()
    need(platform.system()=='Darwin' and platform.machine()=='arm64' and os.environ.get('GITHUB_ACTIONS')=='true', 'Actual execution belongs to admitted hosted Mac ARM64')
    protected=packet(args.packet_sha256)
    base=read(ROOT/'BASE_INPUT_PINS.json')
    for row in base['base_files']:
        path=args.repository/row['path']; observed,_=stable(path)
        need(all(observed[k]==row[k] for k in ('bytes','sha256')),'Exact accepted revision1 base source required')
        protected[path]=row['sha256']
    policy_path=args.repository/'test/grant_assignment_cost/same_job_policy.py'
    sdk=load(policy_path,protected[policy_path],'native_probe_same_job_policy')
    protected.update(sdk.protect_packet(base['base_files'][4]['sha256']))
    admitted=sdk.metadata(args.sdk_evidence,os.environ)
    driver_path=args.repository/'test/sdk_install_qualification.py'
    driver=load(driver_path,sdk.DRIVER_SHA256,'native_probe_sdk_driver')
    paths={k:v['path'] for k,v in admitted['providers'].items()}
    for name,path in paths.items():
        need(digest(path)==admitted['providers'][name]['sha256'],'Same-job compiler provider differs')
        protected[Path(path)]=admitted['providers'][name]['sha256']
    need(digest(Path(sys.executable).resolve())==admitted['runner']['python_sha256']==args.python_sha256,'Same actual Python provider required')
    protected[Path(sys.executable).resolve()]=args.python_sha256
    for path,expected in ((args.native_policy,args.native_policy_sha256),(args.source_gates,args.source_gates_sha256)):
        need(digest(path)==expected,'Externally supplied admission source differs'); protected[path]=expected
    prefix=Path((args.sdk_evidence/'brew-prefix.stdout.txt').read_text().strip()).resolve(strict=True)
    stdlib=prefix/'share/agent-crystal/src'
    need(driver.tree_identity(stdlib)==admitted['stdlib'],'Current installed stdlib differs')
    need(Path(paths['compiler_wrapper'])==prefix/'bin/crystal-alpha' and
         Path(paths['compiler_backend'])==prefix/'libexec/agent-crystal-bin','Exact ordinary installed wrapper/backend paths required')
    driver.verify_wrapper(Path(paths['compiler_wrapper']).read_text(),Path(paths['compiler_backend']),stdlib,
        Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip()),'Darwin')
    for name,relative in (('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')):
        path=prefix/relative
        need(digest(path)==digest(args.sdk_evidence/name),'Current installed formula/receipt differs')
        protected[path]=digest(path)
    before=sdk.roster(args.sdk_evidence)
    def revalidate():
        sdk.metadata(args.sdk_evidence,os.environ)
        need(sdk.roster(args.sdk_evidence)==before,'Same-job SDK evidence changed')
    context={'started':started,'paths':paths,'admitted':admitted,'stdlib':stdlib,'revalidate':revalidate}
    return execute(args,driver,context,protected)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','sdk-evidence','native-policy','source-gates','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python','native-policy','source-gates'):
        parser.add_argument('--'+name+'-sha256',required=True)
    raise SystemExit(main(parser.parse_args()))
