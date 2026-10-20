"""Keep the GC pilot's requested policy, timing scope, and A/B/A identity explicit."""
from pathlib import Path
import copy, hashlib, re

POLICY_KEY = 'GC_FREE_SPACE_DIVISOR'
ARMS = (('default_before', None), ('divisor16', '16'), ('default_after', None))
TIME_FIELDS = ('maximum resident set size', 'average shared memory size',
 'average unshared data size', 'average unshared stack size', 'page reclaims',
 'page faults', 'swaps', 'block input operations', 'block output operations',
 'messages sent', 'messages received', 'signals received',
 'voluntary context switches', 'involuntary context switches',
 'instructions retired', 'cycles elapsed', 'peak memory footprint')

def require(value, message):
 if not value: raise RuntimeError(message)

def policy_environment(baseline, arm):
 require(type(baseline) is dict and POLICY_KEY not in baseline,
         'Baseline policy must be explicitly absent')
 settings = dict(ARMS)
 require(arm in settings, 'Exact A/B/A arm is required')
 output = dict(baseline)
 if settings[arm] is not None: output[POLICY_KEY] = settings[arm]
 return output

def verify_policy_environment(baseline, actual, arm):
 require(actual == policy_environment(baseline, arm),
         'Only the named requested GC policy may differ at this boundary')
 return {'arm': arm, 'requested_value': actual.get(POLICY_KEY),
         'startup_mechanism_expected_value': 16 if arm == 'divisor16' else 3,
         'compiler_getter_observed': False,
         'scope': 'Requested process environment plus retained startup/source mechanism; compiler getter is not instrumented'}

def split_timed_compiler_stderr(raw, compiler_pid):
 require(type(raw) is bytes and len(raw) <= 16 * 2**20, 'Bounded raw compiler/timer stderr required')
 lines = raw.decode('utf-8').splitlines()
 require(len(lines) >= 18, 'Complete Darwin timing footer required')
 first = re.fullmatch(r' *(\d+\.\d{2}) real +(\d+\.\d{2}) user +(\d+\.\d{2}) sys', lines[-18])
 require(first is not None, 'Exact Darwin timing duration footer differs')
 values = {}
 for label, line in zip(TIME_FIELDS, lines[-17:]):
  match = re.fullmatch(r' *(\d+)  ' + re.escape(label), line)
  require(match is not None, 'Exact Darwin timing field differs: ' + label)
  values[label] = int(match[1])
 main, other = [], []
 for number, line in enumerate(lines[:-18], 1):
  match = re.match(r'^dyld\[(\d+)\]: ', line)
  require(match is not None, 'Compiler diagnostic is outside the admitted loader trace grammar')
  record = {'line_number': number, 'pid': int(match[1]), 'text': line}
  (main if record['pid'] == compiler_pid else other).append(record)
 require(main, 'Actual compiler PID loader trace is required')
 return {'compiler_trace': '\n'.join(row['text'] for row in main) + '\n',
  'other_process_trace_lines': other,
  'raw_stderr_sha256': hashlib.sha256(raw).hexdigest(),
  'time': {'wall_seconds_rounded_0_01': float(first[1]),
   'user_seconds_rounded_0_01': float(first[2]), 'system_seconds_rounded_0_01': float(first[3]),
   'fields': values, 'timed_build_command_maximum_bytes': values['maximum resident set size'],
   'scope': 'Darwin waited-command maximum with reaped-descendant maxima; overlapping whole-build memory remains unqualified'},
  'non_loader_compiler_diagnostics': [],
  'other_process_provider_closure_qualified': False}

def verify_aba(samples):
 require(type(samples) is list and len(samples) == 3, 'Three complete A/B/A samples required')
 require([row['arm'] for row in samples] == [row[0] for row in ARMS], 'Exact A/B/A order differs')
 identity_keys = ('models', 'source_tree_sha256', 'fixture_source_sha256', 'manifest_sha256', 'prepared_stdlib_sha256')
 for key in identity_keys:
  require(len({row[key] for row in samples}) == 1, 'Matched A/B/A identity differs: ' + key)
 require(all(row['passed'] is True and row['compiler_color'] == 'GREEN' for row in samples),
         'All complete emits and real behavior gates are required')
 require([row['requested_policy']['requested_value'] for row in samples] == [None, '16', None],
         'Requested GC policy restoration differs')
 require(len({row['cold_cache_identity']['path'] for row in samples}) == 3,
         'Three distinct actually cold cache identities required')
 require(all(row['cold_cache_identity']['was_absent'] and row['cold_cache_identity']['terminal_absent'] for row in samples),
         'Exact cold-cache admission and retirement required')
 peaks=[row['timed_build']['time']['timed_build_command_maximum_bytes'] for row in samples]
 return {'passed': True, 'one_sample_per_arm': True,
  'policy_minus_each_default_bytes':[peaks[1]-peaks[0],peaks[1]-peaks[2]],
  'policy_over_each_default_ratio':[peaks[1]/peaks[0],peaks[1]/peaks[2]],
  'timed_command_maximum_bytes': [row['timed_build']['time']['timed_build_command_maximum_bytes'] for row in samples],
  'sampled_direct_compiler_rss_bytes': [row['compiler_rss_phase_observations']['sampled_direct_pid_peak_bytes'] for row in samples],
  'observed_peak_is_upper_bound': False, 'whole_build_provider_qualified': False,
  'compiler_applied_getter_qualified': False, 'retained_live_heap_measured': False,
  'collection_count_measured': False, 'total_allocation_measured': False,
  'memory_savings_accepted': False, 'canonical_cells_accepted': 0}
