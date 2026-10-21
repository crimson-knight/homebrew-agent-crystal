"""Reject extra heap traffic or an exceeded existing1.5x runtime headroom."""
import argparse
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor'))
from compile_acceptance_contract import parse_json_text

SCENARIOS = ('constructor_keyword', 'constructor_full_hash', 'direct_assignment_narrow', 'direct_assignment_full')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def verify(value):
    expected = {'schema_version', 'compiled_stack_peak_qualified', 'list_of_observations', 'has_value_container', 'value_container_size_bytes', 'broad_input_value_size_bytes', 'narrow_input_value_size_bytes'}
    need(type(value) is dict and set(value) == expected and type(value.get('schema_version')) is int and value['schema_version'] == 1 and value.get('compiled_stack_peak_qualified') is False, 'Typed runtime report and original stack qualification boundary required')
    rows = value.get('list_of_observations')
    need(type(rows) is list and [row.get('scenario') for row in rows] == list(SCENARIOS), 'All four direct constructor/assignment observations required')
    for row in rows:
        need(set(row) == {'scenario', 'iterations', 'checksum', 'allocation_calls', 'requested_bytes', 'elapsed_seconds'}, 'Exact direct-runtime row schema required')
        need(type(row['iterations']) is int and row['iterations'] == 10000 and type(row['checksum']) is int and row['checksum'] == 420000, 'Exact10000-operation behavior/checksum required')
        need(all(type(row[key]) is int and 0 <= row[key] < 2**64 for key in ('allocation_calls', 'requested_bytes')), 'Exact maintained allocation counters required')
        need(type(row['elapsed_seconds']) in (int, float) and type(row['elapsed_seconds']) is not bool and math.isfinite(row['elapsed_seconds']) and 0 < row['elapsed_seconds'] <= 120, 'Finite bounded runtime observation required')
    need(type(value['has_value_container']) is bool, 'Exact container presence required')
    for field in ('value_container_size_bytes', 'broad_input_value_size_bytes', 'narrow_input_value_size_bytes'):
        need(type(value[field]) is int and 0 <= value[field] <= 4096, 'Bounded exact type-layout bytes required')
    need((value['value_container_size_bytes'] > 0) is value['has_value_container'], 'Exact container presence/layout relationship required')
    return {row['scenario']: row for row in rows}


def compare(original, candidate, restored):
    arms = {arm: verify(value) for arm, value in [('original', original), ('candidate', candidate), ('restored', restored)]}
    need(original['has_value_container'] is restored['has_value_container'] is False and candidate['has_value_container'] is True, 'Exact original/container/restored runtime-arm identities required')
    violations, observations = [], []
    for scenario in SCENARIOS:
        row = dict(scenario=scenario)
        for metric in ('allocation_calls', 'requested_bytes'):
            baseline = max(arms['original'][scenario][metric], arms['restored'][scenario][metric])
            actual = arms['candidate'][scenario][metric]
            row[metric + '_delta_from_larger_control'] = actual - baseline
            if actual > baseline:
                violations.append(scenario + ': extra ' + metric)
        timing_limit = 1.5 * max(arms['original'][scenario]['elapsed_seconds'], arms['restored'][scenario]['elapsed_seconds'])
        row['elapsed_seconds_limit'] = timing_limit
        if arms['candidate'][scenario]['elapsed_seconds'] > timing_limit:
            violations.append(scenario + ': exceeded unchanged1.5x CI runtime headroom')
        observations.append(row)
    return dict(passed=not violations, violations=violations, observations=observations,
                runtime_window='Warm calling-fiber allocator traffic and monotonic loop wall time; static sizeof metadata and first64 code bytes are separate copy/frame evidence',
                whole_process_allocation_coverage=False, compiled_stack_peak_qualified=False,
                memory_savings_accepted=False, target_cells_accepted=0)


def read(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 65536, 'Finite direct-runtime evidence required')
    markers = [line.split(b'=', 1)[1] for line in raw.splitlines() if line.startswith(b'ATLAS_ASSIGNMENT_RUNTIME=')]
    need(len(markers) == 1, 'One complete direct-runtime marker required')
    return parse_json_text(markers[0].decode('utf-8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ('original', 'candidate', 'restored'):
        parser.add_argument('--' + arm, type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(read(args.original), read(args.candidate), read(args.restored))
    need(not args.output.exists(), 'Fresh runtime comparison output required')
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
