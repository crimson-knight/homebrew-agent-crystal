"""Retain exact narrow-input error messages as a separate compatibility gate."""
import argparse
import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor'))
from compile_acceptance_contract import parse_json_text

CASES = ('narrow_bool_string', 'full_column_union', 'direct_bool')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def read(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 65536, 'Finite narrow-error probe stdout required')
    markers = [line.split(b'=', 1)[1] for line in raw.splitlines() if line.startswith(b'ATLAS_ASSIGNMENT_NARROW_ERRORS=')]
    need(len(markers) == 1, 'One exact narrow-error observation marker required')
    value = parse_json_text(markers[0].decode('utf-8'))
    verify(value)
    return value


def verify(value):
    need(type(value) is dict and set(value) == {'schema_version', 'list_of_observations'} and type(value['schema_version']) is int and value['schema_version'] == 1, 'Exact narrow-error report schema required')
    rows = value['list_of_observations']
    need(type(rows) is list and [row.get('case_id') for row in rows] == list(CASES), 'Complete narrow/full/direct rejection roster required')
    for row in rows:
        need(set(row) == {'case_id', 'first_name', 'age', 'active', 'raw_age', 'age_change', 'list_of_errors'}, 'Exact narrow-error row schema required')
        need(all(row[field] is None for field in ('first_name', 'age', 'active', 'age_change')) and row['raw_age'] is False, 'Exact rejected Bool/raw/dirty state required')
        errors = row['list_of_errors']
        need(type(errors) is list and len(errors) == 1, 'One original conversion error required')
        error = errors[0]
        need(set(error) == {'field', 'error_class', 'message', 'error_type'} and error['field'] == 'age' and error['error_class'] == 'Grant::ConversionError' and error['error_type'] is None and type(error['message']) is str and 0 < len(error['message']) <= 4096, 'Original conversion error field/class/type and finite message required')


def compare(original, candidate, restored, compatible):
    for value in (original, candidate, restored):
        verify(value)
    need(original == restored, 'Exact restored narrow-error observations required')
    stripped = []
    for value in (original, candidate):
        value = copy.deepcopy(value)
        for row in value['list_of_observations']:
            row['list_of_errors'][0].pop('message')
        stripped.append(value)
    need(stripped[0] == stripped[1], 'Exact value/raw/dirty/error identity required even in the cost-isolation arm')
    differences = [label for label, left, right in zip(CASES, original['list_of_observations'], candidate['list_of_observations']) if left != right]
    return dict(passed=not differences if compatible else True, requires_diagnostic_parity=compatible,
                changed_error_message_cases=differences, shipping_compatibility_accepted=False,
                memory_savings_accepted=False, target_cells_accepted=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ('original', 'candidate', 'restored'):
        parser.add_argument('--' + arm, type=Path, required=True)
    parser.add_argument('--variant', choices=('cost-isolation', 'compatible'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(read(args.original), read(args.candidate), read(args.restored), args.variant == 'compatible')
    need(not args.output.exists(), 'Fresh compatibility result required')
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
