"""Require the proposed heavy-body convergence in observed retained symbols or IR."""
import argparse
import json
from pathlib import Path
import re


def need(value, message):
    if not value:
        raise RuntimeError(message)


def verify(rows, models, arm):
    need(type(models) is int and models in (2, 10, 300, 500) and arm in ('original', 'candidate', 'restored'), 'Exact model count and comparison arm required')
    result = []
    for index in range(models):
        model = 'AcceptancePerson%04d' % index
        prefix = re.compile(r'^_?\*' + model + r'@Grant::Columns#')
        owned = [row['symbol'] for row in rows if prefix.search(row['symbol'])]
        public = [symbol for symbol in owned if '#assign_mass_assignment_column<' in symbol]
        heavy = [symbol for symbol in owned if '#assign_canonical_mass_assignment_column<' in symbol]
        need(len(public) == 2, 'Two original public assignment input specializations required for ' + model)
        need(sum('Array(BigDecimal)' in symbol for symbol in public) == 1, 'One full column-union public entry required for ' + model)
        need(sum('Array(BigDecimal)' not in symbol for symbol in public) == 1, 'One narrow factory public entry required for ' + model)
        if arm == 'candidate':
            need(len(heavy) == 1 and '<String, Grant::Columns::MassAssignmentValue>' in heavy[0], 'Exactly one container-shaped heavy assignment owner required for ' + model)
        else:
            need(not heavy, 'Original/restored heavy method roster required for ' + model)
        result.append(dict(model=model, public_assignment_symbols=public, canonical_heavy_symbols=heavy))
    return dict(arm=arm, models=models, rows=result, source_shape_predicate_passed=True,
                candidate_behavior_accepted=False, memory_savings_accepted=False, target_cells_accepted=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--census', type=Path, required=True)
    parser.add_argument('--models', type=int, required=True)
    parser.add_argument('--arm', choices=('original', 'candidate', 'restored'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = json.loads(args.census.read_bytes())
    rows = value.get('complete_owner_census', value)['definitions']
    result = verify(rows, args.models, args.arm)
    need(not args.output.exists(), 'Fresh assignment-owner result required')
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
