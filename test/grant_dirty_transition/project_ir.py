"""Project complete retained LLVM through the original accepted owner reader."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'vendor'))
from owner_census import census_file
from owner_census_receipt import qualify_report
from retained_symbols import FAMILIES, need


def project(path):
    census = qualify_report(census_file(path))
    families = {}
    for family, pattern in FAMILIES:
        rows = [row for row in census['definitions'] if pattern.search(row['symbol'])]
        families[family] = dict(definition_count=len(rows), definition_lines=sum(row['body_lines'] for row in rows), definitions=rows)
    return dict(format='atlas-grant-assignment-complete-llvm-projection-v1',
                complete_owner_census=census, families=families,
                actual_compiler_jobs=0, target_cells_accepted=0,
                frontend_cache_completeness=False, memory_savings_accepted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and not args.output.is_symlink(), 'Fresh complete LLVM projection output required')
    report = project(args.ir)
    raw = (json.dumps(report, sort_keys=True, allow_nan=False) + '\n').encode()
    need(len(raw) <= 64 * 2**20, 'Bounded complete LLVM projection required')
    args.output.write_bytes(raw)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
