"""Stage exact source overlays, unchanged rich fixtures, and unadmitted runner argv."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from propose_container import derive, verify
from propose_compatible_container import derive as derive_compatible, HEADER as COMPATIBLE_HEADER, WRAPPER as COMPATIBLE_WRAPPER
from retained_symbols import need, sha


def fingerprint(rows):
    return sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode())


def prepare(output, grant_root, compiler, variant='cost-isolation'):
    need(output.is_absolute() and grant_root.is_absolute() and compiler.is_absolute(), 'Absolute declared comparison paths required')
    need(not output.exists() and not output.is_symlink(), 'Fresh source-only comparison output required')
    pins = json.loads((ROOT / 'INPUT_PINS.json').read_bytes())
    for row in pins['files']:
        path = ROOT / row['path']
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path.read_bytes()) == row['sha256'], 'Exact contained immutable input required: ' + row['path'])
    original_inventory = json.loads((ROOT / 'inputs/SOURCE_INPUTS.json').read_bytes())
    need(fingerprint(original_inventory['inputs']) == original_inventory['source_tree_sha256'], 'Exact shared original1554-source closure required')
    rows = original_inventory['inputs']
    raw = (ROOT / 'source/columns.original.cr.txt').read_bytes()
    need(variant in ('cost-isolation', 'compatible'), 'Explicit source proposal variant required')
    if variant == 'cost-isolation':
        candidate = derive(raw)
        delta = verify(raw, candidate)
    else:
        candidate = derive_compatible(raw)
        start = raw.index(COMPATIBLE_HEADER.encode()) + len(COMPATIBLE_HEADER)
        end = raw.index(b'\n  def read_attribute(', start)
        after = candidate.index(COMPATIBLE_WRAPPER.encode()) + len(COMPATIBLE_WRAPPER)
        after_end = candidate.index(b'\n  def read_attribute(', after)
        body = candidate[after:after_end].replace(b'#{assignment_value.converted_type_name({{column.name.stringify}})}', b'#{typeof(converted_value)}')
        need(body == raw[start:end], 'Exact compatible conversion body except original-type diagnostic boundary required')
        delta = dict(changed_library_files=['src/grant/columns.cr'], original_sha256=sha(raw), candidate_sha256=sha(candidate),
                     original_method_signature_retained=True, assignment_body_unchanged_except_original_type_diagnostic=True,
                     runtime_and_api_compatibility_accepted=False)
    changed = json.loads(json.dumps(rows))
    column = [row for row in changed if row['path'] == 'src/grant/columns.cr' and row['kind'] == 'file']
    need(len(column) == 1 and column[0]['sha256'] == sha(raw), 'Exact original column inventory row required')
    column[0]['sha256'] = sha(candidate)
    source_sets = dict(original=rows, candidate=changed, restored=rows)
    output.mkdir(parents=True)
    for arm, contents in [('original', raw), ('candidate', candidate), ('restored', raw)]:
        (output / (arm + '.columns.cr.txt')).write_bytes(contents)
    fixture_rows = []
    for models in (2, 10):
        fixture = (ROOT / ('inputs/FIXTURE_%d.cr.txt' % models)).read_bytes()
        manifest_raw = (ROOT / ('inputs/FIXTURE_%d.json' % models)).read_bytes()
        for extension, contents in [('cr.txt', fixture), ('json', manifest_raw)]:
            (output / ('FIXTURE_%d.' % models + extension)).write_bytes(contents)
        fixture_rows.append(dict(models=models, source_sha256=sha(fixture), manifest_sha256=sha(manifest_raw),
                                 fields=16 * models, operations=3 * models, associations=3 * models))
    runs = []
    for repetition in (1, 2, 3):
        for models in (2, 10):
            for arm in ('original', 'candidate', 'restored'):
                label = '%s-%d-r%d' % (arm, models, repetition)
                directory = grant_root / 'performance/results/compile-acceptance' / ('assignment-value-' + label)
                fixture, binary = directory / 'fixture.cr', directory / 'fixture'
                runs.append(dict(label=label, arm=arm, models=models, repetition=repetition,
                                 expected_source_tree_sha256=fingerprint(source_sets[arm]), source_rows=len(rows),
                                 unchanged_fixture_source_sha256=next(row['source_sha256'] for row in fixture_rows if row['models'] == models),
                                 working_directory=str(grant_root), output_directory=str(directory),
                                 compile_argv=[str(compiler), 'build', '--no-color', '--error-on-warnings', '-Dwithout_mt', '--threads', '1', str(fixture), '-o', str(binary)],
                                 runtime_argv=[str(binary)],
                                 same_binary_controls=[dict(label='normal', field_canary='0', association_canary='0', expected_exit=0),
                                                       dict(label='field-canary', field_canary='1', association_canary='0', expected_exit=1, required_assertion='AcceptancePerson0000 field first_name'),
                                                       dict(label='association-canary', field_canary='0', association_canary='1', expected_exit=1, required_assertion='AcceptancePerson0000 parent model identity')],
                                 private_cache_starts_absent=True, source_restored_in_finally=True))
    plan = dict(format='atlas-grant-assignment-value-comparison-source-plan-v1', mission='memory-budget-experiment',
                variant=variant, shipping_compatibility_accepted=False,
                candidate_delta=delta, source_fingerprints={arm: fingerprint(value) for arm, value in source_sets.items()},
                fixtures=fixture_rows, runs=runs,
                required_runner='Reviewed admitted complete-build Runner/provider; original-group return and raw evidence remain mandatory',
                full_interval_seconds=1500, build_limit_seconds=900, each_same_binary_control_limit_seconds=120,
                maximum_exclusive_bytes=2000000000, kernel_memory_bytes_for_4096_pages=1999998976,
                original_allocation_and_cpu_guard_limits_retained=True,
                late_bound=['current admitted whole interval and ownership/ACK', 'ordinary-installed wrapper/backend/stdlib and exact hashes',
                            'reviewed native projection including GMP/SQLite/loader closure', 'provider/runner/preparation/source-pin successor accepting exactly one candidate file',
                            'actual host/container IDs, labels, read-only mounts and strict limits',
                            'actual lookup, formatter, spec and source compatibility prerequisite results'],
                actual_compiler_jobs=0, actual_native_jobs=0, execution_admitted=False,
                candidate_behavior_accepted=False, memory_savings_accepted=False,
                required_target_matrix_size=144, target_cells_accepted=0)
    (output / 'COMPARISON_PLAN.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--grant-root', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--variant', choices=('cost-isolation', 'compatible'), default='cost-isolation')
    args = parser.parse_args()
    prepare(args.output, args.grant_root, args.compiler, args.variant)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
