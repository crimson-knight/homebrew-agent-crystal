"""Keep useful Grant source fixed while changing one compiler cache option."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'grant_assignment_cost'
sys.path.insert(0, str(BASE))
from same_job_policy import protect_packet
from cache_evidence import BASE_PACKET, need


def fingerprint(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(output, grant_root, compiler, variant='cache-policy'):
    need(variant == 'cache-policy', 'Explicit compiler-cache experiment required')
    need(output.is_absolute() and grant_root.is_absolute() and compiler.is_absolute(), 'Absolute comparison paths required')
    need(not output.exists() and not output.is_symlink(), 'Fresh comparison plan required')
    protect_packet(BASE_PACKET)
    inventory = json.loads((BASE / 'inputs/SOURCE_INPUTS.json').read_bytes())
    rows = inventory['inputs']
    source_fingerprint = fingerprint(rows)
    need(len(rows) == 1554 and source_fingerprint == inventory['source_tree_sha256'], 'Exact original Grant source inventory required')
    output.mkdir(parents=True)
    columns = (BASE / 'source/columns.original.cr.txt').read_bytes()
    column_sha = hashlib.sha256(columns).hexdigest()
    for arm in ['original', 'candidate', 'restored']:
        (output / (arm + '.columns.cr.txt')).write_bytes(columns)
    fixtures = []
    for count in [2, 10]:
        raw = (BASE / ('inputs/FIXTURE_%d.cr.txt' % count)).read_bytes()
        manifest = (BASE / ('inputs/FIXTURE_%d.json' % count)).read_bytes()
        (output / ('FIXTURE_%d.cr.txt' % count)).write_bytes(raw)
        (output / ('FIXTURE_%d.json' % count)).write_bytes(manifest)
        fixtures.append(dict(models=count, source_sha256=hashlib.sha256(raw).hexdigest(), manifest_sha256=hashlib.sha256(manifest).hexdigest(), fields=16 * count, operations=3 * count, associations=3 * count))
    runs = []
    for repetition in [1, 2, 3]:
        for count in [2, 10]:
            for arm in ['original', 'candidate', 'restored']:
                directory = grant_root / 'performance/results/compile-acceptance' / ('cache-policy-%s-%d-r%d' % (arm, count, repetition))
                fixture = directory / 'fixture.cr'
                binary = directory / 'fixture'
                argv = [str(compiler), 'build', '--no-color', '--error-on-warnings', '-Dwithout_mt', '--threads', '1']
                if arm == 'candidate':
                    argv.append('--no-cache')
                argv += [str(fixture), '-o', str(binary)]
                runs.append(dict(label='%s-%d-r%d' % (arm, count, repetition), arm=arm, models=count, repetition=repetition,
                    expected_source_tree_sha256=source_fingerprint, source_rows=1554,
                    unchanged_fixture_source_sha256=next(row['source_sha256'] for row in fixtures if row['models'] == count),
                    working_directory=str(grant_root), output_directory=str(directory), compile_argv=argv, runtime_argv=[str(binary)],
                    same_binary_controls=[dict(label='normal', field_canary='0', association_canary='0', expected_exit=0),
                        dict(label='field-canary', field_canary='1', association_canary='0', expected_exit=1, required_assertion='AcceptancePerson0000 field first_name'),
                        dict(label='association-canary', field_canary='0', association_canary='1', expected_exit=1, required_assertion='AcceptancePerson0000 parent model identity')],
                    private_cache_starts_absent=True, source_unchanged_through_finally=True))
    plan = dict(format='atlas-grant-cold-cache-policy-source-plan-v1', experiment_kind='cold-default-disabled-default-cache',
                variant=variant, execution_admitted=False, required_target_matrix_size=144, target_cells_accepted=0,
                candidate_delta=dict(changed_library_files=[], original_sha256=column_sha, candidate_sha256=column_sha, changed_compiler_option='--no-cache'),
                source_fingerprints={arm: source_fingerprint for arm in ['original', 'candidate', 'restored']}, fixtures=fixtures, runs=runs,
                full_interval_seconds=1500, build_limit_seconds=900, each_same_binary_control_limit_seconds=120,
                maximum_exclusive_bytes=2000000000, whole_build_provider_qualified=False, memory_savings_accepted=False)
    (output / 'COMPARISON_PLAN.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan
