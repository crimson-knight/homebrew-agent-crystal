"""Stage the unchanged complete300-model association fixture as a Mac diagnostic."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from prepare_comparison import prepare
from retained_symbols import need, sha

FIXTURE_SHA256 = 'a3634fb654e1e1b6c4ab6ef6220022aac370295a4126eac9f0255043ed519585'
MANIFEST_SHA256 = '2d822fdf6a21d14e8965d8b4d720065c7b0dcf6f05e884b008bc2ca5480ad8ea'


def prepare_baseline(output, grant_root, compiler, fixture=ROOT / 'inputs/FIXTURE_300.cr.txt', manifest=ROOT / 'inputs/FIXTURE_300.json'):
    raw, manifest_raw = fixture.read_bytes(), manifest.read_bytes()
    need(sha(raw) == FIXTURE_SHA256 and sha(manifest_raw) == MANIFEST_SHA256, 'Exact unchanged first representative300-model fixture/manifest required')
    plan = prepare(output, grant_root, compiler)
    (output / 'FIXTURE_300.cr.txt').write_bytes(raw)
    (output / 'FIXTURE_300.json').write_bytes(manifest_raw)
    row = dict(plan['runs'][0])
    directory = grant_root.parent / 'unchanged300-fixture'
    row.update(label='original-300-r1', models=300, repetition=1, output_directory=str(directory), unchanged_fixture_source_sha256=FIXTURE_SHA256,
               compile_argv=[str(compiler), 'build', '--no-color', '--error-on-warnings', '-Dwithout_mt', '--threads', '1', str(directory / 'fixture.cr'), '-o', str(directory / 'fixture')],
               runtime_argv=[str(directory / 'fixture')])
    plan.update(experiment_kind='original300-feasibility-baseline', variant='unchanged-default-source', runs=[row],
                fixtures=[dict(models=300, source_sha256=FIXTURE_SHA256, manifest_sha256=MANIFEST_SHA256, fields=4800, operations=900, associations=900)],
                full_interval_seconds=1500, build_limit_seconds=900, each_same_binary_control_limit_seconds=120,
                whole_build_provider_qualified=False, target_cells_accepted=0)
    (output / 'COMPARISON_PLAN.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'grant-root', 'compiler'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--fixture', type=Path, default=ROOT / 'inputs/FIXTURE_300.cr.txt')
    parser.add_argument('--manifest', type=Path, default=ROOT / 'inputs/FIXTURE_300.json')
    args = parser.parse_args()
    prepare_baseline(args.output, args.grant_root, args.compiler, args.fixture, args.manifest)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
