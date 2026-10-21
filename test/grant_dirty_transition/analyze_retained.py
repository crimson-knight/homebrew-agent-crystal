"""Compare exact retained code metadata while preserving the accepted archive reader."""
import argparse
import json
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'vendor'))
from artifact_archive import verify_artifacts
from retained_symbols import read_macho, family_rows, need, sha


def read_identity(row):
    path = Path(row['path'])
    need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'], 'Exact ordinary evidence input size required')
    raw = path.read_bytes()
    need(sha(raw) == row['sha256'], 'Exact evidence input SHA required')
    return raw


def analyze(cohort):
    sample = json.loads(read_identity(cohort['sample']))
    source_raw = read_identity(cohort['source'])
    source = json.loads(source_raw)
    if cohort.get('kind') == 'paired-select':
        manifest = sample['archive_manifest']
        sample = sample['sample_receipt']['diagnostic']
        sample['fixture_source_sha256'] = cohort['fixture_sha256']
        need(sample['source_tree_sha256_before'] == sample['source_tree_sha256_after'] == cohort['source_tree_sha256'], 'Exact paired diagnostic before/after source closure required')
    else:
        manifest = sample['artifacts']['manifest']
        compilation = json.loads(read_identity(cohort['compilation']))
        need(compilation['build'] == sample['build'] and compilation['fixture_source_sha256'] == sample['fixture_source_sha256'], 'Exact compiler command/fixture-to-sample binding required')
        if 'source_tree_sha256' in compilation:
            need(compilation['source_tree_sha256'] == cohort['source_tree_sha256'], 'Exact compiler source closure required')
        else:
            campaign = json.loads(read_identity(cohort['campaign']))
            need(campaign['passed'] is True and campaign['original_source_before_after_equal'] is True and sample in campaign['samples'], 'Exact original campaign sample membership and source guards required')
            need(read_identity(cohort['source_after']) == source_raw, 'Exact campaign original before/after source identities required')
        need(sample['compiler_color'] == 'GREEN', 'Actual original diagnostic GREEN compiler required')
    need(sample['passed'] is True and sample['target_accepted'] is False, 'Complete passed diagnostic with original target boundary required')
    archive = Path(cohort['archive'])
    verification = verify_artifacts(archive, manifest, manifest['compressed_cap_bytes'], manifest['content_cap_bytes'])
    member_rows = {row['path']: row for row in manifest['list_of_members']}
    need('fixture' in member_rows and 'fixture.cr' in member_rows, 'Complete retained fixture and binary required')
    with tarfile.open(archive, 'r:gz') as value:
        binary = value.extractfile('fixture').read()
        fixture = value.extractfile('fixture.cr').read()
        if cohort.get('kind') == 'paired-select':
            need(value.extractfile('source_inventory_before.json').read() == source_raw and value.extractfile('source_inventory_after.json').read() == source_raw, 'Exact retained paired source inventory members required')
    need(sha(binary) == sample['binary_sha256'] == member_rows['fixture']['sha256'], 'Exact sample-to-binary identity required')
    need(sha(fixture) == sample['fixture_source_sha256'] == cohort['fixture_sha256'], 'Exact unchanged rich fixture required')
    need(source['source_tree_sha256'] == cohort['source_tree_sha256'] and len(source['inputs']) == cohort['source_rows'], 'Exact upstream source closure required')
    need(sha(json.dumps(source['inputs'], sort_keys=True, separators=(',', ':')).encode()) == cohort['source_tree_sha256'], 'Recomputed complete logical source-inventory identity required')
    definitions = read_macho(binary)
    families = family_rows(definitions)
    models = sorted(set(re.findall(r'class (AcceptancePerson\d{4}) < Grant::Base', fixture.decode())))
    need(len(models) == cohort['models'], 'Exact retained model declaration roster required')
    return dict(label=cohort['label'], models=models, evidence=cohort, archive_verification=verification,
                source_tree_sha256=source['source_tree_sha256'], fixture_sha256=sha(fixture),
                binary={key: value for key, value in definitions.items() if key != 'definitions'},
                families=families,
                explicit_base_plus_symbol_mentions=sum('Grant::Base+' in row['symbol'] for row in definitions['definitions']),
                broad_polymorphic_text_symbols=[row for row in definitions['definitions'] if 'Grant::Polymorphic' in row['symbol']],
                source_instantiation_or_memory_saving_accepted=False, target_cells_accepted=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and not args.output.is_symlink(), 'Fresh retained census output required')
    catalog = json.loads((ROOT / 'COHORTS.json').read_bytes())
    results = [analyze(cohort) for cohort in catalog['cohorts']]
    args.output.mkdir(parents=True)
    report = dict(format='atlas-grant-retained-assignment-symbol-census-v1', cohorts=results,
                  actual_compiler_jobs=0, actual_native_jobs=0, actual_container_jobs=0,
                  required_target_cells=144, target_cells_accepted=0,
                  memory_savings_accepted=False, candidate_runtime_accepted=False)
    raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    need(len(raw) <= 16 * 2**20, 'Finite retained metadata report required')
    (args.output / 'RETAINED_SYMBOL_CENSUS.json').write_bytes(raw)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
