"""Return a finite positive cache-policy result roster after writer retirement."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'grant_assignment_cost'
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / 'vendor'))
sys.path.insert(0, str(ROOT))
from cache_evidence import digest, need
from run_serial import complete_return
from public_evidence_rules import inspect_public_bytes, read_regular


def selected(source):
    outer = json.loads((source / 'CACHE_POLICY_RESULT.json').read_bytes())
    paths = ['CACHE_POLICY_RESULT.json']
    comparison = source / 'comparison/COMPARISON_RESULT.json'
    if not comparison.is_file():
        return paths
    result = json.loads(comparison.read_bytes())
    try:
        complete_return(result)
    except Exception:
        need(outer['passed'] is False, 'Successful outer result requires complete writer return')
        return paths
    paths.append('comparison/COMPARISON_RESULT.json')
    for row in result['samples']:
        arm = row['arm']
        need(arm in ['original', 'candidate', 'restored'], 'Exact cache-policy arm name required')
        for command in row['commands']:
            label = command['label']
            need(label in ['format', 'build', 'normal', 'field-canary', 'association-canary'], 'Exact cache-policy command label required')
            for stream in ['stdout', 'stderr']:
                relative = 'comparison/' + arm + '/' + label + '.' + stream + '.txt'
                need(digest(source / relative) == command[stream + '_sha256'], 'Retired raw cache-policy bytes changed')
                paths.append(relative)
        for name in ['COMMANDS.json', 'DEFINED_TEXT_SYMBOLS.json', 'CACHE_INVENTORY.json']:
            relative = 'comparison/' + arm + '/' + name
            if (source / relative).is_file():
                paths.append(relative)
    calibration = source / 'timing-calibration/CALIBRATION_RESULT.json'
    if calibration.is_file():
        value = json.loads(calibration.read_bytes())
        need(value['passed'] is True, 'Successful timing calibration required before staging its result')
        for name in ['CALIBRATION_RESULT.json', 'TIMING_PROFILE.json', 'COMMANDS.json', 'probe.stdout.txt', 'probe.stderr.txt']:
            paths.append('timing-calibration/' + name)
    if outer['passed'] is True:
        need(digest(comparison) == outer['comparison_sha256'], 'Successful outer result must bind exact comparison bytes')
        need(outer['diagnostic_complete'] is True and result['diagnostic_complete'] is True
             and result['owner_shape_accepted'] is True and result['cache_policy_mechanism_accepted'] is True,
             'Positive outer result requires its complete useful comparison')
        need([row['arm'] for row in result['samples']] == ['original', 'candidate', 'restored'], 'Full successful triplet required')
        for row in result['samples']:
            need(row['passed'] is True and [command['label'] for command in row['commands']] == ['format', 'build', 'normal', 'field-canary', 'association-canary'], 'Successful arm requires every useful behavior and corruption control')
            inventory = source / ('comparison/' + row['arm'] + '/CACHE_INVENTORY.json')
            need(json.loads(inventory.read_bytes()) == row['cache_inventory'], 'Published cache roster must equal measured arm evidence')
            symbols = source / ('comparison/' + row['arm'] + '/DEFINED_TEXT_SYMBOLS.json')
            need(digest(symbols) == row['defined_text_symbols_sha256'], 'Published symbol roster must equal measured arm evidence')
    return paths


def stage(source, output):
    source = source.resolve(strict=True)
    need(output.is_absolute() and not output.exists() and not output.is_symlink(), 'Fresh absolute public staging directory required')
    paths = selected(source)
    need(len(paths) == len(set(paths)) <= 64, 'Finite unique positive result roster required')
    payload = []
    total = 0
    for name in paths:
        path = source / name
        need(not path.is_symlink() and path.is_file() and path.stat().st_size <= 20 * 2**20, 'Bounded ordinary result member required')
        raw = read_regular(source, name)
        total += len(raw)
        need(total <= 64 * 2**20, 'Finite complete public result bytes required')
        inspect_public_bytes(name, raw)
        payload.append((name, raw))
    output.mkdir()
    for name, raw in payload:
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    manifest = dict(format='atlas-cache-policy-public-results-v1', files=[dict(path=name, bytes=len(raw), sha256=digest(output / name)) for name, raw in payload], target_cells_accepted=0)
    (output / 'PUBLIC_STAGE.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    stage(args.source, args.output)
