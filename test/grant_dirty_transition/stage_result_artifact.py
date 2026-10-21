"""Copy a bounded, explicit diagnostic-result roster into one artifact directory."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from public_evidence_rules import inspect_public_bytes, read_regular


def expected_roster(source):
    rows = [(source, 'SERIAL_RESULT.json')]
    for experiment, arms in [('baseline300', ('original',)), ('triplet10', ('original', 'candidate', 'restored'))]:
        prefix = 'results/' + experiment + '/'
        rows.append((source, prefix + 'COMPARISON_RESULT.json'))
        for arm in arms:
            directory = prefix + arm + '/'
            rows.append((source, directory + 'COMMANDS.json'))
            if experiment == 'triplet10':
                rows.append((source, directory + 'DEFINED_TEXT_SYMBOLS.json'))
            for command in ('format', 'build', 'normal', 'field-canary', 'association-canary'):
                for stream in ('stdout', 'stderr'):
                    rows.append((source, directory + command + '.' + stream + '.txt'))
    for directory, count in [('baseline-plan', 300), ('triplet-plan', 10)]:
        for name in ('COMPARISON_PLAN.json', 'original.columns.cr.txt', 'candidate.columns.cr.txt', 'restored.columns.cr.txt', 'FIXTURE_%d.cr.txt' % count, 'FIXTURE_%d.json' % count):
            rows.append((source, directory + '/' + name))
    rows.extend((ROOT, name) for name in ('SOURCE_PINS.json', 'INPUT_PINS.json', 'inputs/SOURCE_INPUTS.json'))
    return rows


def stage(source, output):
    if not source.is_absolute() or not output.is_absolute() or output.exists() or output.is_symlink():
        raise RuntimeError('Fresh absolute owned artifact output required')
    output.mkdir(parents=True)
    files = []
    missing = []
    total = 0
    for root, name in expected_roster(source):
        path = root / name
        if not path.exists() and not path.is_symlink():
            missing.append(name)
            continue
        raw = read_regular(root, name)
        inspect_public_bytes(name, raw)
        size = len(raw)
        if len(files) >= 256 or total + size > 144 * 2**20:
            raise RuntimeError('Bounded diagnostic artifact roster required')
        relative = Path(name) if root == source else Path('packet') / name
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        files.append(dict(path=relative.as_posix(), bytes=size, sha256=hashlib.sha256(raw).hexdigest()))
        total += size
    result = dict(format='atlas-explicit-grant-result-snapshot-v1', files=files, bytes=total, missing_failure_evidence=missing,
                  scope='Bounded result JSON and raw command text snapshots; command records retain actual group-return status and qualification scope',
                  binary_artifacts_retained=False, binary_replay_qualified=False,
                  accepted_target_cells=0, actual_native_acceptance=False, actual_whole_build_acceptance=False)
    (output / 'ARTIFACT_SNAPSHOT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    stage(arguments.source, arguments.output)
