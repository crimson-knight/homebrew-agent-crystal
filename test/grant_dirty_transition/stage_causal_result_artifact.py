"""Reuse the reviewed positive artifact copier for the separate causal-only result."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import stage_result_artifact as original

ORIGINAL_ROSTER = original.expected_roster


def expected_roster(source):
    rows = [(source, 'CAUSAL_ONLY_RESULT.json'), (source, 'HISTORICAL_300_FAILURE.json')]
    rows.extend((source, 'timing-calibration/' + name) for name in (
        'CALIBRATION_RESULT.json', 'TIMING_PROFILE.json', 'COMMANDS.json', 'probe.stdout.txt', 'probe.stderr.txt'))
    for root, name in ORIGINAL_ROSTER(source):
        if name.startswith('results/triplet10/') or name.startswith('triplet-plan/') or root == ROOT:
            rows.append((root, name))
    rows.extend((ROOT, name) for name in ('HISTORICAL_300_FAILURE.json', 'run_causal_only.py',
                'stage_causal_result_artifact.py', 'timing_profile.py', 'TIMING_PROFILE_V105.md',
                'ACTUAL_FOOTER_FAILURE.json', 'inputs/PREDECESSOR_V102_SOURCE_PINS.json',
                'inputs/PREDECESSOR_V104_SOURCE_PINS.json', 'fixtures/timing/actual16.stderr.txt',
                'fixtures/timing/historical18.stderr.txt', 'fixtures/timing/PROVENANCE.json'))
    rows.extend((ROOT, 'inputs/historical_run_39493843606/' + name) for name in (
        'GRANT_EXTRACTION_RECEIPT.json', 'GRANT_EVIDENCE/SERIAL_RESULT.json',
        'GRANT_EVIDENCE/results/baseline300/COMPARISON_RESULT.json',
        'GRANT_EVIDENCE/results/baseline300/original/COMMANDS.json',
        'GRANT_EVIDENCE/results/baseline300/original/build.stdout.txt',
        'GRANT_EVIDENCE/results/baseline300/original/build.stderr.txt'))
    return rows


def stage(source, output):
    try:
        original.expected_roster = expected_roster
        return original.stage(source, output)
    finally:
        original.expected_roster = ORIGINAL_ROSTER


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    stage(args.source, args.output)
