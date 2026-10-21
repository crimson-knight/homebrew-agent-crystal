"""Publish a finite positive metadata roster after the hosted transfer steps return."""
import argparse
from pathlib import Path
import importlib.util
import json
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import proof_tool_transfer as transfer

ROOT = Path(__file__).resolve().parent
FIXED = ('TRANSFER_CLOCK.json', 'TRANSFER_RESULT.json', 'NATIVE_OBSERVATION.json',
         'PROOF_TOOLS.json', 'EXPERIMENT_TOOL_RETURN.json', 'OPERATION_FAILURE.json', 'CLEANUP.json')


def stage(source, output):
    started = time.monotonic()
    transfer.physical(source, directory=True)
    transfer.physical(output.parent, directory=True)
    transfer.need(not output.exists() and not output.is_symlink(), 'Fresh positive tool evidence stage required')
    helper = ROOT / 'vendor/public_evidence_rules.py'
    transfer.need(transfer.sha(helper.read_bytes()) == 'eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed',
                  'Exact accepted public evidence rules required')
    spec = importlib.util.spec_from_file_location('tool_transfer_public_rules', helper)
    rules = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rules)
    payload = {}
    missing = []
    for name in FIXED:
        transfer.clock(started + 30)
        try:
            raw = rules.read_regular(source, name)
        except FileNotFoundError:
            missing.append(name)
            continue
        transfer.need(len(raw) <= 2**20, 'Finite1-MiB observation receipt required')
        rules.inspect_public_bytes(name, raw)
        payload[name] = raw
    observation = transfer.decode(payload['NATIVE_OBSERVATION.json']) if 'NATIVE_OBSERVATION.json' in payload else None
    if observation is not None and observation['passed'] is True:
        native = observation['native']
        expected = {}
        for index, row in enumerate(native['libraries']):
            transfer.need(index < 24, 'Finite selected native library roster required')
            expected['native-data/libraries/%02d.dylib' % index] = row['sha256']
        transfer.need({row['name'] for row in native['packages']} == set(transfer.PACKAGES),
                      'Exact four declared native package metadata rosters required')
        for row in native['packages']:
            expected['native-data/packages/' + row['name'] + '/INSTALL_RECEIPT.json'] = row['receipt_sha256']
            expected['native-data/packages/' + row['name'] + '/FORMULA.rb'] = row['formula_sha256']
        for index, row in enumerate(native['system_files']):
            transfer.need(index < 2 and row['path'] in ('/System/Library/CoreServices/SystemVersion.plist', '/usr/lib/dyld'),
                          'Exact fixed Apple platform metadata roster required')
            expected['native-data/system/%02d.bin' % index] = row['sha256']
        transfer.need({row['path']: row['sha256'] for row in observation['native_evidence_files']} == expected,
                      'Exact complete selected native snapshot manifest required')
        for name, digest in expected.items():
            raw = rules.read_regular(source, name)
            transfer.need(transfer.sha(raw) == digest, 'Exact selected native snapshot digest required')
            rules.inspect_public_bytes(name, raw)
            payload[name] = raw
    transfer.need(sum(len(raw) for raw in payload.values()) <= 64 * 2**20,
                  'Finite64-MiB positive tool/native observation artifact required')
    output.mkdir(mode=0o700)
    rows = []
    for name, raw in payload.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        rows.append(dict(path=name, bytes=len(raw), sha256=transfer.sha(raw)))
    result = dict(format='atlas-grant-tool-admission-public-stage-v1', files=rows, missing=missing,
        maximum_bytes=64 * 2**20, analysis_tool_executable_payload_uploaded=False,
        selected_native_library_payload_uploaded=observation is not None and observation['passed'] is True,
        incomplete_transfer_scope='Missing/canceled transfer has no successful transfer/native/tool-execution claim',
        native_loading_and_full_build_qualification=False, elapsed_seconds=time.monotonic() - started)
    transfer.clock(started + 30)
    (output / 'PUBLIC_STAGE.json').write_bytes(transfer.canonical(result) + b'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--transfer-sha256', required=True)
    args = parser.parse_args()
    transfer.protect_transfer(args.transfer_sha256)
    stage(args.source, args.output)
    transfer.protect_transfer(args.transfer_sha256)
