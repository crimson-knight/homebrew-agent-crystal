"""Retain a positive finite four-arm/proof/calibration roster, including actual refusals."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import stage_result_artifact as original
from dirty_proof import API_METHODS, SPEC_GROUPS
from prepare_dirty_plan import ARMS
from propose_dirty_transition import derive

ORIGINAL_ROSTER = original.expected_roster


def proof_labels():
    result = ['amber_lsp-version','ameba-version']
    for arm in ARMS:
        result.extend([arm+'-format',arm+'-lint'])
        result.extend(arm+'-spec-'+str(index) for index in range(len(SPEC_GROUPS)))
        result.extend([arm+'-probe-build',arm+'-probe-run'])
    result.extend('api-'+str(index) for index in range(len(API_METHODS)))
    result.append('transition-probe-baseline-canary')
    return result


def expected_roster(source):
    rows = [(source,'DIRTY_EXPERIMENT_RESULT.json'),(source,'proof/PROOF_RESULT.json'),(source,'proof/COMMANDS.json')]
    if (source/'proof/CALLBACK_RECEIPT.json').exists() or (source/'proof/CALLBACK_RECEIPT.json').is_symlink():
        rows.append((source,'proof/CALLBACK_RECEIPT.json'))
    labels = proof_labels()
    labels.extend('api-verify-'+str(index) for index in range(len(API_METHODS)) if (source/'proof'/('api-verify-'+str(index)+'.stdout.txt')).exists())
    for label in labels:
        rows.extend((source,'proof/'+label+'.'+stream+'.txt') for stream in ('stdout','stderr'))
    rows.extend((source,'timing-calibration/'+name) for name in ('CALIBRATION_RESULT.json','TIMING_PROFILE.json','COMMANDS.json','probe.stdout.txt','probe.stderr.txt'))
    rows.extend((source,'four-arm-plan/'+name) for name in ('DIRTY_PLAN.json','FIXTURE_2.cr.txt','FIXTURE_2.json'))
    rows.append((source,'results/four-arm2/COMPARISON_RESULT.json'))
    for arm in ARMS:
        prefix = 'results/four-arm2/'+arm+'/'
        rows.extend((source,prefix+name) for name in ('COMMANDS.json','DEFINED_TEXT_SYMBOLS.json','CALLSITE_PROOF.json'))
        rows.extend((source,prefix+label+'.'+stream+'.txt') for label in ('format','build','normal','field-canary','association-canary') for stream in ('stdout','stderr'))
        for relative,raw in derive(arm).items():
            if raw is not None:
                rows.append((source,'four-arm-plan/overlays/'+arm+'/'+relative+'.txt'))
    rows.extend((ROOT,name) for name in ('SOURCE_PINS.json','INPUT_PINS.json','inputs/SOURCE_INPUTS.json',
        'inputs/ACTUAL_ASSIGNMENT_V106_RECEIPT.json','PROOF_TOOLS_PENDING.json','DIRTY_TRANSITION.md','API_AND_HOOK_PREREQUISITES.json'))
    return rows


def stage(source,output):
    if not source.is_absolute() or not output.is_absolute() or output.exists() or output.is_symlink():
        raise RuntimeError('Fresh absolute owned artifact output required')
    output.mkdir(parents=True)
    files,missing,total = [],[],0
    for root,name in expected_roster(source):
        path = root/name
        if not path.exists() and not path.is_symlink():
            missing.append(name)
            continue
        raw = original.read_regular(root,name)
        original.inspect_public_bytes(name,raw)
        if len(files) >= 320 or total+len(raw) > 144 * 2**20:
            raise RuntimeError('Bounded320-entry144-MiB dirty diagnostic artifact roster required')
        relative = Path(name) if root == source else Path('packet')/name
        destination = output/relative
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(raw)
        files.append(dict(path=relative.as_posix(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        total += len(raw)
    result = dict(format='atlas-explicit-grant-dirty-result-snapshot-v1',files=files,bytes=total,missing_failure_evidence=missing,
                  maximum_entries=320,maximum_bytes=144*2**20,binary_artifacts_retained=False,binary_replay_qualified=False,
                  accepted_target_cells=0,actual_native_acceptance=False,actual_whole_build_acceptance=False)
    (output/'ARTIFACT_SNAPSHOT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    stage(args.source,args.output)
