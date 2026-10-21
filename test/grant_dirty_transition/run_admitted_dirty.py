"""Keep analysis-tool/native inputs protected around the unchanged15000-second experiment."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import proof_tool_transfer as transfer
from same_job_policy import metadata
import run_dirty_experiment_with_deadline as original


def run(args, invoke=None):
    started = time.monotonic()
    outer = started + 15120
    result = dict(format='atlas-grant-analysis-tool-experiment-guard-v1', passed=False,
                  controller_maximum_seconds=15000, metadata_return_reservation=120,
                  actual_target_cells_accepted=0, full_native_memory_qualified=False)
    before = admission = None
    code = 2
    paths = {}
    try:
        paths.update(transfer.protect_transfer(args.transfer_packet_sha256))
        budget = transfer.Budget(min(started + 60, outer - 15060))
        admission = metadata(args.sdk_evidence, os.environ)
        observed = transfer.decode(budget.read(args.tool_workspace / 'NATIVE_OBSERVATION.json'))
        transfer.tool_return(args.tool_workspace, budget)
        registry_raw = budget.read(args.proof_tools)
        policy_raw = budget.read(ROOT / 'ANALYSIS_NATIVE_POLICY.json')
        transfer.need(observed['passed'] is True and observed['execution_admitted'] is True and
                      observed['registry_sha256'] == transfer.sha(registry_raw) == args.proof_tools_sha256,
                      'Actual positive reviewed native-input observation/registry required')
        before = transfer.collect_native(budget, admission)
        transfer.need(before == observed['native'] and
                      transfer.registry(args.tool_workspace / 'tools', transfer.decode(policy_raw), before) ==
                      transfer.decode(registry_raw), 'Exact same-job reviewed native policy before experiment required')
        for row in observed['native']['libraries']:
            paths[Path(row['path'])] = row['sha256']
        paths[args.proof_tools] = args.proof_tools_sha256
        paths[ROOT / 'ANALYSIS_NATIVE_POLICY.json'] = transfer.sha(policy_raw)
        for row in transfer.decode(registry_raw)['tools'].values():
            paths[Path(row['path'])] = row['sha256']
        corpus = transfer.decode(registry_raw)['tools']['amber_lsp']
        paths[Path(corpus['api_corpus_path'])] = corpus['api_corpus_sha256']
        transfer.need(time.monotonic() + 15060 <= outer, 'Full15000-second controller plus60-second return required')
        result['controller_started'] = True
        # Production supplies a shared deadline; the consuming controller maps it
        # conservatively into its own unchanged local Runner/Budget clock.
        if invoke is None:
            supplied = transfer.shared_deadline(outer - 60)
            result['supplied_controller_deadline'] = supplied
            result['supplied_controller_clock'] = transfer.SHARED_CLOCK
            code = original.run(args, absolute_deadline=supplied, deadline_clock=transfer.SHARED_CLOCK)
        else:
            # This injected callable executes inside this process and retains the
            # original local-clock fixture contract.
            result['supplied_controller_clock'] = transfer.LOCAL_CLOCK
            code = invoke(args, absolute_deadline=outer - 60)
        transfer.need(type(code) is int and code == 0, 'Complete original experiment success required')
        result['passed'] = True
    except BaseException as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        errors = []
        try:
            budget = transfer.Budget(min(time.monotonic() + 60, outer))
            if admission is not None:
                transfer.need(metadata(args.sdk_evidence, os.environ) == admission,
                              'Exact same-job SDK return around analysis tools required')
            if before is not None:
                transfer.need(transfer.collect_native(budget, admission) == before,
                              'Exact native bytes/aliases/physical identities after experiment required')
            for path, expected in paths.items():
                transfer.need(transfer.sha(budget.read(path)) == expected,
                              'Exact tool/native/source provider return required: ' + str(path))
            transfer.tool_return(args.tool_workspace, budget)
            transfer.clock(outer)
        except BaseException as error:
            errors.append(type(error).__name__ + ': ' + str(error))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic() - started
        result['controller_exit'] = code
        if errors or result['elapsed_seconds'] > 15120:
            result['passed'] = False
        (args.tool_workspace / 'EXPERIMENT_TOOL_RETURN.json').write_bytes(transfer.canonical(result) + b'\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'sdk-evidence', 'output', 'proof-tools', 'tool-workspace'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('packet-sha256', 'python-sha256', 'time-sha256', 'timing-true-sha256', 'proof-tools-sha256', 'transfer-packet-sha256'):
        parser.add_argument('--' + name, required=True)
    raise SystemExit(run(parser.parse_args()))
