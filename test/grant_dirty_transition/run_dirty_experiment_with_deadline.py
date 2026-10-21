"""Compose same-job calibration, proof and four complete arms inside15000 seconds."""
import argparse
import math
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from same_job_policy import digest, metadata, need, protect_packet
from stage_grant_sources import stage
from prepare_dirty_plan import prepare, ARMS, TOTAL_SECONDS, SETUP_SECONDS, PROOF_SECONDS, MEASUREMENT_SECONDS, CONTROLLER_RETURN_SECONDS
from run_hosted_contrast import save
from run_dirty_contrast import qualify
from run_serial import complete_return as arm_return
from timing_profile import calibrate, complete_return as calibration_return, canonical_sha
import dirty_proof
import os


def reserve(deadline, seconds, phase):
    need(deadline-time.monotonic() >= seconds,'Complete '+str(seconds)+'-second reservation required before '+phase)


def run(args, absolute_deadline=None, deadline_clock='process-local.time.monotonic'):
    started = time.monotonic()
    supplied_deadline = absolute_deadline
    outer = started + TOTAL_SECONDS
    if absolute_deadline is not None:
        need(type(absolute_deadline) in (int, float) and math.isfinite(absolute_deadline),
             "Finite supplied absolute dirty-controller deadline required")
        from proof_tool_transfer import SHARED_CLOCK, LOCAL_CLOCK, local_deadline
        need(deadline_clock in (SHARED_CLOCK, LOCAL_CLOCK), 'Explicit supported dirty-controller clock protocol required')
        if deadline_clock == SHARED_CLOCK:
            absolute_deadline = local_deadline(absolute_deadline)
        outer = min(outer, absolute_deadline)
    need(outer-started >= TOTAL_SECONDS, "Complete15000-second actual-entry controller reservation required")
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), 'Fresh absolute owned dirty-experiment output required')
    args.output.mkdir(parents=True)
    result = dict(format='atlas-grant-fixed-carrier-dirty-experiment-v1',mission='memory-budget-experiment',passed=False,
                  diagnostic_complete=False,maximum_seconds=TOTAL_SECONDS,absolute_deadline=outer,
                  supplied_deadline_clock=deadline_clock,supplied_absolute_deadline=supplied_deadline,
                  ordered_arms=list(ARMS),models=2,repetition=1,proof_launch_admitted=False,measurement_launch_admitted=False,
                  same_job_sdk_phase=dict(owner='Separate preceding workflow step',maximum_seconds=840,workflow_minutes=15,
                                          inside_controller_horizon=False,complete_fresh_same_job_receipt_required=True),
                  phase_reservations=dict(setup=600,proof=6600,measurement=7200,controller_return=600),
                  original_build_seconds=900,original_runtime_seconds=120,original_arm_seconds=1500,
                  allocation_improvement_accepted=False,memory_savings_accepted=False,shipping_compatibility_accepted=False,
                  whole_build_provider_qualified=False,native_loader_closure_qualified=False,
                  required_target_cells=144,actual_target_cells_accepted=0)
    protected,admission,calibration,proof,observation = {},None,None,None,None
    calibration_output = args.output/'timing-calibration'
    child_output = args.output/'results/four-arm2'
    save(args.output/'DIRTY_EXPERIMENT_RESULT.json',result)
    try:
        protected = protect_packet(args.packet_sha256)
        providers = {'python':Path(sys.executable).resolve(),'time':Path('/usr/bin/time'),'timing_true':Path('/usr/bin/true')}
        result['providers'] = {}
        for name,path in providers.items():
            expected = getattr(args,name+'_sha256')
            need(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected) and digest(path) == expected,
                 'Exact supplied and observed provider required before source/probe work: '+name)
            protected[path] = expected
            result['providers'][name] = dict(path=str(path),before_sha256=expected)
        admission = metadata(args.sdk_evidence,os.environ)
        result['admitted_same_job'] = admission
        for path in args.sdk_evidence.rglob('*'):
            if path.is_file():
                protected[path] = digest(path)
        for row in admission['providers'].values():
            path = Path(row['path'])
            need(digest(path) == row['sha256'],'Exact same-job provider bytes required before hosted proof')
            protected[path] = row['sha256']
        # Exact reviewed tool bytes are admitted before a native proof or measured arm.
        result['proof_tools'] = dirty_proof.admit_tools(args.proof_tools,args.proof_tools_sha256)
        protected[args.proof_tools] = args.proof_tools_sha256
        for row in result['proof_tools']['tools'].values():
            protected[Path(row['path'])] = row['sha256']
        tool = result['proof_tools']['tools'].get('amber_lsp')
        if tool is not None:
            protected[Path(tool['api_corpus_path'])] = tool['api_corpus_sha256']
        callback_project = getattr(args,'callback_project',None)
        if callback_project is None:
            source = args.output/'private-source'
            result['source_projection'] = stage(ROOT/'inputs/grant-source-and-frozen-dependencies.tar.gz',source)
            grant = source/'grant'
        else:
            from vendor.verify_compile_acceptance import source_input_inventory
            grant = callback_project
            need(grant.is_absolute() and grant.resolve(strict=True) == grant and
                 source_input_inventory(grant)[1] == dirty_proof.hook_callback.ORIGINAL_SOURCE_SHA256,
                 'Exact preprojected callback source required')
            result['source_projection'] = dict(project=str(grant),source_tree_sha256=dirty_proof.hook_callback.ORIGINAL_SOURCE_SHA256,
                owner='Separately bounded real callback prerequisite; exact immutable inner archive projection')
        wrapper = Path(admission['providers']['compiler_wrapper']['path'])
        plan = args.output/'four-arm-plan'
        prepare(plan,grant,wrapper)
        calibration = calibrate(calibration_output,args.driver,args.time_sha256,args.timing_true_sha256,
                                admission['job_identity'],min(outer,started+SETUP_SECONDS))
        result['timing_calibration'] = calibration
        calibration_return(calibration,calibration_output)
        profile = calibration['profile']
        result['timing_profile_sha256'] = canonical_sha(profile)
        for name in ('CALIBRATION_RESULT.json','TIMING_PROFILE.json','COMMANDS.json','probe.stdout.txt','probe.stderr.txt'):
            protected[calibration_output/name] = digest(calibration_output/name)
        need(time.monotonic()-started <= SETUP_SECONDS,'Complete source/provider/calibration setup inside600 seconds required')
        reserve(outer,PROOF_SECONDS+MEASUREMENT_SECONDS+CONTROLLER_RETURN_SECONDS,'hosted API/behavior proof')
        result['proof_launch_admitted'] = True
        save(args.output/'DIRTY_EXPERIMENT_RESULT.json',result)
        proof = dirty_proof.run(args.output/'proof',grant,wrapper,args.driver,args.proof_tools,args.proof_tools_sha256,args.sdk_evidence,
                                outer-MEASUREMENT_SECONDS-CONTROLLER_RETURN_SECONDS,
                                callback_path=getattr(args,'callback_receipt',None),callback_sha256=getattr(args,'callback_receipt_sha256',None))
        dirty_proof.complete_return(proof,args.output/'proof')
        result['proof_result_sha256'] = digest(args.output/'proof/PROOF_RESULT.json')
        reserve(outer,MEASUREMENT_SECONDS+CONTROLLER_RETURN_SECONDS,'four complete measured arms')
        result['measurement_launch_admitted'] = True
        save(args.output/'DIRTY_EXPERIMENT_RESULT.json',result)
        settings = SimpleNamespace(driver=args.driver,plan=plan/'DIRTY_PLAN.json',sdk_evidence=args.sdk_evidence,
            output=child_output,source_sha256=digest(ROOT/'run_dirty_contrast.py'),plan_sha256=digest(plan/'DIRTY_PLAN.json'),
            python_sha256=args.python_sha256,time_sha256=args.time_sha256,timing_true_sha256=args.timing_true_sha256,
            packet_sha256=args.packet_sha256,models=2,repetition=1)
        code = qualify(settings,absolute_deadline=outer-CONTROLLER_RETURN_SECONDS,timing_profile=profile)
        observation = json.loads((child_output/'COMPARISON_RESULT.json').read_bytes())
        arm_return(observation)
        need(code == 0 and observation['diagnostic_complete'] is True and observation.get('owner_shape_accepted') is True and
             [row['arm'] for row in observation['samples']] == list(ARMS),'Complete four-arm owner/functional/corruption proof required')
        need(all(row['source_overlay']['restored'] is True for row in observation['samples']),'Complete exact multi-file source return required')
        result['diagnostic_complete'] = result['passed'] = True
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__,error)
        result['error_context'] = []
        previous = error.__context__
        while previous is not None and len(result['error_context']) < 8:
            result['error_context'].append('%s: %s' % (type(previous).__name__,previous))
            previous = previous.__context__
    finally:
        errors = []
        for filename,key in [(args.output/'proof/PROOF_RESULT.json','proof'),(child_output/'COMPARISON_RESULT.json','arms')]:
            if filename.is_file():
                try:
                    retained = json.loads(filename.read_bytes())
                    if key == 'proof':
                        proof = retained
                        dirty_proof.complete_return(retained,args.output/'proof')
                    else:
                        observation = retained
                        arm_return(retained)
                    result[key+'_result_sha256'] = digest(filename)
                except Exception as error:
                    errors.append('%s: %s' % (type(error).__name__,error))
        for label,check in [('calibration',lambda: calibration_return(calibration,calibration_output)),
                            ('same-job SDK',lambda: need(metadata(args.sdk_evidence,os.environ) == admission,'Exact same-job SDK return required'))]:
            if (calibration is not None if label == 'calibration' else admission is not None):
                try:
                    check()
                except Exception as error:
                    errors.append('%s: %s' % (type(error).__name__,error))
        for path,expected in protected.items():
            try:
                need(digest(path) == expected,'Exact protected source/provider return required: '+str(path))
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__,error))
        for name,row in result.get('providers',{}).items():
            try:
                row['after_sha256'] = digest(Path(row['path']))
                need(row['before_sha256'] == row['after_sha256'],'Exact final controller provider required')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__,error))
        result['finalization_errors'] = errors
        result['elapsed_seconds'] = time.monotonic()-started
        if errors or result['elapsed_seconds'] > TOTAL_SECONDS:
            result['passed'] = result['diagnostic_complete'] = False
        save(args.output/'DIRTY_EXPERIMENT_RESULT.json',result)
    return 0 if result['passed'] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('driver','sdk-evidence','output','proof-tools'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('packet-sha256','python-sha256','time-sha256','timing-true-sha256','proof-tools-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--callback-project',type=Path)
    parser.add_argument('--callback-receipt',type=Path)
    parser.add_argument('--callback-receipt-sha256')
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
