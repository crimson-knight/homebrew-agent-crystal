"""Manifest-first repository-cwd entrypoint for observation and admitted resume."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import stat
import sys
import time

ROOT=Path(__file__).resolve().parent
def need(v,m):
    if not v:raise RuntimeError(m)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def protect(root,name,expected,maximum):
    p=root/name;need(not p.is_symlink() and sha(p)==expected,'Exact external manifest before imports required');rows=json.loads(p.read_bytes())['files'];need(0<len(rows)<=maximum and len({r['path'] for r in rows})==len(rows),'Finite full source roster required')
    for row in rows:
        q=PurePosixPath(row['path']);need(str(q)==row['path'] and not q.is_absolute() and '..' not in q.parts,'Canonical contained source required');current=root/q;need(stat.S_ISREG(current.lstat().st_mode) and current.stat().st_size==row['bytes'] and sha(current)==row['sha256'],'Exact imported source roster member required')
def main(args):
    started=time.monotonic();protect(ROOT,'SOURCE_PINS.json',args.packet_sha256,32)
    coupling=json.loads((ROOT/'inputs/COUPLING.json').read_bytes())
    protect(args.transfer_packet,'SOURCE_PINS.json',coupling['core'],256);protect(args.transfer_packet,'TRANSFER_SOURCE_PINS.json',coupling['transfer'],54)
    protect(args.probe_packet,'SOURCE_PINS.json',coupling['native'],64);protect(args.feedback_packet,'SOURCE_PINS.json',coupling['feedback'],128)
    sys.path.insert(0,str(ROOT));import provider_observation as producer
    if args.operation=='controls':
        for directory,name in ((ROOT,'test_provider_observation.py'),(ROOT,'test_entrypoints.py'),(args.feedback_packet,'test_source_feedback.py'),(args.probe_packet,'test_probe.py')):
            try:runpy.run_path(str(directory/name),run_name='__main__')
            except SystemExit as error:need(type(error.code) is int and error.code==0,'Complete guarded source controls must pass')
        return 0
    if args.operation in ('observe','materialize'):
        args.probe_packet_sha256=coupling['native'];return producer.main(args,started=started)
    if args.operation=='stage':
        import stage_observation;stage_observation.stage(args);return 0
    if args.operation=='bundle':
        import stage_bundle;stage_bundle.stage(args,coupling);return 0
    if args.operation=='fetch':
        driver_path=args.repository/'test/sdk_install_qualification.py';need(sha(driver_path)==producer.DRIVER_SHA,'Exact original bounded fetch Runner required')
        driver=producer.load(driver_path,producer.DRIVER_SHA,'review_decision_fetch_Runner',started+60);args.output.mkdir()
        runner=driver.Runner(args.output);runner.deadline=started+60
        runner.run('decision',[sys.executable,'-I','-S','-B',ROOT/'fetch_decision.py','--url',args.decision_url,'--sha256',args.decision_sha256,'--output',args.output/'DECISION.json'],cwd=args.repository,environment=dict(os.environ),seconds=45)
        need(runner.writers_confirmed_retired and all(g['status']=='absent' for g in runner.group_observations),'Complete original decision fetch group return required');producer.write(args.output/'FETCH_RETURN.json',dict(commands=runner.records,groups=runner.group_observations,decision_sha256=args.decision_sha256));return 0
    if args.operation=='cleanup':
        result=dict(format='atlas-native-provider-tool-cleanup-guard-v1',complete=False,private_payload_preserved=True)
        try:
            for attempted,path in [(args.feedback_attempted,args.feedback_result),(args.probe_attempted,args.probe_result)]:
                if attempted:
                    observed=json.loads((path/'RESULT.json').read_bytes())
                    need(observed.get('writers_confirmed_retired') is True,'Original consumer writers must return before tool payload cleanup')
            helper=producer.load(args.transfer_packet/'proof_tool_transfer.py',producer.TOOL_HELPER_SHA,'guarded_original_transfer_cleanup',started+30)
            result['original_cleanup']=helper.cleanup(args.tool_workspace)
            need(result['original_cleanup']['complete'] is True,'Original finite tool cleanup must report complete')
            result.update(complete=True,private_payload_preserved=False)
        except BaseException as error:result['error']=type(error).__name__+': '+str(error)
        if args.source is not None and args.source.exists():
            rules=producer.load(ROOT/'inputs/public_evidence_rules.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','cleanup_guard_public_rules',started+30)
            raw=producer.canonical(result)+b'\n';rules.inspect_public_bytes('TRANSFER_CLEANUP.json',raw);(args.source/'TRANSFER_CLEANUP.json').write_bytes(raw)
            bundle=json.loads((args.source/'BUNDLE_STAGE.json').read_bytes());bundle['cleanup']=dict(path='TRANSFER_CLEANUP.json',sha256=sha(args.source/'TRANSFER_CLEANUP.json'),bytes=len(raw));producer.write(args.source/'BUNDLE_STAGE.json',bundle)
        return 0 if result['complete'] else 2
    result=json.loads((args.policies/'POLICY_RESULT.json').read_bytes())
    need(result['passed'] is True and result['execution_admitted'] is True and result['finalization_errors']==[],'Successful fresh same-job policy materialization required')
    need(all(sha(args.policies/n)==h for n,h in result['policies'].items()),'Exact policy/result seals required')
    common=['--repository',str(args.repository),'--sdk-evidence',str(args.sdk_evidence),'--python-sha256',args.python_sha256,'--output',str(args.output)]
    if args.operation=='feedback':
        script=args.feedback_packet/'run_source_feedback.py';argv=common+['--packet-sha256',coupling['feedback'],'--transfer-packet',str(args.transfer_packet),'--tool-workspace',str(args.tool_workspace),'--proof-tools',str(args.policies/'PROOF_TOOLS.json'),'--proof-tools-sha256',result['policies']['PROOF_TOOLS.json'],'--tool-policy',str(args.policies/'TOOL_POLICY.json'),'--tool-policy-sha256',result['policies']['TOOL_POLICY.json']]
    elif args.operation=='probe':
        gates=args.feedback_result/'SOURCE_GATES.json';script=args.probe_packet/'run_probe.py';argv=common+['--packet-sha256',coupling['native'],'--native-policy',str(args.policies/'NATIVE_POLICY.json'),'--native-policy-sha256',result['policies']['NATIVE_POLICY.json'],'--source-gates',str(gates),'--source-gates-sha256',sha(gates)]
    else:raise RuntimeError('Known source-pinned operation required')
    sys.path.insert(0,str(script.parent));sys.argv=[str(script),*argv];runpy.run_path(str(script),run_name='__main__')
    raise RuntimeError('Executable delegate must return its explicit status')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('observe','fetch','materialize','feedback','probe','stage','bundle','cleanup','controls'))
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','probe-packet','feedback-packet','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python'):p.add_argument('--'+name+'-sha256',required=True)
    for name in ('decision','observation','source','policies','feedback-result','probe-result'):p.add_argument('--'+name,type=Path)
    for name in ('decision','observation'):p.add_argument('--'+name+'-sha256')
    p.add_argument('--decision-url');p.add_argument('--feedback-attempted',action='store_true');p.add_argument('--probe-attempted',action='store_true');raise SystemExit(main(p.parse_args()))
