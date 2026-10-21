"""Stage a fixed source-feedback evidence roster after original writers return."""
import argparse
import importlib.util
import json
from pathlib import Path
import time
from run_source_feedback import ROOT,MAX_RAW,need,stable,digest,manifest,revalidate,write,load


def stage(args):
    started=time.monotonic();protected=manifest(ROOT,'SOURCE_PINS.json',args.packet_sha256,128)
    need(args.source.resolve(strict=True)==args.source and args.source.is_dir() and not args.output.exists() and args.output.parent.resolve(strict=True)==args.output.parent,'Physical source and fresh owned stage required')
    rules=load(ROOT/'probe/vendor/public_evidence_rules.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','feedback_public_rules')
    selected={};result_path=args.source/'RESULT.json'
    result=json.loads(stable(result_path)) if result_path.exists() else None
    for name in ('RESULT.json','ADMISSION_REFUSAL.json','SOURCE_GATES.json'):
        p=args.source/name
        if p.exists():selected[name]=stable(p,MAX_RAW)
    if result is not None and result.get('writers_confirmed_retired') is not True:selected.pop('SOURCE_GATES.json',None)
    if result is not None and result.get('writers_confirmed_retired') is True:
        gates=json.loads(stable(args.source/'SOURCE_GATES.json'))
        if result['passed'] is True:
            probe=load(ROOT/'probe/run_probe.py',digest(ROOT/'probe/run_probe.py'),'feedback_stage_consumer')
            probe.source_gates(args.source/'SOURCE_GATES.json',digest(args.source/'SOURCE_GATES.json'),{'compiler_profile_sha256':result['compiler_profile_sha256']},result['job_identity'])
            need(gates['controller_result_sha256']==digest(result_path) and result['source_provider_return_accepted'] is True and not result['finalization_errors'],'Complete source-feedback provider/result return required')
        for row in gates['raw_evidence']:
            raw=stable(args.source/row['path'],MAX_RAW);need(len(raw)==row['bytes'] and digest(args.source/row['path'])==row['sha256'],'Exact positive source-feedback raw roster required');selected[row['path']]=raw
    selected['source/SOURCE_PINS.json']=stable(ROOT/'SOURCE_PINS.json')
    for row in json.loads(selected['source/SOURCE_PINS.json'])['files']:selected['source/'+row['path']]=stable(ROOT/row['path'])
    need(sum(len(v) for v in selected.values())<=64*2**20,'Finite64-MiB source-feedback stage required')
    for name,raw in selected.items():rules.public_path(name);rules.inspect_public_bytes(name,raw);need(time.monotonic()-started<=30,'Finite30-second source-feedback stage required')
    args.output.mkdir();rows=[]
    for name,raw in selected.items():p=args.output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);rows.append({'path':name,'bytes':len(raw),'sha256':digest(p)})
    revalidate(protected);need(time.monotonic()-started<=30,'Complete source-feedback stage return deadline required')
    write(args.output/'PUBLIC_STAGE.json',{'format':'atlas-native-buffer-source-feedback-public-stage-v1','files':rows,'complete_source_feedback_accepted':bool(result and result['passed']),'private_projection_uploaded':False,'actual_target_cells_accepted':0})

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--packet-sha256',required=True);stage(p.parse_args())
