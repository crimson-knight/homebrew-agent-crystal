"""One120-second positive stage for observation, reviewed policies and returned proofs."""
from pathlib import Path
from types import SimpleNamespace
import sys
import time
from provider_observation import ROOT,need,stable,digest,write,decode,load,protect
from stage_observation import stage as stage_observation

def stage(args,coupling):
    started=time.monotonic();deadline=started+120
    protected=protect(ROOT,'SOURCE_PINS.json',args.packet_sha256,32,deadline)
    need(not args.output.exists() and args.output.parent.resolve(strict=True)==args.output.parent,'Fresh physical combined public stage required');args.output.mkdir()
    status={}
    if args.source.exists():status['observation']=stage_observation(SimpleNamespace(source=args.source,output=args.output/'observation',packet_sha256=args.packet_sha256),min(deadline,started+45))
    rules=load(ROOT/'inputs/public_evidence_rules.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','combined_provider_public_rules',deadline)
    if args.policies is not None and args.policies.exists():
        target=args.output/'policies';target.mkdir();names=('POLICY_RESULT.json','DECISION.json','CURRENT_SDK_JOIN.json','NATIVE_POLICY.json','TOOL_POLICY.json','PROOF_TOOLS.json','ADMISSION_REFUSAL.json');status['policies']=[]
        for name in names:
            path=args.policies/name
            if path.exists():
                _,raw=stable(path,deadline,8*2**20);rules.inspect_public_bytes(name,raw);(target/name).write_bytes(raw);status['policies'].append(dict(path=name,sha256=digest(target/name,deadline),bytes=len(raw)))
    if args.feedback_result is not None and args.feedback_result.exists():
        need(deadline-time.monotonic()>=60,'Full source/native stage reservations required')
        sys.path.insert(0,str(args.feedback_packet));source=args.feedback_packet/'stage_source_feedback.py';module=load(source,digest(source,deadline),'coupled_feedback_stager',deadline)
        module.stage(SimpleNamespace(source=args.feedback_result,output=args.output/'feedback',packet_sha256=coupling['feedback']));need(time.monotonic()<=deadline-30,'Source stage must return before native stage reservation');status['feedback']='retained'
    if args.probe_result is not None and args.probe_result.exists():
        need(deadline-time.monotonic()>=30,'Full original native stage reservation required');sys.path.insert(0,str(args.probe_packet));source=args.probe_packet/'stage_probe.py';module=load(source,digest(source,deadline),'coupled_native_stager',deadline)
        module.stage(args.probe_result,args.output/'probe',coupling['native']);status['probe']='retained'
    for path,expected in protected.items():need(digest(path,deadline)==expected,'Combined stage source return required')
    need(time.monotonic()<=deadline,'Complete combined staging120-second horizon required');write(args.output/'BUNDLE_STAGE.json',dict(format='atlas-native-buffer-composed-public-stage-v1',status=status,elapsed_seconds=time.monotonic()-started,maximum_seconds=120,actual_target_cells_accepted=0));return status
