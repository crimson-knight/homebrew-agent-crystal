"""Positive finite provider-evidence roster; large selected snapshots stay bounded."""
import argparse
from pathlib import Path, PurePosixPath
import time
from provider_observation import ROOT,MAX_FILE,MAX_TOTAL,MAX_RAW,COMMANDS,need,stable,digest,decode,write,load,protect,admit_observation,public_snapshot,canonical,sha

def stage(args,absolute_deadline=None):
    started=time.monotonic();deadline=started+45
    if absolute_deadline is not None:deadline=min(deadline,absolute_deadline)
    protected=protect(ROOT,'SOURCE_PINS.json',args.packet_sha256,32,deadline)
    rules=load(ROOT/'inputs/public_evidence_rules.py','eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','observed_provider_public_rules',deadline)
    need(args.source.resolve(strict=True)==args.source and args.output.is_absolute() and not args.output.exists() and args.output.parent.resolve(strict=True)==args.output.parent,'Physical owned stage source/fresh output required')
    if not (args.source/'OBSERVATION.json').exists():
        raw=stable(args.source/'ADMISSION_REFUSAL.json',deadline,2**20)[1];value=decode(raw)
        need(value['format']=='atlas-native-buffer-provider-admission-refusal-v1' and value['passed'] is False and value['execution_admitted'] is False,'Exact retained admission refusal required')
        rules.inspect_public_bytes('ADMISSION_REFUSAL.json',raw);args.output.mkdir();(args.output/'ADMISSION_REFUSAL.json').write_bytes(raw)
        result=dict(format='atlas-native-buffer-provider-public-stage-v1',complete_observation=False,execution_admitted=False,files=[dict(path='ADMISSION_REFUSAL.json',bytes=len(raw),sha256=digest(args.output/'ADMISSION_REFUSAL.json',deadline))],actual_target_cells_accepted=0)
        write(args.output/'PUBLIC_STAGE.json',result);return result
    receipt=decode(stable(args.source/'OBSERVATION.json',deadline,MAX_RAW)[1]);names=['OBSERVATION.json']
    generated={}
    need(receipt['format']=='atlas-native-buffer-provider-observation-v1' and type(receipt['passed']) is bool and receipt['execution_admitted'] is False,'Explicit observation-only result required')
    if receipt['passed']:
        admit_observation(args.source,digest(args.source/'OBSERVATION.json',deadline),deadline)
    if receipt.get('writers_confirmed_retired') is True:
        records=receipt['commands'];need(len(records)<=len(COMMANDS),'Finite original metadata command roster')
        for index,record in enumerate(records):
            need(record['label']==COMMANDS[index][0] and record['writers_confirmed_retired'] is True and record['terminal_group_observation']['status']=='absent','Original known returned command stream required')
            for channel in ('stdout','stderr'):
                name=record['label']+'.'+channel+'.txt';need(digest(args.source/name,deadline)==record[channel+'_sha256'],'Exact retained original raw stream required');names.append(name)
        if (args.source/'COMMANDS.json').exists():
            need(decode(stable(args.source/'COMMANDS.json',deadline,MAX_RAW)[1])==records,'Exact persisted command journal required');names.append('COMMANDS.json')
        census=receipt.get('census',receipt.get('partial_census',{}))
        projection=[]
        for row in census.get('snapshots',[]):
            name=row['path'];relative=PurePosixPath(name)
            need(str(relative)==name and name.startswith('provider-bytes/') and relative.suffix=='.bin' and not relative.is_absolute() and '..' not in relative.parts,'Exact positive provider snapshot path required')
            identity,_=stable(args.source/name,deadline)
            need(identity['sha256']==row['sha256'] and identity['bytes']==row['bytes'],'Exact provider snapshot bytes required')
            retained=public_snapshot(row,receipt);projection.append(dict(row,visibility='public-retained' if retained else 'private-fingerprint-only'))
            if retained:names.append(name)
        generated['PUBLIC_PROJECTION.json']=canonical(dict(format='atlas-native-buffer-provider-public-projection-v1',observation_sha256=digest(args.source/'OBSERVATION.json',deadline),private_replay_return_attested=receipt.get('private_snapshot_return_accepted') is True,snapshots=projection))+b'\n';names.append('PUBLIC_PROJECTION.json')
        generated['LLVM_LICENSE.TXT']=stable(ROOT/'inputs/LLVM_LICENSE.TXT',deadline,2**20)[1];names.append('LLVM_LICENSE.TXT')
    need(len(names)==len(set(names))<=640,'Finite unique selected metadata/native roster required')
    payload=[];total=0
    for name in names:
        rules.public_path(name);path=args.source/name
        if name in generated:raw=generated[name];current=dict(bytes=len(raw),sha256=sha(raw))
        else:
            need(all(parent.resolve(strict=True)==parent for parent in [path.parent,args.source]),'Physical source stage parents required');current,raw=stable(path,deadline,MAX_FILE)
        total+=len(raw);need(total<=MAX_TOTAL+16*2**20,'Finite complete provider/metadata public byte ceiling')
        rules.inspect_public_bytes(name,raw);payload.append((name,current,raw))
    for path,expected in protected.items():need(digest(path,deadline)==expected,'Stage source return required')
    args.output.mkdir()
    for name,current,raw in payload:
        clock=time.monotonic();need(clock<=deadline,'Finite public staging deadline required')
        target=args.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);need(digest(target,deadline)==current['sha256'],'Exact public selected byte return required')
    result=dict(format='atlas-native-buffer-provider-public-stage-v1',complete_observation=receipt['passed'],execution_admitted=False,files=[dict(path=n,bytes=i['bytes'],sha256=i['sha256']) for n,i,_ in payload],maximum_seconds=45,elapsed_seconds=time.monotonic()-started,actual_target_cells_accepted=0)
    write(args.output/'PUBLIC_STAGE.json',result);return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--packet-sha256',required=True);stage(p.parse_args())
