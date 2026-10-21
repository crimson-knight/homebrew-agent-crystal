"""Select finite public ordinary-route/bottle evidence after returned-writer checks."""
import argparse
import importlib.util
import json
from pathlib import Path
import tarfile
from route_support import ROOT,need,sha,read,write,stable,source_packet,command_maximum,verify_commands
from build_bottle import bottle_inputs,ROOT_URL

MAIN=('OBSERVATION_RESULT.json','CONSUMER_RESULT.json','PROVIDER_PREPARATION_RESULT.json','REVIEW_HOLD_RESULT.json','DRAFT_PROVIDER_CANDIDATE.json','CATALOG_INITIAL.json','CATALOG_BEFORE.json','CATALOG_AFTER.json','TAP_BEFORE.json','ALIASES_BEFORE.json','ALIASES_AFTER.json','COMMANDS.json','FROZEN_LOCK_RECEIPT.json','FROZEN_DEPENDENCY_RECEIPT.json','REVIEWED_CONSUMER_ADMISSION.json','MINECART_PROVIDER_ROSTER.json','BOTTLE_RESULT.json','BOTTLE_INPUTS.json','BOTTLE_ARCHIVE_ROSTER.json','DRAFT_BOTTLE_PROVIDER.json')
PREP=('NATIVE_CENSUS.json','NATIVE_ROOTS.proposed.json','GIT_ROOTS.proposed.json','NATIVE_MANIFEST.draft.json','GIT_MANIFEST.draft.json','COMPILER_SOURCE_ATTRIBUTION.draft.json','PROFILE_INSPECTION_PATHS.json','PROFILE_INSPECTION.unreviewed.json','COMMANDS.json')

def stage(source,output,packet_sha256):
    source=source.resolve(strict=True);need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical public artifact stage required');source_packet(packet_sha256)
    helper=ROOT/'vendor/public_evidence_rules.py';need(stable(helper)[0]['sha256']=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact public metadata/content policy required')
    spec=importlib.util.spec_from_file_location('ordinary_public_evidence_rules',helper);rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
    results=[read(source/name) for name in ('OBSERVATION_RESULT.json','CONSUMER_RESULT.json','PROVIDER_PREPARATION_RESULT.json','REVIEW_HOLD_RESULT.json','BOTTLE_RESULT.json') if (source/name).is_file()]
    need(results,'At least one original route result required');uncertain=any(r.get('writers_confirmed_retired') is not True for r in results)
    selected={n for n in MAIN if (source/n).exists()}
    if uncertain:selected={n for n in selected if n.endswith('RESULT.json')}
    else:
        if (source/'sdk/READINESS_RESULT.json').exists() and read(source/'sdk/READINESS_RESULT.json').get('passed') is True:
            system=read(source/'sdk/RUNNER.json')['system'];roster=read(ROOT/'inputs/SDK_ARTIFACT_ROSTER.json')['platforms'][system]
            need(all((source/'sdk'/name).is_file() and not (source/'sdk'/name).is_symlink() for name in roster),'Complete successful SDK physical artifact roster required')
        for folder in ('','consumer-command-output','review-command-output','provider-preparation'):
            journal=source/folder/'COMMANDS.json'
            if not journal.is_file():continue
            rows=read(journal);need(len(rows)<=96,'Finite raw command roster required');selected.add((Path(folder)/'COMMANDS.json').as_posix())
            result_name={'':'OBSERVATION_RESULT.json' if (source/'OBSERVATION_RESULT.json').exists() else 'BOTTLE_RESULT.json','consumer-command-output':'CONSUMER_RESULT.json','review-command-output':'REVIEW_HOLD_RESULT.json','provider-preparation':'PROVIDER_PREPARATION_RESULT.json'}[folder]
            result=read(source/result_name);observations=result.get('original_group_observations',result.get('original_groups'))
            verify_commands(rows,observations,successful=result.get('observation_complete',result.get('passed',result.get('metadata_complete',False))) is True)
            for row in rows:
                command_maximum(row['label'])
                for stream in ('stdout','stderr'):
                    name=(Path(folder)/(row['label']+'.'+stream+'.txt')).as_posix();need(stable(source/name)[0]['sha256']==row[stream+'_sha256'],'Exact original command/raw stream hash join required');selected.add(name)
        selected.update('sdk/'+n for n in read(ROOT/'inputs/SDK_ARTIFACT_ROSTER.json')['files'] if (source/'sdk'/n).exists())
        selected.update('provider-preparation/'+n for n in PREP if (source/'provider-preparation'/n).exists())
        selected.update('resolved-catalog/'+n for n in ('formula.jws.json','formula.json') if (source/'resolved-catalog'/n).exists())
        selected.update('admitted-inputs/'+n for n in ('profile.json','native.json','git.json') if (source/'admitted-inputs'/n).exists())
        selected.update(n for n in ('public-install.sh','public-SDK-main.tar.gz','minecart-provider.tar.gz') if (source/n).exists())
        if (source/'BOTTLE_INPUTS.json').exists():
            bottle=bottle_inputs(source,ROOT_URL);selected.add(Path(bottle['archive']['path']).name);selected.add(Path(bottle['json']['path']).name)
    need(len(selected)<=400,'Finite complete positive evidence file roster required')
    payload={};total=0
    for name in sorted(selected):
        rules.public_path(name)
        path=source/name;need(all(not p.is_symlink() for p in [path,*list(path.parents)[:len(Path(name).parts)-1]]),'Ordinary contained artifact members required')
        row,raw=stable(path,128*2**20)
        expected=None
        if name=='sdk/sdk-source.tar.gz':expected='3a6d9c982ece74ef3b72eea0e2569bbfe31cd1767b3c4c7e8723d8f5f6d4b9bf'
        if name=='public-SDK-main.tar.gz':expected='bc00034341a83eb483c21b55d119e006c814fe23c54e1111ff42c525fcef35f6'
        if name.endswith('.tar.gz'):
            if expected:need(row['sha256']==expected,'Exact public source archive required')
            with tarfile.open(path,'r:gz') as archive:
                expanded=0
                for index,member in enumerate(archive):
                    rules.public_path(member.name.rstrip('/'));need(index<4096 and (member.isfile() or member.isdir() or member.issym()),'Finite ordinary public archive kinds required')
                    expanded+=member.size;need(member.size<=128*2**20 and expanded<=256*2**20,'Finite complete public archive bytes required')
                    if member.isfile():rules.inspect_public_bytes(member.name,archive.extractfile(member).read(128*2**20+1))
        else:rules.inspect_public_bytes(name,raw)
        total+=len(raw);need(total<=192*2**20,'Finite192-MiB complete public artifact bound required');payload[name]=raw
    for name in ['SOURCE_PINS.json']+[r['path'] for r in read(ROOT/'SOURCE_PINS.json')['files']]:
        raw=stable(ROOT/name)[1];rules.inspect_public_bytes('source/'+name,raw);payload['source/'+name]=raw
        total+=len(raw);need(total<=192*2**20,'Finite192-MiB complete source/evidence bound required')
    output.mkdir();rows=[]
    for name,raw in payload.items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);rows.append({'path':name,'bytes':len(raw),'sha256':sha(raw)})
    receipt={'format':'ordinary-public-route-positive-artifact-v105','files':rows,'file_count':len(rows),'unqualified_writer_scope':uncertain,'execution_admitted':False,'public_release_publication_admitted':False}
    write(output/'PUBLIC_STAGE.json',receipt);return receipt

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet-sha256',required=True);a=p.parse_args();stage(a.source,a.output,a.packet_sha256)
