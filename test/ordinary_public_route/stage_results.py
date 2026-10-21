"""Select finite public ordinary-route/bottle evidence after returned-writer checks."""
import argparse
import importlib.util
import json
from pathlib import Path
import tarfile
import hashlib
import time
import bottle_source_screen as source_screen
from route_support import ROOT,need,sha,read,write,stable,source_packet,command_maximum,verify_commands
from build_bottle import bottle_inputs,ROOT_URL

MAIN=('HOMEBREW_INVOCATION.json','TAP_WORKTREE_installed.json','TAP_WORKTREE_returned.json','TAP_WORKTREE_before-bottle.json','TAP_WORKTREE_after-bottle.json','OBSERVATION_RESULT.json','CONSUMER_RESULT.json','PROVIDER_PREPARATION_RESULT.json','REVIEW_HOLD_RESULT.json','DRAFT_PROVIDER_CANDIDATE.json','CATALOG_INITIAL.json','CATALOG_BEFORE.json','CATALOG_AFTER.json','TAP_BEFORE.json','ALIASES_BEFORE.json','ALIASES_AFTER.json','COMMANDS.json','FROZEN_LOCK_RECEIPT.json','FROZEN_DEPENDENCY_RECEIPT.json','REVIEWED_CONSUMER_ADMISSION.json','MINECART_PROVIDER_ROSTER.json','BOTTLE_RESULT.json','BOTTLE_INPUTS.json','BOTTLE_ARCHIVE_ROSTER.json','DRAFT_BOTTLE_PROVIDER.json')
PREP=('NATIVE_CENSUS.json','NATIVE_ROOTS.proposed.json','GIT_ROOTS.proposed.json','NATIVE_MANIFEST.draft.json','GIT_MANIFEST.draft.json','COMPILER_SOURCE_ATTRIBUTION.draft.json','PROFILE_INSPECTION_PATHS.json','PROFILE_INSPECTION.unreviewed.json','COMMANDS.json')

def select_evidence(source):
    bottle=None
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
            bottle=bottle_inputs(source,ROOT_URL);need(read(source/'BOTTLE_INPUTS.json')==bottle,'Exact retained ordinary bottle source/input metadata required');selected.add(Path(bottle['archive']['path']).name);selected.add(Path(bottle['json']['path']).name)
    return selected,uncertain,bottle


def load_rules():
    helper=ROOT/'vendor/public_evidence_rules.py';need(stable(helper)[0]['sha256']=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Exact unchanged public credential rules required')
    spec=importlib.util.spec_from_file_location('ordinary_public_evidence_rules',helper);rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
    need(stable(helper)[0]['sha256']=='eacac63dddddb829c9f4dad67c948b0b4a6386e0365ac910c801a5b6f58312ed','Original credential source return required');return rules


def context_diagnostics(paths,category,classification,rules):
    """Retain bounded input identities while keeping rejected contents private."""
    need(len(paths)<=12,'Finite source/provenance diagnostic input roster required')
    result=[]
    for name,path in paths:
        item={'archive_path':None,'member_path':source_screen.safe_path(name,rules),'member_path_sha256':sha(name.encode()),'bytes':None,'sha256':None,'pattern_categories':[category],'origin_classification':classification,'matching_contents_included':False}
        try:
            need(path.is_file() and not path.is_symlink(),'Regular diagnostic input required')
            row,_=stable(path,8*2**20);item.update(bytes=row['bytes'],sha256=row['sha256'])
        except (OSError,ValueError,RuntimeError):item['identity_unavailable']=True
        result.append(item)
    return result


def inspect_payload(name,path,raw,rules,bottle,authority,recognized,metadata_rosters=None):
    rules.public_path(name)
    if name.endswith('.tar.gz'):
        expected={'sdk/sdk-source.tar.gz':'3a6d9c982ece74ef3b72eea0e2569bbfe31cd1767b3c4c7e8723d8f5f6d4b9bf','public-SDK-main.tar.gz':'bc00034341a83eb483c21b55d119e006c814fe23c54e1111ff42c525fcef35f6'}.get(name)
        if expected:need(sha(raw)==expected,'Exact public source archive required')
        verified=bool(bottle and name==Path(bottle['archive']['path']).name and sha(raw)==bottle['archive']['sha256'])
        expanded_stream,metadata=source_screen.archive_metadata(name,raw,rules)
        if metadata_rosters is not None:metadata_rosters.append(metadata)
        with expanded_stream,tarfile.open(fileobj=expanded_stream,mode='r:') as archive:
            expanded=0
            for index,member in enumerate(archive):
                member_name=member.name.rstrip('/')
                try:
                    rules.public_path(member_name);need(index<4096 and (member.isfile() or member.isdir() or member.issym()),'Finite ordinary public archive kinds required');expanded+=member.size;need(member.size<=128*2**20 and expanded<=256*2**20,'Finite complete public archive bytes required')
                    if member.isfile():
                        value=archive.extractfile(member).read(128*2**20+1);need(len(value)==member.size,'Complete original archive member required')
                        accepted=source_screen.inspect_member(name,member_name,value,rules,bottle,authority,verified)
                        if accepted:recognized.append(accepted)
                except (ValueError,RuntimeError) as error:
                    if not hasattr(error,'public_diagnostic'):error.public_diagnostic=source_screen.diagnostic(name,member_name,b'',[],rules)
                    raise
    else:
        matched=source_screen.categories(raw,rules)
        try:rules.inspect_public_bytes(name,raw)
        except ValueError as error:
            error.public_diagnostic=source_screen.diagnostic(None,name,raw,matched,rules);raise


def verify_projection(source,packet_sha256,complete=False):
    source_packet(packet_sha256);rules=load_rules();receipt=read(source/'PUBLIC_STAGE.json')
    try:authority=source_screen.provenance(ROOT)
    except (RuntimeError,ValueError):
        need(receipt.get('screening_complete') is False,'Complete artifact requires exact public source provenance');authority=None
    need(receipt.get('format')=='ordinary-public-route-screened-projection-v109' and receipt.get('clean_projection_verified') is True and receipt.get('source_manifest_sha256')==packet_sha256,'Exact complete clean artifact projection required')
    rows=receipt['files'];need(1<=len(rows)<=512 and len({r['path'] for r in rows})==len(rows),'Finite unique clean projection roster required')
    actual=[]
    for path in source.rglob('*'):
        need(not path.is_symlink(),'Clean projection aliases require separate scope')
        if path.is_file():actual.append(path.relative_to(source).as_posix())
    need(set(actual)=={r['path'] for r in rows}|{'PUBLIC_STAGE.json'},'Exact physical clean projection roster required')
    bottle=None
    if (source/'BOTTLE_INPUTS.json').exists():
        try:
            from build_bottle import portable_bottle_identity
            bottle=bottle_inputs(source,ROOT_URL);need(portable_bottle_identity(read(source/'BOTTLE_INPUTS.json'))==portable_bottle_identity(bottle),'Exact relocated original bottle identities required')
        except (RuntimeError,ValueError,FileNotFoundError):
            need(receipt['screening_complete'] is False,'Complete artifact requires complete ordinary bottle identity');bottle=None
    total=0;recognized=[]
    for row in rows:
        rules.public_path(row['path']);current,raw=stable(source/row['path'],128*2**20);need(current['bytes']==row['bytes'] and current['sha256']==row['sha256'],'Exact screened projection bytes required');total+=len(raw);need(total<=192*2**20,'Finite complete clean projection required')
        if row['path'].startswith('source/'):rules.inspect_public_bytes(row['path'],raw)
        else:inspect_payload(row['path'],source/row['path'],raw,rules,bottle,authority,recognized)
    rules.inspect_public_bytes('PUBLIC_STAGE.json',stable(source/'PUBLIC_STAGE.json')[1])
    if complete:need(receipt['screening_complete'] is True and receipt['refusal_count']==0,'Complete credential-screened artifact required before publication acceptance')
    return receipt


def stage(source,output,packet_sha256,retain_clean_refusals=False):
    source=source.resolve(strict=True);need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical public artifact stage required');protected=source_packet(packet_sha256);rules=load_rules();authority=None
    payload={};failures=[];recognized=[];metadata_rosters=[];first_error=None;total=0;observed_input_bytes=0;uncertain=True;bottle=None
    try:authority=source_screen.provenance(ROOT)
    except Exception as error:
        first_error=error;failures.extend(context_diagnostics([('source/'+n,ROOT/n) for n in ('inputs/PUBLIC_COMPILER_SOURCE_CLASSIFICATION.json','bottle_vendor/Formula/agent-crystal.rb','bottle_vendor/test/sdk_source_lock.json','inputs/ALPHA_MAIN.json')],'public-source-provenance-admission','unadmitted-public-source-context',rules))
    try:selected,uncertain,bottle=select_evidence(source)
    except Exception as error:
        first_error=first_error or error;selected={n for n in MAIN if n.endswith('RESULT.json') and (source/n).exists()};contexts=[(n,source/n) for n in ('BOTTLE_INPUTS.json','COMMANDS.json') if (source/n).exists()]
        for index,path in enumerate(source.glob('*.bottle.json')):
            need(index<8,'Finite original bottle JSON diagnostic roster required');contexts.append((path.name,path))
        failures.extend(context_diagnostics(contexts or [(n,source/n) for n in sorted(selected)],'source-command-or-bottle-provenance-admission','unadmitted-input-context',rules))
    need(len(selected)<=400,'Finite complete positive evidence file roster required')
    candidates=[(name,source/name) for name in sorted(selected)]+[('source/'+name,ROOT/name) for name in ['SOURCE_PINS.json']+[r['path'] for r in read(ROOT/'SOURCE_PINS.json')['files']]]
    for name,path in candidates:
        try:
            rules.public_path(name);need(all(not p.is_symlink() for p in [path,*list(path.parents)[:len(Path(name).parts)-1]]),'Ordinary contained artifact members required');incoming=path.lstat().st_size;need(0<=incoming<=128*2**20 and observed_input_bytes+incoming<=192*2**20,'Finite aggregate staging input capacity required before reading');observed_input_bytes+=incoming;row,raw=stable(path,128*2**20)
            # Static source archives retain the unchanged source-packet screen;
            # selected runtime archives receive complete member screening.
            if name.startswith('source/'):
                try:rules.inspect_public_bytes(name,raw)
                except ValueError as error:error.public_diagnostic=source_screen.diagnostic(None,name,raw,source_screen.categories(raw,rules),rules);raise
            else:inspect_payload(name,path,raw,rules,bottle,authority,recognized,metadata_rosters)
            total+=len(raw);need(total<=192*2**20,'Finite192-MiB complete source/evidence bound required');payload[name]=raw
        except Exception as error:
            if first_error is None:first_error=error
            failures.append(getattr(error,'public_diagnostic',{'archive_path':None,'member_path':source_screen.safe_path(name,rules),'member_path_sha256':sha(name.encode()),'bytes':None,'sha256':None,'pattern_categories':['input-path-size-or-archive-admission'],'origin_classification':'unadmitted-input','matching_contents_included':False,'error_type':type(error).__name__}))
            need(len(failures)<=512,'Finite safe refusal metadata roster required')
    diagnostics={'format':'ordinary-publication-safe-diagnostics-v109','recognized_public_source_members':recognized,'archive_metadata_checks':metadata_rosters,'refusals':failures,'actual_v107_first_refused_member_identified':False,'matching_contents_included':False,'private_original_inputs_modified':False}
    diagnostics_raw=(json.dumps(diagnostics,indent=2,sort_keys=True)+'\n').encode();rules.inspect_public_bytes('STAGING_DIAGNOSTICS.json',diagnostics_raw);payload['STAGING_DIAGNOSTICS.json']=diagnostics_raw
    if first_error is not None and not retain_clean_refusals:raise first_error
    output.mkdir();rows=[]
    for name,raw in payload.items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);need(stable(target)[0]['sha256']==sha(raw),'Exact clean projection copy required');rows.append({'path':name,'bytes':len(raw),'sha256':sha(raw)})
    receipt={'format':'ordinary-public-route-screened-projection-v109','files':rows,'file_count':len(rows),'unqualified_writer_scope':uncertain,'execution_admitted':False,'public_release_publication_admitted':False,'source_manifest_sha256':packet_sha256,'clean_projection_verified':True,'screening_complete':not failures,'refusal_count':len(failures),'recognized_public_source_count':len(recognized),'original_private_inputs_retained_in_owned_workspace':True,'actual_v107_first_refused_member_identified':False}
    write(output/'PUBLIC_STAGE.json',receipt)
    from route_support import revalidate
    revalidate(protected);verify_projection(output,packet_sha256)
    if first_error is not None:raise first_error
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--packet-sha256',required=True);p.add_argument('--retain-clean-refusals',action='store_true');p.add_argument('--require-complete',action='store_true');a=p.parse_args()
    if a.require_complete:verify_projection(a.source,a.packet_sha256,complete=True)
    else:
        need(a.output is not None,'Fresh projection output required')
        need(not a.output.exists() and not a.output.is_symlink(),'Fresh current-attempt projection required before retained-refusal handling')
        try:stage(a.source,a.output,a.packet_sha256,retain_clean_refusals=a.retain_clean_refusals)
        except Exception:
            if not a.retain_clean_refusals:raise
            verify_projection(a.output,a.packet_sha256)
