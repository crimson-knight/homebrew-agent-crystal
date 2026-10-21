"""Generate reviewable bottle formula/release inputs from independently accepted bytes."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from route_support import ROOT,need,sha,read,write,stable,source_packet
from build_bottle import bottle_inputs,portable_bottle_identity,ROOT_URL


def finalize(paths,acceptance,expected,output):
    row,raw=stable(acceptance);need(row['sha256']==expected,'Exact independent bottle acceptance digest required')
    accepted=json.loads(raw)
    need(accepted['bottle_artifacts_reviewed'] is True and re.fullmatch('[0-9a-f]{64}',accepted['parent_receipt_sha256']) and re.fullmatch('[0-9a-f]{64}',accepted['peer_receipt_sha256']),'Parent and independent peer returned-source/provider review required')
    need(len(paths)==2,'Both supported platform bottle artifacts are required')
    rows=[];platforms={}
    for path in paths:
        stage=path/'PUBLIC_STAGE.json';need(stable(stage)[0]['sha256'] in accepted['reviewed_artifact_manifest_sha256'],'Exact independently reviewed complete artifact manifest required')
        stage_rows=read(stage)['files'];need(1<=len(stage_rows)<=512 and len({r['path'] for r in stage_rows})==len(stage_rows),'Finite distinct reviewed artifact files required')
        for item in stage_rows:
            relative=PurePosixPath(item['path']);need(str(relative)==item['path'] and not relative.is_absolute() and '..' not in relative.parts,'Contained reviewed artifact member required')
            current,_=stable(path/relative,128*2**20);need(current['bytes']==item['bytes'] and current['sha256']==item['sha256'],'Reviewed artifact member changed after independent acceptance')
        result=read(path/'BOTTLE_RESULT.json');need(result['passed'] is True and result['writers_confirmed_retired'] is True and result['finalization_errors']==[],'Complete original bottle preparation return required')
        row=bottle_inputs(path,ROOT_URL)
        need(row['archive']['sha256'] in accepted['archive_sha256'] and sha((path/'BOTTLE_RESULT.json').read_bytes()) in accepted['result_sha256'],'Exact accepted bottle/archive/result binding required')
        draft=read(path/'DRAFT_BOTTLE_PROVIDER.json');need(portable_bottle_identity(draft['bottle'])==portable_bottle_identity(row),'Full returned source/provider/bottle join required')
        required={'BOTTLE_RESULT.json','BOTTLE_INPUTS.json','BOTTLE_ARCHIVE_ROSTER.json','DRAFT_BOTTLE_PROVIDER.json','sdk/READINESS_RESULT.json','sdk/PROVIDER_IDENTITIES.json','sdk/REVIEWED_COMPILER_PROFILE.json','sdk/STDLIB_BEFORE.json','sdk/STDLIB_AFTER.json','sdk/INSTALLED_FORMULA.rb','sdk/INSTALL_RECEIPT.json',Path(row['archive']['path']).name,Path(row['json']['path']).name}
        need(required<={r['path'] for r in stage_rows},'Complete reviewed recipe/stdlib/provider/bottle inputs required')
        system='Darwin' if row['tag']=='arm64_tahoe' else 'Linux';need(system not in platforms,'Unique actual platform bottle required')
        profile=draft['qualified_build_profile'];need(profile['compiler_sha256']==draft['qualified_build_provider']['compiler_backend']['sha256'],'Actual qualified backend/profile identity required')
        platforms[system]={'qualified_build_profile':profile,'qualified_build_providers':draft['qualified_build_provider'],'bottle':row};rows.append(row)
    need(set(platforms)=={'Darwin','Linux'},'Both exact supported bottle platforms required')
    formula=(ROOT/'vendor/Formula/agent-crystal.rb').read_text();need(formula.count('  revision 2\n')==1 and '  bottle do\n' not in formula,'Exact selected revision2 recipe without a prior bottle required')
    block='\n  bottle do\n    root_url '+json.dumps(ROOT_URL)+'\n'
    for row in sorted(rows,key=lambda r:r['tag']):
        cellar=row['cellar'];need(cellar in ('any','any_skip_relocation','/opt/homebrew/Cellar','/home/linuxbrew/.linuxbrew/Cellar'),'Actual reviewed supported cellar declaration required')
        value=':'+cellar if cellar in ('any','any_skip_relocation') else json.dumps(cellar)
        block+='    sha256 cellar: '+value+', '+row['tag']+': '+json.dumps(row['archive']['sha256'])+'\n'
    block+='  end\n';generated=formula.replace('  revision 2\n','  revision 2\n'+block)
    need(not output.exists() and output.parent.resolve(strict=True)==output.parent,'Fresh generated source proposal directory required');output.mkdir()
    original={};archive=ROOT/'inputs/public-alpha-main.tar.gz';need(stable(archive)[0]['sha256']=='1fc53c2285e208497bf3cb58fb6b36a4ec44eb4ea4a14442766ee9cce7aaccc4','Exact selected complete Alpha source archive required')
    source_rows={r['file']:r for r in read(ROOT/'inputs/ALPHA_FILES.json')['files']}
    with tarfile.open(archive,'r:gz') as stream:
        for member in stream:
            if not member.isfile():continue
            name=member.name.split('/',1)[1];raw=stream.extractfile(member).read()
            need(name in source_rows and sha(raw)==source_rows[name]['sha256'],'Exact complete selected Alpha source row required');original[name]=raw
    need(set(original)==set(source_rows),'All selected Alpha source rows required')
    proposal=dict(original);proposal['Formula/agent-crystal.rb']=generated.encode()
    old_formula=sha(original['Formula/agent-crystal.rb']);new_formula=sha(generated.encode())
    for name,raw in list(proposal.items()):proposal[name]=raw.replace(old_formula.encode(),new_formula.encode())
    old_lock=sha(original['test/sdk_source_lock.json']);new_lock=sha(proposal['test/sdk_source_lock.json'])
    for name,raw in list(proposal.items()):proposal[name]=raw.replace(old_lock.encode(),new_lock.encode())
    for _ in range(4):
        changed=False
        for name in proposal:
            if name.startswith('.github/'):continue
            before=sha(original[name]);after=sha(proposal[name])
            if before!=after:
                for target,raw in list(proposal.items()):
                    replaced=raw.replace(before.encode(),after.encode());changed=changed or replaced!=raw;proposal[target]=replaced
        if not changed:break
    for name,raw in proposal.items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o755 if source_rows[name]['mode']=='100755' else 0o644)
    lock=read(output/'test/sdk_source_lock.json')
    write(output/'COUPLED_SOURCE_PROPOSAL.json',{'source_files':[{'path':name,'bytes':len(raw),'sha256':sha(raw),'unchanged':raw==original[name]} for name,raw in sorted(proposal.items())],
        'formula_source_version_unchanged':True,'changed_files':[name for name in proposal if proposal[name]!=original[name]],
        'pending':['Independent new formula/lock/CPU/workflow pin review and source tests','Parent public merge and all-file readback','Fresh probe branch binds actual new default main commit/tree and generated formula SHA']})
    write(output/'BOTTLE_ACCEPTANCE.json',{**accepted,'platforms':platforms,'formula_sha256':sha(generated.encode()),'compiler_source_version_unchanged':'1.21.0-incremental-1','compiler_source_commit_unchanged':lock['alpha']['source_commit']})
    write(output/'RELEASE_INPUTS.json',{'root_url':ROOT_URL,'publication_admitted':False,'files':[{'local_file':r['archive']['path'],'filename':r['filename'],'bytes':r['archive']['bytes'],'sha256':r['archive']['sha256']} for r in rows],
        'formula_sha256':sha(generated.encode()),'SDK_lock_sha256':sha((output/'test/sdk_source_lock.json').read_bytes()),
        'remaining':['Parent release publication with exact returned checksums','Formula stanza and coupled source lock/workflow publication','Anonymous release and complete public main readback','Fresh ordinary installer with SDK bottle predicate and exact installed backend check','Schema3 frozen consumer/native/Git/device proof']})
    return platforms

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bottle-result',action='append',type=Path,required=True);parser.add_argument('--acceptance',type=Path,required=True);parser.add_argument('--acceptance-sha256',required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True)
    args=parser.parse_args();source_packet(args.packet_sha256);finalize(args.bottle_result,args.acceptance,args.acceptance_sha256,args.output)
