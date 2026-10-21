"""Select and retain actual hosted metadata providers for fixed route entrypoints."""
import argparse
import os
from pathlib import Path
import runpy
import shutil
import sys
from route_support import ROOT,need,stable,source_packet,revalidate,write

ENTRIES={'tap-metadata':('run_route.py',['--mode','tap-metadata']),'detach-ci-tap':('prepare_ci_checkout.py',['--mode','detach']),'restore-ci-tap':('prepare_ci_checkout.py',['--mode','restore']),'observe':('run_route.py',['--mode','observe']),'prepare':('prepare_retained.py',[]),'wait':('wait_resume.py',[]),'bottle':('build_bottle.py',[])}

def provider_arguments(environment=None,which=shutil.which):
    environment=os.environ if environment is None else environment
    result={}
    for name in ('brew','git','curl','bash','python'):
        if name=='python':candidate=sys.executable
        elif name=='git' and sys.platform=='darwin':
            developer=environment.get('DEVELOPER_DIR','/Applications/Xcode.app/Contents/Developer')
            candidate=str(Path(developer)/'usr/bin/git')
        else:candidate=which(name)
        need(candidate is not None,'Actual hosted metadata provider unavailable: '+name)
        physical=Path(candidate).resolve(strict=True);result[name]=stable(physical)[0]
    argv=[]
    for name,row in result.items():argv+=['--'+name,row['path'],'--'+name+'-sha256',row['sha256']]
    return argv,result


def main(args):
    protected=source_packet(args.packet_sha256);extra,providers=provider_arguments()
    record=args.output.parent/(args.output.name+'.'+args.action+'.providers.json')
    need(not record.exists() and not record.is_symlink(),'Fresh actual provider observation required');write(record,providers)
    name,options=ENTRIES[args.action];argv=[str(ROOT/name),'--output',str(args.output),'--packet-sha256',args.packet_sha256,*extra,*options]
    if args.action in ('detach-ci-tap','restore-ci-tap'):
        need(args.setup_tap_name and args.setup_repository_path,'Actual pinned setup action outputs required')
        argv+=['--setup-tap-name',args.setup_tap_name,'--setup-repository-path',args.setup_repository_path]
        if args.action=='restore-ci-tap':
            need(args.route_output is not None and args.route_step_outcomes is not None,'Original route output and actual workflow outcomes required')
            argv+=['--route-output',str(args.route_output),'--route-step-outcomes',args.route_step_outcomes]
            if getattr(args,'preserve_unaccepted_public_clone',False):argv+=['--preserve-unaccepted-public-clone']
    if args.action=='wait':argv+=['--review-branch',args.review_branch]
    if args.action=='observe' and args.sdk_mode=='bottle':
        need(args.bottle_acceptance is not None and args.bottle_acceptance_sha256,'Reviewed bottle distribution inputs required')
        argv+=['--sdk-mode','bottle','--bottle-acceptance',str(args.bottle_acceptance),'--bottle-acceptance-sha256',args.bottle_acceptance_sha256]
    previous=sys.argv
    try:sys.argv=argv;runpy.run_path(str(ROOT/name),run_name='__main__')
    finally:
        sys.argv=previous;revalidate(protected)
        for row in providers.values():need(stable(row['path'])[0]['sha256']==row['sha256'],'Original hosted provider changed on return')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--action',choices=ENTRIES,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet-sha256',required=True);p.add_argument('--review-branch');p.add_argument('--setup-tap-name');p.add_argument('--setup-repository-path');p.add_argument('--route-output',type=Path);p.add_argument('--route-step-outcomes');p.add_argument('--preserve-unaccepted-public-clone',action='store_true');p.add_argument('--sdk-mode',choices=['source','bottle'],default='source');p.add_argument('--bottle-acceptance',type=Path);p.add_argument('--bottle-acceptance-sha256');main(p.parse_args())
