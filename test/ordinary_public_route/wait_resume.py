"""Finite review hold on the same hosted runner, then exact retained-provider resume."""
import argparse
import json
import os
from pathlib import Path
import re
import time
from route_support import need,read,write,stable,verify_commands,revalidate
from run_route import get_context,run_command,clean_environment,resume,retained_deadline,retained_runner_deadline,CONSUMER,RETURN_RESERVE


def wait(args,driver,protected,providers):
    output=args.output.resolve(strict=True);old=read(output/'OBSERVATION_RESULT.json')
    result={'format':'ordinary-retained-review-hold-v105','passed':False,'approval_consumed':False,'finalization_errors':[]}
    started=time.monotonic();directory=output/'review-command-output';directory.mkdir();runner=driver.Runner(directory)
    runner.deadline=retained_runner_deadline(old['absolute_monotonic_deadline'],900,CONSUMER+RETURN_RESERVE)
    try:
        retained_deadline(old)
        need(old['observation_complete'] is True and old['writers_confirmed_retired'] is True,'Successful ordinary observation remains a prerequisite')
        preparation=output/'PROVIDER_PREPARATION_RESULT.json'
        if preparation.exists():
            returned=read(preparation);need(returned['writers_confirmed_retired'] is True and returned['finalization_errors']==[],'Provider preparation must return before review/resume')
        repository=old['job_identity']['GITHUB_REPOSITORY'];need(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository) is not None,'Exact public owning repository required')
        need(re.fullmatch(r'ordinary-consumer-admission/[A-Za-z0-9_.-]+',args.review_branch) is not None,'Purpose-specific owner review branch required')
        ref='refs/heads/'+args.review_branch;env=clean_environment();approval=output/'REVIEWED_CONSUMER_ADMISSION.json'
        for index in range(30):
            need(time.monotonic()+20<runner.deadline,'Finite retained provider review window expired')
            stdout,_=run_command(runner,providers,'review-poll-'+str(index+1).zfill(2),'git',['ls-remote','https://github.com/'+repository+'.git',ref],output,env,15)
            fields=stdout.split()
            if fields:
                need(len(fields)==2 and re.fullmatch('[0-9a-f]{40}',fields[0]) is not None and fields[1]==ref,'Exact owner review source commit required')
                commit=fields[0];url='https://raw.githubusercontent.com/'+repository+'/'+commit+'/ordinary-consumer-admission.json'
                run_command(runner,providers,'download-reviewed-admission','curl',['--fail','--location','--silent','--show-error','--proto','=https','--tlsv1.2','--connect-timeout','10','--max-time','15','--max-filesize',str(64*2**20),'--output',approval,url],output,env,20)
                row,_=stable(approval);result['review_source']={'repository':repository,'commit':commit,'url':url,'sha256':row['sha256']}
                result['approval_consumed']=True;result['review_wait_seconds']=time.monotonic()-started;args.admission=approval;args.admission_sha256=row['sha256']
                verify_commands(runner.records,runner.group_observations)
                result['resume_return_code']=resume(args,driver,protected,providers);result['passed']=result['resume_return_code']==0
                break
            time.sleep(min(30,max(0,runner.deadline-time.monotonic()-20)))
        need(result['approval_consumed'],'Independent retained-provider review has not arrived within the finite hold')
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected);revalidate(old['source_return_protected']);verify_commands(runner.records,runner.group_observations)
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['writers_confirmed_retired']=runner.writers_confirmed_retired;result['original_groups']=runner.group_observations;result['elapsed_seconds']=time.monotonic()-started
        write(output/'REVIEW_HOLD_RESULT.json',result)
    return 0 if result['passed'] else 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True);parser.add_argument('--review-branch',required=True)
    for name in ('brew','git','curl','bash','python'):parser.add_argument('--'+name,type=Path,required=True);parser.add_argument('--'+name+'-sha256',required=True)
    args=parser.parse_args();raise SystemExit(wait(args,*get_context(args)))
