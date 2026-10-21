"""Run bounded guarded source fixtures under the unchanged accepted SDK Runner."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
from route_support import ROOT,need,read,write,stable,source_packet,revalidate,load_driver

PYTHON_CASES=37
CI_CASES=190
RUBY_CASES=7
RUBY_ASSERTIONS=27


def controls(args):
    output=args.output.absolute();need(output.parent.resolve(strict=True)==output.parent and not output.exists(),'Fresh physical source-control output required');output.mkdir()
    protected=source_packet(args.packet_sha256);providers={}
    for key in ('python','ruby'):
        path=Path(getattr(args,key)).resolve(strict=True);row,_=stable(path);need(row['sha256']==getattr(args,key+'_sha256'),'Exact actual source-fixture provider required');providers[key]=row;protected[str(path)]=row['sha256']
    need(providers['python']['path']==str(Path(sys.executable).resolve()),'Same actual Python source-fixture provider required')
    driver=load_driver();runner=driver.Runner(output);started=time.monotonic();runner.deadline=started+240
    result={'format':'ordinary-public-route-source-controls-v111','passed':False,'actual_compiler_native_container_SSH_jobs':0,'providers':providers,'observed_clock':{'protocol':'POSIX_CLOCK_MONOTONIC','common_seconds':time.clock_gettime(time.CLOCK_MONOTONIC),'Runner_local_seconds':time.monotonic(),'local_clock_implementation':time.get_clock_info('monotonic').implementation},'finalization_errors':[]}
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','LC_ALL')};env.update(PYTHONDONTWRITEBYTECODE='1',NO_COLOR='1')
    try:
        fixtures=args.fixtures.resolve(strict=True) if args.fixtures else output/'fixtures'
        if args.fixtures is None:
            runner.run('fetch-public-source-fixtures',[providers['python']['path'],'-I','-S','-B',str(ROOT/'launch.py'),'--entrypoint','fetch_fixtures.py','--packet-sha256',args.packet_sha256,'--output',str(fixtures)],cwd=ROOT,environment=env,seconds=100)
        from fetch_fixtures import FIXTURES
        for name,commit,size,digest in FIXTURES:
            row,_=stable(fixtures/name);need(row['bytes']==size and row['sha256']==digest,'Exact retained public fixture archive required')
        stdout,_=runner.run('Ruby-provider',[providers['ruby']['path'],'-rrbconfig','-rjson','-e','puts JSON.generate({"runtime_path"=>RbConfig.ruby,"version"=>RUBY_VERSION})'],cwd=ROOT,environment=env,seconds=15)
        ruby_metadata=json.loads(stdout);backend=Path(ruby_metadata['runtime_path']).resolve(strict=True);providers['ruby_backend']=stable(backend)[0];protected[str(backend)]=providers['ruby_backend']['sha256'];result['Ruby_metadata']=ruby_metadata
        env['ORDINARY_ROUTE_FIXTURE_ROOT']=str(fixtures)
        for mode in ('ordinary','optimized'):
            argv=[providers['python']['path'],'-I','-S','-B']+(['-O'] if mode=='optimized' else [])+[str(ROOT/'test_public_route.py')]
            stdout,_=runner.run('Python-'+mode,argv,cwd=ROOT,environment=env,seconds=30)
            summary=json.loads(stdout.strip().splitlines()[-1]);need(summary=={'tests_run':PYTHON_CASES,'errors':0,'failures':0,'skips':0,'actual_guard_calls':0},'Exact guarded Python case totals required')
        for mode in ('ordinary','optimized'):
            argv=[providers['python']['path'],'-I','-S','-B']+(['-O'] if mode=='optimized' else [])+[str(ROOT/'test_ci_checkout.py')]
            stdout,_=runner.run('CI-Python-'+mode,argv,cwd=ROOT,environment=env,seconds=15)
            summary=json.loads(stdout.strip().splitlines()[-1]);need(summary=={'tests_run':CI_CASES,'errors':0,'failures':0,'skips':0,'actual_guard_calls':0},'Exact guarded CI checkout case totals required')
        stdout,_=runner.run('Ruby-writer',[providers['ruby']['path'],str(ROOT/'test_lock_writer.rb')],cwd=ROOT,environment=env,seconds=30)
        need(re.search(r'^'+str(RUBY_CASES)+r' runs, '+str(RUBY_ASSERTIONS)+r' assertions, 0 failures, 0 errors, 0 skips$',stdout,re.M) is not None,'Exact successful guarded Ruby writer totals required')
        result['passed']=True;result['Python_cases_each']=PYTHON_CASES;result['CI_Python_cases_each']=CI_CASES;result['Ruby_cases']=RUBY_CASES;result['Ruby_assertions']=RUBY_ASSERTIONS
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            revalidate(protected)
            need(runner.writers_confirmed_retired and all(g['status']=='absent' for g in runner.group_observations),'All original source-fixture groups must return absent')
        except Exception as error:result['passed']=False;result['finalization_errors'].append(type(error).__name__+': '+str(error))
        result['elapsed_seconds']=time.monotonic()-started;result['original_groups']=runner.group_observations;result['writers_confirmed_retired']=runner.writers_confirmed_retired
        if result['elapsed_seconds']>240:result['passed']=False;result['finalization_errors'].append('Complete source-control deadline exceeded')
        write(output/'SOURCE_CONTROL_RESULT.json',result)
    return 0 if result['passed'] else 2

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--packet-sha256',required=True);p.add_argument('--fixtures',type=Path)
    for key in ('python','ruby'):p.add_argument('--'+key,type=Path,required=True);p.add_argument('--'+key+'-sha256',required=True)
    raise SystemExit(controls(p.parse_args()))
