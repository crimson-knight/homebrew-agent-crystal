"""Own both Python source cohorts and stage their exact bounded raw evidence."""
import argparse,importlib.util,json,os,shutil,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from source_gate import admit,digest,need,read,write
from vendor import public_evidence_rules as rules
DRIVER_SHA='dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
def main(a):
    started=time.monotonic();admit(a.packet_sha256)
    need(digest(a.driver)==DRIVER_SHA and digest(Path(sys.executable).resolve())==a.python_sha256,'Exact source-cohort Runner/Python providers required')
    spec=importlib.util.spec_from_file_location('frontend_source_cohort_driver',a.driver);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
    need(not a.output.exists() and not a.public.exists() and a.output.parent.resolve(strict=True)==a.output.parent and a.public.parent.resolve(strict=True)==a.public.parent,'Fresh physical source-control/public roots required')
    a.output.mkdir();runner=driver.Runner(a.output);runner.deadline=started+150;result=dict(format='atlas-grant-frontend-source-controls-v1',passed=False,source_packet_sha256=a.packet_sha256,python_sha256=a.python_sha256,driver_sha256=DRIVER_SHA,summaries=[],maximum_seconds=180,local_workload_jobs=0)
    try:
        for mode,flags in [('ordinary',[]),('optimized',['-O'])]:
            need(runner.deadline-time.monotonic()>=75,'Complete original source-cohort allowance required')
            out,err=runner.run(mode,[sys.executable,*flags,'-I','-S','-B',ROOT/'test_hosted.py'],cwd=ROOT,environment=dict(os.environ,TMPDIR=str(a.output)),seconds=75)
            summary=json.loads(out);need(summary==dict(tests_run=54,failures=0,errors=0,skipped=0,guard_calls=0,actual_local_compiler_native_container_browser_ssh_workload_jobs=0),'Complete original42 and new12 guarded cases required');result['summaries'].append(summary)
        admit(a.packet_sha256);need(digest(a.driver)==DRIVER_SHA and digest(Path(sys.executable).resolve())==a.python_sha256,'Original source/provider return required');result['passed']=True
    except Exception as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        result.update(commands=runner.records,groups=runner.group_observations,writers_confirmed_retired=runner.writers_confirmed_retired,elapsed_seconds=time.monotonic()-started)
        result['passed']=result['passed'] and runner.writers_confirmed_retired and result['elapsed_seconds']<=180
        write(a.output/'SOURCE_CONTROLS_RESULT.json',result)
        names=['SOURCE_CONTROLS_RESULT.json'] if not runner.writers_confirmed_retired else ['SOURCE_CONTROLS_RESULT.json','COMMANDS.json']+[mode+'.'+stream+'.txt' for mode in ('ordinary','optimized') for stream in ('stdout','stderr') if (a.output/(mode+'.'+stream+'.txt')).exists()]
        a.public.mkdir(mode=0o700)
        for name in names:
            if not (a.output/name).exists():continue
            raw=rules.read_regular(a.output,name);rules.inspect_public_bytes(name,raw);(a.public/name).write_bytes(raw)
    return 0 if result['passed'] else 2
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('driver','output','public'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python'):p.add_argument('--'+name+'-sha256',required=True)
    raise SystemExit(main(p.parse_args()))
