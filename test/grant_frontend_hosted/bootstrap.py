"""Exact-source entrypoint for SDK, fixture controls, ladder and publication."""
import argparse,hashlib,json,os,runpy,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from source_gate import BASE,BASE_SHA,admit,digest

def main(operation,expected,arguments):
    admit(expected,Path.cwd())
    if operation=='verify':return
    names={'sdk':BASE/'qualify_same_job_sdk.py','run':ROOT/'run_frontend.py','stage':ROOT/'stage_results.py','test':ROOT/'check_sources.py'}
    source=names[operation];sys.argv=[str(source),*arguments]
    if operation=='sdk':sys.argv += ['--packet-sha256',BASE_SHA]
    elif operation in ('run','stage','test'):sys.argv += ['--packet-sha256',expected]
    runpy.run_path(str(source),run_name='__main__')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['verify','sdk','run','stage','test']);p.add_argument('--packet-sha256',required=True);args,remaining=p.parse_known_args();main(args.operation,args.packet_sha256,remaining)
