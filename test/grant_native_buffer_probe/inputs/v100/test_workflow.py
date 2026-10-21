"""Inspect an explicit packet or installed workflow fixture under source guards."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent

def need(value,message):
    if not value:raise RuntimeError(message)

def inspect(path):
    raw=path.read_bytes();text=raw.decode()
    manifest=ROOT/'SOURCE_PINS.json'
    manifest_sha=hashlib.sha256(manifest.read_bytes()).hexdigest()
    need(manifest_sha in text,'Exact current source manifest pin required')
    need('  workflow_dispatch:' in text and '\n  push:' not in text,'Explicit manual hosted entrypoint required')
    need('timeout-minutes: 105' in text and 'timeout-minutes: 17' in text,'Complete source-feedback/native/return horizon required')
    need('ATLAS_GRANT_PACKET_SHA256: 9dca430312103538460af4176fceef93f7744ea1e32572474f36ef73bbc25a09' in text,'Exact original215-row SDK/provider policy required')
    need('persist-credentials: false' in text and 'include-hidden-files: false' in text,'Positive source/artifact credential boundary required')
    need(text.index('qualify_same_job_sdk.py')<text.index('source = root / "run_probe.py"'),'Fresh same-job SDK precedes native proof')
    need('ATLAS_NATIVE_BUFFER_POLICY_SHA256' in text and 'UNADMITTED_NATIVE_POLICY.json' in text and
         'native-buffer-source-feedback' in text and 'UNEXECUTED_SOURCE_GATES.json' in text,'Explicit pending native and same-job API prerequisites required')
    need('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' in text and
         'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' in text,'Exact accepted Actions source pins required')
    need(text.count('1955899cb535256cfa477d926d016819e52e747984722c44f76e39a4950fee0e')==2,'Both native and stage Python identities required')
    blocks=[];lines=text.splitlines()
    for index,line in enumerate(lines):
        if line.strip()=="python3 - <<'PYTHON'":
            body=[]
            for next_line in lines[index+1:]:
                if next_line.strip()=='PYTHON':break
                need(next_line.startswith('          '),'Exact inline Python indentation required')
                body.append(next_line[10:])
            ast.parse('\n'.join(body));blocks.append(body)
    need(len(blocks)==3,'Original SDK plus native/stager inline Python source roster required')
    return {'passed':True,'workflow_sha256':hashlib.sha256(raw).hexdigest(),'packet_sha256':manifest_sha,
            'inline_python_blocks_parsed':len(blocks),'actual_workload_jobs':0}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workflow',type=Path,required=True)
    args=parser.parse_args();sys.stdout.write(json.dumps(inspect(args.workflow))+'\n')
