"""Review the complete exact manual workflow and all source-verified inline blocks."""
import argparse,ast,hashlib,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from source_gate import digest,need

def blocks(text):
    result=[];lines=text.splitlines()
    for index,line in enumerate(lines):
        if line.strip()=="python3 - <<'PYTHON'":
            body=[]
            for value in lines[index+1:]:
                if value.strip()=='PYTHON':break
                need(value.startswith('          '),'Exact ten-space Python heredoc indentation required');body.append(value[10:])
            result.append('\n'.join(body)+'\n')
    return result

def inspect(path):
    text=path.read_text();need('  workflow_dispatch:' in text and '\n  push:' not in text,'Manual-only measurement policy required')
    need('timeout-minutes: 90' in text and 'install2700/source180/SDK840/ladder900/stage120/uploads360/slack300' in text,'Exact complete finite90-minute envelope required')
    need('persist-credentials: false' in text and text.count('include-hidden-files: false')==3,'Exact checkout/three positive-upload confidentiality boundary required')
    need(text.count('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')==3 and 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' in text and 'Homebrew/actions/setup-homebrew@4790763c0a3ba4036f72634dc079c4a7dfcd4878' in text,'Exact accepted action source identities required')
    need('ATLAS_FRONTEND_PACKET_SHA256: '+digest(ROOT/'SOURCE_PINS.json') in text,'Exact current frozen frontend source manifest pin required')
    body=blocks(text);need(len(body)==5,'Five exact source-verified executable boundaries required')
    for source in body:
        ast.parse(source)
        for expression in ["hashlib.sha256(raw).hexdigest()!=os.environ['ATLAS_FRONTEND_PACKET_SHA256']","for row in json.loads(raw)['files']:","path.is_symlink()","path.resolve()!=path","hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']","path.stat().st_mode&0o777!=row['mode']"]:
            need(expression in source,'Complete source/mode gate at every inline boundary required')
        need(source.index("for row in json.loads(raw)['files']:")<source.index('runpy.run_path'),'Complete source gate must precede executable import')
    need("steps.result_stage.outcome == 'success'" in text and 'frontend-public-evidence/' in text,'Successful fixed positive staging precedes diagnostic upload')
    return dict(passed=True,inline_blocks=5,source_packet_sha256=digest(ROOT/'SOURCE_PINS.json'),workflow_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),actual_local_workload_jobs=0)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--workflow',type=Path,required=True);a=p.parse_args();print(inspect(a.workflow))
