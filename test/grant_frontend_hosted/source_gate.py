"""Admit both exact source rosters before any inherited executable import."""
import hashlib,json,os,stat
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'grant_assignment_cost'
BASE_SHA='9dca430312103538460af4176fceef93f7744ea1e32572474f36ef73bbc25a09'
def need(v,message):
    if not v:raise RuntimeError(message)
def stable(path,maximum=32*2**20):
    path=Path(path);before=path.lstat()
    need(path.resolve(strict=True)==path and stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,'Bounded physical regular source/evidence required')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(fields(before)==fields(opened)==fields(after)==fields(path.lstat()) and len(raw)==before.st_size,'Stable source/evidence identity required')
    return raw
def digest(path):return hashlib.sha256(stable(path)).hexdigest()
def read(path):return json.loads(stable(path))
def write(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')
def roster(root,expected,maximum):
    manifest=root/'SOURCE_PINS.json';raw=stable(manifest,2**20);need(hashlib.sha256(raw).hexdigest()==expected,'Exact externally pinned source manifest required')
    rows=json.loads(raw)['files'];need(0<len(rows)<=maximum and len({r['path'] for r in rows})==len(rows),'Finite unique complete source roster required')
    protected={manifest:expected};total=0
    for row in rows:
        p=PurePosixPath(row['path']);need(str(p)==row['path'] and p.parts and not p.is_absolute() and '..' not in p.parts,'Contained canonical source path required')
        path=root/p;body=stable(path);total+=len(body)
        need(total<=64*2**20 and len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'] and ('mode' not in row or path.stat().st_mode&0o777==row['mode']),'Exact complete source bytes/mode required: '+str(path))
        protected[path]=row['sha256']
    return protected
def admit(expected,repository=None):
    protected=roster(ROOT,expected,128);protected.update(roster(BASE,BASE_SHA,256))
    if repository is not None:
        for row in read(ROOT/'BASE_INPUT_PINS.json')['base_files']:
            path=repository/row['path'];raw=stable(path);need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'Exact original formula/installer/SDK/215-core prerequisite required')
            protected[path]=row['sha256']
    return protected
