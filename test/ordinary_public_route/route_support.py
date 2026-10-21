"""Bounded source/provider reads for the ordinary public installation protocol."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

ROOT=Path(__file__).resolve().parent
LIMIT=64*2**20

def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(stable(path)[1])
def write(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def stable(path,maximum=LIMIT):
    path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum,'Bounded ordinary file required: '+str(path))
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
    fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(fields(before)==fields(opened)==fields(after)==fields(path.lstat()) and len(raw)==before.st_size,'Stable complete physical file required')
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'mode':stat.S_IMODE(before.st_mode)},raw

def source_packet(expected):
    manifest=ROOT/'SOURCE_PINS.json';row,raw=stable(manifest,1024*1024)
    need(row['sha256']==expected,'Exact externally selected route manifest required')
    rows=json.loads(raw)['files'];need(1<=len(rows)<=40 and len({r['path'] for r in rows})==len(rows),'Finite unique route source roster required')
    protected={str(manifest):expected}
    for row in rows:
        name=PurePosixPath(row['path']);need(str(name)==row['path'] and not name.is_absolute() and '..' not in name.parts,'Contained source path required')
        current,_=stable(ROOT/name);need(current['sha256']==row['sha256'] and current['bytes']==row['bytes'],'Exact source member required')
        protected[str(ROOT/name)]=row['sha256']
    return protected

def revalidate(protected):
    for path,expected in protected.items():need(stable(path)[0]['sha256']==expected,'Pinned source/provider changed: '+path)

def load_driver(bottle=False):
    path=ROOT/('bottle_vendor' if bottle else 'vendor')/'test/sdk_install_qualification.py'
    expected='3e9742c1a11e5c782b31fe1b958aa160d3506f196e545c57d2f37f70c8671619' if bottle else 'd63a6dae115a58fa1fb4330203f219a429b6f3dcbe7ade36054ad847dd76a227'
    need(stable(path)[0]['sha256']==expected,'Exact source/bottle SDK Runner/qualifier required')
    spec=importlib.util.spec_from_file_location('ordinary_route_sdk_authority',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    need(stable(path)[0]['sha256']==expected,'SDK authority changed on import')
    return module

def inventory(root,maximum_files=512):
    rows=[]
    for path in sorted(Path(root).rglob('*')):
        need(not path.is_symlink(),'Source aliases require their own reviewed scope')
        if path.is_dir():continue
        row,_=stable(path);rows.append({'path':path.relative_to(root).as_posix(),**{k:row[k] for k in ('bytes','sha256','mode')}})
        need(len(rows)<=maximum_files,'Finite physical file roster required')
    return rows

def catalog(cache):
    root=cache/'api';rows={}
    for name in ('formula.jws.json','formula.json'):
        path=root/name
        if path.exists() or path.is_symlink():rows[name]=stable(path)[0]
    return rows

def verify_commands(commands,group_observations,successful=True):
    need(len(commands)<=96 and len(commands)==len(group_observations),'Finite exact command/group journal required')
    for row,group in zip(commands,group_observations):
        need(all(type(v) is int and v>0 for v in (row['pid'],row['original_group'],group['group'])) and row['pid']==row['original_group']==group['group'],'Positive joined original PID/group required')
        need(type(row['expected_exit']) is int and type(row['exit_code']) is int,'Exact command return integers required')
        if successful:need(row['exit_code']==row['expected_exit'] and row['refusal'] is None,'Expected command return without refusal required')
        need(row['writers_confirmed_retired'] is True and group['status']=='absent','Original command must return with writers absent')
        need(row['terminal_group_observation']==group,'Command and result group readback must join')
        maximum=command_maximum(row['label'])
        need(type(row['maximum_seconds']) in (int,float) and row['maximum_seconds']==maximum and type(row['elapsed_seconds']) in (int,float) and math.isfinite(row['elapsed_seconds']) and 0<=row['elapsed_seconds'],'Exact original command budget and finite terminal elapsed required')
        if successful:need(row['elapsed_seconds']<=maximum,'Successful command terminal deadline exceeded')

def command_maximum(label):
    if label.startswith('review-poll-') and label[len('review-poll-'):].isdigit() and 1<=int(label[len('review-poll-'):])<=30:return 15
    if any(label==p+'-tap-'+s for p in ('installed','returned','before-bottle','after-bottle','ci-public') for s in ('root','commit','origin')):return 30
    if label in ('alias-acrystal','alias-agent-crystal','alias-crystal-alpha'):return 30
    if label in ('ci-formula-absence-before','ci-brew-root','ci-tap-location','ci-checkout-before','ci-tree-before','ci-checkout-origin','ci-checkout-after','ci-tree-after','ci-formula-absence-after','ci-checkout-restore-before','ci-tree-restore-before','ci-preserved-source','ci-preserved-origin','ci-checkout-restore-after','ci-tree-restore-after'):return 15
    if label=='ci-untap-owned-checkout':return 30
    limits={**dict.fromkeys(('initial-formula-absence','initial-tap-location','public-default-main','homebrew-version','homebrew-config','homebrew-repository','homebrew-source','homebrew-source-return','homebrew-core-return','homebrew-cache','actual-installed-prefix','homebrew-core-source','consumer-install-bundle','consumer-profile'),30),
        **dict.fromkeys(('observed-git-version','observed-curl-version','observed-bash-version','observed-python-version','consumer-lock-check'),15),
        'download-public-installer':45,'ordinary-default-install':2700,'installed-formula-tests':120,'installed-dependency-metadata':60,
        'tap-public-default':120,'build-for-normal-bottle':2700,'create-bottle':300,'download-public-SDK':60,'download-reviewed-minecart':45,'consumer-write-lock':600,'consumer-frozen-install':600,'consumer-budget-spec':120,'download-reviewed-admission':20,'native-candidate':60,'Git-candidate':60,'profile-inspection':15}
    need(label in limits,'Exact finite named command roster required');return limits[label]

def extract_provider(archive,destination,descriptor):
    row,_=stable(archive,16*2**20);need(row['bytes']==descriptor['bytes'] and row['sha256']==descriptor['sha256'],'Exact approved provider archive required')
    expected={r['path']:r for r in descriptor['files']};need(1<=len(expected)<=64 and len(expected)==len(descriptor['files']),'Finite complete provider archive roster required')
    payload={};total=0
    with tarfile.open(archive,'r:gz') as stream:
        for index,member in enumerate(stream):
            need(index<128 and (member.isfile() or member.isdir()),'Ordinary bounded provider archive required')
            name=member.name.rstrip('/');path=PurePosixPath(name)
            need(str(path)==name and not path.is_absolute() and '..' not in path.parts,'Contained provider member required')
            if member.isdir():continue
            need(name in expected and name not in payload,'Exact provider file roster required')
            row=expected[name];need(0<=member.size==row['bytes']<=20*2**20,'Bounded exact provider member required')
            raw=stream.extractfile(member).read(20*2**20+1);mode=0o755 if member.mode&0o111 else 0o644
            need(sha(raw)==row['sha256'] and mode==row['mode'],'Exact provider member bytes/mode required')
            total+=len(raw);need(total<=32*2**20,'Finite expanded provider bytes required');payload[name]=(raw,mode)
    need(set(payload)==set(expected),'Complete approved provider archive files required')
    destination.mkdir()
    for name,(raw,mode) in payload.items():
        path=destination/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
    return inventory(destination)
