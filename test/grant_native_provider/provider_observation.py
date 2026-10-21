"""Read-only hosted provider observation and independently pinned policy materialization."""
import argparse
import ast
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import stat
import struct
import sys
import time
import native_image_evidence as images

ROOT=Path(__file__).resolve().parent
TRANSFER_SHA='439df1016cdfdfa237521eccf1f47f9fc72827a4990c3c35b2ec4d8371e4cd92'
CORE_SHA='e186b50c45c15da64ede2801b41e1b05112222dd25cc969ca628c1a1007a8d0e'
BASE_SHA='9dca430312103538460af4176fceef93f7744ea1e32572474f36ef73bbc25a09'
DRIVER_SHA='dfa1b22d9d2a534d70ed4c22494cf78e107d0ae40acae45b9f72a8970789a797'
TOOL_HELPER_SHA='8db41f1a4c4829dee29f2e3d7f28e038bcf3d6e402d66067432e87091f74e097'
OBSERVE_SECONDS=360
RETURN_SECONDS=60
POLICY_SECONDS=120
MAX_FILE=256*2**20
MAX_TOTAL=2**30
MAX_HEADERS=512
MAX_NATIVE=64
MAX_ALIASES=128
MAX_RAW=8*2**20
COMMANDS=[('developer',5),('sdk',5),('cc-path',5),('ld-path',5),('sdk-version',5),('sdk-build',5),
          ('cc-version',10),('cc-resource',10),('headers',30),('cc-search',10),('link-search',10),
          ('llvm-version',5),('llvm-library',5),('llvm-package',10),('cc-signature',10),('cc-signature-verify',10),('ld-signature',10),('ld-signature-verify',10),('sdk-signature',10),('sdk-signature-verify',10)]
OWNED_ROOTS={}
OWNED_DIRECTORIES={}
OWNED_FILES={}

def need(value,message):
    if not value:raise RuntimeError(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):
    raw=(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode();need(len(raw)<=MAX_RAW,'Finite complete metadata receipt capacity required before writing');write_bytes(path,raw)
def decode(raw):
    def unique(rows):
        value={}
        for k,v in rows:need(k not in value,'Unique JSON fields required');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x:need(False,'Finite JSON values required'))
def clock(deadline):need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<=deadline,'Finite complete phase deadline required')
def identity(path):
    s=Path(path).lstat();return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def owned_root(path,fresh=False):
    path=Path(path)
    if fresh:need(path not in OWNED_ROOTS and not path.exists() and not path.is_symlink(),'Fresh output ownership for this invocation required')
    if path in OWNED_ROOTS:
        need(identity(path)[:3]==OWNED_ROOTS[path] and path.resolve(strict=True)==path,'Original owned output root identity required');return path
    need(path.is_absolute() and path.parent.resolve(strict=True)==path.parent and not path.exists() and not path.is_symlink(),'Fresh physical output required before admission')
    path.mkdir(mode=0o700);OWNED_ROOTS[path]=identity(path)[:3];OWNED_DIRECTORIES[path]=OWNED_ROOTS[path];return path
def output_root(path):
    roots=[root for root in OWNED_ROOTS if Path(path).is_relative_to(root)]
    if not roots:return None
    root=max(roots,key=lambda value:len(value.parts));owned_root(root);return root
def output_directory(path):
    path=Path(path);root=output_root(path)
    if root is None:path.mkdir(parents=True,exist_ok=True);return
    current=root
    for name in path.relative_to(root).parts:
        current=current/name
        if current not in OWNED_DIRECTORIES:
            need(not current.exists() and not current.is_symlink(),'Fresh owned output subdirectory required');current.mkdir(mode=0o700);OWNED_DIRECTORIES[current]=identity(current)[:3]
        need(identity(current)[:3]==OWNED_DIRECTORIES[current] and stat.S_ISDIR(current.lstat().st_mode),'Original physical output directory identity required')
def write_bytes(path,raw):
    path=Path(path);root=output_root(path)
    if root is None:path.write_bytes(raw);return
    output_directory(path.parent)
    if path in OWNED_FILES:need(identity(path)[:3]==OWNED_FILES[path],'Original owned output file identity required')
    else:need(not path.exists() and not path.is_symlink(),'Fresh owned output file required')
    flags=os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_TRUNC if path in OWNED_FILES else os.O_EXCL)
    with os.fdopen(os.open(path,flags,0o644),'wb') as stream:
        before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'Ordinary single-link owned output required');stream.write(raw);stream.flush();after=os.fstat(stream.fileno())
    owned_root(root);need(identity(path)[:3]==[after.st_dev,after.st_ino,after.st_mode] and after.st_size==len(raw),'Exact owned output write return required');OWNED_FILES[path]=identity(path)[:3]

def shim_compile_context(probe,cc,private,object_path,sdk_binding=None,absolute_deadline=1e30):
    """Derive all compiler context directly from the exact admitted actual compile expression."""
    source=Path(probe.__file__);tree=ast.parse(source.read_bytes());assignments=[n.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='cc_argv' for t in n.targets)]
    need(len(assignments)==1 and isinstance(assignments[0],ast.List),'Unique exact planned C shim compile argv required')
    def value(node):
        if isinstance(node,ast.Constant) and type(node.value) is str:return node.value
        expression=ast.dump(node,include_attributes=False)
        choices={ast.dump(ast.parse("policy['cc']",mode='eval').body,include_attributes=False):cc,ast.dump(ast.parse("str(ROOT/'buffer_shim.c')",mode='eval').body,include_attributes=False):str(probe.ROOT/'buffer_shim.c'),ast.dump(ast.parse('str(object_path)',mode='eval').body,include_attributes=False):str(object_path)}
        need(expression in choices,'Reviewed static actual C shim argv expression required');return choices[expression]
    original=[value(node) for node in assignments[0].elts]
    need(original[0]==cc and original.count('-c')==1 and original.count('-o')==1 and original[-2:]==['-o',str(object_path)] and original[-3]==str(probe.ROOT/'buffer_shim.c'),'Exact compile/source/output tuple required')
    sdk=load(ROOT/'sdk_sysroot.py','564108b0928c2cd6cdb5cea486162f8692ef5a37fdbf537b8763528d012788f5','header_observed_sdk_sysroot',absolute_deadline)
    if sdk_binding is not None:original=sdk.compile_argv(original,sdk_binding)
    transformed=sdk.preprocessing_argv(original)
    environment=probe.environment(private,cc)
    semantic={k:('$OWNED_PRIVATE/home' if k=='HOME' else '$OWNED_PRIVATE/cache' if k=='CRYSTAL_CACHE_DIR' else '$CURRENT_JOB_TMPDIR' if k=='TMPDIR' else v) for k,v in environment.items()}
    result=dict(format='atlas-native-buffer-shim-compile-context-v1',original_argv=original,preprocessing_argv=transformed,environment=environment,semantic_environment=semantic,planned_private=str(private),probe_source_sha256=sha(source.read_bytes()))
    if sdk_binding is not None:result['sdk_sysroot']=sdk_binding
    return result

def link_trace(stdout,stderr,temporary,linker):
    """Give one proven cc1-output/linker-input scratch token a stable role."""
    streams=[stdout,stderr];parsed=[[shlex.split(line) for line in text.splitlines()] for text in streams]
    cc1=[tokens for lines in parsed for tokens in lines if '-cc1' in tokens]
    raw_sha=sha((stdout+stderr).encode())
    if not cc1:return dict(protocol='atlas-clang-link-trace-stable-v1',raw_sha256=raw_sha,semantic_sha256=raw_sha,temporary_object=None,normalization='literal-no-cc1-output')
    need(len(cc1)==1 and cc1[0].count('-o')==1,'One actual cc1 scratch-output trace required');scratch=cc1[0][cc1[0].index('-o')+1];path=Path(scratch)
    need(path.is_absolute() and path.name.startswith('null-') and path.suffix=='.o' and path.parent==Path(temporary),'Actual current-job temporary object role required')
    linked=[tokens for lines in parsed for tokens in lines if tokens and tokens[0]==str(linker)]
    need(len(linked)==1 and linked[0].count(scratch)==1 and sum(tokens.count(scratch) for lines in parsed for tokens in lines)==2,'Same exact cc1-output/selected-linker-input token required')
    normalized=[[['$LINK_SEARCH_TEMPORARY_OBJECT' if token==scratch else token for token in tokens] for tokens in lines] for lines in parsed]
    return dict(protocol='atlas-clang-link-trace-stable-v1',raw_sha256=raw_sha,semantic_sha256=sha(canonical(normalized)),temporary_object=scratch,normalization='exact-single-cc1-output-selected-linker-input')

def stable_shim_context(context):
    result={k:v for k,v in context.items() if k!='environment'};source=context['original_argv'][-3];target=context['original_argv'][-1]
    result['original_argv']=['$PROBE_SOURCE/buffer_shim.c' if value==source else '$PROBE_OUTPUT/buffer_shim.o' if value==target else value for value in context['original_argv']]
    result['preprocessing_argv']=['$PROBE_SOURCE/buffer_shim.c' if value==source else value for value in context['preprocessing_argv']];result['planned_private']='$PROBE_OUTPUT/private'
    if 'sdk_sysroot' in result:result['sdk_sysroot']=load(ROOT/'sdk_sysroot.py','564108b0928c2cd6cdb5cea486162f8692ef5a37fdbf537b8763528d012788f5','stable_observed_sdk_sysroot',1e30).metadata(result['sdk_sysroot'])
    return result
def stable(path,deadline,maximum=MAX_FILE):
    clock(deadline);p=Path(path);before=identity(p)
    need(stat.S_ISREG(before[2]) and 0<=before[3]<=maximum,'Bounded physical regular input required: '+str(p))
    chunks=[];size=0
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        need(identity(p)==before and [getattr(os.fstat(stream.fileno()),k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')]==before,'Opened physical identity required')
        while True:
            clock(deadline);chunk=stream.read(min(2**20,maximum+1-size))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk);need(size<=maximum,'Complete file byte ceiling exceeded')
    clock(deadline);need(identity(p)==before and size==before[3],'Exact stable file return required')
    raw=b''.join(chunks)
    return dict(path=str(p),bytes=size,sha256=sha(raw),mode=stat.S_IMODE(before[2]),physical_identity=before),raw
def digest(path,deadline):return stable(path,deadline)[0]['sha256']
def protect(root,name,expected,maximum,deadline):
    path=root/name;raw=stable(path,deadline,2**20)[1];need(sha(raw)==expected,'Exact external source manifest required: '+name)
    rows=decode(raw)['files'];need(0<len(rows)<=maximum and len({r['path'] for r in rows})==len(rows),'Finite source roster required')
    result={path:expected}
    for row in rows:
        rel=PurePosixPath(row['path']);need(str(rel)==row['path'] and not rel.is_absolute() and '..' not in rel.parts,'Canonical contained source member required')
        p=root/rel;current,_=stable(p,deadline);need(current['sha256']==row['sha256'] and current['bytes']==row['bytes'],'Exact source member required')
        if 'mode' in row:need(current['mode']==row['mode'],'Exact source mode required')
        result[p]=row['sha256']
    return result
def load(path,expected,name,deadline):
    need(digest(path,deadline)==expected,'Exact imported executable source required')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    need(digest(path,deadline)==expected,'Imported source return required');return module

def accepted_analysis_native(transfer,native,deadline):
    accepted=decode(stable(ROOT/'inputs/ACCEPTED_TOOL_NATIVE_INPUTS.json',deadline,MAX_RAW)[1])
    decision_raw=stable(ROOT/'inputs/ROOT_ANALYSIS_SOURCE_DECISION.json',deadline,MAX_RAW)[1]
    need(sha(decision_raw)=='c422d3625f7efe657d3c2dbdd575ed3b0f60bfe3ee7f8fde57b3462de9355a4f','Exact independently accepted restricted source-policy decision required')
    decision=decode(decision_raw)
    need(decision['passed'] is True and decision['actual_independent_receipt_sha256']=='8855f58a5c37478ccec1ec01e80fe2523e332688841eead36a342c56f3b3d590' and decision['stable_projection_canonical_sha256']==sha(canonical(accepted))=='41e88da63e122233426ff376cb048f36f1df319e59f841fba335fa1f59923805','Exact actual accepted analysis-input provenance required')
    need(transfer.policy_view(native)==accepted,'Exact independently accepted v103 analysis-tool native inputs required; additional provider scope remains observation-only')
    return accepted

def admit(args,deadline):
    need(platform.system()=='Darwin' and platform.machine()=='arm64' and os.environ.get('GITHUB_ACTIONS')=='true','Actual hosted Mac ARM64 observation required')
    protected=protect(ROOT,'SOURCE_PINS.json',args.packet_sha256,32,deadline)
    protected.update(protect(args.transfer_packet,'SOURCE_PINS.json',CORE_SHA,256,deadline))
    protected.update(protect(args.transfer_packet,'TRANSFER_SOURCE_PINS.json',TRANSFER_SHA,54,deadline))
    base=decode(stable(ROOT/'inputs/BASE_INPUT_PINS.json',deadline)[1])
    for row in base['base_files']:
        p=args.repository/row['path'];current,_=stable(p,deadline);need(current['sha256']==row['sha256'] and current['bytes']==row['bytes'],'Exact original revision1 source prerequisite required');protected[p]=row['sha256']
    policy_path=args.repository/'test/grant_assignment_cost/same_job_policy.py'
    sdk=load(policy_path,protected[policy_path],'native_observation_sdk_policy',deadline)
    protected.update(sdk.protect_packet(BASE_SHA));admitted=sdk.metadata(args.sdk_evidence,os.environ)
    driver=load(args.repository/'test/sdk_install_qualification.py',DRIVER_SHA,'native_observation_runner',deadline)
    transfer=load(args.transfer_packet/'proof_tool_transfer.py',TOOL_HELPER_SHA,'native_observation_transfer_v103',deadline)
    for current in admitted['providers'].values():
        p=Path(current['path']);need(digest(p,deadline)==current['sha256'],'Current SDK provider bytes required');protected[p]=current['sha256']
    need(digest(Path(sys.executable).resolve(),deadline)==args.python_sha256==admitted['runner']['python_sha256'],'Same actual SDK Python provider required')
    prefix=Path((args.sdk_evidence/'brew-prefix.stdout.txt').read_text().strip()).resolve(strict=True);stdlib=prefix/'share/agent-crystal/src'
    need(driver.tree_identity(stdlib)==admitted['stdlib'],'Current installed stdlib required')
    for name,relative in [('INSTALLED_FORMULA.rb','.brew/agent-crystal.rb'),('INSTALL_RECEIPT.json','INSTALL_RECEIPT.json')]:
        p=prefix/relative;need(digest(p,deadline)==digest(args.sdk_evidence/name,deadline),'Installed source/receipt join required');protected[p]=digest(p,deadline)
    budget=transfer.Budget(min(deadline,time.monotonic()+45));transfer.tool_return(args.tool_workspace,budget)
    original=transfer.decode(budget.read(args.tool_workspace/'NATIVE_OBSERVATION.json'))
    need(original['passed'] is True and original['execution_admitted'] is False,'Successful execution-unadmitted same-job tool observation required')
    tool_native=transfer.collect_native(budget,admitted,tool_root=args.tool_workspace/'tools')
    need(original['native']==tool_native and original['same_job']==admitted['job_identity'],'Exact actual tool native observation required')
    accepted_analysis_native(transfer,tool_native,deadline)
    sdk_rows=sdk.roster(args.sdk_evidence)
    def check(end):
        need(sdk.metadata(args.sdk_evidence,os.environ)==admitted and sdk.roster(args.sdk_evidence)==sdk_rows,'Fresh SDK evidence/job return required')
        need(driver.tree_identity(stdlib)==admitted['stdlib'],'Installed stdlib return required')
        transfer.tool_return(args.tool_workspace,transfer.Budget(min(end,time.monotonic()+30)))
        need(transfer.collect_native(transfer.Budget(min(end,time.monotonic()+45)),admitted,tool_root=args.tool_workspace/'tools')==tool_native,'Tool native physical/alias return required')
        for path,expected in protected.items():need(digest(path,end)==expected,'Protected source/provider return required')
    return dict(admitted=admitted,driver=driver,transfer=transfer,tool_native=tool_native,protected=protected,check=check,stream_images=True)

def macho(raw,transfer):
    """Use the exact transfer import parser after selecting a complete ARM64 slice."""
    thin=raw
    if raw[:4] in (b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf'):
        wide=raw[:4]==b'\xca\xfe\xba\xbf';count=struct.unpack_from('>I',raw,4)[0];size=32 if wide else 20
        need(0<count<=16 and 8+count*size<=len(raw),'Bounded complete universal Mach-O table required');arms=[]
        for index in range(count):
            off=8+index*size;cpu=struct.unpack_from('>I',raw,off)[0]
            start,length=struct.unpack_from('>QQ' if wide else '>II',raw,off+8)
            need(start>=8+count*size and start+length<=len(raw),'Complete contained universal Mach-O slice required')
            if cpu==0x100000c:arms.append(raw[start:start+length])
        need(len(arms)==1,'Exactly one complete ARM64 Mach-O slice required');thin=arms[0]
    imports=transfer.native_imports(thin);count,total=struct.unpack_from('<II',thin,16);offset=32;rpaths=[]
    for _ in range(count):
        command,length=struct.unpack_from('<II',thin,offset)
        if command==0x8000001c:
            begin=struct.unpack_from('<I',thin,offset+8)[0];need(12<=begin<length,'Complete rpath load command required')
            value=thin[offset+begin:offset+length];need(b'\0' in value,'Terminated rpath required');rpaths.append(value.split(b'\0',1)[0].decode())
        offset+=length
    need(offset==32+total and len(rpaths)==len(set(rpaths)),'Complete unique rpath roster required')
    return dict(imports=imports,rpaths=rpaths)

def header_paths(raw):
    text=raw.replace('\\\n',' ');need(':' in text,'Complete C preprocessor dependency record required')
    target,values=text.split(':',1);need(target.strip() and len(text)<=2**20,'Bounded complete header dependency output required')
    rows=shlex.split(values);need(rows and len(rows)==len(set(rows))<=MAX_HEADERS+1 and all(Path(p).is_absolute() for p in rows),'Finite unique absolute actual header roster required');return rows

def resolve_input(lexical,transfer):
    """Preserve POSIX parent traversal after intermediate aliases for loader paths."""
    if '..' not in Path(lexical).parts:return transfer.resolve_native(lexical)
    path=Path(lexical);need(path.is_absolute() and str(path)==lexical,'Absolute exact declared native input required')
    pending=list(path.parts[1:]);current=Path('/');links=[]
    while pending:
        component=pending.pop(0)
        if component=='..':current=current.parent;continue
        if component=='.':continue
        current=current/component;before=identity(current)
        if stat.S_ISLNK(before[2]):
            need(len(links)<32,'Finite32-link selected input resolution required');target=os.readlink(current);need(0<len(target)<=4096 and identity(current)==before,'Stable bounded selected symlink target required')
            links.append(dict(path=str(current),target=target,physical_identity=before));target_path=Path(target)
            if target_path.is_absolute():pending=list(target_path.parts[1:])+pending;current=Path('/')
            else:pending=list(target_path.parts)+pending;current=current.parent
        else:need(stat.S_ISDIR(before[2]) if pending else stat.S_ISREG(before[2]),'Physical selected input parent/file required')
    for link in links:need(identity(link['path'])==link['physical_identity'] and os.readlink(link['path'])==link['target'],'Complete selected alias return required')
    return dict(declared_path=lexical,resolved_path=str(current),links=links,resolved_physical_identity=identity(current))

class Census:
    def __init__(self,output,deadline,transfer,stream_images=False):
        self.output=output;self.deadline=deadline;self.transfer=transfer;self.rows={};self.resolutions={};self.snapshots=[];self.total=0
        self.stream_images=stream_images;self.streamed={};self.image_evidence=[];self.image_total=0;self.evidence_total=0
    def file(self,lexical,kind):
        clock(self.deadline);resolution=resolve_input(str(lexical),self.transfer);path=Path(resolution['resolved_path'])
        need(str(lexical) not in self.resolutions or self.resolutions[str(lexical)]==resolution,'Stable lexical resolution required')
        self.resolutions[str(lexical)]=resolution;need(len(self.resolutions)<=768,'Bounded full lexical input roster required')
        if str(path) in self.rows:
            need(self.rows[str(path)]['physical_identity']==identity(path),'Revisited exact native physical identity required');return self.rows[str(path)]
        if self.stream_images and kind in ('metadata-provider','analysis-tool-library','native-image','cc','llvm-image','linker'):
            need(len(self.streamed)<MAX_NATIVE,'Finite streamed native/provider image roster required before reading')
            images.admit_size(identity(path)[3],images.MAX_IMAGE_TOTAL-self.image_total)
            value,evidence,raw=images.fingerprint(path,self.deadline,images.MAX_IMAGE_TOTAL-self.image_total,images.MAX_RETAINED_TOTAL-self.evidence_total)
            need(len(self.streamed)<MAX_NATIVE,'Finite streamed native/provider image roster required');self.image_total+=value['bytes'];value.update(kind=kind,image_format='macho-header-v1' if evidence is not None else 'non-macho-metadata-provider');self.rows[str(path)]=value;self.streamed[str(path)]=dict(value)
            if evidence is not None:
                need(self.evidence_total+len(raw)<=images.MAX_RETAINED_TOTAL,'Aggregate retained native header evidence admission required before writing');self.evidence_total+=len(raw)
                target=self.output/'provider-headers'/('%04d.bin'%len(self.streamed));write_bytes(target,raw)
                self.image_evidence.append(dict(path=str(target.relative_to(self.output)),original_path=str(path),evidence=evidence))
            elif kind=='metadata-provider':
                need(self.total+value['bytes']<=MAX_TOTAL,'Original aggregate full-byte source admission required before reading');self.total+=value['bytes']
                current,raw=stable(path,self.deadline);need(current['sha256']==value['sha256'],'Whole script/provider digest join required');target=self.output/'provider-bytes'/('%04d.bin'%len(self.rows));write_bytes(target,raw)
                self.snapshots.append(dict(path=str(target.relative_to(self.output)),bytes=len(raw),sha256=value['sha256'],original_path=str(path),kind=kind))
            else:need(False,'Native images require complete selected Mach-O header evidence')
            return value
        value,raw=stable(path,self.deadline);need(len(self.rows)<MAX_NATIVE+MAX_HEADERS,'Finite complete native/header roster required')
        self.total+=len(raw);need(self.total<=MAX_TOTAL,'One-GiB aggregate selected native/header source ceiling exceeded')
        value['kind']=kind;self.rows[str(path)]=value
        if kind.endswith('receipt'):
            metadata=decode(raw)
            value['stable_receipt']=dict(source={k:v for k,v in metadata['source'].items() if k in ('versions','spec','tap','tap_git_head')},arch=metadata['arch'],compiler=metadata.get('compiler'),poured_from_bottle=metadata.get('poured_from_bottle'),runtime_dependencies=metadata.get('runtime_dependencies',[]))
        target=self.output/'provider-bytes'/('%04d.bin'%len(self.rows));write_bytes(target,raw)
        need(digest(target,self.deadline)==value['sha256'],'Exact retained source/provider snapshot required')
        self.snapshots.append(dict(path=str(target.relative_to(self.output)),bytes=len(raw),sha256=value['sha256'],original_path=str(path),kind=kind))
        return value
    def verify(self):
        for name,expected in self.resolutions.items():need(resolve_input(name,self.transfer)==expected,'Complete lexical input/alias return required')
        for path,expected in self.rows.items():
            if path in self.streamed:
                current,evidence,raw=images.fingerprint(path,self.deadline)
                retained=next((r for r in self.image_evidence if r['original_path']==path),None)
                need((retained is None and evidence is None) or (retained is not None and retained['evidence']==evidence and stable(self.output/retained['path'],self.deadline,images.MAX_RETAINED_BYTES)[1]==raw),'Fresh whole-image and retained header return join required')
            else:current,_=stable(path,self.deadline)
            need(all(current[k]==expected[k] for k in ('bytes','sha256','mode','physical_identity')),'Complete physical native/header return required')
        for row in self.snapshots:need(digest(self.output/row['path'],self.deadline)==row['sha256'],'Retained provider snapshot return required')
    def view(self):
        value=dict(files=[self.rows[p] for p in sorted(self.rows)],resolutions=[self.resolutions[p] for p in sorted(self.resolutions)],snapshots=self.snapshots,total_bytes=self.total)
        if self.stream_images:value.update(image_protocol='bounded-streaming-native-v2',streamed_files=[self.streamed[p] for p in sorted(self.streamed)],image_evidence=self.image_evidence,image_total_bytes=self.image_total,retained_image_evidence_bytes=self.evidence_total)
        return value

def native_graph(census,roots,allowed_roots):
    pending=list(map(str,roots));visited=set();rows=[];apple=set();unresolved=[];packages={}
    while pending:
        lexical=pending.pop(0)
        if lexical.startswith('/usr/lib/') or lexical.startswith('/System/Library/Frameworks/'):
            apple.add(lexical);continue
        current=census.file(lexical,'native-image');physical=current['path']
        need(any(Path(physical).is_relative_to(Path(root)) for root in allowed_roots),'Selected native input stays in reviewed package/toolchain roots')
        if physical in visited:continue
        need(len(rows)<MAX_NATIVE,'Finite64-image native closure required')
        visited.add(physical)
        if census.stream_images:
            record=next((r for r in census.image_evidence if r['original_path']==physical),None);need(record is not None,'Selected native graph image requires retained architecture evidence')
            evidence=record['evidence'];raw=stable(census.output/record['path'],census.deadline,images.MAX_RETAINED_BYTES)[1];images.validate(raw,evidence,current)
            part=evidence['ranges'][-1];begin=part['retained_offset'];image=macho(raw[begin:begin+part['bytes']],census.transfer)
            need(image=={k:evidence[k] for k in ('imports','rpaths')},'Pinned import parser and retained selected-header interpretation must agree')
        else:raw=stable(physical,census.deadline)[1];image=macho(raw,census.transfer)
        rows.append(dict(current,**image))
        for imported in image['imports']:
            if imported.startswith('@loader_path/'):
                pending.append(str(Path(physical).parent/imported[len('@loader_path/'):]))
            elif imported.startswith('@rpath/'):
                candidates=[]
                for rpath in image['rpaths']:
                    base=rpath.replace('@loader_path',str(Path(physical).parent))
                    if Path(base).is_absolute() and (Path(base)/imported[len('@rpath/'):]).exists():candidates.append(str(Path(base)/imported[len('@rpath/'):]))
                if len(set(candidates))==1:pending.extend(candidates)
                else:unresolved.append(dict(image=physical,imported=imported,candidates=candidates))
            elif imported.startswith('/'):pending.append(imported)
            else:unresolved.append(dict(image=physical,imported=imported,candidates=[]))
    return dict(images=rows,Apple_imports=sorted(apple),unresolved=unresolved,frontier=pending,dyld_shared_cache_bytes_qualified=False)

def stable_view(value):
    selected=value['selected'];census=value['census']
    files=[]
    for row in census['files']:
        if row['kind'].endswith('receipt'):files.append(dict(path=row['path'],kind=row['kind'],stable_receipt=row['stable_receipt'],mode=row['mode']))
        else:files.append({k:row[k] for k in ('path','bytes','sha256','mode','kind')})
    graph=dict(value['native_graph']);graph['images']=[{k:r[k] for k in ('path','bytes','sha256','mode','imports','rpaths')} for r in graph['images']]
    result=dict(protocol='atlas-native-buffer-stable-inputs-v1',sources=value['sources'],platform=value['platform'],
        selected=selected,tool_native=value['tool_native_policy_view'],native_graph=graph,
        files=files,
        lexical=[dict(declared_path=r['declared_path'],resolved_path=r['resolved_path'],links=[dict(path=x['path'],target=x['target']) for x in r['links']]) for r in census['resolutions']],
        package={k:v for k,v in value['package'].items() if k!='receipt_sha256'},header_paths=value['header_paths'],search_outputs=value['search_outputs'],shim_compile_context=stable_shim_context(value['shim_compile_context']))
    if census.get('image_protocol')=='bounded-streaming-native-v2':result.update(protocol='atlas-native-buffer-stable-inputs-v2',native_header_evidence=[dict(original_path=r['original_path'],evidence=r['evidence']) for r in census['image_evidence']])
    return result

def execute_observation(args,context,started):
    deadline=started+OBSERVE_SECONDS;work_deadline=deadline-RETURN_SECONDS
    owned_root(args.output)
    output=args.output;runner=context['driver'].Runner(output);runner.deadline=work_deadline
    census=Census(output,deadline,context['transfer'],context.get('stream_images',False));result=dict(format='atlas-native-buffer-provider-observation-v2' if census.stream_images else 'atlas-native-buffer-provider-observation-v1',passed=False,execution_admitted=False,maximum_seconds=OBSERVE_SECONDS,actual_probe_executions=0,full_native_provider_acceptance=False,whole_build_memory_qualified=False,actual_target_cells_accepted=0,finalization_errors=[],phase='metadata',job_identity=context['admitted']['job_identity'],compiler_profile_sha256=context['admitted']['observed_profile_sha256'])
    if census.stream_images:census.deadline=work_deadline
    expected={k:s for k,s in COMMANDS};env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','LC_ALL','SDKROOT','DEVELOPER_DIR')};env.update(LC_ALL='C',NO_COLOR='1',CRYSTAL_WORKERS='1')
    def run(label,argv,environment=None):
        need(label==COMMANDS[len(runner.records)][0] and work_deadline-time.monotonic()>=expected[label],'Original complete metadata command reservation required')
        owned_root(output)
        census.file(str(Path(argv[0]).resolve(strict=True)),'metadata-provider')
        stdout,stderr=runner.run(label,argv,cwd=args.repository,environment=env if environment is None else environment,seconds=expected[label])
        owned_root(output)
        contract=context['contract'];contract.terminal(runner.records[-1],expected[label],output=output)
        return stdout,stderr
    try:
        need(work_deadline-time.monotonic()>=sum(expected.values())+60,'Full metadata command roster plus selected-byte census reserve required')
        for row in context['tool_native']['libraries']:census.file(row['path'],'analysis-tool-library')
        for row in context['tool_native']['packages']:
            prefix=Path(row['physical_prefix']);census.file(str(prefix/'INSTALL_RECEIPT.json'),'analysis-package-receipt');census.file(str(prefix/'.brew'/(row['name']+'.rb')),'analysis-package-formula')
        metadata_paths=context.get('metadata_paths',dict(xcrun='/usr/bin/xcrun',xcode_select='/usr/bin/xcode-select',codesign='/usr/bin/codesign',platform='/System/Library/CoreServices/SystemVersion.plist'))
        xcrun=metadata_paths['xcrun'];developer=run('developer',[metadata_paths['xcode_select'],'-p'])[0].strip()
        sdk=run('sdk',[xcrun,'--sdk','macosx','--show-sdk-path'])[0].strip();cc=run('cc-path',[xcrun,'--find','clang'])[0].strip();ld=run('ld-path',[xcrun,'--find','ld'])[0].strip()
        sdk_version=run('sdk-version',[xcrun,'--sdk','macosx','--show-sdk-version'])[0].strip();sdk_build=run('sdk-build',[xcrun,'--sdk','macosx','--show-sdk-build-version'])[0].strip()
        need(all(Path(p).is_absolute() for p in (developer,sdk,cc,ld)) and sdk_version and sdk_build,'Exact selected Xcode SDK/compiler/linker metadata required')
        cc_version=run('cc-version',[cc,'--version']);resource=run('cc-resource',[cc,'-print-resource-dir'])[0].strip()
        need(Path(resource).is_absolute(),'Absolute actual C builtin-header path required')
        shim=args.probe_packet/'buffer_shim.c';planned_output=output.parent/'native-buffer-probe'
        census.file(str(Path(sdk)/'SDKSettings.json'),'sdk-settings')
        sdk_module=load(ROOT/'sdk_sysroot.py','564108b0928c2cd6cdb5cea486162f8692ef5a37fdbf537b8763528d012788f5','capture_observed_sdk_sysroot',work_deadline)
        sdk_binding=sdk_module.capture(sdk,sdk_version,sdk_build,work_deadline);result['sdk_sysroot']=sdk_binding
        shim_context=shim_compile_context(context['probe'],str(Path(cc).resolve(strict=True)),planned_output/'private',planned_output/'buffer_shim.o',sdk_binding,work_deadline)
        result['shim_compile_context']=shim_context
        deps=run('headers',shim_context['preprocessing_argv'],shim_context['environment'])[0]
        compile_search=run('cc-search',shim_context['original_argv']+['-###'],shim_context['environment'])
        link_search=run('link-search',[cc,'-isysroot',sdk,'-###','-x','c','/dev/null','-o','/dev/null'],shim_context['environment'])
        prefix=Path((args.sdk_evidence/'brew-root.stdout.txt').read_text().strip());llvm=prefix/'opt/llvm@21';config=llvm/'bin/llvm-config'
        need(run('llvm-version',[str(config),'--version'])[0]=='21.1.8\n','Exact selected LLVM21.1.8 required')
        library=run('llvm-library',[str(config),'--link-shared','--libfiles'])[0].strip();need('\n' not in library and Path(library).is_absolute() and library.endswith('.dylib'),'One exact actual shared LLVM image required')
        package_raw=run('llvm-package',[str(prefix/'bin/brew'),'info','--json=v2','llvm@21'])[0];package=decode(package_raw)['formulae'];need(len(package)==1,'One actual LLVM package metadata record required');package=package[0]
        for label,path in [('cc-signature',cc),('ld-signature',ld),('sdk-signature',str(Path(developer).parents[1]))]:
            stdout,stderr=run(label,[metadata_paths['codesign'],'--display','--verbose=4',path]);need(stdout or stderr,'Retained actual Apple toolchain signature provenance required')
            run(label+'-verify',[metadata_paths['codesign'],'--verify','--strict','--verbose=2',path])
        need(package['versions']['stable']=='21.1.8' and len(package['installed'])==1 and package['installed'][0]['version']==llvm.resolve(strict=True).name,'Actual selected LLVM package version/opt join required')
        llvm_prefix=llvm.resolve(strict=True);receipt=census.file(str(llvm_prefix/'INSTALL_RECEIPT.json'),'llvm-receipt');formula=census.file(str(llvm_prefix/'.brew/llvm@21.rb'),'llvm-formula')
        receipt_value=decode(stable(receipt['path'],deadline)[1]);need(receipt_value['source']['versions']['stable']=='21.1.8' and receipt_value['arch']=='arm64','Actual LLVM receipt source/version/architecture required')
        selected=dict(cc=census.file(cc,'cc')['path'],llvm_library=census.file(library,'llvm-image')['path'],linker=census.file(ld,'linker')['path'],developer=developer,sdk=sdk,resource=resource)
        result['phase']='headers';headers=header_paths(deps);need(str(shim) in headers,'Preprocessor must observe the exact frozen shim')
        for path in headers:
            if path==str(shim):continue
            resolved=Path(path).resolve(strict=True);need(resolved.is_relative_to(Path(sdk).resolve(strict=True)) or resolved.is_relative_to(Path(resource).resolve(strict=True)),'Actual C headers stay inside selected SDK/builtin roots');census.file(path,'header')
        for path,kind in [(Path(sdk)/'SDKSettings.json','sdk-settings'),(Path(sdk)/'usr/lib/libSystem.tbd','sdk-linker-stub'),(Path(metadata_paths['platform']),'Apple-platform')]:census.file(str(path),kind)
        # Clang -### is an actual no-execution driver trace, retained in full.
        need(sdk in ''.join(compile_search) and sdk in ''.join(link_search) and ld in ''.join(link_search),'Driver traces must expose the same selected SDK and linker')
        result['phase']='native-closure';graph=native_graph(census,[library,cc,ld],[prefix/'Cellar',Path(cc).resolve().parents[2],Path(ld).resolve().parents[2]])
        result['native_graph']=graph
        need(not graph['unresolved'] and not graph['frontier'],'Complete selected file closure required; Apple shared-cache scope remains separately unqualified')
        for image in graph['images']:
            path=Path(image['path'])
            if path.is_relative_to(prefix/'Cellar'):
                relative=path.relative_to(prefix/'Cellar');root=prefix/'Cellar'/relative.parts[0]/relative.parts[1]
                census.file(str(root/'INSTALL_RECEIPT.json'),'native-package-receipt');census.file(str(root/'.brew'/(relative.parts[0]+'.rb')),'native-package-formula')
        result.update(selected=selected,header_paths=headers,package=dict(name='llvm@21',version='21.1.8',pkg_version=llvm_prefix.name,receipt_sha256=receipt['sha256'],formula_sha256=formula['sha256']),platform=dict(system=platform.system(),machine=platform.machine(),release=platform.release(),image_os=context['admitted']['runner']['image_os'],image_version=context['admitted']['runner']['image_version'],sdk_version=sdk_version,sdk_build=sdk_build),native_graph=graph,tool_native_policy_view=context['transfer'].policy_view(context['tool_native']),sources=dict(observer=args.packet_sha256,transfer=TRANSFER_SHA,core=CORE_SHA,probe=args.probe_packet_sha256,sdk_lock=context['admitted']['runner']['source_lock_sha256']),search_outputs={k:sha((output/(k+'.stdout.txt')).read_bytes()+(output/(k+'.stderr.txt')).read_bytes()) for k in ('cc-version','cc-resource','headers','cc-search','link-search','cc-signature','cc-signature-verify','ld-signature','ld-signature-verify','sdk-signature','sdk-signature-verify')},census=census.view())
        result['link_trace_normalization']=link_trace(*link_search,shim_context['environment'].get('TMPDIR','/tmp'),ld);result['search_outputs']['link-search']=result['link_trace_normalization']['semantic_sha256']
        result['stable_view']=stable_view(result);result['stable_view_sha256']=sha(canonical(result['stable_view']));result['passed']=True
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        census.deadline=deadline
        result['partial_census']=census.view();result['commands']=runner.records;result['groups']=runner.group_observations;result['writers_confirmed_retired']=runner.writers_confirmed_retired
        try:
            need(runner.writers_confirmed_retired and len(runner.records)==len(runner.group_observations),'Complete original metadata writer/group return required')
            for record,observation in zip(runner.records,runner.group_observations):context['contract'].terminal(record,expected[record['label']],output=output,observation=observation)
        except BaseException as error:result['finalization_errors'].append(type(error).__name__+': '+str(error));result['passed']=False
        returned=True
        for label,check in [('source/SDK/tools',lambda:context['check'](deadline)),('native/header/alias/snapshots',census.verify),('observed SDK directory/settings',lambda:sdk_module.verify(result['sdk_sysroot'],deadline) if 'sdk_sysroot' in result else None),('raw aggregate',lambda:need(sum(p.stat().st_size for p in output.glob('*.txt'))<=MAX_RAW,'Aggregate8-MiB metadata raw ceiling required')),('shim compile environment',lambda:need('shim_compile_context' not in result or result['shim_compile_context']==shim_compile_context(context['probe'],result['shim_compile_context']['original_argv'][0],Path(result['shim_compile_context']['planned_private']),Path(result['shim_compile_context']['original_argv'][-1]),result.get('sdk_sysroot'),deadline),'Original planned shim compile/environment return required'))]:
            try:check()
            except BaseException as error:returned=False;result['finalization_errors'].append(label+': '+type(error).__name__+': '+str(error));result['passed']=False
        result['source_provider_return_accepted']=returned
        result['private_snapshot_return_accepted']=returned
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>OBSERVE_SECONDS:result['passed']=False;result['finalization_errors'].append('Complete360-second observation horizon exceeded')
        result['complete']=result['passed'];write(output/'OBSERVATION.json',result)
    return 0 if result['passed'] else 2

def validate_image_census(root,value,deadline,physical=False):
    census=value['census'];streaming=value['format']=='atlas-native-buffer-provider-observation-v2'
    if not streaming:need('image_protocol' not in census,'Legacy full-byte observations keep their exact census protocol');return
    need(census.get('image_protocol')=='bounded-streaming-native-v2','Explicit streaming image census protocol required')
    rows=census['streamed_files'];need(type(rows) is list and 0<len(rows)<=MAX_NATIVE and len({r['path'] for r in rows})==len(rows),'Unique finite complete-image roster required')
    files={r['path']:r for r in census['files']};need(len(files)==len(census['files']),'Unique complete physical file roster required');remaining=images.MAX_IMAGE_TOTAL
    for row in rows:
        need(row==files.get(row['path']) and row['digest_scope']=='complete-physical-file','Whole-image digest meaning and physical census join required');images.admit_size(row['bytes'],remaining);remaining-=row['bytes']
    need(census['image_total_bytes']==images.MAX_IMAGE_TOTAL-remaining,'Exact aggregate complete-image byte count required')
    evidence_rows=census['image_evidence'];need(len(evidence_rows)==len({r['original_path'] for r in evidence_rows})<=MAX_NATIVE,'Unique finite native header evidence roster required');by_path={r['path']:r for r in rows};expected={r['path'] for r in rows if r['image_format']=='macho-header-v1'}
    need({r['original_path'] for r in evidence_rows}==expected and all(r['image_format']=='macho-header-v1' or (r['image_format']=='non-macho-metadata-provider' and r['kind']=='metadata-provider') for r in rows),'Complete selected native architecture evidence coverage required');total=0
    for record in evidence_rows:
        name=PurePosixPath(record['path']);need(str(name)==record['path'] and record['path'].startswith('provider-headers/') and name.suffix=='.bin' and not name.is_absolute() and '..' not in name.parts,'Contained positive native header evidence path required')
        evidence=record['evidence'];need(type(evidence['retained_bytes']) is int and 0<evidence['retained_bytes']<=images.MAX_RETAINED_BYTES and total+evidence['retained_bytes']<=images.MAX_RETAINED_TOTAL,'Per-image and aggregate retained evidence admission required before reading');total+=evidence['retained_bytes']
        raw=stable(root/name,deadline,images.MAX_RETAINED_BYTES)[1];images.validate(raw,evidence,by_path[record['original_path']])
    need(total==census['retained_image_evidence_bytes'],'Exact aggregate retained-header byte count required')
    evidence_map={r['original_path']:r['evidence'] for r in evidence_rows}
    for row in value['native_graph']['images']:
        need(row['path'] in evidence_map and all(row[k]==files[row['path']][k] for k in ('bytes','sha256','mode','physical_identity')) and all(row[k]==evidence_map[row['path']][k] for k in ('imports','rpaths')),'Whole-image/native-graph/retained-header interpretation join required')
    if physical:
        replay=Census(root,deadline,None,True);replay.rows=files;replay.resolutions={r['declared_path']:r for r in census['resolutions']};replay.snapshots=census['snapshots'];replay.streamed=by_path;replay.image_evidence=evidence_rows
        # The physical replay uses the same externally pinned resolver as production.
        transfer_path=ROOT.parent/'grant_dirty_transition/proof_tool_transfer.py'
        if not transfer_path.exists():transfer_path=ROOT.parents[1]/'grant_dirty_tool_transfer_v103/proof_tool_transfer.py'
        replay.transfer=load(transfer_path,TOOL_HELPER_SHA,'streaming_native_return_resolver',deadline);replay.verify()

def admit_observation(root,expected,absolute_deadline=None,private_snapshots=True):
    deadline=time.monotonic()+POLICY_SECONDS
    if absolute_deadline is not None:deadline=min(deadline,absolute_deadline)
    raw=stable(root/'OBSERVATION.json',deadline,8*2**20)[1];need(sha(raw)==expected,'Exact externally selected observation receipt required');value=decode(raw)
    need(value['format'] in ('atlas-native-buffer-provider-observation-v1','atlas-native-buffer-provider-observation-v2') and value['passed'] is True and value['complete'] is True and value['execution_admitted'] is False and value['source_provider_return_accepted'] is True and value['writers_confirmed_retired'] is True and value['finalization_errors']==[],'Complete returned observation-only receipt required')
    need(type(value['elapsed_seconds']) in (int,float) and math.isfinite(value['elapsed_seconds']) and 0<=value['elapsed_seconds']<=OBSERVE_SECONDS,'Original finite observation return horizon required')
    sdk=load(ROOT/'sdk_sysroot.py','564108b0928c2cd6cdb5cea486162f8692ef5a37fdbf537b8763528d012788f5','read_observed_sdk_sysroot',deadline);sdk.metadata(value['sdk_sysroot'])
    binding=value['sdk_sysroot'];need(binding['path']==(root/'sdk.stdout.txt').read_text().strip() and binding['version']==(root/'sdk-version.stdout.txt').read_text().strip() and binding['build']==(root/'sdk-build.stdout.txt').read_text().strip(),'Exact raw observed SDK path/version/build join required')
    settings=[row for row in value['census']['files'] if row['path']==binding['settings']['path']];need(len(settings)==1 and all(settings[0][key]==binding['settings'][key] for key in ('bytes','sha256','mode','physical_identity')),'Exact observed SDK settings census join required')
    need(value['shim_compile_context'].get('sdk_sysroot')==binding and value['shim_compile_context']['original_argv'][1:3]==['-isysroot',binding['path']],'Exact observed SDK and C compile context receipt join required')
    need(value['shim_compile_context']['preprocessing_argv']==sdk.preprocessing_argv(value['shim_compile_context']['original_argv']),'Complete mechanically derived observed header argv required')
    records={row['label']:row for row in value['commands']};need(records['headers']['arguments']==value['shim_compile_context']['preprocessing_argv'] and records['cc-search']['arguments']==value['shim_compile_context']['original_argv']+['-###'] and records['link-search']['arguments']==[(root/'cc-path.stdout.txt').read_text().strip(),'-isysroot',binding['path'],'-###','-x','c','/dev/null','-o','/dev/null'],'Exact observed SDK header/compile/link-search command joins required')
    need(value['stable_view']==stable_view(value) and value['stable_view_sha256']==sha(canonical(value['stable_view'])),'Exact complete stable review view required')
    need([r['label'] for r in value['commands']]==[r[0] for r in COMMANDS] and len(value['groups'])==len(COMMANDS),'Complete20-command observation roster required')
    contract=load(ROOT/'inputs/command_contract.py','33418b91a8ed01e0d3b442781fb5c7ebdbfbb32927e5caecb9747251d9dd52c9','provider_observation_terminal_reader',deadline)
    need(decode(stable(root/'COMMANDS.json',deadline,MAX_RAW)[1])==value['commands'],'Exact persisted original command journal required')
    for record,group,(_,seconds) in zip(value['commands'],value['groups'],COMMANDS):
        need(record['maximum_seconds']==seconds,'Original complete per-command maximum required');contract.terminal(record,seconds,output=root,observation=group)
    need(value['link_trace_normalization']==link_trace((root/'link-search.stdout.txt').read_text(),(root/'link-search.stderr.txt').read_text(),value['shim_compile_context']['environment'].get('TMPDIR','/tmp'),(root/'ld-path.stdout.txt').read_text().strip()),'Exact narrowly normalized scratch-role/raw trace join required')
    for row in value['census']['snapshots']:
        rel=PurePosixPath(row['path']);need(str(rel)==row['path'] and row['path'].startswith('provider-bytes/') and not rel.is_absolute() and '..' not in rel.parts,'Contained positive selected snapshot required')
        if private_snapshots:
            observed,_=stable(root/rel,deadline);need(observed['sha256']==row['sha256'] and observed['bytes']==row['bytes'],'Exact retained selected source/provider bytes required')
    need(value.get('private_snapshot_return_accepted') is True,'Complete private native/header replay return attestation required')
    need(value['native_graph']['unresolved']==[] and value['native_graph']['frontier']==[] and value['full_native_provider_acceptance'] is False and value['whole_build_memory_qualified'] is False and type(value['actual_probe_executions']) is int and value['actual_probe_executions']==0,'Selected closed-file/Apple platform/whole-build scopes required')
    validate_image_census(root,value,deadline,physical=private_snapshots)
    return value

def public_snapshot(row,value):
    """Publish the exact licensed LLVM image, prior tool-image scope and package metadata."""
    if row['original_path']==value.get('selected',{}).get('llvm_library'):return True
    if row['kind']=='analysis-tool-library':return True
    return row['kind'].endswith('receipt') or row['kind'].endswith('formula')

def physical_public_files(root):
    need(root.resolve(strict=True)==root and stat.S_ISDIR(root.lstat().st_mode),'Physical ordinary public root required');pending=[root];files=set();count=0;directories={}
    while pending:
        directory=pending.pop();before=identity(directory)
        need(stat.S_ISDIR(before[2]),'Physical ordinary public directory required');directories[directory]=before
        for path in sorted(directory.iterdir()):
            count+=1;need(count<=2048,'Finite complete public physical traversal required');mode=path.lstat().st_mode
            if stat.S_ISDIR(mode):pending.append(path)
            else:need(stat.S_ISREG(mode) and path.lstat().st_nlink==1,'Public projection contains ordinary single-link regular files and physical directories');files.add(str(path.relative_to(root)))
        need(identity(directory)==before,'Stable physical public directory roster required')
    need(root.resolve(strict=True)==root and all(identity(directory)==before for directory,before in directories.items()),'Complete original public root/directory identity return required')
    return files

def admit_public_projection(root,expected):
    deadline=time.monotonic()+120
    manifest=stable(ROOT/'SOURCE_PINS.json',deadline,2**20)[0]
    protected=protect(ROOT,'SOURCE_PINS.json',manifest['sha256'],32,deadline)
    source_before={path:stable(path,deadline)[0] for path in protected}
    need(source_before[ROOT/'SOURCE_PINS.json']==manifest and all(source_before[path]['sha256']==pin for path,pin in protected.items()),'Exact original admitted reader source identities required')
    actual=physical_public_files(root);root_before=identity(root)
    preview,raw=stable(root/'OBSERVATION.json',deadline,MAX_RAW);need(preview['sha256']==expected,'Exact externally selected public observation required')
    format=decode(raw)['format'];need(format in ('atlas-native-buffer-provider-observation-v1','atlas-native-buffer-provider-observation-v2'),'Known bounded original public protocol required')
    ceiling=160*2**20 if format=='atlas-native-buffer-provider-observation-v2' else MAX_TOTAL+16*2**20
    need(sum(identity(root/name)[3] for name in actual)<=ceiling,'Complete original public byte admission required before return capture')
    public_before={name:stable(root/name,deadline)[0] for name in sorted(actual)}
    need(public_before['OBSERVATION.json']==preview,'Exact original public observation identity required')
    value=admit_observation(root,expected,deadline,private_snapshots=False)
    projection=decode(stable(root/'PUBLIC_PROJECTION.json',deadline,MAX_RAW)[1])
    need(projection['format']=='atlas-native-buffer-provider-public-projection-v1' and projection['observation_sha256']==expected and projection['private_replay_return_attested'] is True,'Exact public metadata/private replay join required')
    expected_rows=[dict(row,visibility='public-retained' if public_snapshot(row,value) else 'private-fingerprint-only') for row in value['census']['snapshots']]
    need(projection['snapshots']==expected_rows,'Complete exact public/private selected input roster required')
    evidence_rows=value['census'].get('image_evidence',[]);need(projection.get('native_header_evidence',[])==evidence_rows,'Complete bounded public header evidence join required')
    for row in expected_rows:
        if row['visibility']=='public-retained':
            observed,_=stable(root/row['path'],deadline);need(observed['sha256']==row['sha256'] and observed['bytes']==row['bytes'],'Exact selected public native/package byte identity required')
        else:need(not (root/row['path']).exists(),'Apple/private selected snapshots remain in the private replay workspace')
    need(stable(root/'LLVM_LICENSE.TXT',deadline,2**20)[1]==stable(ROOT/'inputs/LLVM_LICENSE.TXT',deadline,2**20)[1],'Exact pinned LLVM distribution license required')
    names={'OBSERVATION.json','PUBLIC_PROJECTION.json','LLVM_LICENSE.TXT','COMMANDS.json'}|{label+'.'+stream+'.txt' for label,_ in COMMANDS for stream in ('stdout','stderr')}|{r['path'] for r in expected_rows if r['visibility']=='public-retained'}|{r['path'] for r in evidence_rows}
    stage=decode(stable(root/'PUBLIC_STAGE.json',deadline,MAX_RAW)[1]);need(stage['format']=='atlas-native-buffer-provider-public-stage-v1' and stage['execution_admitted'] is False and stage['complete_observation'] is True and {r['path'] for r in stage['files']}==names and len(stage['files'])==len(names),'Exact positive public projection file roster required')
    for row in stage['files']:
        observed,_=stable(root/row['path'],deadline);need(observed['bytes']==row['bytes'] and observed['sha256']==row['sha256'],'Complete positive projection hash/size joins required')
    need(actual==physical_public_files(root)==names|{'PUBLIC_STAGE.json'},'Exact physical public projection roster required')
    for name,original in public_before.items():need(stable(root/name,deadline)[0]==original,'Complete original public bytes/hash/physical return required')
    for path,original in source_before.items():need(stable(path,deadline)[0]==original,'Complete original public reader source return required')
    need(identity(root)==root_before and all(identity(root/name)==row['physical_identity'] for name,row in public_before.items()) and all(identity(path)==row['physical_identity'] for path,row in source_before.items()),'Complete final public/source physical identity return required')
    clock(deadline);return value

def materialize(args,context,started):
    deadline=started+POLICY_SECONDS
    owned_root(args.output)
    current=admit_observation(args.observation,args.observation_sha256,deadline)
    need(current['job_identity']==context['admitted']['job_identity'] and current['compiler_profile_sha256']==context['admitted']['observed_profile_sha256'],'Current observation must belong to this fresh SDK job/profile')
    need(current['sources']==dict(observer=args.packet_sha256,transfer=TRANSFER_SHA,core=CORE_SHA,probe=args.probe_packet_sha256,sdk_lock=context['admitted']['runner']['source_lock_sha256']),'Exact current observer/transfer/probe/SDK source joins required')
    need(current['tool_native_policy_view']==context['transfer'].policy_view(context['tool_native']),'Exact current selected analysis-tool native view required')
    raw=stable(args.decision,deadline,2**20)[1];need(sha(raw)==args.decision_sha256,'Externally pinned independent reviewer decision required');decision=decode(raw)
    need(decision['format']=='atlas-native-buffer-stable-review-decision-v1' and decision['execution_admitted'] is True and decision['scope']=='native-buffer-and-analysis-tools-only','Positive scoped reviewer admission required')
    for field in ('Apple_platform_code_loading_reviewed','compiler_driver_search_policy_reviewed','selected_native_closure_reviewed'):need(decision[field] is True,'Explicit native/platform/driver review required: '+field)
    need(re.fullmatch('[0-9a-f]{64}',decision['independent_review_sha256']) is not None and re.fullmatch('[0-9a-f]{64}',decision['origin_observation_sha256']) is not None,'Exact independently retained review/origin identities required')
    need(decision['stable_view']==current['stable_view'] and decision['stable_view_sha256']==current['stable_view_sha256'],'Fresh-run stable native/source/platform inputs must equal the independently reviewed view')
    census=Census(args.observation,deadline,context['transfer'],current['format']=='atlas-native-buffer-provider-observation-v2');census.rows={r['path']:r for r in current['census']['files']};census.resolutions={r['declared_path']:r for r in current['census']['resolutions']};census.snapshots=current['census']['snapshots'];census.streamed={r['path']:r for r in current['census'].get('streamed_files',[])};census.image_evidence=current['census'].get('image_evidence',[]);census.verify()
    native=[{k:r[k] for k in ('path','bytes','sha256','mode')} for r in current['census']['files'] if r['kind']!='header']
    headers=[{k:r[k] for k in ('path','bytes','sha256','mode','physical_identity')} for r in current['census']['files'] if r['kind']=='header']
    need(0<len(native)<=MAX_NATIVE and len(headers)<=MAX_HEADERS,'Original selected-input and separately bounded header rosters required')
    aliases={x['path']:dict(path=x['path'],target=x['target'],resolved_path=str(Path(x['path']).resolve(strict=True))) for r in current['census']['resolutions'] for x in r['links']}
    need(len(aliases)<=MAX_ALIASES,'Original128-alias policy ceiling required')
    admission=context['admitted'];policy=dict(format='atlas-native-buffer-provider-policy-v1',execution_admitted=True,scope='native-buffer-ownership-probe-only',compiler_profile_sha256=admission['observed_profile_sha256'],compiler_wrapper_sha256=admission['providers']['compiler_wrapper']['sha256'],compiler_backend_sha256=admission['providers']['compiler_backend']['sha256'],llvm_version='21.1.8',llvm_source_commit='2078da43e25a4623cab2d0d60decddf709aaea28',selected_native_closure_reviewed=True,compiler_driver_search_policy_reviewed=True,native_files=native,auxiliary_header_files=headers,aliases=list(aliases.values()),cc=current['selected']['cc'],llvm_library=current['selected']['llvm_library'],independent_decision_sha256=args.decision_sha256,current_observation_sha256=args.observation_sha256,job_identity=admission['job_identity'],full_native_provider_acceptance=False,whole_build_memory_qualified=False)
    policy['shim_compile_context']=current['shim_compile_context']
    policy['sdk_sysroot']=current['sdk_sysroot']
    if census.stream_images:policy['streamed_native_files']=current['census']['streamed_files'];policy['native_header_evidence']=current['census']['image_evidence']
    tool_policy=dict(format='atlas-grant-analysis-native-policy-v1',execution_admitted=True,independent_review_sha256=decision['independent_review_sha256'],expected_native=context['transfer'].policy_view(context['tool_native']),Apple_platform_code_loading_reviewed=True)
    result=dict(format='atlas-native-buffer-policy-materialization-v1',passed=False,maximum_seconds=POLICY_SECONDS,execution_admitted=False,origin_observation_sha256=decision['origin_observation_sha256'],current_observation_sha256=args.observation_sha256,reviewer_decision_sha256=args.decision_sha256,stable_view_sha256=current['stable_view_sha256'],job_identity=admission['job_identity'],compiler_profile_sha256=admission['observed_profile_sha256'],compiler_backend_sha256=admission['providers']['compiler_backend']['sha256'],sdk_binding_sha256=digest(args.sdk_evidence/'SAME_JOB_BINDING.json',deadline),finalization_errors=[],actual_target_cells_accepted=0)
    registry=None
    write(args.output/'POLICY_RESULT.json',result)
    try:
        write_bytes(args.output/'DECISION.json',raw);write(args.output/'CURRENT_SDK_JOIN.json',dict(job_identity=admission['job_identity'],observed_profile_sha256=admission['observed_profile_sha256'],providers=admission['providers'],profile=admission['profile'] if 'profile' in admission else {},sdk_binding_sha256=result['sdk_binding_sha256']))
        write(args.output/'NATIVE_POLICY.json',policy);write(args.output/'TOOL_POLICY.json',tool_policy)
        registry=context['transfer'].registry(args.tool_workspace/'tools',tool_policy,context['tool_native']);need(registry['execution_admitted'] is True,'Independently reviewed current tool registry required');write(args.output/'PROOF_TOOLS.json',registry)
        context['probe'].native_policy(args.output/'NATIVE_POLICY.json',digest(args.output/'NATIVE_POLICY.json',deadline),admission,absolute_deadline=deadline)
        context['proof'].admit_tools(args.output/'PROOF_TOOLS.json',digest(args.output/'PROOF_TOOLS.json',deadline))
        result['policies']={n:digest(args.output/n,deadline) for n in ('NATIVE_POLICY.json','TOOL_POLICY.json','PROOF_TOOLS.json')};result['passed']=result['execution_admitted']=True
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            census.verify();context['check'](deadline);need(digest(args.decision,deadline)==args.decision_sha256 and digest(args.observation/'OBSERVATION.json',deadline)==args.observation_sha256,'Exact external decision/current receipt return required')
            if result['passed']:need(all(digest(args.output/n,deadline)==h for n,h in result['policies'].items()),'Materialized policy return required')
        except BaseException as error:result['finalization_errors'].append(type(error).__name__+': '+str(error));result['passed']=result['execution_admitted']=False
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>POLICY_SECONDS:result['passed']=result['execution_admitted']=False
        # A failed materializer leaves clearly unadmitted policies; callers require RESULT.
        if not result['passed']:
            for name,value in [('NATIVE_POLICY.json',policy),('TOOL_POLICY.json',tool_policy),('PROOF_TOOLS.json',registry)]:
                p=args.output/name
                if p.exists() and value is not None:value['execution_admitted']=False;write(p,value)
        write(args.output/'POLICY_RESULT.json',result)
    return 0 if result['passed'] else 2

def main(args,started=None):
    started=time.monotonic() if started is None else started;maximum=OBSERVE_SECONDS if args.operation=='observe' else POLICY_SECONDS
    owned_root(args.output,fresh=True)
    try:
        context=admit(args,started+maximum)
        protected=protect(args.probe_packet,'SOURCE_PINS.json',args.probe_packet_sha256,64,started+maximum)
        context['probe']=load(args.probe_packet/'run_probe.py',protected[args.probe_packet/'run_probe.py'],'observed_native_probe',started+maximum)
        context['contract']=load(args.probe_packet/'vendor/command_contract.py','33418b91a8ed01e0d3b442781fb5c7ebdbfbb32927e5caecb9747251d9dd52c9','observation_original_command_contract',started+maximum)
        sys.path.insert(0,str(args.transfer_packet));context['proof']=load(args.transfer_packet/'dirty_proof.py',context['protected'][args.transfer_packet/'dirty_proof.py'],'observation_dirty_proof',started+maximum)
        context['protected'].update(protected)
        return execute_observation(args,context,started) if args.operation=='observe' else materialize(args,context,started)
    except BaseException as error:
        write(args.output/'ADMISSION_REFUSAL.json',dict(format='atlas-native-buffer-provider-admission-refusal-v1',passed=False,execution_admitted=False,error=type(error).__name__+': '+str(error),elapsed_seconds=time.monotonic()-started,actual_target_cells_accepted=0))
        return 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=('observe','materialize'))
    for name in ('repository','sdk-evidence','transfer-packet','tool-workspace','probe-packet','output'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('packet','python','probe-packet'):parser.add_argument('--'+name+'-sha256',required=True)
    for name in ('decision','observation'):parser.add_argument('--'+name,type=Path)
    for name in ('decision','observation'):parser.add_argument('--'+name+'-sha256')
    raise SystemExit(main(parser.parse_args()))
