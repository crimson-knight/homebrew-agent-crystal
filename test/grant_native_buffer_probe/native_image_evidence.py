"""Stream whole-image identities and retain finite ARM64 Mach-O import evidence."""
import hashlib
import os
from pathlib import Path
import stat
import struct
import time

MAX_IMAGE_BYTES=1024*2**20
MAX_IMAGE_TOTAL=4*2**30
MAX_LOAD_COMMAND_BYTES=2**20
MAX_RETAINED_BYTES=2**20+552
MAX_RETAINED_TOTAL=64*2**20
CHUNK_BYTES=2**20

def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def state(path):
    s=Path(path).lstat();return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def opened(stream):
    s=os.fstat(stream.fileno());return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def clock(deadline):need(time.monotonic()<=deadline,'Complete native-image metadata deadline required')
def admit_size(size,remaining):
    need(type(size) is int and type(remaining) is int and 0<=size<=MAX_IMAGE_BYTES and size<=remaining,'Per-image and aggregate native byte admission required before reading')

def commands(raw):
    need(len(raw)>=32 and struct.unpack_from('<II',raw)==(0xfeedfacf,0x100000c),'Selected ARM64 little-endian Mach-O header required')
    count,total=struct.unpack_from('<II',raw,16);need(0<count<=256 and 0<total<=MAX_LOAD_COMMAND_BYTES and len(raw)==32+total,'Exact bounded complete selected load commands required')
    offset=32;imports=[];rpaths=[]
    for _ in range(count):
        need(offset+8<=len(raw),'Complete load-command header required');command,length=struct.unpack_from('<II',raw,offset)
        need(length>=8 and length%4==0 and offset+length<=len(raw),'Bounded complete load command required')
        if command in (0xc,0x80000018,0x8000001f,0x20,0x80000023,0x8000001c):
            minimum=12 if command==0x8000001c else 24;need(length>=minimum,'Complete load-command path required');start=struct.unpack_from('<I',raw,offset+8)[0]
            need(minimum<=start<length,'Contained load-command path required');value=raw[offset+start:offset+length];need(b'\0' in value,'Terminated load-command path required');value=value.split(b'\0',1)[0].decode('utf-8')
            (rpaths if command==0x8000001c else imports).append(value)
        offset+=length
    need(offset==len(raw) and len(imports)==len(set(imports)) and len(rpaths)==len(set(rpaths)),'Complete unique import/rpath roster required')
    return {'imports':sorted(imports),'rpaths':rpaths}

def layout(read,size,retained_remaining=MAX_RETAINED_BYTES):
    first=read(0,min(8,size))
    if first[:4] not in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf',b'\xbe\xba\xfe\xca',b'\xbf\xba\xfe\xca'):return None,b''
    start=0;length=size;table=b'';cpu_subtype=None
    if first[:4]!=b'\xcf\xfa\xed\xfe':
        need(len(first)==8,'Complete universal Mach-O header required');endian='>' if first[:4] in (b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf') else '<';wide=first[:4] in (b'\xca\xfe\xba\xbf',b'\xbf\xba\xfe\xca')
        count=struct.unpack_from(endian+'I',first,4)[0];entry=32 if wide else 20;need(0<count<=16 and 8+count*entry<=size,'Bounded complete universal architecture table required')
        need(8+count*entry<=retained_remaining,'Aggregate universal header evidence admission required before reading');table=read(0,8+count*entry);arms=[];spans=[]
        for index in range(count):
            off=8+index*entry;cpu,subtype=struct.unpack_from(endian+'II',table,off);begin,extent=struct.unpack_from(endian+('QQ' if wide else 'II'),table,off+8);align=struct.unpack_from(endian+'I',table,off+(24 if wide else 16))[0]
            need(0<=align<=30 and begin>=len(table) and extent>=32 and begin+extent<=size and begin%(1<<align)==0,'Contained aligned universal slice required')
            if wide:need(struct.unpack_from(endian+'I',table,off+28)[0]==0,'Zero universal reserved field required')
            spans.append((begin,begin+extent))
            if cpu==0x100000c:arms.append((begin,extent,subtype))
        need(all(a[1]<=b[0] for a,b in zip(sorted(spans),sorted(spans)[1:])) and len(arms)==1,'Distinct slices and one selected ARM64 architecture required')
        start,length,cpu_subtype=arms[0]
    need(len(table)+32<=retained_remaining,'Aggregate selected header admission required before reading');header=read(start,32);need(len(header)==32 and struct.unpack_from('<II',header)==(0xfeedfacf,0x100000c),'Complete selected ARM64 header required')
    subtype=struct.unpack_from('<I',header,8)[0];need(cpu_subtype is None or subtype==cpu_subtype,'Universal architecture and selected header subtype must agree')
    count,total=struct.unpack_from('<II',header,16);need(0<count<=256 and 0<total<=MAX_LOAD_COMMAND_BYTES and 32+total<=length and len(table)+32+total<=min(MAX_RETAINED_BYTES,retained_remaining),'Selected header/load-command admission required before reading')
    selected=header+read(start+32,total);parsed=commands(selected);parts=[];retained=bytearray()
    for kind,offset,raw in ([('fat-architecture-table',0,table)] if table else [])+[('selected-header-and-load-commands',start,selected)]:
        parts.append({'kind':kind,'image_offset':offset,'bytes':len(raw),'retained_offset':len(retained),'sha256':sha(raw)});retained.extend(raw)
    raw=bytes(retained)
    return {'format':'atlas-native-image-header-evidence-v1','architecture':'arm64','cpu_type':0x100000c,'cpu_subtype':subtype,'slice_offset':start,'slice_bytes':length,'ranges':parts,'retained_bytes':len(raw),'retained_sha256':sha(raw),**parsed},raw

def fingerprint(path,deadline,remaining=MAX_IMAGE_TOTAL,retained_remaining=MAX_RETAINED_BYTES):
    p=Path(path);clock(deadline);before=state(p);need(stat.S_ISREG(before[2]),'Physical regular native image required');admit_size(before[3],remaining)
    digest=hashlib.sha256();size=0
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        need(state(p)==before and opened(stream)==before,'Exact opened native image identity required')
        while size<before[3]:
            clock(deadline);raw=stream.read(min(CHUNK_BYTES,before[3]-size));need(raw,'Complete streamed native image required');size+=len(raw);digest.update(raw)
        need(not stream.read(1),'Exact streamed native EOF required')
        def read(offset,length):
            clock(deadline);need(type(offset) is int and type(length) is int and 0<=offset<=before[3] and 0<=length<=MAX_RETAINED_BYTES and offset+length<=before[3],'Bounded contained image evidence range required before reading')
            stream.seek(offset);raw=stream.read(length);need(len(raw)==length,'Complete exact native evidence range required');return raw
        evidence,raw=layout(read,size,retained_remaining)
        clock(deadline);need(opened(stream)==before and state(p)==before and size==before[3],'Complete streamed native physical return required')
    value={'path':str(p),'bytes':size,'sha256':digest.hexdigest(),'mode':stat.S_IMODE(before[2]),'physical_identity':before,'digest_scope':'complete-physical-file'}
    if evidence is not None:evidence.update(image_bytes=size,image_sha256=value['sha256'])
    return value,evidence,raw

def validate(raw,evidence,whole):
    need(type(evidence) is dict and evidence['image_bytes']==whole['bytes'] and evidence['image_sha256']==whole['sha256'],'Whole-image identity and selected evidence join required')
    need(type(evidence['retained_bytes']) is int and len(raw)==evidence['retained_bytes']<=MAX_RETAINED_BYTES and sha(raw)==evidence['retained_sha256'],'Exact finite retained native evidence required')
    parts=evidence['ranges'];need(type(parts) is list and 1<=len(parts)<=2,'Finite exact native evidence range roster required')
    cursor=0
    for part in parts:
        need(type(part['bytes']) is int and type(part['image_offset']) is int and type(part['retained_offset']) is int and part['retained_offset']==cursor and 0<part['bytes'] and 0<=part['image_offset'] and part['image_offset']+part['bytes']<=whole['bytes'],'Exact contained native evidence offsets/lengths required')
        fragment=raw[cursor:cursor+part['bytes']];need(len(fragment)==part['bytes'] and sha(fragment)==part['sha256'],'Exact native evidence range SHA-256 required');cursor+=part['bytes']
    need(cursor==len(raw),'Complete native evidence coverage required')
    def read(offset,length):
        for part in parts:
            start=part['image_offset'];end=start+part['bytes']
            if start<=offset and offset+length<=end:
                begin=part['retained_offset']+offset-start;return raw[begin:begin+length]
        need(False,'Required image range must be present in retained evidence')
    rebuilt,again=layout(read,whole['bytes']);need(rebuilt is not None and again==raw,'Complete selected native header reconstruction required')
    expected=dict(rebuilt,image_bytes=whole['bytes'],image_sha256=whole['sha256'])
    need(evidence==expected,'Exact selected architecture/header/whole-image evidence record required')
    return rebuilt
