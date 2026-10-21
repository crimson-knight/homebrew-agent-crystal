"""Recognize exact reviewed public source while preserving every other credential rule."""
import hashlib
import json
import io
import tarfile
import zlib
from pathlib import PurePosixPath
from route_support import stable,need,read

CLASSIFICATION_SHA='c074e277c6cfbd17536ef8aed7c82ef4d0358376428ec8917a4a13f6d2496839'
FORMULA_SHA='a286961970e3d773b0881b50741cbcf53f26eb15d770f4863202216ecf0bec67'
LOCK_SHA='be119c899d9a7fcdf2b606df1106f2377b31852f4afdc6528e22ee07c3078d6f'
SOURCE_ARCHIVE_SHA='2c85084ce5ed4973d7f1f73987ba990b7b16381f60dd8ccc8a92b2bec1203b05'
SOURCE_COMMIT='9c1e8ec64f6be6343e90d3979bc9536c4b050292'
TAP_COMMIT='86ff489e927bf2f970abfb0f5bdca2d42f32beca'
VERSION='1.21.0-incremental-1'
PREFIX='agent-crystal/'+VERSION+'_2/share/agent-crystal/src/'
CATEGORIES=('authorization-header-credential-shape','GitHub-token-shape','credential-bearing-HTTP-URL-shape','private-key-header-shape')
PUBLIC_SOURCE={
 'compiler/crystal/tools/playground/server.cr':(14952,'8be7fb5d9070c090378451e3151ecaa4683b77752fd241fcf32a41c4b0dd3650'),
 'uri.cr':(22520,'8dd0444a0ed5798aa7910f33464b8811146d96c85da40f37b19f6b37bd0de051'),
}
PROVENANCE={'classification_sha256':CLASSIFICATION_SHA,'formula_sha256':FORMULA_SHA,'sdk_lock_sha256':LOCK_SHA,'compiler_source_archive_sha256':SOURCE_ARCHIVE_SHA,'compiler_source_commit':SOURCE_COMMIT,'source_version':VERSION,'formula_revision':2,'installed_package_version':VERSION+'_2','promoted_tap_commit':TAP_COMMIT}


def provenance(root):
    classification=root/'inputs/PUBLIC_COMPILER_SOURCE_CLASSIFICATION.json'
    need(stable(classification)[0]['sha256']==CLASSIFICATION_SHA,'Exact independently reviewed public source classification required')
    actual=read(classification)['public_pinned_source_matches']
    need(len(actual)==2 and {row['installed_source_relative_path']:(row['bytes'],row['sha256']) for row in actual}==PUBLIC_SOURCE,'Complete exact two-file public source identity roster required')
    for row in actual:
        need(row['source_archive_sha256']==SOURCE_ARCHIVE_SHA and row['source_commit']==SOURCE_COMMIT and row['source_release']=='v'+VERSION and row['actual_Mac_refused_member_identity_proven'] is False,'Exact public compiler origin and pending actual-member attribution required')
        need(row['occurrences'] and all(v['pattern_category']==CATEGORIES[2] for v in row['occurrences']),'Reviewed credential-bearing-URL category only')
    need(stable(root/'bottle_vendor/Formula/agent-crystal.rb')[0]['sha256']==FORMULA_SHA and stable(root/'bottle_vendor/test/sdk_source_lock.json')[0]['sha256']==LOCK_SHA,'Exact ordinary formula and SDK source lock required')
    alpha=read(root/'bottle_vendor/test/sdk_source_lock.json')['alpha']
    need(alpha['source_archive_sha256']==SOURCE_ARCHIVE_SHA and alpha['source_commit']==SOURCE_COMMIT and alpha['source_version']==VERSION and alpha['formula_revision']==2 and alpha['installed_package_version']==VERSION+'_2' and read(root/'inputs/ALPHA_MAIN.json')['main_commit']==TAP_COMMIT,'Exact formula-pinned compiler archive/version and promoted source provenance required')
    return dict(PROVENANCE)


def categories(raw,rules):
    need(len(rules.PATTERNS)==4,'Complete unchanged four-rule credential screen required')
    return [name for name,pattern in zip(CATEGORIES,rules.PATTERNS) if pattern.search(raw)]


def safe_path(name,rules):
    try:
        rules.public_path(name)
        need(not categories(name.encode('utf-8'),rules),'Public diagnostic path required')
        return name
    except (ValueError,RuntimeError,UnicodeError):return None


def recognizes(name,raw,matched,bottle,authority,archive_verified):
    if matched!=[CATEGORIES[2]] or authority!=PROVENANCE or archive_verified is not True or not isinstance(bottle,dict):return False
    if bottle.get('source_version')!=VERSION or type(bottle.get('formula_revision')) is not int or bottle['formula_revision']!=2 or bottle.get('tap_commit')!=TAP_COMMIT:return False
    relative=name.removeprefix(PREFIX)
    if name!=PREFIX+relative or relative not in PUBLIC_SOURCE:return False
    size,digest=PUBLIC_SOURCE[relative]
    return len(raw)==size and hashlib.sha256(raw).hexdigest()==digest


def diagnostic(archive_name,name,raw,matched,rules,classification='unreviewed-input'):
    return {'archive_path':safe_path(archive_name,rules) if archive_name is not None else None,'member_path':safe_path(name,rules),'member_path_sha256':hashlib.sha256(name.encode('utf-8')).hexdigest(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'pattern_categories':matched or ['archive-or-path-policy'],'origin_classification':classification,'matching_contents_included':False}


def inspect_member(archive_name,name,raw,rules,bottle,authority,archive_verified):
    rules.public_path(name);matched=categories(raw,rules)
    if not matched:
        rules.inspect_public_bytes(name,raw);return None
    if recognizes(name,raw,matched,bottle,authority,archive_verified):
        value=diagnostic(archive_name,name,raw,matched,rules,'exact-reviewed-public-compiler-source')
        value.update(source_archive_sha256=SOURCE_ARCHIVE_SHA,source_commit=SOURCE_COMMIT,classification_sha256=CLASSIFICATION_SHA)
        return value
    error=ValueError('Public evidence credential-shaped content refused')
    error.public_diagnostic=diagnostic(archive_name,name,raw,matched,rules)
    raise error


MAX_TAR_BYTES=272*2**20
MAX_METADATA_BYTES=8*2**20

class MetadataAllowanceReader:
    """Reserve complete physical extensions before serving standard-parser reads."""
    EXTENSIONS=frozenset((tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK,tarfile.SOLARIS_XHDTYPE))
    def __init__(self,stream):
        self.stream=stream;self.position=stream.tell();self.cache=b'';self.cache_start=0
        here=stream.tell();self.length=stream.seek(0,io.SEEK_END);stream.seek(here)
        self.admit(0,MAX_METADATA_BYTES)
    def admit(self,start,remaining):
        need(type(start) is int and type(remaining) is int and 0<=start<=self.length and 0<=remaining<=MAX_METADATA_BYTES,'Finite exact next physical metadata admission required')
        self.start=start;self.remaining=remaining;self.next_header=start;self.cache=b'';self.cache_start=0
    def tell(self):return self.position
    def seek(self,offset,whence=io.SEEK_SET):
        need(type(offset) is int and whence in (io.SEEK_SET,io.SEEK_CUR,io.SEEK_END),'Public finite metadata seek required')
        target=offset if whence==io.SEEK_SET else self.position+offset if whence==io.SEEK_CUR else self.length+offset
        need(0<=target<=self.length,'Contained physical metadata seek required');self.position=target;return target
    def allowed(self,end):
        need(max(0,end-self.start)<=self.remaining,'Finite complete physical TAR metadata capacity required before parser reading')
    def read(self,size=-1):
        need(size is None or type(size) is int,'Exact public parser byte count required')
        size=self.length-self.position if size is None or size<0 else size
        position=self.position;end=position+size;self.allowed(end)
        if self.cache and self.cache_start<=position and end<=self.cache_start+len(self.cache):
            raw=self.cache[position-self.cache_start:end-self.cache_start];self.position+=len(raw);return raw
        need(position!=self.next_header or size==512,'Exact complete standard parser header request required')
        self.stream.seek(position)
        if position==self.next_header and size==512:
            raw=self.stream.read(512);self.position+=len(raw)
            if len(raw)!=512 or raw==b'\0'*512:return raw
            header=tarfile.TarInfo.frombuf(raw,'utf-8','surrogateescape')
            need(header.type!=tarfile.GNUTYPE_SPARSE,'Reviewed contiguous archive layout requires ordinary nonsparse members')
            need(header.size>=0,'Finite nonnegative physical archive member size required')
            padded=((header.size+511)//512)*512
            if header.type in self.EXTENSIONS:
                extent=position+512+padded;self.allowed(extent)
                need(extent<=self.length,'Complete physical extension extent required before reading')
                self.cache_start=position+512;self.cache=self.stream.read(padded)
                need(len(self.cache)==padded,'Complete admitted physical extension payload required')
                self.next_header=extent
            else:self.next_header=position+512+padded
            return raw
        raw=self.stream.read(size);self.position+=len(raw);return raw

def inspect_metadata(archive_name,name,field,raw,rules,zero_padding=False):
    try:
        rules.inspect_public_bytes('archive-text-metadata.bin',raw)
        if zero_padding and any(raw):raise ValueError('Zero archive padding required')
    except ValueError as error:
        error.public_diagnostic=diagnostic(archive_name,name,raw,categories(raw,rules) or ['nonzero-archive-padding'],rules,'archive-text-metadata')
        error.public_diagnostic['metadata_field']=field
        raise


def expanded_archive(archive_name,raw,rules):
    """Inspect gzip text and retain one bounded checksum-verified TAR stream."""
    need(len(raw)>=18 and raw[:3]==b'\x1f\x8b\x08' and not raw[3]&0xe0,'Reviewed gzip container header required')
    flags=raw[3];cursor=10
    if flags&4:
        need(cursor+2<=len(raw),'Complete gzip extra length required');size=int.from_bytes(raw[cursor:cursor+2],'little');cursor+=2
        need(cursor+size<=len(raw),'Complete gzip extra metadata required');inspect_metadata(archive_name,'archive-container','gzip-extra',raw[cursor:cursor+size],rules);cursor+=size
    for flag,field in ((8,'gzip-filename'),(16,'gzip-comment')):
        if flags&flag:
            end=raw.find(b'\0',cursor,min(len(raw),cursor+65537));need(end>=0,'Bounded complete gzip text metadata required');inspect_metadata(archive_name,'archive-container',field,raw[cursor:end],rules);cursor=end+1
    if flags&2:cursor+=2
    need(cursor<=len(raw),'Complete gzip header CRC required')
    decoder=zlib.decompressobj(31);result=io.BytesIO();position=0;pending=b'';iterations=0
    while not decoder.eof:
        iterations+=1;need(iterations<=16384,'Finite gzip decompression progress required')
        if not pending and position<len(raw):pending=raw[position:position+65536];position+=len(pending)
        value=decoder.decompress(pending,2**20);pending=decoder.unconsumed_tail
        need(result.tell()+len(value)<=MAX_TAR_BYTES,'Finite complete uncompressed TAR byte capacity required before retention');result.write(value)
        need(value or pending or position<len(raw) or decoder.eof,'Complete gzip checksum/trailer required')
    trailing=decoder.unused_data+raw[position:];inspect_metadata(archive_name,'archive-container','gzip-trailing-data',trailing,rules,zero_padding=True)
    result.seek(0);return result


def archive_metadata(archive_name,raw,rules):
    """Screen effective and physically retained text, including overridden PAX."""
    expanded=None
    try:
        expanded=expanded_archive(archive_name,raw,rules);size=expanded.getbuffer().nbytes;cursor=0;metadata_bytes=0;members=0;body_bytes=0
        parser_stream=MetadataAllowanceReader(expanded)
        with tarfile.open(fileobj=parser_stream,mode='r:') as archive:
            for index,member in enumerate(archive):
                need(index<4096 and 0<=member.size<=128*2**20,'Finite original archive member count/size required');members+=1;body_bytes+=member.size;need(body_bytes<=256*2**20,'Original expanded member byte capacity required')
                need(not member.sparse and 0<=cursor<=member.offset_data<=size,'Reviewed contiguous member/header layout required')
                span=member.offset_data-cursor;need(span+metadata_bytes<=MAX_METADATA_BYTES,'Finite complete physical TAR metadata capacity required before reading');metadata_bytes+=span
                for field in ('name','linkname','uname','gname'):
                    value=getattr(member,field);need(isinstance(value,str),'Exact archive text field type required');inspect_metadata(archive_name,member.name,field,value.encode('utf-8','surrogateescape'),rules)
                for scope,headers in (('member-pax',member.pax_headers),('global-pax',archive.pax_headers)):
                    need(isinstance(headers,dict) and len(headers)<=4096,'Finite PAX text key/value roster required')
                    for key,value in headers.items():
                        need(isinstance(key,str) and isinstance(value,str),'Exact PAX text field types required')
                        inspect_metadata(archive_name,member.name,scope+'-key',key.encode('utf-8','surrogateescape'),rules);inspect_metadata(archive_name,member.name,scope+'-value',value.encode('utf-8','surrogateescape'),rules)
                expanded.seek(cursor);metadata=expanded.read(span);need(len(metadata)==span,'Complete physical header/extension text required');inspect_metadata(archive_name,member.name,'physical-header-and-extension',metadata,rules)
                body_end=member.offset_data+member.size;cursor=member.offset_data+((member.size+511)//512)*512;need(cursor<=size,'Complete physical member data and padding required');expanded.seek(body_end);padding=expanded.read(cursor-body_end);inspect_metadata(archive_name,member.name,'member-padding',padding,rules,zero_padding=True)
                parser_stream.admit(cursor,MAX_METADATA_BYTES-metadata_bytes)
            trailer_bytes=size-cursor;need(0<=trailer_bytes and metadata_bytes+trailer_bytes<=MAX_METADATA_BYTES,'Finite combined physical TAR metadata and trailer capacity required before reading');expanded.seek(cursor);trailer=expanded.read(trailer_bytes);inspect_metadata(archive_name,'archive-container','tar-trailer',trailer,rules,zero_padding=True);need(len(trailer)>=1024,'Complete zero TAR termination/trailer required')
        expanded.seek(0)
        return expanded,{'archive_path':safe_path(archive_name,rules),'members':members,'uncompressed_bytes':size,'physical_header_and_extension_bytes':metadata_bytes,'tar_trailer_bytes':trailer_bytes,'physical_metadata_bytes':metadata_bytes+trailer_bytes,'gzip_members':1,'effective_and_physical_metadata_screened':True}
    except Exception as error:
        if expanded is not None:expanded.close()
        if not hasattr(error,'public_diagnostic'):
            error.public_diagnostic=diagnostic(archive_name,'archive-container',raw,['archive-metadata-or-format-admission'],rules,'unadmitted-archive-container');error.public_diagnostic['metadata_field']='container-format-or-capacity'
        raise
