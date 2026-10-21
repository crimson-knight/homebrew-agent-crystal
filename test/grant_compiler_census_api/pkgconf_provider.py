"""Bounded pkgconf and GC metadata joins for the separately reviewed compiler-host profile."""
from pathlib import Path
import json
import re

FORMAT='atlas-census-pkgconf-static-v1'
PKGCONF_VERSION='3.0.10'
GC_VERSION='8.2.12'
MAX_PC=65536

def need(value,message):
    if not value:raise RuntimeError(message)

def pc_version(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_PC and b'\x00' not in raw,'Bounded complete pkg-config metadata text required')
    text=raw.decode('utf-8');values=re.findall(r'^Version:[ \t]*([^\r\n]+)[ \t]*$',text,re.M)
    need(len(values)==1 and values[0].strip()==GC_VERSION,'Exact selected bdw-gc8.2.12 metadata version required')
    return values[0].strip()

def descriptor(model,prefix,files,resolutions,packages,images,pc_raw,unresolved):
    lexical=str(prefix/'bin/pkg-config');pc_lexical=str(prefix/'opt/bdw-gc/lib/pkgconfig/bdw-gc.pc');gc_lexical=str(prefix/'opt/bdw-gc/lib/libgc.1.dylib')
    by_lexical={row['declared_path']:row for row in resolutions};by_path={row['path']:row for row in files};by_image={row['path']:row for row in images}
    need(all(name in by_lexical for name in (lexical,pc_lexical,gc_lexical)),'Complete selected pkgconf/GC lexical roles required')
    executable=by_path[by_lexical[lexical]['resolved_path']];pc=by_path[by_lexical[pc_lexical]['resolved_path']];gc=by_path[by_lexical[gc_lexical]['resolved_path']]
    need(executable['mode']&0o111 and executable['path'] in by_image and gc['path'] in by_image,'Actual executable and GC native images required')
    versions={row['name']:row['stable_receipt']['source']['versions']['stable'] for row in packages}
    need(versions.get('pkgconf')==PKGCONF_VERSION and versions.get('bdw-gc')==GC_VERSION,'Exact observed selected package versions required')
    value=dict(format=FORMAT,declared_path=lexical,resolved_path=executable['path'],bytes=executable['bytes'],sha256=executable['sha256'],mode=executable['mode'],package_version=PKGCONF_VERSION,
        pcfile={key:pc[key] for key in ('path','bytes','sha256','mode')},pc_version=pc_version(pc_raw),pcfile_contents=pc_raw.decode('utf-8'),pcfiledir=str(Path(pc['path']).parent),selected_gc_library=gc['path'],
        lexical=[dict(declared_path=by_lexical[name]['declared_path'],resolved_path=by_lexical[name]['resolved_path'],links=[dict(path=x['path'],target=x['target']) for x in by_lexical[name]['links']]) for name in (lexical,pc_lexical,gc_lexical)],
        imports=by_image[executable['path']]['imports'],rpaths=by_image[executable['path']]['rpaths'],native_file_closure_covered=not unresolved,dyld_shared_cache_bytes_qualified=False)
    validate(model,value,by_path)
    return value

def validate(model,value,files=None):
    need(type(value) is dict and set(value)=={'format','declared_path','resolved_path','bytes','sha256','mode','package_version','pcfile','pc_version','pcfile_contents','pcfiledir','selected_gc_library','lexical','imports','rpaths','native_file_closure_covered','dyld_shared_cache_bytes_qualified'},'Exact versioned pkgconf metadata descriptor required')
    need(value['format']==FORMAT and value['package_version']==PKGCONF_VERSION and value['pc_version']==GC_VERSION and value['dyld_shared_cache_bytes_qualified'] is False,'Exact source-qualified pkgconf/GC metadata scope required')
    need(type(value['bytes']) is int and 0<value['bytes']<=256*2**20 and type(value['mode']) is int and value['mode']&0o111 and re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None,'Bounded exact executable pkgconf bytes/mode required')
    pc=value['pcfile'];need(type(pc) is dict and set(pc)=={'path','bytes','sha256','mode'} and type(pc['bytes']) is int and 0<pc['bytes']<=MAX_PC and type(pc['mode']) is int and re.fullmatch('[0-9a-f]{64}',pc['sha256']) is not None,'Exact selected GC pcfile source metadata required')
    need(type(value['pcfile_contents']) is str and pc_version(value['pcfile_contents'].encode())==value['pc_version'] and len(value['pcfile_contents'].encode())==pc['bytes'] and model.sha(value['pcfile_contents'].encode())==pc['sha256'],'Retained complete pcfile text/version/byte/hash interpretation required')
    for name in ('declared_path','resolved_path','pcfiledir','selected_gc_library'):need(type(value[name]) is str and Path(value[name]).is_absolute(),'Absolute selected pkgconf source roles required')
    need(Path(pc['path']).is_absolute() and value['pcfiledir']==str(Path(pc['path']).parent),'Exact physical pkg-config metadata directory required')
    need(type(value['lexical']) is list and len(value['lexical'])==3 and len({row['declared_path'] for row in value['lexical']})==3,'Three exact pkgconf/metadata/GC alias roles required')
    bindings=value['lexical'];need([(r['resolved_path']) for r in bindings]==[value['resolved_path'],pc['path'],value['selected_gc_library']] and bindings[0]['declared_path']==value['declared_path'] and value['declared_path'].endswith('/bin/pkg-config') and bindings[1]['declared_path'].endswith('/opt/bdw-gc/lib/pkgconfig/bdw-gc.pc') and bindings[2]['declared_path'].endswith('/opt/bdw-gc/lib/libgc.1.dylib'),'Exact lexical roles and selected physical metadata join required')
    for row in bindings:need(set(row)=={'declared_path','resolved_path','links'} and type(row['links']) is list and len(row['links'])<=128 and all(set(link)=={'path','target'} and type(link['path']) is str and type(link['target']) is str for link in row['links']),'Bounded exact lexical alias chain metadata required')
    need(type(value['imports']) is list and len(value['imports'])<=128 and type(value['rpaths']) is list and len(value['rpaths'])<=64 and type(value['native_file_closure_covered']) is bool,'Finite explicit complete-or-unresolved pkgconf import scope required')
    if files is not None:
        for name in (value['resolved_path'],pc['path'],value['selected_gc_library']):need(name in files,'Every selected pkgconf role joins the complete physical census')
        need(all(files[value['resolved_path']][key]==value[key] for key in ('bytes','sha256','mode')) and all(files[pc['path']][key]==pc[key] for key in ('bytes','sha256','mode')),'Exact descriptor/complete selected-byte roster required')
    return value

def environment(value):
    return dict(PKG_CONFIG_LIBDIR=value['pcfiledir'],PKG_CONFIG_PATH='',PKG_CONFIG_SYSROOT_DIR='')

def launcher(model,value,python):
    validate(model,value)
    # The original process group is inherited through execve. Every actual load
    # follows the external native decision and a fresh same-job physical census.
    return ('#!'+str(python)+'\n'+
        'import hashlib,os,stat,sys\n'+
        'p='+repr(value['resolved_path'])+'\nexpected='+repr(value['sha256'])+'\n'+
        's=os.stat(p,follow_symlinks=False)\n'+
        'if not stat.S_ISREG(s.st_mode) or s.st_size>'+str(256*2**20)+':raise SystemExit(78)\n'+
        'with open(p,"rb") as f: raw=f.read('+str(256*2**20+1)+')\n'+
        'a=os.stat(p,follow_symlinks=False)\n'+
        'if (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(a.st_dev,a.st_ino,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns) or len(raw)!=s.st_size or hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit(78)\n'+
        'os.execve(p,[p,*sys.argv[1:]],dict(os.environ))\n').encode()

def retained(model,args,context,observed,validate_observation):
    path=getattr(args,'pkgconf_observation',None);expected=getattr(args,'pkgconf_observation_sha256',None)
    need(path is not None and type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected) is not None,'Explicit prior source-bound pkgconf metadata receipt required')
    raw=model.stable(path,16*2**20);need(model.sha(raw)==expected,'Exact prior observation receipt hash required')
    value=validate_observation(model,model.decode(raw),args.packet_sha256)
    need(value['passed'] is True and value['SDK']==context['admitted'] and value['inputs']==observed,'Prior pkgconf observation must equal fresh complete same-job source/profile/alias/metadata inputs')
    return raw
