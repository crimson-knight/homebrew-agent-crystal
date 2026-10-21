"""Bind SDK-copied files and preserved internal symlinks before compilation."""
from pathlib import Path
import hashlib,json,os,stat

def require(value,message):
 if not value:raise RuntimeError(message)

def sha(path):
 return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def inventory(root):
 root=Path(root);rows=[];errors=[]
 if not root.is_dir() or root.is_symlink():
  return {'rows':[],'errors':['Ordinary inventory root directory is required']}
 canonical=root.resolve()
 for path in sorted(root.rglob('*'),key=lambda p:p.as_posix()):
  info=path.lstat();mode=stat.S_IMODE(info.st_mode);relative=path.relative_to(root).as_posix()
  if stat.S_ISLNK(info.st_mode):
   row={'path':relative,'kind':'symlink','mode':mode,'target':os.readlink(path)}
   try:
    resolved=path.resolve(strict=True);row['resolved_relative_path']=resolved.relative_to(canonical).as_posix()
   except (OSError,ValueError,RuntimeError) as error:
    row['resolution_error']=type(error).__name__;errors.append(relative+': internal existing symlink target is required')
   rows.append(row)
  elif stat.S_ISREG(info.st_mode):
   rows.append({'path':relative,'kind':'file','mode':mode,'bytes':info.st_size,'sha256':sha(path)})
  elif not stat.S_ISDIR(info.st_mode):
   rows.append({'path':relative,'kind':'unsupported','mode':mode});errors.append(relative+': ordinary file, directory, or internal symlink is required')
 return {'rows':rows,'errors':errors}

def rows_sha(rows):
 return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def audit_prepared_stdlib(base,prepared,overlay,manifest_path,diagnostic_path):
 base,prepared,overlay,manifest_path,diagnostic_path=map(Path,(base,prepared,overlay,manifest_path,diagnostic_path))
 source=inventory(base);actual=inventory(prepared);manifest=json.loads(manifest_path.read_text())
 expected={row['path']:dict(row) for row in source['rows']};errors=list(source['errors'])
 for entry in manifest['files']:
  path=Path(entry['file']);candidate=overlay/path
  require(not path.is_absolute() and '..' not in path.parts,'Overlay paths are package-relative')
  if not candidate.is_file() or candidate.is_symlink() or sha(candidate)!=entry['sha256']:
   errors.append(path.as_posix()+': exact ordinary overlay source is required');continue
  previous=expected.get(path.as_posix())
  if previous and previous['kind']!='file':errors.append(path.as_posix()+': overlay replaces a regular file');continue
  # FileUtils.cp keeps an existing destination mode; newly created files use source mode.
  expected[path.as_posix()]={'path':path.as_posix(),'kind':'file','mode':previous['mode'] if previous else stat.S_IMODE(candidate.stat().st_mode),'bytes':candidate.stat().st_size,'sha256':entry['sha256']}
 expected_rows=sorted(expected.values(),key=lambda row:row['path']);observed={row['path']:row for row in actual['rows']}
 missing=sorted(set(expected)-set(observed));extra=sorted(set(observed)-set(expected))
 changed=[{'path':name,'expected':expected[name],'actual':observed[name]} for name in sorted(set(expected)&set(observed)) if expected[name]!=observed[name]]
 passed=not(errors or actual['errors'] or missing or extra or changed)
 report={'schema_version':1,'passed':passed,'source_root':str(base),'prepared_root':str(prepared),'overlay_manifest_sha256':sha(manifest_path),'expected_inventory':{'rows':expected_rows,'sha256':rows_sha(expected_rows),'errors':errors},'actual_inventory':dict(actual,sha256=rows_sha(actual['rows'])),'delta':{'missing':missing,'extra':extra,'changed':changed},'scope':'Every physical regular file byte/mode and every logical internal symlink path/target/mode/resolution; directory symlinks retain their source identity and their referenced bytes remain in the physical file roster'}
 diagnostic_path.parent.mkdir(parents=True,exist_ok=True);diagnostic_path.write_text(json.dumps(report,indent=2)+'\n')
 require(passed,'Complete SDK-prepared stdlib inventory differs; preserved diagnostics: '+str(diagnostic_path))
 return {'files':[{'file':r['path'],'sha256':r['sha256']} for r in expected_rows if r['kind']=='file'],'inventory':expected_rows,'sha256':rows_sha(expected_rows),'counter_overlay_manifest_sha256':sha(manifest_path),'scope':'Exact base stdlib physical files and internal symlinks plus four qualified SDK runtime overlay files; counter flag remains absent as in prior no-stats fixtures'}
