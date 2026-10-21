"""Verify the externally selected complete source packet before local delegation."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import runpy
import sys
ROOT=Path(__file__).resolve().parent
need=lambda value,message:None if value else (_ for _ in ()).throw(SystemExit(message))
need(sys.argv.count('--entrypoint')==1 and sys.argv.count('--packet-sha256')==1,'Select one fixed entrypoint and one source packet')
index=sys.argv.index('--entrypoint');name=sys.argv[index+1];need(name in ('run_route.py','build_bottle.py','prepare_retained.py','wait_resume.py','stage_results.py','finalize_bottle.py','fetch_fixtures.py','run_source_controls.py','hosted_entry.py'),'Fixed reviewed hosted entrypoint required')
args=sys.argv[1:index]+sys.argv[index+2:];expected=sys.argv[sys.argv.index('--packet-sha256')+1]
pins=ROOT/'SOURCE_PINS.json';need(hashlib.sha256(pins.read_bytes()).hexdigest()==expected,'Exact route packet manifest differs')
rows=json.loads(pins.read_bytes())['files'];need(1<=len(rows)<=40 and len({r['path'] for r in rows})==len(rows),'Finite complete source packet required')
for row in rows:
    relative=PurePosixPath(row['path']);need(str(relative)==row['path'] and not relative.is_absolute() and '..' not in relative.parts,'Contained source member required')
    path=ROOT/relative
    need(path.is_file() and not path.is_symlink() and path.stat().st_size==row['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],'Source member differs: '+row['path'])
sys.path.insert(0,str(ROOT));sys.argv=[str(ROOT/name),*args];runpy.run_path(str(ROOT/name),run_name='__main__')
