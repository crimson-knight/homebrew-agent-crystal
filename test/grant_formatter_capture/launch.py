"""Manifest-first original formatter entry point."""
import argparse,hashlib,json,runpy,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
if __name__=='__main__':
    p=argparse.ArgumentParser(add_help=False);p.add_argument('--packet-sha256',required=True);a,rest=p.parse_known_args();raw=(ROOT/'SOURCE_PINS.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=a.packet_sha256:raise RuntimeError('Exact external formatter manifest before imports required')
    for r in json.loads(raw)['files']:
        q=ROOT/r['path']
        if q.is_symlink() or len(q.read_bytes())!=r['bytes'] or hashlib.sha256(q.read_bytes()).hexdigest()!=r['sha256']:raise RuntimeError('Exact formatter source before imports required')
    sys.path.insert(0,str(ROOT));sys.argv=[str(ROOT/'capture.py'),*rest,'--packet-sha256',a.packet_sha256];runpy.run_path(str(ROOT/'capture.py'),run_name='__main__')
