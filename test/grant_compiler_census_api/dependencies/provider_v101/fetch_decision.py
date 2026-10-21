"""Fetch one immutable public reviewer decision through an externally supplied SHA."""
import argparse
import hashlib
from pathlib import Path
import re
import time
import urllib.request

def fetch(url,expected,output):
    if not re.fullmatch(r'https://raw\.githubusercontent\.com/crimson-knight/homebrew-agent-crystal/[0-9a-f]{40}/[A-Za-z0-9_./-]+\.json',url):raise RuntimeError('Immutable public reviewer decision URL required')
    if not re.fullmatch('[0-9a-f]{64}',expected) or output.exists() or output.parent.resolve(strict=True)!=output.parent:raise RuntimeError('External exact SHA and fresh physical decision output required')
    started=time.monotonic();chunks=[];size=0
    with urllib.request.urlopen(url,timeout=5) as response:
        if response.geturl()!=url or response.status!=200:raise RuntimeError('Exact public URL/status required')
        while True:
            if time.monotonic()-started>30:raise RuntimeError('Finite decision download horizon exceeded')
            raw=response.read(min(65536,2**20+1-size))
            if not raw:break
            chunks.append(raw);size+=len(raw)
            if size>2**20:raise RuntimeError('One-MiB decision body ceiling exceeded')
    raw=b''.join(chunks)
    if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('Independently supplied reviewer SHA differs')
    output.write_bytes(raw)
    if hashlib.sha256(output.read_bytes()).hexdigest()!=expected:raise RuntimeError('Exact decision file return required')
    return dict(bytes=len(raw),sha256=expected,elapsed_seconds=time.monotonic()-started)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--url',required=True);p.add_argument('--sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(fetch(a.url,a.sha256,a.output))
