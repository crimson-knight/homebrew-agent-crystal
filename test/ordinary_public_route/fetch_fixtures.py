"""Fetch immutable public SDK and compiler source archives for guarded source controls."""
import argparse
import json
from pathlib import Path
import time
import urllib.request
from route_support import need,sha,write

FIXTURES=(('sdk58c.tar.gz','58c20acfed71e27cbcf207014f29d7c7b53dab18',8369770,'3a6d9c982ece74ef3b72eea0e2569bbfe31cd1767b3c4c7e8723d8f5f6d4b9bf'),('sdk-main.tar.gz','6aaf4f953189c051bf11543e64d4c9f3f36e2cd3',8369702,'bc00034341a83eb483c21b55d119e006c814fe23c54e1111ff42c525fcef35f6'))

FIXTURES += (('compiler-source.tar.gz','v1.21.0-incremental-1',4435186,'2c85084ce5ed4973d7f1f73987ba990b7b16381f60dd8ccc8a92b2bec1203b05'),)

def fetch(destination,opener=urllib.request.urlopen,clock=time.monotonic):
    need(destination.parent.resolve(strict=True)==destination.parent and not destination.exists(),'Fresh physical fixture destination required')
    started=clock();payload=[];rows=[]
    for name,commit,size,digest in FIXTURES:
        need(clock()-started<80,'Complete fixture fetch deadline exceeded')
        url=('https://codeload.github.com/crimson-knight/crystal/tar.gz/refs/tags/'+commit) if name=='compiler-source.tar.gz' else 'https://codeload.github.com/amberframework/memory_budget/tar.gz/'+commit
        with opener(url,timeout=10) as stream:
            raw=bytearray()
            while True:
                need(clock()-started<80,'Complete fixture fetch deadline exceeded')
                chunk=stream.read(min(1024*1024,size+1-len(raw)));raw.extend(chunk)
                need(len(raw)<=size,'Exact public fixture byte ceiling exceeded')
                if not chunk:break
        need(len(raw)==size and sha(raw)==digest,'Exact public fixture size/checksum required')
        payload.append((name,bytes(raw)));rows.append({'path':name,'url':url,'bytes':size,'sha256':digest})
    destination.mkdir()
    for name,raw in payload:(destination/name).write_bytes(raw)
    write(destination/'FETCH_RESULT.json',{'passed':True,'files':rows,'elapsed_seconds':clock()-started,'compiler_native_container_SSH_jobs':0})
    return rows

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--packet-sha256',required=True);args=parser.parse_args()
    from route_support import source_packet,revalidate
    protected=source_packet(args.packet_sha256)
    try:fetch(args.output.absolute())
    finally:revalidate(protected)
