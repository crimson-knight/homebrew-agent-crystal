"""Open exact original STDIN and replace this supervised PID with the admitted formatter."""
import argparse,hashlib,json,os,resource,stat,time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import capture

def perform(config_path,expected):
    raw=config_path.read_bytes();capture.need(hashlib.sha256(raw).hexdigest()==expected,'Exact formatter exec configuration required');c=json.loads(raw);capture.clock(c['body_deadline']);source=Path(c['source']['path']);backend=Path(c['backend']['path']);capture.need(capture.physical(backend,c['body_deadline'])==c['backend'],'Fresh exact formatter backend before exec required');capture.need(c['argv']==[str(backend),'tool','format','--no-color','-'] and c['stream_bytes']==131072,'Exact formatter argv and finite raw ceiling required')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);fields=[getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')];body=os.read(fd,9782);capture.need(fields==c['source']['physical_identity'] and stat.S_ISREG(s.st_mode) and len(body)==9781 and hashlib.sha256(body).hexdigest()==capture.FIXTURE_SHA==c['source']['sha256'] and [getattr(os.fstat(fd),k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')]==fields,'Exact physically opened original formatter STDIN required');os.lseek(fd,0,os.SEEK_SET)
        resource.setrlimit(resource.RLIMIT_FSIZE,(131072,131072));resource.setrlimit(resource.RLIMIT_CORE,(0,0));capture.need(list(resource.getrlimit(resource.RLIMIT_FSIZE))==[131072,131072],'Enforced exact per-stream file-size ceiling required')
        if fd!=0:os.dup2(fd,0);os.close(fd);fd=-1
        os.set_inheritable(0,True);capture.write(Path(c['record']),dict(format='atlas-hosted-original-formatter-exec-v1',pid=os.getpid(),process_group=os.getpgrp(),argv=c['argv'],backend=c['backend'],environment=c['environment'],stdin=c['source'],stdin_descriptor=0,config_sha256=expected,profile_sha256=c['profile_sha256'],file_size_limit=list(resource.getrlimit(resource.RLIMIT_FSIZE))))
        capture.need('output_identity' not in c or capture.identity(Path(c['record']).parent)[:3]==c['output_identity'],'Original output identity before formatter exec required');capture.clock(c['body_deadline']);os.execve(str(backend),c['argv'],c['environment'])
        raise RuntimeError('Formatter exec must replace its original supervised process')
    finally:
        if fd>0:os.close(fd)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--config-sha256',required=True);a=p.parse_args();perform(a.config,a.config_sha256)
