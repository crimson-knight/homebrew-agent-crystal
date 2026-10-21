"""Direct-PID metadata sampling around an unchanged reviewed SDK Runner."""
import os,threading,time
from pathlib import Path
from source_gate import need
from vendor.command_contract import terminal
INTERVAL=1.0
MAXIMUM_SAMPLES=128
PS_SECONDS=2

def parse_ps(raw,pid,parent):
    need(type(pid) is int and type(parent) is int and pid>1 and parent>1 and len(raw.encode())<=4096,'Bounded exact direct PID metadata identity required')
    fields=raw.strip().split(None,9)
    need(len(fields)==10 and all(v.isdigit() for v in fields[:3]) and fields[8].isdigit(),'Exact direct PID/parent/group/birth/RSS/command metadata required')
    need(tuple(map(int,fields[:3]))==(pid,parent,pid),'Direct compiler parent/original-group identity differs')
    return dict(pid=pid,birth=' '.join(fields[3:8]),direct_rss_bytes=int(fields[8])*1024,command=fields[9],is_live=True)

class Observer:
    def __init__(self,driver,backend,output,deadline):
        self.driver=driver;self.backend=Path(backend);self.output=output;output.mkdir()
        self.runner=driver.Runner(output);self.runner.deadline=deadline
        self.original=driver.subprocess;self.samples=[];self.errors=[];self.thread=None;self.stop=threading.Event();self.pid=None;self.started=None
    def sample(self):
        index=len(self.samples);before=time.monotonic();label='sample-%03d'%index
        try:
            try:self.runner.run(label,['/bin/ps','-p',str(self.pid),'-o','pid=,ppid=,pgid=,lstart=,rss=,comm='],cwd=self.output,environment={'PATH':'/usr/bin:/bin','LC_ALL':'C'},seconds=PS_SECONDS)
            except Exception:
                need(self.runner.records,'Metadata launch/return failed')
            record=self.runner.records[-1];need(record['label']==label and type(record['exit_code']) is int and record['exit_code'] in (0,1) and record['expected_exit']==0,'Exact metadata present/absent status required')
            # Keep the original record unchanged; ps has a protocol-defined 0/1 result set.
            checking=dict(record,expected_exit=record['exit_code']);terminal(checking,PS_SECONDS,expected=record['exit_code'],output=self.output)
            need((self.output/(label+'.stdout.txt')).stat().st_size<=4096 and (self.output/(label+'.stderr.txt')).stat().st_size<=4096,'Finite one-PID metadata stream bound required')
            raw=(self.output/(label+'.stdout.txt')).read_text();err=(self.output/(label+'.stderr.txt')).read_text();need(not err,'Metadata stderr requires review')
            value=parse_ps(raw,self.pid,os.getpid()) if record['exit_code']==0 else dict(pid=self.pid,birth=None,direct_rss_bytes=0,is_live=False)
            if not record['exit_code']:need(Path(value['command']).name==self.backend.name,'Observed compiler command differs')
            else:need(not raw.strip(),'Absent metadata must have empty stdout')
            stdout_bytes=self.stream.stat().st_size;after=time.monotonic();value.update(monotonic_before=before,monotonic_after=after,stdout_bytes=stdout_bytes,metadata_record_index=len(self.runner.records)-1)
            self.samples.append(value)
        except Exception as error:self.errors.append(type(error).__name__+': '+str(error));self.stop.set()
    def monitor(self):
        for _ in range(MAXIMUM_SAMPLES):
            self.sample()
            if self.stop.wait(INTERVAL):return
        self.errors.append('Finite direct compiler observation sample capacity reached')
    def Popen(self,*args,**kwargs):
        is_compiler=Path(args[0][0])==self.backend
        if is_compiler:need(self.thread is None,'Exactly one direct compiler per observer required')
        process=self.original.Popen(*args,**kwargs)
        if is_compiler:
            self.pid=process.pid;self.started=time.monotonic();self.thread=threading.Thread(target=self.monitor,name='direct-compiler-observer');self.thread.start()
        return process
    def __getattr__(self,name):return getattr(self.original,name)
    def run(self,runner,label,argv,*,cwd,environment,seconds):
        self.stream=runner.output/(label+'.stdout.txt');self.driver.subprocess=self
        try:return runner.run(label,argv,cwd=cwd,environment=environment,seconds=seconds)
        finally:
            self.driver.subprocess=self.original;self.stop.set()
            if self.thread:self.thread.join(timeout=3)
    def complete(self,record):
        joined=self.thread is not None and not self.thread.is_alive()
        retired=joined and self.runner.writers_confirmed_retired and len(self.runner.records)==len(self.runner.group_observations) and all(r['writers_confirmed_retired'] is True for r in self.runner.records)
        need(retired,'Direct observer thread/original metadata groups remain unresolved')
        need(not self.errors,'Direct metadata observation refused: '+str(self.errors))
        need(self.pid==record['pid'] and self.stream.is_file(),'Exact Runner/direct compiler PID/stream join required')
        births={row['birth'] for row in self.samples if row['is_live']};need(len(births)<=1,'Direct compiler sampled birth changed')
        before=time.monotonic();stdout_bytes=self.stream.stat().st_size;after=time.monotonic()
        terminal_row=dict(pid=self.pid,birth=next(iter(births)) if births else None,direct_rss_bytes=0,is_live=False,monotonic_before=before,monotonic_after=after,stdout_bytes=stdout_bytes,terminal_after_original_group_absence=True)
        rows=self.samples+[terminal_row]
        if births:
            for row in rows:row['birth']=next(iter(births))
        return dict(raw_observations=rows,metadata_commands=self.runner.records,metadata_groups=self.runner.group_observations,writers_confirmed_retired=True,thread_joined=True,live_samples=sum(row['is_live'] for row in self.samples),first_sample_latency_seconds=(self.samples[0]['monotonic_before']-self.started) if self.samples else None,sample_interval_seconds=INTERVAL,maximum_samples=MAXIMUM_SAMPLES,overhead_qualified=False,scope='One direct compiler PID and second-resolution ps birth; sampled RSS lower bound; descendant/native/whole-build and unsampled intervals remain separate')
