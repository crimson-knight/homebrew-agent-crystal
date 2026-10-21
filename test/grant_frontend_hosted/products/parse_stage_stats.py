"""Parse pinned compiler GC-heap stage endpoints without promoting them into RSS peaks."""
from pathlib import Path
import hashlib,json,math,re
STAGES=('Parse','Semantic (top level)','Semantic (new)','Semantic (type declarations)','Semantic (abstract def check)','Semantic (restrictions augmenter)','Semantic (ivars initializers)','Semantic (cvars initializers)','Semantic (main)','Semantic (cleanup)','Semantic (recursive struct check)','Codegen (crystal)','Codegen (bc+obj)','Codegen (linking)','dsymutil')
DURATION=r'(\d+):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?'
def require(v,m):
 if not v:raise RuntimeError(m)
def parse_stats(raw):
 require(type(raw) is bytes and len(raw)<1024*1024,'Finite compiler stats bytes required')
 text=raw.decode('utf-8');raw_offset=0;rows=text.replace('\r','\n').splitlines();index=0;observed=[]
 for expected in STAGES:
  require(index<len(rows) and rows[index]==(expected+':').ljust(34),'Exact stage-start order differs: '+expected);index+=1
  require(index<len(rows),'Compiler stage completion is truncated')
  match=re.fullmatch(re.escape((expected+':').ljust(34))+r' '+DURATION+r' \(( *)(\d+\.\d{2})MB\)',rows[index]);require(match is not None,'Exact stage-completion grammar differs: '+expected)
  hours,minutes,seconds,fraction,padding,heap_text=match.groups();require(padding+heap_text==heap_text.rjust(7),'Exact seven-column heap padding differs');duration=int(hours)*3600+int(minutes)*60+int(seconds)+(float('0.'+fraction) if fraction else 0);heap=float(heap_text)
  require(math.isfinite(heap) and heap>=0 and math.isfinite(duration) and duration>=0,'Stage duration/heap must be finite positive')
  completion_bytes=rows[index].encode('utf-8');position=raw.find(completion_bytes,raw_offset);require(position>=0,'Exact raw completion byte binding differs');raw_offset=position+len(completion_bytes)+1
  require(raw[raw_offset-1:raw_offset]==b'\n','Exact completion newline binding differs')
  observed.append({'completion_stdout_byte_end':raw_offset,'stage':expected,'duration_seconds':duration,'compiler_gc_heap_mib_reported':heap,'raw_completion_line':rows[index],'endpoint_scope':'GC.stats.heap_size after the phase; rounded to0.01MiB; excludes a guarantee about live objects, LLVM/native allocations or within-phase peaks'});index+=1
 require(rows[index:]==['','Codegen (bc+obj):',' - no previous .o files were reused'],'Exact cold-codegen footer differs')
 return {'passed':True,'stages':observed,'compiler_reported_heap_scope':'Stage-completion GC heap capacity; binary MiB labeled MB by pinned compiler','raw_stdout_sha256':hashlib.sha256(raw).hexdigest(),'heap_peak_qualified':False,'isolated_compiler_peak_qualified':False,'whole_build_provider_qualified':False}
def associate_observed_intervals(parsed,observations):
 require(type(observations) is list and observations,'Actual observer rows required')
 previous=-1;last_size=0;endpoints=[]
 for row in observations:
  require(row['monotonic_before']<=row['monotonic_after'] and row['monotonic_before']>=previous,'Observer clock domain/order differs')
  require(type(row['stdout_bytes']) is int and row['stdout_bytes']>=last_size,'Observed stdout size regressed')
  require(type(row['pid']) is int and row['pid']>1 and row['birth'],'Actual compiler PID/birth required')
  require(type(row['direct_rss_bytes']) is int and row['direct_rss_bytes']>=0,'Typed sampled RSS required')
  previous=row['monotonic_before'];last_size=row['stdout_bytes']
  endpoints.append(row)
 require(len({(r['pid'],r['birth']) for r in observations})==1,'One directly executed compiler lifetime required')
 buckets={}
 for stage in parsed['stages']:
  found=next((i for i,row in enumerate(observations) if row['stdout_bytes']>=stage['completion_stdout_byte_end']),None)
  require(found is not None,'Observed stdout never reached a recorded phase completion')
  buckets.setdefault(found,[]).append(stage['stage'])
 intervals=[];previous_end=0
 for end,stages in sorted(buckets.items()):
  samples=observations[previous_end:end+1]
  intervals.append({'possibly_during_or_near_completion_of':stages,'lower_observed_monotonic':observations[previous_end]['monotonic_before'],'upper_observed_monotonic':observations[end]['monotonic_after'],'samples':len(samples),'sampled_direct_rss_max_bytes':max(r['direct_rss_bytes'] for r in samples),'coalesced_phase_completions':len(stages)>1})
  previous_end=end
 return {'passed':True,'phase_intervals':intervals,'samples':len(observations),'sampled_direct_pid_peak_bytes':max(r['direct_rss_bytes'] for r in observations),'compiler_pid':observations[0]['pid'],'compiler_birth':observations[0]['birth'],'association_scope':'Intervals between observed newline-flushed phase completions; scheduling/flush/reader latency remains explicit; sampled RSS is a lower bound','maximum_observation_gap_seconds':max([b['monotonic_after']-a['monotonic_before'] for a,b in zip(observations,observations[1:])]+[0]),'whole_build_provider_qualified':False}
