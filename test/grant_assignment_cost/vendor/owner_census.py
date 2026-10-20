"""Bounded lowered LLVM receiver/origin census; frontend cache completeness stays unqualified."""
from pathlib import Path
import hashlib,json,os,re,stat

MAX_IR_BYTES=256*2**20
MAX_LINE_BYTES=2**20
MAX_DEFINITIONS=200000
MAX_REPORT_BYTES=32*2**20
MODELS=('AcceptancePerson0000','AcceptancePerson0001')
FAMILIES=('all','chain_copy','records','select','select_single','chunked_select','each_in_chunk','with_index_hint_fallback','assembler','run')
SYMBOL=re.compile(rb'@(?:"((?:[^"\\]|\\[0-9A-Fa-f]{2})*)"|([-A-Za-z$._0-9]+))\(')


def need(value,message):
    if not value:raise RuntimeError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def symbol_from_header(header):
    need(header.startswith(b'define ')and header.rstrip().endswith(b'{'),'Exact one-line LLVM function header required')
    match=SYMBOL.search(header);need(match is not None,'LLVM function symbol required')
    if match.group(1)is None:return match.group(2).decode('ascii')
    value=re.sub(rb'\\([0-9A-Fa-f]{2})',lambda item:bytes([int(item.group(1),16)]),match.group(1))
    return value.decode('utf-8')


def receiver_identity(symbol):
    result={'self_type':None,'original_owner':None,'method_signature':None,'method_family':None,'model':None,'bucket':'other_or_unclassified'}
    if not symbol.startswith('*')or '#'not in symbol:return result
    receiver,signature=symbol[1:].split('#',1)
    pieces=receiver.split('@');need(len(pieces)<=2,'One exact inherited-owner separator required')
    self_type=pieces[0];origin=pieces[1]if len(pieces)==2 else self_type
    family=re.split('[<:]',signature,maxsplit=1)[0].rstrip("'")
    result.update(self_type=self_type,original_owner=origin,method_signature=signature,method_family=family)
    for model in MODELS:
        builder='Grant::Query::Builder('+model+')';named=model+'::BuildNamedScopeRelation'
        if self_type==builder:result.update(model=model,bucket='direct_builder');break
        if self_type==named:result.update(model=model,bucket='named_scope_inherited'if origin!=named else'named_scope_direct');break
        if model in self_type:result.update(model=model,bucket='other_model_related');break
    if result['model']is None and('Grant::Query::RelationState'in self_type or'SharedListRunner'in self_type):result['bucket']='shared_state_or_cursor'
    return result


def census_stream(source):
    rows=[];symbols=set();whole=hashlib.sha256();total=0;active=None;line_number=0
    while True:
        line=source.readline(MAX_LINE_BYTES+1)
        if not line:break
        line_number+=1;total+=len(line);whole.update(line)
        need(len(line)<=MAX_LINE_BYTES and total<=MAX_IR_BYTES,'Finite LLVM byte/line bound required')
        if line.startswith(b'define '):
            need(active is None,'Prior LLVM function must end before next header')
            symbol=symbol_from_header(line);need(symbol not in symbols,'Unique LLVM function definition required');symbols.add(symbol)
            active={'symbol':symbol,'header_line':line_number,'header_sha256':sha(line),'hash':hashlib.sha256(),'body_lines':0,**receiver_identity(symbol)}
        if active is not None:
            active['hash'].update(line);active['body_lines']+=1
            if line.rstrip(b'\r\n')==b'}':
                active.update(last_line=line_number,definition_sha256=active.pop('hash').hexdigest());rows.append(active);active=None
                need(len(rows)<=MAX_DEFINITIONS,'Finite LLVM function roster required')
    need(active is None and rows,'Complete nonempty LLVM definition roster required')
    counts={}
    for item in rows:
        key=item['bucket'];counts[key]=counts.get(key,0)+1
    result={'schema_version':1,'metric':'lowered single-module LLVM definitions','ir_sha256':whole.hexdigest(),'ir_bytes':total,'definition_count':len(rows),'bucket_counts':counts,'definitions':rows,'selected_family_definitions':[item['symbol']for item in rows if item['method_family']in FAMILIES and item['bucket']in('direct_builder','named_scope_inherited','named_scope_direct')],'frontend_inferred_cache_census_qualified':False,'retained_frontend_memory_qualified':False,'memory_savings_accepted':False}
    verify_report(result);need(len(json.dumps(result).encode())<=MAX_REPORT_BYTES,'Finite complete LLVM report required');return result


def verify_report(value):
    rows=value['definitions'];need(value['definition_count']==len(rows)>0 and len({row['symbol']for row in rows})==len(rows),'Exact complete unique LLVM report roster required')
    counts={}
    for row in rows:
        need({key:row[key]for key in receiver_identity(row['symbol'])}==receiver_identity(row['symbol']),'Exact decoded receiver/origin identity required')
        counts[row['bucket']]=counts.get(row['bucket'],0)+1
    need(counts==value['bucket_counts'],'Exact full LLVM bucket accounting required')
    need(value['selected_family_definitions']==[item['symbol']for item in rows if item['method_family']in FAMILIES and item['bucket']in('direct_builder','named_scope_inherited','named_scope_direct')],'Exact selected terminal-family roster required')


def census_file(path):
    path=Path(path);need(path.resolve()==path,'Canonical LLVM source path required')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb')as source:
        before=os.fstat(source.fileno());need(stat.S_ISREG(before.st_mode)and 0<before.st_size<=MAX_IR_BYTES,'Bounded regular LLVM file required')
        result=census_stream(source);after=os.fstat(source.fileno());named=path.lstat()
    identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    need(identity(before)==identity(after)==identity(named)and result['ir_bytes']==before.st_size,'Stable exact LLVM file required');return result


def context_owners(raw):
    need(type(raw)is bytes and len(raw)<=2**20,'Finite raw context JSON required');value=json.loads(raw)
    need(value.get('status')=='ok'and type(value.get('contexts'))is list and 0<len(value['contexts'])<=128,'Answered bounded compiler owner contexts required')
    contexts=value['contexts'];need(all(type(item)is dict and type(item.get('self'))is str and item['self']for item in contexts),'Explicit owner self in every context required')
    return {'reported_context_count':len(contexts),'reported_owner_sequence':[item['self']for item in contexts],'unique_reported_owners':sorted({item['self']for item in contexts}),'raw_sha256':sha(raw),'context_cache_identity_completeness_qualified':False,'nonowning_graph_traversal_qualified':False}
