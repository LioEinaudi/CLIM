"""HC01 opt-in durable narrowing contracts. POSIX, same-user trust, experimental.

One atomic file commits authority AND audit under flock. A capability distinguishes
reviewed host code from the proposal API, not hostile processes with the same UID.
No OS atomic write gate, arbitrary Shell enforcement, or semantic verifier.
"""
from __future__ import annotations
from contextlib import contextmanager
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
import unicodedata
from ..devpreview.store import atomic_write, locked, read_json
from .contracts_audit import append, digest, verify

DEFAULT_ALLOWED=['src/**','tests/**','docs/**']
DEFAULT_DENIED=['.env','config.prod.json','src/shared/**']


class ContractViolation(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)


def require(condition,code):
    if not condition:raise ContractViolation(code)


def resource(name,pattern=False):
    require(isinstance(name,str) and 0<len(name)<=1024,'UNSAFE_RESOURCE')
    prefix=name[:-3] if pattern and name.endswith('/**') else name
    require(not prefix.startswith('/') and not any(c in prefix for c in '*?[]\\') and
            all(c not in ('','..','.') for c in prefix.split('/')) and
            unicodedata.normalize('NFC',name)==name and
            not any(unicodedata.category(c).startswith('C') for c in name) and
            not any(x in {'.git','.codex','.clim'} for x in prefix.split('/')),'UNSAFE_RESOURCE')
    return name


def contains(parent,child):
    return parent==child or parent.endswith('/**') and child.startswith(parent[:-2])


def intersects(a,b):return contains(a,b) or contains(b,a)


def file_state(root,name):
    resource(name);p=Path(root)
    for part in name.split('/'):
        p=p/part;require(not p.is_symlink(),'UNSAFE_RESOURCE_IDENTITY')
    try:
        if not p.exists():return {'kind':'missing','sha256':None,'bytes':0}
        before=p.stat();require(p.is_file() and before.st_size<=4*1024*1024,'UNINSPECTABLE_RESOURCE')
        # Existing observer checks lstat/open/fstat identity and bounds again.
        from ..devpreview.shadow import path_meta
        value=path_meta(Path(root),name)
        require(value.get('coverage')=='complete' and value.get('kind')=='file','UNINSPECTABLE_RESOURCE')
        return {k:value[k] for k in ['kind','sha256','bytes']}
    except OSError as e:raise ContractViolation('UNINSPECTABLE_RESOURCE') from e


def _host(s,cap):
    require(isinstance(cap,str) and hmac.compare_digest(s['host_capability_sha256'],hashlib.sha256(cap.encode()).hexdigest()),'HOST_CAPABILITY_REQUIRED')


def _event(doc,kind,**data):
    s=doc['state']
    return append(doc['events'],kind,{'task_id':s['task_id'],'session_id':s['session_id'],**data})


def _save(store,doc):
    _event(doc,'STATE_CHECKPOINT',state_digest=digest(doc['state']))
    atomic_write(Path(store)/'contracts_state.json',doc)
    # atomic_write fsyncs the file; also persist its directory entry for POSIX.
    fd=os.open(str(store),os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def _load(store):
    doc=read_json(Path(store)/'contracts_state.json')
    require(isinstance(doc,dict) and doc.get('schema')=='clim-hc01-durable/v1','CONTRACT_STATE_UNAVAILABLE')
    require(verify(doc['events']) and doc['events'] and doc['events'][-1]['kind']=='STATE_CHECKPOINT' and
            doc['events'][-1]['data']['state_digest']==digest(doc['state']),'CONTRACT_STATE_INCONSISTENT')
    return doc


@contextmanager
def _tx(store):
    with locked(Path(store)):
        doc=_load(store);original=copy.deepcopy(doc)
        try:yield doc
        except ContractViolation as error:
            for row in doc['events'][len(original['events']):]:
                if row['kind']=='CONTRACT_PROPOSED':append(original['events'],row['kind'],row['data'])
            _event(original,'CONTRACT_REJECTED',code=error.code);_save(store,original);raise
        else:_save(store,doc)


def snapshot(store):
    with locked(Path(store)):
        doc=_load(store)
        return {**copy.deepcopy(doc['state']),'events':copy.deepcopy(doc['events'])}


def _live(s):
    require(not s['expired'] and time.time()<s['expires_at'],'CONTRACT_EXPIRED')


def _history(doc,c,status):
    c['status']=status;c['version']=c.get('version',0)+1
    row={'snapshot':copy.deepcopy(c),'snapshot_sha256':digest(c)}
    doc['state']['history'].setdefault(c['contract_id'],[]).append(row)
    _event(doc,'CONTRACT_'+status,contract_id=c['contract_id'],version=c['version'],snapshot_sha256=row['snapshot_sha256'])


def register_task(store,root,*,task_id,stages,ttl_seconds=600,allowed=None,denied=None,feedback_mode='F1'):
    root=Path(root).resolve();store=Path(store).resolve()
    require(root.is_dir() and not store.is_relative_to(root),'STORE_MUST_BE_EXTERNAL')
    require(isinstance(task_id,str) and task_id and 0<ttl_seconds<=86400,'INVALID_HOST_REGISTRATION')
    require(feedback_mode in ('F0','F1'),'INVALID_FEEDBACK_MODE')
    allowed=list(DEFAULT_ALLOWED if allowed is None else allowed);denied=list(DEFAULT_DENIED if denied is None else denied)
    for p in allowed+denied:resource(p,True)
    for id,stage in stages.items():
        require(isinstance(id,str) and id and id!='ROOT','INVALID_STAGE_DAG')
        for p in stage['max_allowed']:
            resource(p,True);require(any(contains(a,p) for a in allowed),'INVALID_STAGE_DAG')
        require(all(p in stages and p!=id for p in stage.get('predecessors',[])),'INVALID_STAGE_DAG')
        for pred,paths in stage.get('version_inputs',{}).items():
            require(pred in stage.get('predecessors',[]),'INVALID_STAGE_DAG')
            for path in paths:resource(path)
    def visit(id,seen):
        require(id not in seen,'INVALID_STAGE_DAG')
        for dep in stages[id].get('predecessors',[]):visit(dep,seen|{id})
    for id in stages:visit(id,set())
    cap=secrets.token_hex(32);expiry=time.time()+ttl_seconds
    s={'task_id':task_id,'session_id':None,'project_root':str(root),'stages':copy.deepcopy(stages),
       'feedback_mode':feedback_mode,
       'root_identity':[root.stat().st_dev,root.stat().st_ino],
       'host_capability_sha256':hashlib.sha256(cap.encode()).hexdigest(),'expires_at':expiry,'expired':False,
       'policy_revision':1,'authority_revision':1,'contracts':{},'history':{},'stage_roots':{},'delegated':[],
       'active_stage':None,'active_leaf':None,'requested_contract':None,'completed':{},'steps':{},'pending':{}}
    s['contracts']['ROOT']={'contract_id':'ROOT','parent_id':None,'stage_id':None,'allowed':allowed,'denied':denied,
        'expires_at':expiry,'status':'ACTIVE','generation':1,'version':1,'preconditions':{},'predecessors':[],'semantic_pending':[]}
    doc={'schema':'clim-hc01-durable/v1','state':s,'events':[]}
    with locked(store):
        require(not (store/'contracts_state.json').exists(),'TASK_ALREADY_REGISTERED')
        _event(doc,'TASK_REGISTERED',authority_source='trusted_host_root',stage_envelope_sha256=digest(stages),root_scope_sha256=digest([allowed,denied]))
        _save(store,doc)
    return cap


def bind_session(store,session,cap):
    with _tx(store) as doc:
        s=doc['state'];_host(s,cap);_live(s)
        require(isinstance(session,str) and 0<len(session)<=512,'MISSING_SESSION')
        require(s['session_id'] in (None,session),'SESSION_SCOPE_MISMATCH')
        if s['session_id'] is None:
            s['session_id']=session;s['authority_revision']+=1
            _event(doc,'HOST_SESSION_BOUND',authority_source='trusted_hook_controller')


def submit_proposal(store,proposal,activate_now=False):
    with _tx(store) as doc:
        s=doc['state'];_live(s);p=copy.deepcopy(proposal)
        require(isinstance(p,dict),'UNTRUSTED_AUTHORITY_FIELD')
        try:encoded=json.dumps(p,allow_nan=False,ensure_ascii=False).encode('utf-8')
        except (ValueError,TypeError,RecursionError,OverflowError,UnicodeError) as error:raise ContractViolation('INVALID_PROPOSAL_JSON') from error
        require(len(encoded)<=65536,'PROPOSAL_TOO_LARGE')
        _event(doc,'CONTRACT_PROPOSED',proposal=p,authority_source='untrusted_agent_proposal')
        permitted={'contract_id','parent_id','stage_id','allowed','denied','ttl_seconds','revision_of','predecessors','preconditions','semantic'}
        require(isinstance(p,dict) and not (set(p)-permitted),'UNTRUSTED_AUTHORITY_FIELD')
        id=p.get('contract_id');parent_id=p.get('parent_id');stage=p.get('stage_id')
        require(isinstance(id,str) and 0<len(id)<=80 and id!='ROOT' and id not in s['contracts'],'CONTRACT_ID_NOT_NEW')
        require(isinstance(stage,str) and stage in s['stages'],'STAGE_NOT_TRUSTED')
        require(stage not in s['completed'],'STAGE_ALREADY_COMPLETED')
        require(isinstance(parent_id,str),'PARENT_MISSING')
        parent=s['contracts'].get(parent_id);require(parent is not None,'PARENT_MISSING')
        if parent_id=='ROOT':
            require(stage not in s['stage_roots'],'STAGE_ROOT_ALREADY_BOUND')
        else:
            require(parent_id==s['active_leaf'] and parent_id not in s['delegated'] and parent['status']=='ACTIVE','PARENT_NOT_CURRENT_LEAF')
            require(stage==parent['stage_id'],'STAGE_IDENTITY_MISMATCH')
        require(time.time()<parent['expires_at'],'CONTRACT_EXPIRED')
        allowed=p.get('allowed');require(isinstance(allowed,list) and 0<len(allowed)<=100,'INVALID_SCOPE')
        for path in allowed:resource(path,True)
        if parent_id=='ROOT':
            require(all(any(contains(a,p) for a in s['stages'][stage]['max_allowed']) for p in allowed),'TRUSTED_STAGE_SCOPE_EXCEEDED')
        require(all(any(contains(a,p) for a in parent['allowed']) for p in allowed),'CHILD_SCOPE_EXPANSION')
        denied=p.get('denied',parent['denied'])
        require(isinstance(denied,list),'INVALID_SCOPE')
        for path in denied:resource(path,True)
        require(all(d in denied for d in parent['denied']),'INHERITED_DENY_REMOVED')
        require(not any(intersects(a,d) for a in allowed for d in denied),'DENIED_RESOURCE_INTERSECTION')
        required=set(parent['predecessors'])|set(s['stages'][stage].get('predecessors',[]))
        supplied=p.get('predecessors',parent['predecessors'])
        require(isinstance(supplied,list) and len(supplied)<=100 and all(isinstance(x,str) for x in supplied),'INVALID_STAGE_DAG')
        require(required<=set(supplied),'TRUSTED_DEPENDENCY_MISSING')
        require(all(x in s['stages'] and x!=stage for x in supplied),'INVALID_STAGE_DAG')
        conditions=copy.deepcopy(parent['preconditions'])
        additions=p.get('preconditions',{})
        require(isinstance(additions,dict) and len(additions)<=100,'INVALID_STATE_DIGEST')
        for path,sha in additions.items():
            resource(path);require(isinstance(sha,str) and len(sha)==64 and all(c in '0123456789abcdef' for c in sha),'INVALID_STATE_DIGEST')
            require(path not in conditions or conditions[path]==sha,'STATE_PRECONDITION_RELAXATION');conditions[path]=sha
        ttl=p.get('ttl_seconds',100)
        require(isinstance(ttl,(int,float)) and 0<ttl<=86400,'INVALID_EXPIRY')
        require(p.get('revision_of') in (None,parent_id),'INVALID_REVISION_REFERENCE')
        semantic=p.get('semantic',[]);require(isinstance(semantic,list) and all(isinstance(x,str) for x in semantic),'INVALID_SEMANTIC_CANDIDATE')
        c={'contract_id':id,'parent_id':parent_id,'stage_id':stage,'allowed':allowed,'denied':denied,
           'expires_at':min(time.time()+ttl,parent['expires_at']),'generation':1,'predecessors':sorted(required|set(supplied)),
           'preconditions':conditions,'revision_of':p.get('revision_of'),'semantic_pending':parent['semantic_pending']+semantic}
        s['contracts'][id]=c
        if parent_id=='ROOT':s['stage_roots'][stage]=id
        _history(doc,c,'ACCEPTED')
        if semantic:_event(doc,'SEMANTIC_CONSTRAINT_PROPOSED_UNVERIFIED',contract_id=id,candidates=semantic,status='PENDING_USER_CONFIRMATION')
        if activate_now:_activate(doc,id)
        return copy.deepcopy(c)


def _activate(doc,id):
    s=doc['state'];_live(s)
    # A narrowing proposal arrives INSIDE its own observed Shell window. Shell
    # is not a protected write lease. Never let a pending Patch change authority.
    require(not any(w.get('step') is not None for w in s['pending'].values()),'OPEN_TOOL_WINDOW')
    require(isinstance(id,str),'CONTRACT_NOT_ACCEPTED')
    c=s['contracts'].get(id);require(c is not None and c['status']=='ACCEPTED','CONTRACT_NOT_ACCEPTED')
    require(time.time()<c['expires_at'],'CONTRACT_EXPIRED')
    require(all(p in s['completed'] for p in c['predecessors']),'PREDECESSOR_NOT_COMPLETE')
    require(s['active_stage'] in (None,c['stage_id']),'OTHER_PHASE_ACTIVE')
    if c['parent_id']!='ROOT':
        require(s['active_leaf']==c['parent_id'],'PARENT_NOT_CURRENT_LEAF')
    else:require(s['active_leaf'] is None,'OTHER_PHASE_ACTIVE')
    for dep,paths in s['stages'][c['stage_id']].get('version_inputs',{}).items():
        for path in paths:
            expected=s['completed'][dep]['outputs'].get(path)
            require(expected is not None and expected['kind']=='file','MISSING_PREDECESSOR_OUTPUT')
            require(path not in c['preconditions'] or c['preconditions'][path]==expected['sha256'],'STATE_PRECONDITION_RELAXATION')
            c['preconditions'][path]=expected['sha256']
    for path,sha in c['preconditions'].items():require(file_state(s['project_root'],path)['sha256']==sha,'STATE_PRECONDITION_CHANGED')
    if c['parent_id']!='ROOT':s['delegated'].append(c['parent_id'])
    s['active_stage']=c['stage_id'];s['active_leaf']=id;s['requested_contract']=None;s['authority_revision']+=1
    _history(doc,c,'ACTIVE')


def activate(store,id):
    with _tx(store) as doc:_activate(doc,id)


def select_contract(store,id):
    """Untrusted requested execution reference; never creates or activates authority."""
    with _tx(store) as doc:
        require(isinstance(id,str),'INVALID_CONTRACT_REFERENCE')
        doc['state']['requested_contract']=id;_event(doc,'EXECUTION_REFERENCE_REQUESTED',contract_id=id,authority_source='untrusted_agent_proposal')


def _check(s,session,paths,contract_id=None,group='G2_DYNAMIC'):
    require(group in ('G0_SHADOW','G1_STATIC','G2_DYNAMIC'),'INVALID_GROUP')
    if group=='G0_SHADOW':return {'allowed':True,'enforced':False,'contract_id':None,'coverage':'OBSERVATION_ONLY'}
    _live(s);require(isinstance(session,str) and bool(session) and session==s['session_id'],'SESSION_SCOPE_MISMATCH')
    root_stat=Path(s['project_root']).stat()
    require([root_stat.st_dev,root_stat.st_ino]==s['root_identity'],'PROJECT_ROOT_IDENTITY_CHANGED')
    require(isinstance(paths,list) and paths,'NO_PATCH_TARGETS')
    root=s['contracts']['ROOT']
    for p in paths:
        resource(p);file_state(s['project_root'],p)
        require(not any(contains(d,p) for d in root['denied']),'PROTECTED_BY_ROOT')
        require(any(contains(a,p) for a in root['allowed']),'OUTSIDE_ROOT_SCOPE')
    if group=='G1_STATIC':return {'allowed':True,'enforced':True,'contract_id':'ROOT','allowed_patterns':root['allowed']}
    id=contract_id if contract_id is not None else s['requested_contract'] or s['active_leaf']
    require(id is None or isinstance(id,str),'INVALID_CONTRACT_REFERENCE')
    require(id!='ROOT','ROOT_NOT_EXECUTION_CONTRACT')
    c=s['contracts'].get(id);require(c is not None,'NO_ACTIVE_CONTRACT')
    require(id not in s['delegated'],'DELEGATED_CONTRACT_INACTIVE')
    require(c['status']=='ACTIVE' and id==s['active_leaf'] and c['stage_id']==s['active_stage'],'PHASE_INACTIVE')
    require(time.time()<c['expires_at'],'CONTRACT_EXPIRED')
    for p in paths:
        require(not any(contains(d,p) for d in c['denied']),'INHERITED_DENY_VIOLATION')
        require(any(contains(a,p) for a in c['allowed']),'NOT_IN_PHASE_SCOPE')
    for p,sha in c['preconditions'].items():require(file_state(s['project_root'],p)['sha256']==sha,'STATE_PRECONDITION_CHANGED')
    return {'allowed':True,'enforced':True,'contract_id':id,'contract_generation':c['generation'],
            'contract_version':c['version'],'allowed_patterns':c['allowed'],'preconditions':copy.deepcopy(c['preconditions'])}


def precheck(store,session,paths,contract_id=None,group='G2_DYNAMIC'):
    with _tx(store) as doc:
        result=_check(doc['state'],session,paths,contract_id,group)
        _event(doc,'OFFLINE_PRECHECK',paths=paths,result=result);return result


def close_leaf(store,id,cap):
    with _tx(store) as doc:
        s=doc['state'];_host(s,cap);require(not s['pending'],'OPEN_TOOL_WINDOW')
        require(id==s['active_leaf'],'NOT_CURRENT_LEAF')
        _history(doc,s['contracts'][id],'CLOSED');s['active_leaf']=None;s['authority_revision']+=1


def complete(store,stage,cap,*,outputs,proof):
    with _tx(store) as doc:
        s=doc['state'];_host(s,cap);_live(s);require(not s['pending'],'OPEN_TOOL_WINDOW')
        require(s['active_stage']==stage and stage not in s['completed'],'PHASE_INACTIVE')
        require(isinstance(proof,dict) and proof.get('kind') in ('CONTROLLED_HOST_SETUP','NATIVE_POST_OBSERVED'),'INDEPENDENT_COMPLETION_PROOF_REQUIRED')
        values={p:file_state(s['project_root'],p) for p in outputs}
        for c in s['contracts'].values():
            if c['stage_id']==stage and c['status'] in ('ACTIVE','ACCEPTED'):_history(doc,c,'CLOSED')
        s['completed'][stage]={'outputs':values,'proof':copy.deepcopy(proof)}
        s['active_leaf']=None;s['active_stage']=None;s['requested_contract']=None;s['authority_revision']+=1
        _event(doc,'PHASE_CLOSED',stage=stage,outputs=values,proof=proof)


def expire(store,cap):
    with _tx(store) as doc:
        s=doc['state'];_host(s,cap);s['expired']=True;s['authority_revision']+=1
        for c in s['contracts'].values():
            if c['status'] not in ('CLOSED','EXPIRED'):_history(doc,c,'EXPIRED')
        _event(doc,'TASK_TERMINATED',reason='trusted_host_expiry')


def acknowledge_missing_post(store,cap,*,session_id,tool_use_id,proof):
    """Trusted recovery releases a lease but NEVER synthesizes the absent Post.

    The sticky coverage gap survives all later successful windows. No authority
    expands; the operator explicitly accepts UNKNOWN and must recheck outputs.
    """
    with _tx(store) as doc:
        s=doc['state'];_host(s,cap)
        require(isinstance(proof,dict) and proof.get('kind')=='HOST_RECONCILIATION_NO_SYNTHETIC_POST','INDEPENDENT_RECOVERY_PROOF_REQUIRED')
        key=digest([session_id,tool_use_id]);entry=s['pending'].get(key)
        require(entry is not None,'NO_PENDING_WINDOW')
        gap={'session_id':session_id,'tool_use_id':tool_use_id,'classification':'MISSING_POST_UNKNOWN',
             'resolution':'OPERATOR_ACKNOWLEDGED_UNKNOWN','proof':copy.deepcopy(proof)}
        s.setdefault('sticky_coverage_gaps',[]).append(gap)
        del s['pending'][key];s['authority_revision']+=1
        _event(doc,'COVERAGE_UNKNOWN_ACKNOWLEDGED',**gap,synthetic_post=False)
        return {'released_key':key,'coverage':'UNKNOWN','synthetic_post':False}


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description='HC01 untrusted narrowing proposal API; no host authority commands')
    p.add_argument('--store',type=Path,default=os.environ.get('HC01_STORE'));sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('propose');q.add_argument('proposal');q.add_argument('--activate',action='store_true')
    q=sub.add_parser('activate');q.add_argument('id')
    q=sub.add_parser('select');q.add_argument('id');sub.add_parser('status')
    a=p.parse_args(argv)
    try:
        require(a.store is not None,'STORE_REQUIRED')
        if a.command=='propose':result=submit_proposal(a.store,json.loads(a.proposal),a.activate)
        elif a.command=='activate':activate(a.store,a.id);result={'status':'ACTIVE'}
        elif a.command=='select':select_contract(a.store,a.id);result={'requested':a.id,'authority':'UNTRUSTED_REFERENCE_ONLY'}
        else:
            s=snapshot(a.store);result={k:s[k] for k in ['active_stage','active_leaf','stage_roots','completed']}
        print(json.dumps({'ok':True,'result':result},sort_keys=True));return 0
    except (ContractViolation,ValueError,KeyError) as e:
        print(json.dumps({'ok':False,'code':str(e),'authority_expansion':False}));return 2


if __name__=='__main__':raise SystemExit(main())
