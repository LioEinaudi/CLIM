"""M1 contract domain service: durable state, narrowing and evidence windows.

No implicit Hook registration and no OS enforcement. The operator capability is
same-user local coordination, NOT an independent security principal.
"""
from __future__ import annotations
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any
from .scope import ContractError, require, resource, scope_patterns, safe_identifier, contains, intersects, authorized
from .storage import SQLiteEvidenceSink, digest

TEMPLATES={
  'code-only': {'allowed':['src/**','tests/**'],
                'denied':['.env','config.prod.json','.github/**','src/shared/secrets/**']},
  'single-module': {'allowed':[], 'denied':['.env','config.prod.json','.github/**']},
  'sensitive-paths-review': {'allowed':['src/**','tests/**','docs/**'],
                             'denied':['.env','config.prod.json','.github/**','src/shared/secrets/**']},
}

def template(name:str, module: str|None=None)->dict:
    require(name in TEMPLATES,'UNKNOWN_TEMPLATE')
    data=copy.deepcopy(TEMPLATES[name])
    if name=='single-module':
        require(module is not None, 'MODULE_REQUIRED')
        resource(module)
        data['allowed']=[module+'/**']
    return data

def _identity(root:Path)->list[int]:
    s=root.stat()
    return [s.st_dev,s.st_ino]

def _file_hash(root:Path,path:str)->str:
    resource(path)
    cur=root
    for segment in path.split('/'):
        cur=cur/segment
        require(not cur.is_symlink(),'RESOURCE_SYMLINK_UNVERIFIED')
    try:
        if not cur.is_file() or cur.stat().st_size>4*1024*1024:
            raise ContractError('STATE_PRECONDITION_UNINSPECTABLE')
        # Not an atomic gate; explicitly only a bounded observation.
        with cur.open('rb') as stream: data=stream.read(4*1024*1024+1)
        require(len(data)<=4*1024*1024,'STATE_PRECONDITION_UNINSPECTABLE')
    except OSError as e:raise ContractError('STATE_PRECONDITION_UNINSPECTABLE') from e
    return hashlib.sha256(data).hexdigest()

class ContractRuntime:
    def __init__(self, project:Path, sink:SQLiteEvidenceSink):
        self.project=Path(project).resolve(strict=True)
        require(self.project.is_dir(),'PROJECT_NOT_DIRECTORY')
        self.sink=sink
        require(not sink.path.resolve().is_relative_to(self.project),'STORE_MUST_BE_EXTERNAL')

    @staticmethod
    def _state(c,sink):
        state=sink.get(c,'current_state')
        require(state is not None,'CONTRACT_NOT_INITIALIZED')
        return state

    def _check_root(self,s):
        require(s['project_root']==str(self.project) and s['project_identity']==_identity(self.project),
                'PROJECT_ROOT_IDENTITY_CHANGED')

    def _commit_state(self,c,s):
        # A logical checkpoint makes accidental state-only rewrites detectable
        # without replaying full history on every normal Hook hot-path read.
        self.sink.set(c,'current_state',s)
        self.sink.append(c,'STATE_CHECKPOINT',{'state_digest':digest(s),'task_id':s['task_id']},
                         session_id=s['session_id'])

    @staticmethod
    def _expiry(s):
        require(s['status']=='ACTIVE' and time.time()<s['expires_at'],'TASK_EXPIRED')

    @staticmethod
    def _cap(s,token):
        require(isinstance(token,str) and hmac.compare_digest(s['operator_capability_sha256'],
                    hashlib.sha256(token.encode()).hexdigest()),'OPERATOR_CAPABILITY_REQUIRED')

    def initialize(self, *, task_id:str, allowed:list[str],denied:list[str],stages:dict[str,dict],
                   ttl_seconds:int=3600) -> str:
        safe_identifier(task_id)
        allowed=scope_patterns(allowed); denied=scope_patterns(denied,True)
        require(isinstance(ttl_seconds,int) and 0<ttl_seconds<=86400,'INVALID_TASK_TTL')
        require(isinstance(stages,dict) and 0<len(stages)<=30,'INVALID_STAGE_DAG')
        for sid,step in stages.items():
            safe_identifier(sid,'INVALID_STAGE_DAG')
            require(sid!='ROOT' and isinstance(step,dict) and set(step)<={'max_allowed','predecessors','version_inputs'},'INVALID_STAGE_DAG')
            limits=scope_patterns(step.get('max_allowed'))
            require(all(any(contains(a,x) for a in allowed) for x in limits),'INVALID_STAGE_DAG')
            preds=step.get('predecessors',[])
            require(isinstance(preds,list) and all(isinstance(p,str) and p in stages and p!=sid for p in preds),'INVALID_STAGE_DAG')
            inputs=step.get('version_inputs',{})
            require(isinstance(inputs,dict) and set(inputs)<=set(preds),'INVALID_STAGE_DAG')
            for targets in inputs.values():
                require(isinstance(targets,list),'INVALID_STAGE_DAG')
                for p in targets:resource(p)
        def visit(sid,stack):
            require(sid not in stack,'INVALID_STAGE_DAG')
            for dep in stages[sid].get('predecessors',[]):visit(dep,stack|{sid})
        for sid in stages:visit(sid,set())
        cap=secrets.token_urlsafe(32)
        state={'schema':'clim-contract-runtime-state/v1','task_id':task_id,'project_root':str(self.project),
           'project_identity':_identity(self.project),'expires_at':time.time()+ttl_seconds,'status':'ACTIVE',
           'operator_capability_sha256':hashlib.sha256(cap.encode()).hexdigest(),
           'root':{'allowed':allowed,'denied':denied}, 'stage_envelope':stages,
           'active_stage':None,'active_contract':None,'stage_roots':{},'completed_stages':{},
           'session_id':None,'recovery_events':0}
        with self.sink.transaction() as c:
            require(self.sink.get(c,'current_state') is None,'TASK_ALREADY_REGISTERED')
            row=self.sink.append(c,'TASK_REGISTERED',{'task_id':task_id,'authority_source':'LOCAL_OPERATOR_CLI_UNATTESTED',
                  'root_digest':digest(state['root']),'stage_digest':digest(stages),
                  'root_contract_sha256':digest({'parent_id':None,'stage_id':None,**state['root'],
                     'expires_at':state['expires_at'],'preconditions':{},'predecessors':[]})})
            self.sink.version(c,'ROOT','ACTIVE',{'parent_id':None,'stage_id':None,**state['root'],
                     'expires_at':state['expires_at'],'preconditions':{},'predecessors':[]},row['event_seq'])
            self._commit_state(c,state)
        return cap

    def status(self)->dict:
        with self.sink.read() as c:
            s=copy.deepcopy(self._state(c,self.sink))
            self._check_root(s)
            versions=c.execute('SELECT COUNT(*) FROM contract_versions').fetchone()[0]
            pending=c.execute("SELECT COUNT(*) FROM windows WHERE status='PENDING'").fetchone()[0]
            uncertain=c.execute("SELECT COUNT(*) FROM windows WHERE coverage LIKE '%UNKNOWN%'").fetchone()[0]
            active=self.sink.latest(c,s['active_contract']) if s['active_contract'] else None
            return {'task_id':s['task_id'],'task_status':s['status'],
               'expired_by_clock':time.time()>=s['expires_at'],'project_root':s['project_root'],
               'active_stage':s['active_stage'],'active_contract':s['active_contract'],
               'active_scope':active['payload']['allowed'] if active else None,
               'active_revision':active['revision'] if active else None,
               'completed_stages':sorted(s['completed_stages']),
               'pending_windows':pending,'unknown_windows':uncertain,
               'contract_versions':versions,
               'enforcement':'NOT_ENABLED_M1','authority':'LOCAL_OPERATOR_UNATTESTED'}

    def _validate(self,c,s,p:dict)->dict:
        require(isinstance(p,dict) and not (set(p)-{'contract_id','parent_id','stage_id','allowed',
            'denied','predecessors','preconditions','ttl_seconds','semantic','revision_of'}),'UNTRUSTED_AUTHORITY_FIELD')
        digest(p) # Reject non-JSON / unencodable values before persistent mutation.
        cid=safe_identifier(p.get('contract_id'),'INVALID_CONTRACT_ID')
        require(cid!='ROOT' and c.execute('SELECT 1 FROM contract_versions WHERE contract_id=?',(cid,)).fetchone() is None,
                'CONTRACT_ID_NOT_NEW')
        stage=safe_identifier(p.get('stage_id'),'STAGE_NOT_TRUSTED')
        require(stage in s['stage_envelope'] and stage not in s['completed_stages'],'STAGE_NOT_TRUSTED')
        parent_id=safe_identifier(p.get('parent_id'),'PARENT_MISSING')
        parent=self.sink.latest(c,parent_id)
        if parent_id=='ROOT':
            require(s['active_contract'] is None and stage not in s['stage_roots'],'ACTIVE_STAGE_ROOT_BYPASS')
        else:
            require(parent_id==s['active_contract'] and parent['status']=='ACTIVE' and
                    stage==parent['payload']['stage_id'],'PARENT_NOT_CURRENT_LEAF')
        require(time.time()<parent['payload']['expires_at'],'PARENT_EXPIRED')
        allowed=scope_patterns(p.get('allowed'))
        denials=scope_patterns(p.get('denied',parent['payload']['denied']),True)
        require(all(d in denials for d in parent['payload']['denied']),'INHERITED_DENY_REMOVED')
        require(all(any(contains(a,x) for a in parent['payload']['allowed']) for x in allowed),'CHILD_SCOPE_EXPANSION')
        if parent_id=='ROOT':
            limits=s['stage_envelope'][stage]['max_allowed']
            require(all(any(contains(a,x) for a in limits) for x in allowed),'TRUSTED_STAGE_SCOPE_EXCEEDED')
        require(not any(intersects(a,d) for a in allowed for d in denials),'DENIED_RESOURCE_INTERSECTION')
        predecessors=sorted(set(parent['payload']['predecessors'])|
                            set(s['stage_envelope'][stage].get('predecessors',[])))
        supplied=p.get('predecessors',predecessors)
        require(isinstance(supplied,list) and
                all(isinstance(x,str) and x in s['stage_envelope'] and x!=stage for x in supplied) and
                set(predecessors)<=set(supplied),'TRUSTED_DEPENDENCY_MISSING')
        conditions=copy.deepcopy(parent['payload']['preconditions'])
        more=p.get('preconditions',{})
        require(isinstance(more,dict),'INVALID_PRECONDITIONS')
        for path,sha in more.items():
            resource(path)
            require(isinstance(sha,str) and len(sha)==64 and all(v in '0123456789abcdef' for v in sha),
                    'INVALID_STATE_DIGEST')
            require(path not in conditions or conditions[path]==sha,'STATE_PRECONDITION_RELAXATION')
            conditions[path]=sha
        ttl=p.get('ttl_seconds',3600)
        require(type(ttl) is int and 0<ttl<=86400,'INVALID_EXPIRY')
        require(p.get('revision_of') in (None,parent_id),'INVALID_REVISION_REFERENCE')
        semantics=p.get('semantic',[])
        require(isinstance(semantics,list) and all(isinstance(v,str) and len(v)<500 for v in semantics),
                'INVALID_SEMANTIC_CANDIDATE')
        return {'parent_id':parent_id,'stage_id':stage,'allowed':allowed,'denied':denials,
                'predecessors':sorted(set(supplied)),'preconditions':conditions,
                'semantic_pending':parent['payload'].get('semantic_pending',[])+semantics,
                'expires_at':min(time.time()+ttl,parent['payload']['expires_at'],s['expires_at']),
                'revision_of':p.get('revision_of')}

    def validate(self,proposal:dict)->dict:
        with self.sink.read() as c:
            s=self._state(c,self.sink);self._check_root(s);self._expiry(s)
            result=self._validate(c,s,proposal)
            return {'valid':True,'status':'PROPOSABLE_NOT_AUTHORIZED',
                    'candidate_digest':digest(result),'semantic_pending':result['semantic_pending']}

    def propose(self,proposal:dict)->dict:
        try:
            with self.sink.transaction() as c:
                s=self._state(c,self.sink);self._check_root(s);self._expiry(s)
                data=self._validate(c,s,proposal)
                cid=proposal['contract_id']
                event=self.sink.append(c,'CONTRACT_ACCEPTED',{'contract_id':cid,'candidate_digest':digest(data),
                       'source':'UNTRUSTED_AGENT_PROPOSAL'})
                rev=self.sink.version(c,cid,'ACCEPTED',data,event['event_seq'])
                if data['parent_id']=='ROOT':s['stage_roots'][data['stage_id']]=cid
                self._commit_state(c,s)
                return {'contract_id':cid,'revision':rev,'status':'ACCEPTED_NOT_ACTIVE',
                        'semantic_pending':data['semantic_pending']}
        except ContractError as e:
            # Store rejection after the rolled-back transaction; a rejection never
            # creates a contract. Avoid logging untrusted raw text or secrets.
            try:proposal_digest=digest(proposal)
            except ContractError:proposal_digest=None
            with self.sink.transaction() as c:
                if self.sink.get(c,'current_state') is not None:
                    self.sink.append(c,'CONTRACT_REJECTED',{'code':e.code,'proposal_sha256':proposal_digest})
            raise

    def activate(self,contract_id:str,operator_capability:str,session_id:str|None=None):
        with self.sink.transaction() as c:
            s=self._state(c,self.sink);self._check_root(s);self._expiry(s);self._cap(s,operator_capability)
            require(c.execute("SELECT 1 FROM windows WHERE status='PENDING' LIMIT 1").fetchone() is None,
                    'OPEN_TOOL_WINDOW')
            rec=self.sink.latest(c,contract_id)
            require(rec['status']=='ACCEPTED','CONTRACT_NOT_ACCEPTED')
            info=rec['payload'];phase=info['stage_id']
            require(time.time()<info['expires_at'],'CONTRACT_EXPIRED')
            require(s['active_stage'] in (None,phase),'OTHER_PHASE_ACTIVE')
            if info['parent_id']=='ROOT':require(s['active_contract'] is None,'OTHER_PHASE_ACTIVE')
            else:require(s['active_contract']==info['parent_id'],'PARENT_NOT_CURRENT_LEAF')
            require(all(dep in s['completed_stages'] for dep in info['predecessors']),'PREDECESSOR_NOT_COMPLETE')
            for predecessor,paths in s['stage_envelope'][phase].get('version_inputs',{}).items():
                for path in paths:
                    sha=s['completed_stages'][predecessor]['outputs'].get(path)
                    require(sha is not None,'MISSING_PREDECESSOR_OUTPUT')
                    require(path not in info['preconditions'] or info['preconditions'][path]==sha,'STATE_PRECONDITION_RELAXATION')
                    info['preconditions'][path]=sha
            for path,sha in info['preconditions'].items():
                require(_file_hash(self.project,path)==sha,'STATE_PRECONDITION_CHANGED')
            if session_id is not None:
                safe_identifier(session_id,'INVALID_SESSION')
                require(s['session_id'] in (None,session_id),'SESSION_SCOPE_MISMATCH')
                s['session_id']=session_id
            s['active_stage']=phase;s['active_contract']=contract_id
            event=self.sink.append(c,'CONTRACT_ACTIVATED',{'contract_id':contract_id,'stage_id':phase,
                     'authority':'LOCAL_OPERATOR_CAPABILITY_UNATTESTED',
                     'payload_digest':digest(info)},session_id=s['session_id'])
            rev=self.sink.version(c,contract_id,'ACTIVE',info,event['event_seq'])
            self._commit_state(c,s)
            return {'status':'ACTIVE','contract_id':contract_id,'revision':rev}

    def finish_stage(self,operator_capability:str,output_paths:list[str]|None=None):
        with self.sink.transaction() as c:
            s=self._state(c,self.sink);self._check_root(s);self._expiry(s);self._cap(s,operator_capability)
            require(s['active_contract'] is not None,'NO_ACTIVE_STAGE')
            require(c.execute("SELECT 1 FROM windows WHERE status='PENDING' LIMIT 1").fetchone() is None,
                    'OPEN_TOOL_WINDOW')
            cid=s['active_contract'];rec=self.sink.latest(c,cid)
            outputs={}
            for p in (output_paths or []):outputs[resource(p)]=_file_hash(self.project,p)
            phase=s['active_stage']
            s['completed_stages'][phase]={'contract_id':cid,'outputs':outputs}
            s['active_stage']=None;s['active_contract']=None
            e=self.sink.append(c,'STAGE_COMPLETED',{'stage_id':phase,'contract_id':cid,
                    'output_digests':outputs,'semantic_verified':False,
                    'payload_digest':digest(rec['payload'])},session_id=s['session_id'])
            self.sink.version(c,cid,'CLOSED',rec['payload'],e['event_seq'])
            self._commit_state(c,s)
            return {'stage_id':phase,'status':'CLOSED','output_digests':outputs}

    def begin_window(self,*,window_id:str,session_id:str,tool_use_id:str,targets:list[str],
                     actor_id:str|None=None,trace_id:str|None=None,parent_span_id:str|None=None):
        """Record a bounded PRE observation only; does not intercept any Host tool."""
        for name in (window_id,session_id,tool_use_id):safe_identifier(name)
        require(isinstance(targets,list) and targets,'NO_PATCH_TARGETS')
        for path in targets:resource(path)
        with self.sink.transaction() as c:
            s=self._state(c,self.sink);self._check_root(s);self._expiry(s)
            if s['session_id'] is not None:require(session_id==s['session_id'],'SESSION_SCOPE_MISMATCH')
            cid=s['active_contract'];rec=self.sink.latest(c,cid) if cid else None
            verdict='CONTRACT_NOT_ACTIVE'
            if rec is not None:
                policy=rec['payload']
                if time.time()>=policy['expires_at']:
                    verdict='CONTRACT_EXPIRED'
                elif not authorized(targets,s['root']['allowed'],s['root']['denied']):
                    verdict='ROOT_SCOPE_CONFLICT'
                elif any(_file_hash(self.project,p)!=sha for p,sha in policy['preconditions'].items()):
                    verdict='STATE_PRECONDITION_CHANGED'
                else:
                    verdict=('WITHIN_DECLARED_SCOPE' if authorized(targets,policy['allowed'],policy['denied'])
                             else 'CONTRACT_SCOPE_CONFLICT')
            e=self.sink.append(c,'WINDOW_PRE_OBSERVED',{'targets':targets,'contract_id':cid,
                'scope_verdict':verdict,'enforced':False,'tool_use_id':tool_use_id},session_id=session_id,actor_id=actor_id,
                window_id=window_id,trace_id=trace_id,parent_span_id=parent_span_id)
            try:c.execute('INSERT INTO windows VALUES(?,?,?,?,?,?,?,?)',
                    (window_id,session_id,tool_use_id,'PENDING',e['event_seq'],None,'UNKNOWN_PENDING',json.dumps(targets)))
            except __import__('sqlite3').IntegrityError as error:raise ContractError('DUPLICATE_WINDOW_ID') from error
            return {'window_id':window_id,'event_seq':e['event_seq'],
                    'scope_verdict':verdict,'coverage':'UNKNOWN_PENDING','enforced':False}

    def close_window(self,window_id:str,observed_paths:list[str],*,coverage:str='PARTIAL',
                     actor_id:str|None=None):
        safe_identifier(window_id)
        require(coverage in ('COMPLETE_BOUNDED','PARTIAL','UNKNOWN'),'INVALID_COVERAGE')
        require(isinstance(observed_paths,list),'INVALID_OBSERVED_PATHS')
        for path in observed_paths:resource(path)
        with self.sink.transaction() as c:
            row=c.execute('SELECT * FROM windows WHERE window_id=?',(window_id,)).fetchone()
            require(row is not None and row['status']=='PENDING','WINDOW_NOT_PENDING')
            overlaps=c.execute("SELECT COUNT(*) FROM windows WHERE status='PENDING'").fetchone()[0]>1
            cause='CAUSE_UNKNOWN' if overlaps or observed_paths else 'NO_CHANGE_OBSERVED_IN_BOUNDS'
            e=self.sink.append(c,'WINDOW_POST_OBSERVED',{'changed_paths':observed_paths,
                'coverage':coverage,'cause':cause,'overlap_seen':overlaps,'enforced':False},
                session_id=row['session_id'],actor_id=actor_id,window_id=window_id)
            c.execute('UPDATE windows SET status=?,closed_seq=?,coverage=? WHERE window_id=?',
                      ('CLOSED',e['event_seq'],coverage,window_id))
            return {'window_id':window_id,'coverage':coverage,'attribution':cause}

    def recover(self)->dict:
        """Resolve abandoned bookkeeping as UNKNOWN, never as verified effects."""
        self.sink.verify() # audit consistency before touching recovery state
        with self.sink.transaction() as c:
            s=self._state(c,self.sink);self._check_root(s)
            rows=c.execute("SELECT * FROM windows WHERE status='PENDING' ORDER BY opened_seq").fetchall()
            for row in rows:
                e=self.sink.append(c,'RECOVERY_EFFECT_UNKNOWN',{
                    'reason':'MISSING_POST_OR_INTERRUPTED_EXECUTION',
                    'original_pre_seq':row['opened_seq'],'no_rollback':True},
                    window_id=row['window_id'],session_id=row['session_id'])
                c.execute('UPDATE windows SET status=?,closed_seq=?,coverage=? WHERE window_id=?',
                          ('RECOVERED_UNKNOWN',e['event_seq'],'EFFECT_UNKNOWN',row['window_id']))
            s['recovery_events']+=len(rows)
            self._commit_state(c,s)
            return {'recovered_unknown':len(rows),'windows':[r['window_id'] for r in rows],
                    'files_modified':False,'effect_verified':False}

    def export_spec(self)->dict:
        with self.sink.read() as c:
            s=self._state(c,self.sink)
            return {'schema':'clim-contract-spec/v1','task_id':s['task_id'],
                  'allowed':s['root']['allowed'],'denied':s['root']['denied'],
                  'stages':s['stage_envelope'], 'authority':'UNSIGNED_PORTABLE_POLICY_TEMPLATE',
                  'contains_approvals':False}

    def history(self,limit:int=100)->list[dict]:
        require(type(limit) is int and 1<=limit<=1000,'INVALID_LIMIT')
        with self.sink.read() as c:
            rows=c.execute('SELECT * FROM events ORDER BY seq DESC LIMIT ?',(limit,)).fetchall()
            return [{**json.loads(r['record_json']),'event_hash':r['event_hash'],
                'previous_hash':r['previous_hash']} for r in reversed(rows)]
