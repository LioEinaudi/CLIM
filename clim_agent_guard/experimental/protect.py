"""Opt-in Selective Protect native prototype, separate from released CLIM CLI.

Run `python -m clim_agent_guard.experimental.protect --help`. All ordinary Shell
calls continue, with gaps. Only supported apply_patch requests may be denied.
Nothing here provides OS isolation, full write coverage, undo or causal proof.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time
from ..devpreview.hook import denial
from ..devpreview.policy import match
from ..devpreview.shadow import capture, inventory, transport
from ..devpreview.store import append_audit, atomic_write, locked, read_json
from .permits import (ContractError, consume_locked, digest, initialize, issue_permit,
                      patch_identity, read_policy, relevant_state, set_mode)

TAG='CLIM EXPERIMENTAL Selective Protect v0.1'
MODULE='clim_agent_guard.experimental.protect'


def context(event,policy):
    if not isinstance(event,dict) or Path(event.get('cwd','')).resolve()!=Path(policy['project_root']):
        raise ContractError('PROJECT_ROOT_MISMATCH')
    ids=[event.get('session_id'),event.get('tool_use_id')]
    if not all(isinstance(x,str) and 0<len(x)<=512 for x in ids):
        raise ContractError('MISSING_ACTION_IDENTITY')
    return digest(ids)


def _base(event,policy,phase):
    return {'phase':phase,'mode':policy['mode'],'schema':'clim-experimental-window/v1',
            'session_id':event['session_id'],'tool_use_id':event['tool_use_id'],
            'tool':event.get('tool_name'),'enforced':False}


def _deny(store,base,code,targets=None):
    append_audit(store,{**base,'classification':'PRE_DENIED','decision':'PRE_DENIED',
                        'signals':[code],'code':code,
                        'host_enforcement_status':'REQUESTED_DENY_NOT_HOST_CONFIRMED'})
    return denial(code,targets,detail='Experimental exact-action protection. Use a safe target or obtain a new state-bound operator grant; Shell is outside this protection scope.')


def pre(event,store):
    store=Path(store)
    with locked(store):
        policy=read_policy(store);key=context(event,policy);root=Path(policy['project_root'])
        if event.get('hook_event_name')!='PreToolUse':raise ContractError('NOT_PRE_EVENT')
        base=_base(event,policy,'PRE');tool=event.get('tool_name');identity=None;targets=None;gaps=[]
        pending=read_json(store/'pending.json',{})
        if tool=='apply_patch':
            try:
                identity=patch_identity(event,policy);targets=identity['targets']
                # Unsupported target states must not become a green protection claim.
                states=relevant_state(root,targets)
            except (ContractError,OSError,ValueError) as error:
                if policy['mode']=='selective-protect':return _deny(store,base,str(error))
                gaps.append({'reason':'uninspectable_or_unsafe_patch'})
        else:
            gaps.append({'reason':'unwatched_tool','detail':'Shell and other tool write semantics are not parsed.'})
        proof=None
        protected=[p for p in targets or [] if match(p,policy['protected'])]
        if policy['mode']=='selective-protect' and protected:
            proof=consume_locked(store,event,policy)
            if not proof['allowed']:return _deny(store,base,proof['status'],protected)
        if key in pending:
            if policy['mode']=='selective-protect' and tool=='apply_patch':return _deny(store,base,'DUPLICATE_PENDING_OPERATION',targets)
            gaps.append({'reason':'duplicate_pre_identity'})
        expected=policy['postconditions'].get(identity['exact_patch_sha256'],{}) if identity else {}
        watch,coverage=inventory(root,{'shadow_inventory':policy['inventory']},sorted(set(targets or [])|set(expected)))
        before=capture(root,watch)
        gaps+=coverage['gaps']
        gaps += [{'reason':value['coverage'],'path':name} for name,value in before.items() if value['coverage']!='complete']
        for entry in pending.values():entry['overlapped']=True
        pending[key]={**base,'proposed':targets,'before':before,'coverage_gaps':gaps,
                      'policy_digest':digest(policy),'policy_revision':policy['revision'],
                      'started_ns':time.monotonic_ns(),'overlapped':bool(pending),
                      'expected_post_states':expected,'exact_patch_sha256':identity['exact_patch_sha256'] if identity else None,
                      'grant':proof,'coverage':coverage}
        atomic_write(store/'pending.json',pending)
        signals=['STATE_BOUND_APPROVAL_VERIFIED_AT_PRE'] if proof else []
        append_audit(store,{**base,'classification':'PRE_ALLOWED','decision':'PRE_ALLOWED','signals':signals,
                            'proposed':targets,'protected_proposed':protected,'grant':proof,
                            'coverage_gaps':gaps,'race_prevention':'NOT_PROVIDED'})
        return {}


def _tool_failed(response):
    # Only explicit native/structured evidence; no model text inference.
    return isinstance(response,dict) and (response.get('success') is False or response.get('is_error') is True
           or type(response.get('exit_code')) is int and response['exit_code']!=0)


def _contract_status(expected,after):
    if not expected:return 'NO_TRUSTED_POSTCONDITION',[]
    mismatches=[]
    for path,wanted in expected.items():
        actual=after.get(path,{})
        if actual.get('coverage')!='complete':return 'CONTRACT_UNKNOWN',[]
        exists=actual.get('kind')!='missing'
        if exists!=wanted['exists'] or exists and (actual.get('kind')!=wanted.get('type') or actual.get('sha256')!=wanted.get('sha256')):
            mismatches.append(path)
    return ('STATE_MISMATCH' if mismatches else 'TRUSTED_POST_STATE_MATCHED'),mismatches


def post(event,store):
    store=Path(store)
    with locked(store):
        policy=read_policy(store);key=context(event,policy);root=Path(policy['project_root'])
        if event.get('hook_event_name')!='PostToolUse':raise ContractError('NOT_POST_EVENT')
        base=_base(event,policy,'POST');pending=read_json(store/'pending.json',{});entry=pending.get(key)
        if entry is None:
            append_audit(store,{**base,'classification':'ORPHAN_POST_UNKNOWN','decision':'UNKNOWN',
                                'signals':['ORPHAN_POST'],'coverage_gaps':[{'reason':'missing_pre'}]})
            return {}
        after=capture(root,sorted(entry['before']));before=entry['before']
        known={p for p in before if before[p]['coverage']==after[p]['coverage']=='complete'}
        observed=sorted(p for p in known if before[p]!=after[p])
        gaps=entry['coverage_gaps']+[{'reason':v['coverage'],'path':p} for p,v in after.items() if v['coverage']!='complete']
        policy_changed=entry['policy_digest']!=digest(policy)
        if policy_changed:gaps.append({'reason':'policy_changed'})
        proposed=entry['proposed'];outside=sorted(set(observed)-set(proposed)) if proposed is not None else None
        protected=[p for p in observed if match(p,policy['protected'])]
        semantic,mismatch=(('CONTRACT_INVALIDATED_POLICY_CHANGE',[]) if policy_changed else
                           _contract_status(entry['expected_post_states'],after))
        signals=[]
        if outside:signals.append('OBSERVED_OUTSIDE_PROPOSAL')
        if protected:signals.append('PROTECTED_TARGET_CHANGED')
        if mismatch:signals.append('STATE_MISMATCH')
        failed=_tool_failed(event.get('tool_response'))
        classification=('TOOL_FAILED' if failed else 'STATE_MISMATCH' if mismatch else
                        'UNKNOWN_COVERAGE' if gaps and not observed else
                        'OBSERVED_WITH_COVERAGE_GAPS' if gaps else 'OBSERVED_WITHIN_COVERAGE')
        effect={'before':before,'after':after,'observed':observed,'proposed':proposed,
                'observed_outside_proposal':outside,'protected_changed':protected,
                'coverage_gaps':gaps,'authorization':'UNKNOWN','attribution':'ATTRIBUTION_UNCERTAIN',
                'semantic_status':semantic,'state_mismatch_paths':mismatch,
                'race_prevention':'NOT_PROVIDED','protection_scope':'SUPPORTED_APPLY_PATCH_ONLY',
                'outside_inventory':'UNOBSERVED'}
        effect['tool_status']='FAILED' if failed else 'UNKNOWN_UNLESS_STRUCTURED_NATIVE_SUCCESS'
        append_audit(store,{**base,'classification':classification,'decision':classification,'signals':signals,
                            'effect':effect,'started_ns':entry['started_ns'],'ended_ns':time.monotonic_ns(),
                            'overlapped':entry['overlapped'],'policy_revision':entry['policy_revision']})
        del pending[key];atomic_write(store/'pending.json',pending)
        if mismatch:return {'systemMessage':'CLIM experimental STATE_MISMATCH under a registered independent state contract. No undo or unique attribution is provided.'}
        return {}


def report(store):
    store=Path(store);read_policy(store)
    with locked(store):
        path=store/'events.jsonl'
        events=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        pending=[{'session_id':e['session_id'],'tool_use_id':e['tool_use_id'],
                  'classification':'MISSING_POST','status':'UNKNOWN'} for e in read_json(store/'pending.json',{}).values()]
    counts=Counter()
    for event in events:
        counts.update(set([event.get('classification','UNKNOWN'),*event.get('signals',[])]))
    return {'schema':'clim-experimental-report/v1','events':events,'pending':pending,'counts':dict(counts),
            'coverage_status':'BOUNDED_HOOK_EVIDENCE_ONLY' if events else 'NO_HOOK_EVIDENCE_UNKNOWN',
            'host_enforcement_status':'NOT_ESTABLISHED_BY_HOOK_RECORDS',
            'limitations':['No Hook record does not prove no write.','Same-user store is mutable.',
                           'Pre checks do not prevent TOCTOU.','Only supported apply_patch receives protection.']}


def install(project,store,inventory_paths=None,principal=None):
    project=Path(project).resolve(strict=True);store=Path(store).resolve()
    hook_path=project/'.codex/hooks.json'
    old=read_json(hook_path,{'hooks':{}})
    if old.get('hooks'):raise ContractError('EXISTING_HOOKS_NOT_REPLACED; use a disposable project')
    initialize(project,store,inventory=inventory_paths,principal=principal)
    hooks={'description':'Isolated experimental Selective Protect; explicit native review required.','hooks':{}}
    for native,phase in [('PreToolUse','pre'),('PostToolUse','post')]:
        command=shlex.join([sys.executable,'-m',MODULE,phase,'--store',str(store)])
        hooks['hooks'][native]=[{'matcher':'^(apply_patch|Bash|exec_command|bash|shell_command)$',
                                'hooks':[{'type':'command','command':command,'timeout':15,'statusMessage':TAG+' '+phase}]}]
    atomic_write(hook_path,hooks)
    return {'mode':'shadow','store':str(store),'next':'Review and trust exact definitions through native /hooks. Protection is opt-in.'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    for phase in ['pre','post']:
        p=sub.add_parser(phase);p.add_argument('--store',type=Path,required=True)
    p=sub.add_parser('install');p.add_argument('--project',type=Path,required=True);p.add_argument('--store',type=Path,required=True);p.add_argument('--inventory',type=Path);p.add_argument('--principal')
    p=sub.add_parser('mode');p.add_argument('mode',choices=['shadow','selective-protect']);p.add_argument('--store',type=Path,required=True)
    p=sub.add_parser('grant');p.add_argument('--store',type=Path,required=True);p.add_argument('--request',type=Path,required=True);p.add_argument('--principal',required=True);p.add_argument('--ttl',type=float,default=60)
    p=sub.add_parser('report');p.add_argument('--store',type=Path,required=True)
    args=parser.parse_args(argv)
    if args.action not in ('pre','post'):
        if args.action=='install':result=install(args.project,args.store,read_json(args.inventory) if args.inventory else None,args.principal)
        elif args.action=='mode':result=set_mode(args.store,args.mode)
        elif args.action=='grant':result=issue_permit(args.store,read_json(args.request),principal=args.principal,ttl=args.ttl)
        else:result=report(args.store)
        print(json.dumps(result,ensure_ascii=False,indent=2));return
    started=time.perf_counter_ns();event=None;error_type=None
    try:
        raw=sys.stdin.buffer.read(1_000_001)
        if len(raw)>1_000_000:raise ContractError('EVENT_TOO_LARGE')
        event=json.loads(raw)
        if not isinstance(event,dict):raise ContractError('INVALID_EVENT')
        reply=pre(event,args.store) if args.action=='pre' else post(event,args.store)
    except Exception as error:
        error_type=type(error).__name__
        try:shadow=read_policy(args.store)['mode']=='shadow'
        except Exception:shadow=False
        supported=isinstance(event,dict) and event.get('tool_name')=='apply_patch'
        reply={} if shadow or not supported else denial('EXPERIMENTAL_HOOK_ERROR') if args.action=='pre' else {'systemMessage':'CLIM experimental Hook error; effect UNKNOWN.'}
    try:
        with locked(args.store):
            record=transport(event if isinstance(event,dict) else {},reply,args.action,(time.perf_counter_ns()-started)/1e6)
            record['telemetry_error']=error_type
            append_audit(args.store,record,filename='hook_events.jsonl')
    except Exception:
        print('CLIM_EXPERIMENT_TELEMETRY_GAP',file=sys.stderr)
        try:shadow=read_policy(args.store)['mode']=='shadow'
        except Exception:shadow=False
        if not shadow and args.action=='pre' and isinstance(event,dict) and event.get('tool_name')=='apply_patch':reply=denial('EXPERIMENTAL_RECORD_ERROR')
    print(json.dumps(reply,ensure_ascii=False))


if __name__=='__main__':main()
