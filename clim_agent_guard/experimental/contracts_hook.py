"""Opt-in HC01 native adapter. Use only with independently registered tasks.

Raw native evidence and host receipts are the runner's responsibility. The local
audit records a REQUEST for denial, never fabricates host enforcement evidence.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time
from ..devpreview.hook import denial
from ..devpreview.store import read_json
from . import contracts as c, protect
from .contracts_audit import digest
from .permits import patch_identity, read_policy, ContractError


def _key(event):
    ids=[event.get('session_id'),event.get('tool_use_id')]
    c.require(all(isinstance(v,str) and 0<len(v)<=512 for v in ids),'MISSING_ACTION_IDENTITY')
    return digest(ids)


def _targets(event,policy):
    raw=event.get('tool_input',{}).get('command','')
    # Reject unsafe raw spellings before the older parser normalizes paths.
    for line in raw.splitlines():
        for prefix in ('*** Update File: ','*** Add File: ','*** Delete File: ','*** Move to: '):
            if line.startswith(prefix):c.resource(line[len(prefix):])
    return patch_identity(event,policy)


def _deny(doc,event,code,identity=None):
    from .feedback_renderer import render
    feedback=render(code,mode=doc['state'].get('feedback_mode','F1'))
    c._event(doc,'PRE_DENIED',tool_use_id=event.get('tool_use_id'),tool=event.get('tool_name'),code=code,
             targets=identity.get('targets') if identity else None,
             decision_id=feedback['decision_id'],visible_code=feedback['visible_code'],
             reason_template_version=feedback['reason_template_version'],feedback_mode=feedback['feedback_mode'],
             output_digest=digest(feedback['reply']),visibility_status='UNKNOWN_UNTIL_NATIVE_RECEIPT',
             enforcement='REQUESTED_DENY_NOT_HOST_CONFIRMED')
    return feedback['reply']


def pre(event,store,group):
    store=Path(store)
    with c._tx(store/'hc01') as doc:
        s=doc['state'];identity=None;is_patch=event.get('tool_name')=='apply_patch'
        try:
            c.require(isinstance(event.get('tool_name'),str) and event['tool_name'] in ('apply_patch','Bash','exec_command','bash','shell_command'),'INVALID_NATIVE_TOOL_ENVELOPE')
            key=_key(event);policy=read_policy(store)
            c.require(event.get('hook_event_name')=='PreToolUse','NOT_PRE_EVENT')
            c.require(Path(event.get('cwd','')).resolve()==Path(s['project_root']),'PROJECT_ROOT_MISMATCH')
            if is_patch:
                identity=_targets(event,policy)
                result=c._check(s,event['session_id'],identity['targets'],group=group)
                c.require(key not in s['steps'],'OPERATION_ALREADY_CONSUMED')
                prestate={p:c.file_state(s['project_root'],p) for p in identity['targets']}
                # Exact immutable step consumed in the same atomic commit as Pre.
                step={'task_id':s['task_id'],'session_id':event['session_id'],'tool_use_id':event['tool_use_id'],
                      'stage_id':s['active_stage'],'effective_contract':result.get('contract_id'),
                      'contract_generation':result.get('contract_generation'),'contract_version':result.get('contract_version'),
                      'exact_patch_sha256':identity['exact_patch_sha256'],'targets':identity['targets'],
                      'pre_state_digest':digest(prestate),'pre_state':prestate,'policy_revision':s['policy_revision'],
                      'native_policy_digest':digest(policy),'authority_revision':s['authority_revision'],
                      'expires_at':min(s['expires_at'],time.time()+60),'nonce':secrets.token_hex(16),'consumed':True,
                      'preconditions':result.get('preconditions',{}),'allowed_patterns':result.get('allowed_patterns'),
                      'race_prevention':'NOT_PROVIDED'}
            else:
                result={'contract_id':None};step=None
            reply=protect.pre(event,store)
            if reply.get('hookSpecificOutput',{}).get('permissionDecision')=='deny':
                return _deny(doc,event,'STATIC_P0_REJECTED',identity)
            if is_patch:s['steps'][key]=step
            for window in s['pending'].values():window['overlapped']=True
            s['pending'][key]={'step':step,'tool':event.get('tool_name'),'overlapped':bool(s['pending']),
                               'authority_revision':s['authority_revision']}
            c._event(doc,'PRE_ALLOWED',tool_use_id=event['tool_use_id'],tool=event.get('tool_name'),group=group,
                     step=step,E_proposed=identity['targets'] if identity else None,
                     E_authorized=result.get('allowed_patterns'),coverage='SUPPORTED_PATCH' if is_patch else 'UNKNOWN_SHELL',
                     enforced=False if group=='G0_SHADOW' else is_patch)
            return reply
        except (c.ContractViolation,ContractError,OSError,ValueError) as error:
            if group!='G0_SHADOW' and (is_patch or event.get('tool_name') not in ('Bash','exec_command','bash','shell_command')):return _deny(doc,event,str(error),identity)
            c._event(doc,'COVERAGE_GAP',tool_use_id=event.get('tool_use_id'),code=str(error),decision='UNKNOWN_NOT_ENFORCED')
            return {}


def post(event,store,group):
    store=Path(store)
    with c._tx(store/'hc01') as doc:
        s=doc['state'];key=_key(event);entry=s['pending'].get(key)
        reply=protect.post(event,store)
        if entry is None:
            c._event(doc,'POST_UNKNOWN',tool_use_id=event['tool_use_id'],code='ORPHAN_POST');return reply
        records=[json.loads(line) for line in (store/'events.jsonl').read_text().splitlines()]
        observed=next((r for r in reversed(records) if r.get('phase')=='POST' and r.get('session_id')==event['session_id'] and r.get('tool_use_id')==event['tool_use_id']),{})
        effect=observed.get('effect',{});gaps=copy.deepcopy(effect.get('coverage_gaps',[]));step=entry['step']
        if entry['authority_revision']!=s['authority_revision']:gaps.append({'reason':'contract_authority_changed'})
        if entry['overlapped']:gaps.append({'reason':'overlapping_tool_windows'})
        race=[]
        if step:
            if step['native_policy_digest']!=digest(read_policy(store)):gaps.append({'reason':'policy_changed'})
            if time.time()>=step['expires_at']:gaps.append({'reason':'step_expired_during_window'})
            for p,sha in step['preconditions'].items():
                if p not in step['targets']:
                    try:
                        if c.file_state(s['project_root'],p)['sha256']!=sha:race.append(p)
                    except c.ContractViolation:gaps.append({'reason':'dependency_identity_unknown','path':p})
        if race:gaps.append({'reason':'dependency_changed_after_pre_TOCTOU','paths':race})
        if entry['tool']!='apply_patch':gaps.append({'reason':'shell_write_semantics_not_enforced'})
        failed=protect._tool_failed(event.get('tool_response'))
        status=('TOCTOU_NOT_PREVENTED' if race else 'TOOL_FAILED_UNKNOWN' if failed else
                'UNKNOWN' if gaps else 'BOUNDED_EFFECT_OBSERVED')
        c._event(doc,'POST_OBSERVED' if status=='BOUNDED_EFFECT_OBSERVED' else 'POST_UNKNOWN',
                 tool_use_id=event['tool_use_id'],tool=event.get('tool_name'),group=group,status=status,
                 E_proposed=step['targets'] if step else None,E_authorized=step['allowed_patterns'] if step else None,
                 E_observed=effect.get('observed'),effect=effect,coverage_gaps=gaps,
                 attribution='CAUSE_UNKNOWN',semantic_status='UNVERIFIED',race_prevention='NOT_PROVIDED')
        del s['pending'][key]
        return reply


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['pre','post']);p.add_argument('--store',type=Path,required=True)
    p.add_argument('--group',required=True,choices=['G0_SHADOW','G1_STATIC','G2_DYNAMIC']);a=p.parse_args(argv)
    event={};error=None;started=time.perf_counter_ns()
    try:
        raw=sys.stdin.buffer.read(1_000_001);c.require(len(raw)<=1_000_000,'EVENT_TOO_LARGE');event=json.loads(raw)
        c.require(isinstance(event,dict),'INVALID_NATIVE_ENVELOPE')
        reply=(pre if a.phase=='pre' else post)(event,a.store,a.group)
    except Exception as exc:
        error=type(exc).__name__
        from .feedback_renderer import render
        is_uncovered_shell=isinstance(event,dict) and event.get('tool_name') in ('Bash','exec_command','bash','shell_command')
        reply=render('HC01_CALLBACK_UNAVAILABLE')['reply'] if a.phase=='pre' and a.group!='G0_SHADOW' and not is_uncovered_shell else {}
    if not isinstance(event,dict):event={}
    print(json.dumps(reply));sys.stdout.flush()
    from ..devpreview.store import append_audit
    try:append_audit(a.store,{'phase':a.phase,'tool':event.get('tool_name'),'error_type':error,'handler_ms':(time.perf_counter_ns()-started)/1e6},'hc01_transport.jsonl')
    except OSError:pass


if __name__=='__main__':main()
