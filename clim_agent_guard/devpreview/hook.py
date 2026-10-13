"""Codex native PreToolUse/PostToolUse transport for CLIM Developer Preview.

Uses the real CLIM Core reservation+verification for monitored file edits.
For other tools, supported-policy transport reports coverage and authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any
from clim_agent_guard.core import ActionProposal, Decision, EffectStatus, IntegrityGuard, StateCondition, ToolContract
from .store import append_audit, atomic_write, config_at, locked, read_json
from .policy import parse_patch, rel_target, policy_decision, monitored_paths, snapshot, residual

MAX_EVENT = 1_000_000


def denial(code: str, targets: list[str] | None = None, detail: str = '') -> dict:
    # Never leak the full protected policy inventory to an untrusted model.
    target = ', '.join(repr(t[:120]) for t in targets[:3]) if targets else 'this operation'
    reason = f'CLIM {code}: {target} is not authorized. ' + (detail or 'Use an approved target or ask the project owner to update CLIM policy.')
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
        'permissionDecision': 'deny', 'permissionDecisionReason': reason[:450]}}


def _guard() -> IntegrityGuard:
    return IntegrityGuard([ToolContract(
        tool='codex_patch', requires_fresh_state=True, require_idempotency_key=True,
        postconditions=(
            StateCondition('observed.expected_changed','eq', True, 'EXPECTED_CHANGE_MISSING'),
            StateCondition('observed.scope_valid','eq',True,'UNAUTHORIZED_EFFECT_OBSERVED'),
            StateCondition('observed.evidence_complete','eq',True,'EFFECT_EVIDENCE_INCOMPLETE'),
        ),
    )])


def _response_error(code: str) -> dict:
    return {'systemMessage': 'CLIM effect verification: ' + code + '. Review `clim doctor` and reconcile before further guarded writes.'}


def _classify(event: dict, root: Path, policy: dict) -> tuple[str, list[str], bool, str]:
    name = str(event.get('tool_name',''))
    raw = event.get('tool_input',{})
    if not isinstance(raw, dict):
        return name, [], False, 'MALFORMED_TOOL_INPUT'
    if name == 'apply_patch':
        try:
            paths = [rel_target(root, x) for x in parse_patch(raw.get('command'))]
            good, code, rejected = policy_decision(paths, policy)
            return name, paths, good, code if good else code + ': ' + ', '.join(rejected[:3])
        except (ValueError, OSError) as e:
            return name, [], False, 'UNINSPECTABLE_PATCH: ' + str(e)
    if name in ('Bash','exec_command','bash','shell_command'):
        cmd = raw.get('command') or raw.get('cmd')
        if isinstance(cmd, str) and cmd in policy.get('shell_allow_exact', []):
            return 'shell', [], True, 'EXPLICIT_COMMAND_ALLOW'
        return 'shell', [], False, 'SHELL_UNINSPECTED'
    return name, [], False, 'TOOL_NOT_INSTRUMENTED'


def _state(event: dict, policy: dict, root: Path, store: Path) -> dict:
    if Path(event.get('cwd','')).resolve(strict=False) != root:
        raise ValueError('Hook cwd differs from registered project root')
    if str(root) != policy.get('project_root'):
        raise ValueError('Policy project root mismatch')
    if not isinstance(policy.get('_version'),int):
        raise ValueError('Invalid policy version')
    if store.is_relative_to(root):
        raise ValueError('Policy state must not be stored inside project')
    return {'_version': policy['_version']}


def _key(event: dict) -> tuple[str,str]:
    session = event.get('session_id')
    use = event.get('tool_use_id')
    if not isinstance(session,str) or not session or not isinstance(use,str) or not use:
        raise ValueError('Missing session_id or tool_use_id')
    if len(session)>512 or len(use)>512:
        raise ValueError('Oversized tool identity')
    return hashlib.sha256((session+'\x00'+use).encode()).hexdigest(), use


def _one_time_approval(store: Path, kind: str, paths: list[str], event: dict) -> bool:
    grants=read_json(store/'one_time.json',{})
    if kind=='apply_patch':
        identity='patch:'+','.join(sorted(paths))
    else:
        arg=event.get('tool_input') or {}
        identity='shell:'+hashlib.sha256(str(arg.get('command',arg.get('cmd',''))).encode()).hexdigest()
    if grants.get(identity,0)>0:
        grants[identity] -= 1
        if grants[identity]<=0: del grants[identity]
        atomic_write(store/'one_time.json',grants)
        return True
    return False


def pre(event: dict, store: Path) -> dict:
    root = Path(event.get('cwd','')).resolve(strict=False)
    key, use = _key(event)
    if event.get('hook_event_name')!='PreToolUse':
        raise ValueError('Not a pre-tool event')
    with locked(store):
        pol = config_at(store)
        _state(event, pol, root, store)
        kind,paths,authorized,reason=_classify(event,root,pol)
        mode=pol['mode']
        grant=False
        pending=read_json(store/'pending.json',{})
        event_base={'phase':'PRE','mode':mode,'tool':kind,'tool_use_id':use,
                    'session_id':event.get('session_id'),'targets':paths,'policy_reason':reason,
                    'authorized':authorized,'granted_once':grant}
        if mode=='shadow':
            if kind=='apply_patch' and paths:
                names,complete=monitored_paths(root,pol,paths)
                pending[key]={'targets':paths,'before':snapshot(root,names), 'complete':complete,
                              'policy_version':pol['_version'],'mode':'shadow','tool_use_id':use}
                atomic_write(store/'pending.json',pending)
            append_audit(store, {**event_base,'decision':'WOULD_ALLOW' if authorized else 'WOULD_BLOCK', 'enforced':False})
            return {}  # Deliberately no model-visible advice in shadow mode.
        if pending:
            append_audit(store,{**event_base,'decision':'BLOCK','code':'PENDING_EFFECT'})
            return denial('PENDING_EFFECT',detail='An earlier tool result is unverified. Run `clim doctor`.')
        if (store/'incident.json').exists():
            append_audit(store,{**event_base,'decision':'BLOCK','code':'UNCERTAIN_EFFECT'})
            return denial('UNCERTAIN_EFFECT',detail='Previous execution needs review; run `clim doctor`.')
        if not authorized:
            grant=_one_time_approval(store,kind,paths,event)
            event_base['granted_once']=grant
        if not (authorized or grant):
            append_audit(store,{**event_base,'decision':'BLOCK','code':reason.split(':',1)[0]})
            return denial(reason.split(':',1)[0],paths,
                detail='Choose an authorized file, or have the user approve this exact operation with `clim permit-once`.')
        if kind!='apply_patch':
            # Without a tool-specific effect observer, this is an explicit coverage gap.
            append_audit(store,{**event_base,'decision':'ALLOW_UNVERIFIED','code':'SHELL_APPROVED_UNVERIFIED'})
            return {}
        names,complete=monitored_paths(root,pol,paths)
        before=snapshot(root,names)
        if not complete or any(x in ('UNREADABLE','OVERSIZE','UNSAFE_OR_UNREADABLE') for x in before.values()):
            append_audit(store,{**event_base,'decision':'BLOCK','code':'EFFECT_COVERAGE_INCOMPLETE'})
            return denial('EFFECT_COVERAGE_INCOMPLETE', detail='Cannot verify the required watched files; review project coverage with `clim doctor`.')
        guard=_guard()
        cp=read_json(store/'ledger.json')
        if cp is not None:
            guard.load_state(cp)
        proposal=ActionProposal(tool='codex_patch',args={'paths':paths},observed_state_version=pol['_version'],
             action_id=key,idempotency_key=key)
        d=guard.precheck(proposal,{'_version':pol['_version']})
        if d.decision!=Decision.ALLOW:
            append_audit(store,{**event_base,'decision':d.decision.value,'code':d.code})
            return denial(d.code,paths)
        pending[key]={'targets':paths,'before':before,'complete':complete,
             'policy_version':pol['_version'],'mode':mode,'tool_use_id':use}
        atomic_write(store/'ledger.json',guard.dump_state())
        atomic_write(store/'pending.json',pending)
        append_audit(store,{**event_base,'decision':'ALLOW','code':d.code,'snapshot_count':len(before),'complete':complete})
        return {}


def post(event: dict, store: Path) -> dict:
    root=Path(event.get('cwd','')).resolve(strict=False)
    key,use=_key(event)
    if event.get('hook_event_name')!='PostToolUse':
        raise ValueError('Not a post-tool event')
    with locked(store):
        pol=config_at(store)
        _state(event,pol,root,store)
        pending=read_json(store/'pending.json',{})
        entry=pending.get(key)
        if entry is None:
            append_audit(store,{'phase':'POST','decision':'UNMATCHED','tool_use_id':use})
            return {}  # May be post for unmonitored/explicitly allowed shell.
        after_names, after_complete = monitored_paths(root,pol,entry['targets'])
        all_names = sorted(set(entry['before']) | set(after_names))
        # A protected file created during the tool call must be detected as new.
        before={**{p:None for p in all_names}, **entry['before']}
        after=snapshot(root,all_names)
        r=residual(before,after,entry['targets'])
        r['evidence_complete']=entry['complete'] and after_complete and not r['uncertain_paths']
        r['scope_valid']=not r['unauthorized_changed_paths']
        r['policy_unchanged']=(entry['policy_version']==pol['_version'])
        if entry['mode']=='shadow':
            status='OBSERVED' if r['evidence_complete'] else 'UNKNOWN'
            append_audit(store,{'phase':'POST','decision':status,'tool_use_id':use,
                'effect':r, 'enforced':False})
            del pending[key]
            atomic_write(store/'pending.json',pending)
            return {}
        guard=_guard()
        guard.load_state(read_json(store/'ledger.json'))
        proposal=ActionProposal(tool='codex_patch',args={'paths':entry['targets']},
            observed_state_version=entry['policy_version'],action_id=key,idempotency_key=key)
        valid = r['evidence_complete'] and r['scope_valid'] and r['policy_unchanged']
        status=EffectStatus.SUCCESS if valid else EffectStatus.UNKNOWN
        after_state={'_version':entry['policy_version'],'observed':{
            'expected_changed':r['expected_changed'],'scope_valid':r['scope_valid'],
            'evidence_complete':r['evidence_complete']}}
        verdict=guard.verify_effect(proposal,{'_version':entry['policy_version']},after_state,status)
        atomic_write(store/'ledger.json',guard.dump_state())
        del pending[key]
        atomic_write(store/'pending.json',pending)
        append_audit(store,{'phase':'POST','decision':verdict.decision.value,'code':verdict.code,
            'tool_use_id':use,'effect':r,'policy_unchanged':r['policy_unchanged'], 'enforced':True})
        if verdict.decision != Decision.ALLOW:
            atomic_write(store/'incident.json',{'code':verdict.code,'effect':r,'tool_use_id':use})
            return _response_error(verdict.code)
        return {'systemMessage':'CLIM: EFFECT_VERIFIED for monitored file change.'}


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('phase', choices=['pre','post'])
    ap.add_argument('--store', type=Path,required=True)
    args=ap.parse_args(argv)
    event = None
    try:
        raw=sys.stdin.buffer.read(MAX_EVENT+1)
        if len(raw)>MAX_EVENT: raise ValueError('Oversized hook event')
        event=json.loads(raw)
        if not isinstance(event,dict): raise ValueError('Invalid hook event')
        reply=pre(event,args.store) if args.phase=='pre' else post(event,args.store)
    except Exception as e:
        # A hook transport error is not approval. Codex may ignore hook errors;
        # native OS sandbox and permissions remain necessary.
        if args.phase=='pre':
            # Shadow is observational: do not change tool behavior for a telemetry fault.
            try: is_shadow = config_at(args.store).get('mode') == 'shadow'
            except Exception: is_shadow = False
            reply = {} if is_shadow else denial('HOOK_ERROR',detail=str(e)[:180])
        else: reply=_response_error('HOOK_ERROR: '+str(e)[:180])
    try:
        with locked(args.store):
            append_audit(args.store, {'phase':args.phase, 'input':event, 'output':reply},
                         filename='hook_events.jsonl')
    except Exception as e:
        try: is_shadow = config_at(args.store).get('mode') == 'shadow'
        except Exception: is_shadow = False
        if args.phase == 'pre' and not is_shadow:
            reply = denial('HOOK_RECORD_ERROR', detail=str(e)[:180])
        elif args.phase == 'post':
            reply = _response_error('HOOK_RECORD_ERROR: '+str(e)[:180])
    print(json.dumps(reply,ensure_ascii=False))

if __name__=='__main__':
    main()
