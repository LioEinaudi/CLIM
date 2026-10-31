"""Experimental exact-action grants, bounded state checks and POSIX consumption.

Trust is an operator convention, not privilege separation. Same-user code can
rewrite this store. A successful Pre check does not close the tool's TOCTOU gap.
The legacy path-only `clim permit-once` is deliberately not consulted here.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from ..devpreview.policy import DEFAULT_DENY, MAX_COMMAND, parse_patch, rel_target
from ..devpreview.shadow import names, path_meta
from ..devpreview.store import atomic_write, locked, read_json

SCHEMA='clim-experimental-selective-protect/v1'


class ContractError(ValueError):
    pass


def digest(value):
    if not isinstance(value,bytes):
        value=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    return hashlib.sha256(value).hexdigest()


def read_policy(store):
    policy=read_json(Path(store)/'policy.json')
    if not isinstance(policy,dict) or policy.get('schema')!=SCHEMA:
        raise ContractError('INVALID_EXPERIMENTAL_POLICY')
    if policy.get('mode') not in ('shadow','selective-protect'):
        raise ContractError('INVALID_EXPERIMENTAL_MODE')
    if type(policy.get('revision')) is not int or policy['revision']<1:
        raise ContractError('INVALID_POLICY_REVISION')
    if not isinstance(policy.get('principal'),str) or not policy['principal']:
        raise ContractError('INVALID_OPERATOR_PRINCIPAL')
    if not isinstance(policy.get('protected'),list) or not all(isinstance(p,str) for p in policy['protected']):
        raise ContractError('INVALID_PROTECTION_PATTERNS')
    root=Path(policy['project_root']).resolve(strict=True)
    if str(root)!=policy['project_root'] or not root.is_dir() or Path(store).resolve().is_relative_to(root):
        raise ContractError('INVALID_TRUSTED_PROJECT_ROOT')
    return policy


def initialize(root,store,*,principal=None,inventory=None):
    root=Path(root).resolve(strict=True);store=Path(store).resolve()
    if not root.is_dir() or store.is_relative_to(root):
        raise ContractError('EXTERNAL_STORE_REQUIRED')
    with locked(store):
        if (store/'policy.json').exists():
            raise ContractError('EXPERIMENT_ALREADY_INITIALIZED')
        if inventory is not None:
            # Observation may include symlinks to disclose a gap. Exact grants
            # still use rel_target and reject those targets independently.
            inventory=sorted(set(names(root,p) for p in inventory))
        policy={'schema':SCHEMA,'project_root':str(root),'revision':1,'mode':'shadow',
                'principal':principal or f'uid:{os.getuid()}', 'protected':DEFAULT_DENY.copy(),
                'inventory':inventory,'postconditions':{},
                'limits':{'max_tracked':250,'max_file_bytes':4*1024*1024},
                'warning':'Same-user state is mutable; Pre checks do not prevent TOCTOU.'}
        atomic_write(store/'policy.json',policy)
        atomic_write(store/'exact_permits.json',{})
        atomic_write(store/'pending.json',{})
    return policy


def set_mode(store,mode):
    if mode not in ('shadow','selective-protect'):
        raise ContractError('INVALID_EXPERIMENTAL_MODE')
    with locked(store):
        policy=read_policy(store)
        if policy['mode']!=mode:
            policy['mode']=mode;policy['revision']+=1;atomic_write(Path(store)/'policy.json',policy)
    return policy


def patch_identity(event,policy):
    root=Path(policy['project_root'])
    if Path(event.get('cwd','')).resolve()!=root:
        raise ContractError('PROJECT_ROOT_MISMATCH')
    if event.get('tool_name')!='apply_patch':
        raise ContractError('UNSUPPORTED_PERMIT_TOOL')
    values=[event.get('session_id'),event.get('tool_use_id')]
    if not all(isinstance(x,str) and 0<len(x)<=512 for x in values):
        raise ContractError('MISSING_ACTION_IDENTITY')
    raw=event.get('tool_input',{})
    command=raw.get('command') if isinstance(raw,dict) else None
    if not isinstance(command,str) or not command or len(command)>MAX_COMMAND or '\x00' in command:
        raise ContractError('INVALID_PATCH_BODY')
    try:
        # Codex's valid Delete envelope can have only three lines. The released
        # parser requires four; extend target recognition only in this prototype,
        # without rewriting the request or changing its exact digest.
        lines=command.strip().splitlines() if isinstance(command,str) else []
        if len(lines)==3 and lines[0]=='*** Begin Patch' and lines[-1]=='*** End Patch' and re.fullmatch(r'\*\*\* Delete File: .+',lines[1]):
            raw_targets=[lines[1].removeprefix('*** Delete File: ')]
        else:raw_targets=parse_patch(command)
        targets=sorted(set(rel_target(root,p) for p in raw_targets))
    except (ValueError,OSError,RuntimeError) as error:
        raise ContractError('UNSAFE_OR_UNPARSEABLE_PATCH') from error
    return {'project_root':str(root),'principal':policy['principal'],
            'session_id':values[0],'operation_id':values[1],'tool_name':'apply_patch',
            'targets':targets,'exact_patch_sha256':hashlib.sha256(command.encode()).hexdigest(),
            'policy_revision':policy['revision'],'policy_digest':digest(policy)}


def relevant_state(root,targets):
    result={}
    for name in targets:
        try:name=rel_target(root,name)
        except (ValueError,OSError,RuntimeError) as error:
            raise ContractError('UNSAFE_PRESTATE_PATH') from error
        meta=path_meta(root,name)
        if meta.get('coverage')!='complete' or meta.get('kind') not in ('file','missing'):
            raise ContractError('PRESTATE_NOT_FULLY_OBSERVED')
        result[name]={'exists':meta['kind']!='missing','type':meta['kind'],
                      'sha256':meta.get('sha256'),'bytes':meta.get('bytes')}
    return result


def _now(value):
    value=time.time() if value is None else value
    if not isinstance(value,(int,float)) or not __import__('math').isfinite(value):
        raise ContractError('INVALID_CLOCK')
    return value


def issue_permit(store,event,*,principal,ttl=60,now=None):
    """Caller must independently review/register this exact request and state."""
    store=Path(store);now=_now(now)
    if not isinstance(ttl,(int,float)) or not 0<ttl<=300:
        raise ContractError('INVALID_EXPIRY')
    with locked(store):
        policy=read_policy(store)
        if principal!=policy['principal']:
            raise ContractError('UNREGISTERED_OPERATOR')
        binding=patch_identity(event,policy)
        states=relevant_state(Path(policy['project_root']),binding['targets'])
        permits=read_json(store/'exact_permits.json',{})
        nonce=secrets.token_hex(24)
        public_id=digest(nonce.encode())
        permits[public_id]={'binding':binding,'pre_state_digest':digest(states),
                            'pre_states':states,'issued_at':now,'expires_at':now+ttl,
                            'nonce':nonce,'consumed':False,'revoked':False}
        atomic_write(store/'exact_permits.json',permits)
    return {'status':'ISSUED_STATE_BOUND','permit_id':public_id,
            'pre_state_digest':digest(states),'expires_at':now+ttl,
            'race_prevention':'NOT_PROVIDED; state can change after the Pre check.'}


def consume_locked(store,event,policy,*,now=None,states=None):
    """Must hold the store lock. Consumes durably before allowing the request."""
    store=Path(store);now=_now(now)
    binding=patch_identity(event,policy)
    states=relevant_state(Path(policy['project_root']),binding['targets']) if states is None else states
    permits=read_json(store/'exact_permits.json',{})
    operation_fields=('project_root','principal','session_id','operation_id')
    if any(p.get('consumed') and all(p['binding'].get(k)==binding[k] for k in operation_fields)
           for p in permits.values()):
        return {'allowed':False,'status':'EXACT_ACTION_REPLAY'}
    status='NO_MATCHING_EXACT_PERMIT'
    for public_id,permit in permits.items():
        if permit['binding']!=binding or permit.get('consumed') or permit.get('revoked'):
            continue
        if not permit['issued_at']<=now<permit['expires_at']:
            permit['revoked']=True;status='PERMIT_EXPIRED_OR_CLOCK_INVALID'
        elif permit['pre_state_digest']!=digest(states):
            permit['revoked']=True;status='PRESTATE_CHANGED'
        else:
            permit['consumed']=True;permit['consumed_at']=now
            atomic_write(store/'exact_permits.json',permits)
            return {'allowed':True,'status':'STATE_BOUND_APPROVAL_VERIFIED_AT_PRE',
                    'permit_id':public_id,'pre_state_digest':digest(states),
                    'race_prevention':'NOT_PROVIDED'}
        atomic_write(store/'exact_permits.json',permits)
    return {'allowed':False,'status':status}


def consume_permit(store,event,*,now=None):
    with locked(store):
        return consume_locked(store,event,read_policy(store),now=now)


def register_postcondition(store,patch_sha256,expected,*,principal):
    """Trusted controller-owned hash/existence contract, never inferred from text."""
    with locked(store):
        policy=read_policy(store)
        if principal!=policy['principal']:
            raise ContractError('UNREGISTERED_OPERATOR')
        root=Path(policy['project_root'])
        clean={rel_target(root,p):v for p,v in expected.items()}
        for value in clean.values():
            if not isinstance(value,dict) or type(value.get('exists')) is not bool:
                raise ContractError('INVALID_STATE_CONTRACT')
            if value['exists'] and (value.get('type')!='file' or not isinstance(value.get('sha256'),str) or len(value['sha256'])!=64):
                raise ContractError('INVALID_STATE_CONTRACT')
        policy['postconditions'][patch_sha256]=clean
        policy['revision']+=1
        atomic_write(Path(store)/'policy.json',policy)
