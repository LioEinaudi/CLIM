"""A narrow MCP tool executor guarded by CLIM; no model or MCP SDK dependency."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

from clim_agent_guard.core import (
    ActionProposal, ArgumentBinding, Decision, EffectStatus, IntegrityGuard,
    StateCondition, ToolContract,
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: Path, value) -> None:
    fd, name = tempfile.mkstemp(prefix='.clim-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class BoundaryDenied(RuntimeError):
    pass


class FileBoundary:
    def __init__(self, policy_file: Path, state_dir: Path):
        self.policy_file = policy_file.resolve(strict=True)
        self.state_dir = state_dir.resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.server_instance = str(uuid.uuid4())

    def record(self, row) -> None:
        with (self.state_dir/'audit.jsonl').open('a') as out:
            out.write(json.dumps(row, sort_keys=True)+'\n')
            out.flush()
            os.fsync(out.fileno())

    def set_debug(self, path: str, debug: bool, operation_id: str) -> dict:
        """Host policy authorizes a path; caller text never grants authority."""
        with (self.state_dir/'lock').open('a+b') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            attempt = str(uuid.uuid4())
            receipt = {'transport':'MCP_SERVER_GUARD', 'server_instance':self.server_instance,
                       'attempt_id':attempt, 'operation_id':operation_id,
                       'arguments':{'path':path, 'debug':debug, 'operation_id':operation_id}}
            try:
                return self._execute(receipt, path, debug, operation_id)
            except BoundaryDenied:
                raise
            except Exception as exc:
                self.record(dict(receipt, phase='ADAPTER', decision='BLOCK', code='ADAPTER_DENY',
                                 reason=str(exc)))
                raise BoundaryDenied('CLIM: ADAPTER_DENY: '+str(exc)) from exc

    def _execute(self, receipt, path, debug, operation_id):
        if type(debug) is not bool or not isinstance(operation_id, str) or not 0<len(operation_id)<=128:
            raise ValueError('Expected boolean debug and nonempty operation ID up to 128 characters')
        if (self.state_dir/'incident.json').exists():
            raise ValueError('Prior uncertain effect requires operator reconciliation')
        policy_bytes = self.policy_file.read_bytes()
        policy = json.loads(policy_bytes)
        root = Path(policy['project_root']).resolve(strict=True)
        if not root.is_dir() or root in self.policy_file.parents or root in self.state_dir.parents:
            raise ValueError('Trusted policy/state must be outside the project')
        if type(policy['_version']) is not int or policy['_version']<0 or type(policy['user_confirmed']) is not bool:
            raise ValueError('Invalid host authority state')
        names = [policy['authorized_target'], *policy['protected_targets']]
        if len(set(names))!=len(names) or not policy['protected_targets']:
            raise ValueError('Authorized and protected files must be distinct')

        def resolve(name):
            raw = Path(name)
            item = raw if raw.is_absolute() else root/raw
            if item.is_symlink():
                raise ValueError('Symlink targets are unsupported')
            target = item.resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError('Only existing files are supported')
            return target

        watched = {name:resolve(name) for name in names}
        target = resolve(path)
        before_hashes = {name:sha(item) for name,item in watched.items()}
        guard = IntegrityGuard((ToolContract(
            tool='mcp_set_debug',
            preconditions=(StateCondition('user_confirmed','eq',True,'USER_CONFIRMATION_REQUIRED'),),
            argument_bindings=(ArgumentBinding(arg_path='path',state_path='authorized_path',
                value_type='path_canonical',base_state_path='sandbox_root',code='TARGET_NOT_AUTHORIZED'),),
            postconditions=(StateCondition('observed.changed','eq',True,'EXPECTED_EFFECT_NOT_OBSERVED'),
                StateCondition('observed.protected_unchanged','eq',True,'UNAUTHORIZED_EFFECT_OBSERVED'),
                StateCondition('observed.debug_matches','eq',True,'CONTENT_MISMATCH')),
            require_idempotency_key=True, requires_fresh_state=True),))
        ledger = self.state_dir/'ledger.json'
        if ledger.exists():
            guard.load_state(json.loads(ledger.read_text()))
        if any(entry.unresolved_attempt or entry.effect_status==EffectStatus.UNKNOWN
               for entry in guard.ledger.values()):
            raise ValueError('Unresolved prior effect requires operator reconciliation')
        state = {'_version':policy['_version'], 'user_confirmed':policy['user_confirmed'],
                 'authorized_path':policy['authorized_target'], 'sandbox_root':str(root)}
        proposal = ActionProposal(tool='mcp_set_debug',args={'path':path,'debug':debug},
            observed_state_version=policy['_version'],action_id=receipt['attempt_id'],idempotency_key=operation_id)
        verdict = guard.precheck(proposal,state)
        self.record(dict(receipt,phase='PRE',decision=verdict.decision.value,code=verdict.code,
                         policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),before_hashes=before_hashes))
        if verdict.decision!=Decision.ALLOW:
            raise BoundaryDenied('CLIM: '+verdict.code)
        # Persist the reservation before the side effect. A process crash leaves
        # an unresolved ledger entry; a replay cannot silently repeat it.
        atomic_json(ledger,guard.dump_state())
        try:
            value=json.loads(target.read_text())
            if not isinstance(value,dict):
                raise ValueError('Configuration must be a JSON object')
            value['debug']=debug
            atomic_json(target,value)
            after_hashes={name:sha(item) for name,item in watched.items()}
            observed={'changed':before_hashes[policy['authorized_target']]!=after_hashes[policy['authorized_target']],
                'protected_unchanged':all(before_hashes[name]==after_hashes[name] for name in policy['protected_targets']),
                'debug_matches':json.loads(target.read_text()).get('debug') is debug}
            policy_unchanged=self.policy_file.read_bytes()==policy_bytes
            status=EffectStatus.SUCCESS if policy_unchanged and all(observed.values()) else EffectStatus.UNKNOWN
        except Exception:
            observed={'changed':False,'protected_unchanged':False,'debug_matches':False}
            after_hashes={}
            status=EffectStatus.UNKNOWN
        after_state=dict(state,observed=observed)
        effect=guard.verify_effect(proposal,state,after_state,status)
        self.record(dict(receipt,phase='POST',decision=effect.decision.value,code=effect.code,
                         before_hashes=before_hashes,after_hashes=after_hashes,observed=observed))
        atomic_json(ledger,guard.dump_state())
        if effect.decision!=Decision.ALLOW:
            atomic_json(self.state_dir/'incident.json',{'attempt_id':receipt['attempt_id'],'code':effect.code})
            raise BoundaryDenied('CLIM: '+effect.code+'; reconciliation required')
        return dict(receipt,decision='ALLOW',code=effect.code,file_hashes_after=after_hashes)
