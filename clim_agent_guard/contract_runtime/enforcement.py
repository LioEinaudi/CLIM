"""M3-B experimental *declared-target* guard for Codex apply_patch PreToolUse.

This is NOT an OS execution boundary. It requests Host denial only for an
explicit contract scope violation; unknown, unavailable, malformed and Shell
operations do not produce an allow or deny decision. Local same-UID policy and
ledger do not authenticate an independent operator.
"""
from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
import os
import stat
import time
from typing import Any

from .scope import ContractError, authorized, require, resource
from .service import ContractRuntime, _file_hash
from .storage import digest, SQLiteEvidenceSink

WITHIN = 'WITHIN_AUTHORIZED_SCOPE'
VIOLATION = 'EXPLICIT_SCOPE_VIOLATION'
UNKNOWN = 'NOT_EVALUATED'

DENIAL_REASON = (
    'CLIM experimental contract scope: the proposed apply_patch targets extend '
    'outside the currently registered stage. Keep edits within the existing '
    'stage scope or contact the operator for a stage review. '
    'This hook decision does not grant or change any authority.'
)

# Opaque 128-bit cross-layer correlation token. It is not an authorization
# credential, signature, proof of tool identity, or assertion of Host denial.
_RECEIPT_RE = re.compile(r'clim-deny-[0-9a-f]{32}\Z')


def _valid_receipt_id(value: Any) -> bool:
    return isinstance(value, str) and _RECEIPT_RE.fullmatch(value) is not None


def declared_targets(tool_input: Any, project: Path) -> list[str]:
    """Conservative parser for the supported Codex *** Begin/End Patch envelope.

    Only extract targets from a complete, unambiguous patch envelope. No attempt
    to attest the actual filesystem effects or to support every patch syntax.
    """
    from .codex_observer import _relative_target, MAX_COMMAND
    require(isinstance(tool_input, dict), 'M3B_PATCH_INPUT_UNKNOWN')
    raw = tool_input.get('command')
    require(isinstance(raw, str) and 0 < len(raw) <= MAX_COMMAND, 'M3B_PATCH_INPUT_UNKNOWN')
    lines = raw.splitlines()
    require(len(lines) >= 3 and lines[0] == '*** Begin Patch'
            and lines[-1] == '*** End Patch'
            and lines.count('*** Begin Patch') == 1
            and lines.count('*** End Patch') == 1, 'M3B_PATCH_ENVELOPE_UNKNOWN')
    found = []
    for line in lines[1:-1]:
        if not line.startswith('*** '):
            continue
        if line.startswith('*** Update File: '):
            path = line[len('*** Update File: '):]
        elif line.startswith('*** Add File: '):
            path = line[len('*** Add File: '):]
        elif line.startswith('*** Delete File: '):
            path = line[len('*** Delete File: '):]
        elif line.startswith('*** Move to: '):
            path = line[len('*** Move to: '):]
        elif line == '*** End of File':
            # A valid hunk terminator, not another target declaration.
            continue
        else:
            raise ContractError('M3B_PATCH_SYNTAX_UNKNOWN')
        # Resource validation also rejects whitespace/control ambiguities and
        # parent traversal. Unknown input is not a scope violation.
        require(path and path == path.strip(), 'M3B_PATCH_TARGET_UNKNOWN')
        found.append(_relative_target(path, project))
    found = list(dict.fromkeys(found))
    require(0 < len(found) <= 100, 'M3B_PATCH_TARGETS_UNKNOWN')
    return found


def _check_declared_paths(root: Path, paths: list[str]) -> None:
    """Treat symlink components as UNKNOWN, not as proof of target containment.

    This check is not an atomic open/rename gate; files can still change later.
    """
    for name in paths:
        part = root
        for component in name.split('/'):
            part = part / component
            try:
                mode = part.lstat().st_mode
            except FileNotFoundError:
                # A new declared target may not exist yet.
                break
            except OSError as exc:
                raise ContractError('M3B_TARGET_IDENTITY_UNKNOWN') from exc
            if stat.S_ISLNK(mode):
                raise ContractError('M3B_SYMLINK_TARGET_UNKNOWN')


def _within_transaction(rt: ContractRuntime, c, targets: list[str], session_id: str) -> tuple[str, str, dict]:
    """Pin the active authority and its revision in the *same* ledger txn."""
    state = rt._state(c, rt.sink)
    rt._check_root(state)
    require(state['status'] == 'ACTIVE' and time.time() < state['expires_at'], 'M3B_TASK_INACTIVE')
    bound_session = state.get('session_id')
    require(bound_session is None or bound_session == session_id, 'M3B_SESSION_MISMATCH')
    cid = state.get('active_contract')
    require(isinstance(cid, str) and cid and state.get('active_stage'), 'M3B_CONTRACT_INACTIVE')
    rec = rt.sink.latest(c, cid)
    require(rec['status'] == 'ACTIVE', 'M3B_CONTRACT_INACTIVE')
    policy = rec['payload']
    require(time.time() < policy['expires_at'], 'M3B_CONTRACT_EXPIRED')
    _check_declared_paths(rt.project, targets)
    # A violated precondition makes the policy's applicability UNKNOWN; do not
    # describe a scope decision as authoritative while state is stale.
    for path, sha in policy['preconditions'].items():
        require(_file_hash(rt.project, path) == sha, 'M3B_PRECONDITION_CHANGED')
    info = {'contract_id': cid, 'revision': rec['revision'], 'stage': state['active_stage']}
    if not authorized(targets, state['root']['allowed'], state['root']['denied']):
        return VIOLATION, 'ROOT_SCOPE_CONFLICT', info
    if not authorized(targets, policy['allowed'], policy['denied']):
        return VIOLATION, 'CONTRACT_SCOPE_CONFLICT', info
    return WITHIN, 'WITHIN_DECLARED_SCOPE', info


def evaluate_pre(rt: ContractRuntime, *, window_id: str, session_id: str,
                 tool_use_id: str, targets: list[str]) -> dict:
    """Durable opt-in decision request. No WINDOW_PRE is emitted on denial.

    Any unavailable/untrusted authority becomes NOT_EVALUATED; database/Host
    failures are handled by the caller and must not be disguised as a deny.
    """
    from .scope import safe_identifier
    for val in (window_id, session_id, tool_use_id):
        safe_identifier(val)
    require(isinstance(targets, list) and 0 < len(targets) <= 100,
            'M3B_PATCH_TARGETS_UNKNOWN')
    for target in targets:
        resource(target)
    sink = rt.sink
    with sink.transaction() as c:
        # Duplicate callbacks for an identical Host tool identity must not
        # append contradictory decisions or fake extra denials.
        c.execute('''CREATE TABLE IF NOT EXISTS m3b_pre_decisions (
            window_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
            tool_use_id TEXT NOT NULL, event_seq INTEGER NOT NULL,
            target_digest TEXT NOT NULL)''')
        earlier = c.execute('SELECT * FROM m3b_pre_decisions WHERE window_id=?',
                            (window_id,)).fetchone()
        if earlier is not None:
            require(earlier['session_id'] == session_id and earlier['tool_use_id'] == tool_use_id
                    and earlier['target_digest'] == digest(targets), 'M3B_DUPLICATE_ID_MISMATCH')
            event = c.execute('SELECT record_json FROM events WHERE seq=?',
                              (earlier['event_seq'],)).fetchone()
            require(event is not None, 'M3B_EVIDENCE_INDEX_INCONSISTENT')
            record = json.loads(event[0])
            require(record['kind'] == 'M3B_PRE_DECISION' and record['window_id'] == window_id
                    and record['session_id'] == session_id
                    and record['data']['target_digest'] == earlier['target_digest']
                    and record['data']['tool_use_id']==tool_use_id,
                    'M3B_EVIDENCE_INDEX_INCONSISTENT')
            return {'schema':'clim-m3b-pre/v1', **record['data'],
                    'event_seq':record['event_seq'], 'replay':True}
        try:
            verdict, reason, info = _within_transaction(rt, c, targets, session_id)
        except (ContractError, KeyError, TypeError, ValueError) as exc:
            verdict, reason, info = UNKNOWN, (
                exc.code if isinstance(exc, ContractError) else 'M3B_AUTHORITY_UNVERIFIED'), {}
        requested = verdict == VIOLATION
        receipt_id = f'clim-deny-{secrets.token_hex(16)}' if requested else None
        data = {'verdict':verdict, 'reason_code':reason, 'target_digest':digest(targets), 'tool_use_id':tool_use_id,
                'authority':info, 'coverage':'DECLARED_PATCH_TARGETS_ONLY',
                'mode':'EXPERIMENTAL_OPT_IN', 'host_denial_requested':requested,
                'receipt_id':receipt_id,
                'host_denial_confirmed':False, 'enforced':False}
        event = sink.append(c,'M3B_PRE_DECISION',data,
                            session_id=session_id,window_id=window_id)
        c.execute('INSERT INTO m3b_pre_decisions VALUES(?,?,?,?,?)',
                  (window_id,session_id,tool_use_id,event['event_seq'],data['target_digest']))
        return {'schema':'clim-m3b-pre/v1',**data,'event_seq':event['event_seq'], 'replay':False}


def pre_denial_output(receipt: dict | None) -> dict:
    """Only a logged EXPLICIT_SCOPE_VIOLATION generates a Host deny request."""
    if not isinstance(receipt,dict) or receipt.get('verdict') != VIOLATION or not receipt.get('host_denial_requested'):
        return {}
    # Old ledger events (created before receipt_id existed) remain replayable.
    # Never invent a post-hoc receipt or interpolate untrusted text into Host
    # output. New events always carry a valid, persisted receipt_id.
    receipt_id = receipt.get('receipt_id')
    reason = DENIAL_REASON
    if _valid_receipt_id(receipt_id):
        reason += f' Receipt: {receipt_id}'
    return {'hookSpecificOutput': {'hookEventName':'PreToolUse',
        'permissionDecision':'deny', 'permissionDecisionReason':reason}}


def enforcement_summary(sink: SQLiteEvidenceSink, *, limit: int = 5000) -> dict:
    """Counts requested decisions, not actual Host denial successes."""
    require(type(limit) is int and 1 <= limit <= 100000,'INVALID_M3B_LIMIT')
    counts={WITHIN:0, VIOLATION:0, UNKNOWN:0}
    receipts_issued=0
    legacy_denials_without_receipt=0
    with sink.read() as c:
        rows=c.execute('SELECT record_json FROM events ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
        for row in rows:
            record=json.loads(row[0])
            if record['kind']=='M3B_PRE_DECISION':
                data=record['data']
                counts[data['verdict']]+=1
                if data['verdict']==VIOLATION:
                    if _valid_receipt_id(data.get('receipt_id')):
                        receipts_issued+=1
                    else:
                        legacy_denials_without_receipt+=1
    return {'schema':'clim-m3b-summary/v1', 'recorded_decisions':sum(counts.values()),
            'verdicts':counts, 'receipts_issued':receipts_issued,
            'legacy_denials_without_receipt':legacy_denials_without_receipt,
            'host_denials_confirmed':None,
            'limits':['HOST_DENIAL_NOT_ATTESTED','SAME_UID_UNTRUSTED',
                      'PATCH_TARGETS_ONLY','NO_SHELL_OR_OS_GATE','HOST_FAIL_OPEN_UNRESOLVED']}


def verify_enforcement(sink: SQLiteEvidenceSink) -> dict:
    """One-snapshot cross-check of a derived decision index and event ledger."""
    with sink.read() as c:
        present=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='m3b_pre_decisions'").fetchone()
        if not present:
            return {'schema':'clim-m3b-integrity/v1','decisions':0,'status':'NOT_INITIALIZED'}
        rows=c.execute('SELECT * FROM m3b_pre_decisions').fetchall()
        indexed={r['event_seq']:r for r in rows}
        seen=set()
        receipt_ids=set()
        legacy_denials_without_receipt=0
        for row in c.execute('SELECT seq,record_json FROM events ORDER BY seq'):
            event=json.loads(row['record_json'])
            if event['kind']!='M3B_PRE_DECISION':continue
            seq=row['seq']; rec=indexed.get(seq)
            require(rec is not None and rec['window_id']==event['window_id']
                    and rec['session_id']==event['session_id']
                    and rec['target_digest']==event['data']['target_digest']
                    and rec['tool_use_id']==event['data'].get('tool_use_id')
                    and event['data']['verdict'] in (WITHIN,VIOLATION,UNKNOWN)
                    and event['data']['host_denial_requested']==(event['data']['verdict']==VIOLATION),
                    'M3B_EVIDENCE_INDEX_INCONSISTENT')
            # Legacy append-only records have no receipt_id. Do not rewrite or
            # silently invent one when replaying them with the new verifier.
            data=event['data']
            rid=data.get('receipt_id')
            if 'receipt_id' in data:
                require((_valid_receipt_id(rid) if data['verdict']==VIOLATION else rid is None),
                        'M3B_EVIDENCE_INDEX_INCONSISTENT')
            elif data['verdict']==VIOLATION:
                legacy_denials_without_receipt+=1
            if rid is not None:
                require(rid not in receipt_ids,'M3B_EVIDENCE_INDEX_INCONSISTENT')
                receipt_ids.add(rid)
            require(seq not in seen,'M3B_EVIDENCE_INDEX_INCONSISTENT')
            seen.add(seq)
        require(len(seen)==len(indexed),'M3B_EVIDENCE_INDEX_INCONSISTENT')
        return {'schema':'clim-m3b-integrity/v1','decisions':len(seen),
                'receipts_linkable':len(receipt_ids),
                'legacy_denials_without_receipt':legacy_denials_without_receipt,
                'status':'LOCAL_CONSISTENCY_ONLY', 'host_denial_attested':False}
