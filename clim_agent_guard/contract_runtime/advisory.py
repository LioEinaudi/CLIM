"""M3-A deterministic, opt-in, non-authorizing feedback.

Only a trusted active-contract, inspected Patch PRE scope decision can trigger
model-visible context.  Shell/unknown coverage is silent to the model.  Events
measure recorded proposals, not what the agent saw or why it acted.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .scope import ContractError, require
from .storage import canonical

_CONFLICT = frozenset(('CONTRACT_SCOPE_CONFLICT', 'ROOT_SCOPE_CONFLICT'))
_MAX_CONTEXT = 420  # bytes/chars bounded further by host additionalContextLimit


def _fingerprint(decision: dict) -> str:
    """No untrusted patch text goes into a feedback key or model context."""
    fields = [decision['stage'], decision['active_contract'], decision['contract_revision'],
              decision['authority_verdict'], decision['authorized_scope'], decision['proposed']]
    return hashlib.sha256(canonical(fields).encode('utf-8')).hexdigest()


def _eligible(decision: dict) -> bool:
    return (isinstance(decision, dict) and decision.get('authority_verdict') in _CONFLICT
            and decision.get('observation_coverage') == 'BOUNDED_WATCH_SET'
            and not decision.get('unknown_reasons')
            and isinstance(decision.get('stage'), str) and bool(decision['stage'])
            and isinstance(decision.get('active_contract'), str) and bool(decision['active_contract'])
            and type(decision.get('contract_revision')) is int
            and isinstance(decision.get('authorized_scope'), list)
            and isinstance(decision.get('proposed'), list))


def _message(code: str, count: int, allowed: list[str]) -> str:
    if count >= 3:
        return ('CLIM advisory REPEATED_SCOPE_CONFLICT (nonblocking): recurring recorded scope conflict; '
                'OPERATOR_REVIEW_RECOMMENDED. Observation only; tool permission unchanged.')
    if count == 2:
        return ('CLIM advisory SCOPE_CONFLICT (nonblocking): this proposed edit remains outside the '
                'registered stage scope. Keep edits within the current stage; no authority change.')
    # Give only a small, trusted positive allowed-scope description; never
    # echo untrusted proposed commands/paths, deny rules, capabilities or secrets.
    shown = ', '.join(allowed[:3])[:140]
    return ('CLIM advisory SCOPE_CONFLICT (nonblocking): proposed edit exceeds the registered '
            'stage scope. Current allowed patterns: ' + shown + '. '
            'Adjust the edit to the already authorized scope or ask the operator '
            'to review the registered stage. This notice does NOT grant permissions.')[:_MAX_CONTEXT]


def record_advisory(sink: Any, *, session_id: str, window_id: str, decision: dict) -> dict | None:
    """Serialize a scope-conflict note with a M2 PRE receipt in one ledger tx.

    Repetition is counted only if the immediately preceding registered window
    for that session had CLOSED *before this window opened*, and its advisory
    was also recorded before this PRE. Checking status at advisory time alone
    can mistake overlapping windows for sequential retries.
    This is not a claim the agent saw the prior advisory or acted causally.
    """
    if not _eligible(decision):
        return None
    fingerprint = _fingerprint(decision)
    with sink.transaction() as c:
        current = c.execute('''SELECT w.opened_seq, w.status, m.decision_json
            FROM windows w JOIN m2_observation_windows m USING(window_id)
            WHERE w.window_id=? AND w.session_id=?''', (window_id, session_id)).fetchone()
        require(current is not None and current['status'] == 'PENDING', 'M3_WINDOW_MISSING')
        actual = json.loads(current['decision_json'])
        require(all(decision.get(k) == v for k, v in actual.items()), 'M3_DECISION_CHANGED')
        decision = actual  # authoritative pinned M2 decision, not caller-supplied extras
        # Prevent duplicate advisories for the same PRE even on retry.
        for row in c.execute('SELECT record_json FROM events WHERE seq>? ORDER BY seq', (current['opened_seq'],)):
            event = json.loads(row[0])
            if event['kind'] == 'M3_ADVISORY' and event['window_id'] == window_id:
                raise ContractError('M3_ALREADY_RECORDED')
        previous = c.execute('''SELECT w.window_id,w.status,w.opened_seq,w.closed_seq
            FROM windows w WHERE w.session_id=? AND w.opened_seq<?
            ORDER BY w.opened_seq DESC LIMIT 1''', (session_id, current['opened_seq'])).fetchone()
        count = 1
        # No fabricated seriality for windows already overlapping in native time.
        if (previous is not None and previous['status'] == 'CLOSED'
                and previous['closed_seq'] is not None
                and previous['closed_seq'] < current['opened_seq']):
            # Only advisories already recorded when the new PRE opened may
            # contribute to a sequential retry. Late callback ordering cannot
            # retroactively establish continuity.
            for row in c.execute('SELECT record_json FROM events WHERE seq>? AND seq<? ORDER BY seq DESC',
                                 (previous['opened_seq'], current['opened_seq'])):
                event = json.loads(row[0])
                if event['kind'] == 'M3_ADVISORY' and event['window_id'] == previous['window_id']:
                    if event['data'].get('fingerprint') == fingerprint:
                        count = min(3, int(event['data']['repeat_count']) + 1)
                    break
        code = 'REPEATED_SCOPE_CONFLICT' if count >= 3 else 'SCOPE_CONFLICT'
        note = {'code':code, 'repeat_count':count, 'fingerprint':fingerprint,
                'contract_id':decision['active_contract'], 'contract_revision':decision['contract_revision'],
                'stage':decision['stage'], 'authority_verdict':decision['authority_verdict'],
                'operator_review_recommended':count >= 3,
                'model_visibility':'UNVERIFIED', 'permission_changed':False,
                'observation_coverage':decision['observation_coverage']}
        sink.append(c, 'M3_ADVISORY', note, session_id=session_id, window_id=window_id)
    return {'schema':'clim-m3a-advisory/v1', **note,
            'message':_message(code,count,decision['authorized_scope']),
            'enforced':False, 'authorized':False}


def pre_hook_context(advisory: dict | None) -> dict:
    """Codex PreToolUse model context only, never permissionDecision/updatedInput.

    The host decides whether to deliver context; emitting it is not proof of
    model visibility. Do not include arbitrary source/tool text in the context.
    """
    if advisory is None:
        return {}
    return {'hookSpecificOutput':{'hookEventName':'PreToolUse',
                                  'additionalContext':advisory['message']}}


def advisory_summary(sink: Any, limit: int = 2000) -> dict:
    """Operator-only counters. The next *recorded* proposal is not a D3 result."""
    require(type(limit) is int and 1 <= limit <= 100000, 'INVALID_M3_LIMIT')
    with sink.read() as c:
        rows = c.execute('SELECT record_json FROM events ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
    events = [json.loads(row[0]) for row in reversed(rows)]
    notes = [e for e in events if e['kind'] == 'M3_ADVISORY']
    next_proposal = {'WITHIN_DECLARED_SCOPE':0, 'STILL_CONFLICT':0, 'OTHER_OR_UNKNOWN':0, 'NOT_OBSERVED':0}
    for item in notes:
        after = next((e for e in events if e['event_seq'] > item['event_seq']
                      and e['session_id'] == item['session_id']
                      and e['kind'] == 'WINDOW_PRE_OBSERVED'), None)
        if after is None:
            next_proposal['NOT_OBSERVED'] += 1
        else:
            verdict = after['data'].get('scope_verdict')
            if verdict == 'WITHIN_DECLARED_SCOPE': next_proposal['WITHIN_DECLARED_SCOPE'] += 1
            elif verdict in _CONFLICT: next_proposal['STILL_CONFLICT'] += 1
            else: next_proposal['OTHER_OR_UNKNOWN'] += 1
    return {'schema':'clim-m3a-statistics/v1','ledger_events_examined':len(events),
            'advisory_count':len(notes),
            'operator_review_recommended':sum(bool(e['data'].get('operator_review_recommended')) for e in notes),
            'next_recorded_proposal':next_proposal,
            'limits':['WINDOWED_EVENT_SAMPLE', 'NOT_MODEL_VISIBILITY', 'NOT_CAUSAL_REPLAN_PROOF',
                      'SHELL_UNOBSERVED', 'NON_ENFORCING']}
