"""M2 opt-in bounded live filesystem observations for M1 tool windows.

P = declared tool targets; A = trusted active contract decision; O = *bounded*
filesystem state delta; C = explicit evidence limits.  A changed hash does NOT
attribute the writer.  No Hook installation, OS gate, Shell effect inference,
or implicit protection happens here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any

from .scope import ContractError, require, resource, authorized, safe_identifier
from .service import ContractRuntime
from .storage import canonical, digest

MAX_WATCHED = 100
MAX_FILE_BYTES = 4 * 1024 * 1024


def _state(root: Path, name: str) -> dict:
    """Best-effort local snapshot. Unstable/missing/oversize states are explicit."""
    resource(name)
    target = root
    try:
        for segment in name.split('/'):
            target = target / segment
            try:
                mode = target.lstat().st_mode
            except FileNotFoundError:
                return {'kind': 'ABSENT'}
            if stat.S_ISLNK(mode):
                return {'kind': 'UNINSPECTABLE', 'reason': 'SYMLINK_PATH'}
        meta = target.stat()
        if not stat.S_ISREG(meta.st_mode):
            return {'kind': 'UNINSPECTABLE', 'reason': 'NON_REGULAR_FILE'}
        if meta.st_size > MAX_FILE_BYTES:
            return {'kind': 'UNINSPECTABLE', 'reason': 'OVERSIZE_FILE'}
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(target, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
                return {'kind': 'UNINSPECTABLE', 'reason': 'UNSTABLE_FILE'}
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(fd)
            if (len(data) > MAX_FILE_BYTES or before.st_size != len(data) or
                (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)):
                return {'kind': 'UNINSPECTABLE', 'reason': 'CHANGED_DURING_READ'}
            return {'kind': 'HASH', 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return {'kind': 'UNINSPECTABLE', 'reason': 'IO_OR_IDENTITY_UNVERIFIED'}


def _capture(root: Path, names: list[str]) -> dict:
    return {name: _state(root, name) for name in names}


def _unknowns(*snapshots: dict) -> list[str]:
    out = set()
    for snaps in snapshots:
        for item in snaps.values():
            if item['kind'] == 'UNINSPECTABLE':
                out.add('RESOURCE_' + item['reason'])
    return sorted(out)


def _changed(before: dict, after: dict) -> list[str]:
    return sorted(p for p in before if before[p]['kind'] in ('HASH', 'ABSENT') and
                  after[p]['kind'] in ('HASH', 'ABSENT') and before[p] != after[p])


class LiveShadowDifferential:
    """Local operator/host-adapter API. Explicitly non-enforcing.

    Host adapters must await pre() completing before dispatching a tool. An
    unmatched pre/post or concurrent external writer is not causally proven.
    """
    def __init__(self, runtime: ContractRuntime):
        self.runtime = runtime
        self.sink = runtime.sink
        with self.sink.transaction() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS m2_observation_windows (
                window_id TEXT PRIMARY KEY REFERENCES windows(window_id),
                pre_seq INTEGER NOT NULL, post_seq INTEGER,
                tool_kind TEXT NOT NULL, watch_json TEXT NOT NULL,
                before_json TEXT NOT NULL, after_json TEXT,
                decision_json TEXT NOT NULL, summary_json TEXT)''')

    def pre(self, *, window_id: str, session_id: str, tool_use_id: str,
            targets: list[str], watch: list[str] | None = None,
            tool_kind: str = 'apply_patch', actor_id: str | None = None) -> dict:
        require(tool_kind in ('apply_patch', 'shell', 'other'), 'INVALID_TOOL_KIND')
        require(isinstance(targets, list) and bool(targets), 'NO_DECLARED_TARGETS')
        require(watch is None or isinstance(watch, list), 'INVALID_WATCH_SET')
        names = list(dict.fromkeys([*targets, *(watch or [])]))
        require(len(names) <= MAX_WATCHED, 'WATCH_SET_TOO_LARGE')
        for p in names: resource(p)
        # M1 registers the window and checks the active contract in its own
        # transaction. The bounded snapshot is captured BEFORE pre() returns
        # to the host adapter. Failure between phases leaves UNKNOWN pending.
        receipt = self.runtime.begin_window(window_id=window_id,
            session_id=session_id, tool_use_id=tool_use_id,
            targets=targets, actor_id=actor_id)
        before = _capture(self.runtime.project, names)
        reasons = _unknowns(before)
        if tool_kind != 'apply_patch':
            reasons.append('SHELL_EFFECT_UNINSPECTED' if tool_kind == 'shell' else 'TOOL_EFFECT_UNINSPECTED')
        with self.sink.transaction() as c:
            row = c.execute('SELECT opened_seq FROM windows WHERE window_id=? AND status=\'PENDING\'',
                            (window_id,)).fetchone()
            require(row is not None, 'WINDOW_NOT_PENDING')
            state = self.runtime._state(c, self.sink)
            active = state['active_contract']
            active_policy = self.sink.latest(c, active) if active else None
            # Stage transition or other pre alteration cannot silently turn an
            # earlier decision into a verified active-contract decision.
            pre_event = c.execute('SELECT record_json FROM events WHERE seq=?',
                                  (row['opened_seq'],)).fetchone()
            pinned = json.loads(pre_event[0])['data'].get('contract_id')
            if pinned != active:
                reasons.append('ACTIVE_CONTRACT_CHANGED_DURING_PRE')
            decision = {'proposed': targets,
                'authority_verdict': receipt['scope_verdict'] if tool_kind == 'apply_patch' else 'UNVERIFIED_TOOL_TARGET_SEMANTICS',
                'declared_target_policy_verdict': receipt['scope_verdict'],
                'active_contract': pinned, 'stage': state['active_stage'],
                'contract_revision': active_policy['revision'] if active_policy and pinned == active else None,
                'authorized_scope': active_policy['payload']['allowed'] if active_policy and pinned == active else None,
                'denied_scope': active_policy['payload']['denied'] if active_policy and pinned == active else None,
                'observation_coverage': 'PARTIAL' if reasons else 'BOUNDED_WATCH_SET',
                'unknown_reasons': sorted(set(reasons)), 'enforced': False}
            # Pin tool_kind to the append-only PRE event: coverage semantics in
            # POST depend on this value, so the mutable observation index must
            # never be able to reinterpret an earlier tool call.
            event = self.sink.append(c, 'M2_PRE_SNAPSHOT',
                {'pre_seq': receipt['event_seq'], 'tool_kind': tool_kind,
                 'watch_digest': digest(names),
                 'snapshot_digest': digest(before), 'decision_digest': digest(decision)},
                window_id=window_id, session_id=session_id, actor_id=actor_id)
            c.execute('''INSERT INTO m2_observation_windows
                         (window_id,pre_seq,post_seq,tool_kind,watch_json,before_json,after_json,decision_json,summary_json)
                         VALUES(?,?,?,?,?,?,?,?,NULL)''',
                         (window_id,event['event_seq'],None,tool_kind,canonical(names),
                          canonical(before),None,canonical(decision)))
        return {'window_id': window_id, 'pre_seq': receipt['event_seq'],
                'observation_seq': event['event_seq'], **decision}

    def post(self, *, window_id: str) -> dict:
        safe_identifier(window_id)
        with self.sink.read() as c:
            rec = c.execute('SELECT * FROM m2_observation_windows WHERE window_id=?',
                            (window_id,)).fetchone()
            require(rec is not None, 'M2_PRE_SNAPSHOT_MISSING')
            require(rec['post_seq'] is None, 'M2_ALREADY_CLOSED')
            watch = json.loads(rec['watch_json'])
            before = json.loads(rec['before_json'])
            decision = json.loads(rec['decision_json'])
            tool_kind = rec['tool_kind']
            # Fail closed for an M2 index that is no longer backed by its
            # immutable PRE event (also rejects unverified legacy M2 rows).
            pre_record = c.execute('SELECT record_json FROM events WHERE seq=?',
                                   (rec['pre_seq'],)).fetchone()
            require(pre_record is not None and
                    json.loads(pre_record[0])['data'].get('tool_kind') == tool_kind,
                    'M2_EVIDENCE_INDEX_INCONSISTENT')
        after = _capture(self.runtime.project, watch)
        changed = _changed(before, after)
        reasons = sorted(set(decision['unknown_reasons'] + _unknowns(after)))
        if tool_kind == 'shell' and 'SHELL_EFFECT_UNINSPECTED' not in reasons:
            reasons.append('SHELL_EFFECT_UNINSPECTED')
        # M1's close receipt and M2's post snapshot are distinct transactions.
        # If interrupted between them, reporting correctly shows incomplete M2.
        self.runtime.close_window(window_id, changed,
            coverage='PARTIAL' if reasons else 'COMPLETE_BOUNDED')
        with self.sink.transaction() as c:
            win = c.execute('SELECT * FROM windows WHERE window_id=?', (window_id,)).fetchone()
            require(win is not None and win['status'] == 'CLOSED', 'WINDOW_NOT_CLOSED')
            overlap = c.execute('''SELECT 1 FROM windows
                WHERE window_id<>? AND opened_seq<?
                  AND (closed_seq IS NULL OR closed_seq>?) LIMIT 1''',
                (window_id, win['closed_seq'], win['opened_seq'])).fetchone() is not None
            if overlap: reasons.append('OVERLAPPING_WINDOWS')
            if tool_kind != 'apply_patch': reasons.append('TOOL_EFFECT_NOT_FULLY_OBSERVED')
            # Even without an observed overlap, local hash differences do not
            # establish which process wrote the file.
            cause = 'CAUSE_UNKNOWN' if changed else 'NO_CHANGE_OBSERVED_IN_BOUNDS'
            proposed = set(decision['proposed'])
            allowed = decision.get('authorized_scope')
            denied = decision.get('denied_scope')
            outside = (sorted(p for p in changed if not authorized([p], allowed, denied))
                       if isinstance(allowed, list) and isinstance(denied, list) else [])
            summary = {'window_id': window_id, 'proposed': decision['proposed'],
                'authority_verdict': decision['authority_verdict'],
                'active_contract': decision['active_contract'],
                'stage': decision['stage'], 'changed_paths': changed,
                'undeclared_observed_effects': sorted(set(changed) - proposed),
                'observed_outside_active_scope': outside,
                'attribution': cause,
                'coverage': 'PARTIAL' if reasons else 'COMPLETE_BOUNDED',
                'unknown_reasons': sorted(set(reasons)), 'overlap_seen': overlap,
                'watched_paths': len(watch), 'unwatched_workspace': True,
                'enforced': False, 'semantic_verified': False}
            event = self.sink.append(c, 'M2_POST_DIFFERENTIAL',
                {'window_close_seq': win['closed_seq'],
                 'after_digest': digest(after), 'summary_digest': digest(summary)},
                window_id=window_id, session_id=win['session_id'])
            c.execute('''UPDATE m2_observation_windows
                      SET post_seq=?,after_json=?,summary_json=? WHERE window_id=?''',
                      (event['event_seq'],canonical(after),canonical(summary),window_id))
        return summary

    def verify(self) -> dict:
        """Check M2 index against its append-only receipts in one WAL snapshot.

        Local consistency only; not source authentication or tamperproof storage.
        """
        self.sink.verify()
        with self.sink.read() as c:
            events = {}
            for row in c.execute('SELECT seq,record_json FROM events ORDER BY seq'):
                event = json.loads(row['record_json'])
                if event['kind'] in ('M2_PRE_SNAPSHOT', 'M2_POST_DIFFERENTIAL'):
                    events[row['seq']] = event
            rows = c.execute('SELECT * FROM m2_observation_windows').fetchall()
            seen = set()
            incomplete = 0
            for row in rows:
                wid = row['window_id']
                pre = events.get(row['pre_seq'])
                require(pre is not None and pre['kind'] == 'M2_PRE_SNAPSHOT' and
                        pre['window_id'] == wid, 'M2_EVIDENCE_INDEX_INCONSISTENT')
                require(pre['data'].get('tool_kind') in ('apply_patch', 'shell', 'other') and
                        pre['data']['tool_kind'] == row['tool_kind'] and
                        pre['data']['watch_digest'] == digest(json.loads(row['watch_json'])) and
                        pre['data']['snapshot_digest'] == digest(json.loads(row['before_json'])) and
                        pre['data']['decision_digest'] == digest(json.loads(row['decision_json'])),
                        'M2_EVIDENCE_INDEX_INCONSISTENT')
                window = c.execute('SELECT * FROM windows WHERE window_id=?',(wid,)).fetchone()
                require(window is not None and pre['data']['pre_seq'] == window['opened_seq'],
                        'M2_EVIDENCE_INDEX_INCONSISTENT')
                seen.add(row['pre_seq'])
                if row['post_seq'] is None:
                    require(row['after_json'] is None and row['summary_json'] is None,
                            'M2_EVIDENCE_INDEX_INCONSISTENT')
                    incomplete += 1
                else:
                    post = events.get(row['post_seq'])
                    require(post is not None and post['kind'] == 'M2_POST_DIFFERENTIAL' and
                            post['window_id'] == wid and
                            post['data']['window_close_seq'] == window['closed_seq'] and
                            post['data']['after_digest'] == digest(json.loads(row['after_json'])) and
                            post['data']['summary_digest'] == digest(json.loads(row['summary_json'])),
                            'M2_EVIDENCE_INDEX_INCONSISTENT')
                    seen.add(row['post_seq'])
            require(set(events) == seen, 'M2_EVIDENCE_INDEX_INCONSISTENT')
            unobserved = c.execute('SELECT COUNT(*) FROM windows w '
                'LEFT JOIN m2_observation_windows m ON w.window_id=m.window_id '
                'WHERE m.window_id IS NULL').fetchone()[0]
        return {'integrity':'LOCAL_CONSISTENCY_ONLY',
                'observations':len(rows), 'incomplete_observations':incomplete,
                'm1_windows_without_m2_snapshot':unobserved,
                'tamper_proof':False, 'origin_authenticated':False}

    def report(self, limit: int = 20) -> dict:
        require(type(limit) is int and 1 <= limit <= 200, 'INVALID_LIMIT')
        status = self.runtime.status()
        with self.sink.read() as c:
            rows = c.execute('''SELECT w.window_id,w.status,w.coverage AS m1_coverage,
                       m.tool_kind,m.decision_json,m.summary_json,m.pre_seq,m.post_seq
                       FROM windows AS w LEFT JOIN m2_observation_windows AS m
                         ON w.window_id=m.window_id
                       ORDER BY w.opened_seq DESC LIMIT ?''',(limit,)).fetchall()
            exec_states=dict(c.execute('SELECT status,COUNT(*) FROM windows GROUP BY status').fetchall())
        items = []
        for row in reversed(rows):
            if row['summary_json'] is not None:
                item = json.loads(row['summary_json'])
            else:
                decision = json.loads(row['decision_json']) if row['decision_json'] else {}
                reasons = list(decision.get('unknown_reasons', []))
                if row['status'] == 'RECOVERED_UNKNOWN':reasons.append('MISSING_POST_RECOVERED')
                elif row['status'] == 'CLOSED':reasons.append('POST_EVIDENCE_INCOMPLETE')
                else:reasons.append('MISSING_POST_OR_WINDOW_PENDING')
                if row['pre_seq'] is None:reasons.append('PRE_SNAPSHOT_MISSING')
                item = {'window_id': row['window_id'], 'proposed': decision.get('proposed'),
                    'authority_verdict': decision.get('authority_verdict', 'UNKNOWN'),
                    'active_contract': decision.get('active_contract'),
                    'stage': decision.get('stage'), 'changed_paths': [],
                    'undeclared_observed_effects': [], 'observed_outside_active_scope': [],
                    'attribution': 'CAUSE_UNKNOWN',
                    'coverage': 'UNKNOWN', 'unknown_reasons': sorted(set(reasons)),
                    'enforced': False, 'semantic_verified': False}
            items.append(item)
        summary={
            'm1_exec_pending':exec_states.get('PENDING',0),
            'm1_exec_recovered':exec_states.get('RECOVERED_UNKNOWN',0),
            'm2_obs_complete':sum(item.get('coverage')=='COMPLETE_BOUNDED' for item in items),
            'm2_obs_partial':sum(item.get('coverage')=='PARTIAL' for item in items),
            'm2_obs_unknown':sum(item.get('coverage')=='UNKNOWN' for item in items),
        }
        return {'schema': 'clim-m2-shadow-differential/v1', 'mode': 'SHADOW_ONLY',
                'task': status, 'windows': items, 'window_count': len(items), 'summary':summary,
                'limitations': ['NO_ATOMIC_PRE_SNAPSHOT_ANCHOR', 'BOUNDED_WATCH_SET_ONLY', 'CAUSE_NOT_PROVEN',
                                'SHELL_EFFECTS_NOT_ENFORCED', 'NO_OS_ATOMIC_GATE']}


def render_card(report: dict) -> str:
    status = report['task']
    lines = ['CLIM Contract Shadow · local observation (NO ENFORCEMENT)',
             f"Task: {status['task_id']} | Stage: {status['active_stage'] or 'none'} | "
             f"Contract: {status['active_contract'] or 'none'}",
             f"Windows shown: {report['window_count']} | M1 Exec Pending: {report.get('summary',{}).get('m1_exec_pending',status['pending_windows'])} | "
             f"M1 Exec Recovered: {report.get('summary',{}).get('m1_exec_recovered',0)}",
             f"M2 Obs (shown): Complete: {report.get('summary',{}).get('m2_obs_complete',0)} | "
             f"Partial: {report.get('summary',{}).get('m2_obs_partial',0)} | "
             f"UNKNOWN: {report.get('summary',{}).get('m2_obs_unknown',0)}"]
    for item in report['windows']:
        # Unknown coverage or tool semantics are NOT policy violations.
        # An observed out-of-scope file delta is a scope conflict, never proof
        # that the current Agent authored it.
        verdict = item.get('authority_verdict')
        if verdict in ('CONTRACT_SCOPE_CONFLICT', 'ROOT_SCOPE_CONFLICT',
                       'CONTRACT_EXPIRED', 'STATE_PRECONDITION_CHANGED') or item.get('observed_outside_active_scope'):
            label = 'CONFLICT'
        elif verdict == 'WITHIN_DECLARED_SCOPE' and item.get('coverage') == 'COMPLETE_BOUNDED':
            label = 'OBSERVED'
        else:
            label = 'UNKNOWN'
        lines.append(f"[{label}] {item['window_id']} | {item['authority_verdict']} | "
                     f"coverage={item['coverage']}")
        if item['changed_paths']:
            lines.append('  Changed in bounded watch set: ' + ', '.join(item['changed_paths'][:8]))
        if item.get('observed_outside_active_scope'):
            lines.append('  Observed scope conflict (writer unproven): ' + ', '.join(item['observed_outside_active_scope'][:8]))
        if item['unknown_reasons']:
            lines.append('  UNKNOWN: ' + ', '.join(item['unknown_reasons']))
        if item['attribution'] == 'CAUSE_UNKNOWN' and item['changed_paths']:
            lines.append('  Attribution: CAUSE_UNKNOWN (no unique writer proven)')
    lines.append('Observation never authorizes, denies, or proves semantic correctness.')
    return '\n'.join(lines)
