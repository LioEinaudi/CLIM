"""M2.1 read-only terminal streaming of local Contract Shadow evidence."""
from __future__ import annotations
import json
import sys
import time

from .differential import LiveShadowDifferential, render_card
from .scope import ContractError


def _gap_events(obs: LiveShadowDifferential, limit: int = 15) -> list[dict]:
    with obs.sink.read() as c:
        rows=c.execute("SELECT seq,record_json FROM events ORDER BY seq DESC LIMIT ?",(max(1,limit*5),)).fetchall()
    result=[]
    for row in reversed(rows):
        event=json.loads(row['record_json'])
        if event['kind']=='M21_OBSERVER_COVERAGE_GAP':
            result.append({'seq':row['seq'], 'window_id':event.get('window_id'),
                           'reason':event['data']['reason'],
                           'phase':event['data']['hook_phase'],
                           'tool_kind':event['data']['tool_kind'], 'coverage':'UNKNOWN'})
    return result[-limit:]


def _denial_requests(obs: LiveShadowDifferential, limit: int) -> dict:
    # This is a bounded event sample, not a count of all decisions or Host denials.
    scan_limit = 2000
    with obs.sink.read() as c:
        rows = c.execute('SELECT record_json FROM events ORDER BY seq DESC LIMIT ?',
                         (scan_limit + 1,)).fetchall()
    requests = []
    for row in rows[:scan_limit]:
        event = json.loads(row['record_json'])
        data = event.get('data', {})
        if event.get('kind') == 'M3B_PRE_DECISION' and data.get('host_denial_requested') is True:
            requests.append({'time': event.get('event_time_utc'),
                             'reason': data.get('reason_code'),
                             'receipt': data.get('receipt_id'),
                             'event_seq': event.get('event_seq')})
            if len(requests) >= limit:
                break
    return {'requests': requests, 'event_scan_limit': scan_limit,
            'event_scan_truncated': len(rows) > scan_limit,
            'host_denial_confirmed': 'UNVERIFIED'}


def evidence_snapshot(obs: LiveShadowDifferential, limit: int = 20) -> dict:
    report = obs.report(limit=limit)
    report['observer_gaps'] = _gap_events(obs, limit=limit)
    report['local_denial_requests'] = _denial_requests(obs, limit=limit)
    windows=report['windows']
    report['summary']['m21_hook_gaps_shown'] = len(report['observer_gaps'])
    return report


def _tip(verdict: str) -> str:
    if verdict in ('CONTRACT_SCOPE_CONFLICT','ROOT_SCOPE_CONFLICT'):
        return '  Guidance: restrict proposed paths or request operator-approved stage change.'
    return ''


def _ux_gap_display_lines(gaps: list[dict]) -> list[str]:
    """Collapse repeated Shell coverage warnings in the card UI only.

    Never reinterpret an UNKNOWN as an observed effect. `evidence_snapshot`,
    SQLite event records and NDJSON retain every original gap independently.
    """
    shell, other = [], []
    for gap in gaps:
        if str(gap.get('tool_kind', '')).lower() in ('bash', 'shell'):
            shell.append(gap)
        else:
            other.append(gap)
    lines = []
    if shell:
        pre = sum(str(g.get('phase', '')).lower().startswith('pre') for g in shell)
        post = sum(str(g.get('phase', '')).lower().startswith('post') for g in shell)
        identifiers = [g.get('window_id') for g in shell]
        if all(isinstance(w, str) and w for w in identifiers):
            identities = f'{len(set(identifiers))} distinct Hook windows'
        else:
            identities = 'Hook-window count unknown (missing IDs)'
        reasons = {}
        for gap in shell:
            reason = str(gap.get('reason') or 'UNSPECIFIED')
            reasons[reason] = reasons.get(reason, 0) + 1
        reason_summary = ', '.join(f'{name}={count}'
                                   for name, count in sorted(reasons.items()))
        lines.append(f'[UNKNOWN] Shell coverage (shown sample): {identities}; '
                     f'{len(shell)} gap events (Pre={pre}, Post={post}); '
                     f'reasons: {reason_summary}. '
                     'Shell effects are NOT verified or blocked by this gate.')
    for gap in other:
        lines.append(f"[UNKNOWN] Hook {gap.get('phase', '?')} "
                     f"{gap.get('tool_kind', '?')} | {gap.get('reason', 'UNSPECIFIED')} "
                     '(not a verified tool effect)')
    return lines


def render_live_card(report: dict) -> str:
    stats=report['summary']
    status=report['task']
    lines=['CLIM Contract Live · LOCAL EVIDENCE / HOST UNVERIFIED',
      f"Task: {status['task_id']}  Stage: {status['active_stage'] or 'none'}  "
      f"Contract: {status['active_contract'] or 'none'}",
      f"M1 Exec: pending={stats['m1_exec_pending']} recovered/unknown={stats['m1_exec_recovered']}",
      f"M2 Obs (shown): complete={stats['m2_obs_complete']} partial={stats['m2_obs_partial']} "
      f"unknown={stats['m2_obs_unknown']} | Hook gaps shown={stats['m21_hook_gaps_shown']}"]
    if status.get('active_scope'):
        lines.append('Authorized active scope: '+', '.join(status['active_scope'][:6]))
    denial = report['local_denial_requests']
    lines.append(f"Denial requests (recent {denial['event_scan_limit']} events; Host unverified):")
    if not denial['requests']:
        lines.append('  None in scanned events; this does not establish Hook coverage.')
    for item in denial['requests']:
        lines.append(f"[DENIAL_REQUESTED] {item['time'] or 'time unknown'} | "
                     f"{item['reason'] or 'reason unknown'} | Receipt: {item['receipt'] or 'unavailable'}")
    # Reuse the tested M2 verdict mapping; do not reclassify Shell unknown as conflict.
    base=render_card(report).splitlines()
    first = next((i for i,line in enumerate(base)
                  if line.startswith(('[OBSERVED]','[CONFLICT]','[UNKNOWN]'))),len(base))
    for line in base[first:]:
        if line.startswith('Observation never '):
            continue
        lines.append(line)
        if line.startswith('[CONFLICT]') and 'CONTRACT_SCOPE_CONFLICT' in line:
            lines.append(_tip('CONTRACT_SCOPE_CONFLICT'))
    lines.extend(_ux_gap_display_lines(report['observer_gaps']))
    lines.append('Scope conflict != proven writer; Hook gaps != completed observations.')
    return '\n'.join(lines)


def last_event_seq(obs: LiveShadowDifferential) -> int:
    with obs.sink.read() as c:
        return int(c.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0])


def watch(obs: LiveShadowDifferential, *, interval:float=0.5,
          limit:int=20, fmt:str='card', once:bool=False,
          max_polls:int|None=None, out=None) -> None:
    """Poll a monotonic SQLite event watermark; print only when it changes.

    stdout Card frames are separated (no dependency on curses/TTY features).
    JSON mode emits one full snapshot per new watermark (newline delimited).
    """
    out=out or sys.stdout
    if not (0.1 <= interval <= 60):
        raise ContractError('INVALID_WATCH_INTERVAL')
    previous=None
    polls=0
    while True:
        seq=last_event_seq(obs)
        if previous != seq:
            report=evidence_snapshot(obs,limit)
            if fmt=='ndjson':
                out.write(json.dumps({'event_seq':seq,'report':report},ensure_ascii=False,sort_keys=True)+'\n')
            else:
                out.write(('\n' if previous is not None else '')+render_live_card(report)+'\n')
            out.flush()
            previous=seq
        polls+=1
        if once or (max_polls is not None and polls>=max_polls):
            return
        time.sleep(interval)
