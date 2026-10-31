"""M3-A operator diagnostics. Read-only; neither installs hooks nor grants trust."""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .codex_setup import _owned
from ..devpreview.store import project_store


def contract_doctor(project: Path, *, stale_seconds: int = 900) -> dict:
    root = Path(project).expanduser().resolve(strict=True)
    hookfile = root / '.codex' / 'hooks.json'
    ledger = project_store(root) / 'contract_runtime' / 'ledger.sqlite3'
    result = {'schema':'clim-contract-doctor/v1','project':str(root),
              'hook_config':'NOT_INSTALLED', 'hook_review_trust':'UNVERIFIED',
              'observer_health':'OBSERVER_HEALTH_UNKNOWN',
              'last_pre':None,'last_post':None,'pending_windows':None,
              'feedback_configured':False,'enforced':False,'issues':[],
              'enforcement_configured':False, 'enforcement_health':'ENFORCEMENT_DISABLED',
              'enforcement_pre_decisions':None, 'enforcement_denial_requests':None,
              'enforcement_event_scan_limit':2000, 'enforcement_events_scanned':None,
              'enforcement_scan_truncated':None, 'last_enforcement_decision':None,
              'host_denial_confirmed':'UNVERIFIED'}
    if hookfile.is_symlink():
        result['hook_config']='INVALID_CONFIG';result['issues'].append('UNSAFE_HOOK_SYMLINK')
    elif hookfile.is_file():
        try:
            doc = json.loads(hookfile.read_text(encoding='utf-8'))
            # Treat malformed third-party config as a diagnostic, not a crash.
            # Match the installer's expected structure without modifying it.
            if not isinstance(doc, dict) or not isinstance(doc.get('hooks'), dict):
                raise ValueError('INVALID_CODEX_HOOK_CONFIG')
            records = {}
            for phase in ('PreToolUse','PostToolUse'):
                groups = doc['hooks'].get(phase, [])
                if not isinstance(groups, list):
                    raise ValueError('INVALID_CODEX_HOOK_CONFIG')
                hooks = []
                for group in groups:
                    if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                        raise ValueError('INVALID_CODEX_HOOK_CONFIG')
                    for item in group['hooks']:
                        if not isinstance(item, dict):
                            raise ValueError('INVALID_CODEX_HOOK_CONFIG')
                        if _owned(item):
                            hooks.append(item)
                records[phase] = hooks
            result['hook_config'] = ('INSTALLED' if records['PreToolUse'] and records['PostToolUse']
                                     else 'INCOMPLETE_OR_ABSENT')
            result['feedback_configured'] = any('--enable-feedback' in h['command'] for h in records['PreToolUse'])
            result['enforcement_configured'] = (result['hook_config']=='INSTALLED' and
                any('--enable-enforcement' in h['command'] for h in records['PreToolUse']))
            if result['enforcement_configured']:
                result['enforcement_health']='ENFORCEMENT_CONFIGURED_HOST_UNVERIFIED'
        except (KeyError,TypeError,ValueError,UnicodeError,OSError):
            result['hook_config']='INVALID_CONFIG';result['issues'].append('INVALID_HOOK_CONFIG')
            result['enforcement_configured']=None
            result['enforcement_health']='ENFORCEMENT_CONFIG_UNKNOWN'
    if result['hook_config']=='INVALID_CONFIG':
        result['enforcement_configured']=None
        result['enforcement_health']='ENFORCEMENT_CONFIG_UNKNOWN'
    if result['hook_config'] != 'INSTALLED':
        result['issues'].append('REVIEW_PROJECT_HOOK_INSTALLATION')
    if not ledger.is_file() or ledger.is_symlink():
        result['issues'].append('NO_READABLE_CONTRACT_LEDGER')
        return result
    try:
        # Read-only URI avoids creating a database, schema or new contract.
        connection=sqlite3.connect(ledger.as_uri()+'?mode=ro',uri=True,timeout=0.15)
        try:
            connection.execute('BEGIN')
            result['pending_windows'] = connection.execute(
                "SELECT COUNT(*) FROM windows WHERE status='PENDING'").fetchone()[0]
            rows=connection.execute('SELECT record_json FROM events ORDER BY seq DESC LIMIT 2001').fetchall()
            pre_decisions = 0
            denial_requests = 0
            last_decision = None
            for (record,) in rows[:2000]:
                event=json.loads(record)
                if event['kind']=='M3B_PRE_DECISION':
                    pre_decisions+=1
                    if event['data'].get('host_denial_requested'):
                        denial_requests+=1
                    if last_decision is None:
                        data=event['data']
                        last_decision={'time':event.get('event_time_utc'),
                                       'verdict':data.get('verdict'),
                                       'reason':data.get('reason_code'),
                                       'receipt':data.get('receipt_id'),
                                       'event_seq':event.get('event_seq')}
                if event['kind'] == 'M2_PRE_SNAPSHOT' and result['last_pre'] is None:
                    result['last_pre']=event['event_time_utc']
                if event['kind'] == 'M2_POST_DIFFERENTIAL' and result['last_post'] is None:
                    result['last_post']=event['event_time_utc']
                # Do not break: enforcement event totals require the full
                # bounded event sample, independent from M2 activity.
            connection.commit()
            result.update(enforcement_pre_decisions=pre_decisions,
                          enforcement_denial_requests=denial_requests,
                          enforcement_events_scanned=min(len(rows),2000),
                          enforcement_scan_truncated=len(rows)>2000,
                          last_enforcement_decision=last_decision)
        finally:connection.close()
        if result['last_pre']:
            delta=(datetime.now(timezone.utc)-datetime.fromisoformat(result['last_pre'])).total_seconds()
            if 0 <= delta <= stale_seconds:
                result['observer_health']='RECENT_PRE_OBSERVED'
            else:
                result['issues'].append('NO_RECENT_PRE_OBSERVED')
        else:
            result['issues'].append('NO_PRE_OBSERVED')
        if result['pending_windows']:
            result['issues'].append('PENDING_WINDOWS_REVIEW_EFFECTS')
    except (sqlite3.Error,ValueError,KeyError,OSError):
        result['issues'].append('OBSERVER_LEDGER_UNREADABLE')
        if result['enforcement_configured']:
            result['enforcement_health']='ENFORCEMENT_COVERAGE_UNKNOWN'
    # A trust flag in a project file is not authoritative host attestation.
    result['guidance']='Inspect /hooks in Codex. Local requests are not evidence of Host denial; this command cannot verify Host trust or fail-open coverage.'
    return result
