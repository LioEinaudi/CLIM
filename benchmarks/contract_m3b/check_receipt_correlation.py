"""Compare a PRIVATE Host refusal excerpt to the local M3-B ledger receipt.

Does NOT authenticate Host provenance, independently establish nested Host identity,
prove a denial prevented execution, or validate a trusted OS security boundary.

Example:
  python benchmarks/contract_m3b/check_receipt_correlation.py \
    --ledger /path/to/ledger.sqlite3 --host-feedback /path/to/PRIVATE_host_output.txt \
    --blocked-file /path/to/src/client/blocked.py --before-sha256 SHA256HEX
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3

PATTERN = re.compile(r'\bReceipt: (clim-deny-[a-f0-9]{32})\b')


def check(ledger: Path, host_feedback: Path, blocked_file: Path,
          before_sha256: str, window_id: str | None = None) -> dict:
    result = {'schema':'clim-m3b-correlation-check/v1', 'scope':'LOCAL_TEXT_AND_HASH_ONLY',
              'host_origin_authenticated':False, 'nested_hook_tool_id_confirmed':False,
              'host_denial_confirmed_by_script':False,
              'gate':'FAIL'}
    if not re.fullmatch(r'[a-fA-F0-9]{64}', before_sha256):
        result['reason'] = 'INVALID_BEFORE_SHA256'
        return result
    text = host_feedback.read_text(encoding='utf-8')
    ids = set(PATTERN.findall(text))
    result['host_receipt_count'] = len(ids)
    if len(ids) != 1:
        result['reason'] = 'HOST_RECEIPT_NOT_UNIQUE'
        return result
    host_receipt = next(iter(ids))
    result['host_receipt_id'] = host_receipt
    # Read-only SQLite access: never modify an original Host/ledger receipt.
    with sqlite3.connect(f'file:{ledger.resolve()}?mode=ro', uri=True) as conn:
        rows = conn.execute('SELECT record_json FROM events ORDER BY seq').fetchall()
    matches=[]
    for row in rows:
        event=json.loads(row[0])
        if event.get('kind')!='M3B_PRE_DECISION':
            continue
        data=event.get('data') or {}
        if data.get('receipt_id') == host_receipt:
            matches.append(event)
    result['ledger_matches'] = len(matches)
    if len(matches)!=1:
        result['reason']='LEDGER_RECEIPT_NOT_UNIQUE'
        return result
    event=matches[0]
    result['window_id'] = event.get('window_id')
    result['session_id'] = event.get('session_id')
    result['ledger_event_seq'] = event.get('event_seq')
    if window_id and event.get('window_id') != window_id:
        result['reason']='WINDOW_ID_MISMATCH'
        return result
    if event['data'].get('verdict')!='EXPLICIT_SCOPE_VIOLATION' or not event['data'].get('host_denial_requested'):
        result['reason']='LEDGER_NOT_A_DENIAL_REQUEST'
        return result
    # A blocked file being unchanged is required but not sufficient proof of
    # a Host deny; the real Host refusal itself must be inspected separately.
    after_sha256 = hashlib.sha256(blocked_file.read_bytes()).hexdigest()
    result['blocked_file_sha256_unchanged'] = after_sha256.lower() == before_sha256.lower()
    if not result['blocked_file_sha256_unchanged']:
        result['reason']='BLOCKED_FILE_CHANGED'
        return result
    result['gate']='PASS_RECEIPT_TEXT_MATCH_ONLY'
    result['reason']='REQUIRES_PRIVATE_HOST_PROVENANCE_AND_RECEIPT_INSPECTION'
    return result


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ledger',type=Path,required=True)
    p.add_argument('--host-feedback',type=Path,required=True)
    p.add_argument('--blocked-file',type=Path,required=True)
    p.add_argument('--before-sha256',required=True)
    p.add_argument('--window-id')
    args=p.parse_args()
    try:
        result=check(args.ledger,args.host_feedback,args.blocked_file,args.before_sha256,args.window_id)
    except (OSError,sqlite3.Error,ValueError,KeyError,json.JSONDecodeError) as exc:
        result={'schema':'clim-m3b-correlation-check/v1','gate':'FAIL',
                'reason':type(exc).__name__, 'host_origin_authenticated':False}
    print(json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2))
    return 0 if result['gate']=='PASS_RECEIPT_TEXT_MATCH_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
