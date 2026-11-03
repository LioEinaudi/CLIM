#!/usr/bin/env python3
"""Correlate an actual Host refusal with one captured codex exec turn.

Uses only an independently saved Host text, the opt-in project Hook capture,
the runner's monotonic time bounds, and the public codex exec --json stream.
It does not read Codex's private session databases and is not an attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys

if __package__:
    from .attempt_capture import OUTSIDE, SCHEMA, _create_private, _outside
    from .pilot import read_host_feedback
else:
    from attempt_capture import OUTSIDE, SCHEMA, _create_private, _outside
    from pilot import read_host_feedback


def _private_file(path: Path, operator: Path) -> Path:
    if path.is_symlink():
        raise ValueError('Evidence files must not be symlinks')
    path = path.resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(operator):
        raise ValueError('Evidence files must be regular files within the operator directory')
    return path


def verify(args: argparse.Namespace) -> dict:
    project = Path(args.project).expanduser().resolve(strict=True)
    operator = _outside(Path(args.operator), project)
    events = _private_file(Path(args.events), operator)
    metadata = _private_file(Path(args.run_metadata), operator)
    host_path = _private_file(Path(args.host_feedback), operator)
    capture = _private_file(operator/'pretool-capture.jsonl', operator)
    if events != operator/'conflict.codex-exec.jsonl' or metadata != operator/'conflict.run.json':
        raise ValueError('Expected the conflict runner event stream and metadata in the operator directory')
    key = _private_file(operator/'pretool-capture-key.bin', operator).read_bytes()
    if len(key) != 32:
        raise ValueError('Invalid private capture key')
    event_bytes = events.read_bytes()
    metadata_bytes = metadata.read_bytes()
    host_bytes = host_path.read_bytes()
    capture_bytes = capture.read_bytes()
    meta = json.loads(metadata_bytes)
    reasons = []
    start, end = meta.get('start_monotonic_ns'), meta.get('end_monotonic_ns')
    if (meta.get('schema') != 'clim-scope-recovery-run-v1' or meta.get('phase') != 'conflict' or
            meta.get('run_status') != 'FINISHED' or type(start) is not int or type(end) is not int or start > end or
            meta.get('events_sha256') != hashlib.sha256(event_bytes).hexdigest()):
        reasons.append('RUN_METADATA_INCOMPLETE_OR_MISMATCHED')
    threads = []
    started = completed = failed = invalid = 0
    for line in event_bytes.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (ValueError, UnicodeError):
            invalid += 1
            continue
        if not isinstance(obj, dict):
            invalid += 1
            continue
        if obj.get('type') == 'thread.started':
            threads.append(obj.get('thread_id'))
        elif obj.get('type') == 'turn.started':
            started += 1
        elif obj.get('type') == 'turn.completed':
            completed += 1
        elif obj.get('type') in ('turn.failed', 'error'):
            failed += 1
    if (len(threads) != 1 or not isinstance(threads[0], str) or not threads[0] or
            len(threads[0]) > 256 or started != 1 or completed != 1 or failed or invalid):
        reasons.append('JSONL_SESSION_OR_TURN_AMBIGUOUS')
    host = read_host_feedback(host_path, None)
    receipt_sha = host.get('receipt_sha256')
    if host['decision'] != 'BLOCKED' or not receipt_sha:
        reasons.append('UNIQUE_NATIVE_HOST_RECEIPT_NOT_FOUND')
    session_hash = (hmac.new(key, b'session\0'+threads[0].encode(), hashlib.sha256).hexdigest()
                    if len(threads) == 1 and isinstance(threads[0], str) and threads[0] else None)
    anchors = []
    for line in capture_bytes.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            reasons.append('INVALID_ATTEMPT_CAPTURE')
            break
        if not isinstance(event, dict) or event.get('schema') != SCHEMA:
            reasons.append('INVALID_ATTEMPT_CAPTURE')
            break
        if (event.get('session_hash') == session_hash and event.get('kind') == 'apply_patch' and
                event.get('target') == OUTSIDE and event.get('clim_denial_requested') is True and
                event.get('requested_receipt_sha256') == receipt_sha and
                type(event.get('start_ns')) is int and type(event.get('end_ns')) is int and
                type(start) is int and type(end) is int and start <= event['start_ns'] <= event['end_ns'] <= end):
            anchors.append(event.get('tool_id_hash'))
    if not anchors or len(set(anchors)) != 1 or not re.fullmatch(r'[0-9a-f]{64}', str(anchors[0])):
        reasons.append('RECEIPT_SESSION_TIME_ANCHOR_NOT_UNIQUE')
    result = {'schema': 'clim-scope-recovery-run-link-v1', 'same_native_run': 'UNKNOWN' if reasons else 'YES',
            'reasons': sorted(set(reasons)), 'events_sha256': hashlib.sha256(event_bytes).hexdigest(),
            'host_feedback_sha256': hashlib.sha256(host_bytes).hexdigest(),
            'run_metadata_sha256': hashlib.sha256(metadata_bytes).hexdigest(),
            'attempt_capture_sha256': hashlib.sha256(capture_bytes).hexdigest(),
            'basis': 'Unique native Host receipt, fixture Hook HMAC session match, bounded runner time, one completed turn',
            'note': 'Local correlation only; not authenticated attestation or proof of complete tool coverage.'}
    payload = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    result['link_hmac_sha256'] = hmac.new(key, b'run-link\0' + payload, hashlib.sha256).hexdigest()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'operator', 'events', 'run-metadata', 'host-feedback', 'out'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    try:
        project = Path(args.project).expanduser().resolve(strict=True)
        operator = _outside(Path(args.operator), project)
        out = _outside(Path(args.out), project)
        if out.parent.resolve(strict=True) != operator:
            raise ValueError('Run-link output must be directly inside the operator directory')
        result = verify(args)
        _create_private(out, (json.dumps(result, indent=2)+'\n').encode())
        print(json.dumps({'same_native_run': result['same_native_run'], 'reasons': result['reasons']}))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
