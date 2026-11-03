#!/usr/bin/env python3
"""Optional Linux-only, fixture-scoped PreToolUse capture for the CLIM pilot.

This wraps only a disposable project's already-installed CLIM PreToolUse hook.
It forwards CLIM's stdout, stderr, and exit status, and stores only HMACed IDs,
a fixture-only target, timing, and a hash of a requested-denial receipt.  A
requested denial is never treated as a Host denial until a separate native Host
text with the same receipt is supplied to `normalize`.  This adapter does not
trust hooks, alter global settings, read Codex session databases, or provide an
OS security boundary.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time

if __package__:
    from .pilot import INSIDE, OUTSIDE, read_host_feedback
else:
    from pilot import INSIDE, OUTSIDE, read_host_feedback

SCHEMA = 'clim-fixture-pre-capture-v1'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
RECEIPT = re.compile(r'\bclim-deny-[0-9a-f]{32}\b')


def _outside(path: Path, project: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved == project or project in resolved.parents:
        raise ValueError('Operator evidence must be outside the project')
    return resolved


def _create_private(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _verify_fixture(project: Path) -> None:
    root = subprocess.check_output(['git', '-C', str(project), 'rev-parse', '--show-toplevel'], text=True).strip()
    if Path(root).resolve() != project:
        raise ValueError('The project must be the root of its own disposable Git fixture')
    agents = project / 'AGENTS.md'
    if agents.is_symlink() or not agents.is_file() or not agents.read_text(encoding='utf-8').startswith('# Synthetic fixture instructions\n'):
        raise ValueError('Expected the synthetic fixture created by pilot prepare')
    for name in (INSIDE, OUTSIDE):
        path = project / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(project):
            raise ValueError('Expected regular fixture target files')


def _is_clim_pre(argv: list[str], project: Path) -> bool:
    if len(argv) != 7:
        return False
    if argv[1:5] != ['-m', 'clim_agent_guard.contract_runtime.codex_observer', 'pre', '--project']:
        return False
    if argv[6] != '--enable-enforcement':
        return False
    try:
        return Path(argv[0]).is_absolute() and Path(argv[5]).resolve() == project
    except (OSError, ValueError):
        return False


def configure(args: argparse.Namespace) -> None:
    if not args.acknowledge_disposable:
        raise ValueError('Use --acknowledge-disposable for this fixture-only adapter')
    project = Path(args.project).expanduser().resolve(strict=True)
    operator = _outside(Path(args.operator), project)
    if not operator.is_dir():
        raise ValueError('Existing operator directory required')
    _verify_fixture(project)
    hook_dir = project / '.codex'
    if hook_dir.is_symlink() or not hook_dir.is_dir():
        raise ValueError('Expected a real fixture-local .codex directory')
    hook_path = hook_dir / 'hooks.json'
    if hook_path.is_symlink() or not hook_path.is_file():
        raise ValueError('Install the CLIM project Hook first')
    original = hook_path.read_bytes()
    config = json.loads(original)
    matches = []
    for group in config.get('hooks', {}).get('PreToolUse', []):
        for handler in group.get('hooks', []):
            if handler.get('type') != 'command' or not isinstance(handler.get('command'), str):
                continue
            try:
                argv = shlex.split(handler['command'])
            except ValueError:
                continue
            if _is_clim_pre(argv, project):
                matches.append((handler, argv))
    if len(matches) != 1:
        raise ValueError('Expected exactly one opt-in CLIM PreToolUse handler')
    handler, delegate = matches[0]
    script = Path(__file__).resolve(strict=True)
    capture = operator / 'pretool-capture.jsonl'
    key = operator / 'pretool-capture-key.bin'
    backup = operator / 'hooks-before-capture.json'
    setup = operator / 'capture-setup.json'
    for path in (capture, key, backup, setup):
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing to overwrite existing capture files')
    _create_private(key, secrets.token_bytes(32))
    _create_private(capture, b'')
    _create_private(backup, original)
    handler['command'] = shlex.join([delegate[0], str(script), 'hook', '--project', str(project),
                                      '--operator', str(operator), '--', *delegate])
    payload = (json.dumps(config, indent=2, ensure_ascii=False) + '\n').encode()
    setup_data = {'schema': 'clim-fixture-capture-setup-v1',
                  'project_root_sha256': hashlib.sha256(os.fsencode(str(project))).hexdigest(),
                  'hook_sha256': hashlib.sha256(payload).hexdigest(),
                  'adapter_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                  'note': 'Not proof that an operator reviewed or trusted the Hook.'}
    _create_private(setup, (json.dumps(setup_data, indent=2) + '\n').encode())
    with tempfile.NamedTemporaryFile(dir=hook_path.parent, prefix='.clim-pilot-', delete=False) as tmp:
        temp_path = Path(tmp.name)
        tmp.write(payload)
    try:
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, hook_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    print(json.dumps({'status': 'CONFIGURED_NOT_TRUSTED', 'project_hook': str(hook_path),
                      'capture': str(capture), 'hook_sha256': hashlib.sha256(payload).hexdigest(),
                      'adapter_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                      'note': 'Human must inspect and trust this exact Hook in Codex /hooks.'}, indent=2))


def _target(payload: dict, project: Path) -> tuple[str, str]:
    tool = payload.get('tool_name')
    if tool == 'apply_patch':
        try:
            from clim_agent_guard.contract_runtime.enforcement import declared_targets
            targets = declared_targets(payload.get('tool_input'), project)
        except Exception:
            return 'apply_patch', 'UNCLASSIFIED'
        return 'apply_patch', targets[0] if len(targets) == 1 and targets[0] in (INSIDE, OUTSIDE) else 'UNCLASSIFIED'
    return ('shell', 'UNCLASSIFIED') if tool in ('Bash', 'shell_command') else ('other', 'UNCLASSIFIED')


def _record(operator: Path, project: Path, raw: bytes, output: bytes, start_ns: int, end_ns: int) -> None:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return
    key_path = operator / 'pretool-capture-key.bin'
    if key_path.is_symlink() or not key_path.is_file():
        return
    key = key_path.read_bytes()
    if len(key) != 32:
        return
    session = payload.get('session_id')
    tool_id = payload.get('tool_use_id')
    if not all(isinstance(v, str) and 0 < len(v) <= 256 for v in (session, tool_id)):
        return
    session_hash = hmac.new(key, b'session\0' + session.encode(), hashlib.sha256).hexdigest()
    tool_hash = hmac.new(key, b'tool\0' + session.encode() + b'\0' + tool_id.encode(), hashlib.sha256).hexdigest()
    kind, target = _target(payload, project)
    receipt_hash = None
    requested = False
    try:
        data = json.loads(output)
        hook = data.get('hookSpecificOutput', {})
        reason = hook.get('permissionDecisionReason', '')
        receipts = set(RECEIPT.findall(reason)) if isinstance(reason, str) else set()
        if (hook.get('permissionDecision') == 'deny' and
                'CLIM experimental contract scope' in reason and len(receipts) == 1):
            requested = True
            receipt_hash = hashlib.sha256(next(iter(receipts)).encode()).hexdigest()
    except (ValueError, TypeError, AttributeError):
        pass
    record = {'schema': SCHEMA, 'session_hash': session_hash, 'tool_id_hash': tool_hash,
              'kind': kind, 'target': target, 'start_ns': start_ns, 'end_ns': end_ns,
              'clim_denial_requested': requested, 'requested_receipt_sha256': receipt_hash}
    capture = operator / 'pretool-capture.jsonl'
    fd = os.open(capture, os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, (json.dumps(record, separators=(',', ':')) + '\n').encode())
    finally:
        os.close(fd)


def hook(args: argparse.Namespace) -> int:
    project = Path(args.project).resolve(strict=True)
    operator = _outside(Path(args.operator), project)
    delegate = list(args.delegate)
    if delegate and delegate[0] == '--':
        delegate.pop(0)
    if not _is_clim_pre(delegate, project):
        raise ValueError('Refusing unexpected delegate command')
    raw = sys.stdin.buffer.read()
    start_ns = time.monotonic_ns()
    try:
        proc = subprocess.run(delegate, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError:
        print('CLIM pilot could not invoke the configured hook', file=sys.stderr)
        return 1
    end_ns = time.monotonic_ns()
    try:
        _record(operator, project, raw, proc.stdout, start_ns, end_ns)
    except (OSError, ValueError, TypeError, BlockingIOError):
        # Observation failure must not replace or fabricate CLIM's decision.
        pass
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode if proc.returncode >= 0 else 128 - proc.returncode


def normalize(args: argparse.Namespace) -> None:
    project = Path(args.project).expanduser().resolve(strict=True)
    operator = _outside(Path(args.operator), project)
    host_path = _outside(Path(args.host_feedback), project)
    output = _outside(Path(args.out), project)
    if output.exists() or output.is_symlink():
        raise ValueError('Refusing to overwrite normalized attempts')
    host = read_host_feedback(host_path, None)
    receipt = host.get('receipt_sha256')
    if host['decision'] != 'BLOCKED' or not receipt:
        raise ValueError('Unique native Host denial receipt is required')
    capture = operator / 'pretool-capture.jsonl'
    if capture.is_symlink() or not capture.is_file():
        raise ValueError('No regular capture file')
    records = []
    for line in capture.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if (not isinstance(event, dict) or event.get('schema') != SCHEMA
                or not HEX64.fullmatch(str(event.get('session_hash', '')))
                or not HEX64.fullmatch(str(event.get('tool_id_hash', '')))
                or event.get('kind') not in ('apply_patch', 'shell', 'other')
                or event.get('target') not in (INSIDE, OUTSIDE, 'UNCLASSIFIED')
                or type(event.get('start_ns')) is not int or type(event.get('end_ns')) is not int
                or event['start_ns'] > event['end_ns']):
            raise ValueError('Incomplete or invalid capture; attempts remain UNKNOWN')
        records.append(event)
    anchors = [e for e in records if e.get('kind') == 'apply_patch' and e.get('target') == OUTSIDE
               and e.get('clim_denial_requested') is True and e.get('requested_receipt_sha256') == receipt]
    anchor_ids = {e['tool_id_hash'] for e in anchors}
    if len(anchor_ids) != 1:
        raise ValueError('Native receipt does not identify exactly one captured fixture attempt')
    anchor_id = next(iter(anchor_ids))
    anchor = min(anchors, key=lambda e: e['start_ns'])
    session = [e for e in records if e['session_hash'] == anchor['session_hash']]
    dedup = {}
    for event in session:
        key = event['tool_id_hash']
        if key in dedup:
            old = dedup[key]
            if (old['kind'], old['target'], old.get('requested_receipt_sha256')) != (event['kind'], event['target'], event.get('requested_receipt_sha256')):
                raise ValueError('Conflicting duplicate tool identity; attempts remain UNKNOWN')
            if event['start_ns'] < old['start_ns']:
                dedup[key] = event
        else:
            dedup[key] = event
    ordered = sorted(dedup.values(), key=lambda e: (e['start_ns'], e['end_ns']))
    if len({e['start_ns'] for e in ordered}) != len(ordered):
        raise ValueError('Ambiguous ordering; attempts remain UNKNOWN')
    anchor = dedup[anchor_id]
    if any(e['tool_id_hash'] != anchor_id and e['start_ns'] <= anchor['end_ns']
           and e['end_ns'] >= anchor['start_ns'] for e in ordered):
        raise ValueError('Concurrent attempts around denial; ordering remains UNKNOWN')
    rows = []
    for seq, event in enumerate(ordered, 1):
        row = {'seq': seq, 'tool_id_hash': event['tool_id_hash'], 'kind': event['kind'],
               'target': event['target'], 'host_result': 'BLOCKED' if event['tool_id_hash'] == anchor_id else 'UNKNOWN'}
        if event['tool_id_hash'] == anchor_id:
            row['receipt_sha256'] = receipt
        rows.append(row)
    _create_private(output, ''.join(json.dumps(x, separators=(',', ':')) + '\n' for x in rows).encode())
    print(json.dumps({'status': 'RECEIPT_LINKED_CAPTURE', 'captured_events': len(rows),
                      'coverage': 'MATCHED_PRETOOLUSE_ONLY',
                      'note': 'No later captured event does not prove the agent stopped.'}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('configure');p.add_argument('--project', required=True);p.add_argument('--operator', required=True);p.add_argument('--acknowledge-disposable', action='store_true');p.set_defaults(func=configure)
    p = sub.add_parser('hook');p.add_argument('--project', required=True);p.add_argument('--operator', required=True);p.add_argument('delegate', nargs=argparse.REMAINDER);p.set_defaults(func=hook)
    p = sub.add_parser('normalize');p.add_argument('--project', required=True);p.add_argument('--operator', required=True);p.add_argument('--host-feedback', required=True);p.add_argument('--out', required=True);p.set_defaults(func=normalize)
    args = parser.parse_args()
    try:
        return args.func(args) or 0
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
