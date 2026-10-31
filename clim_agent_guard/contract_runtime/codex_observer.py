"""M2.1 Codex project observer adapter. Non-enforcing and explicitly opt-in.

Input is Codex PreToolUse/PostToolUse JSON on stdin. M3-B optionally
requests a bounded Host denial for an explicit contract scope violation. Uncertain/missing hooks are not evidence of
absence of effects. Filesystem timestamps and local sequence do not prove
which process made a change.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
from typing import Any

from .scope import ContractError, resource, safe_identifier
from .service import ContractRuntime
from .storage import SQLiteEvidenceSink
from .differential import LiveShadowDifferential
from ..devpreview.store import project_store

MAX_STDIN = 128 * 1024
MAX_COMMAND = 128 * 1024
# This is a best-effort POSIX alarm, not a Codex Host deadline or hard guarantee.
OBSERVE_DEADLINE_S = 0.8


class _Deadline(Exception):
    pass


@contextmanager
def bounded_observation(seconds: float = OBSERVE_DEADLINE_S):
    if not (hasattr(signal, 'setitimer') and hasattr(signal, 'SIGALRM')):
        yield
        return
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    def hit(_signum, _frame):
        raise _Deadline('OBSERVER_DEADLINE')
    signal.signal(signal.SIGALRM, hit)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


class ObserverSink(SQLiteEvidenceSink):
    """Use a short busy timeout; do not wait the normal 10s on the tool path."""
    def _connect(self):
        c = super()._connect()
        c.execute('PRAGMA busy_timeout=125')
        return c


def _id(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ContractError('MISSING_' + label)
    try:
        return safe_identifier(raw)
    except ContractError:
        # Stable, unambiguous digest encoding; raw IDs never placed in paths.
        return label.lower() + '-' + hashlib.sha256(raw.encode('utf-8')).hexdigest()[:40]


def _window_id(raw_session: Any, raw_tool: Any) -> str:
    if not isinstance(raw_session, str) or not isinstance(raw_tool, str) or not raw_session or not raw_tool:
        raise ContractError('MISSING_NATIVE_TOOL_IDENTITY')
    return 'codex-' + hashlib.sha256((raw_session + '\0' + raw_tool).encode('utf-8')).hexdigest()[:40]


def _relative_target(raw: str, project: Path) -> str:
    """Convert only an absolute path lexically under root; NEVER normalize ../ away."""
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        raise ContractError('INVALID_PROPOSED_TARGET')
    if os.path.isabs(raw):
        try:
            raw = str(Path(raw).relative_to(project))
        except ValueError as exc:
            raise ContractError('TARGET_OUTSIDE_PROJECT') from exc
    return resource(raw.replace(os.sep, '/') if os.sep != '/' else raw)


_PATCH_LINE = re.compile(r'^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$')


def proposed_patch_targets(tool_input: Any, project: Path) -> list[str]:
    """Extract *declared* patch targets, not proven side effects.

    Supports Codex unified patch blocks; ambiguous forms become UNKNOWN rather
    than a guessed authorized target. Duplicate paths preserve first order.
    """
    if not isinstance(tool_input, dict):
        raise ContractError('PATCH_INPUT_UNINSPECTABLE')
    raw = tool_input.get('command')
    if not isinstance(raw, str) or len(raw) > MAX_COMMAND:
        raise ContractError('PATCH_COMMAND_UNINSPECTABLE')
    if not ('*** Begin Patch' in raw and '*** End Patch' in raw):
        raise ContractError('PATCH_FORMAT_UNINSPECTABLE')
    found: list[str] = []
    for line in raw.splitlines():
        match = _PATCH_LINE.match(line)
        if match:
            found.append(_relative_target(match.group(1).strip(), project))
    if not found:
        raise ContractError('PATCH_TARGETS_UNINSPECTABLE')
    found = list(dict.fromkeys(found))
    if len(found) > 100:
        raise ContractError('PATCH_TARGET_SET_TOO_LARGE')
    return found


def _reason_from_exception(exc: BaseException) -> str:
    if isinstance(exc, ContractError):
        return exc.code
    if isinstance(exc, _Deadline):
        return 'OBSERVER_TIMEOUT_UNKNOWN'
    if isinstance(exc, sqlite3.Error):
        return 'OBSERVER_STORAGE_UNKNOWN'
    return 'OBSERVER_FAILURE_UNKNOWN'


def _record_gap(sink: ObserverSink, *, event_name: str, session_id: Any,
                tool_use_id: Any, tool_name: Any, reason: str) -> None:
    """Best-effort additive gap event, with no tool command/secrets/raw IDs."""
    if not sink.path.exists():
        return
    try:
        with bounded_observation(0.18):
            with sink.transaction() as c:
                sink.append(c, 'M21_OBSERVER_COVERAGE_GAP',
                            {'hook_phase': event_name, 'tool_kind': str(tool_name)[:40],
                             'coverage': 'UNKNOWN', 'reason': reason, 'enforced': False},
                            session_id=_id(session_id, 'SESSION') if session_id else None,
                            window_id=_window_id(session_id, tool_use_id) if session_id and tool_use_id else None)
    except (Exception, KeyboardInterrupt):
        # Cannot promise the gap is persisted after a Host/SIGKILL failure.
        pass


def process_event(payload: Any, event_name: str, project: Path, *, enable_feedback: bool = False,
                  enable_enforcement: bool = False) -> dict:
    """Return an internal receipt; opt-in M3-B may request Host denial."""
    root = Path(project).resolve(strict=True)
    storage = project_store(root) / 'contract_runtime' / 'ledger.sqlite3'
    if not storage.is_file() or storage.is_symlink():
        return {'status': 'SKIPPED_NO_CONTRACT', 'enforced': False}
    # No M1/M2 work if Codex event identity cannot be validated.
    raw_session = payload.get('session_id') if isinstance(payload, dict) else None
    raw_tool = payload.get('tool_use_id') if isinstance(payload, dict) else None
    tool = payload.get('tool_name') if isinstance(payload, dict) else None
    sink = None
    try:
        with bounded_observation():
            if not isinstance(payload, dict) or payload.get('hook_event_name') != event_name:
                raise ContractError('INVALID_NATIVE_HOOK_EVENT')
            session = _id(raw_session, 'SESSION')
            tool_id = _id(raw_tool, 'TOOL')
            wid = _window_id(raw_session, raw_tool)
            if tool not in ('Bash', 'apply_patch'):
                return {'status': 'IGNORED_TOOL_KIND', 'enforced': False}
            sink = ObserverSink(storage)
            rt = ContractRuntime(root, sink)
            obs = LiveShadowDifferential(rt)
            if event_name == 'PreToolUse':
                if tool == 'Bash':
                    # No fabricated P/A for unstructured shell commands.
                    raise ContractError('SHELL_TARGETS_UNVERIFIED')
                if enable_enforcement:
                    from .enforcement import declared_targets, evaluate_pre, VIOLATION
                    # Only a completely parsed declared Patch can be used for
                    # experimental enforcement; any uncertainty means no deny.
                    targets = declared_targets(payload.get('tool_input'), root)
                    evaluated = evaluate_pre(rt, window_id=wid, session_id=session,
                                             tool_use_id=tool_id, targets=targets)
                    if evaluated['verdict'] == VIOLATION:
                        # No fabricated WINDOW_PRE: the tool has not run and a
                        # denial ordinarily prevents its PostToolUse callback.
                        return {'status':'DENY_REQUESTED', 'window_id':wid,
                                'enforcement':evaluated, 'enforced':False}
                else:
                    targets = proposed_patch_targets(payload.get('tool_input'), root)
                result = obs.pre(window_id=wid, session_id=session,
                                 tool_use_id=tool_id, targets=targets,
                                 tool_kind='apply_patch')
                advisory = None
                if enable_feedback:
                    try:
                        from .advisory import record_advisory
                        advisory = record_advisory(sink, session_id=session, window_id=wid,
                                                   decision=result)
                    except Exception:
                        # Observation stays valid; inability to record feedback
                        # cannot change tool permissions or fabricate visibility.
                        _record_gap(sink, event_name=event_name, session_id=raw_session,
                                    tool_use_id=raw_tool, tool_name=tool,
                                    reason='M3_ADVISORY_UNAVAILABLE')
                return {'status':'OBSERVED_PRE', 'window_id':wid,
                        'observation_seq':result['observation_seq'], 'enforced':False,
                        'advisory':advisory}
            if event_name == 'PostToolUse':
                if tool == 'Bash':
                    raise ContractError('SHELL_EFFECT_UNINSPECTED')
                result = obs.post(window_id=wid)
                return {'status':'OBSERVED_POST', 'window_id':wid,
                        'coverage':result['coverage'], 'enforced':False}
            raise ContractError('INVALID_NATIVE_HOOK_EVENT')
    except (Exception, _Deadline) as exc:
        reason = _reason_from_exception(exc)
        try:
            _record_gap(sink or ObserverSink(storage), event_name=event_name,
                        session_id=raw_session, tool_use_id=raw_tool,
                        tool_name=tool, reason=reason)
        except Exception:
            pass
        return {'status':'UNKNOWN', 'reason':reason, 'enforced':False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='clim-codex-observer')
    parser.add_argument('phase', choices=['pre', 'post'])
    parser.add_argument('--project', required=True)
    parser.add_argument('--enable-feedback', action='store_true',
                        help='non-blocking PreToolUse context; explicit opt-in')
    parser.add_argument('--enable-enforcement', action='store_true',
                        help='EXPERIMENTAL Patch denial request; not an OS security boundary')
    args = parser.parse_args(argv)
    phase = 'PreToolUse' if args.phase == 'pre' else 'PostToolUse'
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            payload: Any = None
        else:
            payload = json.loads(raw.decode('utf-8'))
        receipt = process_event(payload, phase, Path(args.project),
                                enable_feedback=args.enable_feedback and phase == 'PreToolUse',
                                enable_enforcement=args.enable_enforcement and phase == 'PreToolUse')
        if args.enable_enforcement and phase == 'PreToolUse':
            from .enforcement import pre_denial_output
            output = pre_denial_output(receipt.get('enforcement'))
            if output:
                sys.stdout.write(json.dumps(output, ensure_ascii=False, sort_keys=True)+'\n')
                return 0
        if args.enable_feedback and phase == 'PreToolUse':
            from .advisory import pre_hook_context
            output = pre_hook_context(receipt.get('advisory'))
            if output:
                sys.stdout.write(json.dumps(output, ensure_ascii=False, sort_keys=True)+'\n')
                return 0
    except (Exception, KeyboardInterrupt):
        # The observer is opt-in and never expresses a Host security decision.
        pass
    # A success exit is NOT proof an observation succeeded. Codex may also
    # skip or kill a hook without invoking this entrypoint.
    sys.stdout.write('{}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
