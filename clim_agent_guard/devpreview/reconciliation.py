"""Read-only, bounded Shadow effect-review presentation (v0.3 prototype).

NOT a causal proof, policy decision, security control, or code-quality review.
Source: existing local events.jsonl. Never changes the original audit ledger.
"""
from __future__ import annotations
from collections import Counter
import json
import unicodedata
from typing import Any


PRIORITY = {
    'TRUSTED_AUTHORITY_RESIDUAL': 0,
    'PROTECTED_TARGET_CHANGED': 1,
    'UNDECLARED_OBSERVED_CHANGE': 2,
    'POSSIBLE_LOST_WORK': 3,
    'CONFLICTING_HOOK_EVIDENCE': 3,
    'PRE_PROTECTED_PROPOSAL': 4,
    'PRE_DEFAULT_PROTECTION_CONFLICT': 4,
    'MISSING_POST': 5,
    'UNMATCHED_PRE': 5,
    'COVERAGE_LIMITATION': 5,
    'UNVERIFIED_SHELL': 6,
    'LEXICAL_RISK_ONLY': 7,
}


def _merge_event(first: dict, last: dict) -> dict:
    """Retain positive observations from conflicting callbacks, never certify them.

    This is a display union of reported evidence, not a reconstructed execution.
    The original events stay untouched in the ledger.
    """
    merged = dict(last)
    for key in ('signals', 'risk_signals', 'coverage_gaps', 'E_proposed', 'targets'):
        if isinstance(first.get(key), list) and isinstance(last.get(key), list):
            merged[key] = first[key] + [v for v in last[key] if v not in first[key]]
    for key in ('effect', 'W', 'proposal'):
        if key not in first and key not in last:
            continue
        a, b = first.get(key, {}), last.get(key, {})
        if isinstance(a, dict) and isinstance(b, dict):
            merged[key] = _merge_event(a, b)
            for field in ('E_observed', 'protected_changed_paths', 'R_proposal', 'protected_proposed', 'gaps'):
                if isinstance(a.get(field), list) and isinstance(b.get(field), list):
                    merged[key][field] = a[field] + [v for v in b[field] if v not in a[field]]
    return merged


def _paths(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    return sorted({p for p in value if isinstance(p, str) and p})


def _gaps(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    found = set()
    for item in value:
        if isinstance(item, dict) and isinstance(item.get('reason'), str):
            found.add(item['reason'])
    return sorted(found)


def build_review(events: list[dict], pending_gaps: list[dict] | None = None, *, max_items: int = 12) -> dict:
    """Collapse PRE/POST into *windows* to avoid double-counting one operation.

    Events with missing identifiers are kept separate; a stale or missing callback
    is NOT converted to verified. For Shell, proposed target set remains unknown.
    """
    windows: dict[tuple, dict] = {}
    for index, event in enumerate(events):
        if not isinstance(event, dict) or event.get('mode') != 'shadow':
            continue
        phase = event.get('phase')
        if phase not in ('PRE', 'POST'):
            continue
        session, use_id = event.get('session_id'), event.get('tool_use_id')
        key = (session, use_id) if isinstance(session, str) and session and isinstance(use_id, str) and use_id else ('unpaired', index)
        window = windows.setdefault(key, {'pre': None, 'post': None, 'duplicate_events': 0, 'conflict': False, 'last_index': index})
        entry_key = phase.lower()
        if window[entry_key] is not None:
            window['duplicate_events'] += 1
            old = window[entry_key]
            if {k:v for k,v in old.items() if k != 'timestamp'} != {k:v for k,v in event.items() if k != 'timestamp'}:
                window['conflict'] = True
                event = _merge_event(old, event)
        window[entry_key] = event
        window['last_index'] = index

    items = []
    counts = Counter()
    distinct_observed: set[str] = set()
    for window in windows.values():
        pre, post = window['pre'], window['post']
        src = post or pre or {}
        effect = post.get('effect', {}) if post else {}
        if not isinstance(effect, dict):
            effect = {}
        proposed = _paths((pre or {}).get('E_proposed', (pre or {}).get('targets')))
        if proposed is None:
            proposed = _paths(effect.get('E_proposed'))
        observed = _paths(effect.get('E_observed')) if post else None
        authority = _paths(effect.get('E_authorized')) if post else _paths((pre or {}).get('E_authorized'))
        residual = _paths(effect.get('R_authority')) if post else None
        protected = _paths(effect.get('protected_changed_paths')) or []
        extra_proposal = _paths(effect.get('R_proposal')) if post else None
        if window['conflict']:
            # Conflicting callbacks do not establish one proposal or authority.
            proposed, authority, residual, extra_proposal = None, None, None, None
        pre_protected = _paths((pre or {}).get('proposal', {}).get('protected_proposed')) if pre else []
        pre_protected = pre_protected or []
        signals = sorted(set((pre or {}).get('signals') or []) | set((post or {}).get('signals') or []))
        coverage = _gaps((pre or {}).get('W', {}).get('gaps'))
        coverage.extend(_gaps(effect.get('coverage_gaps')))
        coverage.extend(_gaps((post or {}).get('coverage_gaps')))
        coverage = sorted(set(coverage))
        issues = []
        if residual and authority is not None:
            issues.append('TRUSTED_AUTHORITY_RESIDUAL')
        if protected:
            issues.append('PROTECTED_TARGET_CHANGED')
        if extra_proposal:
            issues.append('UNDECLARED_OBSERVED_CHANGE')
        if 'POSSIBLE_LOST_WORK' in signals:
            issues.append('POSSIBLE_LOST_WORK')
        if pre_protected:
            issues.append('PRE_PROTECTED_PROPOSAL')
        elif pre is not None and 'DEFAULT_PROTECTION_CONFLICT' in ((pre or {}).get('signals') or []):
            # Current native PRE audit records the signal, not exact rejected targets.
            issues.append('PRE_DEFAULT_PROTECTION_CONFLICT')
        if pre is not None and post is None:
            issues.append('MISSING_POST')
            coverage.append('missing_post')
        if post is not None and pre is None:
            coverage.append('unmatched_pre')
            issues.append('UNMATCHED_PRE')
        if window['duplicate_events']:
            coverage.append('duplicate_hook_event')
        if window['conflict']:
            issues.append('CONFLICTING_HOOK_EVIDENCE')
        if set(coverage) - {'unwatched_tool', 'skipped_dir', 'missing_post', 'unmatched_pre', 'duplicate_hook_event'}:
            issues.append('COVERAGE_LIMITATION')
        if 'UNINSPECTED_SHELL' in signals:
            issues.append('UNVERIFIED_SHELL')
        if 'RISK_SIGNAL' in signals:
            issues.append('LEXICAL_RISK_ONLY')
        coverage = sorted(set(coverage))
        for issue in issues:
            counts[issue] += 1
        if coverage or not pre or not post or (post and post.get('decision') == 'UNKNOWN'):
            counts['UNCERTAIN_WINDOWS'] += 1
        if observed:
            distinct_observed.update(observed)
        tool = (pre or post or {}).get('tool') or 'unknown'
        items.append({
            'tool': str(tool), 'session_id': src.get('session_id'), 'tool_use_id': src.get('tool_use_id'),
            'pre': pre is not None, 'post': post is not None,
            'proposed': proposed, 'observed': observed,
            'authority': authority, 'authority_status': 'HOST_REGISTERED' if authority is not None else 'UNKNOWN',
            'out_of_authorized_scope': residual if authority is not None else None,
            'outside_proposal': extra_proposal,
            'protected_changed': protected, 'protected_proposed': pre_protected,
            'risk_signals': _paths((pre or {}).get('risk_signals')) or [],
            'coverage_gaps': coverage, 'attribution': effect.get('attribution', 'UNVERIFIED'),
            'labels': sorted(set(issues), key=lambda s: (PRIORITY[s], s)),
            'status': str(post.get('decision', 'UNKNOWN')) if post else 'MISSING_POST',
            'last_index': window['last_index'],
        })
    items.sort(key=lambda item: (min((PRIORITY[x] for x in item['labels']), default=99), -item['last_index']))
    # Keep neutral Shell/routine windows visible in totals, without spamming the card.
    high_labels = {'TRUSTED_AUTHORITY_RESIDUAL', 'PROTECTED_TARGET_CHANGED',
                   'UNDECLARED_OBSERVED_CHANGE', 'POSSIBLE_LOST_WORK',
                   'PRE_PROTECTED_PROPOSAL', 'PRE_DEFAULT_PROTECTION_CONFLICT',
                   'MISSING_POST', 'UNMATCHED_PRE', 'COVERAGE_LIMITATION',
                   'CONFLICTING_HOOK_EVIDENCE'}
    high = [i for i in items if high_labels.intersection(i['labels'])]
    neutral = [i for i in items if not high_labels.intersection(i['labels'])]
    budget = max(0, max_items)
    recent = high[:budget] + neutral[:min(2, max(0, budget-len(high[:budget])))]
    pending_count = len(pending_gaps or [])
    return {'schema': 'clim-execution-reconciliation/v0.3-prototype',
            'source': 'local_shadow_hook_events', 'windows': len(items),
            'observed_changed_distinct_paths': len(distinct_observed),
            'counts': dict(sorted(counts.items())), 'authority': 'PER_WINDOW',
            'selected_items': recent, 'omitted_windows': max(0, len(items) - len(recent)),
            'collapsed_neutral_windows': max(0, len(neutral) - min(2, max(0, budget-len(high[:budget])))),
            'collapsed_high_priority_windows': max(0, len(high)-budget),
            'pending_gap_count': pending_count,
            'limitations': ['Bounded file inventory; files outside coverage may have changed',
                            'Concurrent writers may change files; causation not established',
                            'No task authority inferred from tool proposals',
                            'Shell command effects are not fully parsed',
                            'This report does not establish code correctness or enforcement']}


def render_card(report: dict) -> str:
    """Plain terminal output, no ANSI/color/dependencies; safe for CI snapshots."""
    def safe(value: Any) -> str:
        # JSON already escapes ASCII controls. Escape C1 and Unicode format/bidi
        # controls too, preserving ordinary Chinese/Unicode filenames.
        return ''.join(f'\\u{ord(c):04x}' if unicodedata.category(c) in {'Cc', 'Cf'} else c
                       for c in str(value))

    def path_text(paths: list[str] | None) -> str:
        if paths is None:
            return 'UNKNOWN'
        if not paths:
            return '(none observed)'
        shown = paths[:4]
        return ', '.join(safe(json.dumps(p, ensure_ascii=False)) for p in shown) + (f' (+{len(paths)-4} more)' if len(paths) > 4 else '')

    lines = [
        '=' * 74,
        'CLIM  |  EXECUTION RECONCILIATION  [v0.3 preview]',
        '=' * 74,
        f"Hook windows: {report['windows']}   Distinct changed paths (observed): {report['observed_changed_distinct_paths']}",
        f"Uncertain windows: {report['counts'].get('UNCERTAIN_WINDOWS',0)}   Pending markers: {report['pending_gap_count']}",
        'Observation only. Not proof of authorship, authorization, or code quality.',
        'Issue totals (windows): ' + (', '.join(f'{k}={v}' for k,v in report['counts'].items()) or '(none)'),
        'DISPLAY POLICY (review priority, NOT a security severity or deny decision):',
        '  PROMINENT: host-scope residuals, protected/undeclared observed changes,',
        '             possible lost work, protected proposals, broken Hook pairing,',
        '             conflicts and substantive coverage limitations.',
        '  SAMPLE/COLLAPSE: routine windows, neutral Shell gaps, lexical-only hints.',
        '             Up to 2 neutral windows shown; all remain in original audit.',
        '  LIVE NOTICE: OFF by default. Optional for protected apply_patch proposals;',
        '             never a Shadow denial and not guaranteed in headless JSON.',
        '-' * 74,
    ]
    items = report['selected_items']
    if not items:
        lines.append('No matched Shadow PRE/POST evidence in the selected window.')
    for i, item in enumerate(items, 1):
        lbl = ', '.join(item['labels']) if item['labels'] else 'NO_PRIORITY_SIGNAL'
        safe_tool = safe(json.dumps(item['tool'], ensure_ascii=False))
        lines.append(f"[{i:02d}] {safe_tool}  |  {lbl}  |  Post: {safe(item['status'])}")
        lines.append(f"     Proposed  : {path_text(item['proposed'])}")
        lines.append(f"     Observed  : {path_text(item['observed'])}")
        if item['outside_proposal']:
            lines.append(f"     Extra vs proposal : {path_text(item['outside_proposal'])}")
        if item['protected_changed']:
            lines.append(f"     Protected changed : {path_text(item['protected_changed'])}")
        if item['protected_proposed']:
            lines.append(f"     Proposed protected: {path_text(item['protected_proposed'])}")
        if item['out_of_authorized_scope']:
            lines.append(f"     Outside HOST scope: {path_text(item['out_of_authorized_scope'])}")
        lines.append(f"     Authority : {item['authority_status']} | Attribution: {safe(item['attribution'])}")
        if item['coverage_gaps']:
            lines.append('     UNKNOWN / coverage: ' + ', '.join(safe(g) for g in item['coverage_gaps'][:7]))
        if item['risk_signals']:
            lines.append('     Lexical hints only: ' + ', '.join(safe(g) for g in item['risk_signals']))
        lines.append('-' * 74)
    if report['omitted_windows']:
        lines.append(f"Showing {len(items)} prioritized/sample windows; {report['omitted_windows']} other windows collapsed.")
        lines.append(f"Neutral/routine windows collapsed: {report['collapsed_neutral_windows']} (all retained in original audit).")
        lines.append(f"High-priority windows collapsed: {report['collapsed_high_priority_windows']} (inspect full ledger/report).")
    lines.append('Inspect full JSON: clim report --format json --advanced')
    lines.append('No Hook record is not evidence that no file change occurred.')
    return '\n'.join(lines)
