"""Idempotent project-scoped Codex observer hook setup; never edits trust DB."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shlex
import sys

from .scope import ContractError, require
from ..devpreview.store import atomic_write

# Retain the historical tag solely to recognize and remove pre-v3 CLIM hooks.
LEGACY_TAG = 'CLIM Contract Observer M2.1 (nonblocking)'
TAG = 'CLIM Contract Observer (observation only)'
ENFORCEMENT_TAG = 'CLIM Contract Observer (experimental Patch denial request)'
MODULE = 'clim_agent_guard.contract_runtime.codex_observer'
MATCHER = '^(Bash|apply_patch)$'


def _owned(hook: object) -> bool:
    return (isinstance(hook, dict) and hook.get('type') == 'command'
            and isinstance(hook.get('command'), str)
            and MODULE in hook['command'] and hook.get('statusMessage') in (LEGACY_TAG, TAG, ENFORCEMENT_TAG))


def _read_file(path: Path) -> dict:
    if path.is_symlink():
        raise ContractError('UNSAFE_HOOKS_CONFIG_SYMLINK')
    if not path.exists():
        return {'hooks': {}}
    doc = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(doc, dict) and isinstance(doc.get('hooks'),dict), 'INVALID_CODEX_HOOK_CONFIG')
    return doc


def _remove_ours(doc: dict) -> int:
    count = 0
    for event in ('PreToolUse','PostToolUse'):
        groups = doc.get('hooks',{}).get(event, [])
        require(isinstance(groups,list), 'INVALID_CODEX_HOOK_CONFIG')
        new = []
        for group in groups:
            require(isinstance(group,dict) and isinstance(group.get('hooks'),list),
                    'INVALID_CODEX_HOOK_CONFIG')
            hits = [item for item in group['hooks'] if _owned(item)]
            count += len(hits)
            left = [item for item in group['hooks'] if not _owned(item)]
            if left:
                new.append({**group, 'hooks':left})
        if new:
            doc['hooks'][event] = new
        else:
            doc['hooks'].pop(event, None)
    return count


def configure(project: Path, *, action: str, dry_run: bool = False, enable_feedback: bool = False,
              enable_enforcement: bool = False) -> dict:
    root = Path(project).resolve(strict=True)
    require(root.is_dir(), 'PROJECT_NOT_DIRECTORY')
    require(action in ('install','uninstall','status'), 'INVALID_HOOK_OPERATION')
    config = root / '.codex' / 'hooks.json'
    # Avoid surprising Codex double-load warning from the same layer.
    if action == 'install' and (root/'.codex'/'config.toml').exists():
        # Avoid dependency on tomllib (Python 3.10 must remain supported).
        import re
        toml_text = (root/'.codex'/'config.toml').read_text(encoding='utf-8')
        require(not re.search(r'^\s*\[{1,2}hooks(?:\.|\])', toml_text, re.M),
                'INLINE_CODEX_HOOKS_PRESENT_REVIEW_MANUALLY')
    doc = _read_file(config)
    working = copy.deepcopy(doc)
    existing = _remove_ours(working)
    if action == 'install':
        for name, phase in [('PreToolUse','pre'),('PostToolUse','post')]:
            arguments = [sys.executable, '-m', MODULE, phase, '--project', str(root)]
            if enable_feedback and phase == 'pre':
                arguments.append('--enable-feedback')
            if enable_enforcement and phase == 'pre':
                arguments.append('--enable-enforcement')
            command = shlex.join(arguments)
            handler = {'type':'command','command':command, 'timeout':4,
                       'statusMessage':(ENFORCEMENT_TAG if enable_enforcement and phase == 'pre' else TAG)}
            if enable_feedback and phase == 'pre':
                handler['additionalContextLimit'] = 256
            record = {'matcher': MATCHER, 'hooks':[handler]}
            working.setdefault('hooks',{}).setdefault(name,[]).append(record)
    altered = working != doc if action != 'status' else False
    if altered and action != 'status' and not dry_run:
        config.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(config, working)
    return {'action':action, 'project':str(root), 'config_path':str(config),
            'installed_before':existing, 'changed':altered,
            'dry_run':dry_run, 'feedback_opt_in_requested':bool(enable_feedback),
            'enforcement_opt_in_requested':bool(enable_enforcement),
            'requires_codex_hook_review': action=='install',
            'not_trusted_automatically':True, 'enforced':False,
            'note':'Inspect/trust project hooks using /hooks; experimental denial is limited to declared apply_patch targets and remains Host-unattested.'}
