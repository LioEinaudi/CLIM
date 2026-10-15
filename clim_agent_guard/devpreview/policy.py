"""Host-owned developer policy, patch target parsing, and bounded effect snapshots."""
from __future__ import annotations
import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

DEFAULT_DENY = [
    '.env', '.env.*', '**/.env', '**/.env.*',
    'config.prod.*', '**/config.prod.*',
    '*.prod.*', '**/*.prod.*', 'production/**', '**/production/**',
    '**/prod/**', 'prod/**',
    '**/*.pem', '*.pem', '**/*.key', '*.key',
    'id_rsa', '**/id_rsa', 'id_ed25519', '**/id_ed25519',
    'id_ecdsa', '**/id_ecdsa', 'id_dsa', '**/id_dsa',
    '.git/**', '.codex/**', '.clim/**', '.clim.json',
]
SKIP_DIRS = {'.git', '.codex', '.clim', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build'}
MAX_COMMAND = 500_000
MAX_TRACKED = 250
MAX_FILE_SIZE = 4 * 1024 * 1024


def rel_target(root: Path, raw: str) -> str:
    if not isinstance(raw, str) or not raw or '\x00' in raw or raw != raw.strip():
        raise ValueError('Invalid file target')
    root = root.resolve(strict=True)
    value = Path(raw)
    p = value if value.is_absolute() else root / value
    # Deny symlinks in any existing path component (not just the leaf).
    current = root
    parts = p.relative_to(root).parts if p.is_relative_to(root) else None
    if parts is None:
        raise ValueError('Path is outside the project')
    for piece in parts:
        if piece in ('', '.', '..'):
            raise ValueError('Unsafe path component')
        current = current / piece
        if current.is_symlink():
            raise ValueError('Symlink path is not supported')
    resolved = p.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError('Path escapes the project')
    relative = resolved.relative_to(root).as_posix()
    if relative in ('', '.'):
        raise ValueError('Project root is not a writable file')
    return relative


def parse_patch(command: Any) -> list[str]:
    """Parse Codex apply_patch envelope; reject unknown metacommands and target forms."""
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND or '\x00' in command:
        raise ValueError('Invalid patch')
    lines = command.strip().splitlines()
    if len(lines) < 4 or lines[0] != '*** Begin Patch' or lines[-1] != '*** End Patch':
        raise ValueError('Unsupported patch envelope')
    paths = []
    for line in lines[1:-1]:
        if line.startswith('*** '):
            change = re.fullmatch(r'\*\*\* (Update|Add|Delete) File: (.+)', line)
            move = re.fullmatch(r'\*\*\* Move to: (.+)', line)
            if change:
                paths.append(change.group(2))
            elif move:
                if not paths:
                    raise ValueError('Move to without file header')
                paths.append(move.group(1))
            elif line == '*** End of File':
                continue
            else:
                raise ValueError('Unsupported patch directive')
    if not paths or len(paths) > 100:
        raise ValueError('Patch must declare 1..100 targets')
    return sorted(set(paths))


def match(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def policy_decision(paths: list[str], policy: dict) -> tuple[bool, str, list[str]]:
    rejected = []
    for path in paths:
        if match(path, policy['protected']) and not match(path, policy.get('explicit_overrides', [])):
            rejected.append(path)
    if rejected:
        return False, 'TARGET_NOT_AUTHORIZED', rejected
    return True, 'TARGET_AUTHORIZED', []


def _hash_file(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        if path.stat().st_size > MAX_FILE_SIZE:
            return 'OVERSIZE'
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, PermissionError):
        return 'UNREADABLE'


def monitored_paths(root: Path, policy: dict, proposed: list[str]) -> tuple[list[str], bool]:
    """Track declared targets and discovered protected files, not the entire workspace."""
    items = set(proposed)
    root = root.resolve()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(directory)/d).is_symlink()]
        for name in files:
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if match(rel, policy['protected']):
                items.add(rel)
                if len(items) > MAX_TRACKED:
                    return sorted(items)[:MAX_TRACKED], False
    return sorted(items), True


def snapshot(root: Path, names: list[str]) -> dict[str, str | None]:
    out = {}
    for name in names:
        try:
            valid = rel_target(root, name)
            out[valid] = _hash_file(root / valid)
        except (ValueError, OSError):
            out[name] = 'UNSAFE_OR_UNREADABLE'
    return out


def residual(before: dict, after: dict, allowed: list[str]) -> dict:
    changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
    unexpected = sorted(set(changed) - set(allowed))
    uncertain = [p for p, h in {**before, **after}.items() if h in ('UNREADABLE','OVERSIZE','UNSAFE_OR_UNREADABLE')]
    return dict(changed_paths=changed, unauthorized_changed_paths=unexpected,
                uncertain_paths=sorted(set(uncertain)), expected_changed=bool(allowed) and set(allowed).issubset(set(changed)))


def defaults(root: Path) -> dict:
    return {'schema': 'clim-developer-policy/v0.2', '_version': 1,
            'project_root': str(root.resolve()), 'mode': 'shadow',
            'protected': DEFAULT_DENY.copy(), 'explicit_overrides': [],
            'shell_allow_exact': [], 'permissions_notice': 'Host controls these rules; not model prompts.'}
