"""Simple POSIX atomic state storage. Not a privilege or tamper-proof boundary."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def base_dir() -> Path:
    override = os.getenv('CLIM_HOME')
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / '.local' / 'state' / 'clim').resolve()


def project_store(root: Path) -> Path:
    h = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:20]
    return base_dir() / 'projects' / h


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def atomic_write(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.clim-write-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def append_audit(store: Path, event: dict, filename: str = 'events.jsonl') -> None:
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    e = {'timestamp': datetime.now(timezone.utc).isoformat(), **event}
    with open(store / filename, 'a', encoding='utf-8') as f:
        os.chmod(store / filename, 0o600)
        f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + '\n')
        f.flush()
        os.fsync(f.fileno())


@contextlib.contextmanager
def locked(store: Path):
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(store / '.lock', 'a+b') as f:
        os.chmod(store / '.lock', 0o600)
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def config_at(store: Path) -> dict:
    conf = read_json(store / 'policy.json')
    if not isinstance(conf, dict) or conf.get('schema') != 'clim-developer-policy/v0.2':
        raise ValueError('CLIM policy missing/invalid')
    if conf.get('mode') not in {'shadow', 'ask', 'guarded'}:
        raise ValueError('CLIM mode invalid')
    return conf
