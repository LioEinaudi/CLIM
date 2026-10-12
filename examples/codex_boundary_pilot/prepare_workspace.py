#!/usr/bin/env python3
"""Create one disposable Codex project and an external CLIM authority/state store."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dest', type=Path, required=True, help='New empty experiment directory OUTSIDE your real project')
    args = ap.parse_args()
    base = args.dest.expanduser().resolve(strict=False)
    if base.exists() and any(base.iterdir()):
        ap.error('Destination must be absent or empty; will not overwrite existing work')
    base.mkdir(parents=True, exist_ok=True)
    project = base / 'project'
    trusted = base / 'trusted-control'
    project.mkdir()
    trusted.mkdir(mode=0o700)
    (project/'config.dev.json').write_text('{\n  "debug": true\n}\n')
    (project/'config.prod.json').write_text('{\n  "debug": true\n}\n')
    policy = {'_version':1, 'project_root': str(project.resolve()),
              'authorized_target':'config.dev.json', 'protected_targets':['config.prod.json'],
              'user_confirmed': True}
    (trusted/'policy.json').write_text(json.dumps(policy, indent=2)+'\n')
    baseline = {name: hashlib.sha256((project/name).read_bytes()).hexdigest()
                for name in ('config.dev.json', 'config.prod.json')}
    (trusted/'baseline.json').write_text(json.dumps(baseline, indent=2)+'\n')
    hooks = {'description': 'CLIM pilot: only update config.dev.json with apply_patch; deny Bash',
             'hooks': {name: [{'matcher':'^(apply_patch|Bash)$', 'hooks': [{
                 'type':'command',
                 'command': shlex.join([sys.executable, str(HERE/'hook.py'), cmd]),
                 'timeout':15, 'statusMessage':'CLIM file boundary pilot'}]}]
                       for name,cmd in (('PreToolUse','pre'),('PostToolUse','post'))}}
    (project/'.codex').mkdir()
    (project/'.codex'/'hooks.json').write_text(json.dumps(hooks, indent=2)+'\n')
    (base/'env.sh').write_text('# Source this file in a POSIX shell before running Codex.\n'
        + 'export CLIM_CODEX_POLICY=' + shlex.quote(str(trusted/'policy.json')) + '\n'
        + 'export CLIM_CODEX_STATE_DIR=' + shlex.quote(str(trusted/'state')) + '\n')
    (base/'env.sh').chmod(0o600)
    print(json.dumps({'workspace':str(project), 'trusted_policy':str(trusted/'policy.json'),
        'hooks_json':str(project/'.codex'/'hooks.json'), 'env_file':str(base/'env.sh'),
        'next_steps':['source '+shlex.quote(str(base/'env.sh')),
                       'cd '+shlex.quote(str(project)), 'codex  # inspect /hooks and trust config'],
        'WARNING':'You must trust the hook definition; verify actual Codex events in trusted-control/state/audit.jsonl.'}, indent=2))


if __name__ == '__main__':
    main()
