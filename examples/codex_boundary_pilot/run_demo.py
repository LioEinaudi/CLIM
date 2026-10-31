#!/usr/bin/env python3
"""Local transport and CLIM-boundary simulation. Does NOT run Codex itself."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def patch(name: str, old: str = '"debug": true', new: str = '"debug": false') -> str:
    return (f'*** Begin Patch\n*** Update File: {name}\n@@\n-  {old}\n+  {new}\n*** End Patch')


def invoke(when: str, root: Path, env: dict, tool_id: str, tool_name: str, command: str, response=None):
    payload = {'hook_event_name': 'PreToolUse' if when == 'pre' else 'PostToolUse',
        'session_id': 'clim-demo-1', 'tool_use_id': tool_id,
        'tool_name': tool_name, 'tool_input': {'command': command}, 'cwd': str(root),
        'turn_id': 'demo-turn', 'tool_response': response}
    proc = subprocess.run([sys.executable, str(HERE/'hook.py'), when], input=json.dumps(payload),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=str(root), check=True)
    return json.loads(proc.stdout)


def denied(result: dict) -> bool:
    return result.get('hookSpecificOutput', {}).get('permissionDecision') == 'deny'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    with tempfile.TemporaryDirectory(prefix='clim-codex-pilot-') as temp:
        base = Path(temp)
        project, trusted = base / 'project', base / 'trusted_control'
        project.mkdir()
        trusted.mkdir(mode=0o700)
        dev, prod = project / 'config.dev.json', project / 'config.prod.json'
        dev.write_text('{\n  "debug": true\n}\n', encoding='utf-8')
        prod.write_text('{\n  "debug": true\n}\n', encoding='utf-8')
        policy = {'_version': 1, 'project_root': str(project), 'authorized_target': 'config.dev.json',
            'protected_targets': ['config.prod.json'], 'user_confirmed': True}
        pfile = trusted/'policy.json'
        pfile.write_text(json.dumps(policy), encoding='utf-8')
        env = dict(os.environ, CLIM_CODEX_POLICY=str(pfile), CLIM_CODEX_STATE_DIR=str(trusted/'state'))
        hooks = {'hooks': {
            event: [{'matcher': '^(apply_patch|Bash)$', 'hooks': [{
                'type': 'command', 'command': shlex.join([sys.executable, str(HERE/'hook.py'), mode]),
                'timeout': 15, 'statusMessage': 'CLIM execution boundary check'}]}]
            for event, mode in (('PreToolUse', 'pre'), ('PostToolUse', 'post'))}}
        (project/'.codex').mkdir()
        (project/'.codex'/'hooks.json').write_text(json.dumps(hooks, indent=2), encoding='utf-8')
        # Case 1: proposed production config modification: deny, no simulated execution.
        prod_before = digest(prod)
        bad = patch('config.prod.json')
        r_bad = invoke('pre', project, env, 'bad-1', 'apply_patch', bad)
        assert denied(r_bad) and digest(prod) == prod_before
        # Case 2: Bash path is explicitly denied in this single-purpose pilot.
        r_bash = invoke('pre', project, env, 'bash-1', 'Bash', 'echo changed > config.prod.json')
        assert denied(r_bash)
        # Case 3: authorized dev config change; simulate the permitted native tool effect.
        good = patch('config.dev.json')
        r_pre = invoke('pre', project, env, 'ok-1', 'apply_patch', good)
        assert not denied(r_pre)
        dev.write_text('{\n  "debug": false\n}\n', encoding='utf-8')
        r_post = invoke('post', project, env, 'ok-1', 'apply_patch', good, response={'success': True})
        assert 'EFFECT_VERIFIED' in r_post.get('systemMessage', '') and digest(prod) == prod_before
        records = [json.loads(line) for line in (trusted/'state'/'audit.jsonl').read_text().splitlines()]
        summary = {'kind': 'SIMULATED_HOOK_TRANSPORT_NOT_REAL_CODEX',
          'unauthorized_prod_patch_denied': denied(r_bad), 'shell_denied': denied(r_bash),
          'authorized_dev_pre_allowed': not denied(r_pre),
          'authorized_dev_effect_verified': 'EFFECT_VERIFIED' in r_post.get('systemMessage', ''),
          'protected_config_unchanged': digest(prod) == prod_before,
          'audited_events': len(records), 'records': records,
          'codex_hooks_json_example': hooks}
        return summary


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, ensure_ascii=False))
