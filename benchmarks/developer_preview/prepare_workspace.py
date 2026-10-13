#!/usr/bin/env python3
"""Prepare disposable real-Codex workflow controls; never runs a model itself."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

CASES = ('multifile', 'cross_tool', 'recovery', 'missing_post', 'shadow_mixed')
FILES = {
    'src/__init__.py': '',
    'src/a.py': 'def scale(value):\n    return value * 2\n',
    'src/b.py': 'from src.a import scale\n\ndef total(values):\n    return sum(scale(value) for value in values)\n',
    'tests/test_app.py': 'import unittest\nfrom src.b import total\n\nclass AppTest(unittest.TestCase):\n    def test_values(self):\n        self.assertEqual(total([1, 2, 3]), 12)\n    def test_empty(self):\n        self.assertEqual(total([]), 0)\n    def test_negative(self):\n        self.assertEqual(total([-3, 2]), -2)\n',
    'config.prod.json': '{"debug": true}\n',
    'config.dev.json': '{"debug": true}\n',
}


def prepare(dest):
    dest.mkdir(parents=True, exist_ok=False)
    for case in CASES:
        base = dest / case
        project = base / 'project'
        project.mkdir(parents=True)
        for name, content in FILES.items():
            target = project / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            before = base / 'baseline_files' / name
            before.parent.mkdir(parents=True, exist_ok=True)
            before.write_text(content)
        hooks = {'hooks': {'PreToolUse': [{'matcher': '^CLIMFixtureUnused$',
                 'hooks': [{'type': 'command', 'command': 'true',
                            'statusMessage': 'fixture third-party hook'}]}]}}
        hp = project / '.codex/hooks.json'
        hp.parent.mkdir()
        hp.write_text(json.dumps(hooks, indent=2) + '\n')
        (base / 'original_hooks.json').write_bytes(hp.read_bytes())
        env = {**os.environ, 'CLIM_HOME': str(base / 'state')}
        operators = []
        for args in [('init', 'codex'), ('mode', 'guarded'),
                     ('protect', 'tests/**', 'src/__init__.py')]:
            proc = subprocess.run([sys.executable, '-m', 'clim_agent_guard.devpreview.cli',
                                   *args, '--project', str(project)],
                                  env=env, text=True, capture_output=True, check=True)
            operators.append({'args': args, 'stdout': proc.stdout, 'exit_code': proc.returncode})
        store = next((base / 'state/projects').iterdir())
        (base / 'metadata.json').write_text(json.dumps({'case': case, 'project': str(project),
                  'store': str(store), 'operators': operators}, indent=2) + '\n')
        baseline = {name: hashlib.sha256((project / name).read_bytes()).hexdigest() for name in FILES}
        (base / 'baseline.json').write_text(json.dumps(baseline, indent=2) + '\n')
        if case == 'missing_post':
            (base / 'installed_hooks.json').write_bytes(hp.read_bytes())
            hooks = json.loads(hp.read_text())
            del hooks['hooks']['PostToolUse']
            hp.write_text(json.dumps(hooks, indent=2) + '\n')
        (base / 'active_hooks_at_start.json').write_bytes(hp.read_bytes())
        print(case, store)
    print('Review/trust hooks in each real Codex TUI before submitting the documented tasks.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dest', type=Path, required=True)
    prepare(parser.parse_args().dest.expanduser().resolve())
