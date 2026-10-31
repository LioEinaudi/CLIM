"""Isolated tests against the two CLIM source files after the exact v3 patch.

Run with CLIM_UX_TEST_REPO=/path/to/CLIM python -m pytest -q path/to/this/file.
The tests never call Codex Host, never alter real project hooks or state DBs.
"""
from __future__ import annotations
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import types
from unittest.mock import patch

ROOT = Path(os.environ.get('CLIM_UX_TEST_REPO', '.')).resolve()
SRC = ROOT / 'clim_agent_guard' / 'contract_runtime'


def _packages() -> dict:
    p = {}
    for name in ('clim_agent_guard', 'clim_agent_guard.contract_runtime', 'clim_agent_guard.devpreview'):
        obj = types.ModuleType(name)
        obj.__path__ = []
        p[name] = obj
    scope = types.ModuleType('clim_agent_guard.contract_runtime.scope')
    class ContractError(ValueError):
        pass
    scope.ContractError = ContractError
    def require(ok, reason):
        if not ok:
            raise ContractError(reason)
    scope.require = require
    p[scope.__name__] = scope
    store = types.ModuleType('clim_agent_guard.devpreview.store')
    def atomic_write(path, doc):
        Path(path).write_text(json.dumps(doc), encoding='utf-8')
    store.atomic_write = atomic_write
    p[store.__name__] = store
    differential = types.ModuleType('clim_agent_guard.contract_runtime.differential')
    differential.LiveShadowDifferential = type('LiveShadowDifferential', (), {})
    differential.render_card = lambda report: '[OBSERVED] preserved original card line'
    p[differential.__name__] = differential
    return p


def _module(name: str):
    path = SRC / (name + '.py')
    assert path.is_file(), f'missing target source {path}'
    module_name = 'clim_agent_guard.contract_runtime.' + name
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hook_label_upgrade_reinstall_and_uninstall_do_not_touch_foreign_hooks(tmp_path):
    with patch.dict(sys.modules, _packages()):
        mod = _module('codex_setup')
    root = tmp_path / 'game'
    config = root / '.codex' / 'hooks.json'
    config.parent.mkdir(parents=True)
    previous = {'type': 'command', 'command': 'python -m ' + mod.MODULE + ' pre',
                'statusMessage': mod.LEGACY_TAG}
    foreign = {'type': 'command', 'command': 'echo another-tool', 'statusMessage': 'other'}
    config.write_text(json.dumps({'hooks': {'PreToolUse': [{'matcher': mod.MATCHER,
                              'hooks': [previous, foreign]}]}}), encoding='utf-8')
    assert mod._owned(previous)
    assert not mod._owned(foreign)
    assert mod.configure(root, action='install', enable_enforcement=True)['installed_before'] == 1
    hooks = json.loads(config.read_text())['hooks']
    pre = [h for g in hooks['PreToolUse'] for h in g['hooks']]
    post = [h for g in hooks['PostToolUse'] for h in g['hooks']]
    assert len(pre) == 2 and len(post) == 1
    new_pre = next(h for h in pre if mod.MODULE in h['command'])
    assert new_pre['statusMessage'] == mod.ENFORCEMENT_TAG
    assert '--enable-enforcement' in new_pre['command']
    assert post[0]['statusMessage'] == mod.TAG
    assert '--enable-enforcement' not in post[0]['command']
    assert mod.configure(root, action='install', enable_enforcement=True)['changed'] is False
    assert mod.configure(root, action='uninstall')['installed_before'] == 2
    assert json.loads(config.read_text())['hooks']['PreToolUse'][0]['hooks'] == [foreign]
    assert 'PostToolUse' not in json.loads(config.read_text())['hooks']


def test_shadow_mode_pre_post_labels_are_observational(tmp_path):
    with patch.dict(sys.modules, _packages()):
        mod = _module('codex_setup')
    root = tmp_path / 'game'
    root.mkdir()
    mod.configure(root, action='install', enable_enforcement=False)
    hooks = json.loads((root / '.codex' / 'hooks.json').read_text())['hooks']
    for event in ('PreToolUse', 'PostToolUse'):
        assert hooks[event][0]['hooks'][0]['statusMessage'] == mod.TAG
        assert '--enable-enforcement' not in hooks[event][0]['hooks'][0]['command']


def test_shell_unknowns_collapsed_only_in_card_and_other_unknowns_retained():
    with patch.dict(sys.modules, _packages()):
        mod = _module('live_watch')
    gaps = [{'window_id': f'win{i}', 'phase': phase, 'tool_kind': 'Bash',
             'reason': reason, 'coverage': 'UNKNOWN'}
            for i in range(4)
            for phase, reason in [('PreToolUse', 'SHELL_TARGETS_UNVERIFIED'),
                                  ('PostToolUse', 'SHELL_EFFECT_UNINSPECTED')]]
    extra = {'window_id': 'unknown', 'phase': 'PreToolUse', 'tool_kind': 'apply_patch',
             'reason': 'ADAPTER_FAILURE', 'coverage': 'UNKNOWN'}
    report = {'task': {'task_id': 'TEST', 'active_stage': 'mechanics',
                       'active_contract': 'MECH', 'active_scope': ['src/game/mechanics/**']},
              'summary': {'m1_exec_pending': 0, 'm1_exec_recovered': 0,
                          'm2_obs_complete': 0, 'm2_obs_partial': 0,
                          'm2_obs_unknown': 0, 'm21_hook_gaps_shown': 9},
              'windows': [], 'observer_gaps': gaps + [extra],
              'local_denial_requests': {'event_scan_limit': 2000,
                                       'requests': [{'time': 'time',
                                                     'reason': 'CONTRACT_SCOPE_CONFLICT',
                                                     'receipt': 'receipt-fixture'}]}}
    original = json.dumps(report, sort_keys=True)
    text = mod.render_live_card(report)
    assert text.count('[UNKNOWN] Shell coverage') == 1
    assert '4 distinct Hook windows' in text
    assert '8 gap events (Pre=4, Post=4)' in text
    assert 'SHELL_TARGETS_UNVERIFIED=4' in text
    assert 'SHELL_EFFECT_UNINSPECTED=4' in text
    assert '[UNKNOWN] Hook PreToolUse apply_patch | ADAPTER_FAILURE' in text
    assert 'Hook gaps shown=9' in text
    assert 'Host unverified' in text
    assert '[DENIAL_REQUESTED]' in text
    assert 'LOCAL EVIDENCE / HOST UNVERIFIED' in text
    assert json.dumps(report, sort_keys=True) == original
    missing = gaps[0].copy(); missing['window_id'] = None
    assert 'Hook-window count unknown' in mod._ux_gap_display_lines([missing])[0]


def test_snapshot_keeps_8_raw_shell_gaps_and_host_unverified():
    with patch.dict(sys.modules, _packages()):
        mod = _module('live_watch')
    connection = sqlite3.connect(':memory:')
    connection.row_factory = sqlite3.Row
    connection.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY, record_json TEXT NOT NULL)')
    for i in range(4):
        for phase, reason in [('PreToolUse','SHELL_TARGETS_UNVERIFIED'),
                              ('PostToolUse','SHELL_EFFECT_UNINSPECTED')]:
            evt = {'kind': 'M21_OBSERVER_COVERAGE_GAP', 'window_id': f'window{i}',
                   'data': {'hook_phase': phase, 'tool_kind': 'Bash', 'reason': reason}}
            connection.execute('INSERT INTO events (record_json) VALUES (?)', (json.dumps(evt),))
    connection.commit()
    class Sink:
        @contextlib.contextmanager
        def read(self):
            yield connection
    class Obs:
        sink = Sink()
        def report(self, limit=20):
            return {'windows': [], 'summary': {'m21_hook_gaps_shown': 0}}
    obs = Obs()
    snapshot = mod.evidence_snapshot(obs, limit=20)
    assert len(snapshot['observer_gaps']) == 8
    assert snapshot['summary']['m21_hook_gaps_shown'] == 8
    assert snapshot['local_denial_requests']['host_denial_confirmed'] == 'UNVERIFIED'
    connection.close()
