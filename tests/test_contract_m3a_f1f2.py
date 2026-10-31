"""M3-A F1/F2 targeted regressions. Local only: no Codex Host or Agent."""
import json

import pytest

from clim_agent_guard.contract_runtime import ContractRuntime, SQLiteEvidenceSink
from clim_agent_guard.contract_runtime.advisory import record_advisory
from clim_agent_guard.contract_runtime.differential import LiveShadowDifferential
from clim_agent_guard.contract_runtime.doctor import contract_doctor


def _observer(tmp_path):
    project = tmp_path / 'project'
    (project / 'src/api').mkdir(parents=True)
    (project / 'src/client').mkdir()
    (project / 'src/client/a.py').write_text('a=0\n')
    runtime = ContractRuntime(project, SQLiteEvidenceSink(tmp_path / 'state/ledger.sqlite3'))
    cap = runtime.initialize(task_id='review', allowed=['src/**'], denied=[],
                             stages={'A': {'max_allowed': ['src/api/**']}})
    runtime.propose({'contract_id': 'A1', 'parent_id': 'ROOT', 'stage_id': 'A',
                     'allowed': ['src/api/**']})
    runtime.activate('A1', cap)
    return project, runtime, LiveShadowDifferential(runtime)


def _conflict(obs, runtime, index):
    wid = 'w' + str(index)
    decision = obs.pre(window_id=wid, session_id='same-session', tool_use_id=wid,
                       targets=['src/client/a.py'])
    return wid, decision


def test_f1_precedes_close_even_if_previous_is_closed_when_noted(tmp_path):
    _project, runtime, obs = _observer(tmp_path)
    results = []
    for index in range(1, 4):
        wid, decision = _conflict(obs, runtime, index)
        if index > 1:
            obs.post(window_id='w' + str(index - 1))
        results.append(record_advisory(runtime.sink, session_id='same-session',
                                       window_id=wid, decision=decision))
    assert [r['repeat_count'] for r in results] == [1, 1, 1]
    assert all(not r['operator_review_recommended'] for r in results)
    with runtime.sink.read() as conn:
        rows = conn.execute('SELECT opened_seq,closed_seq FROM windows ORDER BY opened_seq').fetchall()
        assert rows[1]['opened_seq'] < rows[0]['closed_seq']
        assert rows[2]['opened_seq'] < rows[1]['closed_seq']
    assert runtime.sink.verify()['integrity'] == 'LOCAL_CONSISTENCY_ONLY'


def test_f1_truly_sequential_pre_close_preserves_1_2_3(tmp_path):
    _project, runtime, obs = _observer(tmp_path)
    results = []
    for index in range(1, 4):
        wid, decision = _conflict(obs, runtime, index)
        results.append(record_advisory(runtime.sink, session_id='same-session',
                                       window_id=wid, decision=decision))
        obs.post(window_id=wid)
    assert [r['repeat_count'] for r in results] == [1, 2, 3]
    assert [r['operator_review_recommended'] for r in results] == [False, False, True]


@pytest.mark.parametrize('bad_hook_config', [
    {'hooks': []},
    [],
    {'hooks': {'PreToolUse': 'not-a-list'}},
    {'hooks': {'PreToolUse': [None]}},
    {'hooks': {'PreToolUse': [{'hooks': None}]}},
    {'hooks': {'PreToolUse': [{'hooks': [None]}]}},
])
def test_f2_malformed_hook_config_returns_diagnostic_and_never_writes(tmp_path, bad_hook_config):
    project, _runtime, _obs = _observer(tmp_path)
    path = project / '.codex/hooks.json'
    path.parent.mkdir()
    original = json.dumps(bad_hook_config)
    path.write_text(original)
    result = contract_doctor(project)
    assert result['hook_config'] == 'INVALID_CONFIG'
    assert 'INVALID_HOOK_CONFIG' in result['issues']
    assert result['hook_review_trust'] == 'UNVERIFIED'
    assert result['enforced'] is False
    assert path.read_text() == original


def test_f2_malformed_json_returns_diagnostic_without_rewriting(tmp_path):
    project, _runtime, _obs = _observer(tmp_path)
    path = project / '.codex/hooks.json'
    path.parent.mkdir()
    path.write_text('{"hooks":')
    result = contract_doctor(project)
    assert result['hook_config'] == 'INVALID_CONFIG'
    assert 'INVALID_HOOK_CONFIG' in result['issues']
    assert path.read_text() == '{"hooks":'
