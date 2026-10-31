"""Opt-in M2 offline integration tests. No Native Hook/Agent involved."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from clim_agent_guard.contract_runtime import ContractRuntime, SQLiteEvidenceSink
from clim_agent_guard.contract_runtime.differential import LiveShadowDifferential, render_card
from clim_agent_guard.contract_runtime.scope import ContractError

@pytest.fixture
def setup_m2(tmp_path):
    root=tmp_path/'project';(root/'src/api').mkdir(parents=True)
    (root/'src/client').mkdir(parents=True)
    (root/'src/api/service.py').write_text('api=0\n')
    (root/'src/client/adapter.py').write_text('client=0\n')
    rt=ContractRuntime(root,SQLiteEvidenceSink(tmp_path/'state/ledger.sqlite3'))
    cap=rt.initialize(task_id='task',allowed=['src/**'],denied=['.env'],
        stages={'A':{'max_allowed':['src/api/**']}})
    rt.propose({'contract_id':'A','parent_id':'ROOT','stage_id':'A',
                'allowed':['src/api/**']})
    rt.activate('A',cap)
    return root, rt, LiveShadowDifferential(rt)


def begin(obs, n, targets=None, watch=None, tool_kind='apply_patch'):
    return obs.pre(window_id=f'w{n}',session_id='s',tool_use_id=f't{n}',
        targets=targets or ['src/api/service.py'], watch=watch,tool_kind=tool_kind)


def test_normal_delta_and_attribution(setup_m2):
    root,rt,obs=setup_m2
    pre=begin(obs,1)
    assert pre['authority_verdict']=='WITHIN_DECLARED_SCOPE'
    (root/'src/api/service.py').write_text('api=1\n')
    post=obs.post(window_id='w1')
    assert post['changed_paths']==['src/api/service.py']
    assert post['attribution']=='CAUSE_UNKNOWN'
    assert post['coverage']=='COMPLETE_BOUNDED'
    assert not post['undeclared_observed_effects']
    report=obs.report()
    assert report['mode']=='SHADOW_ONLY'
    assert 'CAUSE_UNKNOWN' in render_card(report)
    assert rt.sink.verify()['event_count']>0


def test_outside_scope_warns_without_block(setup_m2):
    root,rt,obs=setup_m2
    p=begin(obs,2,targets=['src/client/adapter.py'])
    assert p['authority_verdict']=='CONTRACT_SCOPE_CONFLICT'
    (root/'src/client/adapter.py').write_text('client=2\n')
    result=obs.post(window_id='w2')
    assert result['authority_verdict']=='CONTRACT_SCOPE_CONFLICT'
    assert result['changed_paths']==['src/client/adapter.py']
    assert result['enforced'] is False


def test_cross_target_effect_is_not_named_unauthorized(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,3,watch=['src/client/adapter.py'])
    (root/'src/client/adapter.py').write_text('external=1\n')
    result=obs.post(window_id='w3')
    assert result['undeclared_observed_effects']==['src/client/adapter.py']
    assert result['observed_outside_active_scope']==['src/client/adapter.py']
    assert result['attribution']=='CAUSE_UNKNOWN'
    assert 'unauthorized' not in json.dumps(result)


def test_missing_post_recovery_preserves_unknown(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,4)
    (root/'src/api/service.py').write_text('still_changed=1\n')
    assert obs.report()['windows'][-1]['coverage']=='UNKNOWN'
    result=rt.recover()
    assert result['recovered_unknown']==1
    report=obs.report()
    assert 'MISSING_POST_RECOVERED' in report['windows'][-1]['unknown_reasons']
    assert 'still_changed=1' in (root/'src/api/service.py').read_text()
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_overlap_keeps_cause_unknown(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,5)
    begin(obs,6)
    (root/'src/api/service.py').write_text('overlap\n')
    assert 'OVERLAPPING_WINDOWS' in obs.post(window_id='w6')['unknown_reasons']
    assert 'OVERLAPPING_WINDOWS' in obs.post(window_id='w5')['unknown_reasons']


def test_shell_does_not_claim_coverage(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,7,tool_kind='shell')
    (root/'src/api/service.py').write_text('shell\n')
    result=obs.post(window_id='w7')
    assert result['coverage']=='PARTIAL'
    assert 'SHELL_EFFECT_UNINSPECTED' in result['unknown_reasons']
    assert result['authority_verdict']=='UNVERIFIED_TOOL_TARGET_SEMANTICS'


def test_symlink_and_oversize_unknown(setup_m2):
    root,rt,obs=setup_m2
    (root/'src/api/link.py').symlink_to(root/'src/api/service.py')
    pre=begin(obs,8,watch=['src/api/link.py'])
    assert 'RESOURCE_SYMLINK_PATH' in pre['unknown_reasons']
    result=obs.post(window_id='w8')
    assert result['coverage']=='PARTIAL'
    assert result['changed_paths']==[]


def test_duplicate_and_invalid_path_safely_rejected(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,9)
    with pytest.raises(ContractError): begin(obs,9)
    with pytest.raises(ContractError):begin(obs,10,watch=['../outside'])
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_cli_roundtrip_and_legacy_default_unchanged(setup_m2, monkeypatch):
    root,rt,obs=setup_m2
    monkeypatch.setenv('CLIM_HOME',str(root.parent/'cli-home'))
    from clim_agent_guard.devpreview.store import project_store
    cli_rt=ContractRuntime(root,SQLiteEvidenceSink(project_store(root)/'contract_runtime/ledger.sqlite3'))
    cap=cli_rt.initialize(task_id='cli-task',allowed=['src/**'],denied=['.env'],
        stages={'A':{'max_allowed':['src/api/**']}})
    cli_rt.propose({'contract_id':'A','parent_id':'ROOT','stage_id':'A','allowed':['src/api/**']})
    cli_rt.activate('A',cap)
    def call(*args):
        return subprocess.run([sys.executable,'-m','clim_agent_guard.devpreview.cli',
            'contract',*args,'--project',str(root)],capture_output=True,text=True)
    pre=call('observe-pre','--window-id','w11','--session-id','s',
             '--tool-use-id','t11','--target','src/api/service.py')
    assert pre.returncode==0,pre.stderr
    (root/'src/api/service.py').write_text('cli write\n')
    post=call('observe-post','--window-id','w11')
    assert post.returncode==0,post.stderr
    report=call('shadow-report','--format','card')
    assert report.returncode==0,report.stderr
    assert 'CAUSE_UNKNOWN' in report.stdout
    assert cli_rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_m2_index_integrity_and_tamper_diagnosis(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,20)
    (root/'src/api/service.py').write_text('test-m2-integrity\n')
    obs.post(window_id='w20')
    assert obs.verify()['observations']==1
    with rt.sink.transaction() as c:
        c.execute("UPDATE m2_observation_windows SET summary_json='{}' WHERE window_id='w20'")
    with pytest.raises(ContractError, match='M2_EVIDENCE_INDEX_INCONSISTENT'):
        obs.verify()
    # M1 historic event chain is still intact, proving M2 needs its own check.
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_m2_verify_incomplete_and_m1_only_window(setup_m2):
    root,rt,obs=setup_m2
    begin(obs,21)
    rt.begin_window(window_id='m1only',session_id='s',tool_use_id='m1tool',targets=['src/api/service.py'])
    result=obs.verify()
    assert result['incomplete_observations']==1
    assert result['m1_windows_without_m2_snapshot']==1
    rt.recover()
    assert 'MISSING_POST_RECOVERED' in obs.report()['windows'][-2]['unknown_reasons']


def test_card_unknown_not_conflict_and_true_conflict_unchanged(setup_m2):
    root, rt, obs = setup_m2
    begin(obs, 31, tool_kind='shell')
    obs.post(window_id='w31')
    begin(obs, 32, targets=['src/client/adapter.py'])
    (root / 'src/client/adapter.py').write_text('out of phase\n')
    obs.post(window_id='w32')
    card = render_card(obs.report())
    assert '[UNKNOWN] w31 | UNVERIFIED_TOOL_TARGET_SEMANTICS' in card
    assert '[CONFLICT] w31' not in card
    assert '[CONFLICT] w32 | CONTRACT_SCOPE_CONFLICT' in card
    assert 'writer unproven' in card
    begin(obs, 33)
    assert '[UNKNOWN] w33 | WITHIN_DECLARED_SCOPE | coverage=UNKNOWN' in render_card(obs.report())


@pytest.mark.parametrize('kind', ['apply_patch', 'shell', 'other'])
def test_tool_kind_anchored_to_pre_event_and_verified(setup_m2, kind):
    root, rt, obs = setup_m2
    obs.pre(window_id='kind1', session_id='s', tool_use_id='tk1',
            targets=['src/api/service.py'], tool_kind=kind)
    with rt.sink.read() as c:
        row = c.execute('SELECT pre_seq FROM m2_observation_windows WHERE window_id=?',
                        ('kind1',)).fetchone()
        evt = c.execute('SELECT record_json FROM events WHERE seq=?',
                        (row['pre_seq'],)).fetchone()
        assert json.loads(evt[0])['data']['tool_kind'] == kind
    obs.post(window_id='kind1')
    assert obs.verify()['observations'] == 1
    replacement = 'shell' if kind != 'shell' else 'apply_patch'
    with rt.sink.transaction() as c:
        c.execute('UPDATE m2_observation_windows SET tool_kind=? WHERE window_id=?',
                  (replacement, 'kind1'))
    with pytest.raises(ContractError, match='M2_EVIDENCE_INDEX_INCONSISTENT'):
        obs.verify()
    assert rt.sink.verify()['integrity'] == 'LOCAL_CONSISTENCY_ONLY'


def test_changed_tool_kind_is_rejected_before_post(setup_m2):
    root, rt, obs = setup_m2
    begin(obs, 41, tool_kind='shell')
    with rt.sink.transaction() as c:
        c.execute('UPDATE m2_observation_windows SET tool_kind=? WHERE window_id=?',
                  ('apply_patch', 'w41'))
    with pytest.raises(ContractError, match='M2_EVIDENCE_INDEX_INCONSISTENT'):
        obs.post(window_id='w41')
    with rt.sink.read() as c:
        assert c.execute("SELECT status FROM windows WHERE window_id='w41'").fetchone()[0] == 'PENDING'
