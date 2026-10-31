"""M3-B Phase 1: opt-in declared-target enforcement, never full Host/OS security."""
import json
import sqlite3
import subprocess
import sys

import pytest

from clim_agent_guard.contract_runtime.codex_observer import process_event, _window_id
from clim_agent_guard.contract_runtime.codex_setup import configure
from clim_agent_guard.contract_runtime.differential import LiveShadowDifferential
from clim_agent_guard.contract_runtime.doctor import contract_doctor
from clim_agent_guard.contract_runtime.enforcement import (
    WITHIN, VIOLATION, UNKNOWN, declared_targets, evaluate_pre, pre_denial_output,
    enforcement_summary, verify_enforcement)
from clim_agent_guard.contract_runtime.scope import ContractError
from clim_agent_guard.contract_runtime.service import ContractRuntime
from clim_agent_guard.contract_runtime.storage import SQLiteEvidenceSink
from clim_agent_guard.devpreview.store import project_store


@pytest.fixture
def ready(tmp_path, monkeypatch):
    p=tmp_path/'project'; (p/'src/api').mkdir(parents=True); (p/'src/client').mkdir()
    (p/'src/api/a.py').write_text('a=1\n')
    (p/'src/client/b.py').write_text('b=1\n')
    monkeypatch.setenv('CLIM_HOME',str(tmp_path/'external'))
    sink=SQLiteEvidenceSink(project_store(p)/'contract_runtime/ledger.sqlite3')
    rt=ContractRuntime(p,sink)
    cap=rt.initialize(task_id='m3b',allowed=['src/**'],denied=['src/shared/**'],
                      stages={'A':{'max_allowed':['src/api/**']}})
    rt.propose({'contract_id':'A1','parent_id':'ROOT','stage_id':'A','allowed':['src/api/**']})
    rt.activate('A1',cap)
    return p,rt


def payload(path='src/client/b.py',tool='apply_patch',s='session-1',t='tool-1'):
    return {'hook_event_name':'PreToolUse','tool_name':tool,'session_id':s,
        'tool_use_id':t, 'tool_input':{
            'command':f'*** Begin Patch\n*** Update File: {path}\n@@\n-x=1\n+x=2\n*** End Patch'}}


def test_explicit_violation_requests_denial_without_fake_window(ready):
    p,rt=ready
    result=process_event(payload(),'PreToolUse',p,enable_enforcement=True)
    assert result['status']=='DENY_REQUESTED'
    record=result['enforcement']
    assert record['verdict']==VIOLATION and record['reason_code']=='CONTRACT_SCOPE_CONFLICT'
    assert record['host_denial_requested'] and not record['host_denial_confirmed']
    out=pre_denial_output(record)['hookSpecificOutput']
    assert out['permissionDecision']=='deny'
    assert 'permissionDecisionReason' in out and 'updatedInput' not in out
    assert rt.status()['pending_windows']==0
    assert LiveShadowDifferential(rt).report()['windows']==[]
    assert enforcement_summary(rt.sink)['verdicts'][VIOLATION]==1
    assert verify_enforcement(rt.sink)['decisions']==1


def test_default_off_no_deny_and_existing_advisory_independent(ready):
    p,rt=ready
    r=process_event(payload(),'PreToolUse',p)
    assert r['status']=='OBSERVED_PRE' and 'enforcement' not in r
    assert r['enforced'] is False
    assert rt.status()['pending_windows']==1
    assert enforcement_summary(rt.sink)['recorded_decisions']==0


def test_within_scope_has_no_allow_decision_and_observes(ready):
    p,rt=ready
    r=process_event(payload('src/api/a.py'),'PreToolUse',p,enable_enforcement=True)
    assert r['status']=='OBSERVED_PRE'
    assert r['enforced'] is False and 'enforcement' not in r
    assert rt.status()['pending_windows']==1
    stat=enforcement_summary(rt.sink)
    assert stat['verdicts'][WITHIN]==1
    assert not pre_denial_output({'verdict':WITHIN,'host_denial_requested':False})


def test_shell_and_untrusted_patch_unknown_no_denial(ready):
    p,rt=ready
    shell=payload(tool='Bash')
    shell['tool_input']['command']='touch src/client/b.py'
    r=process_event(shell,'PreToolUse',p,enable_enforcement=True)
    assert r['status']=='UNKNOWN' and r['enforced'] is False
    assert r['reason']=='SHELL_TARGETS_UNVERIFIED'
    malformed=payload()
    malformed['tool_input']['command']='*** Begin Patch\n*** Another Field: hi\n*** Update File: src/client/b.py\n*** End Patch'
    r=process_event(malformed,'PreToolUse',p,enable_enforcement=True)
    assert r['status']=='UNKNOWN' and r['enforced'] is False
    assert rt.status()['pending_windows']==0
    assert enforcement_summary(rt.sink)['recorded_decisions']==0


def test_malformed_envelope_absolute_escape_and_move_target_unknown(ready):
    p,_=ready
    assert declared_targets(payload('src/api/a.py')['tool_input'],p)==['src/api/a.py']
    for path in ('../escape','/outside/repo','src/../client/b.py'):
        with pytest.raises(ContractError):declared_targets(payload(path)['tool_input'],p)
    with pytest.raises(ContractError):declared_targets({'command':'*** Begin Patch\n*** Update File: src/client/b.py\n*** End Patch\n*** End Patch'},p)
    cmd='*** Begin Patch\n*** Update File: src/api/a.py\n*** Move to: src/client/b.py\n*** End Patch'
    assert declared_targets({'command':cmd},p)==['src/api/a.py','src/client/b.py']


def test_replay_is_idempotent_and_mismatch_not_authorized(ready):
    p,rt=ready
    w=_window_id('session-1','tool-1')
    first=evaluate_pre(rt,window_id=w,session_id='session-1',tool_use_id='tool-1',targets=['src/client/b.py'])
    second=evaluate_pre(rt,window_id=w,session_id='session-1',tool_use_id='tool-1',targets=['src/client/b.py'])
    assert first['verdict']==VIOLATION and second['replay'] is True
    assert first['event_seq']==second['event_seq']
    with pytest.raises(ContractError,match='M3B_DUPLICATE_ID_MISMATCH'):
        evaluate_pre(rt,window_id=w,session_id='session-1',tool_use_id='tool-1',targets=['src/api/a.py'])
    assert verify_enforcement(rt.sink)['decisions']==1


def test_missing_active_contract_never_requests_denial(tmp_path,monkeypatch):
    p=tmp_path/'p';p.mkdir();monkeypatch.setenv('CLIM_HOME',str(tmp_path/'home'))
    rt=ContractRuntime(p,SQLiteEvidenceSink(project_store(p)/'contract_runtime/ledger.sqlite3'))
    r=evaluate_pre(rt,window_id='w',session_id='s',tool_use_id='t',targets=['src/anything.py'])
    assert r['verdict']==UNKNOWN and not pre_denial_output(r)
    assert verify_enforcement(rt.sink)['decisions']==1


def test_cli_process_real_hook_shape_and_no_post_window(ready):
    p,rt=ready
    proc=subprocess.run([sys.executable,'-m','clim_agent_guard.contract_runtime.codex_observer',
                         'pre','--project',str(p),'--enable-enforcement'],
                        input=json.dumps(payload()),text=True,capture_output=True,timeout=8)
    assert proc.returncode==0 and proc.stderr==''
    data=json.loads(proc.stdout)
    assert data['hookSpecificOutput']['permissionDecision']=='deny'
    assert set(data['hookSpecificOutput']) == {'hookEventName','permissionDecision','permissionDecisionReason'}
    assert rt.status()['pending_windows']==0
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_hook_install_reversible_and_doctor_host_unverified(ready):
    p,rt=ready
    cfg=configure(p,action='install',enable_enforcement=True)
    assert cfg['enforcement_opt_in_requested'] and cfg['not_trusted_automatically']
    hook=(p/'.codex/hooks.json').read_text()
    assert '--enable-enforcement' in hook
    stat=contract_doctor(p)
    assert stat['enforcement_configured']
    assert stat['enforcement_health']=='ENFORCEMENT_CONFIGURED_HOST_UNVERIFIED'
    assert stat['host_denial_confirmed']=='UNVERIFIED'
    assert not configure(p,action='install',enable_enforcement=True)['changed']
    configure(p,action='uninstall')
    assert '--enable-enforcement' not in (p/'.codex/hooks.json').read_text()
    assert not contract_doctor(p)['enforcement_configured']


def test_index_change_detected_without_history_change(ready):
    p,rt=ready
    evaluate_pre(rt,window_id='w',session_id='s',tool_use_id='t',targets=['src/client/b.py'])
    with rt.sink.transaction() as c:
        c.execute("UPDATE m3b_pre_decisions SET target_digest='different' WHERE window_id='w'")
    with pytest.raises(ContractError,match='M3B_EVIDENCE_INDEX_INCONSISTENT'):
        verify_enforcement(rt.sink)


def test_alias_cli_enable_enforcement_and_summary(ready,capsys):
    from clim_agent_guard.devpreview.cli import main
    p,rt=ready
    assert main(['codex','install-hook','--project',str(p),'--enable-enforcement'])==0
    result=json.loads(capsys.readouterr().out)
    assert result['enforcement_opt_in_requested']
    assert main(['contract','enforcement-summary','--project',str(p)])==0
    assert json.loads(capsys.readouterr().out)['recorded_decisions']==0
    assert main(['contract','enforcement-verify','--project',str(p)])==0
    assert json.loads(capsys.readouterr().out)['status']=='NOT_INITIALIZED'


def test_symlink_target_never_claims_enforced_scope(ready):
    p,rt=ready
    (p/'src/client/link.py').symlink_to(p/'src/api/a.py')
    decision=evaluate_pre(rt,window_id='w-symlink',session_id='s',tool_use_id='t',
                          targets=['src/client/link.py'])
    assert decision['verdict']==UNKNOWN
    assert decision['reason_code']=='M3B_SYMLINK_TARGET_UNKNOWN'
    assert not pre_denial_output(decision)


def test_root_denied_path_is_explicit_scope_conflict(ready):
    p,rt=ready
    record=evaluate_pre(rt,window_id='w-root',session_id='s',tool_use_id='t',
                        targets=['src/shared/hidden.py'])
    assert record['verdict']==VIOLATION and record['reason_code']=='ROOT_SCOPE_CONFLICT'
    assert pre_denial_output(record)['hookSpecificOutput']['permissionDecision']=='deny'


def test_enforce_plus_advisory_returns_only_denial_when_explicitly_outside(ready):
    p,rt=ready
    receipt=process_event(payload(),'PreToolUse',p,enable_feedback=True,enable_enforcement=True)
    assert receipt['status']=='DENY_REQUESTED'
    assert 'advisory' not in receipt
    with rt.sink.read() as c:
        kinds=[json.loads(r[0])['kind'] for r in c.execute('SELECT record_json FROM events')]
    assert 'M3_ADVISORY' not in kinds
    assert 'WINDOW_PRE_OBSERVED' not in kinds


def test_install_opt_in_is_independent_of_feedback(ready):
    p,rt=ready
    from clim_agent_guard.devpreview.cli import main
    assert main(['codex','install-hook','--project',str(p),'--enable-enforcement'])==0
    data=json.loads((p/'.codex/hooks.json').read_text())
    pre=data['hooks']['PreToolUse'][0]['hooks'][0]['command']
    post=data['hooks']['PostToolUse'][0]['hooks'][0]['command']
    assert '--enable-enforcement' in pre and '--enable-feedback' not in pre
    assert '--enable-enforcement' not in post
    assert main(['codex','install-hook','--project',str(p)])==0
    pre=json.loads((p/'.codex/hooks.json').read_text())['hooks']['PreToolUse'][0]['hooks'][0]['command']
    assert '--enable-enforcement' not in pre
