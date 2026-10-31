"""M3-A local gates; no native host/agent model visibility claims."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from clim_agent_guard.contract_runtime import ContractRuntime, SQLiteEvidenceSink
from clim_agent_guard.contract_runtime.advisory import advisory_summary, pre_hook_context
from clim_agent_guard.contract_runtime.codex_observer import process_event
from clim_agent_guard.contract_runtime.codex_setup import configure
from clim_agent_guard.contract_runtime.doctor import contract_doctor
from clim_agent_guard.contract_runtime.scope import ContractError
from clim_agent_guard.devpreview.store import project_store


@pytest.fixture
def site(tmp_path,monkeypatch):
    root=tmp_path/'project'; (root/'src/api').mkdir(parents=True)
    (root/'src/client').mkdir(parents=True)
    (root/'src/api/a.py').write_text('safe=1\n')
    (root/'src/client/b.py').write_text('client=1\n')
    monkeypatch.setenv('CLIM_HOME',str(tmp_path/'home'))
    rt=ContractRuntime(root,SQLiteEvidenceSink(project_store(root)/'contract_runtime'/'ledger.sqlite3'))
    cap=rt.initialize(task_id='m3a',allowed=['src/**'],denied=[],stages={'A':{'max_allowed':['src/api/**']}})
    rt.propose({'contract_id':'A1','parent_id':'ROOT','stage_id':'A','allowed':['src/api/**']})
    rt.activate('A1',cap)
    return root,rt


def ev(tool_id,phase='PreToolUse',path='src/client/b.py',tool='apply_patch'):
    return {'hook_event_name':phase,'session_id':'native-session','tool_use_id':tool_id,
            'tool_name':tool,'tool_input':{'command':f'*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch'}}


def _subprocess(site, payload, *, feedback=False):
    root,_=site
    args=[sys.executable,'-m','clim_agent_guard.contract_runtime.codex_observer',
          'pre','--project',str(root)]
    if feedback: args.append('--enable-feedback')
    return subprocess.run(args,input=json.dumps(payload),text=True,capture_output=True,timeout=10)


def test_default_opt_out_has_no_advisory_and_no_permission(site):
    root,rt=site
    response=_subprocess(site,ev('d1'))
    assert response.returncode==0 and json.loads(response.stdout)=={}
    assert advisory_summary(rt.sink)['advisory_count']==0
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_scope_conflict_non_authorizing_host_context(site):
    root,rt=site
    response=_subprocess(site,ev('f1'),feedback=True)
    assert response.returncode==0 and response.stderr==''
    payload=json.loads(response.stdout)
    assert set(payload)=={'hookSpecificOutput'}
    assert set(payload['hookSpecificOutput'])=={'hookEventName','additionalContext'}
    assert payload['hookSpecificOutput']['hookEventName']=='PreToolUse'
    msg=payload['hookSpecificOutput']['additionalContext']
    assert 'src/api/**' in msg and 'SCOPE_CONFLICT' in msg
    assert 'src/client/b.py' not in msg  # never echo untrusted proposed text
    assert advisory_summary(rt.sink)['advisory_count']==1
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_conflict_repetition_3_then_operator_review_and_later_compliant(site):
    root,rt=site
    outs=[]
    for n in (1,2,3,4):
        pre=process_event(ev('c'+str(n)),'PreToolUse',root,enable_feedback=True)
        outs.append(pre['advisory'])
        assert process_event(ev('c'+str(n),'PostToolUse'),'PostToolUse',root)['status']=='OBSERVED_POST'
    assert [v['repeat_count'] for v in outs]==[1,2,3,3]
    assert [v['code'] for v in outs]==['SCOPE_CONFLICT','SCOPE_CONFLICT','REPEATED_SCOPE_CONFLICT','REPEATED_SCOPE_CONFLICT']
    assert not outs[0]['operator_review_recommended']
    assert outs[2]['operator_review_recommended']
    assert all(not v['enforced'] and not v['authorized'] for v in outs)
    assert len(outs[2]['message'])<420
    normal=process_event(ev('ok',path='src/api/a.py'),'PreToolUse',root,enable_feedback=True)
    assert normal['advisory'] is None
    process_event(ev('ok','PostToolUse'),'PostToolUse',root)
    resumed=process_event(ev('again'),'PreToolUse',root,enable_feedback=True)
    assert resumed['advisory']['repeat_count']==1
    stats=advisory_summary(rt.sink)
    assert stats['advisory_count']==5 and stats['operator_review_recommended']==2
    assert stats['next_recorded_proposal']['WITHIN_DECLARED_SCOPE']>=1
    assert 'NOT_CAUSAL_REPLAN_PROOF' in stats['limits']


def test_parallel_pending_does_not_count_as_repeated_sequential(site):
    root,rt=site
    a=process_event(ev('p1'),'PreToolUse',root,enable_feedback=True)
    b=process_event(ev('p2'),'PreToolUse',root,enable_feedback=True)
    assert a['advisory']['repeat_count']==b['advisory']['repeat_count']==1


def test_shell_unknown_and_uninspectable_patch_are_silent_to_model(site):
    root,rt=site
    p=ev('sh',tool='Bash');p['tool_input']={'command':'echo arbitrary'}
    out=_subprocess(site,p,feedback=True)
    assert out.returncode==0 and json.loads(out.stdout)=={}
    (root/'src/client/b.py').unlink()
    (root/'src/client/b.py').symlink_to(root/'src/api/a.py')
    p=_subprocess(site,ev('slink'),feedback=True)
    assert p.returncode==0 and json.loads(p.stdout)=={}
    assert advisory_summary(rt.sink)['advisory_count']==0


def test_invalid_hook_identity_still_no_model_message(site):
    p=ev('bad');p['tool_use_id']=None
    assert pre_hook_context(None)=={}
    assert pre_hook_context({'message':'bounded'})['hookSpecificOutput']['additionalContext']=='bounded'


def test_hook_config_explicit_enable_then_disable_and_coexistence(site):
    root,_=site
    hooks=root/'.codex/hooks.json';hooks.parent.mkdir()
    original={'hooks':{'PreToolUse':[{'matcher':'Bash','hooks':[{'type':'command','command':'echo other'}]}]}}
    hooks.write_text(json.dumps(original))
    assert configure(root,action='install')['feedback_opt_in_requested'] is False
    assert not contract_doctor(root)['feedback_configured']
    assert configure(root,action='install',enable_feedback=True)['changed']
    config=json.loads(hooks.read_text())
    assert any('additionalContextLimit' in item for group in config['hooks']['PreToolUse'] for item in group['hooks'])
    assert contract_doctor(root)['feedback_configured']
    assert configure(root,action='install',enable_feedback=True)['changed'] is False
    configure(root,action='uninstall')
    assert json.loads(hooks.read_text())==original


def test_doctor_read_only_and_unverified_trust(site):
    root,rt=site
    status=contract_doctor(root)
    assert status['hook_config']=='NOT_INSTALLED'
    assert status['hook_review_trust']=='UNVERIFIED'
    assert status['observer_health']=='OBSERVER_HEALTH_UNKNOWN'
    assert status['last_pre'] is None
    configure(root,action='install',enable_feedback=True)
    assert contract_doctor(root)['observer_health']=='OBSERVER_HEALTH_UNKNOWN'
    process_event(ev('d1'),'PreToolUse',root)
    status=contract_doctor(root)
    assert status['observer_health']=='RECENT_PRE_OBSERVED'
    assert status['pending_windows']==1
    assert 'PENDING_WINDOWS_REVIEW_EFFECTS' in status['issues']
    process_event(ev('d1','PostToolUse'),'PostToolUse',root)
    assert contract_doctor(root)['pending_windows']==0


def test_cli_doctor_and_summary(site,capsys):
    from clim_agent_guard.devpreview.cli import main
    root,_=site
    assert main(['contract','doctor','--project',str(root)])==0
    result=json.loads(capsys.readouterr().out)
    assert result['hook_review_trust']=='UNVERIFIED'
    assert main(['contract','advisory-summary','--project',str(root)])==0
    assert json.loads(capsys.readouterr().out)['advisory_count']==0
    assert main(['codex','install-hook','--enable-feedback','--project',str(root)])==0
    assert 'feedback_opt_in_requested' in capsys.readouterr().out
