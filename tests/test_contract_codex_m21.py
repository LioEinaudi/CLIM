"""M2.1 product adapter local integration (not Codex Native)."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from clim_agent_guard.contract_runtime import ContractRuntime, SQLiteEvidenceSink
from clim_agent_guard.contract_runtime.codex_setup import configure, TAG
from clim_agent_guard.contract_runtime.codex_observer import process_event, proposed_patch_targets, _window_id
from clim_agent_guard.contract_runtime.live_watch import evidence_snapshot, render_live_card, watch
from clim_agent_guard.contract_runtime.differential import LiveShadowDifferential
from clim_agent_guard.devpreview.store import project_store
from clim_agent_guard.contract_runtime.scope import ContractError


@pytest.fixture
def env(tmp_path, monkeypatch):
    project=tmp_path/'work'; (project/'src/api').mkdir(parents=True)
    (project/'src/api/demo.py').write_text('x=1\n')
    (project/'src/client').mkdir()
    (project/'src/client/main.py').write_text('x=1\n')
    monkeypatch.setenv('CLIM_HOME',str(tmp_path/'outside'))
    rt=ContractRuntime(project,SQLiteEvidenceSink(project_store(project)/'contract_runtime'/'ledger.sqlite3'))
    cap=rt.initialize(task_id='m21',allowed=['src/**'],denied=['.env'],
                      stages={'A':{'max_allowed':['src/api/**']}})
    rt.propose({'contract_id':'A1','parent_id':'ROOT','stage_id':'A','allowed':['src/api/**']})
    rt.activate('A1',cap)
    return project,rt


def event(name='PreToolUse', tool='apply_patch', session='native-session', call='t1', path='src/api/demo.py'):
    return {'hook_event_name':name, 'tool_name':tool,'session_id':session,'tool_use_id':call,
            'tool_input':{'command':f'*** Begin Patch\n*** Update File: {path}\n@@\n-x=1\n+x=2\n*** End Patch'}}


def test_native_patch_pre_post_and_diff(env):
    project,rt=env
    pre=process_event(event(), 'PreToolUse',project)
    assert pre['status']=='OBSERVED_PRE'
    assert pre['enforced'] is False
    (project/'src/api/demo.py').write_text('x=2\n')
    post=process_event(event('PostToolUse'),'PostToolUse',project)
    assert post['status']=='OBSERVED_POST'
    obs=LiveShadowDifferential(rt)
    report=obs.report()
    assert report['windows'][-1]['changed_paths']==['src/api/demo.py']
    assert rt.sink.verify()['integrity']=='LOCAL_CONSISTENCY_ONLY'


def test_native_out_of_scope_nonblocking(env):
    project,rt=env
    payload=event(path='src/client/main.py')
    assert process_event(payload,'PreToolUse',project)['enforced'] is False
    (project/'src/client/main.py').write_text('changed\n')
    assert process_event(event('PostToolUse',path='src/client/main.py'),'PostToolUse',project)['status']=='OBSERVED_POST'
    assert LiveShadowDifferential(rt).report()['windows'][-1]['authority_verdict']=='CONTRACT_SCOPE_CONFLICT'


def test_shell_no_fabricated_target_unknown(env):
    project,rt=env
    payload=event(tool='Bash');payload['tool_input']={'command':'echo ok'}
    r=process_event(payload,'PreToolUse',project)
    assert r['reason']=='SHELL_TARGETS_UNVERIFIED'
    assert process_event(event('PostToolUse','Bash'),'PostToolUse',project)['reason']=='SHELL_EFFECT_UNINSPECTED'
    obs=LiveShadowDifferential(rt)
    snap=evidence_snapshot(obs)
    assert snap['summary']['m21_hook_gaps_shown']==2
    assert snap['windows']==[]
    assert 'SHELL_TARGETS_UNVERIFIED' in render_live_card(snap)


def test_invalid_event_keeps_unknown(env):
    project,rt=env
    p=event();p['hook_event_name']='SomethingElse'
    assert process_event(p,'PreToolUse',project)['reason']=='INVALID_NATIVE_HOOK_EVENT'
    assert evidence_snapshot(LiveShadowDifferential(rt))['summary']['m21_hook_gaps_shown']==1


def test_missing_post_is_pending_not_good(env):
    project,rt=env
    process_event(event(),'PreToolUse',project)
    snap=evidence_snapshot(LiveShadowDifferential(rt))
    assert snap['summary']['m1_exec_pending']==1
    assert snap['summary']['m2_obs_unknown']==1
    assert '[UNKNOWN]' in render_live_card(snap)


def test_overlap_unproven(env):
    project,rt=env
    process_event(event(call='t1'),'PreToolUse',project)
    process_event(event(call='t2'),'PreToolUse',project)
    (project/'src/api/demo.py').write_text('overlap\n')
    process_event(event('PostToolUse',call='t1'),'PostToolUse',project)
    assert any('OVERLAPPING_WINDOWS' in item['unknown_reasons'] for item in LiveShadowDifferential(rt).report()['windows'])


def test_no_contract_skip_and_no_create(tmp_path, monkeypatch):
    project=tmp_path/'empty';project.mkdir()
    monkeypatch.setenv('CLIM_HOME',str(tmp_path/'outside'))
    assert process_event(event(),'PreToolUse',project)['status']=='SKIPPED_NO_CONTRACT'
    assert not (tmp_path/'outside').exists()


def test_patch_parser_rejects_escape_and_unknown(env):
    project,_=env
    with pytest.raises(ContractError): proposed_patch_targets({'command':'rm -rf whatever'},project)
    with pytest.raises(ContractError): proposed_patch_targets(event(path='../outside')['tool_input'],project)
    with pytest.raises(ContractError): proposed_patch_targets(event(path='/tmp/outside')['tool_input'],project)
    assert proposed_patch_targets(event(path=str(project/'src/api/demo.py'))['tool_input'],project)==['src/api/demo.py']


def test_hook_install_uninstall_preserves_other_hooks(env):
    project,_=env
    hooks=project/'.codex/hooks.json';hooks.parent.mkdir()
    orig={'description':'keep', 'hooks':{'PreToolUse':[{'matcher':'^Bash$', 'hooks':[{'type':'command','command':'echo untouched'}]}]}}
    hooks.write_text(json.dumps(orig))
    r=configure(project,action='install')
    assert r['changed'] and r['not_trusted_automatically']
    doc=json.loads(hooks.read_text())
    assert len(doc['hooks']['PreToolUse'])==2
    assert doc['hooks']['PreToolUse'][1]['hooks'][0]['type']=='command'
    assert TAG in hooks.read_text()
    r2=configure(project,action='install')
    assert r2['changed'] is False
    configure(project,action='uninstall')
    assert json.loads(hooks.read_text())==orig
    assert configure(project,action='uninstall')['changed'] is False


def test_hook_install_dry_run_does_not_touch_file(env):
    project,_=env
    assert configure(project,action='install',dry_run=True)['changed']
    assert not (project/'.codex/hooks.json').exists()


def test_invalid_existing_config_preserved(env):
    project,_=env
    folder=project/'.codex';folder.mkdir()
    file=folder/'hooks.json';file.write_text('{invalid')
    with pytest.raises(ValueError):configure(project,action='install')
    assert file.read_text()=='{invalid'


def test_does_not_override_inline_hooks(env):
    project,_=env
    folder=project/'.codex';folder.mkdir()
    (folder/'config.toml').write_text('[[hooks.PreToolUse]]\nmatcher="Bash"\n')
    with pytest.raises(ContractError):configure(project,action='install')


def test_watch_once_and_ndjson(env):
    project,rt=env
    import io
    buf=io.StringIO()
    watch(LiveShadowDifferential(rt),fmt='ndjson',once=True,out=buf)
    parsed=json.loads(buf.getvalue())
    assert parsed['report']['summary']['m1_exec_pending']==0
    assert parsed['event_seq']>=1


def test_cli_hook_adapter_subprocess_nonblocking(env):
    project,_=env
    result=subprocess.run([sys.executable,'-m','clim_agent_guard.contract_runtime.codex_observer',
                           'pre','--project',str(project)],
                          input=json.dumps(event()),text=True,capture_output=True,timeout=8)
    assert result.returncode==0 and json.loads(result.stdout)=={}
    # Test observer actually recorded a PRE rather than silently pretending.
    assert process_event(event('PostToolUse'),'PostToolUse',project)['status']=='OBSERVED_POST'


def test_cli_routes_show_and_hook(env, monkeypatch, capsys):
    from clim_agent_guard.devpreview.cli import main
    project,_=env
    assert main(['contract','watch','--project',str(project),'--once'])==0
    assert 'M1 Exec:' in capsys.readouterr().out
    assert main(['contract','codex-hook','install','--project',str(project)])==0
    assert (project/'.codex/hooks.json').exists()
    assert main(['contract','codex-hook','uninstall','--project',str(project)])==0



def test_codex_short_alias(env, capsys):
    from clim_agent_guard.devpreview.cli import main
    project,_=env
    assert main(['codex','install-hook','--project',str(project)])==0
    assert 'requires_codex_hook_review' in capsys.readouterr().out
    assert main(['codex','hook-status','--project',str(project)])==0
    assert main(['codex','uninstall-hook','--project',str(project)])==0


def test_nonblocking_bad_input_stdio(env):
    project,_=env
    proc=subprocess.run([sys.executable,'-m','clim_agent_guard.contract_runtime.codex_observer',
                         'pre','--project',str(project)],input='invalid JSON',text=True,
                         capture_output=True,timeout=8)
    assert proc.returncode==0
    assert json.loads(proc.stdout)=={}
    assert proc.stderr==''


def test_card_m1_and_m2_unknown_counts_are_distinct(env):
    project,rt=env
    process_event(event(tool='Bash'),'PreToolUse',project)
    process_event(event(), 'PreToolUse',project)
    view=evidence_snapshot(LiveShadowDifferential(rt))
    assert view['summary']['m1_exec_pending']==1
    assert view['summary']['m1_exec_recovered']==0
    assert view['summary']['m2_obs_unknown']==1
    assert view['summary']['m21_hook_gaps_shown']==1
    lines=render_live_card(view)
    assert 'M1 Exec: pending=1 recovered/unknown=0' in lines
    assert 'M2 Obs (shown): complete=0 partial=0 unknown=1' in lines


def test_explicit_bootstrap_scope_and_operator_ack(tmp_path, monkeypatch, capsys):
    from clim_agent_guard.devpreview.cli import main
    root=tmp_path/'project';(root/'src/api').mkdir(parents=True)
    monkeypatch.setenv('CLIM_HOME',str(tmp_path/'external-state'))
    argv=['contract','bootstrap','--project',str(root),'--template','code-only',
          '--scope','src/api/**']
    assert main(argv)==2
    # CLI currently creates an empty local DB when invoked; it must not grant a task.
    from clim_agent_guard.contract_runtime.storage import SQLiteEvidenceSink
    s=SQLiteEvidenceSink(project_store(root)/'contract_runtime/ledger.sqlite3')
    with s.read() as c: assert s.get(c,'current_state') is None
    capsys.readouterr()
    assert main(argv+['--acknowledge-scope'])==0
    data=json.loads(capsys.readouterr().out)
    assert data['active_scope']==['src/api/**']
    assert data['enforced'] is False
    assert not (root/'.codex').exists()
    assert data['hook_config_changed'] is False
    rt=ContractRuntime(root,SQLiteEvidenceSink(project_store(root)/'contract_runtime/ledger.sqlite3'))
    assert rt.status()['active_contract']=='CLIM_BOOTSTRAP_1'
