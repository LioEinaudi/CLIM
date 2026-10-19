"""Deterministic v0.3 Shadow-card / maintainer-scale acceptance fixtures.

Synthetic traces exercise presentation invariants, NOT independent Codex runs.
"""
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from clim_agent_guard.devpreview.reconciliation import build_review, render_card
from clim_agent_guard.devpreview.shadow import git_dirty
from clim_agent_guard.devpreview.cli import cmd_report


def pre(session, tool_id, *, tool='apply_patch', targets=None, authority=None, signals=None, coverage=None, risk=None, protected=None):
    return {
        'timestamp':'2026-10-18T00:00:00+00:00','phase':'PRE','mode':'shadow',
        'session_id':session, 'tool_use_id':tool_id, 'tool':tool,
        'E_proposed':targets,'targets':targets,'E_authorized':authority,
        'authority_source':'HOST_POLICY' if authority is not None else 'AUTHORITY_UNKNOWN',
        'signals':signals or [],'risk_signals':risk or [],
        'proposal':{'protected_proposed':protected or []},
        'W':{'gaps':coverage or []},'decision':'WOULD_ALLOW',
    }


def post(session, tool_id, *, proposed=None, observed=None, authorized=None, r_auth=None,
         r_prop=None, protected=None, gaps=None, signals=None, decision='OBSERVED'):
    return {
        'timestamp':'2026-10-18T00:00:01+00:00','phase':'POST','mode':'shadow',
        'session_id':session,'tool_use_id':tool_id,'tool':'apply_patch','decision':decision,
        'signals':signals or [],'effect':{
            'E_proposed':proposed, 'E_observed':observed or [],'E_authorized':authorized,
            'R_authority':r_auth,'R_proposal':r_prop,'protected_changed_paths':protected or [],
            'attribution':'ATTRIBUTION_UNCERTAIN','coverage_gaps':gaps or [],
        },
    }


def test_mixed_pr_effects_no_authorization_conflation():
    """300-file PR fixture: extra change and sensitive config high priority, not falsely unauthorized."""
    events=[]
    for i in range(300):
        p=f'src/module_{i}.py'
        events.extend((pre('s',str(i),targets=[p]),post('s',str(i),proposed=[p],observed=[p],r_prop=[])))
    events += [pre('s','bad',targets=['src/pricing.py']),
               post('s','bad',proposed=['src/pricing.py'],observed=['src/pricing.py','config.prod.json'],
                    r_prop=['config.prod.json'],protected=['config.prod.json'])]
    report=build_review(events,[],max_items=3)
    assert report['windows']==301
    assert report['observed_changed_distinct_paths']==302
    assert report['counts']['UNDECLARED_OBSERVED_CHANGE']==1
    assert report['counts']['PROTECTED_TARGET_CHANGED']==1
    top=report['selected_items'][0]
    assert top['authority_status']=='UNKNOWN'
    assert top['out_of_authorized_scope'] is None
    text=render_card(report)
    assert 'config.prod.json' in text
    assert 'UNDECLARED_OBSERVED_CHANGE' in text
    assert 'Showing 3 prioritized/sample windows' in text
    assert 'TRUSTED_AUTHORITY_RESIDUAL' not in text


def test_trusted_scope_is_separate_from_agent_proposal():
    events=[pre('s','p',targets=['src/a.py'],authority=['src/a.py']),
            post('s','p',proposed=['src/a.py'],observed=['config.prod.json'],
                 authorized=['src/a.py'],r_auth=['config.prod.json'],r_prop=['config.prod.json'])]
    item=build_review(events)['selected_items'][0]
    assert item['authority_status']=='HOST_REGISTERED'
    assert item['out_of_authorized_scope']==['config.prod.json']
    assert 'TRUSTED_AUTHORITY_RESIDUAL' in item['labels']


def test_shell_unverified_does_not_become_unauthorized_or_fully_inspected():
    events=[pre('s','sh',tool='Bash',targets=None,signals=['UNINSPECTED_SHELL','RISK_SIGNAL'],
                risk=['recursive_delete'],coverage=[{'reason':'unwatched_tool'}]),
            post('s','sh',proposed=None,observed=[],gaps=[{'reason':'unwatched_tool'}],
                 signals=['UNINSPECTED_SHELL'],decision='UNKNOWN')]
    report=build_review(events)
    item=report['selected_items'][0]
    assert item['observed']==[] and item['proposed'] is None
    assert item['authority_status']=='UNKNOWN'
    assert 'UNVERIFIED_SHELL' in item['labels']
    assert 'LEXICAL_RISK_ONLY' in item['labels']
    assert item['coverage_gaps']==['unwatched_tool']
    assert report['counts']['UNCERTAIN_WINDOWS']==1
    output=render_card(report)
    assert 'Proposed  : UNKNOWN' in output
    assert 'Lexical hints only: recursive_delete' in output
    assert 'No Hook record is not evidence' in output


def test_missing_post_keeps_unknown_even_with_pre_patch_target():
    item=build_review([pre('s','lost',targets=['src/a.py'])])['selected_items'][0]
    assert item['status']=='MISSING_POST'
    assert item['observed'] is None
    assert 'missing_post' in item['coverage_gaps']


def test_pre_warning_is_proposal_not_observed_effect():
    item=build_review([pre('s','sensitive',targets=['config.prod.json'],
                           protected=['config.prod.json'])])['selected_items'][0]
    assert item['protected_proposed']==['config.prod.json']
    assert item['protected_changed']==[]
    assert 'PRE_PROTECTED_PROPOSAL' in item['labels']
    assert 'PROTECTED_TARGET_CHANGED' not in item['labels']


def test_duplicate_callbacks_do_not_double_count_and_remain_uncertain():
    events=[pre('s','a',targets=['src/a.py']),pre('s','a',targets=['src/a.py']),
            post('s','a',proposed=['src/a.py'],observed=['src/a.py'])]
    report=build_review(events)
    assert report['windows']==1
    assert 'duplicate_hook_event' in report['selected_items'][0]['coverage_gaps']
    assert report['counts']['UNCERTAIN_WINDOWS']==1


def test_dirty_git_baseline_tracks_staged_unstaged_and_untracked():
    """Actual disposable git worktree, no private projects touched."""
    def git(root,*args):
        return subprocess.run(['git','-C',str(root),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with TemporaryDirectory(prefix='clim-git-baseline-') as tmp:
        root=Path(tmp)
        git(root,'init','-q');git(root,'config','user.email','test@example.invalid');git(root,'config','user.name','Test')
        for name in ('staged.py','unstaged.py','clean.py'):
            (root/name).write_text('baseline\n')
        git(root,'add','.');git(root,'commit','-qm','init')
        (root/'staged.py').write_text('baseline\nuser_stage\n')
        git(root,'add','staged.py')
        (root/'unstaged.py').write_text('baseline\nuser_unstaged\n')
        (root/'untracked.py').write_text('user_untracked\n')
        found=git_dirty(root,['staged.py','unstaged.py','untracked.py','clean.py'])
        assert found['available'],found
        assert found['dirty_paths']==['staged.py','unstaged.py','untracked.py']
        assert found['dirty_kinds']['staged.py']==['STAGED']
        assert found['dirty_kinds']['unstaged.py']==['UNSTAGED']
        assert found['dirty_kinds']['untracked.py']==['UNTRACKED']
        assert all(found['added_line_sha256'][p] for p in found['dirty_paths'])
        assert not found['gap']


def test_cli_card_is_opt_in_and_original_json_default(capsys,monkeypatch):
    with TemporaryDirectory(prefix='clim-report-') as tmp:
        root=Path(tmp)/'project'; root.mkdir()
        monkeypatch.setenv('CLIM_HOME',str(Path(tmp)/'state'))
        from clim_agent_guard.devpreview.store import project_store
        store=project_store(root);store.mkdir(parents=True)
        events=[pre('s','p',targets=['src/a.py']),post('s','p',proposed=['src/a.py'],observed=['src/a.py'])]
        (store/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
        cmd_report(SimpleNamespace(project=str(root),today=False,limit=20,advanced=False,format='card'))
        out=capsys.readouterr().out
        assert 'EXECUTION RECONCILIATION' in out
        assert 'src/a.py' in out
        cmd_report(SimpleNamespace(project=str(root),today=False,limit=20,advanced=False))
        old=json.loads(capsys.readouterr().out)
        assert old['schema']=='clim-developer-report/v0.2.1'
        assert old['events']==2


def test_untrusted_path_escapes_terminal_control_characters():
    event=pre('s','e',targets=['src/\x1b[31mbad\nname.py'])
    out=render_card(build_review([event]))
    assert '\x1b' not in out and 'name.py' in out
    assert '\nname.py' not in out


def test_many_shell_windows_are_collapsed_but_not_hidden_from_counts():
    events=[]
    for i in range(40):
        tid=f'shell-{i}'
        events.extend((pre('s',tid,tool='Bash',targets=None,signals=['UNINSPECTED_SHELL'],
                           coverage=[{'reason':'unwatched_tool'}]),
                       post('s',tid,proposed=None,observed=[],decision='UNKNOWN',
                            signals=['UNINSPECTED_SHELL'],gaps=[{'reason':'unwatched_tool'}])))
    report=build_review(events, max_items=10)
    assert report['windows']==40
    assert report['counts']['UNVERIFIED_SHELL']==40
    assert report['collapsed_neutral_windows']==38
    assert len(report['selected_items'])==2
    assert '38 other windows collapsed' in render_card(report)


def test_maintainer_git_only_missing_hook_trace_is_not_certified():
    report=build_review([])
    assert report['windows']==0
    out=render_card(report)
    assert 'No matched Shadow PRE/POST evidence' in out
    assert 'No Hook record is not evidence that no file change occurred' in out



def test_realistic_native_pre_default_protection_signal_never_claims_write():
    # Current native PRE audit includes DEFAULT_PROTECTION_CONFLICT as a signal
    # but does not always include exact protected targets in a nested proposal.
    e=pre('s','p',targets=['src/a.py','config.prod.json'],
          signals=['DEFAULT_PROTECTION_CONFLICT'])
    item=build_review([e])['selected_items'][0]
    assert 'PRE_DEFAULT_PROTECTION_CONFLICT' in item['labels']
    assert item['protected_changed']==[]
    assert item['protected_proposed']==[]  # do not guess which of multiple targets matched
    assert item['observed'] is None
