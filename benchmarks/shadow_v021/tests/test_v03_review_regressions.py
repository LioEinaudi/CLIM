"""Review findings at actual report/Git seams; all fixtures are synthetic."""
import subprocess

from clim_agent_guard.devpreview.reconciliation import build_review, render_card
from clim_agent_guard.devpreview.shadow import digest, git_dirty
from test_v03_execution_reconciliation import pre, post


def test_conflicting_duplicate_post_does_not_erase_sensitive_effect():
    events = [pre('s', 'x', targets=['src/a.py']),
              post('s', 'x', observed=['config.prod.json'], protected=['config.prod.json']),
              post('s', 'x', observed=[])]
    review = build_review(events)
    assert review['counts']['PROTECTED_TARGET_CHANGED'] == 1
    assert 'CONFLICTING_HOOK_EVIDENCE' in review['selected_items'][0]['labels']
    assert 'config.prod.json' in render_card(review)


def test_important_unknown_is_visible_among_routine_shell():
    events = [pre('s', 'gap', targets=['src/a.py']),
              post('s', 'gap', observed=[], gaps=[{'reason': 'symlink_target_changed'}])]
    for i in range(10):
        events += [pre('s', str(i), tool='Bash', signals=['UNINSPECTED_SHELL']),
                   post('s', str(i), signals=['UNINSPECTED_SHELL'], decision='UNKNOWN')]
    review = build_review(events, max_items=3)
    assert review['selected_items'][0]['tool_use_id'] == 'gap'
    assert 'COVERAGE_LIMITATION' in review['selected_items'][0]['labels']


def test_collapsed_high_priority_and_all_issue_totals_are_disclosed():
    events = [pre('s', str(i), targets=['config.prod.json'], protected=['config.prod.json']) for i in range(4)]
    text = render_card(build_review(events, max_items=1))
    assert 'High-priority windows collapsed: 3' in text
    assert 'MISSING_POST=4' in text


def test_no_observation_payload_is_unknown_not_empty_verified_set():
    review = build_review([{'phase': 'POST', 'mode': 'shadow', 'session_id': 's',
                            'tool_use_id': 'lost-pre', 'decision': 'UNKNOWN'}])
    assert review['selected_items'][0]['observed'] is None
    assert 'UNMATCHED_PRE' in review['selected_items'][0]['labels']


def test_terminal_controls_in_all_event_fields_are_escaped():
    e = post('s', 'x', observed=['src/\u009b31m.py'], gaps=[{'reason': 'gap\x1b[2J'}])
    e['decision'] = 'UNKNOWN\x1b[2J'
    e['effect']['attribution'] = '\u202ereversed'
    text = render_card(build_review([e]))
    assert not any(c in text for c in ('\x1b', '\u009b', '\u202e'))


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout


def test_unborn_git_baseline_uses_current_content_not_superseded_index(tmp_path):
    git(tmp_path, 'init', '-q')
    p = tmp_path/'a.py'
    p.write_text('staged_only\n'); git(tmp_path, 'add', 'a.py')
    p.write_text('current_user_work\n')
    found = git_dirty(tmp_path, ['a.py'])
    assert found['added_line_sha256']['a.py'] == [digest(b'current_user_work')]


def test_git_literal_pathspec_and_subdirectory_baseline(tmp_path):
    git(tmp_path, 'init', '-q')
    (tmp_path/'sub').mkdir()
    p = tmp_path/'sub'/'a.py'; p.write_text('base\n')
    git(tmp_path, 'add', '.')
    git(tmp_path, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'base')
    p.write_text('base\nuser\n')
    found = git_dirty(tmp_path/'sub', ['a.py'])
    assert found['dirty_paths'] == ['a.py']
    assert found['added_line_sha256']['a.py'] == [digest(b'user')]
    special = tmp_path/':(glob)*'; special.write_text('mine\n'); git(tmp_path, '--literal-pathspecs', 'add', ':(glob)*')
    found = git_dirty(tmp_path, [':(glob)*'])
    assert found['added_line_sha256'][':(glob)*'] == [digest(b'mine')]


def test_notices_opt_in_deduplicated_nonblocking_and_no_shell_hints(tmp_path, monkeypatch, capsys):
    from clim_agent_guard.devpreview.cli import main
    from clim_agent_guard.devpreview.hook import pre as native_pre
    from clim_agent_guard.devpreview.store import project_store
    root = tmp_path/'project'; root.mkdir()
    monkeypatch.setenv('CLIM_HOME', str(tmp_path/'state'))
    assert main(['init', 'codex', '--project', str(root)]) in (None, 0)
    def event(use, tool='apply_patch', command=None):
        return {'session_id':'notice-test', 'tool_use_id':use, 'tool_name':tool,
                'tool_input':{'command':command or '*** Begin Patch\n*** Add File: config.prod.json\n+{}\n*** End Patch'},
                'cwd':str(root), 'hook_event_name':'PreToolUse'}
    store = project_store(root)
    assert native_pre(event('default-off'), store) == {}
    main(['notices', 'on', '--project', str(root)])
    result = native_pre(event('on'), store)
    assert set(result) == {'systemMessage'}
    assert 'Proposal only' in result['systemMessage']
    assert native_pre(event('duplicate'), store) == {}
    assert native_pre(event('literal', 'Bash', "printf '%s' 'rm -rf harmless'"), store) == {}
    for i in range(10):
        result = native_pre(event(str(i), command=f'*** Begin Patch\n*** Add File: production/{i}.json\n+{{}}\n*** End Patch'), store)
        assert bool(result) == (i < 7)
        assert not result.get('hookSpecificOutput')
    main(['notices', 'off', '--project', str(root)])
    assert native_pre(event('off'), store) == {}
