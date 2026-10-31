"""Controlled callback tests, not evidence of native Host enforcement."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from clim_agent_guard.experimental.permits import initialize, issue_permit, register_postcondition, set_mode
from clim_agent_guard.experimental.protect import pre, post, report


def patch(path,old='old',new='new',kind='Update'):
    body=f'@@\n-{old}\n+{new}' if kind=='Update' else '+new' if kind=='Add' else ''
    return f'*** Begin Patch\n*** {kind} File: {path}\n{body}\n*** End Patch'


def event(root,command,operation='O1',tool='apply_patch'):
    return {'cwd':str(root),'session_id':'S1','tool_use_id':operation,'tool_name':tool,
            'hook_event_name':'PreToolUse','tool_input':{'command':command}}


def after(e,**response):
    return {**e,'hook_event_name':'PostToolUse','tool_response':response or {'success':True}}


@pytest.fixture
def env(tmp_path):
    root=tmp_path/'project';root.mkdir();(root/'src').mkdir()
    (root/'src/a.py').write_text('old\n');(root/'src/b.py').write_text('old\n')
    (root/'config.prod.json').write_text('old\n')
    store=tmp_path/'store';initialize(root,store,principal='operator:test',inventory=['src/a.py','src/b.py','config.prod.json','.env.new'])
    set_mode(store,'selective-protect')
    return root,store


def denied(value):return value.get('hookSpecificOutput',{}).get('permissionDecision')=='deny'


def test_thirty_normal_patches_and_routine_shell_are_not_denied(env):
    root,store=env
    for n in range(30):
        e=event(root,patch('src/a.py',old=str(n),new=str(n+1)),str(n))
        assert not denied(pre(e,store))
        (root/'src/a.py').write_text(str(n+1)+'\n');post(after(e),store)
    e=event(root,'python -B -m unittest','shell','Bash')
    assert not denied(pre(e,store));post(after(e),store)
    assert report(store)['counts'].get('PRE_DENIED',0)==0


def test_twenty_sensitive_unapproved_requests_including_add_delete(env):
    root,store=env;before=(root/'config.prod.json').read_bytes()
    for n in range(20):
        target='.env.new' if n%3==0 else 'config.prod.json'
        kind='Add' if n%3==0 else 'Delete' if n%3==1 else 'Update'
        assert denied(pre(event(root,patch(target,kind=kind),str(n)),store))
    assert not (root/'.env.new').exists() and (root/'config.prod.json').read_bytes()==before
    assert report(store)['counts']['PRE_DENIED']==20
    assert report(store)['host_enforcement_status']=='NOT_ESTABLISHED_BY_HOOK_RECORDS'


def test_exact_permit_and_same_path_different_patch(env):
    root,store=env;e=event(root,patch('config.prod.json'))
    issue_permit(store,e,principal='operator:test')
    assert not denied(pre(e,store));(root/'config.prod.json').write_text('new\n');post(after(e),store)
    assert denied(pre(e,store))
    assert denied(pre(event(root,patch('config.prod.json',new='other'),'O2'),store))
    assert report(store)['counts']['STATE_BOUND_APPROVAL_VERIFIED_AT_PRE']==1


def test_changed_prestate_revokes_exact_permission(env):
    root,store=env;e=event(root,patch('config.prod.json'));issue_permit(store,e,principal='operator:test')
    (root/'config.prod.json').write_text('controller\n')
    assert denied(pre(e,store));assert report(store)['counts']['PRESTATE_CHANGED']==1


@pytest.mark.parametrize('repeat',range(10))
def test_observed_extra_file_is_not_authorship_or_authorization(env,repeat):
    root,store=env;e=event(root,patch('src/a.py'))
    pre(e,store);(root/'src/a.py').write_text('new\n');(root/'src/b.py').write_text('controller\n');post(after(e),store)
    row=report(store)['events'][-1]
    assert row['effect']['observed_outside_proposal']==['src/b.py']
    assert 'OBSERVED_OUTSIDE_PROPOSAL' in row['signals']
    assert row['effect']['attribution']=='ATTRIBUTION_UNCERTAIN'
    assert row['effect']['authorization']=='UNKNOWN'


@pytest.mark.parametrize('repeat',range(5))
def test_missing_post_and_orphan_post_are_unknown(env,repeat):
    root,store=env;e=event(root,patch('src/a.py'));pre(e,store)
    r=report(store);assert r['pending'][0]['classification']=='MISSING_POST'
    assert r['pending'][0]['status']=='UNKNOWN'
    post(after(event(root,patch('src/b.py'),'orphan')),store)
    assert report(store)['events'][-1]['classification']=='ORPHAN_POST_UNKNOWN'


@pytest.mark.parametrize('repeat',range(5))
def test_explicit_tool_failure_never_success(env,repeat):
    root,store=env;e=event(root,patch('src/a.py'));pre(e,store);post(after(e,success=False),store)
    assert report(store)['events'][-1]['classification']=='TOOL_FAILED'


@pytest.mark.parametrize('repeat',range(10))
def test_shell_side_effect_is_observed_with_gap_not_comprehensively_protected(env,repeat):
    root,store=env;e=event(root,'python tools/side_effect.py',tool='Bash')
    assert not denied(pre(e,store));(root/'config.prod.json').write_text('controller\n');post(after(e),store)
    row=report(store)['events'][-1]
    assert row['effect']['observed']==['config.prod.json']
    assert row['effect']['proposed'] is None and row['effect']['coverage_gaps']
    assert row['effect']['protection_scope']=='SUPPORTED_APPLY_PATCH_ONLY'


def test_trusted_state_postcondition_mismatch(env):
    root,store=env;command=patch('src/a.py');sha=hashlib.sha256(command.encode()).hexdigest()
    register_postcondition(store,sha,{'src/a.py':{'exists':True,'type':'file','sha256':hashlib.sha256(b'expected\n').hexdigest()}},principal='operator:test')
    e=event(root,command);pre(e,store);(root/'src/a.py').write_text('wrong\n');post(after(e),store)
    assert report(store)['events'][-1]['classification']=='STATE_MISMATCH'


def test_hash_change_alone_is_not_semantic_success(env):
    root,store=env;e=event(root,patch('src/a.py'));pre(e,store);(root/'src/a.py').write_text('wrong\n');post(after(e),store)
    row=report(store)['events'][-1]
    assert row['classification']=='OBSERVED_WITHIN_COVERAGE'
    assert row['effect']['semantic_status']=='NO_TRUSTED_POSTCONDITION'


def test_native_three_line_delete_of_normal_file_is_supported(env):
    root,store=env;e=event(root,'*** Begin Patch\n*** Delete File: src/a.py\n*** End Patch')
    assert not denied(pre(e,store))


def test_policy_revision_invalidates_old_postcondition(env):
    root,store=env;command=patch('src/a.py');sha=hashlib.sha256(command.encode()).hexdigest()
    register_postcondition(store,sha,{'src/a.py':{'exists':True,'type':'file','sha256':hashlib.sha256(b'expected\n').hexdigest()}},principal='operator:test')
    e=event(root,command);pre(e,store);set_mode(store,'shadow');post(after(e),store)
    row=report(store)['events'][-1]
    assert row['effect']['semantic_status']=='CONTRACT_INVALIDATED_POLICY_CHANGE'
    assert row['classification']!='STATE_MISMATCH'


def test_overlap_is_recorded_conservatively(env):
    root,store=env;a=event(root,patch('src/a.py'),'A');b=event(root,patch('src/b.py'),'B')
    pre(a,store);pre(b,store);post(after(a),store);post(after(b),store)
    assert all(e['overlapped'] for e in report(store)['events'] if e['phase']=='POST')


def test_shadow_retains_observational_default_even_protected(env):
    root,store=env;set_mode(store,'shadow');e=event(root,patch('config.prod.json'))
    assert not denied(pre(e,store));(root/'config.prod.json').write_text('new\n');post(after(e),store)
    assert report(store)['counts'].get('PRE_DENIED',0)==0


@pytest.mark.parametrize('repeat',range(5))
def test_empty_hook_store_does_not_claim_protection(env,repeat):
    _,store=env;r=report(store)
    assert r['coverage_status']=='NO_HOOK_EVIDENCE_UNKNOWN'


def test_unsupported_shell_errors_do_not_expand_protection_scope(env):
    root,store=env;e=event(root,'printf harmless',tool='Bash');e['cwd']=str(root/'wrong-cwd')
    proc=subprocess.run([sys.executable,'-B','-m','clim_agent_guard.experimental.protect','pre','--store',str(store)],
                        input=json.dumps(e),capture_output=True,text=True,cwd=Path(__file__).resolve().parents[1])
    assert proc.returncode==0 and json.loads(proc.stdout)=={}


@pytest.mark.parametrize('repeat',range(10))
def test_symlink_and_large_target_not_marked_protected_verified(env,repeat):
    root,store=env
    (root/'alias.prod.json').symlink_to('config.prod.json')
    assert denied(pre(event(root,patch('alias.prod.json'),'symlink'),store))
    (root/'large.prod.json').write_bytes(b'x'*(4*1024*1024+1))
    assert denied(pre(event(root,patch('large.prod.json'),'large'),store))
    assert not any(e.get('classification')=='PROTECTED_AND_VERIFIED' for e in report(store)['events'])


def test_inventory_limit_is_disclosed(env):
    root,store=env
    from clim_agent_guard.experimental.permits import read_policy
    p=read_policy(store);p['inventory']=['src/a.py']+[f'padding/{n:03d}.py' for n in range(300)]
    (store/'policy.json').write_text(json.dumps(p))
    e=event(root,patch('src/a.py'));pre(e,store);post(after(e),store)
    gaps=report(store)['events'][-1]['effect']['coverage_gaps']
    assert any(g['reason']=='scan_limit' for g in gaps)


def test_check_use_race_observed_but_not_prevented(env):
    root,store=env;e=event(root,patch('config.prod.json'));issue_permit(store,e,principal='operator:test')
    assert not denied(pre(e,store))
    (root/'config.prod.json').write_text('external after approved Pre\n')
    post(after(e),store)
    row=report(store)['events'][-1]
    assert row['effect']['race_prevention']=='NOT_PROVIDED'
    assert row['effect']['attribution']=='ATTRIBUTION_UNCERTAIN'


@pytest.mark.parametrize('repeat',range(10))
def test_no_user_bytes_or_git_index_mutated_by_hooks(env,repeat):
    root,store=env
    def git(*args):return subprocess.run(['git','-C',str(root),*args],capture_output=True,check=True).stdout
    git('init','-q');git('add','.');git('-c','user.name=LioEinaudi','-c','user.email=Jinbin.Zhao.Dev@gmail.com','commit','-qm','fixture')
    (root/'src/b.py').write_text('user staged\n');git('add','src/b.py');(root/'src/b.py').write_text('user staged\nuser unstaged\n')
    (root/'notes.txt').write_text('untracked operator note\n')
    user=(root/'src/b.py').read_bytes();index=(root/'.git/index').read_bytes();notes=(root/'notes.txt').read_bytes()
    e=event(root,patch('src/a.py'));pre(e,store);post(after(e),store)
    assert (root/'src/b.py').read_bytes()==user and (root/'.git/index').read_bytes()==index
    assert (root/'notes.txt').read_bytes()==notes
