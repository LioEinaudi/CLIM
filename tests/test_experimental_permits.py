"""State-bound permission contract tests; these are not native Codex receipts."""
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
import json
import shutil
import pytest

from clim_agent_guard.experimental.permits import (
    ContractError, consume_permit, initialize, issue_permit, read_policy,
    relevant_state, set_mode,
)


def patch(path='config.prod.json', old='old', new='new'):
    return f'*** Begin Patch\n*** Update File: {path}\n@@\n-{old}\n+{new}\n*** End Patch'


def request(root, command=None, session='S1', operation='O1'):
    return {'cwd': str(root), 'session_id': session, 'tool_use_id': operation,
            'tool_name': 'apply_patch', 'tool_input': {'command': command or patch()}}


@pytest.fixture
def setup(tmp_path):
    root=tmp_path/'project'; root.mkdir(); (root/'config.prod.json').write_text('old\n')
    store=tmp_path/'state'; initialize(root,store,principal='operator:test')
    set_mode(store,'selective-protect')
    return root,store,request(root)


def consume_worker(args):
    store,event=args
    return consume_permit(Path(store),event,now=101)['allowed']


def test_default_is_observational(tmp_path):
    root=tmp_path/'p';root.mkdir();store=tmp_path/'s';initialize(root,store)
    assert read_policy(store)['mode']=='shadow'


@pytest.mark.parametrize('repeat',range(5))
def test_exact_state_bound_action_once(setup,repeat):
    root,store,event=setup
    grant=issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    assert grant['status']=='ISSUED_STATE_BOUND'
    first=consume_permit(store,event,now=101)
    assert first['allowed'] and first['status']=='STATE_BOUND_APPROVAL_VERIFIED_AT_PRE'
    assert consume_permit(store,event,now=102)['allowed'] is False
    assert (root/'config.prod.json').read_text()=='old\n'


@pytest.mark.parametrize('repeat',range(5))
@pytest.mark.parametrize('variant',['patch','session','operation','expired','policy','principal','prestate','project'])
def test_grant_cannot_cross_binding(setup,tmp_path,variant,repeat):
    root,store,event=setup
    issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    changed=json.loads(json.dumps(event));now=101
    if variant=='patch':changed['tool_input']['command']=patch(new='different')
    if variant=='session':changed['session_id']='S2'
    if variant=='operation':changed['tool_use_id']='O2'
    if variant=='expired':now=121
    if variant=='policy':set_mode(store,'shadow');set_mode(store,'selective-protect')
    if variant=='principal':
        p=read_policy(store);p['principal']='operator:other'
        (store/'policy.json').write_text(json.dumps(p))
    if variant=='prestate':(root/'config.prod.json').write_text('external\n')
    if variant=='project':
        other=tmp_path/'other';other.mkdir();(other/'config.prod.json').write_text('old\n')
        other_store=tmp_path/'other-state';initialize(other,other_store,principal='operator:test');set_mode(other_store,'selective-protect')
        shutil.copyfile(store/'exact_permits.json',other_store/'exact_permits.json')
        store=other_store;changed['cwd']=str(other)
    assert not consume_permit(store,changed,now=now)['allowed']


@pytest.mark.parametrize('repeat',range(5))
def test_stale_prestate_is_revoked_even_if_restored(setup,repeat):
    root,store,event=setup;issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    (root/'config.prod.json').write_text('external\n')
    assert consume_permit(store,event,now=101)['status']=='PRESTATE_CHANGED'
    (root/'config.prod.json').write_text('old\n')
    assert not consume_permit(store,event,now=102)['allowed']


@pytest.mark.parametrize('repeat',range(5))
def test_atomic_cross_process_consume_at_most_once(setup,repeat):
    _,store,event=setup;issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    with ProcessPoolExecutor(max_workers=6) as pool:
        results=list(pool.map(consume_worker,[(str(store),event)]*8))
    assert sum(results)==1


def test_absence_is_distinct_from_empty_file(setup):
    root,store,_=setup;name='new.prod.json'
    missing=relevant_state(root,[name]);(root/name).write_bytes(b'')
    present=relevant_state(root,[name])
    assert missing!=present
    assert missing[name]['exists'] is False and present[name]['exists'] is True


def test_duplicate_grants_do_not_replay_one_operation(setup):
    _,store,event=setup
    for _ in range(2):issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    assert consume_permit(store,event,now=101)['allowed']
    assert consume_permit(store,event,now=102)['status']=='EXACT_ACTION_REPLAY'


@pytest.mark.parametrize('shape',['symlink','parent_symlink','oversize','unreadable'])
def test_uncertain_prestate_cannot_get_grant(setup,shape):
    root,store,_=setup
    if shape=='symlink':(root/'alias.prod.json').symlink_to('config.prod.json');target='alias.prod.json'
    elif shape=='parent_symlink':(root/'alias').symlink_to(root,target_is_directory=True);target='alias/config.prod.json'
    elif shape=='oversize':(root/'large.prod.json').write_bytes(b'x'*(4*1024*1024+1));target='large.prod.json'
    else:(root/'config.prod.json').chmod(0);target='config.prod.json'
    with pytest.raises(ContractError):issue_permit(store,request(root,patch(target)),principal='operator:test')


def test_grant_requires_registered_operator(setup):
    _,store,event=setup
    with pytest.raises(ContractError):issue_permit(store,event,principal='agent:self-asserted')


def test_state_check_does_not_promise_toctou_prevention(setup):
    root,store,event=setup;issue_permit(store,event,principal='operator:test',ttl=20,now=100)
    assert consume_permit(store,event,now=101)['allowed']
    (root/'config.prod.json').write_text('external-after-pre\n')
    assert (root/'config.prod.json').read_text()=='external-after-pre\n'
