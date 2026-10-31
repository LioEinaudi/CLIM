"""Controlled research oracle tests; no inference about actual Agent behavior."""
import pytest
from clim_agent_guard.experimental.trace import handoff,alignment,state_dependency

def meta(value):return {'kind':'file','coverage':'complete','sha256':value,'bytes':1}
def windows():
    return [{'action':a,'start_ns':i*10,'end_ns':i*10+5,'complete':True,'overlapped':False,
             'pre':{'src/api.py':meta('v1')},'post':{'src/api.py':meta('v1')}} for i,a in enumerate('ABC')]
PLAN={'registrar':'independent_test_controller','version':1,'edges':[['A','B'],['B','C']]}

@pytest.mark.parametrize('repeat',range(10))
def test_serial_shared_state(repeat):
    a,b,_=windows()
    assert handoff(a,b,['src/api.py'],synchronous_contract=True)['status']=='HANDOFF_MATCHED_WITHIN_COVERAGE'
    assert alignment(PLAN,windows(),synchronous_contract=True)['status']=='DECLARED_ORDER_MATCHED'

@pytest.mark.parametrize('repeat',range(10))
def test_external_shared_resource_without_attribution(repeat):
    a,b,_=windows();b['pre']['src/api.py']=meta('external')
    r=handoff(a,b,['src/api.py'],synchronous_contract=True)
    assert r['status']=='INTER_WINDOW_CHANGE_OBSERVED' and r['cause']=='UNKNOWN'

@pytest.mark.parametrize('repeat',range(10))
def test_unrelated_file_not_dependency_noise(repeat):
    a,b,_=windows();a['post']['notes.txt']=meta('old');b['pre']['notes.txt']=meta('external')
    assert handoff(a,b,['src/api.py'],synchronous_contract=True)['status']=='HANDOFF_MATCHED_WITHIN_COVERAGE'

@pytest.mark.parametrize('repeat',range(10))
@pytest.mark.parametrize('gap',['missing_post','overlap','unknown_resource','async'])
def test_unknown_boundaries_not_matched_or_violated(repeat,gap):
    a,b,_=windows();sync=True
    if gap=='missing_post':a['complete']=False
    if gap=='overlap':a['overlapped']=True
    if gap=='unknown_resource':del b['pre']['src/api.py']
    if gap=='async':sync=False
    assert handoff(a,b,['src/api.py'],synchronous_contract=sync)['status']=='CHAIN_UNKNOWN'

@pytest.mark.parametrize('repeat',range(10))
def test_declared_reverse_order_not_task_success_or_agent_fault(repeat):
    ws=windows();ws[0]['action']='B';ws[1]['action']='A'
    r=alignment(PLAN,ws,synchronous_contract=True)
    assert r['status']=='DECLARED_ORDER_VIOLATION' and r['violated_edges']==[['A','B']]
    assert state_dependency('v1','v0','api=v1;expect=v0',trusted_contract=True,complete=True)['status']=='STATE_DEPENDENCY_VIOLATION'

@pytest.mark.parametrize('repeat',range(10))
def test_missing_or_agent_declared_plan_never_violation(repeat):
    assert alignment(None,windows(),synchronous_contract=True)['status']=='PLAN_NOT_VERIFIED'
    assert alignment({**PLAN,'registrar':'model:self-report'},windows(),synchronous_contract=True)['status']=='PLAN_NOT_VERIFIED'
    assert alignment({**PLAN,'valid':False},windows(),synchronous_contract=True)['status']=='PLAN_NOT_VERIFIED'

@pytest.mark.parametrize('repeat',range(10))
def test_incomplete_duplicate_overlap_order_is_unknown(repeat):
    assert alignment(PLAN,windows()[:-1],synchronous_contract=True)['status']=='ORDER_UNKNOWN'
    assert alignment(PLAN,windows()+windows(),synchronous_contract=True)['status']=='ORDER_UNKNOWN'
    ws=windows();ws[0]['complete']=False
    assert alignment(PLAN,ws,synchronous_contract=True)['status']=='ORDER_UNKNOWN'
    ws=windows();ws[0]['overlapped']=True
    assert alignment(PLAN,ws,synchronous_contract=True)['status']=='ORDER_UNKNOWN'

def test_invalid_cyclic_plan_not_trusted():
    assert alignment({**PLAN,'edges':[['A','B'],['B','A']]},windows(),synchronous_contract=True)['status']=='PLAN_NOT_VERIFIED'
