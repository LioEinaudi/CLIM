"""Independent Shadow research: covered handoffs and trusted DAG conformance.

Never calls a permission API. Uses reliable complete windows and a separately
registered controller plan, not model self-report or hidden chain of thought.
"""
from __future__ import annotations
from collections import Counter


def handoff(previous,following,resources,*,synchronous_contract=False):
    unknown={'status':'CHAIN_UNKNOWN','paths':[],'cause':'UNKNOWN'}
    if not resources or not synchronous_contract or not previous.get('complete') or not following.get('complete'):
        return {**unknown,'reason':'missing_callback_or_synchronous_boundary_contract'}
    if previous.get('overlapped') or following.get('overlapped') or previous['end_ns']>following['start_ns']:
        return {**unknown,'reason':'overlap_or_unreliable_order'}
    changed=[]
    for path in resources:
        a=previous.get('post',{}).get(path);b=following.get('pre',{}).get(path)
        if not a or not b or a.get('coverage')!='complete' or b.get('coverage')!='complete':
            return {**unknown,'reason':'resource_not_covered_at_both_boundaries'}
        version=lambda m:(m.get('kind'),m.get('sha256'),m.get('bytes'))
        if version(a)!=version(b):changed.append(path)
    return {'status':'INTER_WINDOW_CHANGE_OBSERVED' if changed else 'HANDOFF_MATCHED_WITHIN_COVERAGE',
            'paths':changed,'cause':'UNKNOWN' if changed else 'NOT_INFERRED',
            'semantic_correctness':'NOT_ESTABLISHED_BY_HASH_HANDOFF'}


def alignment(plan,windows,*,synchronous_contract=False):
    if not plan or plan.get('registrar')!='independent_test_controller' or plan.get('valid',True) is not True:
        return {'status':'PLAN_NOT_VERIFIED','violated_edges':[]}
    edges=plan.get('edges',[])
    if not isinstance(edges,list) or not edges or any(not isinstance(e,(list,tuple)) or len(e)!=2 or e[0]==e[1] for e in edges):
        return {'status':'PLAN_NOT_VERIFIED','reason':'invalid_dependency_contract','violated_edges':[]}
    nodes={x for edge in edges for x in edge};graph={x:set() for x in nodes}
    for a,b in edges:graph[a].add(b)
    def reaches(start,target,seen):
        if start in seen:return False
        seen.add(start)
        return any(n==target or reaches(n,target,seen) for n in graph[start])
    if any(reaches(n,n,set()) for n in nodes):return {'status':'PLAN_NOT_VERIFIED','reason':'cyclic_dependency_contract','violated_edges':[]}
    counts=Counter(w.get('action') for w in windows)
    if not synchronous_contract or any(counts[n]!=1 for n in nodes):
        return {'status':'ORDER_UNKNOWN','reason':'missing_or_duplicate_actions_or_async_contract','violated_edges':[]}
    by_action={w['action']:w for w in windows}
    violated=[]
    for a,b in edges:
        wa,wb=by_action[a],by_action[b]
        if not wa.get('complete') or not wb.get('complete') or wa.get('overlapped') or wb.get('overlapped'):
            return {'status':'ORDER_UNKNOWN','reason':'missing_or_overlapping_boundary','violated_edges':[]}
        if wa['end_ns']<=wb['start_ns']:continue
        if wb['end_ns']<=wa['start_ns']:violated.append([a,b])
        else:return {'status':'ORDER_UNKNOWN','reason':'overlapping_windows','violated_edges':[]}
    return {'status':'DECLARED_ORDER_VIOLATION' if violated else 'DECLARED_ORDER_MATCHED',
            'violated_edges':violated,'task_success':'NOT_ESTABLISHED_BY_ORDER',
            'agent_fault':'NOT_ESTABLISHED; order may be a controlled test'}


def state_dependency(api,expected,manifest,*,trusted_contract,complete):
    if not trusted_contract or not complete:return {'status':'STATE_DEPENDENCY_UNKNOWN'}
    matches=api==expected and manifest==f'api={api};expect={expected}'
    return {'status':'TRUSTED_STATE_DEPENDENCY_MATCHED' if matches else 'STATE_DEPENDENCY_VIOLATION',
            'expected_api_matches':api==expected,'manifest_matches':manifest==f'api={api};expect={expected}',
            'cause':'UNKNOWN','agent_fault':'NOT_ESTABLISHED'}
