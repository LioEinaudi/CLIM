#!/usr/bin/env python3
"""Archive deterministic S1-S10 tests with independent snapshots, not Codex runs."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from clim_agent_guard.devpreview.policy import SKIP_DIRS,parse_patch
from clim_agent_guard.devpreview.shadow import names
from clim_agent_guard.devpreview.store import read_json

REPO=Path(__file__).resolve().parents[2]


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)


def main(out):
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    tests=load_module('deterministic_shadow_tests',REPO/'tests/test_shadow_v021.py')
    oracle=load_module('independent_oracle_track_a',REPO/'benchmarks/shadow_v021/handoff/shadow_effect_oracle.py')
    original_pre,original_post=tests.pre,tests.post
    methods=sorted(n for n in dir(tests.Shadow) if n.startswith('test_S'))
    results=[]
    for method in methods:
        case_id=method.split('_')[1];dest=out/case_id;dest.mkdir();case=tests.Shadow(method);case.setUp();windows={};counter=0
        def sample(event):
            nonlocal counter
            counter+=1;op=dest/f'window_{counter:02d}'
            pol=read_json(case.store/'policy.json')
            inv=pol.get('shadow_inventory')
            if inv is None:inv=sorted(p.relative_to(case.root).as_posix() for p in case.root.rglob('*') if p.is_file() and not any(x in SKIP_DIRS for x in p.relative_to(case.root).parts[:-1]))
            try:proposed=[names(case.root,p) for p in parse_patch(event.get('tool_input',{}).get('command'))] if event['tool_name']=='apply_patch' else []
            except ValueError:proposed=[]
            inv=sorted(set(inv)|set(proposed));save(op/'inventory.json',inv)
            before=oracle.capture(str(case.root),str(op/'inventory.json'));save(op/'before.json',before)
            save(op/'host_context.json',{'E_authorized':pol.get('shadow_authorized'),'E_required':pol.get('shadow_required'),
                 'E_proposed':proposed,'origin':'DETERMINISTIC_HOOK_TRANSPORT_NOT_CODEX','session_id':event['session_id'],'tool_use_id':event['tool_use_id']})
            windows[(event['session_id'],event['tool_use_id'])]=(op,before,proposed,pol)
        def wrapped_pre(event,store):
            sample(event);return original_pre(event,store)
        def close(event,missing=False):
            w=windows.get((event['session_id'],event['tool_use_id']))
            if w is None:return
            op,before,prop,pol=w;after=oracle.capture(str(case.root),str(op/'inventory.json'));save(op/'after.json',after)
            save(op/'independent_oracle.json',oracle.effect_compare(before,after,prop,pol.get('shadow_authorized'),pol.get('shadow_required')))
            save(op/'transport_status.json',{'post_received':not missing,'origin':'DETERMINISTIC_HOOK_TRANSPORT_NOT_CODEX',
                  'closure':'test_completion_snapshot_not_a_post_event' if missing else 'simulated_post'})
            del windows[(event['session_id'],event['tool_use_id'])]
        def wrapped_post(event,store):
            result=original_post(event,store);close(event);return result
        tests.pre,tests.post=wrapped_pre,wrapped_post
        status='PASS';failure=None
        try:getattr(case,method)()
        except Exception as e:status='FAIL';failure=type(e).__name__+': '+str(e)
        for session,use in list(windows):close({'session_id':session,'tool_use_id':use},missing=True)
        state=dest/'state';state.mkdir()
        for p in case.store.iterdir():
            if p.is_file() and p.name!='.lock':shutil.copy2(p,state/p.name)
        save(dest/'result.json',{'id':case_id,'status':status,'method':method,'failure':failure,
                 'type':'TRACK_A_DETERMINISTIC_NOT_REAL_CODEX','recorded_windows':counter})
        results.append({'id':case_id,'status':status,'method':method,'recorded_windows':counter})
        tests.pre,tests.post=original_pre,original_post;case.doCleanups()
    save(out/'summary.json',{'type':'TRACK_A_DETERMINISTIC_NOT_REAL_CODEX','cases':results,'passed':sum(r['status']=='PASS' for r in results)})
    print(json.dumps({'track':'A','passed':sum(r['status']=='PASS' for r in results),'total':len(results)},indent=2))
    if any(r['status']!='PASS' for r in results):raise SystemExit(1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);main(p.parse_args().out)
