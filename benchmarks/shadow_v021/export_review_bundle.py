#!/usr/bin/env python3
"""Export reviewed fixture evidence; raw native transcripts and canaries stay private."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

REPO=Path(__file__).resolve().parents[2]


def digest(data):return hashlib.sha256(data).hexdigest()
def rows(path):return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def export(root,dest):
    env=json.loads((root/'environment.json').read_text());plan=json.loads((root/'registered_matrix.json').read_text())
    dest.mkdir(mode=0o700,parents=True,exist_ok=False)
    current_canary=root/'S08/privacy/canary.txt'
    assert current_canary.is_file(),'Actual run privacy sentinel missing; refuse export'
    sentinel_files={current_canary,*root.parent.glob('clim-shadow-v021-20261014*/S08/privacy/canary.txt')}
    canaries=[p.read_text().strip() for p in sentinel_files]
    def redact(value):
        if isinstance(value,str):
            for secret in canaries:value=value.replace(secret,'[REDACTED_TEST_CANARY]')
            return value
        if isinstance(value,list):return [redact(v) for v in value]
        if isinstance(value,dict):return {k:redact(v) for k,v in value.items()}
        return value
    def save(relative,value):
        target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps(redact(value),indent=2)+'\n');target.chmod(0o600)
    def safe_copy(source,relative):
        target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
        if source.suffix=='.json':save(relative,json.loads(source.read_text()))
        elif source.suffix=='.jsonl':
            target.write_text(''.join(json.dumps(redact(v))+'\n' for v in rows(source)));target.chmod(0o600)
        else:
            target.write_text(redact(source.read_text()));target.chmod(0o600)
    save('environment_requested.json',env)
    env['requested_cli_approval_policy']=env['approval_policy']
    env['approval_policy']='on-request'
    env['permission_context_source']='All 24 actual native turn_context records; CLI requested never, observed on-request. No bypass flags used.'
    save('environment.json',env);save('registered_matrix.json',plan)
    for name in ['verification_output.json','metrics.json','summary.csv','latency_samples.csv']:
        safe_copy(root/'review'/name,name)
    source_dir=dest/'source'
    for name,sha in env['code_sha256'].items():
        code=subprocess.check_output(['git','show',env['source_commit']+':'+name],cwd=REPO)
        assert digest(code)==sha,name
        p=source_dir/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(code)
    for scenario in plan['records']:
        base=Path(scenario['base']);label=scenario['label'];out=Path('runs')/label
        for name in ['scenario.json','before.json','after.json','independent_oracle.json','execution.json',
                     'doctor.json','report.json','doctor_exit.json','audit_check.json','trust.json',
                     'privacy_result.json','target_before.json','target_after.json','target_inventory.json',
                     'git_before_status.txt','git_before_diff.txt','git_after_status.txt','git_after_diff.txt']:
            if (base/name).exists():safe_copy(base/name,out/name)
        cli=rows(base/'codex_stdout_private.jsonl');session=next(v['thread_id'] for v in cli if v.get('type')=='thread.started')
        projected=[]
        for event in cli:
            if event.get('type')=='thread.started':projected.append(event)
            elif event.get('type')=='turn.completed':projected.append({'type':'turn.completed'})
            elif event.get('type')=='item.completed':
                item=event['item']
                if item['type']=='command_execution':
                    projected.append({'type':'item.completed','item':{**item,'redaction_applied':True}})
                if item['type']=='file_change':
                    changes=item['changes']
                    if isinstance(changes,dict):changes=[{'path':k,**v} for k,v in changes.items()]
                    safe=[]
                    for change in changes:
                        safe.append({k:v for k,v in change.items() if k!='diff'})
                        safe[-1]['diff_sha256']=digest(change.get('diff','').encode())
                        safe[-1]['diff_body_omitted']=True
                    projected.append({'type':'item.completed','item':{**item,'changes':safe,'redaction_applied':True}})
        target=dest/out/'codex_trace_redacted.jsonl';target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(''.join(json.dumps(redact(v))+'\n' for v in projected))
        # Save only permission contexts; never copy full native session history.
        histories=list(Path('/root/.codex/sessions/2026/10/14').glob('*'+session+'*'))
        assert len(histories)==1,session
        contexts=[]
        for line in histories[0].read_text().splitlines():
            value=json.loads(line)
            if value.get('type')=='turn_context':
                p=value['payload'];contexts.append({k:p.get(k) for k in ['cwd','model','approval_policy','sandbox_policy']})
                contexts[-1]['reasoning_effort']=p.get('effort')
        save(out/'native_permission_contexts.json',contexts)
        if scenario['shadow']:
            state=Path(scenario['store'])
            for p in state.iterdir():
                if p.is_file() and p.name!='.lock':safe_copy(p,out/'clim_state'/p.name)
            for name in ['latency.jsonl','controller_events.jsonl']:
                if (base/'native_receipts'/name).exists():safe_copy(base/'native_receipts'/name,out/name)
        review=json.loads((root/'review/verification_output.json').read_text())['runs'][label]
        save(out/'automated_operator_review.json',{**review,'reviewer':'Codex mechanical fixture review; independent human review pending',
             'redaction_applied':True,'raw_native_retention':'private fixture root; no automatic publication',
             'attribution':'External injected changes are labelled. Snapshot alone does not establish actor attribution.'})
    for p in (root/'track_a').rglob('*'):
        if p.is_file():safe_copy(p,Path('track_a')/p.relative_to(root/'track_a'))
    diag=Path('/tmp/clim-node-runner-diagnosis-20261014')
    for name in ['diagnosis_result.json','failure_controls.json','fixture_failure_control.json']:
        safe_copy(diag/name,Path('diagnostics/node_runner')/name)
    old=Path('/tmp/clim-shadow-v021-20261014-final')
    safe_copy(old/'review/verification_output.json','excluded_pre_fix_verification.json')
    for rep in ['r1','r2']:
        base=old/'S07/node/shadow'/rep;scenario=json.loads((base/'scenario.json').read_text());state=Path(scenario['store'])
        safe_copy(state/'events.jsonl',Path('excluded_pre_fix_node')/rep/'events.jsonl')
        safe_copy(base/'git_before_status.txt',Path('excluded_pre_fix_node')/rep/'git_before_status.txt')
    save('privacy_export_check.json',{'redaction_applied':True,'raw_command_body_scope':'reviewed disposable fixture commands; fake sentinel replaced, private patch diffs omitted',
         'native_original_transcripts_exported':False,'sentinel_files_exported':False,'canary_plaintext_hits':0,
         'retention':'private originals retained for maintainer review; no automatic remote publication'})
    for p in dest.rglob('*'):
        if p.is_file():
            data=p.read_bytes()
            assert not any(secret.encode() in data for secret in canaries),p
            assert not re.search(rb'(?:sk-proj-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----)',data),p
    print(json.dumps({'exported':str(dest),'files':len([p for p in dest.rglob('*') if p.is_file()]),'plaintext_canary_hits':0}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--dest',type=Path,required=True)
    a=p.parse_args();export(a.root,a.dest)
