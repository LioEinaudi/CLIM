#!/usr/bin/env python3
"""Exercise reviewed native trust UI, then sequential real Codex acceptance runs.

This does not edit the trust database or use bypass flags. Operator must review
CLIM code, controller code and all generated definitions before invoking --trust.
Raw native output stays in the private disposable root and must be redacted.
"""
import argparse
from datetime import datetime,timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import termios
import time

REPO=Path(__file__).resolve().parents[2]
ANSI=re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|M)')
FLAGS=['-m','gpt-6.1-sol','-c','model_reasoning_effort="medium"']
APPROVAL=['-c','approval_policy="on-request"']


def save(path,obj):
    path.write_text(json.dumps(obj,indent=2)+'\n');path.chmod(0o600)


def trust(record):
    base=Path(record['base']);master,slave=pty.openpty()
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',45,180,0,0))
    cmd=['codex','--no-daemon',*FLAGS,*APPROVAL,'--no-alt-screen','-C',record['project'],'-s','workspace-write']
    def controlling_terminal():
        os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    proc=subprocess.Popen(cmd,stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm-256color'},preexec_fn=controlling_terminal)
    os.close(slave);raw=b'';stage=0;active=False;deadline=time.monotonic()+90;replied=False
    while time.monotonic()<deadline and proc.poll() is None:
        ready,_,_=select.select([master],[],[],0.2)
        if ready:
            try:chunk=os.read(master,65536)
            except OSError:break
            raw+=chunk
            (base/'trust_ui_in_progress_private.txt').write_bytes(raw)
            if not replied:
                os.write(master,b'\x1b[1;1R\x1b[?1;2c');replied=True
        clean=ANSI.sub('',raw.decode(errors='replace'))
        if stage==0 and 'Trust and continue' in clean:
            time.sleep(1)
            os.write(master,b'\x1b[1;1R\x1b[?1;2c\r');stage=1
            print(json.dumps({'trust_action':record['label'],'action':'folder_review_enter'}),flush=True)
        if stage<=1 and 'Hooks need review' in clean:
            time.sleep(1);os.write(master,b'\r');stage=2
            print(json.dumps({'trust_action':record['label'],'action':'open_native_hook_review'}),flush=True)
        if stage==2 and re.search(r't\s+trust all',clean):
            time.sleep(1);os.write(master,b't');stage=3
            print(json.dumps({'trust_action':record['label'],'action':'trust_inspected_definitions'}),flush=True)
        if stage==3 and re.search(r'PreToolUse\s+1\s+1',clean) and re.search(r'PostToolUse\s+1\s+1',clean):
            active=True;break
        if stage==1 and 'Hooks need review' not in clean and 'GPT-6.1-Sol' in clean:
            os.write(master,b'/hooks');time.sleep(0.2);os.write(master,b'\r');stage=2
    if active:
        os.write(master,b'\x1b');time.sleep(0.4)
    os.write(master,b'\x03')
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
    os.close(master)
    (base/'trust_ui_private.txt').write_bytes(raw)
    save(base/'trust.json',{'status':'TRUSTED_ACTIVE' if active else 'FAILED','recorded_at':datetime.now(timezone.utc).isoformat(),
         'native_command':cmd,'pre_active':active,'post_active':active,'hook_trust_bypass':False})
    if not active:raise RuntimeError('Trust UI activation failed: '+record['label'])


def oracle_module():
    p=REPO/'benchmarks/shadow_v021/handoff/shadow_effect_oracle.py'
    spec=importlib.util.spec_from_file_location('independent_oracle',p);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def execute(record):
    base=Path(record['base']);project=Path(record['project']);oracle=oracle_module()
    before=oracle.capture(str(project),str(base/'inventory.json'));save(base/'before.json',before)
    if (base/'target').exists():
        target_inventory=sorted(p.name for p in (base/'target').iterdir())
        save(base/'target_inventory.json',target_inventory)
        save(base/'target_before.json',oracle.capture(str(base/'target'),str(base/'target_inventory.json')))
    if record['shadow']:
        assert json.loads((base/'trust.json').read_text())['status']=='TRUSTED_ACTIVE'
    cmd=['codex','--no-daemon','exec',*FLAGS,*APPROVAL,'--json','-s','workspace-write','-C',str(project),'-']
    started=datetime.now(timezone.utc).isoformat();clock=time.monotonic_ns();load_before=os.getloadavg()
    with (base/'prompt.txt').open('rb') as prompt,(base/'codex_stdout_private.jsonl').open('wb') as output,(base/'codex_stderr_private.txt').open('wb') as errors:
        proc=subprocess.run(cmd,stdin=prompt,stdout=output,stderr=errors,timeout=480)
    elapsed=(time.monotonic_ns()-clock)/1e9
    save(base/'execution.json',{'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
         'argv':cmd,'exit_code':proc.returncode,'elapsed_seconds':elapsed,'load_before':load_before,'load_after':os.getloadavg(),
         'origin':'ACTUAL_CODEX_CLI','paired_arm':'shadow' if record['shadow'] else 'native'})
    from permission_receipts import contexts_from_rollout, permission_receipt
    with (base/'codex_stdout_private.jsonl').open() as stream:
        thread=next(json.loads(line)['thread_id'] for line in stream
                    if json.loads(line).get('type')=='thread.started')
    sessions=Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))/'sessions'
    rollouts=list(sessions.rglob('*'+thread+'*.jsonl'))
    contexts=[context for path in rollouts for context in contexts_from_rollout(path)]
    receipt=permission_receipt(contexts,'on-request',record['label'],
        subprocess.run(['codex','--version'],capture_output=True,text=True,check=True).stdout.strip())
    receipt.update(requested_model='gpt-6.1-sol',requested_effort='medium',
        configuration_mismatch=not contexts or any(c.get('model')!='gpt-6.1-sol' or
            c.get('effort')!='medium' or c.get('sandbox_policy',{}).get('type')!='workspace-write' or
            c.get('sandbox_policy',{}).get('network_access') is not False for c in contexts))
    save(base/'permission_receipt.json',receipt)
    if receipt['policy_mismatch'] or receipt['configuration_mismatch']:
        raise RuntimeError('Native configuration differs from preregistered request: '+record['label'])
    save(base/'after.json',oracle.capture(str(project),str(base/'inventory.json')))
    before=oracle.load(base/'before.json');after=oracle.load(base/'after.json')
    proposals=[]
    if record['shadow']:
        audit=Path(record['store'])/'events.jsonl'
        if audit.exists():
            for line in audit.read_text().splitlines():
                entry=json.loads(line)
                if entry.get('phase')=='PRE' and entry.get('E_proposed') is not None:
                    proposals.extend(entry['E_proposed'])
    comparison=oracle.effect_compare(before,after,sorted(set(proposals)),record['E_authorized'],record['E_required'])
    comparison['proposal_source']='ACTUAL_CLIM_PRE_TRANSPORT' if record['shadow'] else 'UNKNOWN_NATIVE_ONLY'
    if not proposals:
        comparison['R_proposal']=None
    save(base/'independent_oracle.json',comparison)
    if (base/'target').exists():save(base/'target_after.json',oracle.capture(str(base/'target'),str(base/'target_inventory.json')))
    for kind,args in [('status',['status','--porcelain=v1']),('diff',['diff','--no-ext-diff','--no-textconv'])]:
        result=subprocess.run(['git','-C',str(project),*args],capture_output=True,text=True,check=True)
        (base/('git_after_'+kind+'.txt')).write_text(result.stdout)
    if record['shadow']:
        env={**os.environ,'CLIM_HOME':str(base/'clim_home'),'PYTHONDONTWRITEBYTECODE':'1'}
        for command in ['doctor','report']:
            args=[str(REPO/'.venv/bin/clim'),command,'--project',str(project)]
            if command=='report':args+=['--limit','50']
            result=subprocess.run(args,env=env,capture_output=True,text=True)
            (base/(command+'.json')).write_text(result.stdout)
            save(base/(command+'_exit.json'),{'exit_code':result.returncode})
        save(base/'audit_check.json',oracle.audit_check(str(Path(record['store'])/'events.jsonl')))
    if record['label']=='S08/privacy':
        save(base/'privacy_result.json',oracle.privacy_scan([base/'clim_home',base/'report.json',base/'doctor.json'],base/'canary.txt'))
    print(json.dumps({'completed':record['label'],'exit':proc.returncode,'seconds':round(elapsed,2)}),flush=True)
    if proc.returncode:raise RuntimeError('Native Codex exited unsuccessfully: '+record['label'])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--trust',action='store_true');parser.add_argument('--run',action='store_true');parser.add_argument('--labels',nargs='*')
    args=parser.parse_args();plan=json.loads((args.root/'registered_matrix.json').read_text())
    records=[r for r in plan['records'] if not args.labels or r['label'] in args.labels]
    for record in records:
        prior=Path(record['base'])/'trust.json'
        already=prior.exists() and json.loads(prior.read_text()).get('status')=='TRUSTED_ACTIVE'
        if args.trust and record['shadow'] and not already:
            trust(record);print(json.dumps({'trusted':record['label']}),flush=True)
        if args.run and not (Path(record['base'])/'execution.json').exists():execute(record)

if __name__=='__main__':main()
