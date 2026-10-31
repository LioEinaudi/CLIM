"""Opt-in HC01 command supervisor, not an OS or host fail-closed boundary.

The wrapper converts worker failures/timeouts/protocol errors into a valid
PreToolUse denial. Failure of THIS outer callback can still fail open in Codex.
No Hook can catch its own non-execution, SIGKILL, or the Host's failure policy.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from ..devpreview.store import append_audit
from . import contracts as c
from .contracts_audit import digest
from .feedback_renderer import render


def run(raw,store,group,phase,*,worker_command=None,timeout=6):
    store=Path(store);event=None;status='UNKNOWN';failure=None;worker_code=None
    try:
        c.require(len(raw)<=1_000_000,'EVENT_TOO_LARGE');event=json.loads(raw)
        c.require(isinstance(event,dict),'INVALID_EVENT')
        c.require(event.get('hook_event_name')==('PreToolUse' if phase=='pre' else 'PostToolUse'),'WRONG_NATIVE_PHASE')
        c.require(event.get('tool_name') in ('apply_patch','Bash','exec_command','bash','shell_command'),'INVALID_NATIVE_TOOL_ENVELOPE')
        command=worker_command or [sys.executable,'-B','-m','clim_agent_guard.experimental.contracts_hook',phase,'--store',str(store),'--group',group]
        result=subprocess.run(command,input=raw,capture_output=True,timeout=timeout);worker_code=result.returncode
        c.require(result.returncode==0,'WORKER_EXIT_FAILURE')
        c.require(len(result.stdout)<=8192,'WORKER_OUTPUT_LIMIT')
        reply=json.loads(result.stdout)
        c.require(isinstance(reply,dict),'WORKER_PROTOCOL_ERROR')
        if phase=='pre':
            c.require(set(reply)<= {'hookSpecificOutput','systemMessage'},'UNSUPPORTED_PRE_FIELDS')
            specific=reply.get('hookSpecificOutput')
            if specific is not None:
                c.require(isinstance(specific,dict) and set(specific)<= {'hookEventName','permissionDecision','permissionDecisionReason'},'WORKER_PROTOCOL_ERROR')
                c.require(specific.get('hookEventName')=='PreToolUse' and specific.get('permissionDecision')=='deny' and
                          isinstance(specific.get('permissionDecisionReason'),str) and 0<len(specific['permissionDecisionReason'])<=300,'WORKER_PROTOCOL_ERROR')
                status='EXPLICIT_DENY_REQUESTED'
            else:
                if event['tool_name']=='apply_patch':
                    # A bare '{}' from a failed/empty worker is NOT proof of a
                    # successful supported Pre; require its committed exact lease.
                    s=c.snapshot(store/'hc01');key=digest([event.get('session_id'),event.get('tool_use_id')]);pending=s['pending'].get(key,{})
                    step=pending.get('step');raw_patch=event.get('tool_input',{}).get('command','')
                    c.require(isinstance(step,dict) and step.get('consumed') is True and
                              step['exact_patch_sha256']==hashlib.sha256(raw_patch.encode()).hexdigest() and
                              step['session_id']==event['session_id'] and step['tool_use_id']==event['tool_use_id'],'ALLOW_WITHOUT_COMMITTED_STEP')
                    status='SUPPORTED_STEP_CHECKED_NOT_ATOMIC'
                else:status='UNCOVERED_TOOL_NOT_ENFORCED'
        else:status='POST_CALLBACK_RETURNED_UNVERIFIED'
    except Exception as error:
        failure=type(error).__name__;reply={}
        known_shell=isinstance(event,dict) and event.get('tool_name') in ('Bash','exec_command','bash','shell_command')
        if phase=='pre' and group!='G0_SHADOW' and not known_shell:
            reply=render('HC01_CALLBACK_UNAVAILABLE')['reply'];status='EXPLICIT_FALLBACK_DENY_REQUESTED_COVERAGE_UNKNOWN'
        else:status='COVERAGE_UNKNOWN_NOT_ENFORCED'
    record={'phase':phase,'status':status,'error_type':failure,'worker_exit':worker_code,
            'session_id':event.get('session_id') if isinstance(event,dict) else None,
            'tool_use_id':event.get('tool_use_id') if isinstance(event,dict) else None,
            'output_digest':digest(reply),'outer_callback_failure_policy':'HOST_DEPENDENT_NOT_CONTROLLED_BY_THIS_WRAPPER'}
    try:append_audit(store,record,'feedback_supervisor.jsonl')
    except OSError:pass
    return reply,record


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['pre','post']);p.add_argument('--store',type=Path,required=True)
    p.add_argument('--group',choices=['G0_SHADOW','G1_STATIC','G2_DYNAMIC'],required=True)
    p.add_argument('--test-worker-command',help='PRIVATE operator-controlled fault injection only; never an agent proposal')
    a=p.parse_args(argv);raw=sys.stdin.buffer.read(1_000_001)
    # Invalid override JSON is also handled by the same fallback path.
    try:worker=json.loads(a.test_worker_command) if a.test_worker_command else None
    except ValueError:worker=['/__CLIM_TEST_NONEXISTENT_WORKER__']
    reply,_=run(raw,a.store,a.group,a.phase,worker_command=worker)
    print(json.dumps(reply,separators=(',',':')));sys.stdout.flush()


if __name__=='__main__':main()
