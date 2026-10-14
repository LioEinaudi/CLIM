#!/usr/bin/env python3
"""Acceptance-only native Hook timing/fault controller; not CLIM enforcement.

Child stdout is passed through. Registered external injections and a proposal-only
remote-script veto are explicitly recorded as test-controller actions.
Never persist raw Hook input, private command bodies or tool responses here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import re
import shlex
import subprocess
import sys
import time


def write(path, value):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('a') as f:f.write(json.dumps(value,sort_keys=True)+'\n')
    p.chmod(0o600)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('phase',choices=['pre','post'])
    ap.add_argument('--store',required=True);ap.add_argument('--controller',required=True)
    ap.add_argument('--child-command')
    a=ap.parse_args();ctl=json.loads(Path(a.controller).read_text())
    raw=sys.stdin.buffer.read(1_000_001);e=json.loads(raw);start=time.perf_counter_ns()
    identity={'phase':a.phase,'session_id':e.get('session_id'),'tool_use_id':e.get('tool_use_id'),
              'tool_name':e.get('tool_name'),'input_sha256':hashlib.sha256(raw).hexdigest()}
    marker=Path(ctl['evidence_dir'])/'controller_once.json'
    flags=json.loads(marker.read_text()) if marker.exists() else {}
    command=(e.get('tool_input') or {}).get('command','')
    suppress=a.phase=='post' and e.get('tool_name')=='apply_patch' and ctl.get('suppress_post_once') and not flags.get('post_suppressed')
    if suppress:
        flags['post_suppressed']=True;stdout=b'{}\n';stderr=b'';code=0
        write(ctl['controller_events'],{**identity,'action':'SUPPRESSED_ADAPTER_POST_CALLBACK','origin':'TEST_CONTROLLER'})
    else:
        child=shlex.split(a.child_command) if a.child_command else [sys.executable,'-m','clim_agent_guard.devpreview.hook',a.phase,'--store',a.store]
        r=subprocess.run(child,input=raw,capture_output=True)
        stdout,stderr,code=r.stdout,r.stderr,r.returncode
    child_ms=(time.perf_counter_ns()-start)/1e6
    if a.phase=='pre' and e.get('tool_name')=='apply_patch' and ctl.get('inject_third_file') and not flags.get('injected'):
        target=Path(ctl['inject_third_file']);assert target.resolve().is_relative_to(Path(ctl['fixture_root']).resolve())
        target.write_text('value = 2\n');flags['injected']=True
        write(ctl['controller_events'],{**identity,'action':'EXTERNAL_INJECTION','path':'src/c.py','origin':'TEST_CONTROLLER','attribution':'ATTRIBUTION_UNCERTAIN'})
    if a.phase=='pre' and e.get('tool_name')=='apply_patch' and ctl.get('switch_link') and not flags.get('link_switched'):
        link=Path(ctl['switch_link']);target=Path(ctl['switch_target'])
        assert link.parent.resolve().is_relative_to(Path(ctl['fixture_root']).resolve())
        assert target.resolve().is_relative_to(Path(ctl['test_parent']).resolve())
        link.unlink();link.symlink_to(target);flags['link_switched']=True
        write(ctl['controller_events'],{**identity,'action':'CONTROLLED_LINK_SWITCH','origin':'TEST_CONTROLLER','attribution':'ATTRIBUTION_UNCERTAIN'})
    reply=json.loads(stdout)
    controller_veto=False
    if a.phase=='pre' and ctl.get('remote_proposal_only') and re.search(r'\b(?:curl|wget)\b',command):
        controller_veto=True
        reply={'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny',
                'permissionDecisionReason':'TEST_CONTROLLER_PROPOSAL_ONLY: remote script execution intentionally disabled.'}}
        write(ctl['controller_events'],{**identity,'action':'TEST_CONTROLLER_DENY','origin':'TEST_CONTROLLER','clim_output':json.loads(stdout)})
    marker.parent.mkdir(parents=True,exist_ok=True);marker.write_text(json.dumps(flags));marker.chmod(0o600)
    write(ctl['latency_path'],{**identity,'elapsed_ms':(time.perf_counter_ns()-start)/1e6,
            'child_elapsed_ms':child_ms,'monotonic_start_ns':start,'rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            'clim_invoked':not suppress,'controller_veto':controller_veto,'clim_output':json.loads(stdout),
            'child_exit':code,'telemetry_stderr_present':bool(stderr)})
    sys.stdout.write(json.dumps(reply)+'\n');sys.stderr.buffer.write(stderr)
    return code

if __name__=='__main__':raise SystemExit(main())
