#!/usr/bin/env python3
"""Native acceptance observer. One explicitly registered missing-Post control.

All raw native payloads remain in a private disposable evidence directory.
Snapshots and timings are independent of CLIM. Never writes project files,
rewrites input, or returns a permission decision. The omission is test-only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


def append(path, value):
    with path.open('a', encoding='utf-8') as f:
        os.chmod(path, 0o600)
        f.write(json.dumps(value, ensure_ascii=False)+'\n')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('phase',choices=['pre','post']);p.add_argument('--base',type=Path,required=True)
    p.add_argument('--child-command',required=True);p.add_argument('--oracle',type=Path,required=True)
    a=p.parse_args();base=a.base;plan=json.loads((base/'scenario.json').read_text())
    project=Path(plan['project']);assert not base.resolve().is_relative_to(project.resolve())
    raw=sys.stdin.buffer.read(1_000_001);event=json.loads(raw)
    spec=importlib.util.spec_from_file_location('oracle',a.oracle)
    oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    snap=oracle.capture(str(project),str(base/'inventory.json'))
    append(base/'hook_inputs_private.jsonl',{'phase':a.phase,'input':event})
    marker=base/'suppressed_post.json'
    suppress=(plan['control']=='SUPPRESS_ONE_ADAPTER_POST' and a.phase=='post'
              and event['tool_name']=='apply_patch' and not marker.exists())
    start=time.perf_counter_ns()
    if suppress:
        marker.write_text(json.dumps({'origin':'TEST_CONTROLLER','action':'SUPPRESS_ONE_ADAPTER_POST',
                                      'tool_use_id':event['tool_use_id']})+'\n')
        marker.chmod(0o600);code=0;stdout=b'{}\n';stderr=b''
    else:
        result=subprocess.run(shlex.split(a.child_command),input=raw,capture_output=True)
        code,stdout,stderr=result.returncode,result.stdout,result.stderr
    append(base/'native_windows.jsonl',{'phase':a.phase,'session_id':event['session_id'],
           'tool_use_id':event['tool_use_id'],'tool':event['tool_name'],
           'input_sha256':hashlib.sha256(raw).hexdigest(),'snapshot':snap,
           'clim_invoked':not suppress,'controller_omission':suppress,
           'clim_output':json.loads(stdout),'exit_code':code,
           'child_elapsed_ms':(time.perf_counter_ns()-start)/1e6})
    sys.stdout.buffer.write(stdout);sys.stderr.buffer.write(stderr)
    return code


if __name__=='__main__':raise SystemExit(main())
