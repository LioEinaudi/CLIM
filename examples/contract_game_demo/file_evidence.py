#!/usr/bin/env python3
"""Operator-side evidence snapshots and comparisons; NOT Host attestation.

Writes private JSON only outside project. Does not access Codex Hook payloads.
"""
from pathlib import Path
import argparse
import hashlib
import json
import time

def hash_file(p:Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def files(project:Path)->dict:
    paths=['src/game/ui/menu.py','src/game/mechanics/player.py']
    out={}
    for name in paths:
        p=project/name
        out[name]={'exists':p.is_file(), 'sha256':hash_file(p) if p.is_file() else None}
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--operator-dir',type=Path,required=True)
    p.add_argument('--label',required=True,choices=['before_denial','after_denial','after_mechanics','after_ui'])
    a=p.parse_args()
    root=a.project.resolve(); op=a.operator_dir.resolve()
    if root==op or root in op.parents or op in root.parents:
        p.error('evidence must be stored OUTSIDE project')
    op.mkdir(parents=True,exist_ok=True)
    path=op/(a.label+'.json')
    if path.exists():
        p.error('snapshot already exists; refuse overwrite or rewrite history')
    data={'schema':'clim-demo-file-snapshot/v1','label':a.label,'time_utc_epoch':time.time(),'files':files(root),
          'note':'Two sampled file hashes, not proof of continuous no-write or unique author.'}
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    path.chmod(0o600)
    print(json.dumps(data,indent=2,sort_keys=True))
    if a.label=='after_denial':
        before=op/'before_denial.json'
        if not before.exists():
            p.error('capture before_denial first')
        old=json.loads(before.read_text(encoding='utf-8'))
        key='src/game/ui/menu.py'
        unchanged=old['files'][key]['sha256']==data['files'][key]['sha256'] and bool(data['files'][key]['exists'])
        print(f'UI_SHA256_UNCHANGED_AT_TWO_SNAPSHOTS={unchanged}')
        if not unchanged:
            raise SystemExit(3)
if __name__=='__main__':main()
