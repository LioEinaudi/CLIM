#!/usr/bin/env python3
"""Read-only requested-vs-effective approval-policy audit for CLIM S1-S10 ZIP.
Do NOT modify source receipts or silently rewrite historical policy values.
"""
import argparse
import json
import zipfile
from pathlib import Path


def evaluate(z):
    names=z.namelist()
    requested=[n for n in names if n.endswith('/environment_requested.json')]
    if len(requested)!=1:raise ValueError('Need exactly one environment_requested.json')
    req=json.loads(z.read(requested[0]))
    value=req.get('approval_policy')
    reports=[]
    for name in sorted(n for n in names if n.endswith('/native_permission_contexts.json')):
        contexts=json.loads(z.read(name))
        for i,c in enumerate(contexts):
            actual=c.get('approval_policy')
            reports.append({'run':name.rsplit('/native_permission_contexts.json',1)[0].split('/runs/')[-1],
                 'index':i,'requested':value,'effective':actual,
                 'match':value==actual,'source':'native_permission_contexts.json'})
    if not reports:raise ValueError('No native permission context receipts found')
    return {'requested':value,'n_contexts':len(reports),'matches':sum(x['match'] for x in reports),
            'mismatches':sum(not x['match'] for x in reports),'contexts':reports,
            'conclusion':'EFFECTIVE_POLICY_FROM_NATIVE_RECEIPTS; ORIGIN_OF_MISMATCH_NOT_PROVEN'}


def main():
    a=argparse.ArgumentParser()
    a.add_argument('archive',type=Path)
    a.add_argument('--strict',action='store_true',help='Exit nonzero if requested differs from actual')
    a.add_argument('--output',type=Path)
    args=a.parse_args()
    with zipfile.ZipFile(args.archive) as z:result=evaluate(z)
    output=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.write_text(output,encoding='utf-8')
    else:print(output,end='')
    if args.strict and result['mismatches']:return 2
    return 0


if __name__=='__main__':raise SystemExit(main())
