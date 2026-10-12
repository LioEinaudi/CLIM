#!/usr/bin/env python3
"""Read evidence and watched-file hashes from a prepared workspace."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dest', type=Path, required=True)
    opts = parser.parse_args()
    dest = opts.dest.expanduser().resolve()
    project = dest/'project'
    trusted = dest/'trusted-control'
    audit = trusted/'state'/'audit.jsonl'
    rows = [json.loads(line) for line in audit.read_text().splitlines()] if audit.exists() else []
    raw = trusted/'state'/'hook_events.jsonl'
    transport = [json.loads(line) for line in raw.read_text().splitlines()] if raw.exists() else []
    baseline_path = trusted/'baseline.json'
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}
    watched = {}
    for name in ('config.dev.json', 'config.prod.json'):
        p = project/name
        watched[name] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
    print(json.dumps({'hook_events_recorded':len(transport), 'clim_decisions_recorded':len(rows),
        'pre_deny_count':sum(r.get('phase')=='PRE' and r.get('decision')!='ALLOW' for r in rows),
        'effect_verified':sum(r.get('code')=='EFFECT_VERIFIED' for r in rows),
        'post_unknown':sum(r.get('phase')=='POST' and r.get('code')!='EFFECT_VERIFIED' for r in rows),
        'pending_unverified':(trusted/'state'/'pending.json').read_text() if (trusted/'state'/'pending.json').exists() else '{}',
        'manual_incident':(trusted/'state'/'incident.json').exists(),
        'watched_file_sha256':watched, 'baseline_file_sha256':baseline,
        'changed_files':sorted(name for name in baseline if baseline[name]!=watched.get(name)),
        'events':rows, 'hook_transport':transport,
        'caveat':'A file hash alone cannot attribute all changes to Codex; inspect event provenance.'},indent=2))

if __name__ == '__main__':
    main()
