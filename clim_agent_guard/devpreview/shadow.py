"""Bounded observational Shadow telemetry. Never authorizes or blocks a tool.

File changes are observations within W, with independent host authority and
explicit gaps. Same-user state, sampling and Git evidence are not an OS boundary.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from datetime import datetime, timezone
from .policy import DEFAULT_DENY, SKIP_DIRS, MAX_TRACKED, MAX_FILE_SIZE, match, parse_patch
from .store import append_audit, atomic_write, read_json


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def names(root, raw):
    """Lexical project identity; preserve symlink spelling for risk observation."""
    root = root.resolve()
    p = Path(raw)
    if p.is_absolute():
        p = p.relative_to(root)
    value = p.as_posix()
    if not value or value == '.' or '..' in p.parts or '\x00' in value:
        raise ValueError('Invalid project resource identity')
    return value


def path_meta(root, name):
    p = root / name
    current = root
    links = []
    try:
        for part in PurePosixPath(name).parts:
            current = current / part
            if current.is_symlink():
                target = current.resolve(strict=False)
                links.append({'at':current.relative_to(root).as_posix(),
                              'target_sha256':digest(os.readlink(current)),
                              'resolved_target_sha256':digest(str(target)),
                              'resolved_inside_root':target.is_relative_to(root)})
        if links:
            return {'kind':'symlink_path', 'links':links, 'coverage':'symlink_effect_unverified'}
        if any(part in SKIP_DIRS for part in PurePosixPath(name).parts[:-1]):
            return {'kind':'skipped', 'coverage':'skipped_dir'}
        try: before = p.stat()
        except FileNotFoundError: return {'kind':'missing', 'coverage':'complete'}
        if not stat.S_ISREG(before.st_mode):
            return {'kind':'special', 'coverage':'not_regular_file'}
        if before.st_mode & 0o444 == 0:
            return {'kind':'file', 'coverage':'unreadable', 'bytes':before.st_size,
                    'error_source':'mode_bits_no_read_permission; root override deliberately unused'}
        if before.st_size > MAX_FILE_SIZE:
            return {'kind':'file', 'coverage':'oversize', 'bytes':before.st_size}
        h = hashlib.sha256()
        with p.open('rb') as f:
            opened = os.fstat(f.fileno())
            total = 0
            while chunk := f.read(128 * 1024):
                total += len(chunk)
                if total > MAX_FILE_SIZE:
                    return {'kind':'file', 'coverage':'oversize', 'bytes':total}
                h.update(chunk)
        after = p.stat()
        token = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        if token(before) != token(opened) or token(before) != token(after) or p.is_symlink():
            return {'kind':'unknown', 'coverage':'race_detected'}
        return {'kind':'file', 'coverage':'complete','bytes':total,'sha256':h.hexdigest()}
    except (OSError,ValueError,RuntimeError):
        return {'kind':'unknown', 'coverage':'unreadable'}


def inventory(root, policy, proposed):
    explicit = policy.get('shadow_inventory')
    gaps = []
    if explicit is None:
        candidates = set()
        for directory, dirs, files in os.walk(root, followlinks=False):
            omitted = [d for d in dirs if d in SKIP_DIRS]
            for d in omitted:
                gaps.append({'reason':'skipped_dir','path':(Path(directory)/d).relative_to(root).as_posix()})
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(directory)/d).is_symlink()]
            for f in files:
                candidates.add((Path(directory)/f).relative_to(root).as_posix())
            if len(candidates) > 10000:
                gaps.append({'reason':'enumeration_limit'}); break
    else:
        candidates = set(explicit)
    candidates.update(proposed or [])
    # Retain declared paths before the ordinary inventory limit; do not hide omissions.
    order = sorted(set(proposed or [])) + sorted(candidates-set(proposed or []))
    watch = order[:MAX_TRACKED]
    omitted = order[MAX_TRACKED:]
    if omitted:
        gaps.append({'reason':'scan_limit', 'omitted_count':len(omitted), 'omitted_paths':omitted})
    return watch, {'selection':'HOST_REGISTERED' if explicit is not None else 'BOUNDED_DISCOVERY',
                   'inventory_count':len(candidates),'sampled_count':len(watch),
                   'max_tracked':MAX_TRACKED,'max_file_bytes':MAX_FILE_SIZE,
                   'gaps':gaps,'outside_inventory':'UNOBSERVED'}


def capture(root, paths):
    return {name:path_meta(root,name) for name in paths}


def git_dirty(root, paths):
    result = {'available':False,'dirty_paths':[],'added_line_sha256':{},'gap':None}
    try:
        proc = subprocess.run(['git','-C',str(root),'diff','--name-only','-z','--no-renames'],
                              capture_output=True,timeout=2,check=True)
        if len(proc.stdout)>1_000_000: raise ValueError('Git output bound')
        dirty = sorted(set(proc.stdout.decode(errors='strict').split('\x00'))-{''})
        result.update(available=True,dirty_paths=dirty,status_sha256=digest(proc.stdout))
        for name in sorted(set(paths)&set(dirty)):
            proc = subprocess.run(['git','-C',str(root),'diff','--no-ext-diff','--no-textconv',
                                   '--unified=0','--',name],capture_output=True,timeout=2,check=True)
            if len(proc.stdout)>MAX_FILE_SIZE:raise ValueError('Git diff bound')
            result['added_line_sha256'][name] = sorted(set(digest(line[1:]) for line in proc.stdout.splitlines()
                   if line.startswith(b'+') and not line.startswith(b'+++')))
        return result
    except (OSError,ValueError,subprocess.SubprocessError):
        result['gap']='git_baseline_unavailable';return result


def risk(command):
    if not isinstance(command,str):return []
    rules = {'recursive_delete':r'\brm\s+[^\n]*-[^\s]*[rf]',
             'in_place_edit':r'\bsed\s+[^\n]*-i',
             'output_redirect':r'(?<![>])>{1,2}(?![>])',
             'remote_script_pipeline':r'\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b'}
    return sorted(name for name,pattern in rules.items() if re.search(pattern,command))


def proposal(event, root, policy):
    tool = str(event.get('tool_name',''))
    raw = event.get('tool_input')
    command = raw.get('command',raw.get('cmd')) if isinstance(raw,dict) else None
    paths, gaps = None, []
    if tool == 'apply_patch':
        try:paths=sorted(set(names(root,p) for p in parse_patch(command)))
        except (ValueError,OSError):gaps.append({'reason':'uninspectable_patch'})
    elif tool in ('Bash','exec_command','bash','shell_command'):
        gaps.append({'reason':'unwatched_tool','detail':'Shell resource semantics are not parsed'})
    else:gaps.append({'reason':'unwatched_tool'})
    rejected = [p for p in paths or [] if match(p,policy['protected']) and not match(p,policy.get('explicit_overrides',[]))]
    return {'tool':tool,'E_proposed':paths,'policy_would_block':bool(rejected) or paths is None,
            'protected_proposed':rejected,'risk_signals':risk(command), 'proposal_gaps':gaps,
            'command_sha256':digest(command) if isinstance(command,str) else None}


def prepare(event, root, store, policy, key):
    p = proposal(event,root,policy)
    watch, coverage = inventory(root,policy,p['E_proposed'])
    before = capture(root,watch)
    if any(before.get(t,{}).get('kind')=='symlink_path' for t in p['E_proposed'] or []):
        p['policy_would_block']=True
    coverage['gaps'] += p['proposal_gaps']
    for name, meta in before.items():
        if meta['coverage']!='complete':coverage['gaps'].append({'reason':meta['coverage'],'path':name})
    authority = policy.get('shadow_authorized')
    required = policy.get('shadow_required')
    baseline = git_dirty(root,watch)
    signals = []
    dirty_touched = sorted(set(p['E_proposed'] or []) & set(baseline['dirty_paths']))
    if dirty_touched:signals.append('PREEXISTING_DIRTY_FILE_TOUCHED')
    if any(m['kind']=='symlink_path' for m in before.values()): signals += ['SYMLINK_TARGET_RISK','SYMLINK_EFFECT_UNVERIFIED']
    if p['risk_signals']:signals.append('RISK_SIGNAL')
    entry = {'schema':'clim-shadow-window/v0.2.1','mode':'shadow','session_id':event['session_id'],
             'tool_use_id':event['tool_use_id'],'started_at':datetime.now(timezone.utc).isoformat(),
             'policy_version':policy['_version'],'E_proposed':p['E_proposed'],
             'E_authorized':authority,'E_required':required,'authority_source':'HOST_POLICY' if authority is not None else 'AUTHORITY_UNKNOWN',
             'before':before,'W':coverage,'git_baseline':baseline,'signals':signals,
             'dirty_touched':dirty_touched,'proposal':p,'awaiting':'PostToolUse'}
    pending=read_json(store/'pending.json',{})
    pending[key]=entry
    atomic_write(store/'pending.json',pending)
    append_audit(store,{'phase':'PRE','mode':'shadow','tool':p['tool'],'session_id':event['session_id'],
                 'tool_use_id':event['tool_use_id'],'decision':'WOULD_BLOCK' if p['policy_would_block'] else 'WOULD_ALLOW',
                 'enforced':False,'targets':p['E_proposed'],'E_proposed':p['E_proposed'],
                 'E_authorized':authority,'E_required':required,'authority_source':entry['authority_source'],
                 'command_sha256':p['command_sha256'],'signals':signals,'risk_signals':p['risk_signals'],
                 'W':coverage,'git_baseline':baseline,'before':before})
    return {}


def finish(event,root,store,policy,key):
    pending=read_json(store/'pending.json',{})
    entry=pending.get(key)
    if entry is None or entry.get('schema')!='clim-shadow-window/v0.2.1':
        append_audit(store,{'phase':'POST','mode':'shadow','decision':'UNKNOWN','enforced':False,
                     'session_id':event['session_id'],'tool_use_id':event['tool_use_id'],
                     'coverage_gaps':[{'reason':'unmatched_pre'}]})
        return {}
    before=entry['before'];after=capture(root,sorted(before))
    known={p for p in before if before[p]['coverage']=='complete' and after[p]['coverage']=='complete'}
    observed=sorted(p for p in known if before[p]!=after[p])
    proposed=entry['E_proposed'];authority=entry['E_authorized'];required=entry['E_required']
    gaps = entry['W']['gaps'].copy()
    for p in before:
        if after[p]['coverage']!='complete':gaps.append({'reason':after[p]['coverage'],'path':p})
        if before[p].get('links')!=after[p].get('links'):
            gaps.append({'reason':'symlink_target_changed','path':p})
    if entry['policy_version']!=policy['_version']:gaps.append({'reason':'policy_changed'})
    signals=entry['signals'].copy()
    if observed:signals.append('EFFECT_OBSERVED')
    protected=sorted(p for p in observed if match(p,policy['protected']))
    if protected:signals.append('PROTECTED_TARGET_CHANGED')
    r_auth=sorted(set(observed)-set(authority)) if authority is not None else None
    if r_auth:signals.append('OUTSIDE_AUTHORIZED_SCOPE')
    if any(g['reason']=='symlink_target_changed' for g in gaps):signals.append('TOCTOU_UNCERTAIN')
    dirty_preserved={}
    for p in entry['dirty_touched']:
        if p not in known:dirty_preserved[p]=None;continue
        try:
            data=(root/p).read_bytes()
            line_hashes={digest(line) for line in data.splitlines()}
            originals=entry['git_baseline']['added_line_sha256'].get(p,[])
            dirty_preserved[p]=set(originals).issubset(line_hashes) if originals else None
            if dirty_preserved[p] is False:signals.append('POSSIBLE_LOST_WORK')
        except OSError:dirty_preserved[p]=None
    effect={'E_proposed':proposed,'E_authorized':authority,'E_required':required,'E_observed':observed,
            'R_proposal':sorted(set(observed)-set(proposed)) if proposed is not None else None,
            'R_authority':r_auth,'R_missing':sorted((set(required)&known)-set(observed)) if required is not None else None,
            'required_effect_unknown_paths':sorted(set(required)-known) if required is not None else None,
            'unauthorized_changed_paths':r_auth,'protected_changed_paths':protected,
            'coverage_gaps':gaps,'W':{**entry['W'],'sampled_paths':sorted(before)},
            'window_start':entry['started_at'],'window_end':datetime.now(timezone.utc).isoformat(),
            'before':before,'after':after,'authority_source':entry['authority_source'],
            'attribution':'ATTRIBUTION_UNCERTAIN','dirty_added_lines_preserved':dirty_preserved,
            'scope_granularity':'file','race_prevention':'NOT_PROVIDED'}
    append_audit(store,{'phase':'POST','mode':'shadow','tool':entry['proposal']['tool'],
                 'session_id':event['session_id'],'tool_use_id':event['tool_use_id'],
                 'decision':'OBSERVED' if observed else 'UNKNOWN' if gaps else 'OBSERVED_NO_CHANGE',
                 'enforced':False,'signals':sorted(set(signals)),'effect':effect})
    del pending[key];atomic_write(store/'pending.json',pending)
    return {}


def gaps_for_pending(store):
    return [{'reason':'missing_post','status':'UNKNOWN','session_id':e.get('session_id'),
             'tool_use_id':e.get('tool_use_id'),'since':e.get('started_at'),
             'note':'PostToolUse has not been observed; not proof of failure or no change.'}
            for e in read_json(store/'pending.json',{}).values() if e.get('mode')=='shadow']


def last_window_gaps(store):
    path=store/'events.jsonl'
    if not path.exists():return []
    last=[]
    for line in path.read_text().splitlines():
        try:event=json.loads(line)
        except ValueError:continue
        if event.get('mode')=='shadow' and event.get('phase')=='POST':
            last=event.get('effect',{}).get('coverage_gaps',event.get('coverage_gaps',[]))
    return last


def transport(event, reply, phase, elapsed_ms):
    """Default transport is an identity/digest record, never private command text."""
    raw=json.dumps(event,sort_keys=True,ensure_ascii=False).encode() if event is not None else b''
    safe={k:event[k] for k in ('hook_event_name','session_id','tool_use_id','turn_id','tool_name') if k in (event or {})}
    command=(event or {}).get('tool_input',{})
    command=command.get('command',command.get('cmd')) if isinstance(command,dict) else None
    safe['tool_input']={'command_sha256':digest(command) if isinstance(command,str) else None,
                        'content_omitted':True}
    response=(event or {}).get('tool_response')
    safe['tool_response']={'sha256':digest(json.dumps(response,sort_keys=True,ensure_ascii=False)),
                           'content_omitted':True} if response is not None else None
    return {'phase':phase,'input':safe,'input_sha256':digest(raw),'output':reply,
            'redaction_applied':True,'scope':'command, patch body, native response and transcript path omitted',
            'processing_ms':elapsed_ms}
