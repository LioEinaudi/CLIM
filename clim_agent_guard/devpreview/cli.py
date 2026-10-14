"""`clim` developer-preview CLI. Safe config merging; no automatic hook trust."""
from __future__ import annotations
import argparse
import contextlib
import io
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
from .store import atomic_write, base_dir, config_at, locked, project_store, read_json
from .policy import defaults, rel_target

TAG='CLIM Developer Preview v0.2'
MATCHER='^(apply_patch|Bash|exec_command|bash|shell_command)$'


def _root(raw: str) -> Path:
    path=Path(raw).expanduser().resolve(strict=True)
    if not path.is_dir(): raise ValueError('Project must be a directory')
    return path


def _hooks_obj(root: Path):
    path=root/'.codex'/'hooks.json'
    if not path.exists(): return {'hooks':{}},None
    raw=path.read_bytes()
    value=json.loads(raw)
    if not isinstance(value,dict) or not isinstance(value.get('hooks',{}),dict):
        raise ValueError('Existing Codex hooks.json must contain a hooks object')
    return value,raw


def _own_hook(item):
    return isinstance(item,dict) and item.get('type')=='command' and TAG in item.get('statusMessage','') and '-m clim_agent_guard.devpreview.hook' in item.get('command','')


def _remove_owned(doc:dict)->dict:
    for stage, groups in list(doc.get('hooks',{}).items()):
        remaining=[]
        for group in groups:
            if not isinstance(group,dict):
                remaining.append(group); continue
            other=[h for h in group.get('hooks',[]) if not _own_hook(h)]
            if other:
                remaining.append({**group,'hooks':other})
        if remaining: doc['hooks'][stage]=remaining
        else: doc['hooks'].pop(stage,None)
    return doc


def _write_hooks(path:Path,data:dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    atomic_write(path,data)


def cmd_init(args):
    root=_root(args.project)
    store=project_store(root)
    hooks_path=root/'.codex'/'hooks.json'
    if store.is_relative_to(root): raise ValueError('CLIM_HOME must not be inside project')
    with locked(store):
        info=read_json(store/'install.json')
        if info is not None:
            if hooks_path.exists() and TAG in hooks_path.read_text(encoding='utf-8'):
                print(f'Already installed: {root}'); return
            raise ValueError('Install record exists but hook was modified; inspect before reinstall')
        hooks,old=_hooks_obj(root)
        hooks=_remove_owned(hooks)
        old_hash=hashlib.sha256(old).hexdigest() if old is not None else None
        for stage,phase in [('PreToolUse','pre'),('PostToolUse','post')]:
            command=shlex.join([sys.executable,'-m','clim_agent_guard.devpreview.hook',phase,
                                '--store',str(store)])
            entry={'matcher':MATCHER,'hooks':[{'type':'command','command':command,
                'timeout':15,'statusMessage':TAG+' '+phase}]}
            hooks.setdefault('hooks',{}).setdefault(stage,[]).append(entry)
        policy=defaults(root)
        atomic_write(store/'policy.json',policy)
        atomic_write(store/'pending.json',{})
        atomic_write(store/'install.json',{'project_root':str(root),
            'original_hooks_present':old is not None,'original_hooks_hash':old_hash,
            'original_hooks_bytes':old.decode('utf-8') if old is not None else None})
        _write_hooks(hooks_path,hooks)
    print('CLIM installed for Codex (mode: shadow).')
    print('Project: '+str(root))
    print('Policy: '+str(store/'policy.json'))
    print('Next: launch Codex, open /hooks and explicitly review/trust both project hooks.')
    print('Then run: clim doctor --project '+shlex.quote(str(root)))
    if not shutil.which('codex'): print('WARNING: codex CLI not found in current PATH')
    print('WARNING: same-user policy/ledger are NOT an OS security boundary.')


def cmd_mode(args):
    root=_root(args.project); store=project_store(root)
    with locked(store):
        policy=config_at(store)
        if policy['mode']==args.mode:
            print('Already in '+args.mode+' mode'); return
        policy['mode']=args.mode
        policy['_version']+=1
        atomic_write(store/'policy.json',policy)
    print('Mode: '+args.mode)
    if args.mode=='ask': print('Codex PreToolUse has no native ask. CLIM denies until explicit `clim permit-once`.')


def _edit_policy(args,op):
    root=_root(args.project); store=project_store(root)
    with locked(store):
        p=config_at(store)
        paths=[rel_target(root, t) if not any(x in t for x in '*?[') else t for t in args.paths]
        if op=='protect':
            for path in paths:
                if path not in p['protected']:p['protected'].append(path)
        elif op=='allow':
            for path in paths:
                if path not in p['explicit_overrides']:p['explicit_overrides'].append(path)
        p['_version']+=1
        atomic_write(store/'policy.json',p)
    print(f'Updated {op} paths: '+', '.join(paths))
    if op=='allow': print('Warning: persistent override to default protection; review with clim doctor.')


def cmd_permit(args):
    root=_root(args.project);store=project_store(root)
    if args.command is not None:
        identity='shell:'+hashlib.sha256(args.command.encode()).hexdigest()
    else:
        if not args.paths: raise ValueError('Provide --path or --command')
        paths=sorted(set(rel_target(root,x) for x in args.paths))
        identity='patch:'+','.join(paths)
    with locked(store):
        config_at(store)
        grants=read_json(store/'one_time.json',{})
        grants[identity]=grants.get(identity,0)+1
        atomic_write(store/'one_time.json',grants)
    print('One-use approval recorded for the exact '+('command' if args.command else 'patch target set')+'.')
    print('This does not grant tool/OS permissions beyond CLIM; only future matched calls consume it.')


def cmd_doctor(args):
    root=_root(args.project);store=project_store(root)
    result={'project':str(root),'store':str(store),'mode':None,'checks':{},'warnings':[]}
    try:
        policy=config_at(store);result['mode']=policy['mode']
        result['checks']['external_policy_location']=not store.is_relative_to(root)
        result['checks']['protected_patterns_present']=bool(policy['protected'])
        result['checks']['policy_consistent']=policy.get('project_root')==str(root)
    except (ValueError,FileNotFoundError) as e:
        result['warnings'].append(str(e))
    try:
        hooks,_=_hooks_obj(root)
        for stage in ('PreToolUse','PostToolUse'):
            result['checks'][stage+'_registered']=any(_own_hook(h) for g in hooks.get('hooks',{}).get(stage,[]) for h in g.get('hooks',[]))
    except (ValueError,json.JSONDecodeError) as e:
        result['warnings'].append('Malformed Codex hooks: '+str(e))
    pending=read_json(store/'pending.json',{})
    from .shadow import gaps_for_pending, last_window_gaps
    result['coverage_gaps']=gaps_for_pending(store)
    result['last_window_coverage_gaps']=last_window_gaps(store)
    result['shadow_observation']={k:policy.get(k) for k in ('shadow_inventory','shadow_authorized','shadow_required')} if result['mode'] else {}
    result['checks']['no_unverified_pending']=not bool(pending)
    result['checks']['no_incident']=not (store/'incident.json').exists()
    result['checks']['codex_on_path']=bool(shutil.which('codex'))
    result['warnings']+= [
        'Hook trust cannot be determined by this CLI. Inspect /hooks in Codex.',
        'Same-user state storage is not tamper-resistant if the agent can execute arbitrary same-user code.',
        'Coverage: matched apply_patch and shell names ONLY; no OS-level or other-tool coverage.',
        'Shell commands allowed by exception have no tool-specific effect verification.',
    ]
    if result['mode']=='shadow': result['warnings'].append('SHADOW does not block any tool calls.')
    if result['mode']=='ask': result['warnings'].append('ASK is deny-and-manual-retry, not a native Codex approval dialog.')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if not all(v for k,v in result['checks'].items() if k!='codex_on_path'):
        return 2
    return 0


def cmd_report(args):
    root=_root(args.project);store=project_store(root)
    path=store/'events.jsonl'
    events=[]
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            try:
                e=json.loads(line)
                if args.today and datetime.fromisoformat(e['timestamp']).astimezone().date()!=datetime.now().astimezone().date():continue
                events.append(e)
            except (ValueError,KeyError):continue
    stats={k:sum(1 for e in events if e.get('decision')==k) for k in ('BLOCK','ALLOW','WOULD_BLOCK','WOULD_ALLOW','RECONCILIATION_ACKNOWLEDGED','OBSERVED','UNKNOWN','ALLOW_UNVERIFIED')}
    from .shadow import gaps_for_pending
    print(json.dumps({'schema':'clim-developer-report/v0.2.1','events':len(events),'counts':stats,
        'coverage_gaps':gaps_for_pending(store),'redaction_applied':True,
        'retention':'Until explicit uninstall --purge-state; existing legacy logs are not rewritten.',
        'recent':events[-min(args.limit,50):]},indent=2,ensure_ascii=False))


def cmd_observe(args):
    """Register external host truth; never derive authority from agent proposals."""
    from .shadow import names
    root=_root(args.project);store=project_store(root)
    def load_paths(path):
        if path is None:return None
        file=Path(path).resolve(strict=True)
        if file.is_relative_to(root):raise ValueError('Observation/authority inputs must be outside the agent project')
        raw=json.loads(file.read_text());raw=raw.get('paths') if isinstance(raw,dict) else raw
        if not isinstance(raw,list) or len(raw)>10000:raise ValueError('Expected at most 10000 registered paths')
        return sorted(set(names(root,p) for p in raw))
    with locked(store):
        policy=config_at(store)
        policy.update(shadow_inventory=load_paths(args.inventory),shadow_authorized=load_paths(args.authorized),
                      shadow_required=load_paths(args.required))
        policy['_version']+=1
        atomic_write(store/'policy.json',policy)
    print('Host Shadow observation registered. Authority is independent of tool proposals; Shadow does not enforce it.')


def cmd_reconcile(args):
    root=_root(args.project);store=project_store(root)
    if not args.acknowledge:
        raise ValueError('Explicit --acknowledge required; inspect affected files and audit first')
    with locked(store):
        pending=read_json(store/'pending.json',{})
        incident=read_json(store/'incident.json')
        if pending or incident:
            from .store import append_audit
            append_audit(store,{'phase':'OPERATOR','decision':'RECONCILIATION_ACKNOWLEDGED',
                'note':'Operator confirmed current filesystem inspected; no retrospective effect verification claimed.'})
            atomic_write(store/'pending.json',{})
            (store/'incident.json').unlink(missing_ok=True)
    print('Pending/incident markers acknowledged; earlier unverified effects remain in audit.')


def cmd_uninstall(args):
    root=_root(args.project);store=project_store(root);hooks_path=root/'.codex'/'hooks.json'
    with locked(store):
        info=read_json(store/'install.json')
        if info is None: raise ValueError('No CLIM install record; will not modify hooks')
        hooks,_=_hooks_obj(root)
        _remove_owned(hooks)
        original=info.get('original_hooks_bytes')
        # Restore original bytes exactly if no other hooks changed; else preserve new hooks.
        originally= json.loads(original) if original is not None else {'hooks':{}}
        if hooks==originally:
            if original is None:
                hooks_path.unlink(missing_ok=True)
                try:hooks_path.parent.rmdir()
                except OSError:pass
            else:
                hooks_path.write_bytes(original.encode())
        else:
            _write_hooks(hooks_path,hooks)
        (store/'install.json').unlink()
        if args.purge_state:
            # Require explicit opt-in; do not delete unrelated files in store.
            allowed_files={'policy.json','ledger.json','pending.json','one_time.json',
                           'events.jsonl','hook_events.jsonl','incident.json'}
            for p in store.iterdir():
                if p.is_file() and not p.is_symlink() and p.name in allowed_files:
                    p.unlink()
    if args.purge_state:
        try:
            (store/'.lock').unlink()
            store.rmdir()
        except OSError:
            # Keep non-CLIM files. Never recursively remove unknown material.
            pass
    print('CLIM Codex hooks removed. Third-party hooks retained.')
    print('Local policy/evidence '+('purged by request' if args.purge_state else f'retained at {store}'))


def cmd_demo(args):
    """Non-Codex transport self-test in an ephemeral fixture; never touches user work."""
    import tempfile
    from .hook import pre, post
    with tempfile.TemporaryDirectory(prefix='clim-v02-demo-') as tmp:
        base=Path(tmp)
        project=base/'project';project.mkdir()
        (project/'src').mkdir()
        for name in ('src/a.py','src/b.py','config.prod.json'):
            (project/name).write_text('old\n')
        original_home=os.environ.get('CLIM_HOME')
        os.environ['CLIM_HOME']=str(base/'state')
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cmd_init(argparse.Namespace(project=str(project)))
                cmd_mode(argparse.Namespace(project=str(project),mode='guarded'))
            store=project_store(project)
            def event(stage,command,tool_use_id):
                return {'hook_event_name':stage,'cwd':str(project),'session_id':'demo',
                        'tool_use_id':tool_use_id,'tool_name':'apply_patch',
                        'tool_input':{'command':command}}
            bad='*** Begin Patch\n*** Update File: config.prod.json\n@@\n-old\n+new\n*** End Patch'
            denied=pre(event('PreToolUse',bad,'one'),store)
            safe='*** Begin Patch\n*** Update File: src/a.py\n@@\n-old\n+new\n*** Update File: src/b.py\n@@\n-old\n+new\n*** End Patch'
            allowed=pre(event('PreToolUse',safe,'two'),store)
            (project/'src/a.py').write_text('new\n')
            (project/'src/b.py').write_text('new\n')
            verified=post(event('PostToolUse',safe,'two'),store)
            print(json.dumps({'type':'SIMULATED_HOOK_TRANSPORT_NOT_REAL_CODEX',
                'guarded_production_denied':denied.get('hookSpecificOutput',{}).get('permissionDecision')=='deny',
                'authorized_multifile_allowed':allowed=={},
                'effects_verified':'EFFECT_VERIFIED' in verified.get('systemMessage',''),
                'production_file_unchanged':(project/'config.prod.json').read_text()=='old\n'},indent=2))
        finally:
            if original_home is None:os.environ.pop('CLIM_HOME',None)
            else:os.environ['CLIM_HOME']=original_home

def main(argv=None):
    p=argparse.ArgumentParser(prog='clim',description='CLIM Developer Preview v0.2 (Codex native-hook pilot)')
    sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('demo')
    init=sub.add_parser('init');init.add_argument('client',choices=['codex']);init.add_argument('--project',default='.')
    un=sub.add_parser('uninstall');un.add_argument('--project',default='.');un.add_argument('--purge-state',action='store_true')
    doc=sub.add_parser('doctor');doc.add_argument('--project',default='.')
    mod=sub.add_parser('mode');mod.add_argument('mode',choices=['shadow','ask','guarded']);mod.add_argument('--project',default='.')
    report=sub.add_parser('report');report.add_argument('--project',default='.');report.add_argument('--today',action='store_true');report.add_argument('--limit',type=int,default=20)
    prot=sub.add_parser('protect');prot.add_argument('paths',nargs='+');prot.add_argument('--project',default='.')
    allow=sub.add_parser('allow');allow.add_argument('paths',nargs='+');allow.add_argument('--project',default='.')
    permit=sub.add_parser('permit-once');permit.add_argument('--path',action='append',dest='paths');permit.add_argument('--command');permit.add_argument('--project',default='.')
    rec=sub.add_parser('reconcile');rec.add_argument('--project',default='.');rec.add_argument('--acknowledge',action='store_true')
    obs=sub.add_parser('observe');obs.add_argument('--project',default='.')
    obs.add_argument('--inventory',required=True);obs.add_argument('--authorized');obs.add_argument('--required')
    args=p.parse_args(argv)
    try:
        if args.cmd=='demo':cmd_demo(args)
        elif args.cmd=='init':cmd_init(args)
        elif args.cmd=='uninstall':cmd_uninstall(args)
        elif args.cmd=='observe':cmd_observe(args)
        elif args.cmd=='doctor':return cmd_doctor(args)
        elif args.cmd=='mode':cmd_mode(args)
        elif args.cmd=='report':cmd_report(args)
        elif args.cmd=='protect':_edit_policy(args,'protect')
        elif args.cmd=='allow':_edit_policy(args,'allow')
        elif args.cmd=='permit-once':cmd_permit(args)
        elif args.cmd=='reconcile':cmd_reconcile(args)
    except (ValueError,OSError,json.JSONDecodeError) as e:
        p.exit(2,'CLIM error: '+str(e)+'\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
