"""Operator-facing M1 opt-in CLI; no hook mutations or protection claims."""
from __future__ import annotations
import argparse
import json
import os
import sqlite3
from pathlib import Path
import sys
from .scope import ContractError, require, scope_patterns, contains, intersects
from .service import ContractRuntime, template
from .storage import SQLiteEvidenceSink
from .differential import LiveShadowDifferential, render_card
from ..devpreview.store import project_store


def runtime(args):
    root=Path(args.project).expanduser().resolve(strict=True)
    storage=project_store(root)/'contract_runtime'
    return ContractRuntime(root,SQLiteEvidenceSink(storage/'ledger.sqlite3')),storage

def _load(path):
    obj=json.loads(Path(path).expanduser().read_text(encoding='utf-8'))
    require(isinstance(obj,dict),'INVALID_JSON_OBJECT')
    return obj

def _operator_cap(storage:Path):
    path=storage/'operator-capability.txt'
    require(path.is_file() and not path.is_symlink(),'OPERATOR_CAPABILITY_REQUIRED')
    return path.read_text(encoding='utf-8').strip()

def _emit(obj):print(json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=False))

def handle(args)->int:
    try:
        action=args.contract_action
        if action=='codex-hook':
            from .codex_setup import configure
            _emit(configure(Path(args.project),action=args.operation,dry_run=args.dry_run,
                            enable_feedback=getattr(args,'enable_feedback',False),
                            enable_enforcement=getattr(args,'enable_enforcement',False)))
            return 0
        if action=='doctor':
            from .doctor import contract_doctor
            _emit(contract_doctor(Path(args.project), stale_seconds=args.stale_seconds))
            return 0
        if action=='enforcement-summary':
            from .enforcement import enforcement_summary
            rt, _ = runtime(args)
            _emit(enforcement_summary(rt.sink,limit=args.limit))
            return 0
        if action=='enforcement-verify':
            from .enforcement import verify_enforcement
            rt, _ = runtime(args)
            _emit(verify_enforcement(rt.sink))
            return 0
        if action=='advisory-summary':
            from .advisory import advisory_summary
            rt, _ = runtime(args)
            _emit(advisory_summary(rt.sink, args.limit))
            return 0
        if action=='template':
            doc=template(args.template,args.module)
            _emit({'template':args.template,**doc,'authority':'CANDIDATE_ONLY'})
            return 0
        rt,storage=runtime(args)
        if action=='bootstrap':
            require(args.acknowledge_scope,'EXPLICIT_OPERATOR_ACKNOWLEDGEMENT_REQUIRED')
            scope=scope_patterns([args.scope])[0]
            plan=template(args.template,args.module)
            require(any(contains(a,scope) for a in plan['allowed']),
                    'BOOTSTRAP_SCOPE_OUTSIDE_ROOT')
            require(not any(intersects(scope,d) for d in plan['denied']),
                    'BOOTSTRAP_SCOPE_INTERSECTS_DENY')
            cap=rt.initialize(task_id=args.task_id,allowed=plan['allowed'],denied=plan['denied'],
                              stages={'work':{'max_allowed':[scope],'predecessors':[]}},
                              ttl_seconds=args.ttl)
            capfile=storage/'operator-capability.txt'
            fd=os.open(str(capfile),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                f.write(cap+'\n');f.flush();os.fsync(f.fileno())
            proposal={'contract_id':'CLIM_BOOTSTRAP_1','parent_id':'ROOT',
                      'stage_id':'work','allowed':[scope]}
            rt.propose(proposal)
            active=rt.activate('CLIM_BOOTSTRAP_1',cap)
            _emit({'initialized':True,'active_contract':active['contract_id'],
                   'active_scope':[scope],'project':str(rt.project),
                   'operator_capability_file':str(capfile),
                   'enforced':False,'hook_config_changed':False,
                   'warning':'Operator explicitly registered local scope; same-UID token is not independently trusted.'})
        elif action=='init':
            require(args.acknowledge_scope,'EXPLICIT_OPERATOR_ACKNOWLEDGEMENT_REQUIRED')
            if args.file:
                spec=_load(args.file)
                require(spec.get('schema') in ('clim-contract-spec/v1',None),'INVALID_SPEC_SCHEMA')
                allowed=spec['allowed'];denied=spec['denied'];stages=spec['stages'];task=spec['task_id']
            else:
                plan=template(args.template,args.module)
                allowed=plan['allowed'];denied=plan['denied'];task=args.task_id
                stages={'work':{'max_allowed':allowed,'predecessors':[]}}
            cap=rt.initialize(task_id=task,allowed=allowed,denied=denied,stages=stages,
                              ttl_seconds=args.ttl)
            capfile=storage/'operator-capability.txt'
            fd=os.open(str(capfile),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(cap+'\n');f.flush();os.fsync(f.fileno())
            _emit({'initialized':True,'project':str(rt.project),'storage':str(storage),
                   'status':'OBSERVE_ONLY_M1','operator_capability_file':str(capfile),
                   'warning':'Same-user capability is NOT independent authorization; no Host hooks changed.'})
        elif action=='status':_emit(rt.status())
        elif action=='validate':_emit(rt.validate(_load(args.file)))
        elif action=='propose':_emit(rt.propose(_load(args.file)))
        elif action=='activate':_emit(rt.activate(args.contract_id,_operator_cap(storage),args.session))
        elif action=='finish-stage':_emit(rt.finish_stage(_operator_cap(storage),args.output or []))
        elif action=='verify':_emit(rt.sink.verify())
        elif action=='recover':_emit(rt.recover())
        elif action=='history':_emit(rt.history(args.limit))
        elif action=='observe-pre':
            _emit(LiveShadowDifferential(rt).pre(window_id=args.window_id, session_id=args.session_id,
                tool_use_id=args.tool_use_id, targets=args.target, watch=args.watch,
                tool_kind=args.tool_kind))
        elif action=='observe-post':
            _emit(LiveShadowDifferential(rt).post(window_id=args.window_id))
        elif action=='shadow-verify':_emit(LiveShadowDifferential(rt).verify())
        elif action=='watch':
            from .live_watch import watch
            watch(LiveShadowDifferential(rt),interval=args.interval,limit=args.limit,
                  fmt=args.format,once=args.once,max_polls=args.max_polls)
        elif action=='shadow-report':
            report=LiveShadowDifferential(rt).report(args.limit)
            if args.format=='card':print(render_card(report))
            else:_emit(report)
        elif action=='export':
            data=rt.export_spec()
            if args.output:
                target=Path(args.output).expanduser()
                with target.open('x',encoding='utf-8') as f:
                    json.dump(data,f,indent=2,sort_keys=True,ensure_ascii=False);f.write('\n')
                _emit({'exported':str(target),'authority':'UNSIGNED_TEMPLATE_ONLY'})
            else:_emit(data)
        else:raise ContractError('UNKNOWN_CONTRACT_COMMAND')
        return 0
    except sqlite3.Error:
        print('CLIM contract error: SQLITE_STORAGE_ERROR',file=sys.stderr)
        return 2
    except (ContractError,KeyError,ValueError,OSError,json.JSONDecodeError) as e:
        print('CLIM contract error: '+str(e),file=sys.stderr)
        return 2


def add_parser(sub):
    root=sub.add_parser('contract',help='M1 opt-in contract runtime (no Hook enforcement)')
    cs=root.add_subparsers(dest='contract_action',required=True)
    def shared(cmd):cmd.add_argument('--project',default='.')
    p=cs.add_parser('template');p.add_argument('template',choices=['code-only','single-module','sensitive-paths-review']);p.add_argument('--module')
    p=cs.add_parser('bootstrap',help='operator-confirmed local scope and one active work stage')
    shared(p);p.add_argument('--template',default='code-only',choices=['code-only','single-module','sensitive-paths-review'])
    p.add_argument('--module');p.add_argument('--scope',required=True)
    p.add_argument('--task-id',default='local-task');p.add_argument('--ttl',type=int,default=3600)
    p.add_argument('--acknowledge-scope',action='store_true')
    p=cs.add_parser('init');shared(p)
    p.add_argument('--task-id',default='local-task');p.add_argument('--template',default='code-only',choices=['code-only','single-module','sensitive-paths-review'])
    p.add_argument('--module');p.add_argument('--file');p.add_argument('--ttl',type=int,default=3600)
    p.add_argument('--acknowledge-scope',action='store_true',help='local operator acknowledgement; no OS identity authentication')
    for action in ('status','recover','verify','history','export','validate','propose','activate','finish-stage'):
        q=cs.add_parser(action);shared(q)
        if action in ('validate','propose'):q.add_argument('--file',required=True)
        if action=='activate':q.add_argument('contract_id');q.add_argument('--session')
        if action=='finish-stage':q.add_argument('--output',action='append')
        if action=='export':q.add_argument('--output')
        if action=='history':q.add_argument('--limit',type=int,default=50)
    p=cs.add_parser('observe-pre',help='M2 explicit bounded PRE snapshot; no automatic hook or block')
    shared(p);p.add_argument('--window-id',required=True);p.add_argument('--session-id',required=True)
    p.add_argument('--tool-use-id',required=True);p.add_argument('--target',action='append',required=True)
    p.add_argument('--watch',action='append');p.add_argument('--tool-kind',default='apply_patch',choices=['apply_patch','shell','other'])
    p=cs.add_parser('observe-post',help='M2 bounded POST snapshot')
    shared(p);p.add_argument('--window-id',required=True)
    p=cs.add_parser('shadow-report',help='M2 opt-in bounded differential report')
    shared(p);p.add_argument('--limit',type=int,default=20);p.add_argument('--format',choices=['json','card'],default='card')
    p=cs.add_parser('shadow-verify',help='M2 read-only evidence consistency verification');shared(p)
    p=cs.add_parser('watch',help='M2.1 local incremental terminal evidence stream')
    shared(p);p.add_argument('--limit',type=int,default=20)
    p.add_argument('--interval',type=float,default=0.5)
    p.add_argument('--format',choices=['card','ndjson'],default='card')
    p.add_argument('--once',action='store_true')
    p.add_argument('--max-polls',type=int)
    p=cs.add_parser('doctor',help='read-only Contract Observer configuration and receipt diagnostics')
    shared(p);p.add_argument('--stale-seconds',type=int,default=900)
    p=cs.add_parser('advisory-summary',help='recorded feedback counts; not causal replan claims')
    shared(p);p.add_argument('--limit',type=int,default=2000)
    p=cs.add_parser('enforcement-summary',help='M3-B local decision requests, not Host denial proof')
    shared(p);p.add_argument('--limit',type=int,default=5000)
    p=cs.add_parser('enforcement-verify',help='read-only M3-B event/index cross-check');shared(p)
    p=cs.add_parser('codex-hook',help='install/uninstall opt-in local Codex observer hooks')
    shared(p);p.add_argument('operation',choices=['install','uninstall','status'])
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--enable-feedback',action='store_true',help='model-visible context; never grants/denies tools')
    p.add_argument('--enable-enforcement',action='store_true',help='EXPERIMENTAL PreToolUse deny for known out-of-scope Patch only')
    return root
