#!/usr/bin/env python3
"""Read-only-vs-source, disposable-fixture checks of known v0.2 Shadow gaps.

Usage: python v02_baseline_probe.py --source /path/to/extracted/v02/source
Synthetic Hook transport only; does not launch Codex. All files under tempfile.
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(src):
    src=Path(src).resolve()
    if not (src/'clim_agent_guard/devpreview/hook.py').is_file():
        raise FileNotFoundError('v0.2 source missing')
    sys.path.insert(0, str(src))
    from clim_agent_guard.devpreview.cli import main as cli
    from clim_agent_guard.devpreview.hook import _classify, pre, post
    from clim_agent_guard.devpreview.policy import defaults, monitored_paths
    from clim_agent_guard.devpreview.store import project_store, read_json
    with tempfile.TemporaryDirectory(prefix='clim-shadow-v02-probe-') as td:
        p=Path(td); project=p/'project'; project.mkdir(); (project/'src').mkdir()
        for x in ['config.prod.json','src/a.py','src/b.py','src/c.py']:
            (project/x).write_text('before')
        os.environ['CLIM_HOME']=str(p/'state')
        with contextlib.redirect_stdout(io.StringIO()):cli(['init','codex','--project',str(project)])
        state=project_store(project)
        def patch(*paths, canary=None):
            lines=['*** Begin Patch']
            for v in paths:lines.extend(['*** Update File: '+v,'@@','-before','+'+(canary or 'after')])
            return '\n'.join(lines+['*** End Patch'])
        def ev(phase,use,cmd):
            return {'hook_event_name':phase,'session_id':'s1','tool_use_id':use,
                    'cwd':str(project),'tool_name':'apply_patch','tool_input':{'command':cmd}}
        # S2: protected target is proposed and changed; legacy residual says unauthorized_changed_paths=[]
        cmd=patch('config.prod.json')
        assert pre(ev('PreToolUse','s2',cmd),state)=={}
        (project/'config.prod.json').write_text('after')
        assert post(ev('PostToolUse','s2',cmd),state)=={}
        evt=[json.loads(x) for x in (state/'events.jsonl').read_text().splitlines()]
        s2=evt[-1]['effect']
        # S5: ordinary undeclared third file omitted from watch inventory.
        names, complete=monitored_paths(project,read_json(state/'policy.json'), ['src/a.py','src/b.py'])
        # S3: symlink target becomes uninspectable without explicit target fields.
        external=p/'outside_dummy.txt';external.write_text('placeholder')
        (project/'src/link.py').symlink_to(external)
        kind,paths,authorized,code=_classify(ev('PreToolUse','s3',patch('src/link.py')),
                                              project,read_json(state/'policy.json'))
        # S6: missing PostHook leaves pending, but no actual coverage-gap event is generated.
        pre(ev('PreToolUse','s6',patch('src/a.py')),state)
        evt=[json.loads(x) for x in (state/'events.jsonl').read_text().splitlines()]
        pending=read_json(state/'pending.json',{})
        # S8: actual Hook main writes raw input; canary is synthetic.
        canary='CLIM_SYNTHETIC_CANARY_V02_PRIVACY_9C8A'
        shell={'hook_event_name':'PreToolUse','session_id':'s2','tool_use_id':'s8',
               'cwd':str(project),'tool_name':'Bash','tool_input':{'command':'echo '+canary}}
        env=os.environ.copy();env['PYTHONPATH']=str(src)+os.pathsep+env.get('PYTHONPATH','')
        cmdline=[sys.executable,'-m','clim_agent_guard.devpreview.hook','pre','--store',str(state)]
        completed=subprocess.run(cmdline,input=json.dumps(shell),text=True,capture_output=True,env=env,timeout=15)
        assert completed.returncode==0,completed.stderr
        leaked=canary in (state/'hook_events.jsonl').read_text()
        # S10: protected-list coverage flag on >MAX_TRACKED files
        for k in range(270):(project / f'coverage_{k:03d}.key').write_bytes(b'')
        _,complete_large=monitored_paths(project,read_json(state/'policy.json'), ['src/a.py'])
        return {'type':'LOCAL_SYNTHETIC_V02_BASELINE_GAP_PROBE_NOT_CODEX',
                'source_package':'archived_v02_source',
                'archive_integration_validation_separate':True,
                'S2_policy_would_block':evt[0]['decision']=='WOULD_BLOCK',
                'S2_effect_observed': 'config.prod.json' in s2['changed_paths'],
                'S2_legacy_unauthorized_changed_paths_empty':s2['unauthorized_changed_paths']==[],
                'S3_symlink_classified_uninspectable_without_paths':not paths and code.startswith('UNINSPECTABLE_PATCH'),
                'S5_third_ordinary_file_not_watched':'src/c.py' not in names,
                'S6_unpaired_pending_remains':bool(pending),
                'S6_explicit_missing_post_gap_event_present':any(e.get('code')=='MISSING_POST' for e in evt),
                'S8_canary_in_v02_raw_hook_events':leaked,
                'S10_v02_monitor_limit_disclosed_by_internal_flag':not complete_large,
                'warning':'These are known v0.2 baseline gaps, not v0.2.1 live acceptance outcomes.'}


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--out')
    a=ap.parse_args();result=run(a.source)
    val=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.out:Path(a.out).write_text(val)
    else:print(val)
