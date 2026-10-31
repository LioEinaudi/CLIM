import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from clim_agent_guard.devpreview.cli import main
from clim_agent_guard.devpreview.hook import pre, post
from clim_agent_guard.devpreview.policy import parse_patch, rel_target, residual
from clim_agent_guard.devpreview.store import project_store, read_json


def patch_cmd(*names):
    lines=['*** Begin Patch']
    for name in names:
        lines += ['*** Update File: '+name, '@@', '-old', '+new']
    return '\n'.join(lines+['*** End Patch'])


class Preview(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)/'state_home'
        self.proj=Path(self.tmp.name)/'project'
        self.proj.mkdir()
        (self.proj/'src').mkdir()
        for name in ['config.dev.json','config.prod.json','src/a.py','src/b.py','.env']:
            (self.proj/name).write_text('old')
        self.env=patch.dict(os.environ,{'CLIM_HOME':str(self.home)})
        self.env.start();self.addCleanup(self.env.stop)
        self.cmd('init','codex')
        self.store=project_store(self.proj)
    def cmd(self,*args):
        with contextlib.redirect_stdout(io.StringIO()):
            return main([*args,'--project',str(self.proj)])
    def event(self,phase,cmd=None,tool='apply_patch',use='t1'):
        return {'hook_event_name':phase,'session_id':'s1','tool_use_id':use,
                'cwd':str(self.proj),'tool_name':tool,'tool_input':{'command':cmd or patch_cmd('src/a.py')}}
    def mode(self,s):self.cmd('mode',s)

    def test_installer_uninstaller_restores_existing_hooks_exact(self):
        self.cmd('uninstall')
        original=b'{"description":"custom", "hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hello"}]}]}}\n'
        hp=self.proj/'.codex'/'hooks.json';hp.parent.mkdir(exist_ok=True);hp.write_bytes(original)
        self.cmd('init','codex')
        self.assertEqual(hp.read_text().count('CLIM Developer Preview'),2)
        self.cmd('uninstall')
        self.assertEqual(hp.read_bytes(),original)
        self.assertTrue((self.store/'events.jsonl').exists() is False)

    def test_default_shadow_never_denies_protected(self):
        ans=pre(self.event('PreToolUse',patch_cmd('config.prod.json')),self.store)
        self.assertEqual(ans,{})
        (self.proj/'config.prod.json').write_text('changed')
        ans=post(self.event('PostToolUse',patch_cmd('config.prod.json')),self.store)
        self.assertEqual(ans,{})
        audits=(self.store/'events.jsonl').read_text()
        self.assertIn('WOULD_BLOCK',audits)
        self.assertIn('unauthorized_changed_paths',audits)

    def test_guarded_protected_denied(self):
        self.mode('guarded')
        ans=pre(self.event('PreToolUse',patch_cmd('config.prod.json')),self.store)
        self.assertEqual(ans['hookSpecificOutput']['permissionDecision'],'deny')
        self.assertIn('TARGET_NOT_AUTHORIZED',json.dumps(ans))
        self.assertEqual((self.proj/'config.prod.json').read_text(),'old')

    def test_guarded_multifile_allowed_verified(self):
        self.mode('guarded')
        cmd=patch_cmd('src/a.py','src/b.py')
        ans=pre(self.event('PreToolUse',cmd),self.store)
        self.assertEqual(ans,{})
        (self.proj/'src/a.py').write_text('a changed')
        (self.proj/'src/b.py').write_text('b changed')
        answer=post(self.event('PostToolUse',cmd),self.store)
        self.assertIn('EFFECT_VERIFIED',answer['systemMessage'])
        self.assertFalse((self.store/'incident.json').exists())

    def test_multifile_partial_effect_requires_reconciliation(self):
        self.mode('guarded')
        cmd=patch_cmd('src/a.py','src/b.py')
        self.assertEqual(pre(self.event('PreToolUse',cmd),self.store),{})
        (self.proj/'src/a.py').write_text('a changed')
        reply=post(self.event('PostToolUse',cmd),self.store)
        self.assertIn('EXPECTED_CHANGE_MISSING',reply['systemMessage'])
        self.assertTrue((self.store/'incident.json').exists())

    def test_guarded_multifile_atomic_pre_denial(self):
        self.mode('guarded')
        ans=pre(self.event('PreToolUse',patch_cmd('src/a.py','config.prod.json')),self.store)
        self.assertEqual(ans['hookSpecificOutput']['permissionDecision'],'deny')
        self.assertEqual(read_json(self.store/'pending.json'),{})

    def test_post_effect_violation_flags_incident(self):
        self.mode('guarded')
        cmd=patch_cmd('src/a.py')
        pre(self.event('PreToolUse',cmd),self.store)
        (self.proj/'src/a.py').write_text('good')
        (self.proj/'config.prod.json').write_text('bad')
        r=post(self.event('PostToolUse',cmd),self.store)
        self.assertIn('UNKNOWN_EFFECT',r['systemMessage'])
        self.assertTrue((self.store/'incident.json').exists())
        r2=pre(self.event('PreToolUse',cmd,use='t2'),self.store)
        self.assertEqual(r2['hookSpecificOutput']['permissionDecision'],'deny')

    def test_missing_post_requires_reconcile(self):
        self.mode('guarded')
        pre(self.event('PreToolUse'),self.store)
        ans=pre(self.event('PreToolUse',use='t2'),self.store)
        self.assertIn('PENDING_EFFECT',json.dumps(ans))
        self.cmd('reconcile','--acknowledge')
        with contextlib.redirect_stdout(io.StringIO()) as out:
            main(['report','--project',str(self.proj)])
        self.assertEqual(json.loads(out.getvalue())['counts']['RECONCILIATION_ACKNOWLEDGED'],1)
        ans2=pre(self.event('PreToolUse',use='t2'),self.store)
        self.assertEqual(ans2,{})

    def test_shell_deny_except_one_use_grant(self):
        self.mode('guarded')
        command='pytest -q'
        event=self.event('PreToolUse',command,'Bash')
        blocked=pre(event,self.store)
        self.assertEqual(blocked['hookSpecificOutput']['permissionDecision'],'deny')
        self.cmd('permit-once','--command',command)
        self.assertEqual(pre(event,self.store),{})
        again=pre(event,self.store)
        self.assertEqual(again['hookSpecificOutput']['permissionDecision'],'deny')

    def test_ask_mode_denies_until_manual_grant(self):
        self.mode('ask')
        cmd=patch_cmd('config.prod.json')
        self.assertEqual(pre(self.event('PreToolUse',cmd),self.store)['hookSpecificOutput']['permissionDecision'],'deny')
        self.cmd('permit-once','--path','config.prod.json')
        self.assertEqual(pre(self.event('PreToolUse',cmd),self.store),{})
        (self.proj/'config.prod.json').write_text('changed')
        # Since the protected path was explicitly approved once it should verify its change.
        self.assertIn('EFFECT_VERIFIED',post(self.event('PostToolUse',cmd),self.store)['systemMessage'])

    def test_symlink_denied(self):
        self.mode('guarded')
        (self.proj/'link').symlink_to('/etc')
        ans=pre(self.event('PreToolUse',patch_cmd('link/passwd')),self.store)
        self.assertIn('UNINSPECTABLE_PATCH',json.dumps(ans))

    def test_patch_parser_moved_file_protected(self):
        cmd='*** Begin Patch\n*** Update File: src/a.py\n*** Move to: config.prod.json\n@@\n-old\n+new\n*** End Patch'
        self.mode('guarded')
        ans=pre(self.event('PreToolUse',cmd),self.store)
        self.assertIn('TARGET_NOT_AUTHORIZED',json.dumps(ans))

    def test_allow_override_authoritative_cli(self):
        self.mode('guarded')
        self.cmd('allow','config.prod.json')
        self.assertEqual(pre(self.event('PreToolUse',patch_cmd('config.prod.json')),self.store),{})

    def test_created_protected_file_is_observed(self):
        self.mode('guarded')
        (self.proj/'.env').unlink()
        cmd=patch_cmd('src/a.py')
        self.assertEqual(pre(self.event('PreToolUse',cmd),self.store),{})
        (self.proj/'src/a.py').write_text('updated')
        (self.proj/'.env').write_text('SECRET=value')
        answer=post(self.event('PostToolUse',cmd),self.store)
        self.assertIn('UNKNOWN_EFFECT',answer['systemMessage'])
        incident=read_json(self.store/'incident.json')
        self.assertIn('.env',incident['effect']['unauthorized_changed_paths'])

    def test_shell_with_exact_grant_logs_unverified(self):
        self.mode('guarded')
        cmd='pytest -q'
        self.cmd('permit-once','--command',cmd)
        self.assertEqual(pre(self.event('PreToolUse',cmd,tool='Bash'),self.store),{})
        self.assertIn('SHELL_APPROVED_UNVERIFIED',(self.store/'events.jsonl').read_text())

    def test_uninstall_preserves_third_party_modifications(self):
        hp=self.proj/'.codex'/'hooks.json'
        doc=json.loads(hp.read_text())
        doc['hooks']['PreToolUse'].append({'matcher':'Read','hooks':[{'type':'command','command':'echo existing'}]})
        hp.write_text(json.dumps(doc))
        self.cmd('uninstall')
        result=json.loads(hp.read_text())
        self.assertIn('echo existing',json.dumps(result))
        self.assertNotIn('CLIM Developer Preview',json.dumps(result))

    def test_real_subprocess_hook_transport(self):
        self.mode('guarded')
        event=self.event('PreToolUse',patch_cmd('config.prod.json'))
        proc=subprocess.run([sys.executable,'-m','clim_agent_guard.devpreview.hook',
                             'pre','--store',str(self.store)],input=json.dumps(event),
                             text=True,capture_output=True,check=True)
        actual=json.loads(proc.stdout)
        self.assertEqual(actual['hookSpecificOutput']['permissionDecision'],'deny')
        transport=json.loads((self.store/'hook_events.jsonl').read_text().splitlines()[-1])
        self.assertEqual(transport['input']['tool_use_id'],event['tool_use_id'])
        self.assertTrue(transport['redaction_applied'])
        self.assertNotIn('command',transport['input']['tool_input'])
        self.assertEqual(transport['output'],actual)
        self.assertEqual((self.proj/'config.prod.json').read_text(),'old')

    def test_uninstall_purge_removes_owned_store(self):
        self.mode('shadow')
        pre(self.event('PreToolUse',patch_cmd('config.prod.json')),self.store)
        self.cmd('uninstall','--purge-state')
        self.assertFalse(self.store.exists())
        self.assertFalse((self.proj/'.codex'/'hooks.json').exists())

    def test_doctor_reports_coverage(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc=main(['doctor','--project',str(self.proj)])
        d=json.loads(out.getvalue())
        self.assertTrue(d['checks']['PreToolUse_registered'])
        self.assertTrue(d['checks']['PostToolUse_registered'])
        self.assertIn('coverage',json.dumps(d).lower())
        self.assertEqual(rc,0)

if __name__=='__main__': unittest.main()
