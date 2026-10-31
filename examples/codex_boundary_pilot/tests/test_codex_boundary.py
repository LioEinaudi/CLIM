"""Minimal process-level hook transport and state-machine tests; no Codex dependency."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from run_demo import patch, invoke, denied, digest


class CodexHookPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.root = base/'workspace'
        self.root.mkdir()
        self.admin = base/'trusted'
        self.admin.mkdir()
        self.dev = self.root/'config.dev.json'
        self.prod = self.root/'config.prod.json'
        self.dev.write_text('original dev')
        self.prod.write_text('original prod')
        self.policy_file = self.admin/'policy.json'
        self.policy = {'_version':1, 'project_root':str(self.root), 'authorized_target':'config.dev.json',
             'protected_targets':['config.prod.json'], 'user_confirmed':True}
        self.save_policy()
        self.env = dict(os.environ, CLIM_CODEX_POLICY=str(self.policy_file),
                         CLIM_CODEX_STATE_DIR=str(self.admin/'state'))

    def tearDown(self):
        self.temp.cleanup()

    def save_policy(self):
        self.policy_file.write_text(json.dumps(self.policy))

    def call(self, mode, id_, tool, command):
        return invoke(mode, self.root, self.env, id_, tool, command)

    def test_prod_target_denied_with_no_change(self):
        before = digest(self.prod)
        r = self.call('pre', '1', 'apply_patch', patch('config.prod.json'))
        self.assertTrue(denied(r))
        self.assertEqual(digest(self.prod), before)
        log = (self.admin/'state'/'audit.jsonl').read_text()
        self.assertIn('TARGET_NOT_AUTHORIZED', log)

    def test_dev_pre_post_verified(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        self.dev.write_text('changed dev')
        result = self.call('post','1','apply_patch',cmd)
        self.assertIn('EFFECT_VERIFIED', result['systemMessage'])

    def test_absolute_dev_target_verifies_against_canonical_policy_target(self):
        cmd = patch(str(self.dev))
        self.assertFalse(denied(self.call('pre','abs','apply_patch',cmd)))
        self.dev.write_text('changed dev')
        self.assertIn('EFFECT_VERIFIED', self.call('post','abs','apply_patch',cmd)['systemMessage'])

    def test_raw_transport_preserves_actual_proposal_and_deny_reply(self):
        cmd = patch('config.prod.json')
        result = self.call('pre','raw','apply_patch',cmd)
        rows = [json.loads(line) for line in (self.admin/'state'/'hook_events.jsonl').read_text().splitlines()]
        self.assertEqual(rows[0]['input']['tool_input']['command'], cmd)
        self.assertEqual(rows[0]['input']['tool_use_id'], 'raw')
        self.assertEqual(rows[0]['output'], result)

    def test_unexpected_prod_change_is_alert_and_incident(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        self.dev.write_text('changed dev')
        self.prod.write_text('changed prod')
        result = self.call('post','1','apply_patch',cmd)
        self.assertEqual(result['decision'], 'block')
        self.assertTrue((self.admin/'state'/'incident.json').exists())
        self.assertTrue(denied(self.call('pre','2','apply_patch',cmd)))

    def test_missing_post_is_blocked_on_new_call(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        self.assertTrue(denied(self.call('pre','2','apply_patch',cmd)))

    def test_no_change_causes_unknown_effect(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        result = self.call('post','1','apply_patch',cmd)
        self.assertEqual(result['decision'],'block')
        self.assertTrue((self.admin/'state'/'incident.json').exists())

    def test_bash_denied(self):
        self.assertTrue(denied(self.call('pre','1','Bash','printf hi > config.prod.json')))

    def test_multiple_update_denied(self):
        cmd = ('*** Begin Patch\n*** Update File: config.dev.json\n@@\n-old\n+new\n'
               '*** Update File: config.prod.json\n@@\n-old\n+new\n*** End Patch')
        self.assertTrue(denied(self.call('pre','1','apply_patch',cmd)))

    def test_missing_input_denied(self):
        result = subprocess.run([sys.executable, str(HERE/'hook.py'),'pre'],
                  input='not json', text=True, capture_output=True, env=self.env, cwd=self.root)
        self.assertEqual(result.returncode,0)
        self.assertTrue(denied(json.loads(result.stdout)))

    def test_policy_confirmation_false(self):
        self.policy['user_confirmed']=False
        self.save_policy()
        self.assertTrue(denied(self.call('pre','1','apply_patch',patch('config.dev.json'))))

    def test_ledger_retained_duplicate_call(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        self.dev.write_text('changed dev')
        self.assertIn('EFFECT_VERIFIED',self.call('post','1','apply_patch',cmd)['systemMessage'])
        self.assertTrue(denied(self.call('pre','1','apply_patch',cmd)))

    def test_missing_pre_cannot_verify(self):
        result = self.call('post','1','apply_patch',patch('config.dev.json'))
        self.assertEqual(result['decision'],'block')

    def test_authority_changed_midflight_alert(self):
        cmd = patch('config.dev.json')
        self.assertFalse(denied(self.call('pre','1','apply_patch',cmd)))
        self.dev.write_text('changed dev')
        self.policy['_version']=2
        self.save_policy()
        self.assertEqual(self.call('post','1','apply_patch',cmd)['decision'],'block')


if __name__=='__main__':
    unittest.main()
