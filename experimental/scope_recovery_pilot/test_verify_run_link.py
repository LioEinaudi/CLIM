"""Synthetic same-session correlation tests; not evidence of native Codex behavior."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

if __package__:
    from . import attempt_capture, pilot, verify_run_link
else:
    import attempt_capture
    import pilot
    import verify_run_link


class RunLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root/'project'
        (self.project/'src/game/ui').mkdir(parents=True)
        (self.project/'src/game/ui/menu.py').write_text('VALUE = 1\n')
        self.operator = self.root/'operator'
        self.operator.mkdir()
        (self.operator/'pretool-capture-key.bin').write_bytes(bytes(range(32)))
        (self.operator/'pretool-capture.jsonl').write_text('')
        self.receipt = 'clim-deny-' + 'a'*32
        self.host = self.operator/'native-host.txt'
        self.host.write_text('Command blocked by PreToolUse hook: CLIM experimental contract scope Receipt: '+self.receipt)
        self.events = self.operator/'conflict.codex-exec.jsonl'
        self.meta = self.operator/'conflict.run.json'
        self.write_events('same-session')
        event = {'hook_event_name':'PreToolUse','tool_name':'apply_patch',
                 'session_id':'same-session','tool_use_id':'tool-1',
                 'tool_input':{'command':'*** Begin Patch\n*** Update File: src/game/ui/menu.py\n@@\n-VALUE = 1\n+VALUE = 2\n*** End Patch'}}
        out = {'hookSpecificOutput':{'permissionDecision':'deny',
               'permissionDecisionReason':'CLIM experimental contract scope Receipt: '+self.receipt}}
        attempt_capture._record(self.operator, self.project, json.dumps(event).encode(), json.dumps(out).encode(), 20, 30)
        self.write_meta()

    def write_events(self, session):
        rows = [{'type':'thread.started','thread_id':session},{'type':'turn.started'},
                {'type':'turn.completed','usage':{'input_tokens':10,'output_tokens':2,
                  'cached_input_tokens':0,'reasoning_output_tokens':0}}]
        self.events.write_text(''.join(json.dumps(r)+'\n' for r in rows))

    def write_meta(self, status='FINISHED'):
        self.meta.write_text(json.dumps({'schema':'clim-scope-recovery-run-v1','phase':'conflict',
          'run_status':status,'start_monotonic_ns':10,'end_monotonic_ns':40,
          'events_sha256':hashlib.sha256(self.events.read_bytes()).hexdigest()}))

    def args(self):
        return argparse.Namespace(project=str(self.project), operator=str(self.operator),
                                  events=str(self.events), run_metadata=str(self.meta), host_feedback=str(self.host))

    def test_matching_receipt_session_time_and_single_turn_links_usage(self):
        result = verify_run_link.verify(self.args())
        self.assertEqual(result['same_native_run'], 'YES')
        link=self.operator/'run-link.json';link.write_text(json.dumps(result))
        self.assertEqual(pilot.same_run_link(link,self.events,self.host),'YES')
        self.events.write_text(self.events.read_text()+'\n')
        self.assertEqual(pilot.same_run_link(link,self.events,self.host),'UNKNOWN')

    def test_other_session_or_incomplete_run_cannot_be_linked(self):
        self.write_events('other-session');self.write_meta()
        result=verify_run_link.verify(self.args())
        self.assertEqual(result['same_native_run'],'UNKNOWN')
        self.assertIn('RECEIPT_SESSION_TIME_ANCHOR_NOT_UNIQUE',result['reasons'])
        self.write_events('same-session');self.write_meta('HARNESS_TIMEOUT')
        result=verify_run_link.verify(self.args())
        self.assertEqual(result['same_native_run'],'UNKNOWN')
        self.assertIn('RUN_METADATA_INCOMPLETE_OR_MISMATCHED',result['reasons'])

    def test_changed_capture_or_wrong_receipt_invalidates_link(self):
        result=verify_run_link.verify(self.args());link=self.operator/'run-link.json';link.write_text(json.dumps(result))
        with (self.operator/'pretool-capture.jsonl').open('a') as out:out.write('\n')
        self.assertEqual(pilot.same_run_link(link,self.events,self.host),'UNKNOWN')
        self.host.write_text('Command blocked by PreToolUse hook: CLIM experimental contract scope Receipt: clim-deny-'+'b'*32)
        self.assertEqual(verify_run_link.verify(self.args())['same_native_run'],'UNKNOWN')

    def test_unsigned_or_edited_link_is_not_accepted(self):
        result = verify_run_link.verify(self.args())
        link = self.operator/'run-link.json'
        result.pop('link_hmac_sha256')
        link.write_text(json.dumps(result))
        self.assertEqual(pilot.same_run_link(link, self.events, self.host), 'UNKNOWN')
        result = verify_run_link.verify(self.args())
        result['basis'] = 'edited'
        link.write_text(json.dumps(result))
        self.assertEqual(pilot.same_run_link(link, self.events, self.host), 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
