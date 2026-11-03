"""Synthetic safety and correlation tests; none constitute a native Host run."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from . import attempt_capture as capture
    from . import pilot
else:
    import attempt_capture as capture
    import pilot


class AttemptCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root / 'fixture'
        with patch('sys.stdout', new_callable=io.StringIO):
            pilot.prepare(argparse.Namespace(root=str(self.fixture), acknowledge_disposable=True))
        self.project = self.fixture / 'project'
        self.operator = self.fixture / 'operator'
        self.hook_file = self.project / '.codex' / 'hooks.json'
        self.hook_file.parent.mkdir()
        command = [sys.executable, '-m', 'clim_agent_guard.contract_runtime.codex_observer',
                   'pre', '--project', str(self.project), '--enable-enforcement']
        import shlex
        self.original = {'hooks': {'PreToolUse': [{'matcher': '^(Bash|apply_patch)$', 'hooks': [
            {'type': 'command', 'command': shlex.join(command), 'timeout': 4}]}],
            'PostToolUse': [{'matcher': 'apply_patch', 'hooks': [{'type': 'command', 'command': 'echo post'}]}]}}
        self.hook_file.write_text(json.dumps(self.original))
        self.delegate = command

    def configure(self):
        with patch('sys.stdout', new_callable=io.StringIO):
            capture.configure(argparse.Namespace(project=str(self.project), operator=str(self.operator),
                                                 acknowledge_disposable=True))

    def event(self, tool, path, session='private-session-id'):
        return {'hook_event_name': 'PreToolUse', 'tool_name': 'apply_patch',
                'session_id': session, 'tool_use_id': tool,
                'tool_input': {'command': f'*** Begin Patch\n*** Update File: {path}\n@@\n-a\n+b\n*** End Patch'}}

    def record(self, tool, path, start, end, receipt=None):
        output = {} if not receipt else {'hookSpecificOutput': {'permissionDecision': 'deny',
                    'permissionDecisionReason': 'CLIM experimental contract scope: Receipt: ' + receipt}}
        capture._record(self.operator, self.project, json.dumps(self.event(tool, path)).encode(),
                        json.dumps(output).encode(), start, end)

    def host(self, receipt):
        p = self.operator/'native-host.txt'
        p.write_text('Command blocked by PreToolUse hook: CLIM experimental contract scope: Receipt: '+receipt)
        return p

    def normalize(self, host, name='attempts.jsonl'):
        with patch('sys.stdout', new_callable=io.StringIO):
            capture.normalize(argparse.Namespace(project=str(self.project), operator=str(self.operator),
                                                 host_feedback=str(host), out=str(self.operator/name)))
        return self.operator/name

    def test_configure_wraps_only_disposable_pre_hook_and_never_trusts(self):
        self.configure()
        actual = json.loads(self.hook_file.read_text())
        self.assertEqual(actual['hooks']['PostToolUse'], self.original['hooks']['PostToolUse'])
        command = actual['hooks']['PreToolUse'][0]['hooks'][0]['command']
        self.assertIn('attempt_capture.py', command)
        self.assertIn('--enable-enforcement', command)
        self.assertEqual((self.operator/'pretool-capture.jsonl').read_bytes(), b'')
        self.assertEqual((self.operator/'pretool-capture-key.bin').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            self.configure()

    def test_configuration_refuses_evidence_inside_project(self):
        old = self.hook_file.read_bytes()
        with self.assertRaisesRegex(ValueError, 'outside'):
            capture.configure(argparse.Namespace(project=str(self.project), operator=str(self.project/'subdir'),
                                                 acknowledge_disposable=True))
        self.assertEqual(self.hook_file.read_bytes(), old)

    def test_capture_does_not_persist_raw_identity_patch_or_receipt(self):
        self.configure()
        receipt = 'clim-deny-' + 'a' * 32
        self.record('private-tool-id', pilot.OUTSIDE, 10, 20, receipt)
        text = (self.operator/'pretool-capture.jsonl').read_text()
        row = json.loads(text)
        self.assertNotIn('private-tool-id', text)
        self.assertNotIn('private-session-id', text)
        self.assertNotIn('*** Begin Patch', text)
        self.assertNotIn(receipt, text)
        self.assertEqual(row['target'], pilot.OUTSIDE)
        self.assertTrue(row['clim_denial_requested'])
        self.assertEqual(row['requested_receipt_sha256'], hashlib.sha256(receipt.encode()).hexdigest())

    def test_receipt_linked_attempts_are_deduplicated_and_scoped(self):
        self.configure()
        receipt = 'clim-deny-' + 'b' * 32
        self.record('tool-one', pilot.OUTSIDE, 10, 20, receipt)
        self.record('tool-one', pilot.OUTSIDE, 21, 25, receipt)
        self.record('tool-two', pilot.OUTSIDE, 30, 40)
        host = self.host(receipt)
        path = self.normalize(host)
        actual = [json.loads(x) for x in path.read_text().splitlines()]
        self.assertEqual(len(actual), 2)
        self.assertEqual(actual[0]['host_result'], 'BLOCKED')
        self.assertEqual(actual[1]['host_result'], 'UNKNOWN')
        result = pilot.normalized_attempts(path, True, hashlib.sha256(receipt.encode()).hexdigest())
        self.assertEqual(result['repeated_target_attempts'], 1)

    def test_mismatched_receipt_and_concurrent_attempts_stay_unknown(self):
        self.configure()
        receipt = 'clim-deny-' + 'c' * 32
        self.record('tool-one', pilot.OUTSIDE, 10, 30, receipt)
        self.record('tool-two', pilot.OUTSIDE, 20, 40)
        with self.assertRaisesRegex(ValueError, 'Concurrent'):
            self.normalize(self.host(receipt))
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.normalize(self.host('clim-deny-' + 'd' * 32))
        self.assertFalse((self.operator/'attempts.jsonl').exists())

    def test_hook_forwards_exact_clim_output_and_exit_status(self):
        self.configure()
        receipt = 'clim-deny-' + 'e' * 32
        raw = json.dumps(self.event('tool-1', pilot.OUTSIDE)).encode()
        output = json.dumps({'hookSpecificOutput': {'permissionDecision': 'deny',
                 'permissionDecisionReason': 'CLIM experimental contract scope: Receipt: '+receipt}}).encode()
        original = subprocess.CompletedProcess(self.delegate, 0, stdout=output, stderr=b'')
        fake_in = type('In', (), {'buffer': io.BytesIO(raw)})()
        fake_out = type('Out', (), {'buffer': io.BytesIO()})()
        fake_err = type('Err', (), {'buffer': io.BytesIO()})()
        args = argparse.Namespace(project=str(self.project), operator=str(self.operator), delegate=self.delegate)
        with patch.object(capture.subprocess, 'run', return_value=original), \
             patch.object(sys, 'stdin', fake_in), patch.object(sys, 'stdout', fake_out), patch.object(sys, 'stderr', fake_err):
            rc = capture.hook(args)
        self.assertEqual(rc, 0)
        self.assertEqual(fake_out.buffer.getvalue(), output)
        self.assertEqual(fake_err.buffer.getvalue(), b'')
        self.assertEqual(len((self.operator/'pretool-capture.jsonl').read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
