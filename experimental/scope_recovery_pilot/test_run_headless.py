"""Synthetic runner tests; no live Codex, Host, or Hook trust is simulated as real."""
import argparse
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from . import attempt_capture, pilot, review_manifest, run_headless
else:
    import attempt_capture
    import pilot
    import review_manifest
    import run_headless


class HeadlessRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root/'fixture'
        with patch('sys.stdout', new_callable=io.StringIO):
            pilot.prepare(argparse.Namespace(root=str(self.fixture), acknowledge_disposable=True))
        self.project = self.fixture/'project'
        self.operator = self.fixture/'operator'
        self.runtime = self.fixture/'runtime'
        (self.runtime/'bin').mkdir(parents=True)
        (self.runtime/'bin/python').write_text('#!/bin/sh\nprintf "0.3.0a2+scopefix.20261103\\n"\n')
        (self.runtime/'bin/python').chmod(0o700)
        (self.runtime/'bin/clim').write_text('#!/bin/sh\nexit 0\n')
        (self.runtime/'bin/clim').chmod(0o700)
        fake_package=self.runtime/'lib/python3.12/site-packages/clim_agent_guard/contract_runtime'
        fake_package.mkdir(parents=True)
        (fake_package/'codex_observer.py').write_text('# synthetic runtime\n')
        hook = self.project/'.codex/hooks.json'
        hook.parent.mkdir()
        import shlex,sys
        cmd=shlex.join([sys.executable,'-m','clim_agent_guard.contract_runtime.codex_observer',
                        'pre','--project',str(self.project),'--enable-enforcement'])
        hook.write_text(json.dumps({'hooks': {'PreToolUse': [{'hooks': [{'type':'command','command':cmd}]}]}}))
        with patch('sys.stdout', new_callable=io.StringIO):
            attempt_capture.configure(argparse.Namespace(project=str(self.project), operator=str(self.operator),
                                                        acknowledge_disposable=True))
        manifest=review_manifest.collect(self.project,self.operator,self.runtime)
        (self.operator/'review-manifest.json').write_text(json.dumps(manifest))
        self.fakebin = self.root/'fakebin'
        self.fakebin.mkdir()
        self.codex = self.fakebin/'codex'

    def args(self, **kwargs):
        fields = dict(project=str(self.project), operator=str(self.operator), runtime=str(self.runtime),
                      phase='in-scope', timeout_seconds=2, operator_attests_hook_reviewed=True)
        fields.update(kwargs)
        return argparse.Namespace(**fields)

    def fake(self, code):
        self.codex.write_text('#!/usr/bin/env python3\n'+code)
        self.codex.chmod(0o700)

    def test_requires_manual_review_attestation(self):
        with self.assertRaisesRegex(ValueError, 'human must review'):
            run_headless.run(self.args(operator_attests_hook_reviewed=False))
        self.assertFalse((self.operator/'in-scope.codex-exec.jsonl').exists())

    def test_changed_hook_requires_review_again(self):
        with (self.project/'.codex/hooks.json').open('a') as f:
            f.write('\n')
        with self.assertRaisesRegex(ValueError, 'changed since configuration'):
            run_headless.run(self.args())

    def test_changed_runtime_requires_review_again(self):
        p=self.runtime/'lib/python3.12/site-packages/clim_agent_guard/contract_runtime/codex_observer.py'
        p.write_text('# modified synthetic runtime\n')
        with self.assertRaisesRegex(ValueError, 'dependencies changed'):
            run_headless.run(self.args())

    def test_runner_uses_scoped_options_and_drops_parent_secret_variables(self):
        self.fake("import json, os, sys\n"
                  "sys.stdin.read()\n"
                  "print(json.dumps({'type':'test','args':sys.argv[1:],'secret_present':'JUPYTER_TOKEN' in os.environ}))\n")
        with patch.dict(os.environ, {'PATH':str(self.fakebin)+os.pathsep+os.environ['PATH'],
                                     'JUPYTER_TOKEN':'synthetic-token'}, clear=False), \
             patch('sys.stdout', new_callable=io.StringIO):
            run_headless.run(self.args())
        meta=json.loads((self.operator/'in-scope.run.json').read_text())
        event=json.loads((self.operator/'in-scope.codex-exec.jsonl').read_text())
        self.assertEqual(meta['run_status'], 'FINISHED')
        self.assertFalse(meta['host_hook_enforcement_proven'])
        self.assertFalse(event['secret_present'])
        self.assertIn('workspace-write', event['args'])
        self.assertIn('--ephemeral', event['args'])
        self.assertNotIn('--dangerously-bypass-hook-trust', event['args'])
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', event['args'])

    def test_timeout_terminates_child_and_is_labeled_harness_timeout(self):
        self.fake('import sys,time\nsys.stdin.read()\ntime.sleep(30)\n')
        with patch.dict(os.environ, {'PATH':str(self.fakebin)+os.pathsep+os.environ['PATH']}, clear=False), \
             patch('sys.stdout', new_callable=io.StringIO):
            run_headless.run(self.args(timeout_seconds=1))
        meta=json.loads((self.operator/'in-scope.run.json').read_text())
        self.assertEqual(meta['run_status'], 'HARNESS_TIMEOUT')
        self.assertLess(meta['elapsed_seconds'], 5)
        self.assertFalse(meta['host_hook_enforcement_proven'])


if __name__ == '__main__':
    unittest.main()
