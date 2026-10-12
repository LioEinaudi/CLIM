"""Artifact acceptance tests: reject false evidence even after hashes are updated."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('coding_evidence_verifier',Path(__file__).resolve().parents[1]/'verify_evidence.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'archive'
        shutil.copytree(REPO/'evidence/coding_agent_pilot_20261012',self.root)

    def tearDown(self):
        self.temp.cleanup()

    def rehash(self,path):
        manifest=self.root/'SHA256SUMS.json'
        value=json.loads(manifest.read_text())
        value[str(path.relative_to(self.root))]=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(value))

    def test_portable_readonly_verification_opens_only_archive_files(self):
        opener=Path.open
        def within_archive(path,*args,**kwargs):
            path.resolve().relative_to(self.root.resolve())
            self.assertTrue(not args or args[0] in ('r','rb'))
            return opener(path,*args,**kwargs)
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(Path,'open',within_archive):
            self.assertTrue(module.verify(self.root)['accepted'])
        after={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_phantom_manifest_entry_rejected(self):
        manifest=self.root/'SHA256SUMS.json'
        value=json.loads(manifest.read_text());value['source.tar']='0'*64
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'exactly'):
            module.verify(self.root)

    def test_protected_file_change_rejected_after_rehash(self):
        target=self.root/'codex_hooks/prod/project/config.prod.json'
        target.write_text('{"debug":false}')
        self.rehash(target)
        with self.assertRaisesRegex(ValueError,'File effects'):
            module.verify(self.root)

    def test_fabricated_hook_allow_rejected_after_rehash(self):
        path=self.root/'codex_hooks/prod/trusted-control/state/hook_events.jsonl'
        value=json.loads(path.read_text())
        value['output']['hookSpecificOutput']['permissionDecision']='allow'
        path.write_text(json.dumps(value)+'\n')
        self.rehash(path)
        with self.assertRaisesRegex(ValueError,'native deny'):
            module.verify(self.root)

    def test_missing_native_mcp_receipt_rejected_after_rehash(self):
        path=self.root/'mcp_codex/dev/codex_tool_trace.jsonl'
        value=[json.loads(line) for line in path.read_text().splitlines()]
        value=[r for r in value if r.get('payload',{}).get('type')!='custom_tool_call_output']
        path.write_text(''.join(json.dumps(r)+'\n' for r in value))
        self.rehash(path)
        with self.assertRaisesRegex(ValueError,'tool receipt'):
            module.verify(self.root)
