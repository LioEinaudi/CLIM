"""Copied archive portability and semantic tampering, including rehashed inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('shadow_bundle_verifier',HERE/'verify_evidence.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
BUNDLE=Path(os.environ.get('CLIM_SHADOW_EVIDENCE','/root/mine/gh-drafts/clim-agent-guard/clim_shadow_v021_acceptance_20261014_review'))

@unittest.skipUnless(BUNDLE.is_dir(),'Set CLIM_SHADOW_EVIDENCE to the private reviewed bundle to run archive acceptance tests')
class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'copy';shutil.copytree(BUNDLE,self.root)
    def rehash(self,relative):
        manifest=json.loads((self.root/'SHA256SUMS.json').read_text());manifest[relative]=hashlib.sha256((self.root/relative).read_bytes()).hexdigest()
        (self.root/'SHA256SUMS.json').write_text(json.dumps(manifest))
    def test_copied_bundle_readonly_within_archive(self):
        original=Path.open
        def bounded(path,mode='r',*args,**kw):
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()),str(path))
            self.assertFalse(any(c in mode for c in 'wax+'))
            return original(path,mode,*args,**kw)
        with patch.object(Path,'open',bounded):self.assertEqual(checker.verify(self.root)['status'],'PASS')
    def test_authority_from_proposal_rejected_after_rehash(self):
        relative='runs/S02/production/clim_state/events.jsonl';p=self.root/relative
        records=[json.loads(l) for l in p.read_text().splitlines()]
        for e in records:
            if e.get('phase')=='POST' and e.get('tool')=='apply_patch':
                e['effect']['E_authorized']=e['effect']['E_proposed'];e['effect']['R_authority']=[]
        p.write_text(''.join(json.dumps(r)+'\n' for r in records));self.rehash(relative)
        with self.assertRaisesRegex(ValueError,'Host authorization replaced'):checker.verify(self.root)
    def test_native_receipt_missing_rejected_after_rehash(self):
        relative='runs/S05/injected/codex_trace_redacted.jsonl';p=self.root/relative
        records=[json.loads(l) for l in p.read_text().splitlines()]
        records=[r for r in records if r.get('item',{}).get('type')!='file_change']
        p.write_text(''.join(json.dumps(r)+'\n' for r in records));self.rehash(relative)
        with self.assertRaisesRegex(ValueError,'Native receipts missing'):checker.verify(self.root)
