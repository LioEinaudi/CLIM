"""Public closeout portability and rehashed semantic tampering regressions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('closeout_archive',HERE/'verify_closeout.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
BUNDLE=HERE.parents[1]/'evidence/shadow_v021_closeout_20261015'


class CloseoutBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'copy';shutil.copytree(BUNDLE,self.root)

    def rehash(self,name):
        path=self.root/'SHA256SUMS.json';manifest=json.loads(path.read_text())
        manifest[name]=hashlib.sha256((self.root/name).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))

    def test_copied_archive_reads_only_its_payload(self):
        original=Path.open
        def bounded(path,mode='r',*args,**kwargs):
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()))
            self.assertFalse(any(c in mode for c in 'wax+'))
            return original(path,mode,*args,**kwargs)
        with patch.object(Path,'open',bounded):
            self.assertEqual(checker.verify(self.root)['hook_invocations'],32)

    def test_authority_cannot_be_replaced_by_proposal_after_rehash(self):
        name='smoke/registered/events.jsonl';path=self.root/name
        events=[json.loads(line) for line in path.read_text().splitlines()]
        for e in events:
            if e.get('phase')=='POST' and e.get('tool')=='apply_patch':
                e['effect']['E_authorized']=e['effect']['E_proposed']
        path.write_text(''.join(json.dumps(e)+'\n' for e in events));self.rehash(name)
        with self.assertRaisesRegex(ValueError,'Host authority replaced'):checker.verify(self.root)

    def test_native_patch_receipt_cannot_be_removed_after_rehash(self):
        name='smoke/unknown/native_trace_redacted.jsonl';path=self.root/name
        events=[json.loads(line) for line in path.read_text().splitlines()]
        events=[e for e in events if e.get('item',{}).get('type')!='file_change']
        path.write_text(''.join(json.dumps(e)+'\n' for e in events));self.rehash(name)
        with self.assertRaisesRegex(ValueError,'Actual native Patch receipt missing'):checker.verify(self.root)
