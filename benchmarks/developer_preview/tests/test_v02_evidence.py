"""Meaningful archive portability and semantic tampering checks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location('v02_evidence', HERE / 'verify_evidence.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'copied_archive'
        shutil.copytree(REPO / 'evidence/developer_preview_v02_20261013', self.root)

    def tearDown(self):
        self.temp.cleanup()

    def rehash(self, relative):
        p = self.root / 'SHA256SUMS.json'
        manifest = json.loads(p.read_text())
        manifest[relative] = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
        p.write_text(json.dumps(manifest))

    def test_copied_archive_reads_only_its_payload(self):
        original = Path.open
        def bounded_open(path, mode='r', *args, **kwargs):
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()), str(path))
            self.assertFalse(any(c in mode for c in 'wax+'), mode)
            return original(path, mode, *args, **kwargs)
        with patch.object(Path, 'open', bounded_open):
            self.assertEqual(checker.verify(self.root)['status'], 'PASS')

    def test_rehashed_production_mutation_rejected(self):
        relative = 'cross_tool/project.json'
        p = self.root / relative
        files = json.loads(p.read_text())
        files['config.prod.json'] = '{"debug": false}\n'
        p.write_text(json.dumps(files))
        self.rehash(relative)
        with self.assertRaisesRegex(ValueError, 'Unexpected final file effects'):
            checker.verify(self.root)

    def test_rehashed_missing_native_receipt_rejected(self):
        relative = 'cross_tool/codex_tool_trace.jsonl'
        p = self.root / relative
        records = [json.loads(line) for line in p.read_text().splitlines()]
        records = [r for r in records if r.get('payload', {}).get('type') != 'custom_tool_call_output']
        p.write_text(''.join(json.dumps(r) + '\n' for r in records))
        self.rehash(relative)
        with self.assertRaisesRegex(ValueError, 'Missing native calls or receipts'):
            checker.verify(self.root)


if __name__ == '__main__':
    unittest.main()
