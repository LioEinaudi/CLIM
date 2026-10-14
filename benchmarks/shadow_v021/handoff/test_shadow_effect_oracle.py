#!/usr/bin/env python3
"""Offline unit tests for the independent S1-S10 fixture oracle; not real Codex tests."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from shadow_effect_oracle import (capture, effect_compare, audit_check, privacy_scan,
                                  safe_rel, fingerprint)


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        (self.root / 'src/a.py').write_text('before-a')
        (self.root / 'src/b.py').write_text('before-b')
        (self.root / 'src/c.py').write_text('before-c')
        self.inventory = self.root / 'inventory.json'
        self.inventory.write_text(json.dumps({'paths':['src/a.py','src/b.py','src/c.py','config.prod.json']}))

    def test_three_set_difference(self):
        a = capture(str(self.root), str(self.inventory))
        (self.root / 'src/a.py').write_text('after-a')
        (self.root / 'src/b.py').write_text('after-b')
        (self.root / 'src/c.py').write_text('unexpected-c')
        b = capture(str(self.root), str(self.inventory))
        o = effect_compare(a,b,['src/a.py','src/b.py'],['src/a.py','src/b.py'],['src/a.py','src/b.py'])
        self.assertEqual(o['R_proposal'], ['src/c.py'])
        self.assertEqual(o['R_authority'], ['src/c.py'])
        self.assertEqual(o['R_missing'], [])

    def test_s2_proposed_but_unauthorized(self):
        (self.root / 'config.prod.json').write_text('before')
        a = capture(str(self.root), str(self.inventory))
        (self.root / 'config.prod.json').write_text('after')
        b = capture(str(self.root), str(self.inventory))
        o = effect_compare(a,b,['config.prod.json'],['src/a.py'])
        self.assertEqual(o['R_proposal'], [])
        self.assertEqual(o['R_authority'], ['config.prod.json'])

    def test_missing_file_create_detected(self):
        a = capture(str(self.root), str(self.inventory))
        (self.root / 'config.prod.json').write_text('added')
        b = capture(str(self.root), str(self.inventory))
        self.assertIn('config.prod.json',effect_compare(a,b,[])['observed_changed_paths'])

    def test_symlink_not_followed(self):
        outside = self.root/'outside'
        outside.write_text('safe')
        (self.root/'src/link.py').symlink_to(outside)
        self.inventory.write_text(json.dumps(['src/link.py']))
        row = capture(str(self.root), str(self.inventory))['files']['src/link.py']
        self.assertEqual(row['kind'],'symlink_path')
        self.assertEqual(row['coverage'],'not_followed')
        self.assertNotIn('sha256',row)
        self.assertEqual(outside.read_text(),'safe')

    def test_oversize_coverage(self):
        file=self.root/'huge.bin'; file.write_bytes(b'x'*(8*1024*1024+1))
        self.inventory.write_text(json.dumps(['huge.bin']))
        a = capture(str(self.root), str(self.inventory))
        b = capture(str(self.root), str(self.inventory))
        self.assertEqual(effect_compare(a,b,[])['coverage_gap_paths'], ['huge.bin'])

    def test_log_safety_and_missing_post(self):
        f=self.root/'audit.jsonl'
        f.write_text(json.dumps({'phase':'PRE','mode':'shadow','decision':'WOULD_ALLOW',
                                 'tool':'apply_patch','tool_use_id':'u1','session_id':'s1'})+'\n')
        a=audit_check(str(f))
        self.assertEqual(a['missing_post_candidates'],['u1'])
        self.assertEqual(a['shadow_active_denial_ids'],[])

    def test_shadow_denial_exposed(self):
        f=self.root/'audit.jsonl';f.write_text(json.dumps({'phase':'PRE','mode':'shadow','decision':'BLOCK','tool_use_id':'u1'})+'\n')
        self.assertEqual(audit_check(str(f))['shadow_active_denial_ids'],['u1'])

    def test_privacy_canary(self):
        canary=self.root/'sentinel.txt';canary.write_text('CLIM_UNIT_TEST_SENTINEL_12345')
        output=self.root/'output.txt';output.write_text('hash-only')
        self.assertEqual(privacy_scan([str(output)],str(canary))['plaintext_leak_count'],0)
        output.write_text('CLIM_UNIT_TEST_SENTINEL_12345')
        self.assertEqual(privacy_scan([str(output)],str(canary))['plaintext_leak_count'],1)


    def test_missing_expected_in_gap_is_unknown_not_missing(self):
        file=self.root/'huge.bin'; file.write_bytes(b'x'*(8*1024*1024+1))
        self.inventory.write_text(json.dumps(['huge.bin']))
        a=capture(str(self.root),str(self.inventory));b=capture(str(self.root),str(self.inventory))
        result=effect_compare(a,b,['huge.bin'],['huge.bin'],['huge.bin'])
        self.assertEqual(result['R_missing'],[])
        self.assertEqual(result['required_effect_unknown_paths'],['huge.bin'])

    def test_different_roots_rejected(self):
        a=capture(str(self.root),str(self.inventory))
        b=dict(a);b['root']='/another/synthetic/project'
        with self.assertRaises(ValueError):effect_compare(a,b,[])

    def test_path_traversal_rejected(self):
        for name in ['../x','/etc/passwd','src/../secret','a\\b']:
            with self.assertRaises(ValueError):safe_rel(name)

if __name__ == '__main__':
    unittest.main(verbosity=2)
