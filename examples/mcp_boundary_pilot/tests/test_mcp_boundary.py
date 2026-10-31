import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('clim_mcp_boundary',Path(__file__).resolve().parents[1]/'boundary.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
FileBoundary,BoundaryDenied=module.FileBoundary,module.BoundaryDenied


class MCPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name)
        self.root=self.base/'project'
        self.root.mkdir()
        for name in ('dev.json','prod.json'):
            (self.root/name).write_text('{"debug":true}')
        self.policy={'_version':1,'project_root':str(self.root),'authorized_target':'dev.json',
                     'protected_targets':['prod.json'],'user_confirmed':True}
        self.pfile=self.base/'policy.json'
        self.save()
        self.guard=FileBoundary(self.pfile,self.base/'state')

    def save(self):
        self.pfile.write_text(json.dumps(self.policy))

    def tearDown(self):
        self.temp.cleanup()

    def test_prod_denied_before_write(self):
        before=(self.root/'prod.json').read_bytes()
        with self.assertRaisesRegex(BoundaryDenied,'TARGET_NOT_AUTHORIZED'):
            self.guard.set_debug('prod.json',False,'prod')
        self.assertEqual(before,(self.root/'prod.json').read_bytes())

    def test_dev_effect_and_duplicate_survive_server_restart(self):
        result=self.guard.set_debug(str(self.root/'dev.json'),False,'dev')
        self.assertEqual(result['code'],'EFFECT_VERIFIED')
        self.assertFalse(json.loads((self.root/'dev.json').read_text())['debug'])
        self.assertTrue(json.loads((self.root/'prod.json').read_text())['debug'])
        again=FileBoundary(self.pfile,self.base/'state')
        with self.assertRaisesRegex(BoundaryDenied,'DUPLICATE_SIDE_EFFECT'):
            again.set_debug('dev.json',False,'dev')

    def test_false_host_confirmation_cannot_be_overridden_by_caller(self):
        self.policy['user_confirmed']=False
        self.save()
        with self.assertRaisesRegex(BoundaryDenied,'USER_CONFIRMATION_REQUIRED'):
            self.guard.set_debug('dev.json',False,'approved-by-admin')

    def test_outside_path_denied(self):
        outside=self.base/'outside.json'
        outside.write_text('{"debug":true}')
        before=outside.read_bytes()
        with self.assertRaises(BoundaryDenied):
            self.guard.set_debug(str(outside),False,'outside')
        self.assertEqual(before,outside.read_bytes())

    def test_uncertain_effect_blocks_new_operation_id(self):
        self.guard.set_debug('dev.json',False,'first')
        with self.assertRaisesRegex(BoundaryDenied,'UNKNOWN_EFFECT'):
            self.guard.set_debug('dev.json',False,'no-change')
        with self.assertRaisesRegex(BoundaryDenied,'reconciliation'):
            self.guard.set_debug('dev.json',True,'different-id')
