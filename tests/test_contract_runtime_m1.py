"""M1 offline contract runtime; NOT Native Codex Hook acceptance."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from clim_agent_guard.contract_runtime import ContractRuntime, ContractError, SQLiteEvidenceSink
from clim_agent_guard.contract_runtime.service import template

class TestM1(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='clim-m1-')
        base=Path(self.temp.name)
        self.root=base/'project';self.root.mkdir();(self.root/'src').mkdir();(self.root/'src/api').mkdir();(self.root/'src/client').mkdir();(self.root/'tests').mkdir()
        (self.root/'src/api/a.py').write_text('api-v1\n')
        self.path=base/'external'/'ledger.sqlite3'
        self.ledger=SQLiteEvidenceSink(self.path)
        self.rt=ContractRuntime(self.root,self.ledger)
        self.stages={'A':{'max_allowed':['src/api/**'],'predecessors':[]},
                     'B':{'max_allowed':['src/client/**'],'predecessors':['A'],
                          'version_inputs':{'A':['src/api/a.py']}}}
        self.cap=self.rt.initialize(task_id='test-task',allowed=['src/**','tests/**'],
              denied=['.env','src/shared/**'],stages=self.stages)
    def tearDown(self):self.temp.cleanup()
    def proposal(self,id='A1',parent='ROOT',stage='A',allowed=None,**kw):
        return {'contract_id':id,'parent_id':parent,'stage_id':stage,
               'allowed':['src/api/**'] if allowed is None else allowed,**kw}
    def assert_denied(self,call,code):
        with self.assertRaises(ContractError) as err:call()
        self.assertEqual(err.exception.code,code)
    def test_initial_status_is_observe_only(self):
        status=self.rt.status()
        self.assertEqual(status['enforcement'],'NOT_ENABLED_M1')
        self.assertEqual(status['active_stage'],None)
    def test_root_broad_with_specific_deny(self):
        self.assertEqual(self.rt.propose(self.proposal())['status'],'ACCEPTED_NOT_ACTIVE')
    def test_validate_no_effect_and_propose_history(self):
        p=self.proposal()
        self.assertTrue(self.rt.validate(p)['valid'])
        self.assertEqual(self.rt.status()['contract_versions'],1)
        self.rt.propose(p)
        self.assertEqual(self.rt.status()['contract_versions'],2)
        self.assertEqual(self.rt.sink.verify()['integrity'],'LOCAL_CONSISTENCY_ONLY')
    def test_child_expansion_rejected(self):
        self.assert_denied(lambda:self.rt.propose(self.proposal(allowed=['src/**'])),'TRUSTED_STAGE_SCOPE_EXCEEDED')
    def test_root_rebinding_after_activation_rejected(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.assert_denied(lambda:self.rt.propose(self.proposal('bad','ROOT','A',['src/client/**'])),'ACTIVE_STAGE_ROOT_BYPASS')
    def test_root_as_execution_contract_never_active(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        state=self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='tool1',targets=['src/client/adapter.py'])
        self.assertEqual(state['scope_verdict'],'CONTRACT_SCOPE_CONFLICT')
        self.assertFalse(state['enforced'])
    def test_narrowing_delegation_no_parent_fallback(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.propose(self.proposal('A2','A1','A',['src/api/v2/**']))
        self.rt.activate('A2',self.cap)
        state=self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='t1',targets=['src/api/a.py'])
        self.assertEqual(state['scope_verdict'],'CONTRACT_SCOPE_CONFLICT')
    def test_parent_denial_cannot_be_removed(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.assert_denied(lambda:self.rt.propose(self.proposal('A2','A1','A',['src/api/**'],denied=[])),
                           'INHERITED_DENY_REMOVED')
    def test_approval_requires_capability(self):
        self.rt.propose(self.proposal())
        self.assert_denied(lambda:self.rt.activate('A1','wrong'),'OPERATOR_CAPABILITY_REQUIRED')
    def test_stage_dependency_and_bound_output_sha(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.finish_stage(self.cap,['src/api/a.py'])
        self.rt.propose(self.proposal('B1','ROOT','B',['src/client/**']))
        (self.root/'src/api/a.py').write_text('tampered\n')
        self.assert_denied(lambda:self.rt.activate('B1',self.cap),'STATE_PRECONDITION_CHANGED')
    def test_stage_completion_and_no_reactivation(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.finish_stage(self.cap,['src/api/a.py'])
        self.assert_denied(lambda:self.rt.activate('A1',self.cap),'CONTRACT_NOT_ACCEPTED')
    def test_window_exact_identity_prevents_duplicate(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='t1',targets=['src/api/a.py'])
        self.assert_denied(lambda:self.rt.begin_window(window_id='w2',session_id='s1',tool_use_id='t1',targets=['src/api/a.py']),
                           'DUPLICATE_WINDOW_ID')
    def test_overlap_does_not_assert_causality(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='t1',targets=['src/api/a.py'])
        self.rt.begin_window(window_id='w2',session_id='s1',tool_use_id='t2',targets=['src/api/a.py'])
        self.assertEqual(self.rt.close_window('w1',['src/api/a.py'],coverage='PARTIAL')['attribution'],'CAUSE_UNKNOWN')
    def test_recover_marks_unknown_not_verified(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='t1',targets=['src/api/a.py'])
        changed=self.rt.recover()
        self.assertEqual(changed['recovered_unknown'],1)
        self.assertFalse(changed['effect_verified'])
        self.assertEqual(self.rt.status()['pending_windows'],0)
        self.assertGreaterEqual(self.rt.status()['unknown_windows'],1)
        self.assertEqual(self.rt.recover()['recovered_unknown'],0)
    def test_recover_never_changes_file(self):
        orig=(self.root/'src/api/a.py').read_bytes()
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap)
        self.rt.begin_window(window_id='w1',session_id='s1',tool_use_id='t1',targets=['src/api/a.py'])
        self.rt.recover()
        self.assertEqual((self.root/'src/api/a.py').read_bytes(),orig)
    def test_history_persists_versions_and_seq(self):
        self.rt.propose(self.proposal());self.rt.activate('A1',self.cap);self.rt.finish_stage(self.cap)
        with self.ledger.read() as c:
            revs=c.execute("SELECT revision,status FROM contract_versions WHERE contract_id='A1' ORDER BY revision").fetchall()
        self.assertEqual([(r[0],r[1]) for r in revs],[(1,'ACCEPTED'),(2,'ACTIVE'),(3,'CLOSED')])
        seq=[e['event_seq'] for e in self.rt.history()]
        self.assertEqual(seq,list(range(1,len(seq)+1)))
    def test_hash_tampering_detected(self):
        # The normal SQL connection must refuse mutation of historical records.
        with self.assertRaises(sqlite3.IntegrityError):
            with self.ledger.transaction() as c:
                c.execute("UPDATE events SET event_hash='invalid' WHERE seq=1")
        # If an administrator drops the trigger, verify() detects partial rewrites.
        with self.ledger.transaction() as c:
            c.execute('DROP TRIGGER events_no_update')
            c.execute("UPDATE events SET event_hash='invalid' WHERE seq=1")
        self.assert_denied(lambda:self.ledger.verify(),'AUDIT_CHAIN_INCONSISTENT')
    def test_materialized_state_tampering_detected(self):
        with self.ledger.transaction() as c:
            state=self.ledger.get(c,'current_state')
            state['active_stage']='FAKE'
            self.ledger.set(c,'current_state',state)
        self.assert_denied(lambda:self.ledger.verify(),'MATERIALIZED_STATE_INCONSISTENT')

    def test_export_does_not_contain_capability(self):
        exported=self.rt.export_spec()
        self.assertEqual(exported['contains_approvals'],False)
        self.assertNotIn(self.cap,json.dumps(exported))
    def test_resource_path_injection_fails(self):
        for path in ('../x','/etc/passwd','src/x/../../secrets','src/*','src\\dir','src\nsecret'):
            with self.subTest(path=path):
                self.assert_denied(lambda:self.rt.propose(self.proposal('bad','ROOT','A',[path])),
                                   'UNSAFE_RESOURCE')
    def test_semantics_remain_pending(self):
        p=self.proposal(semantic=['API tests pass'])
        out=self.rt.propose(p)
        self.assertEqual(out['semantic_pending'],['API tests pass'])
        self.assertEqual(out['status'],'ACCEPTED_NOT_ACTIVE')
    def test_wrong_stage_dependency_denied(self):
        self.rt.propose(self.proposal('B1','ROOT','B',['src/client/**']))
        self.assert_denied(lambda:self.rt.activate('B1',self.cap),'PREDECESSOR_NOT_COMPLETE')
    def test_reopen_works_after_process_restart(self):
        rt=ContractRuntime(self.root,SQLiteEvidenceSink(self.path))
        self.assertEqual(rt.status()['task_id'],'test-task')
        self.assertEqual(rt.sink.verify()['event_count'],2)
    def test_no_contract_hook_modifications(self):
        self.assertFalse((self.root/'.codex').exists())
    def test_cli_subcommand_smoke(self):
        env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])}
        r=subprocess.run([sys.executable,'-m','clim_agent_guard.devpreview.cli','contract','status','--project',str(self.root)],
                         env={**env,'CLIM_HOME':str(Path(self.temp.name)/'different_state')},capture_output=True,text=True)
        self.assertEqual(r.returncode,2)
        self.assertIn('CONTRACT_NOT_INITIALIZED',r.stderr)
    def test_template_valid(self):
        self.assertEqual(template('single-module','src/api')['allowed'],['src/api/**'])
        self.assert_denied(lambda:template('single-module','../oops'),'UNSAFE_RESOURCE')

if __name__=='__main__':unittest.main()
