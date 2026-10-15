"""Regression checks for report uncertainty and native permission receipts."""
import importlib.util
import json
from pathlib import Path
from clim_agent_guard.devpreview import cli, policy

spec=importlib.util.spec_from_file_location('native_permissions',
    Path(__file__).resolve().parents[1]/'benchmarks/shadow_v021/permission_receipts.py')
permissions=importlib.util.module_from_spec(spec)
spec.loader.exec_module(permissions)


def test_business_id_source_is_not_a_default_private_key(tmp_path):
    patterns=policy.defaults(tmp_path)['protected']
    assert not policy.match('src/id_utils.py',patterns)
    assert not policy.match('id_map.py',patterns)


def test_basic_report_keeps_unknown_and_does_not_mutate_audit():
    event={'mode':'shadow','phase':'POST','decision':'UNKNOWN',
           'coverage_gaps':[{'reason':'unmatched_pre'}]}
    original=json.dumps(event,sort_keys=True)
    summary=cli._shadow_display_event(event)
    assert summary['observation_status']=='UNKNOWN'
    assert summary['coverage_gaps']==[{'reason':'unmatched_pre'}]
    assert json.dumps(event,sort_keys=True)==original
    assert cli._shadow_display_event(event,advanced=True) is event


def test_explicit_override_is_not_reported_as_protected_effect(tmp_path):
    from clim_agent_guard.devpreview import shadow
    root=tmp_path/'project';root.mkdir();target=root/'config.prod.json'
    target.write_text('old\n');store=tmp_path/'state';store.mkdir()
    pol=policy.defaults(root);pol['explicit_overrides']=['config.prod.json']
    patch='*** Begin Patch\n*** Update File: config.prod.json\n@@\n-old\n+new\n*** End Patch'
    event={'session_id':'override','tool_use_id':'patch','tool_name':'apply_patch',
           'tool_input':{'command':patch},'cwd':str(root)}
    assert shadow.prepare(event,root,store,pol,'k')=={}
    target.write_text('new\n')
    assert shadow.finish(event,root,store,pol,'k')=={}
    post=json.loads((store/'events.jsonl').read_text().splitlines()[-1])
    assert post['effect']['protected_changed_paths']==[]
    assert 'DEFAULT_PROTECTION_CONFLICT' not in post['signals']
    assert post['effect']['R_authority'] is None


def test_native_context_reader_excludes_prompt_and_checks_actual_policy(tmp_path):
    path=tmp_path/'rollout.jsonl'
    path.write_text(json.dumps({'type':'response_item','payload':{'secret':'private body'}})+'\n'+
        json.dumps({'type':'turn_context','payload':{'approval_policy':'on-request',
            'sandbox_policy':{'type':'workspace-write','network_access':False},
            'model':'test','effort':'medium','private':'never export'}})+'\n')
    contexts=permissions.contexts_from_rollout(path)
    receipt=permissions.permission_receipt(contexts,'never','run','test-version')
    assert receipt['policy_mismatch'] is True
    assert receipt['effective_policy']=='on-request'
    assert 'private' not in json.dumps(receipt)
    assert permissions.permission_receipt(contexts,'on-request','run','test-version')['policy_mismatch'] is False


def test_missing_or_mixed_native_receipts_never_confirm_a_request():
    assert permissions.permission_receipt([],'never','run','version')['policy_mismatch'] is True
    contexts=[{'approval_policy':'never'},{'approval_policy':'on-request'}]
    receipt=permissions.permission_receipt(contexts,'never','run','version')
    assert receipt['policy_mismatch'] is True
    assert receipt['effective_policy'] is None
