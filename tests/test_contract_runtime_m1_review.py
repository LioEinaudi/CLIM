"""M1 review regressions: local ledger semantics, never Native acceptance."""
from unittest import mock

import pytest

from clim_agent_guard.contract_runtime import ContractError
from tests import test_contract_runtime_m1 as fixtures


@pytest.fixture
def runtime():
    fixture = fixtures.TestM1()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


def test_nested_dependency_rejected_with_typed_error(runtime):
    with pytest.raises(ContractError, match='TRUSTED_DEPENDENCY_MISSING'):
        runtime.rt.propose(runtime.proposal(predecessors=[[]]))
    assert runtime.rt.status()['contract_versions'] == 1


def test_unencodable_proposal_rejected_and_audited(runtime):
    with pytest.raises(ContractError, match='INVALID_JSON_VALUE'):
        runtime.rt.propose(runtime.proposal(semantic=['\ud800']))
    rejected = [e for e in runtime.rt.history() if e['kind'] == 'CONTRACT_REJECTED']
    assert rejected[-1]['data']['code'] == 'INVALID_JSON_VALUE'
    assert runtime.rt.status()['contract_versions'] == 1
    runtime.ledger.verify()


def test_partial_window_index_rewrite_detected(runtime):
    runtime.rt.propose(runtime.proposal())
    runtime.rt.activate('A1', runtime.cap)
    runtime.rt.begin_window(window_id='w1', session_id='s1', tool_use_id='t1',
                            targets=['src/api/a.py'])
    with runtime.ledger.transaction() as conn:
        conn.execute("UPDATE windows SET status='CLOSED',coverage='COMPLETE_BOUNDED' "
                     "WHERE window_id='w1'")
    with pytest.raises(ContractError, match='WINDOW_INDEX_INCONSISTENT'):
        runtime.ledger.verify()
    with pytest.raises(ContractError, match='WINDOW_INDEX_INCONSISTENT'):
        runtime.rt.recover()


def test_verify_uses_one_snapshot_during_valid_concurrent_commit(runtime):
    connect = runtime.ledger._connect
    committed = []

    def reader_connection():
        conn = connect()

        def trace(sql):
            if sql == "SELECT value FROM metadata WHERE key='current_state'" and not committed:
                committed.append(True)
                runtime.rt.propose(runtime.proposal())

        conn.set_trace_callback(trace)
        return conn

    with mock.patch.object(runtime.ledger, '_connect', reader_connection):
        result = runtime.ledger.verify()
    assert committed == [True]
    assert result['integrity'] == 'LOCAL_CONSISTENCY_ONLY'
    # The reader saw the old snapshot, the writer still committed successfully.
    assert result['event_count'] == 2
    assert runtime.ledger.verify()['event_count'] == 4


def test_corrupt_sqlite_cli_returns_actionable_error(runtime, monkeypatch, capsys):
    from clim_agent_guard.contract_runtime.cli import handle
    from argparse import Namespace

    bad = runtime.path.parent / 'bad.sqlite3'
    bad.write_bytes(b'not a SQLite database')
    from clim_agent_guard.contract_runtime import cli
    monkeypatch.setattr(cli, 'project_store', lambda root: runtime.path.parent / 'bad_store')
    target = runtime.path.parent / 'bad_store/contract_runtime'
    target.mkdir(parents=True)
    (target / 'ledger.sqlite3').write_bytes(bad.read_bytes())
    assert handle(Namespace(contract_action='status', project=str(runtime.root))) == 2
    captured = capsys.readouterr()
    assert 'SQLITE_STORAGE_ERROR' in captured.err
    assert 'Traceback' not in captured.err
    assert (target / 'ledger.sqlite3').read_bytes() == bad.read_bytes()


@pytest.mark.parametrize('mutation', [
    "UPDATE windows SET tool_use_id='other-tool'",
    "UPDATE windows SET coverage='COMPLETE_BOUNDED'",
    "UPDATE windows SET closed_seq=1",
    "DELETE FROM windows",
])
def test_window_identity_and_lifecycle_index_match_history(runtime, mutation):
    runtime.rt.begin_window(window_id='w1', session_id='s1', tool_use_id='t1',
                            targets=['src/api/a.py'])
    with runtime.ledger.transaction() as conn:
        conn.execute(mutation)
    with pytest.raises(ContractError, match='WINDOW_INDEX_INCONSISTENT'):
        runtime.ledger.verify()


@pytest.mark.parametrize('mutation', [
    "UPDATE contract_versions SET status='CLOSED' WHERE contract_id='ROOT'",
    "UPDATE contract_versions SET revision=2 WHERE contract_id='ROOT'",
    "DELETE FROM contract_versions WHERE contract_id='ROOT'",
])
def test_contract_identity_revision_and_status_match_history(runtime, mutation):
    with runtime.ledger.transaction() as conn:
        conn.execute('DROP TRIGGER versions_no_update')
        conn.execute('DROP TRIGGER versions_no_delete')
        conn.execute(mutation)
    with pytest.raises(ContractError, match='CONTRACT_HISTORY_INCONSISTENT'):
        runtime.ledger.verify()


def test_original_m1_window_without_event_tool_identity_is_explicitly_unverified(runtime):
    append = runtime.ledger.append

    def legacy_append(conn, kind, data, **kwargs):
        if kind == 'WINDOW_PRE_OBSERVED':
            data = {key: value for key, value in data.items() if key != 'tool_use_id'}
        return append(conn, kind, data, **kwargs)

    with mock.patch.object(runtime.ledger, 'append', legacy_append):
        runtime.rt.begin_window(window_id='w1', session_id='s1', tool_use_id='t1',
                                targets=['src/api/a.py'])
    with pytest.raises(ContractError, match='LEGACY_WINDOW_IDENTITY_UNVERIFIED'):
        runtime.ledger.verify()
