"""First-use diagnostics distinguish local requests from Host results."""
from clim_agent_guard.contract_runtime.codex_observer import process_event
from clim_agent_guard.contract_runtime.codex_setup import configure
from clim_agent_guard.contract_runtime.differential import LiveShadowDifferential
from clim_agent_guard.contract_runtime.doctor import contract_doctor
from clim_agent_guard.contract_runtime.live_watch import evidence_snapshot, render_live_card
from tests.test_contract_m3b import ready, payload


def test_watch_reports_request_without_fabricating_window_or_host_denial(ready):
    project, runtime = ready
    event = process_event(payload(), 'PreToolUse', project, enable_enforcement=True)
    report = evidence_snapshot(LiveShadowDifferential(runtime))
    record = report['local_denial_requests']['requests'][0]
    card = render_live_card(report)
    assert record['reason'] == 'CONTRACT_SCOPE_CONFLICT'
    assert record['receipt'] == event['enforcement']['receipt_id']
    assert '[DENIAL_REQUESTED]' in card and record['receipt'] in card
    assert 'Host unverified' in card and 'src/client/b.py' not in card
    assert report['windows'] == []
    assert runtime.status()['pending_windows'] == 0


def test_doctor_counts_are_bounded_historical_requests_and_do_not_assert_trust(ready):
    project, runtime = ready
    configure(project, action='install', enable_enforcement=True)
    process_event(payload(), 'PreToolUse', project, enable_enforcement=True)
    status = contract_doctor(project)
    assert status['enforcement_denial_requests'] == 1
    assert status['enforcement_event_scan_limit'] == 2000
    assert status['enforcement_events_scanned'] > 0
    assert status['last_enforcement_decision']['receipt']
    assert status['host_denial_confirmed'] == 'UNVERIFIED'
    configure(project, action='install')
    status = contract_doctor(project)
    assert not status['enforcement_configured']
    assert status['enforcement_health'] == 'ENFORCEMENT_DISABLED'
    assert status['enforcement_denial_requests'] == 1  # historical, not current protection


def test_doctor_does_not_report_zero_for_unknown_ledger_or_invalid_config(tmp_path, monkeypatch):
    project = tmp_path / 'project'; project.mkdir()
    monkeypatch.setenv('CLIM_HOME', str(tmp_path / 'home'))
    status = contract_doctor(project)
    assert status['enforcement_denial_requests'] is None
    assert status['enforcement_events_scanned'] is None
    (project / '.codex').mkdir()
    (project / '.codex' / 'hooks.json').write_text('{broken')
    status = contract_doctor(project)
    assert status['enforcement_configured'] is None
    assert status['enforcement_health'] == 'ENFORCEMENT_CONFIG_UNKNOWN'
