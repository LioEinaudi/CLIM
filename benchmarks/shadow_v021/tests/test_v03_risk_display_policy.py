"""Doc/UI release guardrails for the v0.3 card; no Codex client needed."""
from pathlib import Path
from clim_agent_guard.devpreview.reconciliation import build_review, render_card


def test_card_discloses_visibility_policy_and_non_enforcement():
    card=render_card(build_review([]))
    assert 'PROMINENT:' in card
    assert 'SAMPLE/COLLAPSE:' in card
    assert 'LIVE NOTICE: OFF by default' in card
    assert 'NOT a security severity or deny decision' in card
    assert 'No Hook record is not evidence that no file change occurred.' in card


def test_card_discloses_collapsed_high_priority_windows():
    events=[]
    for n in range(4):
        events.append({'phase':'PRE','mode':'shadow','session_id':'s', 'tool_use_id':f'u{n}',
                       'tool':'apply_patch', 'E_proposed':['config.prod.json'],
                       'signals':['DEFAULT_PROTECTION_CONFLICT']})
    card=render_card(build_review(events,max_items=2))
    assert 'High-priority windows collapsed: 2' in card
    assert 'MISSING_POST' in card
    assert 'No Hook record is not evidence' in card


def test_readme_documents_true_risk_policy_without_conflation():
    root=Path(__file__).resolve().parents[3]
    readme=(root/'README.md').read_text()
    for phrase in ['Risk-display and noise policy', 'Prominent: review first',
                   'Sampled / collapsed', 'No live pop-up by default',
                   'outside the proposal', 'not necessarily outside the user',
                   'clim report --project /path/to/your/project --today --format card',
                   'clim notices on', 'visibility in headless',
                   'Other clients, including Claude']:
        assert phrase in readme
