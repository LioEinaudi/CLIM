"""Deterministic synthetic demonstration; never claims to be a native Codex run.

Usage (after `python -m pip install -e .`):
    python benchmarks/shadow_v03/demo_reconciliation.py
    python benchmarks/shadow_v03/demo_reconciliation.py --json
"""
from __future__ import annotations
import argparse
import json
from clim_agent_guard.devpreview.reconciliation import build_review, render_card


def generate_demo_events() -> list[dict]:
    def event(phase, use_id, tool, **kw):
        return {'timestamp': '2026-10-18T11:00:00+00:00',
                'phase': phase, 'mode': 'shadow', 'session_id': 'DEMO-NOT-REAL-CODEX',
                'tool_use_id': use_id, 'tool': tool, **kw}
    events = []
    events.append(event('PRE','ordinary','apply_patch',E_proposed=['src/pricing.py'],
                        targets=['src/pricing.py'],E_authorized=None,authority_source='AUTHORITY_UNKNOWN',
                        signals=[],W={'gaps':[]},proposal={'protected_proposed':[]}))
    events.append(event('POST','ordinary','apply_patch',decision='OBSERVED',signals=['EFFECT_OBSERVED'],
                        effect={'E_proposed':['src/pricing.py'],'E_observed':['src/pricing.py'],
                                'E_authorized':None,'R_proposal':[],'R_authority':None,
                                'protected_changed_paths':[], 'coverage_gaps':[],
                                'attribution':'ATTRIBUTION_UNCERTAIN'}))
    events.append(event('PRE','deviation','apply_patch',E_proposed=['src/pricing.py'],
                        targets=['src/pricing.py'],E_authorized=None,authority_source='AUTHORITY_UNKNOWN',
                        signals=[],W={'gaps':[]},proposal={'protected_proposed':[]}))
    events.append(event('POST','deviation','apply_patch',decision='OBSERVED',
                        signals=['PROTECTED_TARGET_CHANGED','DEFAULT_PROTECTION_CONFLICT'],
                        effect={'E_proposed':['src/pricing.py'],'E_observed':['src/pricing.py','config.prod.json'],
                                'E_authorized':None,'R_authority':None,'R_proposal':['config.prod.json'],
                                'protected_changed_paths':['config.prod.json'],'coverage_gaps':[],
                                'attribution':'ATTRIBUTION_UNCERTAIN'}))
    events.append(event('PRE','shell','Bash',E_proposed=None,targets=None,E_authorized=None,
                        authority_source='AUTHORITY_UNKNOWN',signals=['UNINSPECTED_SHELL'],
                        risk_signals=[],W={'gaps':[{'reason':'unwatched_tool'}]},
                        proposal={'protected_proposed':[]}))
    events.append(event('POST','shell','Bash',decision='UNKNOWN',signals=['UNINSPECTED_SHELL'],
                        effect={'E_proposed':None,'E_observed':[], 'E_authorized':None, 'R_proposal':None,
                                'R_authority':None,'protected_changed_paths':[],
                                'coverage_gaps':[{'reason':'unwatched_tool'}],
                                'attribution':'ATTRIBUTION_UNCERTAIN'}))
    events.append(event('PRE','missing','apply_patch',E_proposed=['src/tests.py'],
                        targets=['src/tests.py'],E_authorized=None,authority_source='AUTHORITY_UNKNOWN',
                        signals=[],W={'gaps':[]},proposal={'protected_proposed':[]}))
    return events


def main():
    p=argparse.ArgumentParser();p.add_argument('--json',action='store_true');a=p.parse_args()
    print('SYNTHETIC FIXTURE ONLY — not a real Codex run, not a CLIM detection claim')
    review=build_review(generate_demo_events(),pending_gaps=[{'reason':'missing_post'}])
    print(json.dumps(review,indent=2,ensure_ascii=False) if a.json else render_card(review))


if __name__=='__main__':
    main()
