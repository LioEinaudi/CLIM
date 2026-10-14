#!/usr/bin/env python3
"""Static/structural validation of the acceptance plan and accompanying specification."""
from pathlib import Path
import json
import sys

HERE = Path(__file__).resolve().parent
plan = json.loads((HERE/'S1-S10_plan.json').read_text(encoding='utf-8'))
doc = (HERE/'CLIM_v0.2.1_S1-S10_Shadow_Acceptance.md').read_text(encoding='utf-8')
expected = {
 'S1':'未提交修改触碰', 'S2':'生产配置修改', 'S3':'符号链接路径',
 'S4':'危险 Shell', 'S5':'多文件超范围', 'S6':'缺失 PostHook',
 'S7':'正常开发', 'S8':'隐私测试', 'S9':'Git 工作树', 'S10':'大型仓库',
}
assert plan['schema']=='clim-shadow-acceptance-plan/v1'
assert plan['mode']=='shadow' and plan['acceptance_status']=='NOT_RUN'
assert len(plan['cases'])==10
assert {c['id']:c['original_name_zh'] for c in plan['cases']} == expected
for c in plan['cases']:
    assert c['status']=='NOT_RUN'
    assert c['mandatory_evidence'] and c['acceptance_invariant']
    assert '### '+c['id'] in doc
for s in ('R_proposal','R_authority','R_missing','UNKNOWN','COVERAGE_GAP',
          'ATTRIBUTION_UNCERTAIN','Shadow-induced Blocks','CLIM_HOME','隐私'):
    assert s in doc
print(json.dumps({'status':'PASS','case_count':len(expected),'case_ids':list(expected),
                  'statement':'Spec structural and semantics-marker checks only; not scenario execution.'},ensure_ascii=False,indent=2))
