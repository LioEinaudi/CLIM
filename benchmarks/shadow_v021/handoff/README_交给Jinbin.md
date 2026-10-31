# 交接给 Jinbin — CLIM v0.2.1 Shadow S1–S10

**这是一套验收规范与独立证据对账工具，不是 CLIM v0.2.1 功能补丁，也不是 S1–S10 已通过的测试报告。** 任何没有真正触发真实 Codex Hook 的场景都不能记为真实验收 PASS。

## 内含文件

- `CLIM_v0.2.1_S1-S10_Shadow_Acceptance.md`：正式测试计划（原版十项、逐项夹具、步骤、PASS/FAIL、证据格式、指标/发布条件）。**从这里开始读。**
- `S1-S10_plan.json`：可机器核对的十项预注册清单，当前均为 `NOT_RUN`。
- `shadow_effect_oracle.py`：独立文件快照、三集合差异、Hook 事件一致性和假密钥隐私扫描工具（Python ≥3.10，无额外依赖）。**仅为交叉检验，不能归因给 Agent。**
- `check_matrix.py` 与 `test_shadow_effect_oracle.py`：矩阵结构检查及独立工具的离线单元测试。
- `v02_baseline_probe.py`：针对归档 v0.2 的**合成 Hook**基线缺口复现实验；只能用来说明 v0.2 缺什么，不能冒充真实 Codex v0.2.1 结果。
- `v02_baseline_gap_probe.json`：上述脚本的本地结果（供回归参考）。
- `v02_archived_evidence_verification.json`：原 v0.2 ZIP 的只读证据验证记录（113 个载荷、五个固定案例）。
- `SUMMARY_TEMPLATE.csv` 与 `METRICS_TEMPLATE.json`：十项验收记录及关键指标的空白模板；初始值均为 `NOT_RUN` 或 `null`。
- `sample_*.json`：对账命令的输入格式示例，不包含真实测试结果。

## 建议执行顺序

1. **锁定代码与环境**：新建 v0.2.1 开发分支，记录 commit 和 Codex 版本；全程在临时克隆项目与独立 `CLIM_HOME` 下测试，确认 Pre/Post Hook 已被信任。先参考报告的 P0 列表实现最小 Shadow 模型，不改动 CLIM Core 的既有 Guarded 行为。
2. **跑静态与离线结构校验**：

   ```bash
   python check_matrix.py
   python -m unittest test_shadow_effect_oracle.py -v
   ```

3. **回归 v0.2 能力**：在归档 v0.2 的 `source/` 目录执行已存在的 `test_developer_preview_v02.py`；仓库已有 Core 测试按其原生测试说明执行。独立基线缺口复现：

   ```bash
   python v02_baseline_probe.py --source /path/to/v02/archive/source
   ```

   该命令会创建并销毁临时 fixture，**不会运行 Codex**。它预期检测到：S2 旧字段将提案当授权、S3 symlink 显示不充分、S5 漏掉普通第三文件、S6 Shadow 缺 Post 未具名上报、S8 raw hook log 泄露假 canary、S10 监控有上限。修复后不能因旧版现象不再成立而把整个验收视为失败。

4. **用独立快照交叉核验真实用例**。注意先准备临时项目，再把两次快照输出放在**项目目录外**；inventory 必须在执行前固定且包含预期第三文件，不能事后追补“神奇捕获”。例如 S5：

   ```bash
   python shadow_effect_oracle.py capture --root /tmp/clim-s5-work \
       --inventory sample_inventory.json --out /tmp/clim-s5-evidence/before.json

   # 此处由 Jinbin 在真正的 Codex CLI + CLIM Shadow 下运行任务，
   # 并按规范注明所有受控注入和环境阻断；不可直接当作自动化已做完。

   python shadow_effect_oracle.py capture --root /tmp/clim-s5-work \
       --inventory sample_inventory.json --out /tmp/clim-s5-evidence/after.json

   python shadow_effect_oracle.py compare \
       --before /tmp/clim-s5-evidence/before.json \
       --after /tmp/clim-s5-evidence/after.json \
       --proposed sample_proposed.json \
       --authorized sample_authorized.json \
       --required sample_required.json \
       --out /tmp/clim-s5-evidence/independent_oracle.json

   python shadow_effect_oracle.py audit \
       --events /path/to/CLIM_HOME/projects/PROJECT_ID/events.jsonl \
       --out /tmp/clim-s5-evidence/audit_check.json
   ```

   先独立比较文件效果；之后再核实 Codex Trace/Hook ID，防止把其他进程的文件变化误归因到 Agent。注意 `compare` 中的 `--authorized` 必须来自**宿主预注册**，不是工具提案。

5. **S8 隐私检查**：将一次性假秘密放到项目外部 `canary.txt`（文件权限建议 0600），只检查 CLIM 生成的 state/report 路径，不扫描包含 canary 的测试输入或 Codex 本身原始转录：

   ```bash
   python shadow_effect_oracle.py privacy \
       --sentinel-file /tmp/clim-test-private/canary.txt \
       --path /tmp/clim-test-private/clim-state/ \
       --path /tmp/clim-test-private/clim-report.json \
       --out /tmp/clim-test-private/privacy_result.json
   ```

   输出 `plaintext_leak_count: 0` 是必须条件。CLI exit code `2` 表示发现泄漏，`3` 表示检查失败。**不应把 canary 文件、真密钥或原始私有 Hook transcript 上传至公开 GitHub。**

6. **执行 Track A/Track B**：先做十项确定性场景（含 S3 TOCTOU、S5 已标记的第三方注入）；再做真实 Codex 流程（特别 S7 Python/Node paired tasks），按文档逐项给出 `PASS / FAIL / INCONCLUSIVE / NOT_EXERCISED / BLOCKED_BY_ENV`。不得仅用自模拟 Hook 宣告“真实 Codex 已通过”。
7. **最终产出**：按主文档第 7 节组织 `summary.csv`、十组证据、指标、环境信息和独立校验报告。提交时必须附完整 source commit 与测试版本，并注明人工复核结论。

## 验收原则与注意事项

- **S2 的陷阱**：`WOULD_BLOCK` 并不意味着已经阻断或已有副作用；`R_authority` 不得从 `E_proposed` 代替计算。
- **S3 的陷阱**：`UNINSPECTABLE_PATCH` 不是完整 symlink 风险透明度；TOCTOU 未覆盖应写 gap，不宣称发现 Codex 某个特定厂商漏洞。
- **S5 的陷阱**：如果 `src/c.py` 是人为注入造成变更，能证明监测系统捕获了第三文件，却**不能证明 Codex 主动越界**。
- **S6 的陷阱**：真实缺 Post 是证据缺口，不是文件未修改。Shadow 不可因此主动 deny。
- **S8 的陷阱**：v0.2 的 `hook_events.jsonl` 保存完整输入，已有本地合成复现为泄漏；必须在推广 v0.2.1 前修正。
- **S10 的陷阱**：不能因为默认只跟踪有限文件就宣称“没有发生范围外修改”。

**提交 S1–S10 的验收报告时，建议先只私下发送给维护者审核，脱敏和权限检查通过后再决定公开哪些数据。**
