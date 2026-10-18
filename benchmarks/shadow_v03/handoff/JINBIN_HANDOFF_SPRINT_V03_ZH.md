# 交给 Jinbin：CLIM v0.3 Sprint — 一键效果对账卡片

**依据**：`LioEinaudi/CLIM`，GitHub `main` 提交 `5f754d1050389cd0e88bbd4e95e6873f56def90e`（2026-10-16）；修改的生产源文件的 Git blob 与当前 `main` 已核对。2026-10-18 生成的本地候选补丁，尚未合并或部署。

## 决策边界

1. **主入口仍叫 `clim report`**。`clim reconcile` 现在的意义是操作员确认/清除 pending / incident，**禁止重定义**成展示报告，以免修改具副作用的命令语义。
2. 第一阶段增加 **`clim report --format card`**，保持原默认 JSON 完全不变；原生验证通过以后，再由 Jinbin 审核是否在 v0.3 切换为默认 card，另保留 `--format json`。
3. 不要求用户每次手动创建 Scope。若宿主未注册可信授权：**AUTHORITY_UNKNOWN，不显示已证明 OUT_OF_SCOPE**。可显示 `UNDECLARED_OBSERVED_CHANGE` 和 `PROTECTED_TARGET_CHANGED`（仅样本观测范围内）。
4. 终端卡片按 `(session_id, tool_use_id)` 合并 PRE/POST，展示 Proposed / Observed / Unknown；普通事件与不完整 Shell 不重复刷屏。
5. 编码 Agent 个人用户是 v0.3 首批受众。ROS/Linux/LLVM/Python/JS Maintainer 的第三方 PR 通常没有原生 Hook 数据；PR 预检是 **P1 独立适配器**，必须区分 `GIT_ONLY` 与 `HOOK_VERIFIED`，不能虚构 Agent 因果轨迹。

## 补丁分工（请按序检查）

- `0001`：`clim_agent_guard/devpreview/reconciliation.py` 及 `cli.py` 的 `--format card`；只读，保留 JSON。
- `0002`：将前次 v0.2.2 暂缓的 staged/unstaged/untracked Git baseline 补丁集成进 `shadow.py`（代码来自此前可选补丁，经本地复测，注意审查 Git 边界行为）。
- `0003`：离线 pytest 测试、独立演示脚本和设计/验收说明；演示数据**明确是合成 fixture**，不能用作真实 Codex 运行截图。

解压后在工作树根执行：

```bash
# 在新分支使用，切勿直接操作生产工作区
for p in /path/to/patches/000*.patch; do git apply --check "$p" && git apply "$p"; done
python -m pip install -e '.[dev]'
python -m pytest -q .
python benchmarks/shadow_v03/demo_reconciliation.py
clim report --project /path/to/test-repo --format card --limit 20
clim report --project /path/to/test-repo --format json --advanced
```

注意：文件同时提供 `combined-preview.patch` 便于审核，但**不要再与串行补丁重复应用**。

## 验收分段

### Track A — 我方本地离线（已执行）

- 新增 12 项确定性 pytest 检查：混合多文件变更、已登记授权、Shell 盲区、缺 Post、Pre-only 风险、重复 Hook、Git 三种状态、JSON 兼容、终端转义。
- 全套离线 pytest：**179 passed / 3 skipped**（3 项需历史私有评审包），环境 Python 3.13.5。只证明候选源码及离线夹具可运行，不代表 Python 3.10/3.12 或 Codex 原生验收。
- 真实 Git 临时仓库验证 staged / unstaged / untracked；不需要私有源文件。

### Track B — Jinbin 必做原生验证（未执行）

- [ ] 固定版本及实际 Codex CLI、模型/effort/审批/沙箱生效上下文，记录真实 argv 与原生收据；如果与预注册不符立即停止。
- [ ] 最少两次真实 Codex CLI：普通合法 Patch + 明确标注的受控对照；保留独立 oracle、完整 Pre/Post Hook 收据、差异路径、原始 JSON、卡片输出。
- [ ] 更复杂的 PR-like 夹具：至少 300 文件的 repo 中执行多文件修改（不强制真实改 300 个文件）、已有 Dirty State（staged/untracked）、Shell 难解释的副作用及缺 Post。
- [ ] 确认 Shadow 本身 0 Denials，Pre/Post 计数不能伪称为全部工具调用覆盖率。
- [ ] 使用真实操作者检查 10 份报告，统计关键变化被突出显示的准确率、无效警报数和哪些高风险项目被折叠；发现风险则调整展示阈值。
- [ ] 记录 p50/p95 的 Hook 与报告生成时延；做隐私 canary 检查。历史私有证据不应被覆盖。
- [ ] 真实 CI 在 Python 3.10 + 3.12 成功，保留旧测试清单和 JUnit。

### Track C — 发布前必须关闭的剩余问题

- `Pre-Execution Risk Notice` 当前仅存在 Pre 事件可见的风险证据，**实时面向用户的提示尚未实现**。需要在原生 Codex Host 上设计最小不阻断提示与抗刷屏策略，不能把事后卡片说成实时拦截。
- `Git-only PR preflight` 尚未实现。不可把只含 Git Diff 的外部 PR 称作 Hook 验证或可信因果审计。
- `ATTRIBUTION_UNCERTAIN` 要保留；其他同用户进程可能同时写文件。
- 调整 README 文案：先展示真实 CLI 卡片与使用命令，限制 `No per-task scope required` 的含义；不宣称 100% 覆盖、防篡改、自动安全或减少一半 Review 时间。
- 当上述 Track B 与 C 的 P0 验收完成再决定转为 v0.3，期间不可把合成演示当作发布验收。

## 未来 Maintainer 适配建议（不在当前合并范围）

对于外部 PR，第一阶段以 Git-only 路径展示配置改动、核心测试删除、锁文件/CI 改动、隐式依赖和 diff 边界，同时允许人工设定审查规则。没有贡献者可信提供的 Hook 轨迹，就无法证明 Agent 的实际工具调用和原始任务 Scope。明确告知该限制，避免维护者误将“静态 PR 扫描”视为“已验证的执行因果链”。
