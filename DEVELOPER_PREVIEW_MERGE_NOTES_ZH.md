# CLIM Developer Preview v0.2 开发补丁 — Jinbin 交付说明

以下为原补丁交付时的说明。现已完成合入与真实 Codex 工作流验收，当前结果见 [2026-10-13 报告](docs/developer_preview_v02_results_20261013.md)；原始 ZIP 和校验值保留在证据包中。

## 已开发与本地验证

基于 `LioEinaudi/CLIM` 的公开主分支 `clim_agent_guard/core.py`（SHA ff74fe755971eb2a1d600e7a291c50f5588e7a38）以及 2026-10-12 Codex Pilot 公开证据包中的相同源码快照。本补丁没有改动 CLIM Core、现有 Codex Pilot、MCP Pilot 和已有实验数据。新增 `clim_agent_guard/devpreview/`、新测试、新文档，更新仓库 `pyproject.toml` 来注册 CLI 并暂用 `0.2.0.dev0` 版本号。**没有写入远端仓库**。

本地真实 CLIM Core + Python 3.13 运行测试：`60 passed`（包含原 Core 与 Phase-1 审计测试 41 项、新产品测试 19 项；本地重建过程中曾需补齐 `contracts/refund_order.json` 测试 fixture，但该文件在 Jinbin 仓库里原本就有）。Python 安装 `pip install --no-deps --no-build-isolation -e .` 成功，`clim demo` 成功，新增 subprocess Hook JSON 测试成功。尚未在 Codex CLI 中执行 v0.2 原生实跑、Windows 验收或真实多文件重构压测。

## 合入步骤

1. 先在 Jinbin 仓库开启新分支 `feat/developer-preview-v02`，备份现有项目配置。
2. 解压本 ZIP 的内容到仓库根目录。ZIP 中 `pyproject.toml` 是依据当时的 v0.1.3 版本生成；如果上游文件已更新，请**手动合并** `[project.scripts]` 和版本号，不要覆盖新依赖和版权配置。不要用本 ZIP 覆盖根 README；只从 `docs/developer_preview_v02_README_SNIPPET.md` 摘取首页内容。
3. `python -m pip install -e .`，运行 `python -m pytest -q tests/test_developer_preview_v02.py`，再运行全部现有仓库回归。
4. 在**一次性项目**运行 `clim init codex`，在 Codex TUI `/hooks` 人工审查和信任；执行 `docs/developer_preview_v02.md` 的 R0–R8 验收矩阵并记录真实工具回执。
5. 若真实 Codex 有 Hook event 的字段/别名差异，只调整接入层，不要改变 Core 授权语义。
6. 复测 `clim uninstall` 对第三方 Hook 的保留，确认项目源码无意外更改。

## 重要未完成项（不可提前承诺）

- 未提供生产级受保护的权限隔离：策略与账本在本地同一用户目录；有不受限 Shell 权限的 Agent 可能绕过。
- Shadow 是**有限覆盖观察**，非文件系统审计器；也不自动阻止操作。
- Ask 使用“先 deny、人工 permit-once、再重试”，不是 Codex 原生弹窗。
- Guarded 默认拒绝未经人工明确授权的 Shell；运行 pytest/build/依赖工具存在摩擦；需要测试任务成功率与用户体验。
- PostToolUse 仅对已监测文件效果核对，不是全工作区保证；如 post 未回调会保留 pending，需要人工确认。
- 未引入 MCP 正式 CLI（现有 SDK MCP Pilot 仍在 examples 中）；MCP 产品化属于 v0.3。
- 未有 DIR、Token 节省率、正常任务 FBR、真实延迟或“5分钟安装”用户实测。与研究报告不要混用。
- 上述 60 项测试是本地运行，不等于 Jinbin 的 Codex 实机验收。

## 技术设计

`policy.py` 处理所有 patch target 和 `authorized/observed` 文件集合差异（来自 AFIO/OBIO 的方法启发，但不修改其代码或 NARH 数学）；`hook.py` 持续状态、Core 预留和效果验证；`store.py` 管理锁、外部 JSON/ledger/evidence；`cli.py` 配置和报告。

**授权边界≠工具名**，但未经解析的 Shell 无法安全证明同一资源效果，严格模式默认拒绝。未来应用程序的护城河应是可共享的授权资源不变量和跨工具的真实效果核对，而不是给普通函数合成虚构的非结合残差。
