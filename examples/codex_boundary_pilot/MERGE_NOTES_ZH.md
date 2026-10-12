# CLIM Codex Hook Pilot — 合入说明

- 将 ZIP 中 `examples/codex_boundary_pilot/` 复制到 CLIM v0.1.3 根目录的 `examples/` 下，不覆盖 Core。
- 已实现真实 CLIM `precheck()`/`verify_effect()` 与独立台账，非 `assess()` 伪放行。
- 当前只支持单个 `apply_patch` 修改现有 `config.dev.json`；其他文件、批量 patch、Bash 一律拒绝。
- 运行 `python -m unittest discover -s examples/codex_boundary_pilot/tests -v` 与 `python examples/codex_boundary_pilot/run_demo.py`。
- `run_demo.py` 为 Codex JSON Hook 协议级模拟，不是实际 Codex 模型实验。实际测试需本地 Codex CLI，执行 README 中 `/hooks` 信任步骤。
- 无生产级 OS 边界、未知工具 Hook 覆盖、完整文件写入隔离，也没有跨 Windows 兼容；禁止将此稿包装为“Codex 100% 文件安全”。
