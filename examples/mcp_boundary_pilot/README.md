# CLIM MCP execution boundary pilot

This experimental stdio server uses the official MCP Python SDK, pinned at 2.3.0.
It exposes one tool, `clim_set_debug(path, debug, operation_id)`, and calls the real
CLIM `precheck()` before writing and `verify_effect()` after observing file hashes
and the resulting JSON value. The model does not supply host confirmation or the
authorized path. No changes to CLIM Core are required.

## Install and test without a model

From the repository root, with Python 3.10+ on Linux/macOS:

```bash
python -m pip install -e .
python -m pip install -r examples/mcp_boundary_pilot/requirements.txt
python -m unittest discover -s examples/mcp_boundary_pilot/tests -v
python examples/mcp_boundary_pilot/prepare_workspace.py --dest /tmp/clim-mcp-sdk-01
python examples/mcp_boundary_pilot/run_smoke.py --dest /tmp/clim-mcp-sdk-01
```

The smoke run starts a separate server process and connects through the official
SDK's real stdio transport. It tests production-config denial, development-config
effect verification, and duplicate-operation denial. Expected deny cases print
SDK tool-error messages. The final result must have `accepted: true`.
This is a protocol integration test with zero LLM calls.

## Test through Codex or another MCP client

```bash
python examples/mcp_boundary_pilot/prepare_workspace.py --dest /tmp/clim-mcp-codex-prod-01
cd /tmp/clim-mcp-codex-prod-01/project
codex
```

Review/trust the disposable project, then check `/mcp` for the active `clim` server.
Its project-scoped `.codex/config.toml` supplies the launcher and trusted-policy
environment. This test installs no Codex tool hooks: enforcement is inside the
MCP server. Ask Codex to call `clim_set_debug` exactly once with
`path="config.prod.json", debug=false, operation_id="codex-prod-01"`, report the
result, and stop without switching tools. Require an actual MCP call, an error
receipt containing `TARGET_NOT_AUTHORIZED`, and both files unchanged.

Prepare a **fresh** second workspace for the positive control. Call the same tool
with `path="config.dev.json", debug=false, operation_id="codex-dev-01"`. Require
`EFFECT_VERIFIED`, development JSON `debug=false`, and unchanged production JSON.

`client_mcp.json` contains the generated standard stdio launcher for clients that
accept an `mcpServers` configuration. Other clients may require a different config
location or UI import; use their own documented procedure. The server has no
dependency on the chosen model. Only independently executed client integrations
can establish that a particular host works; a generated config is not a test.

## Evidence and scope

The external `trusted-control/` contains host policy, initial hashes, the persisted
ledger, and `state/audit.jsonl` with operation IDs, server instance, pre/post
decisions, arguments and measured effects. Save the client's actual tool request
and result too. SDK smoke receipts are written to `sdk_smoke.json`.

This is a guarded MCP **tool**, not a universal interceptor for all tools in the
client. Native editing tools, shell, and other MCP servers remain separate paths.
To enforce an application-wide boundary, those paths must also be restricted by
the host/sandbox. Neither MCP support nor using a closed/open model proves this.
Post-effect uncertainty does not roll back changes. It creates an incident and
blocks future operations until an operator reconciles the state. The ledger is
saved before writing; unresolved reservations also block new operation IDs.

Only existing local JSON files are supported. POSIX locking serializes operations.
This pilot does not claim hostile symlink-race protection, arbitrary filesystem
coverage, Windows support, or production OS isolation. Its same-user sibling
policy/state folder is convenient experiment storage; production deployments must
place policy, code, ledger and audit outside the agent's write authority.

Protocol references: [official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/)
and [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).
