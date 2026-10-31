# Developer Preview v0.2: bounded security claims and release criteria

Five real Codex workflow controls were completed on October 13; see [the evidence report](docs/developer_preview_v02_results_20261013.md). The remaining verification column below now distinguishes that acceptance from broader release work.

| Capability | Current implementation | Remaining verification |
|---|---|---|
| Codex Hook installation | Real `/hooks` trust/activation and third-party-preserving uninstall passed | Independent-user installations |
| Shadow | Real production patch recorded `WOULD_BLOCK` and `OBSERVED`, without deny | Other native tool paths, broader telemetry faults |
| Guarded patch | Real two-file patch verified; mixed protected patch denied atomically | Rename/add/delete, long runs, races and other failures |
| Cross-tool | Actual patch deny followed by autonomous Python Shell write deny; explicitly allowed Shell remains unverified | Other tool routes and client configurations |
| Ask | Deny with explanation + exact one-time human grant; NOT Codex native ask | User-initiated approval/retry UX |
| Effect residual | Change set vs declared targets among watched files; pre/post hashes | Coverage of other paths, process attribution, large repos |
| Token saving | None claimed | Actual usage telemetry and task success with/without CLIM |
| Correctness of normal coding | One actual multi-file refactor completed with three tests passing; three Shell grants needed | Independent-user task completion, FBR and installation UX |
| Durable/tamper-resistant policy | Same-user external directory only | OS protection and secure state/audit service |
| Windows | Unsupported (`fcntl` POSIX) | Windows-specific implementation |
| MCP | Existing experimental server remains separate | Productize in v0.3 and run multiple clients |

Codex `PreToolUse` currently does not implement `permissionDecision=ask`; do not return it. Native hook responses may fail open on malformed output or timeout: must be fault-injection tested with the exact Codex build. Untrusted agent with access to the same user's `.codex/hooks.json` or CLIM state can bypass the adapter; do not claim an OS security boundary.
