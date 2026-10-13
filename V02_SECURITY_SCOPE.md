# Developer Preview v0.2: bounded security claims and release criteria

| Capability | Current implementation | Remaining verification |
|---|---|---|
| Codex Hook installation | Writes project `.codex/hooks.json` while preserving other entries | Live Codex `/hooks` trust review and activation |
| Shadow | Logs hook proposals, observes watched effects without intentional deny | Confirm missing PostToolUse and native tools in real workflows |
| Guarded patch | Checks every declared patch target and protected patterns; calls actual Core pre/post | Real Codex multi-file patch, rename/add/delete, long runs, race/failure |
| Cross-tool | Guarded denies uninspected Bash; explicitly allowed Shell has no effect verification | Real alternate tools and native OS sandbox behavior |
| Ask | Deny with explanation + exact one-time human grant; NOT Codex native ask | User-initiated approval/retry UX |
| Effect residual | Change set vs declared targets among watched files; pre/post hashes | Coverage of other paths, process attribution, large repos |
| Token saving | None claimed | Actual usage telemetry and task success with/without CLIM |
| Correctness of normal coding | Single/multiple target patch unit tests | Independent-user task completion, FBR and installation UX |
| Durable/tamper-resistant policy | Same-user external directory only | OS protection and secure state/audit service |
| Windows | Unsupported (`fcntl` POSIX) | Windows-specific implementation |
| MCP | Existing experimental server remains separate | Productize in v0.3 and run multiple clients |

Codex `PreToolUse` currently does not implement `permissionDecision=ask`; do not return it. Native hook responses may fail open on malformed output or timeout: must be fault-injection tested with the exact Codex build. Untrusted agent with access to the same user's `.codex/hooks.json` or CLIM state can bypass the adapter; do not claim an OS security boundary.
