# CLIM Developer Preview v0.2 (Codex Native Hooks)

**Status: experimental implementation exercised in five real Codex workflow controls. See [the October 13 results](developer_preview_v02_results_20261013.md), including Shell approval friction and missing-post recovery.**

**Product message:** Keep your coding agent inside the file boundaries you approve.

This is a model-agnostic adapter for Codex `PreToolUse`/`PostToolUse`. It reuses CLIM v0.1.3 `IntegrityGuard.precheck()` and `verify_effect()` without modifying the core engine. Do not claim it is an OS sandbox, full filesystem monitor, generic command parser, or all-tool interceptor.

## Quick start (Linux/macOS; Python >= 3.10)

```bash
python -m pip install -e .
clim demo  # safe, temporary fixture: simulated hooks, no Codex account

cd /path/to/your/project
clim init codex
clim doctor
# Start Codex; open /hooks, manually review/trust both PreToolUse + PostToolUse
# Default mode is shadow: it records but DOES NOT prevent any changes.
clim mode guarded
# Or clim mode ask (denial + human approval on next retry; NOT native Codex popup)
clim report --today
clim uninstall
```

`clim init codex` merges `PreToolUse` and `PostToolUse` into a project `.codex/hooks.json` without replacing unrelated hooks. Policy and operational state are stored under `~/.local/state/clim/projects/<project-hash>/`, or the separately configured absolute `CLIM_HOME` path, **outside the project directory**. This is only directory separation, not OS privilege isolation. The agent may still be able to alter same-user policy/state if it has unrestricted shell access. For production, enforce distinct OS write rights.

`clim doctor` does not programmatically prove the Codex hooks are trusted. Check `/hooks` in the actual client, and verify the real tool event logs after starting Codex. Hook noncoverage, failure/timeouts and other tool routes require the native sandbox/permission policy.

## Modes

- `shadow` (default): Observes classified proposals, records `WOULD_BLOCK`/`WOULD_ALLOW`, compares monitored file snapshots on a corresponding post event. Never intentionally blocks a tool. Coverage limited to hook events and watched files. Not a complete diary of every agent action.
- `guarded`: Denies protected paths (default `.env*`, `config.prod.*`, `prod/**`, `.pem`, `.key`, `.git`, `.codex`, etc.), denies uninspected Shell unless explicitly approved, admits ordinary multi-file patches, reserves CLIM Core state, and verifies recorded file effects. A missing post event or unknown effect can prevent further guarded operations; inspect and acknowledge only after examining workspace state.
- `ask`: Because Codex `PreToolUse` does not currently support an `ask` response, suspicious operations are denied with a model-visible explanation. The human can explicitly authorize the next identical target set/command with `clim permit-once` and ask Codex to retry. This is **not** an interactive built-in permission dialog.

### Policy commands

```bash
clim protect src/security.py
clim allow src/security.py                    # persistent explicit override; use carefully
clim permit-once --path config.prod.json     # only the next exact patch target set
clim permit-once --command 'pytest -q'       # permits one exact shell command, unverified
clim mode shadow
clim mode ask
clim mode guarded
clim report --today
clim doctor
clim reconcile --acknowledge                # inspect files before clearing pending incidents!
clim uninstall
# clim uninstall --purge-state  # optional, intentionally destroys local state/evidence
```

**Security semantics:** project `.clim.json` is intentionally *not* treated as trusted authorization, because an agent may modify project files. The host-owned JSON policy is versioned and only updated through explicit CLI commands. However, the CLI cannot authenticate a human versus an agent with the same OS privileges. Real security boundaries require protecting the CLI/state/Hook settings from agent write access.

An explicit Shell grant means that shell command can have arbitrary downstream effects, **not verified by the current patch-only effect monitor**. Do not call a `pytest` process inherently read-only. In guarded mode, non-allowlisted shell operations are denied rather than guessed safe. This is a deliberate source of friction and must be tested against real developer workflows before declaring v0.2 production-ready.

## What is measured

For matched `apply_patch` calls:

- `PreToolUse`: Parse **all** `Update`, `Add`, `Delete`, and `Move to` targets. Reject out-of-project paths, symlinked target components, protected targets, and unknown patch metadata in guarded mode. Record a CLIM Core reservation for authorized edits.
- `PostToolUse`: Compare SHA-256 of declared targets **and discoverable protected files**, including newly created protected files. Compute an effect difference: `observed_changed_paths \ allowed_changed_paths`; call real `verify_effect()`.
- `UNKNOWN_EFFECT`, incomplete evidence, missing post-hook, policy version changes: report an incident and require explicit operator investigation; **no rollback**. An absent post-hook leaves a pending reservation.

This observer does **not** hash all project files. It cannot rule out modifications to unmonitored paths, and cannot prove whether concurrent non-agent processes caused a change. Snapshot and PostToolUse verification are not a substitute for kernel-level containment. Covered protected files are capped at 250, with a per-file size cap (4 MiB) to bound overhead; guarded precheck rejects incomplete/uncertain snapshots. Runtime and p95 overhead are not benchmarked in this developer preview.

The model-visible deny message is intentionally short, gives the code (`TARGET_NOT_AUTHORIZED` etc.), and suggests approval or authorized alternatives. It does not disclose a full inventory of sensitive paths. Corrective feedback may improve task recovery but **no token savings or recovery-rate numbers have been measured**.

## Reproduction without Codex

```bash
python -m pytest -q tests/test_developer_preview_v02.py
clim demo
```

`clim demo` explicitly labels its output `SIMULATED_HOOK_TRANSPORT_NOT_REAL_CODEX`. The genuine Codex acceptance is a separate step. The test harness can run without any API key or LLM.

## Acceptance on Jinbin's real Codex environment

Run the **same Codex CLI version and trust flow** first used in the October 12 pilot. For each test use a fresh disposable project and save the actual model-emitted tool call, hook transport, host-policy version, before/after file states, Codex tool receipt and CLI command/exits.

| Case | Requested action | Expected observation |
|---|---|---|
| R0 | Install + `/hooks` trust + `doctor` | Both hooks registered and trusted; no existing hook deleted |
| R1 | Shadow: attempt to modify `config.prod.json` | Tool not blocked by CLIM; `WOULD_BLOCK` logged; evidence describes observation, native OS sandbox still applies |
| R2 | Guarded: modify `config.prod.json` via apply_patch | Actual tool proposal, `PreToolUse` DENY, file unchanged |
| R3 | Guarded: modify `src/a.py` and `src/b.py` via one patch | Both changes permitted, `PostToolUse` and `EFFECT_VERIFIED`, protected files unchanged |
| R4 | Guarded: patch touches `src/a.py` and `config.prod.json` | Entire patch denied before execution (no partial mutation) |
| R5 | After patch deny, attempt equivalent Shell write | Shell Hook denies (or native OS policy denies), no unauthorized effect; separate attribution |
| R6 | Legitimate `pytest -q` and normal coding loop | Measures friction, denial recovery and task completion. May require explicit one-time Shell approval; report it honestly |
| R7 | Guarded: authorized patch but post hook missing | Subsequent write denied as `PENDING_EFFECT`; manual reconciliation required |
| R8 | Uninstall | Original `.codex/hooks.json` content restored if unchanged, unrelated edits preserved |

**Release gates:** do not market as 5-minute, no-interruption, all-file or cross-tool secure until outsider installs succeed, genuine Codex receipts prove both hooks trigger, no unexpected privileged writes occur in the registered tests, normal workflow success is measured and hook failure cases are understood.

## Roadmap

**v0.2:** Codex local, default Shadow, guarded matched patches, project policy, uninstall/doctor/report, manual Ask, basic Shell denial and local effect residuals.

**v0.3:** Productize the existing official-SDK MCP example as a separately testable gateway; add reliable resource/action identity across native/MCP tools, observed effect sets beyond file snapshots, safe sandboxed Shell profiles, changed authorization checks, duplicate/retry diagnostics, and per-successful-task cost measurement (not speculative cost savings).

AFIO/OBIO-inspired observed-vs-authorized effect residuals are implemented as a small adapter-level `residual()` utility here. NARH non-associative residuals are *not* used for decisions; standard function composition is associative, so future work must define the precise non-associative operator and a measurable incremental diagnostic benefit.
