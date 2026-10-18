# CLIM v0.3 Execution Reconciliation — Prototype Fixtures

This folder is a **synthetic offline demonstration**, not a real Codex or Claude Code trace.

```bash
python -m pip install -e '.[dev]'
python benchmarks/shadow_v03/demo_reconciliation.py
python -m pytest -q benchmarks/shadow_v021/tests/test_v03_execution_reconciliation.py
```

The proposed additive CLI is `clim report --project /path/to/repo --format card`.
Default `clim report` remains v0.2.1 JSON until compatibility and real native
Hook validation are complete. `clim reconcile` is intentionally unchanged; it
acknowledges pending incidents and is **not** a review/report command.

The card collapses matching Pre/Post events, prioritizes observed protected-path
changes and proposal/effect differences, marks trusted-scope residuals only when
host scope exists, and surfaces missing Post / unknown Shell semantics. It is
not a security boundary, code-quality reviewer, complete filesystem inventory,
or reliable proof of causality. There is no built-in PR adapter or Claude Code
adapter in this prototype.

## Maintainer-like deterministic scenarios

1. 300 routine source windows + one extra observed production config change.
   Validate anomaly ranking, noise compression, and no invented authorization.
2. A real temp Git repo with staged, unstaged, and untracked files before the
   Agent's first window. Validate session-first dirty baseline coverage.
3. Uninspected Shell + missing Post + protected pre-proposal. Check UNKNOWN
   is not incorrectly counted as a safety verdict and proposals are never
   reported as completed effects.
4. Duplicate callbacks and terminal-escape-containing paths. Count one window,
   disclose inconsistent evidence, and never interpret a filename as terminal
   control characters.
5. Legacy JSON report compatibility. Existing raw `events.jsonl` is not changed.
6. A flood of 40 neutral Shell gaps collapses to two example windows while the
   summary retains the total count. A Git-only external PR has no invented Hook trace.

## Explicitly OUT of scope until subsequent sprints

- Receiving a third-party PR without native Hook evidence: compare Git changes
  but say `GIT_ONLY / TRACE_NOT_AVAILABLE`, not `HOOK_VERIFIED`.
- PreToolUse live user-facing notification (the prototype only shows pre-proposal
  signals in the later report; notification delivery needs native tests).
- Runtime enforcement / Guarded and Ask promotion to stable.
- Comprehensive Shell action prediction, multi-process attribution, artifact
  immutability, semantic code correctness, and review-time reduction claims.
