# CLIM v0.3 Sprint — Execution Reconciliation Review (working draft)

> Prepared against main `5f754d1050389cd0e88bbd4e95e6873f56def90e`, with file baselines from Oct 15 source snapshot. Additive offline prototype; **not merged, not native-Codex accepted**.

## Product contract

- Default no per-task scope form. `clim init codex` still needs local installation, native Hook inspection and explicit trust.
- High-signal review, not automatic code-quality verification. CLIM observes and reconciles supported actions and file effects, and says UNKNOWN when it cannot verify.
- No invented permission: `E_proposed` is NEVER authorization; `E_authorized=null` is `AUTHORITY_UNKNOWN`.
- A file modified during a Hook window is **temporally observed**, not necessarily changed by that Agent; return `ATTRIBUTION_UNCERTAIN`.
- Keep v0.2.1 raw JSON and audit evidence intact. `clim reconcile` remains an acknowledgement operation.

## Implementation staged for review

1. `clim report --format card`: additive, read-only, no external service. Group each `(session_id, tool_use_id)` PRE+POST pair as one audit window. Rank actual observed protected paths and proposal/effect differences above routine changes. Missing POST => UNKNOWN. Shell lexical hints explicitly neutral, not execution proofs.
2. `shadow.git_dirty()` staged/unstaged/untracked expansion: refresh baseline at first session observation only. Hash user edits and keep dirty status kind; never include private diff content.
3. Synthetic maintainer-like test matrix and sample report under `benchmarks/shadow_v03`. CI required before changing default UI.

## Jinbin P0: review / integration / real native acceptance

- [ ] Apply serial patches to a fresh branch based on verified `main`, inspect commits, validate that the snapshot-backed files still match. No automatic remote changes from this handoff.
- [ ] Verify 3.10/3.12 CI full offline suite; all old tests must remain collected, private archive cases SKIP only when evidence unavailable.
- [ ] 2 disposable real Codex repositories, 1 normal source task and 1 controlled extra observed path. Preserve native Pre/Post receipts, independent filesystem oracle, all missed hooks, report JSON and new card outputs. DO NOT disguise controlled fault injection as spontaneous Agent wrongdoing.
- [ ] Validate at least one real staged-only + one untracked dirty file preserved during Agent edits. Verify path spaces, symlinks, missing Post, and no canary plaintext leaks.
- [ ] Check report latency on 250 watched paths and large repo Git status. Time only end-to-end operations with precise environment, no blanket 'zero overhead'.
- [ ] Compare report content to original audit events and Git porcelain. Review whether severity prioritization causes noise or hides important unknowns. At least 10 task reports with operator review before default-card migration.
- [ ] Design and test *nonblocking native PreToolUse notice* separately. Should only notify for high-confidence explicit target-risk events, not routine `pwd`, formatter churn, or literal printed `rm -rf`. Leave Shadow tool permission unchanged.
- [ ] Consider `clim report` default card + `--format json` only **after** scripts, CI and first-run documentation are updated. Preserve machine JSON affordance explicitly.

## Jinbin P1: future PR preflight adapter (DO NOT claim present)

- If repository contains just an incoming PR Git diff, return `GIT_ONLY / TRACE_NOT_AVAILABLE`; do not infer use of Codex/Claude, task intent, or authorship.
- Compare `base...head` plus independently inspect target commit, highlighting config/tests/dependencies/CI paths as reviewer attention flags, not automatic violation verdicts.
- Support optional, independently verified Hook evidence bundle: upgrade labels to `HOOK_EVIDENCE_AVAILABLE` only after checking session association, integrity and completeness; absence remains UNKNOWN.
- Fail safe around forks, GitHub Actions secrets, untrusted PR code execution, symlinks, renamed files, shallow history, missing merge-base, oversized diffs, and worktree dirt.
- Benchmark head-to-head against git diff-only and Overscope using identical tasks; report measured false positives, reviewer time and missed changes, never marketing assumptions.

## Strict acceptance invariants

- `AUTHORITY_UNKNOWN` never rendered as a verified scope violation.
- `UNDECLARED_OBSERVED_CHANGE` is observed outside *the tool proposal*, not confirmed attacker attribution.
- A PRE proposed protected target is not presented as an actual protected write.
- Missing Post, Shell blind spots, unrelated writers, skipped paths and inventory limits explicitly remain unknown.
- No raw secrets/command bodies in default report; audit retained; path names are sanitized for terminal display.
- A `GIT_ONLY` report must not show invented Pre/Post provenance.
- Experimental Guarded remains experimental; no default denials.
