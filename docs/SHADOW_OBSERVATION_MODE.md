# CLIM — Shadow Observation Mode (read-only)

This page documents the separate, older Shadow observation and execution-reconciliation
workflow. **Shadow does not request native Host denial.** The Linux Community Alpha's
explicitly enabled, limited `apply_patch` stage-scope refusal mode is documented in
[the Alpha README](../README.md).

The following section preserves prior Shadow preview guidance; distinguish historical
version-specific statements from the current tested Linux Alpha.


The following describes the separate Shadow observation and reconciliation workflow.
Its notices do not enable the scoped refusal mode above. To use Shadow in a
project, run `clim init codex --project /path/to/your/project`, then review and
trust its project Hooks in Codex `/hooks` and complete a task before reporting.

### v0.3 preview: Execution Reconciliation Card (opt-in)

The v0.3 candidate adds a **read-only terminal summary** of supported Codex Hook
windows. The existing JSON report remains the default, so automation is not
silently broken. After installing a build containing this preview:

```bash
clim report --project /path/to/your/project --today --format card --limit 20
clim report --project /path/to/your/project --today --format json --advanced
```

The card distinguishes **Proposed** tool targets, **Observed** changes to sampled
files, and **UNKNOWN / coverage** gaps. A file changed outside the targets of
one tool call is **outside the proposal**, not necessarily outside the user's
task authorization. Only an independently registered host authorization can
support a trusted-scope residual. Even a matched file change does **not** prove
which process caused it or that the code is correct.

**Risk-display and noise policy (not a security severity score):**

| Card treatment | What appears | Meaning / action |
| --- | --- | --- |
| **Prominent: review first** | `TRUSTED_AUTHORITY_RESIDUAL` (only with host scope), `PROTECTED_TARGET_CHANGED`, `UNDECLARED_OBSERVED_CHANGE`, `POSSIBLE_LOST_WORK`, proposed protected targets, missing/unmatched or conflicting Hook callbacks, substantive coverage limits | Shown before neutral windows. A protected-path match is a review signal, **not proof of unauthorized action**. Lost-work and attribution findings retain uncertainty. |
| **Sampled / collapsed** | Routine observed edits, neutral `UNVERIFIED_SHELL` windows and `LEXICAL_RISK_ONLY` signals without a prominent finding | Up to **two** neutral windows are shown if the report has space; counts and original audit remain available. Lexical matches can flag printed text without an executed destructive command. |
| **No live pop-up by default** | Ordinary edits, unflagged operations and neutral Shell coverage notices | Shadow never intentionally denies tools. No pre-execution notice is sent unless the operator enables experimental notices; *silence is not proof of full coverage*. |

A card shows up to `--limit` windows, prioritizing review signals and reporting
**how many high-priority and neutral windows were collapsed**. Inspect full
structured evidence with `--format json --advanced`; do not interpret collapsed
items as clean or verified. `UNKNOWN`, missing Post, unreadable/oversize files,
symlink content, 250-path sampling and unsupported Shell semantics remain gaps.
Staged, unstaged and untracked Git state is sampled for the *initial session*
baseline, but that does not guarantee complete coverage or file authorship.
The default protection templates cover common `.env`, production configuration,
SSH-key name and `.git/**` patterns; **lockfiles and CI workflow files are not
automatically protected by those defaults**. An operator can register additional
patterns. In particular, `.git` contents are skipped by normal filesystem
inventory, so a `.git/**` policy pattern is not proof that Git internals were
observed.

**Optional pre-execution notice (experimental, off by default):**

```bash
clim notices on --project /path/to/your/project
# Later, to disable:
clim notices off --project /path/to/your/project
```

A notice is currently limited to **explicitly proposed protected targets in
supported `apply_patch` calls**. It does not block or rewrite a tool request.
Target sets are deduplicated, with at most eight notices per session. Native TUI
visibility has been checked; visibility in headless `codex exec --json` is **not
guaranteed**. Arbitrary Shell effects are **not** pre-interpreted or prevented.

This preview is designed for a human reviewer: it does not replace `git diff`,
code review, backups, or the native sandbox/permission system. Logs are local
metadata and persist until explicitly purged; see
[Known Limitations](KNOWN_LIMITATIONS.md). Other clients, including Claude
Code, have not yet undergone native integration acceptance for this feature.
