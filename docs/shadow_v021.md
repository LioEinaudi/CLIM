# Shadow-first v0.2.1 preview

Shadow returns no execution decision. It records proposals, samples registered
file effects and distinguishes host authorization from tool declarations.
The Core engine and Guarded checks are unchanged; Guarded remains experimental.

```bash
clim init codex --project /tmp/disposable-project
# Review/trust both generated handlers in Codex /hooks.
clim observe --project /tmp/disposable-project --inventory /tmp/inventory.json \
  --authorized /tmp/authorized.json --required /tmp/required.json
clim report --project /tmp/disposable-project --today --limit 50
clim doctor --project /tmp/disposable-project
```

Inputs are JSON path lists (or `{"paths": [...]}`) outside the project, supplied
by the host. Without registered authority the report says `AUTHORITY_UNKNOWN`;
it never substitutes proposal paths. `E_required` is independent of permission.
File-level `R_proposal`, `R_authority` and `R_missing` are separate. Required
effects outside verifiable coverage are unknown, rather than falsely missing.

`W` is bounded to 250 files and 4 MiB per file. Explicit inventories include
ordinary third files; default discovery skips `.git`, `.codex`, dependencies,
build outputs and virtual environments. Reports name actual scan limits,
oversize/unreadable/link paths and missing callbacks. Shell risk cues describe
proposal text; the adapter does not parse arbitrary Shell resource semantics.

Git baseline is fixed at the first observation of each native session. It records
dirty names and added-line hashes, never private diff text. Later edits by the
same agent do not become a new user dirty baseline.
Touching a dirty file is a risk signal. A disappeared baseline line yields
`POSSIBLE_LOST_WORK`, with uncertain attribution; unchanged or retained hunks
are not labelled lost work. This is not a line-level authorization engine.

Symlink spelling and hashed destination metadata are recorded without following
links for content. Link target changes yield `TOCTOU_UNCERTAIN`. No resolve-based
race prevention or external-target effect proof is claimed. All file deltas say
`ATTRIBUTION_UNCERTAIN`; separate native receipts/operator evidence are needed
to review causation. Other processes may change sampled files.

An unmatched pending pre-event appears as `UNKNOWN / missing_post` in report and
doctor. Shadow retains it and continues later operations without denial. It
does not silently invent a verified result. Pending/history storage is retained
until explicit reconciliation or purging, and is not a bounded production store.

Default telemetry omits full commands, patch bodies, native output and transcript
paths. It retains identities, relative file names, SHA-256, observation metadata
and timings. File state/audit permissions are 0600; directory separation is not
tamper resistance. Raw native Codex transcripts are client-owned and may contain
private input. Existing pre-v0.2.1 raw logs and original third-party Hook config
backups are not rewritten automatically; review legacy data separately.

Retention is until explicit `clim uninstall --purge-state`; uninstallation alone
preserves evidence. Export only reviewed/redacted records. Sampling a sensitive
write is not proof of read, exfiltration detection or full filesystem coverage.

The S1–S10 handoff and independent oracle are preserved under
`benchmarks/shadow_v021/handoff/`. Static checks, deterministic Hook inputs and
real Codex sessions are separate tracks. Do not claim the full matrix passed
until real execution, independent effects, privacy checks and paired task/performance
results establish every requirement.
