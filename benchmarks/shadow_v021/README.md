# S1–S10 acceptance tooling

The supplied handoff is preserved under `handoff/`. It is a specification and
independent oracle, not an implementation patch or successful execution record.

See [the October 14 results](../../docs/shadow_v021_results_20261014.md) and
[the Shadow implementation notes](../../docs/shadow_v021.md).

`prepare_run.py` preregisters 24 disposable Git clones. `native_hook.py` measures
actual Hook processing and records clearly labelled test-only injection,
proposal-only veto and callback suppression. `trust_and_run.py` drives the real
native trust UI and then sequential Codex CLI sessions without bypass flags.
`run_track_a.py` is explicitly deterministic transport, not Codex evidence.

`review_run.py` performs mechanical fixture checks and retains unknowns. It
leaves human precision review unset. `export_review_bundle.py` excludes original
private prompts, complete client histories, canary values and patch diff bodies.
Review the export before sharing. `verify_evidence.py` opens only archived files.

CLI permission requests must be checked against the actual native contexts; the
October 14 leading `-a never` request was recorded as effective `on-request` in
every turn. Both paired arms used the same actual policy. Never infer sandbox or
approval policy only from a requested flag.

Archive tests accept `CLIM_SHADOW_EVIDENCE=/path/to/private/review-bundle`; private
data is not required for ordinary repository test collection.
