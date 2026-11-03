# Codex Scope & Retry Check — experimental pilot

This is a separate Linux experiment based on CLIM `v0.3.0a2`, not part of the released CLIM command or its default Hook. It asks what can actually be observed after a **controlled** out-of-stage Codex patch request. It does not claim that the model drifted spontaneously, stopped, wasted tokens, or crossed a production security boundary.

Review found that the released `0.3.0a2` parser treats the valid `*** End of File` patch hunk marker as unsupported; the observer then emits no denial. This experimental branch recognizes that marker and identifies its locally built package as `0.3.0a2+scopefix.20261103`. The original release and its tag are unchanged. The fix has offline coverage, not native Host verification, and other unsupported inputs and Shell remain outside the guard's coverage.

**Native status: NOT YET VERIFIED.** Offline tests and synthetic examples are not evidence that a Codex Host ran or refused a tool call. Do not publish a real boundary result until the actual Host response, matching CLIM receipt and independent file snapshots have been reviewed.

## Components

- `pilot.py` prepares a new disposable Git fixture, records bounded independent snapshots, parses Codex JSONL, and creates a short `share.md` plus local `result.json` and `technical.md`. Snapshot inputs and report outputs must remain outside the project. Snapshots bind to the same project using a local path digest; old snapshots without that digest need to be recreated.
- `attempt_capture.py` optionally wraps **only the installed CLIM PreToolUse handler in this fixture**. It forwards the delegate's stdout, stderr and exit status, and records only per-run HMACed IDs, a fixture-only target, timings, a boolean indicating the hunk marker, and a hash of a CLIM *requested* denial receipt. It never turns that request into a Host denial. It does not alter CLIM's global/default Hook or trust a Hook. It observes only matched PreToolUse calls; Shell is not interpreted or blocked by this adapter.
- `review_manifest.py` records hashes of the project Hook, adapter, `pilot.py` dependency and installed CLIM runtime so the runner can detect changes after the operator's review. These hashes do not prove human review or Host enforcement.
- `run_headless.py` runs a fixed in-scope or controlled-conflict `codex exec --json` task with `workspace-write`, `on-request` approvals, ephemeral sessions and a 180-second default wall-clock limit (maximum 300). It requires the caller to attest that a human reviewed the exact Hook. That attestation is not proof of enforcement. A forced stop is labeled `HARNESS_TIMEOUT`, never a CLIM token guard.
- `verify_run_link.py` can correlate a separately captured **real** Host denial with one headless turn using the unique receipt hash, HMACed session identity, runner time bounds, and JSONL thread/turn boundaries. The generated link includes a local HMAC to detect accidental edits. Mismatch or missing evidence remains `UNKNOWN`; this is local correlation, not an authenticated attestation, since the operator holds the key. It never reads Codex's private session database.

`turn.completed.usage` is counted per completed turn. Cached input is a subset of input and reasoning output is a subset of output; neither is added twice. Missing optional fields, malformed JSONL, stream errors, a failed or unfinished turn produce `PARTIAL` where applicable. `tokens_after_denial` remains **NOT_AVAILABLE**: a completed-turn total cannot be attributed to a specific refused patch. If a Host result and JSONL cannot be linked to the same run, the share card does not combine their token figure with that Host result.

The statement in `pilot.py`'s generated metadata that its offline harness does not invoke Codex refers to `pilot.py` itself. The separately invoked, opt-in `run_headless.py` does launch Codex after human Hook review.

## Prepare a disposable fixture

Use a new path and a separately installed runtime built from this experimental branch, with version `0.3.0a2+scopefix.20261103`. The commands below change only the new fixture and its operator directory; they do not change the user's global Codex configuration.

```bash
CLIM_PILOT=/path/to/CLIM/experimental/scope_recovery_pilot
CLIM_FIXTURE=/tmp/clim-scope-retry-pilot-001
python3 "$CLIM_PILOT/pilot.py" prepare --root "$CLIM_FIXTURE" --acknowledge-disposable
CLIM_PROJECT="$CLIM_FIXTURE/project"
CLIM_OPERATOR="$CLIM_FIXTURE/operator"
CLIM_RUNTIME=/path/to/venv-containing-clim-0.3.0a2+scopefix.20261103
export CLIM_HOME="$CLIM_OPERATOR/clim-state"
export PATH="$CLIM_RUNTIME/bin:$PATH"
python3 "$CLIM_PILOT/pilot.py" snapshot --project "$CLIM_PROJECT" --out "$CLIM_OPERATOR/before.json"
clim contract bootstrap --project "$CLIM_PROJECT" --template code-only --scope 'src/game/mechanics/**' --acknowledge-scope
clim codex install-hook --project "$CLIM_PROJECT" --enable-enforcement
clim contract doctor --project "$CLIM_PROJECT"
python3 "$CLIM_PILOT/attempt_capture.py" configure --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --acknowledge-disposable
python3 "$CLIM_PILOT/review_manifest.py" --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --runtime "$CLIM_RUNTIME"
```

The fixture and operator directory are private by default. The adapter preserves a private copy of the original project Hook and creates a per-run capture key. Do not upload the operator directory.

## Human Hook review and real runs

On the same Linux host and account, open Codex in the disposable project with the same `CLIM_HOME`, use `/hooks`, inspect the project Hook, adapter, its `pilot.py` dependency and the review manifest, and personally decide whether to trust them. Trust belongs to the exact reviewed definition. Never use a Hook-trust or sandbox bypass for this pilot. The runner refuses to run without the operator's explicit review attestation and stops if the Hook, adapter, pilot dependency or installed CLIM runtime changed.

```bash
codex -C "$CLIM_PROJECT"
# In Codex: /hooks → inspect and trust the fixture Hook; then exit.
python3 "$CLIM_PILOT/run_headless.py" --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --runtime "$CLIM_RUNTIME" --phase in-scope --operator-attests-hook-reviewed
python3 "$CLIM_PILOT/run_headless.py" --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --runtime "$CLIM_RUNTIME" --phase conflict --operator-attests-hook-reviewed
```

Each invocation writes private JSONL, stderr, a final-message file if available, and run metadata under the operator directory. The two tasks are separate sessions; the in-scope run is a positive control, not part of the conflict turn's token total. A successful CLI exit or a CLIM `DENIAL_REQUESTED` entry does not prove a Host denial. `codex exec --json` may omit the refused tool output; inspect the actual Host output independently and save its exact text in `operator/native-host.txt` **only if it was actually obtained**. A model's description or an invented expected string is not Host evidence. Capture Watch output separately for receipt comparison.

If a unique real Host receipt is available, the optional adapter can normalize only the captured fixture events for the matching session. If the Host result was observed during this exact headless conflict run, verify the receipt/session/time/turn link before attributing its completed-turn usage:

```bash
python3 "$CLIM_PILOT/attempt_capture.py" normalize --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --host-feedback "$CLIM_OPERATOR/native-host.txt" --out "$CLIM_OPERATOR/attempts.jsonl"
python3 "$CLIM_PILOT/verify_run_link.py" --project "$CLIM_PROJECT" --operator "$CLIM_OPERATOR" --events "$CLIM_OPERATOR/conflict.codex-exec.jsonl" --run-metadata "$CLIM_OPERATOR/conflict.run.json" --host-feedback "$CLIM_OPERATOR/native-host.txt" --out "$CLIM_OPERATOR/run-link.json"
python3 "$CLIM_PILOT/pilot.py" snapshot --project "$CLIM_PROJECT" --out "$CLIM_OPERATOR/after.json"
python3 "$CLIM_PILOT/pilot.py" analyze --before "$CLIM_OPERATOR/before.json" --after "$CLIM_OPERATOR/after.json" --host-feedback "$CLIM_OPERATOR/native-host.txt" --watch-feedback "$CLIM_OPERATOR/watch.txt" --events "$CLIM_OPERATOR/conflict.codex-exec.jsonl" --attempts "$CLIM_OPERATOR/attempts.jsonl" --run-link "$CLIM_OPERATOR/run-link.json" --output-dir "$CLIM_OPERATOR/report"
```

Omit unavailable optional flags and do not manufacture missing files. If `codex exec` does not load/trust the same Hook, interactive Host proof and headless usage are different runs and must not be combined. If Host evidence is missing, the result is `UNKNOWN`; if later events cannot be linked, retry behavior is `UNKNOWN`. `NO_FURTHER_ATTEMPT_IN_CAPTURE` describes only captured events and does not prove the agent stopped. A repeated target attempt is not proof of a retry loop or of post-denial token cost.

For a trusted-fixture-only cleanup, `clim codex uninstall-hook --project "$CLIM_PROJECT"` removes CLIM-owned Hook definitions. Because this experiment wraps a CLIM handler, first restore the operator's `hooks-before-capture.json` to the disposable project's `.codex/hooks.json`, then invoke the CLI uninstall. Do not overwrite Hook definitions added by someone else; if they changed, inspect and remove the fixture manually.

## Offline checks

```bash
python3 -m unittest discover -s experimental/scope_recovery_pilot -p 'test_*.py' -v
```

Synthetic tests, including fake receipts and runner output, are labeled as synthetic and never count toward native Host acceptance. Public sharing must exclude raw transcripts, Hook payloads, private paths, receipt values and capture keys. Linux Codex `apply_patch` is the only claimed refusal scope; Hook failures can fail open and other tools, platforms, network and OS writes remain outside that guarantee.
