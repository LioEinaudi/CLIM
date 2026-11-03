# Normalized PreToolUse attempt events — fixture-scoped adapter

`attempt_capture.py` is an optional experimental adapter for this disposable Linux fixture. It wraps the fixture's existing CLIM PreToolUse command, forwards the command's output and status, and records an HMAC of the session/tool identity, fixture-only target, local timing and the SHA-256 of a **requested** denial receipt. It does not persist the raw session ID, tool ID, patch, shell command, private path or receipt. The original CLIM handler remains the authority for the Hook output; this adapter never independently issues an allow or deny.

The private raw capture also records `patch_end_of_file_marker` as a boolean for `apply_patch`, or null when no patch command is available. This records whether the literal hunk marker was present, not whether the Host executed or denied the call; it does not store the patch contents.

An operator must inspect and trust the resulting Hook in `/hooks`; configuration alone is not trust. The adapter is intentionally limited to the fixture and the installed Hook matchers. Calls it did not receive are outside coverage, and Shell effects are not parsed or blocked.

After an operator independently saves the actual native Host refusal text, `normalize` requires a single exact receipt match to one captured out-of-stage `apply_patch`, restricts records to the same HMACed session, deduplicates tool IDs and rejects ambiguous concurrent ordering. Only the matched anchor receives `host_result: BLOCKED`; all later Host results remain `UNKNOWN` unless independently evidenced. It writes a private JSONL file in the following shape:

```json
{"seq":1,"tool_id_hash":"<opaque-hmac>","kind":"apply_patch","target":"src/game/ui/menu.py","host_result":"BLOCKED","receipt_sha256":"<sha256-of-exact-native-host-receipt>"}
{"seq":2,"tool_id_hash":"<different-hmac>","kind":"apply_patch","target":"src/game/ui/menu.py","host_result":"UNKNOWN"}
```

These values are schema examples, not observations. Unknown, multi-target and unsupported requests have target `UNCLASSIFIED`; no raw arguments are exported. A same-target event after an anchored denial is a captured repeat, not proof of a cognitive retry loop or token waste. No later captured event does not establish that the agent stopped.

`verify_run_link.py` additionally requires the native receipt to match a Hook event whose session HMAC matches the `thread.started` ID in exactly one completed conflict turn, within the bounded runner's monotonic interval. The link binds the input file hashes and carries a local HMAC using the private capture key; a mismatched session, missing Host text, failed/unfinished turn, modified input or unsigned/edited link produces `UNKNOWN`. This is local consistency checking, not cryptographic authentication of Host output or complete coverage: the local operator can access the key. Never infer `tokens_after_denial` from these records.
