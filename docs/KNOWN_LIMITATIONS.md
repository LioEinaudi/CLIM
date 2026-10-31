# CLIM — Known Limitations

## Historical Shadow observation limitations (v0.2.1)

> **Read-only Shadow mode is observation, not enforcement.** The Shadow workflow records matched tool proposals and bounded file effects; it does not request native Host refusal. The opt-in Linux Alpha contract-observer path below is a separate, limited experiment. Some version-specific details in this historical section may differ from the current Alpha build.

1. **Partial tool visibility.** Coverage is limited to matching supported Codex Hook names. A missing or untrusted Hook, unsupported tool, background process, or direct OS execution may be missed. Shell command contents are **not semantically interpreted**; lexical `RISK_SIGNAL` notices are review hints, not proofs of dangerous effects.
2. **Bounded file evidence.** Automatic inventory samples at most 250 paths and 4 MiB per file. Directories such as `.git`, `.codex`, dependencies/build artifacts and symlink contents can be skipped or recorded as coverage gaps. `.git/**` is a protected **policy pattern**, not proof that all `.git` changes are observed.
3. **No implicit task authorization.** Default sensitive-path patterns offer policy guidance but are not a task-specific authorization set. If no independent host authorization is registered, CLIM reports `AUTHORITY_UNKNOWN` and must not infer that an Agent's own proposal was authorized.
4. **Git dirty observation.** The v0.2.1 baseline primarily covered unstaged tracked changes. The current Shadow code samples staged, unstaged and untracked paths at the initial session baseline, subject to size, path and Git-output limits. Ignored files, later concurrent edits and external actors may be missed. Line-digest heuristics do not establish reliable authorship or guarantee preservation. The earlier same-session false warning was repaired before the October 14 acceptance run; regressions remain possible.
5. **Uncertainty stays uncertainty.** Missing PostToolUse, sampled-out paths, unreadable files and concurrent changes may produce `UNKNOWN` or coverage gaps. Not observed does not mean not modified. Cross-process or multi-agent attribution is not guaranteed.
6. **Privacy and retention.** Default v0.2.1 telemetry uses identities, hashes and structured metadata in place of raw Patch / Shell content. Original client history and legacy logs are not retroactively sanitized; CLIM's local logs persist until explicit state purge, and automatic expiry/rotation is not yet supported. File names and digests can still be sensitive metadata.
7. **Performance is measurable, not zero.** Instrumented acceptance Hook p95 was approximately 78.75 ms Pre / 75.75 ms Post, including process startup and a test controller. Different repos and large sessions may differ; no population-wide latency or token-saving claim follows.
8. **No OS isolation or guaranteed recovery.** Same-user policy/state files are not tamper-proof against arbitrary same-user code. Shell checks do not confer filesystem or network isolation. No claim of comprehensive secret exfiltration detection or automated backdoor analysis is made.

**Supported use**: local diagnostic observation for supported Codex workflows with a readable report and explicit uncertainty. Enable native sandbox/permissions and use version control/backups when stronger protection is required.

---

## Linux Alpha contract observer: known limitations

CLIM records supported tool requests and bounded, sampled file changes locally.
Explicitly enabled experimental enforcement can request a Codex Host denial for
an `apply_patch` with fully parsed targets that conflict with an active registered
file/stage scope. A local `DENIAL_REQUESTED` is not proof the Host denied it.
Check the actual Host tool result; the receipt is a correlation token, not a signature.

Controlled Linux Codex CLI tests have exercised this path. Other versions and
platforms may behave differently. Windows and macOS native enforcement remain
unverified; Windows command quoting with paths containing spaces has not been
validated on a Windows Host. Shell, network, MCP and other tools are not enforced
by this feature. Unknown inputs and missing, failed or timed-out Hooks can pass
without a denial. There is no general fail-closed or production security guarantee.

Snapshots sample watched files at particular times; they do not establish the
writer, capture all intermediate effects, or prove a file was never briefly
changed. Races between checking and use (TOCTOU), and same-user modification of
local configuration or evidence, remain possible. The operator capability and
ledger are not an independent security boundary. Review the gaps and Host results.

CLIM's contract runtime stores its records locally and has no CLIM telemetry
service. This does not describe or constrain Codex CLI's own network access.
