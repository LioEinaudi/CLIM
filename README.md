# CLIM — Intercept Out-of-Scope Codex Patches

**Your task needs one folder. A Codex patch can still target another.**

Asked Codex to work in one part of your project, but encountered a proposed edit elsewhere? **CLIM** lets you register which files belong to the current stage. With experimental enforcement **explicitly enabled**, it asks the **native Codex Host** to refuse a supported out-of-stage `apply_patch` **before execution**. CLIM also records local request/observation evidence so you can inspect what was attempted and what was observed.

### A real Linux test, in three text frames

The following is a **controlled** Codex CLI test. The operator deliberately requested a stage-conflicting patch; it is **not evidence of spontaneous agent drift**.

**1 · Outside-stage request** — Allowed stage: `src/game/mechanics/**`. The actual Codex tool request targeted `src/game/ui/menu.py`.

**2 · Native refusal** — The real Codex tool response reported `Command blocked by PreToolUse hook` with a receipt. CLIM Watch separately showed `DENIAL_REQUESTED` with the matching receipt. **The Codex tool response—not CLIM's local Watch entry—is the evidence that the Host refused the patch.**

**3 · File check** — Independently collected SHA-256 snapshots of `ui/menu.py` were identical immediately before and after the refused request. A separate permitted Mechanics edit changed its file; after the **operator manually switched stages**, a permitted UI edit succeeded. **These hashes were independently collected for the demo, not an automatic CLIM file-hash guarantee.**

[Read the redacted Host / Watch / hash evidence and its limits](docs/CONTROLLED_LINUX_ALPHA_CASE.md). These are **text records, not screenshots or footage**. Equal hashes establish equality at the sampled moments, not continuous filesystem integrity.

> **Experimental Linux-tested Alpha · Not a security boundary.** The verified pre-execution refusal is limited to a local Codex CLI `apply_patch` path. Shell commands, network activity and other tool paths are **not comprehensively blocked**; missing or failed Hooks may **fail open**; file observations are incomplete. Windows/macOS are **NOT_TESTED**. Keep Git backups and normal Codex sandbox/approval controls. [Known limitations](docs/KNOWN_LIMITATIONS.md).

### Try it in a fresh test repository

**Runs locally · No CLIM telemetry service · Apache-2.0 license.** This describes CLIM; Codex CLI and model-service data handling are separate.

**Requires:** Linux, Python 3.10+, local Codex CLI with project Hook support, a terminal. Not available for web-only Codex sessions.

```bash
python -m pip install 'git+https://github.com/LioEinaudi/CLIM.git@v0.3.0a2'
```

Create a fresh, non-production repository containing `src/game/mechanics/`; then, from its root:

```bash
clim contract bootstrap --project . --template code-only --scope 'src/game/mechanics/**' --acknowledge-scope
clim codex install-hook --project . --enable-enforcement
clim contract doctor --project .
```

Open **Codex CLI in the same repository**. Use `/hooks` to inspect, review and trust the project Hook. In a second terminal:

```bash
clim contract watch --project .
```

A Watch entry saying `DENIAL_REQUESTED` means **CLIM asked** for refusal; check the **actual Codex tool response** to determine whether the Host refused. A receipt is a correlation identifier, **not** an authenticated proof of enforcement. Watch still reports Shell coverage gaps.

To return to ordinary observation mode:

```bash
clim codex install-hook --project .
```

### What CLIM is—and is not

**CLIM** originally stands for **Codex Local Integrity Monitor**. Shadow mode focuses on local observations; this **opt-in** Alpha adds limited pre-execution stage-scope refusal requests for supported Codex patches. The three-command setup creates **one active stage**; parent/child and multi-stage flows use the separate file-based Contract Runtime. A child stage cannot independently widen its registered parent scope.

CLIM does **not** stop unnecessary tests inside allowed files, measure wasted tokens, prove task completion, or replace Codex's own permission system. Other agents (including Claude Code and Cline) are **not tested or supported by this Alpha**; possible future adapters are not current functionality.

**Feedback wanted:** Would you use a local, opt-in stage boundary when Codex proposes a patch outside the files you intended? Where would legitimate cross-stage edits or setup complexity get in your way? Please share redacted examples, never raw Hook payloads or private transcripts.

For CLIM's separate **read-only Shadow observation / reconciliation** workflow, see
[Shadow Observation Mode](docs/SHADOW_OBSERVATION_MODE.md). Shadow notices are not
the opt-in stage-scope refusal mechanism described above.
