# CLIM Linux Community Alpha `0.3.0a3`

This pre-release adds the experimental Codex Scope & Retry Check and fixes one `apply_patch` coverage gap in the `0.3.0a2` stage-scope observer. In `0.3.0a2`, a valid `*** End of File` hunk marker could make the parser return unknown and emit no denial. The updated parser recognizes this marker while keeping unknown formats unknown. The `v0.3.0a2` tag remains unchanged.

The pilot provides a disposable fixture, a bounded native Codex runner, a local evidence report, and a sharing card generated from the same supplied evidence. Users must review and trust their exact project Hooks through Codex `/hooks`; the pilot does not automatically trust Hooks or bypass sandbox approvals.

An implementer-reported controlled Linux run used the earlier local `0.3.0a2+scopefix.20261103` build: native Host refusal and CLIM Watch receipt matched, the sampled outside file stayed unchanged, a separate in-scope patch succeeded, and a subsequent captured Shell command read the file. The run measured a whole-turn total of 49,639 tokens; tokens after denial are not independently available. See the [redacted evidence](../experimental/scope_recovery_pilot/evidence/controlled-linux-20261103.md). This observation is not a claim about all Codex versions or spontaneous agent behavior.

This remains an opt-in experimental Linux Alpha, not a production security boundary. Shell writes, network and other tools are not comprehensively enforced; unknown inputs and missing, failed or timed-out Hooks can fail open, and same-user processes may alter local state. WSL2, macOS and native Windows were not tested in this run. No token-saving, infinite-retry prevention or 100% protection claim is made.

[Reproduction and evidence limits](../experimental/scope_recovery_pilot/README.md).
