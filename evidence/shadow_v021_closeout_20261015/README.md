# P0 closeout evidence, October 15

Measured source: eb55e4e3b64548508dddb75b3809d5af249b3b88.
`source_snapshot.zip` contains the COMPLETE tracked repository at that commit, including all 140 historical test sources and 30 added tests. It does not contain Codex account credentials or the private 24-run review archive.

Two NEW native P0 smoke runs; not another full S1-S10 run. Both use native Hook trust, gpt-6.1-sol / medium / on-request / workspace-write / network=false. Raw client history, prompts and random canaries are excluded; toy command receipts replace canaries with a placeholder.

Clean Python 3.10/3.12 environments collected 170: 167 passed, 3 private-archive checks skipped. The author environment supplied that archive and passed all 170. Top-level tests alone are a narrower suite. CI results at later commits are separate.

Ten assistant-reviewed samples distinguish valid controlled effects, policy hints, neutral gaps and uncertain attribution. No independent human precision or population false-positive rate is claimed. Historical evidence and mismatched approval contexts are preserved, not corrected retroactively.

Verify without installed CLIM, original project paths, account or network:

```bash
python verify_closeout.py .
```

This verifies membership, hashes and cross-artifact semantic assertions; unsigned hashes are not proof against replacement of the entire archive. Historical S1-S10 verification summary and selected samples do not replace the private complete historical review archive.
