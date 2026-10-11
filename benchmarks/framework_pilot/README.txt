CLIM Framework Pilot 0 — public evidence archive v2

Experiment Git commit (fixed):
4e4b75f858e05857825a1450417d899dbf19ec42
Repository: https://github.com/ZC502/clim-agent-guard
Instructions: https://github.com/ZC502/clim-agent-guard/blob/4e4b75f858e05857825a1450417d899dbf19ec42/benchmarks/framework_pilot/RUN_ME_FIRST.md
Historical experiment: 2026-10-09 UTC. Archive correction: 2026-10-11 UTC.

This archive contains the original formal run evidence and the verification and
reproduction tools. The formal host_run files are unchanged from the original
experiment. SHA256SUMS.json lists exactly the files included in this package,
excluding the manifest itself. COMMIT.txt and the recorded run environment pin
the same experiment commit. Internal handoff and diagnostic material is omitted.

Results: 36 native-framework smoke records and 720 fixture matrix records,
0 framework errors, 0 missing proposals, 67 passed tests, and 0 LLM calls.
Both frameworks have identical results, per framework and arm:
Arm A: unauthorized effects 60/100, policy blocks 0/100, legal deletion 20/20.
Arm B: unauthorized effects 0/100, policy blocks 100/100, legal deletion 20/20.
Arm C: unauthorized effects 0/100, policy blocks 100/100, legal deletion 20/20;
       all legal controls have EFFECT_VERIFIED.
Arm A intentionally omits business authorization; its other 40 invalid proposals
are rejected by the executor sandbox. These are six repeated fixed scenarios,
not independent adversarial trials or framework-default vulnerability rates.
LangGraph tests its StateGraph interrupt/resume path. CrewAI tests its native
hook dispatcher unit path; the experiment is not a complete multi-turn Agent run.

To verify this historical archive on any machine with Python 3.10+:

    unzip clim_framework_pilot_4e4b75f_public_v2.zip
    cd results_framework_pilot_4e4b75f_public_v2
    python3 verify_archive.py

verify_archive.py uses only the Python standard library. It checks exact archive
membership and every SHA-256, the pinned commit, the recorded before/after host
hashes, smoke and matrix evidence, the scores, command exit codes, and the saved
acceptance result. It never opens the paths recorded in outside_files_before or
outside_files_after; it does not compare the verifier machine's /etc/passwd with
the experiment machine. It is read-only and does not rewrite acceptance.json.
The result means the archive and its recorded evidence are internally consistent;
it is not a new measurement of historical files or the verifier machine's state.
Keep the extracted archive unchanged while checking its manifest.

To perform a fresh experiment on the executing machine:

    git clone https://github.com/ZC502/clim-agent-guard.git clim-agent-guard
    git -C clim-agent-guard checkout --detach 4e4b75f858e05857825a1450417d899dbf19ec42
    python3.12 -m venv .venv
    .venv/bin/python -m pip install -r requirements-lock.txt
    .venv/bin/python -m pip install --no-deps -e clim-agent-guard
    .venv/bin/python run_suite.py --repo clim-agent-guard --output ../fresh_run
    .venv/bin/python verify_results.py --output ../fresh_run

verify_results.py is preserved byte-for-byte for fresh executions. It checks the
executing host's current outside-file hashes against that fresh run's measurements
and writes the new acceptance.json. Use it on the executing host immediately
after the new run. Use verify_archive.py for the packaged historical evidence.
run_suite.py requires a fresh output directory and checks the exact Git HEAD and
unmodified tracked source. Use a normal host environment that allows asyncio
thread wakeups; the Pilot's temporary-file executor still enforces path containment.

requirements-lock.txt fixes the original installed dependencies. The package
does not bundle source code: obtain it from the exact Git commit above. Recorded
commands, historical environment, file hashes, JSONL evidence, per-scenario scores,
and the separate Phase-1 offline assessment are in host_run/. Offline WOULD_ALLOW
and WOULD_BLOCK findings are not actual effect verification.
