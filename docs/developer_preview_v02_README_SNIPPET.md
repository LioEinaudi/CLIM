## CLIM Developer Preview v0.2 (experimental)

**Keep your coding agent inside the file boundaries you approve.**

Codex native Hook adapter; model-agnostic CLIM execution contracts and watched-file effect verification.

```bash
python -m pip install -e .
clim demo             # offline simulated demonstration; no Codex needed
clim init codex       # from an existing disposable/test project
clim doctor           # check coverage and review hooks in Codex `/hooks`
clim mode guarded     # Shadow is the default; Guarded is opt-in
clim report --today
```

**What it can currently do:** Block supported `apply_patch` changes to protected paths; allow normal multiple-target patches; report actual changes to watched files; deny uncovered Shell commands in strict mode. It does not protect unhooked tool routes, provide an OS privilege boundary, silently install trusted hooks, analyze arbitrary Shell effects, or guarantee false-positive-free workflows.

[Full installation, limitations, uninstallation and real Codex acceptance](docs/developer_preview_v02.md). Previous 720-trial LangGraph/CrewAI benchmarks remain available as supporting research, **not** the main product experience.
