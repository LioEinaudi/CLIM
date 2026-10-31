# Controlled Codex Native game demo

This fixture is for a new, non-production project. The operator's contract
files and evidence are placed outside the project to avoid putting the demo
script in the model's working tree. This is not a filesystem security boundary.

From a source checkout, choose two new, separate directories and run:

```sh
python examples/contract_game_demo/prepare_clean_demo.py \
  --project /tmp/clim-clean-game-example \
  --operator-dir /tmp/clim-operator-example
```

The helper creates the game placeholders and `game_contract_spec.json`,
`mechanics_proposal.json`, `invalid_expansion.json` and `ui_proposal.json` in
the operator directory. The developer can then initialize and activate the
Mechanics stage, explicitly enable enforcement, and review the project Hooks in
Codex `/hooks`. Use `file_evidence.py` to record independent snapshots outside
the project. The [controlled case](../../docs/CONTROLLED_LINUX_ALPHA_CASE.md)
describes an actual run and its limits.

`clim contract bootstrap --scope ...` creates one `work` stage. The two-stage
example instead uses `clim contract init --file ...`, `validate`, `propose`,
`activate`, and, after the operator finishes Mechanics, `finish-stage` and
another proposal and activation for UI. Disabling the experimental opt-in uses
`clim codex install-hook --project /path/to/project`; removing the CLIM-owned
project Hook uses `clim codex uninstall-hook --project /path/to/project`.

The Host response is needed to confirm a denial. Shell and other tools are not
covered by the same denial path; see [known limitations](../../docs/KNOWN_LIMITATIONS.md).
