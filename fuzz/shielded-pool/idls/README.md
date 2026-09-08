# IDL

`shielded_pool.json` describes the shielded pool's instructions and account layouts
for the fuzz harness.

The program is native (Pinocchio), not Anchor, so there is no `anchor idl build` to
run: this file is maintained alongside the program. If an instruction's tag, account
order, or payload layout changes, update it here — the harness builds its calls from
this description, and a stale entry makes the corresponding action fail at account
validation rather than exercise the handler.
