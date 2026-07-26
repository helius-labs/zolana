# 2026-07-26 15:55 UTC | gate1-gaps seats hasher and test-kit | H15 TK01 TK02

- Baseline: worktree `zolana-wt-gate1-gaps`, branch `port/gate1-gaps`
- Worker: gate1-gaps
- Scope: checklist seats, live inventory, test-kit `/node` disposition ledger

- Verdict: `H15` PARITY
- Verdict: `TK01` PARITY
- Verdict: `TK02` NOT_APPLICABLE

Primary rows move from 145 to 148. Progress is `137 done / 148 total`.
Live inventory rows for `hasher-wasm` and the test-kit annex sit in
`sdk-libs/ts/reports/inventory-live.json` because those paths are absent from
the frozen 182-path `sdk-libs` tree at `frozenCommit`.
