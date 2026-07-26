# 2026-07-26 14:46 UTC | I01, W01, W05, W07 | checklist reconciliation

- Baseline: worktree `zolana-ts-w03` on `port/w03`; substance from `zolana-ts-rowdebt` (`row-updates/rowdebt.md`) and `certification-evidence.md` §5
- Worker: reconciler (checklist-only for these rows; I01/W07 fixes landed in the rowdebt worktree)
- Explanation: An independent spot-check found two previously closed rows whose written evidence did not support the verdict as stated. Rowdebt cleared both in substance; this entry records the checklist catch-up. W01 and W05 were sibling-checked in the same pass and needed no verdict change.
- Evidence: I01: `rust-oracle.test.ts` now compares `{ code, message }` for 29 codes via `ShieldedPoolErrorMessages`. W07: `program-libs-parity-v1.json` `senderViewingKeyRule` plus `program-libs-registry.test.ts` pin no-delegate, active-with-entries, active-empty-entries, and revoked-with-entries; Rust and TypeScript agree on each. W01 ATA fixture evidence re-checked; W05 surface evidence re-checked with the hand-typed `mod.json` allowlist residual left explicit.
- Verdicts: `PARITY` for `I01`, `W01`, `W05`, `W07`
- Row transition: notes only; status `done` / verdict `PARITY` unchanged
