# 2026-07-26 08:45 UTC | reconciliation: a stalled pass finished by the coordinator, C22 closed on the ledger fix | queue-wide

- Baseline: HEAD `aaec0719`, the `ts-sdk-port` tip after `port/reconcile4` merged
- Worker: coordinator, standing in for a reconciler the signing prompt stalled
- Explanation: the fourth reconciler moved eight rows and stopped before writing its log entry or recounting, because `git commit` hung on a GPG passphrase prompt with no terminal to answer it. Its work is salvaged rather than rerun. Subagent connections were failing at the time, so this pass was finished in the foreground
- Evidence: `review-checklist-check.mjs`, `pkp-entry-gate.mjs`, and a direct read of the two export barrels for the claim below
- Verdict: `C22` reaches PARITY, on the check recorded below

## C22, and why it can close

The gate refused C22 as `done` / `PARITY` with no log entry recording the
upgrade, which was correct: the reconciler moved the row and then stalled before
justifying it.

The row recorded a ledger defect rather than a code one.
`planning/typescript-sdk-port/public-exports.md` listed `MERGE_INPUTS` under
`@zolana/interface`, which exports no such name, while `@zolana/transaction`,
which does export it, had no entry. A reader checking the public surface
against the ledger would have found a name that does not exist and missed one
that does.

Checked at this HEAD rather than taken from the report that claimed it:
`public-exports.md:341` now carries `MERGE_INPUT_COUNT` in the interface section
and `:792` carries `MERGE_INPUTS` in the transaction section, and the barrels
agree. `sdk-libs/ts/interface/src/index.ts:57` exports `MERGE_INPUT_COUNT`,
`sdk-libs/ts/transaction/src/index.ts:18` exports `MERGE_INPUTS`. Both names,
both directions, no residual.

The fix arrived through `row-updates/zone-read.md`, which took it as one of three
debt items rather than as its main work.

## What this pass does not do

It does not fold `row-updates/c03-rpc-surface.md`, and the count is therefore
still short of what the tree supports. C03 is the row where eight of fifteen
reportedly missing methods turned out to be Rust trait declarations defaulting to
`unsupported()` with no implementor and no caller, so the row needs judgement
rather than arithmetic, and judgement is what a stalled pass cannot supply. The
next reconciler owns it.
