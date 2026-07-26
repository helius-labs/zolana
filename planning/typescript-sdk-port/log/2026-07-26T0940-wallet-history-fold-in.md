# 2026-07-26 09:40 UTC | reconciliation: the wallet history port folded, T14 and T15 closed | `T14`, `T15`

- Baseline: HEAD `569544e0`, the `ts-sdk-port` tip after `port/tx-history` merged
- Worker: coordinator, still standing in for the reconciler role
- Verdict: `T14` and `T15` reach PARITY
- Evidence: build, unit tests, lint and typecheck were run on the history branch before it merged, and each came back green. The claims below were spot-checked against code at this HEAD rather than credited to the report

## Why one port closed two rows

Both rows recorded the same residual from opposite sides. T14 said
`PrivateTransaction` was missing `asset`, `amount`, and the counterparty viewing
key, and could not do otherwise while the four `record_*` builders were unported.
T15 said `SyncReport` was a different record while the history was unported, and
that the scan counters were compared against TypeScript's own expectations rather
than against Rust.

The earlier reviews filed these separately and proposed adding three fields to an
interface. That would not have closed either row, because Rust writes the history
rows and the report counters from one walk over one tag index, and TypeScript had
neither the walk nor the rows. There would have been nothing to fill the fields
with. What landed is the algorithm: `TagIndex` for Rust's `TxIndex`, `SyncPass`
for `SyncCtx`, and the four recorders hanging off the latter where Rust hangs
them off the former.

## What was checked rather than taken on trust

`transaction/src/wallet/state.ts:51` declares `PrivateTransactionStatus` as the
single variant `"confirmed"`. The removed `"pending"` was not dropped for
convenience: nothing produced it, and nothing could. A wallet is mutated only by
`sync`, whose input is transactions an indexer has already confirmed, so a row
exists only because a confirmed transaction produced it. A consumer narrowing on
`tx.status === "pending"` would have written dead code, with the compiler unable
to warn them because the union claimed the state was reachable.

The four recorders are present in `sync.ts`, and `wallet-sync.test.ts` replays
the Rust oracle.

## The evidence standard this one actually meets

Five control edits, five failures: an outbound row recorded as `inbound`; the
change subtraction skipped so the outbound amount is the gross spend; a
zero-recipient confidential send recorded as `privateTransfer`; the
single-recipient counterparty dropped; a tag counter advanced by the wrong step.

That is the property the audit on 2026-07-25 found missing from 35 of the 36 rows
then claiming parity. These two are closed on assertions demonstrated to fail
when the behaviour breaks, not on a reading that found two files similar.

## Not folded

`row-updates/c03-rpc-surface.md` stays open. A worker is re-verifying C03 now,
including the claim that eight of the fifteen methods it calls missing are Rust
trait declarations with no implementor, and folding a verdict the live review may
contradict would create the exact desynchronization this log exists to prevent.
