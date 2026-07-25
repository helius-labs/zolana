# 2026-07-26 00:15 UTC | transaction batch B, the builder and type rows | `sdk-libs/transaction/src/instructions/`, `utxo.rs`

- Baseline: HEAD `c61f71b0`; source [row-updates/transaction-b.md](../row-updates/transaction-b.md)
- Worker: Opus 5 reconciliation subagent
- Explanation: Seven rows close, two advance, and one is downgraded from the batch's own claim. The evidence class is the same generated oracle checked in the previous entry, so the judging here is about coverage rather than about whether the oracle is real.
- Evidence: `sdk-libs/transaction/tests/ts_oracle.rs` and `sdk-libs/ts/transaction/test/vectors/rust-oracle.test.ts`, 210 replayed tests passing at this HEAD, plus the two Rust currency tests.

## `T29` is held at `PARTIAL`, against the batch's `PARITY`

The batch fixed the shape half of this row's divergence and its case list is good: `prepareZoneAuthority` now resolves the shape through the shared `exactShape` lookup and rejects padded slot counts that name no proving system, and the `unsupportedShape` case fails without the fix.

The other half is untouched. Rust `PreparedZoneAuthority::new` takes `payer: Address` and derives `payer_pubkey_hash = sha256_be(payer.as_array())`; TypeScript takes `payerPublicKeyHash: Bytes32` from the caller. So a TypeScript caller can prepare a zone-authority transaction whose payer hash names someone other than the payer who signs, and Rust makes that unrepresentable.

The reason this survived a 66-assertion oracle is worth stating, because it generalises: the nine cases feed both languages the correct hash, so no replay can see a missing derivation. An oracle compares what both sides do with the same input; it cannot see an input one side would have refused to accept in that form. The batch listed "the payer hash" among the compared values, which is true and does not bear on the derivation. Smallest fix is one line, and `instructions/transact.ts:558` already does it on the confidential rail.

## Rows closed

- Verdicts: `PARITY` for `T11`, `T18`, `T19`, `T22`, `T24`, `T25`, `T27`

`T25` carries the two fixes with consequences beyond correctness. Padding moved from `prepare` to `finalizeTransfer`, because `prepare().outputs` is what a wallet hands its authority to encrypt, so the old placement asked an authority to encrypt dummy slots. And padded slots now sample the dummy rail from the transaction's real recipients as Rust does, where TypeScript used the sender's rail: on a mixed-rail transfer that marked each dummy for anyone running a curve-membership test on the published view tag. Two guards were also deleted rather than added, since `send` and `withdraw` refused a zero amount Rust accepts.

`T11` and `T18` share a shape worth naming once: TypeScript rejects at construction where Rust rejects at the hash or at `try_from`. That is a difference in where, not in what, and the per-field cases execute Rust's rejection for each field rather than asserting that it must happen somewhere.

`T27` closes with one named exclusion rather than silently: `MergeInputRailMismatch` is implemented on both sides and executed on neither, because the oracle builds no ed25519 keypair. That last clause is a reading, so the row says so and names the fix.

## Rows advanced, still adverse

- Verdicts: `PARTIAL` for `T06`, `T28`, and `T29`

`T06` and `T28` are held on behaviour rather than on a class held elsewhere: shared-tag progression is unexercised, and canonical zone-hash validation exists in neither language, so `T28` needs a Rust rule before TypeScript can match it. Adding it to TypeScript alone would refuse input Rust accepts, which is the failure mode this batch corrected twice in its own work.

## One rule, not one exception

The previous entry recorded where the export-allowlist, browser, and packed-artifact classes are held. It applies to the remaining `T` rows too: `T10`, `T17`, `T26`, `T30`, and `T31` are the aggregate rows that hold those classes for this package, and the batch's own note agrees they need a build-and-pack harness rather than an oracle.

- Gap and smallest fix: `T29`, derive the payer hash from the address. `T06`, replay a tag sequence. `T27`, add an ed25519 keypair to the oracle and execute the rail check. `T28`, a Rust rule first
- Row transitions: `PARTIAL -> PARITY` for `T11`, `T22`, `T24`, `T27`; `DIVERGENT -> PARITY` for `T18`, `T19`, `T25`; `DIVERGENT -> PARTIAL` for `T06`; `DIVERGENT -> PARTIAL` for `T29`, downgraded from the batch's claimed `PARITY`; `T28` unchanged at `PARTIAL`
- Progress: `87/145` after this entry
- Exact next file: none from this batch. `T05`, `T10`, `T12`, `T13`-`T17`, `T21`, `T23`, `T26`, `T30`, and `T31` are the transaction rows still open
- Full SDK parity claim: unsupported
