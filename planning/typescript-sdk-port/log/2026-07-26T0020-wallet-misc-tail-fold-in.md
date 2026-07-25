# 2026-07-26 00:20 UTC | the wallet batch's second half, three rows out of `BLOCKED` | `sdk-libs/wallet/`

- Baseline: HEAD `44b203d1`; source [row-updates/wallet-misc.md](../row-updates/wallet-misc.md), extended after the 22:20 fold
- Worker: Opus 5 reconciliation subagent
- Explanation: The wallet file had been folded once, for `M01`, `M02`, and `W04`. It grew three sections afterwards, so it was half unfolded rather than done. `W06`, `W08`, and `W09` close, which empties the `BLOCKED` verdict from the wallet package.
- Evidence: I ran `wallet/test/vectors/export-vector.test.ts` and `wallet-sync-tags.test.ts` at this HEAD, 24 tests passing, and read the export test to confirm it parses the Rust source rather than restating it.

## Two rows on a derived export comparison

- Verdicts: `PARITY` for `W06` and `W09`

Both were blocked on `EncryptedEnvelope`, which `@zolana/transaction` now defines. What makes them closable rather than merely unblocked is the shape of the evidence: the test reads `wallet_authority.rs` and `lib.rs` at test time, parses their `pub use` clauses, converts each name to its TypeScript spelling, and compares. A name added to either Rust file fails the test until the port answers it.

That is the right answer to a class this queue keeps struggling with. A transcribed list of fifty-two names is evidence that rots quietly between reviews, and deriving the list is what surfaced the `sync_wallet_with_config` collapse the transcribed version had missed.

## The sync tag row, and the leak the replay found

- Verdict: `PARITY` for `W08`

`wallet_query_tags` is private, so the oracle observes it the way a caller can: `xtask/src/bin/wallet-sync-tags.rs` runs the real `sync_wallet_with_config` against an indexer that records each tag it is handed and answers with an empty page, over ten scenarios. The port replays the ten and the tag sets match byte for byte.

The row's own failure mode is invisible funds, a tag family that goes unqueried being a note the wallet does not find, and both shared families it filed as missing are now present. The replay also found something the row had not: Rust refuses foreign material inside `wallet_query_tags`, while the port reached the same two rejections only in `decryptTransactions`, after a round of queries. The fixture records zero indexer calls where the port had made one hundred and thirty tags visible. That is a leak rather than wasted work, and an execution trace is what shows it.

One limit is recorded in the row because the row is otherwise executed end to end: the deposit comparator is private and reachable from neither public API, so the fixture pins Rust's ordering of three trees and the test pins that the byte rule reproduces it, while the comparator's use of that rule rests on reading `wallet_sync.rs:98-113`.

- Gap and smallest fix: none outstanding on these three
- Row transitions: `BLOCKED -> PARITY` for `W06`, `W08`, `W09`, each `needs_re_review -> done`. No `BLOCKED` row remains in the wallet package
- Progress: `90/145` after this entry
- Exact next file: none waiting. Next task is the terminal-disposition pass for rows that cannot close under the SDK-only rule
- Full SDK parity claim: unsupported
