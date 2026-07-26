# Wallet transaction history: the four recording paths

Worker on `port/tx-history` from `ts-sdk-port`. Touches
`sdk-libs/ts/transaction`, `xtask/src/ts_fixtures_transaction.rs`, the
`wallet-sync` fixture, and this directory. No Rust behaviour changed; Rust is
the authority throughout.

Rows: T14 for `PrivateTransaction`, T15 for `SyncReport` and the scan counters.

## What both rows were really looking at

[stragglers.md](./stragglers.md) recorded T14 as three missing fields and T15 as
a differing report, and filed them separately. They are one thing. Rust's
`SyncCtx` writes history rows and report counters from the same walk over the
same tag index; TypeScript had neither the walk nor the rows, so its report
counted what its own loop happened to touch. Adding three fields to the
`PrivateTransaction` interface would have left nothing to fill them.

So the port is the algorithm, not the type. `sync.ts` now carries `TagIndex`
(Rust's `TxIndex`) and `SyncPass` (Rust's `SyncCtx`), and the four recorders
hang off the latter where Rust hangs them off the former.

## The four recorders

`#recordOutboundTransfer(tx, spent, change, kind, counterparty)` is the shared
one. It nets each spent asset down by the change paid back, sorts by asset,
drops zero rows, and writes what survives at
`SENDER_HISTORY_ROW_BASE + row`. Rust's `saturating_sub` is
`total > utxo.amount ? total - utxo.amount : 0n`; the sort is by asset bytes so
the row indices are stable across languages. A dropped zero row still consumes
its index, as in Rust.

`#recordSplit(tx, spent)` writes one `split`/`selfTransfer` row per spent asset
with no netting, because a split pays nobody and every lamport stays with the
wallet.

`#recordMerge(tx, outputContext, utxo)` writes a single `merge`/`selfTransfer`
row indexed by the output leaf, not by the sender row base: a merge produces one
note and the wallet reads it as a recipient.

`recordConfidentialSend(tx, index, key, knownRecipients)` is the only one that
does work before recording. The unified confidential scheme carries no
sender-side recipient list, so the author re-derives the transaction viewing key
from the first nullifier, checks it against the published one, and decrypts
every slot with it: slots below `SENDER_SLOT_COUNT` rebuild as change, slots
above yield the recipient key prefixed to the ciphertext, and dummy slots fail
the decrypt and are skipped. Zero recipients means the value left the pool, so
the kind is `publicWithdrawal`; exactly one recipient is recorded as the
counterparty, more than one is recorded as none.

Two guards matter and both are Rust's. `#processedOutbound` keeps a transaction
from being recorded twice when several viewing keys reach it, and `#authored`
suppresses the inbound row for a slot the wallet sent to itself, which
`recordConfidentialSend` has already logged as outbound.

## `"pending"`: TypeScript invented it

Removed, and not because Rust lacks it.

Nothing ever produced it. The sole writer of a history row before this branch
was `transactionRow`, which hardcoded `status: "confirmed"`
(`sync.ts` at `ts-sdk-port`); no other code path constructed a
`PrivateTransaction` at all. The variant was reachable only by a caller
hand-building a row, and a caller who did would find nothing in the SDK that
reads it back.

That is a symptom rather than the argument. The argument is that a wallet has no
source for the state. `Wallet` is mutated by exactly one thing, `sync`, and
sync's input is transactions an indexer has already confirmed on chain. A row
can only exist because a confirmed transaction produced it. Recording a
transaction as pending would need a submit path that writes the row at
submission and revises it at confirmation, and neither language has one. The
client submits and the wallet later learns about it by scanning. So Rust is not
missing a state it should have; TypeScript admitted one its own data flow cannot
reach.

Keeping it would cost something real. A consumer narrowing on
`tx.status === "pending"` writes a branch that never runs, and the compiler
cannot tell them, because the union says it can. Deleting it makes
`PrivateTransactionStatus` a single-variant type that says what is true: every
row a wallet holds is confirmed. If a submit path arrives later it will add the
state along with the code that produces it.

## Everything else T14 flagged

- `slot` moved from `PrivateTransaction` into `PrivateTransactionId`, where Rust
  keeps it. It is part of the row's identity, not a payload field.
- `asset`, `amount` and `counterpartyViewingPublicKey` added. The last is
  optional, matching Rust's `Option<P256Pubkey>`, and is absent rather than
  `undefined` on rows that have no single counterparty.
- Kind and direction variants follow the house `lowerCamelCase` mapping of the
  Rust variant names: `privateTransfer`, `publicWithdrawal`, `selfTransfer`.
  TypeScript previously used `transfer`/`withdrawal` and
  `incoming`/`outgoing`/`self`, which are not transliterations of anything Rust
  writes.

`SyncReport` is now Rust's four fields: `storedUtxos`, `unparsedTransactions`,
`undecryptableCandidates`, `unknownAssetIds`. The old `received`/`spent`/
`transactions` triple counted loop iterations, which is why it could not be
mapped field by field.

## Oracle coverage

The row and the report are pinned by Rust, not by TypeScript expectations. That
was T15's actual complaint and the reason a field-by-field type edit would not
have closed it.

`wallet_history_transactions` in `ts_fixtures_transaction.rs` builds seven
transactions in sequence (deposit, inbound anonymous, outbound anonymous,
confidential send, withdrawal, split, merge), chained so each spends notes the
previous ones stored. All four recorders run. `wallet_history_vectors` then
syncs them one at a time and records, after every step, the `SyncReport`, the
full history, and each viewing key's scan counters. TypeScript replays the same
seven transactions in the same order and compares all three.

Syncing one at a time is load-bearing: an outbound row can only net its change
down if the sync that stored the spent notes already ran, so a single batched
sync would have compared a weaker thing.

The counters were added second, after noticing that the first pass pinned the
rows but still compared scan positions against TypeScript's own expectations,
which is the same class of gap T15 raised about the report.

### Control edits

The assertions were checked by breaking the code and confirming the test caught
it, rather than by reading them. Five edits, five failures: recording an
outbound row as `inbound`; skipping the change subtraction so the outbound
amount is the gross spend; recording a zero-recipient confidential send as
`privateTransfer`; dropping the single-recipient counterparty; and advancing a
tag counter by the wrong step.

## Merge with `ts-sdk-port`

`sync.ts` conflicted. Resolved by keeping the ported algorithm and adopting the
zone read-path work inside it: `ViewingKeyLike` throughout, and the local
`prooflessNote` and `plaintextTransferUtxos` replaced by
`decodeProofless`/`prooflessUtxo` and the exported `plaintextTransferUtxos`, so
zone resolution happens in `resolveZoneProgramId` where Rust does it rather than
in a decoder this file owns.

One test from that branch then failed, and it is worth recording why.
`zone-resolution.test.ts` published its plaintext-transfer slot under a
zero view tag and read `report.received`. The field rename explains half of it;
the tag explains the rest. Rust files plaintext transfers in `recipient_sites`
under the owner's confidential view tag, so a slot tagged zero is one the sync
never opens. The test only reached the decoder because TypeScript used to try
every slot regardless of tag. Tagging the slot the way the sync indexes it
restores what the test meant to check, and it still fails when the zone-data
rejection is removed.

## Rows

T14 and T15 can close. Both were blocked on the same absent behaviour, both are
now pinned by the Rust oracle rather than by TypeScript-side expectations.

## Fixtures

Regenerated `sdk-libs/ts/fixtures/transaction/wallet-sync-v1.json` and its
`manifest.json` hash row. No other fixture changed;
`rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check` verifies 58
fixtures and 182 inventory rows clean.
