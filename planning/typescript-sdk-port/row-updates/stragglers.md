# Stragglers: the eight unowned rows

Branch `port/stragglers`, from `921e4bfd`. Each verdict below rests on a Rust
oracle replayed in TypeScript with at least one control edit applied to the
implementation and observed to fail, except where the entry says otherwise in so
many words.

`tools/control-edit.mjs` is the harness the controls run through: it applies a
literal substitution to a source file, runs a test selection, restores the file,
and reports whether the selection caught the edit. It rebuilds under `--build`,
because cross-package imports resolve through `dist/` and an unbuilt control
edit reads as passing.

## Summary

| Row | Was | Now | Needed |
| --- | --- | --- | --- |
| C01 | PARTIAL | PARITY | new oracle, no code change |
| C02 | DIVERGENT | PARITY | a real fix |
| C03 | DIVERGENT | DIVERGENT | an owner's scope decision |
| C05 | PARTIAL | PARTIAL | a real fix; one residual needs a mock RPC |
| T14 | DIVERGENT | PARTIAL | a real fix; history rows remain |
| T15 | DIVERGENT | PARTIAL | evidence gap closed; history rows remain |
| W02 | STALE | PARITY | new oracle, no code change |
| W04 | PARTIAL | PARTIAL | new oracle; one rule is unobservable |

Already correct, needing only evidence: **C01**, **W02**. Needing a real fix:
**C02**, **C05**, **T14**, **W04**. Cannot close here: **C03**, and the
remaining halves of **T14**, **T15**, **C05**.

## C01 `retry.rs` against `retry.ts`: PARITY

The row's one open item was that no oracle compared the delay sequence, the cap,
or the attempt accounting. One configuration was compared, `(4, 5, 12)` through
the indexer poll in `indexer-client.test.ts`, which is a narrow slice of
arithmetic that diverges at its edges.

`xtask/src/bin/retry-schedule.rs` now records, from the crate, what `backoff`,
`attempts`, and `poll_until` do across eight configurations chosen for those
edges: the default, a first delay above the cap, a doubling that leaves `u64`
(`delay_ms = u64::MAX / 2`), a cap never reached, a zero delay, no retries, and
`u32::MAX` retries for its attempt arithmetic alone. It also records seven poll
outcomes, each with its request count and the variant it ended on: a response
the acceptor refuses, a retryable indexer failure, a fatal one, a retryable RPC
failure, an indexer timeout, an unrelated fatal error, and a request accepted
partway through. `client/test/vectors/retry-schedule-oracle.test.ts` replays all
fifteen cases. No implementation change was needed, since TypeScript already
agreed at every edge, including the `u64` doubling one.

Control edits, each observed to fail:

- dropping the initial clamp to the cap, caught by `firstDelayClampedToCap`.
- tripling instead of doubling, caught by four schedules.
- `attempts` returning `numRetries`, caught by twelve of the fifteen.
- dropping the immediate first attempt from the schedule, caught by four polls.
- retrying a fatal error, caught by `fatalIndexer` and `fatalOther`.

## C02 `error.rs` against `error.ts`: PARITY

`CLIENT_SOLANA_TRANSACTION_SIGNING` had no producer. `sign_private_transaction`
(`wallet/src/actions/transaction.rs:582`) maps a `Transaction::try_sign` failure
to `ClientError::SolanaTransactionSigning`; the port called the caller's
`signNativeTransaction` and let its rejection through unnamed, so a fee payer
that cannot sign arrived as whatever the caller's signer threw.

`signPrivateTransaction` now wraps that one call in the same error, at the one
site Rust wraps it. The deposit path was checked and deliberately left alone:
`create_and_send_transaction` builds through `Transaction::new`, which does not
produce this variant, so wrapping there would have invented a producer Rust does
not have. The `NO_TYPESCRIPT_PRODUCER` disposition is removed, which also retires
the conflation the row recorded. The two entries that remain are both codes no
SDK package produces, so the set no longer mixes them with a code whose producer
lives in another package.

Control edit: naming the wrapped error `CLIENT_FEE_PAYER_MISMATCH` instead,
caught twice, by the new `wallet.test.ts` case and by the producer-disposition
scan in `client/test/error.test.ts`, which fails when a dispositioned code gains
a producer or a produced code loses one.

## C03 `rpc.rs` against `rpc.ts`: DIVERGENT, needs a scope decision

The row asks for a determination before any writing, and the determination is
that "11 of 30" is the wrong measure and the remainder is genuinely mixed.

Rust's `Rpc` is one trait over three roles, Solana RPC, SPP indexer, and prover,
with each method defaulting to `unsupported(..)`. TypeScript split those roles:
`Rpc` and `SolanaRpc` hold the Solana surface, `Indexer` holds
`getEncryptedUtxosByTags` and `getShieldedTransactionsByTags`, `ProverClient`
holds `prove`, and `ZolanaClient` assembles the three. Counting the split
surface against the single trait charges the port for a deliberate
decomposition. That part is scope, not a gap.

What has no TypeScript home, verified by searching each `sdk-libs/ts` source for
a method definition of the same name:

- Solana reads: `get_slot`, `get_block_height`, `get_transaction_slot`,
  `get_signature_statuses`, `get_minimum_balance_for_rent_exemption`, `health`.
- Send variants: `send_transaction_with_config`,
  `send_versioned_transaction_with_config`, `process_transaction`,
  `process_transaction_with_context`, `process_versioned_transaction`.
- Construction conveniences: `create_and_send_transaction`,
  `create_and_send_versioned_transaction`.
- `should_retry`, `send_and_prove`, and
  `subscribe_to_shielded_transactions_by_tags`.

Two of those are not test-only conveniences. `create_and_send_transaction` is
called by `wallet/src/actions/deposit.rs`,
`actions/create_associated_token_account.rs`, and `user_registry.rs`, and
`get_minimum_balance_for_rent_exemption` by the account-creating actions, so they
are SDK flow rather than harness. The port reaches the same outcomes in a
different shape (build, hand to the caller's signer, `sendTransaction`), which is
a defensible design rather than an omission, but it is a design the owner should
affirm rather than a reviewer infer.

Nothing is written for this row. Deciding it means answering two questions: does
`Rpc` stay the Solana-only surface with the indexer and prover assembled
alongside it, and do the plain Solana reads get ported for parity even with no
TypeScript consumer? Both answers are the owner's, and either one makes the row
mechanical.

## C05 `solana_rpc.rs` against `solana-rpc.ts`: PARTIAL

One of the two remaining behaviours is fixed. `fetch_confirmed_transaction`
retries each failure until the confirmation deadline; `getConfirmedTransaction`
retried only the unknown-transaction answer and failed on the first transport or
JSON-RPC failure, so a validator that dropped one request mid-confirmation
failed a fetch Rust completes. It now waits each failure out, and the abort check
inside `sleep` ends the wait when the caller cancels.

Three cases cover it: a request that fails once and then answers, the deadline
passing with the last failure reported, and an abort. Control edits: failing on
the first request failure, caught by two cases; never checking the deadline,
caught by the deadline case. A third control, restricting the retry to
`isRetryable` errors, was *not* caught, and rather than keep an unobservable
guard I removed it. `sleep` already refuses to wait on an aborted context, and
Rust retries each failure, so the guard would have made TypeScript the stricter
side for no reachable benefit.

Still open, and it is the reason the row is not `PARITY`: the grouping rules have
no Rust oracle. `transact_output_view_tags_from_instruction_groups` is public and
already pinned by `rpc-indexer-v1.json`, but
`instruction_groups_from_confirmed_transaction` is private and reachable only
through a client holding a URL. That is the function that turns a `getTransaction`
body into groups, appends loaded addresses writable before readonly, and rejects
absent metadata, an orphan inner group, and an out-of-range index. An oracle for
it needs the generator to stand up a mock HTTP endpoint and point a blocking
`SolanaRpc` at it, the way `xtask/src/bin/ts-fixtures.rs` already stands up a
listener. That is the smallest thing that closes the row, and it did not fit
here.

## T14 `wallet/state.rs` against `state.ts`: PARTIAL

The balance half is closed with an oracle. `AssetBalance` carried
`spendableAmount`, which has no Rust counterpart, and omitted `asset_id` and
`utxos`; `balance` had no `Filter` parameter, answered `undefined` for a
registered mint holding no note where Rust returns a zero balance, and answered
`undefined` for an unregistered mint where Rust raises `UnknownMint`; `balances`
declared `skipUtxos` and ignored it; `getPrivateTokenBalances` passed nothing
where `get_private_token_balances` passes `true`; and `id.index` was a `number`
against a Rust `u64`. The `walletBalances` section of the transaction oracle now
records that behaviour from the crate and `rust-oracle.test.ts` replays six
`balance` cases and both `balances` cases. Controls, each observed to fail:
ignoring `skipUtxos`, ignoring the filter, swallowing the unknown-mint rejection,
sorting by mint rather than asset id, and counting spent notes.

`last_synced` is also closed. The wallet now carries it, `decryptTransactions`
takes `config.syncedAt` the way `Wallet::sync` takes `synced_at`, and the sync
fixture's already-pinned `lastSynced: 30`, written by a Rust generator that syncs
at 10, 20, and 30, is now read. Control: hard-coding the commit to `0n`, caught.

The residual is one thing rather than a list: the transaction history. Rust
`PrivateTransaction` carries `asset`, `amount`, and
`counterparty_viewing_pubkey`, keeps `slot` inside the id, and has three
`direction` values; the port's row has none of the three fields, hoists `slot`,
and hard-codes `direction: "incoming"`. It cannot do otherwise, because the
sender-side rows that make the other two directions reachable are built by
`record_outbound_transfer`, `record_split`, `record_merge`, and
`record_confidential_send` in `sync.rs`, none of which is ported. That makes it a
T15 residual which T14's type signature exposes. `Balances` and `get_balance` are
deliberately not ported: `balances()` returns the array and `balance(mint)` is
`get_balance`, so a wrapper with no consumer would be new surface rather than
parity. `_state`, `_replace`, and `registerAsset` remain TypeScript-only, and are
the staging mechanism the clone-then-replace commit path needs.

## T15 `wallet/sync.rs` against `sync.ts`: PARTIAL

The recorded residual, "TypeScript still performs no tag-window scan", is stale.
`sync.ts` has `tagSites`, `scanStream`, `nextCount`, and
`advanceViewingKeyEntry`; it validates the window, resumes each family from its
stored counter, and advances `txCount`, `requestCount`, `knownSenders`, and
`knownRecipients`. Four tests in `wallet-viewing-key-history.test.ts` cover it.

That was not the whole story. A control edit that collapses `scanStream` to a
single window, deleting the extension that lets a wallet catch up with a
counterparty that ran ahead, passed all four tests. No test reached past the
first window. A fifth case now places sender tags at indices 1 and 3 with a
window of 2, so settling on 4 requires two extensions, and the same control edit
is caught.

Two things keep the row off `PARITY`. The counters are compared against
TypeScript expectations rather than a Rust oracle; the vehicle for one exists,
since `wallet_sync_vectors` in `xtask/src/ts_fixtures_transaction.rs` already
emits the transactions the port rebuilds, but its regeneration runs the whole
58-fixture generator. And the history rows described under T14 are unported,
which also makes `SyncReport` a different record: Rust reports `stored_utxos`,
`unparsed_transactions`, `undecryptable_candidates`, and `unknown_asset_ids`,
while the port reports `received`, `spent`, `transactions`, and
`unknownAssetIds`. Porting the four `record_*` builders and aligning the report
is the work; it is inside the SDK and it is roughly a row of its own.

## W02 `deposit.rs` against `deposit.ts`: PARITY

Nothing was wrong with the implementation; the evidence was hollow. The vector
test fed `utxoHashBytes` into the `Deposit` constructor and never compared it, so
the `owner_hash` and `ProofInputUtxo::new(..).hash()` derivation the row asked
about was echoed rather than checked. It now recomputes the hash from the
recorded owner and blinding and compares it. The fixture's SPL branch, meaning
the vault and registry PDAs and the `MissingSplTokenAccount` rejection, had no
reader at all; a second case drives `createDeposit` through it.

Control edits, each observed to fail: tagging with the viewing key instead of
`confidentialViewTag` (2 tests), swapping the vault and registry PDAs, dropping
the missing-token-account rejection, and reordering the asset and amount fields
of the commitment.

## W04 `actions/transaction.rs` against `private-transaction.ts`: PARTIAL

The row's two signing clauses rested on a reading. `wallet-actions` now records
from the crate which rail `apply_p256_signature` selects across the
authority/note rail matrix, and which single-field substitution between build and
sign `validate_unsigned_inputs` refuses; the port replays both through
`signPrivateTransaction`. All eleven substitutions are refused on both sides and
the unmodified case is accepted.

The rail rule produced a result a reading could not have. Rust selects on the
authority's own address alone, so it will build a P256 authority spending
ed25519-owned notes. The port cannot be driven there at all, because
`ConfidentialTransfer` rejects an input owned by another key before signing is
reached. TypeScript is therefore stricter, but on an input no Rust caller can
carry to a proof either, and loosening it would mean removing an owner check in
order to observe a rule. The test pins the earlier refusal and the row records
the rail rule as not discriminable through the public TypeScript surface. That is
the one judgement here an owner may want to revisit.

Control edits: reading the rail off the input notes is NOT caught, which is the
evidence for the paragraph above; never applying a P256 signature is caught by
the P256 case; dropping the whole-note comparison from the re-check is caught by
the five `utxo.*` substitutions; dropping the two attached hashes is caught by
their own two.

## What stands between this and the next phase

1. **C03 needs an owner's decision**, not an implementation. Does `Rpc` stay
   Solana-only with the indexer and prover assembled alongside it, and do the six
   plain Solana reads get ported without a TypeScript consumer?
2. **The wallet transaction history is unported** (`record_outbound_transfer`,
   `record_split`, `record_merge`, `record_confidential_send`). It is the shared
   residual of T14 and T15, and it is a row of work rather than a fix.
3. **The C05 grouping oracle needs a mock RPC** in the generator, because
   `instruction_groups_from_confirmed_transaction` is private and reachable only
   through a client holding a URL.
4. **W04's rail rule is unobservable** from the public TypeScript surface. If
   that rule has to be pinned, it needs a seam Rust has and the port does not.
