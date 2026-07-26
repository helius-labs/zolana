# The transaction package's exported names, pinned to Rust

Eleven of the fifteen open transaction rows named the same defect: a Rust type
with no TypeScript counterpart, or one that exists but never reaches a barrel.
This batch closes that cluster by making the omission detectable instead of
fixing eleven names by hand.

Commits: `c57f0566`, `7365c675`, on `port/tx-surface`.

## The gate that was missing

The brief said the package's public surface is pinned by export allowlists that
`check:packaging` enforces, and that widening it is a deliberate act with a gate
behind it. That is not what the gate does. `workspace-check.mjs exports` asserts
the manifest shape and that `package.json` export *paths* equal
`packages.mjs` `entryPoints`; `api:check` is a scaffold check. Neither reads a
single exported name. Adding twelve names to the root and running
`check:packaging` passes without comment, which is why eleven rows could each
record a missing name and none of them could be caught by CI.

So the first piece of work was the gate. `sdk-libs/transaction/tests/ts_oracle.rs`
now emits, for each of the five Rust modules that back a TypeScript entry point,
the names that module publishes and the names its submodules publish, plus the
`UtxoSerialization` implementors and the trait's operations. The oracle is
committed at `sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`
and `cargo test -p zolana-transaction --test ts_oracle` fails if it drifts from
the Rust source.

`sdk-libs/ts/transaction/test/vectors/module-surface.test.ts` replays it. Every
Rust name must be carried under the same name, carried under a recorded rename,
or dispositioned with a written reason. Every TypeScript export must have a Rust
counterpart or a recorded reason to exist. A disposition that stops being true
fails too: a name recorded as not carried that later ships, and a reason
recorded for an export that is later removed, both break the test.

**Control edit.** Deleting `PrivateTransactionKind` from the wallet barrel and
adding a bogus `ControlOnlyName` export produced two failures naming both
symbols exactly. Restored, 471 tests pass. The test detects a divergence in both
directions rather than merely passing.

## Rows

### T10 `serialization/mod.rs`: propose `done` on the named residual

The row named `DecodeCx`, `OwnerCx` and `UtxoSerialization` as unrepresented,
`SplitBundlePlaintext` as two different types, and the allowlists as absent.

`DecodeCx` ships as `DecodeContext` with a `decodeContextForSlot` constructor,
from the root and `./serialization`. It is threaded through `decodeCandidate` in
`wallet/sync.ts`, which previously destructured the same five values at each
call site, so the type is load-bearing rather than declared to satisfy a row.
`OwnerCx` already shipped as `OwnerContext` and is now pinned by the oracle.

`UtxoSerialization` closes as **not-applicable**, and the reason is in the test
rather than in this file. A Rust trait has to be in scope for `Split::decode` to
resolve; it is never a bound and never a `dyn`, so there is no polymorphism for
an interface to carry. What the trait actually buys is a promise that every
scheme offers the same operations, and that promise is now pinned directly: a
capability table names the TypeScript function behind all six operations of all
seven schemes, and the oracle supplies both lists, so a scheme Rust adds fails
the test until its row is filled in.

`SplitBundlePlaintext` is one type, since `wallet/authority.ts` re-exports the
`serialization/codecs.ts` declaration, so that half of the row was already
fixed. It was not *pinned*, though, and a general check for the same defect
found the next instance: `P256Signature` was declared independently in
`instructions/transact.ts` and `wallet/authority.ts`. Structural typing hides a
split like that until the copies drift, at which point two entry points hand out
incompatible shapes under one name. Consolidated, and the test now fails on any
name two modules declare (`7365c675`).

Residual, and the reason this row may not close outright: the declaration,
runtime, tarball, browser and consumer allowlists the row also asks for are
still absent. They are packaging artifacts rather than surface facts, and this
batch did not produce them.

### T26 `instructions/transact/mod.rs`: propose `done`

The residual was that `./transact` omits most of the 29 flattened Rust symbols,
naming `EncryptedTransaction`, `InputUtxo`, `OutputSlot`, `ShieldedTransaction`
and `SppProofOutputUtxo`. Three already shipped. `OutputSlot`, `ProofOutputUtxo`,
`SENDER_SLOT_COUNT`, `encodeConfidentialSlots` and `signedToField` were added.
The barrel now carries or dispositions every name the Rust module publishes, by
execution against the oracle rather than by inspection.

Allowlists remain absent, as on T10.

### T30 `instructions/mod.rs`: propose `done` on the surface half

`OutputSlot` reached `./instructions`. The row's own observation that Rust
`instructions/mod.rs` declares its modules without re-exports is confirmed by
the oracle: that module's published surface is its submodule surface, which is
what the test compares against. The row inherits T18 to T29 and its allowlists are
absent, so the reconciler decides whether the inheritance keeps it open.

### T31 `lib.rs`: propose `done` on the surface half

Every name in the row's omission list is now carried or dispositioned.
`OutputSlot`, `IndexedShieldedTransaction` (the deliberate rename of
`ShieldedTransaction`), `DecodeContext`, `OwnerContext` and the four
`PrivateTransaction*` types were added; `EncryptedTransaction`, `InputUtxo`,
`Blinding`, `ApprovalRequest`, `Filter`, `LocalWalletAuthority`,
`ViewingKeyEntry` and `WalletSyncConfig` already shipped and are now pinned;
`UtxoSerialization`, `Balances` and `decrypt_transactions_with_config` are
dispositioned with reasons.

The row's separate quality finding is fixed. `TRANSFER`, `SPLIT`, `MERGE` and
`TRANSFER_PLAINTEXT` were declared at the root with no consumer while the codecs
that read and write those bytes used a private `SPLIT_TYPE_PREFIX` and a bare
literal `4`. The constants now live once, beside the reader and writer that
enforce them, and the root re-exports them. `DEFAULT_TAG_WINDOW` had the same
shape, a root constant with no consumer beside a literal `64n` default in
`wallet/sync.ts`, and now lives in `wallet/sync.ts` as the default the sync
actually reads.

### T17 `wallet/mod.rs`: propose `done` on the named residual

`ApprovalRequest`, `Filter`, `LocalWalletAuthority`, `ViewingKeyEntry` and
`SyncConfig` (as `WalletSyncConfig`) were already exported and are now pinned.
The four `PrivateTransaction*` types were unions inlined in `PrivateTransaction`
and are now named types exported from the root and `./wallet`.

Two dispositions, both arguing the row should not get a mechanical export:

`Balances` closes as **not-applicable**. It is a newtype over
`Vec<AssetBalance>` whose only method finds an entry by mint. `Wallet.balances()`
returns the array and the caller finds. The wrapper buys nothing in a language
with array methods, and adding it would put a second shape between callers and
their balances.

`decrypt_transactions_with_config` closes as **not-applicable**:
`decryptTransactions` takes the config as an optional parameter, so one
TypeScript function covers both Rust entry points.

`decryptTransactionsWorkerEquivalent` is recorded as a declared TypeScript-only
alias rather than a silent one, which is what the row asked for; the behaviour
behind it stays with T16.

### T14 `wallet/state.rs`: propose `needs_fix`, with the surface half closed

The row's surface asks are done: `ViewingKeyEntry`, `Filter` and the four
`PrivateTransaction*` types are exported, and `Balances` is dispositioned above.

The rest of the row is not a surface problem and this batch did not touch it.
Reading the two files side by side while naming the types turned up that the
divergence is wider than the row records:

- Rust `PrivateTransaction` carries `asset`, `amount` and
  `counterparty_viewing_pubkey` (`wallet/state.rs:44-52`). TypeScript carries
  none of the three, so a history row cannot say what moved or who it moved to.
- Rust `PrivateTransactionId` carries `slot` alongside `signature` and `index`
  (`wallet/state.rs:14-21`). TypeScript puts `slot` on the transaction and omits
  it from the id.
- Rust `PrivateTransactionStatus` has one variant, `Confirmed`. TypeScript
  admits `"pending"`, a state Rust cannot represent and nothing in the port
  produces.
- Rust's variants are `PrivateTransfer` and `PublicWithdrawal`; TypeScript's
  union says `"transfer"` and `"withdrawal"`.

Each is a change to what the wallet's history returns, with fixtures behind it.
Naming the types without changing their contents was deliberate: it is the half
that can be verified today, and it leaves the behavioural half to T14's owner
rather than burying a shape change inside a surface batch.

### T12 `wallet/asset.rs`: no change, one decision still open

The row is waiting on an API call about `entries()`, not on evidence. This batch
did not make that call. Noting only that `entries()` is now pinned by the
surface test as an export requiring a disposition, so whichever way the owner
decides, the decision gets recorded rather than assumed.

### T06, T13, T15, T16, T21, T23, T28, T29: no change

These are behavioural rows. Their residuals are shared-tag progression (T06),
four Rust authority prerequisites (T13), the tag-window scan (T15), the worker
adaptation (T16), the `ExternalDataHash` boundary vector (T21), the payer-hash
derivation (T29), and so on. None is a surface omission and none is closed here.

## Found, not fixed: the read path drops Rust's zone resolution

The capability table has two empty cells, and they are empty for a reason worth
recording rather than filling.

`PlaintextTransfer::into_utxos` and `Proofless::into_utxos` have no exported
TypeScript counterpart. The logic exists, since `decodeCandidate` in `wallet/sync.ts`
reconstructs both, so exporting it would look like a one-line extraction. It is
not, because the inline version is not the same function.

Rust's `into_utxos` runs every reconstructed UTXO through
`resolve_zone_program_id` (`utxo.rs:49-60`), which returns
`MissingZoneProgramId` when the plaintext's `Data` carries zone data but no zone
program id was supplied. Wallet sync supplies `zone_program_id: None`
(`wallet/sync.rs:472-476`), so a plaintext-transfer or proofless slot whose data
carries zone data is refused and counted as an undecryptable candidate. The
TypeScript path applies no such check: it builds the UTXO with no zone program
id and stores it. A crafted payload therefore lands a UTXO in a TypeScript
wallet that Rust would have rejected, and whose commitment will not match the
one on chain.

Three schemes are affected in principle, since `PlaintextTransfer`,
`AnonymousRecipient` and `Split` all resolve the zone in Rust, though the
anonymous and split paths reach it through helpers this batch did not trace to
the same depth.

This is a behavioural finding on the read path, which belongs to T04, T07 and
T15 rather than to a surface batch, and closing it needs oracle cases for the
rejection rather than an export. The two cells are recorded in
`ABSENT_OPERATIONS` with the reason and a pointer, and the assertion inverts for
them: shipping either function without clearing the entry fails the test, so the
absence stays declared only while it is true.

## No Rust change required

Nothing in this cluster turned out to require Rust to move first. The one Rust
edit is to `tests/ts_oracle.rs`, which generates the oracle and ships no
protocol behaviour.

## Gates

`npx tsc -p sdk-libs/ts/transaction/tsconfig.json --noEmit`, `npm run
lint:packages`, `npm run check:packaging`, `cargo test -p zolana-transaction
--test ts_oracle`, and the package suite at 471 passing tests, before each of
the two commits.
