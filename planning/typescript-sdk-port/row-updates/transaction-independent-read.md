# Transaction cluster: an independent read, salvaged from a collision

A second worker was dispatched onto `port/tx-close` while the first was still
live, because the coordinator misread a lagging transcript as a hung process.
The second one detected the collision, made no edits, and stopped. This file is
what its read found, kept because the findings are unowned and none of them is
recorded anywhere else.

Nothing here has been folded into a row. The worker still on `port/tx-close`
owns these rows; where its report and this one disagree, read its report and
ignore this one.

## The instruction the coordinator gave was wrong: T28 clause three

The task sent to the transaction worker said the only thing left on T28 was
"refusing a zone data hash at or above the BN254 modulus." Implementing that in
TypeScript alone would have created a divergence rather than closed one.

Both languages already refuse an out-of-field zone data hash, by deferring to the
Poseidon range check rather than by validating up front. Rust maps
`light_poseidon` failures to `TransactionError::Poseidon` in
`sdk-libs/transaction/src/utxo.rs:12-18`. TypeScript reaches the same category
through `commitmentPoseidon`, which the live worker added at
`ts/transaction/src/internal.ts:114-115` as its T28 error-mapping fix. After that
commit the two agree.

An early constructor refusal on the TypeScript side would move the rejection
earlier while Rust stayed where it is, which is the "TypeScript stricter than
Rust" shape this port has already been caught by once, on the zone read path. The
clause is Rust-first or simultaneous, and Rust is out of scope. On this clause
the row looks already at parity rather than owed.

Verified independently by the coordinator before recording: the Rust mapping and
the `commitmentPoseidon` call site both read as described.

## T23 is wider than the row records, and three of the gaps run the dangerous way

The row records one residual, that TypeScript refuses out-of-field Poseidon
inputs where `spp_proof_inputs.rs` range-checks nothing. Comparing the two
`SppProofInputs` in full turns up four more. Three of them are TypeScript
refusing inputs Rust accepts.

- Rust's constructor does not validate the shape; `check_shape` is a separate
  method (`spp_proof_inputs.rs:91-104` and `:118-125`). TypeScript's constructor
  calls `this.checkShape()` (`transact.ts:514`), so it refuses to build an
  unsupported shape that Rust builds and hashes without complaint.
- Rust `sign_p256` checks the keypair's curve (`:106-116`). TypeScript
  `applyP256Signature` checks the inputs instead and adds a
  `TRANSACTION_SIGNATURE_OWNER_MISMATCH` rule Rust has nowhere
  (`transact.ts:564-580`). A P256 keypair signing a transaction whose inputs are
  all Ed25519-owned succeeds in Rust and throws in TypeScript.
- Rust `public_amounts()` returns three 32-byte field encodings including the
  resolved SPL asset field and can fail with `MultiplePublicSplAssets` or
  `MissingPublicSplAsset` (`:127-160`). TypeScript's `publicAmounts()` returns
  `{ sol?: bigint, spl?: bigint }` with no field encoding, no asset, and no
  failure modes (`transact.ts:521-530`). It is not a port of the Rust method.
- `input_utxo_hashes()` returns `Vec<InputUtxoContext>` in Rust (`:162-178`); the
  identically named `inputUtxoHashes()` returns `Bytes32[]`, with the contexts
  split into `inputContexts()` (`transact.ts:532-546`).

T23 needs re-scoping before anyone declares it closed.

## `decrypt_transactions` names different behaviour in the two languages

Rust's `decrypt_transactions(key, transactions, registry) -> Balances` builds a
fresh wallet, syncs it, and returns balances (`sync.rs:940-962`). TypeScript's
`decryptTransactions({ wallet, authority, ... }) -> SyncReport` mutates a
caller-supplied wallet and returns the report (`sync.ts:856-925`), which is
Rust's `Wallet::sync` (`sync.rs:711-720`). `module-surface.test.ts:47` records
the pair as a plain rename, which conceals the difference. Rust's `Wallet::sync`
and `sync_with_material` have no TypeScript counterpart under any name.

## T16: it is Rust's serial path that is non-deterministic

`parallel.rs` parallelises only the pure tag probes; every decode stays serial.
The parallel path sorts counterparties by key bytes (`parallel.rs:242-243`,
`:268-269`) while the serial path walks `known_senders.keys()` in `HashMap` order
(`sync.rs:868`, `:893`). Decode order sets the push order of `Wallet::utxos`, so
Rust's serial sync yields a UTXO ordering that varies between processes once two
counterparties both have shared-tag hits. TypeScript's `CounterpartyCounters` is
a `Map` walked in discovery order: deterministic, and matching neither Rust path.

Any oracle pinning `utxos` order is pinning something Rust leaves unspecified.
That is worth knowing before more oracles are written against it.

## The "missing allowlists" residual on T17, T26, T30 and T31 is stale

`transaction/test/vectors/module-surface.test.ts` already drives all five
aggregates from the Rust-generated `moduleSurfaces` oracle. It requires every
Rust-published name to be carried or dispositioned with a written reason,
requires every TypeScript-only export to be explained, fails when a disposition
goes stale, and fails when a dispositioned name ships anyway (`:333-387`). It
pins the `UtxoSerialization` capability table per scheme (`:390-427`) and
enforces one declaration site per exported name (`:435-456`).

There is a trap in the recorded fix. `Balances` and
`decrypt_transactions_with_config` are deliberately dispositioned as not carried
(`:70-75`, `:88-91`), so the checklist's implied "add the missing names" would
turn that test red. The worker had that fix queued and the test caught it.
