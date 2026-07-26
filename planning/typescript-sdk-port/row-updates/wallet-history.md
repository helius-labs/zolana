# Wallet history, merged with the zone read path and the K11 narrowing

Worker on `port/tx-history` from `ts-sdk-port`. Touches
`sdk-libs/ts/{transaction,wallet}`, `xtask/src/ts_fixtures_transaction.rs`, the
`wallet-sync` fixture, and this directory. No Rust behaviour changed; Rust is
the authority throughout.

Rows: **T14** and **T15** can close. **T16** improves but stays open.

[tx-history.md](./tx-history.md) is this branch's earlier record and holds the
recorder-by-recorder detail, the argument for deleting `"pending"`, and the
fixture layout. Read it for the port itself. This file records the merged state:
what the integration with `ts-sdk-port` cost, what the evidence now is, and what
is still owed. Where the two disagree, this one is later.

## The merge: both sides survive

`sync.ts` was the only real conflict, and it was an integration rather than a
choice between two texts. This branch was cut before the zone read-path rewrite
and the K11 narrowing, and both belong inside the ported algorithm rather than
beside it.

**The zone read path.** The rewrite moved the zone-shape rule out of the `Utxo`
constructor into `resolveZoneProgramId`, called where Rust's
`resolve_zone_program_id` is called, and lifted `plaintextTransferUtxos` and
`prooflessUtxo` out of `wallet/sync.ts` into `serialization/codecs.ts`. This
branch's `sync.ts` had its own decoders and relied on the constructor invariant.
Resolved by deleting both and calling the exported pair, so the rule now fires at
one place per rail. `decodeSlot` passes no zone program id to
`plaintextTransferUtxos`, `anonymousSenderUtxos`, `splitBundleUtxos`,
`anonymousRecipientUtxo` or `mergeUtxo`, which is Rust's
`OwnerCx { zone_program_id: None }`; the confidential and proofless rails read
the id out of their own payload, as Rust does. The constructor invariant is not
reintroduced.

**K11.** `ViewingKey` became `ViewingKeyLike` at every call site that takes a
key, and `publicKey()` returns the narrowed type. `NullifierKey` and
`ShieldedPublicKey` stay, as type-only imports, because `SyncPass` holds them as
fields rather than accepting them at a boundary.

**No semantic conflict.** The two changes and the history port touch disjoint
concerns: one decides how a decoded plaintext becomes a UTXO, one decides what a
key parameter is typed as, and one decides what a decoded UTXO writes into the
history. Nothing had to be given up on either side.

One test from the zone-read branch failed afterwards, correctly.
`zone-resolution.test.ts` published its plaintext-transfer slot under a zero view
tag and read `report.received`. The rename explains half; the tag explains the
rest. `PlaintextTransfer::encode` tags the sender slot with the owner's
`confidential_view_tag` (`serialization/plaintext.rs:42`), and `TxIndex` files it
under that tag, so a slot tagged zero is one the sync never opens. The test only
reached the decoder because TypeScript used to try every slot regardless of tag.
Tagging the slot the way the sync indexes it restores what the case meant to
check, and it still fails when the zone-data refusal is deleted.

## Evidence

The claim is not that the two files read alike. Three things back it.

**The oracle is reproducible from Rust.**
`rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check` regenerates
every fixture from the crates and compares: 58 fixtures and 182 inventory rows
clean, including the regenerated `wallet-sync-v1.json`. So the committed history
rows, reports and scan counters are what Rust produces at this revision, not what
someone typed.

**The replay compares everything the oracle records.**
`wallet_history_vectors` syncs seven chained transactions one at a time (deposit,
inbound anonymous, outbound anonymous, confidential send, confidential
withdrawal, split, merge) and records, after each step, the `SyncReport`, the
full history, and each viewing key's scan counters.
`wallet-sync.test.ts` replays the same seven in the same order and compares all
three. The `parallelEquivalent` and `tamper` sections now compare the whole
report rather than only `storedUtxos`.

**Controls.** Seven edits, seven failures. Five are recorded in
[tx-history.md](./tx-history.md); two were re-run against the merged tree:
recording a merge as `inbound` (caught by the row comparison) and advancing a tag
counter by `maxPresent` instead of `maxPresent + 1` (caught by the counter
comparison). An eighth control covers the guard-order fix below.

## What T14 and T15 were blocked on

T14's residual was the history: `PrivateTransaction` lacking `asset`, `amount`
and the counterparty key, `slot` hoisted out of the id, and a hard-coded
`direction`. All four are fixed, and the recorders that fill them exist.

T15's residual was two things. The counters were compared against TypeScript
expectations rather than a Rust oracle: they are now compared against
`viewing_key_counters_json`, per step, with the off-by-one control caught. And
`SyncReport` was a different record while the history was unported: it is now
Rust's four fields, pinned per step and at three more call sites.

T15 also carried an observation that Rust passes an `OwnerCx` without a zone
program for the non-proofless schemes. That is still true of Rust and is now
mirrored exactly rather than approximated, so it is a note about Rust rather than
a gap in the port.

## T16 stays open

`decryptTransactionsWorkerEquivalent` still returns `decryptTransactions(input)`.
No worker, no cancellation, no secret transfer, and no recorded platform
disposition for the alias. That is T16's core finding and it is untouched.

One clause of the row is now false and should be struck when the row is next
read: "no test asserts that serial and parallel runs reach the same state". Both
sides assert it. `wallet_sync_vectors` asserts `sequential.utxos ==
parallel.utxos` and `sequential.transactions == parallel.transactions` in the
generator, and the TypeScript replay asserts its own report equals the report
Rust's `sync_parallel_with_material` produced, and that its notes and history
equal the sequential run's. So the equality is pinned; the implementation is not.
`DIVERGENT` -> `PARTIAL` looks right, but the verdict is the reconciler's.

## Fixed here, beyond the two rows

**The material guards ran in the wrong order.** Rust checks the identity, then
that the material carries the current viewing key, then the nullifier key
(`sync.rs:747-760`). TypeScript folded the nullifier-key check into the identity
check, so material wrong in both ways was rejected as
`TRANSACTION_WALLET_AUTHORITY_MISMATCH` where Rust says
`MissingCurrentViewingKey`. That is a plausible input rather than a contrived
one: rotated key material is where both go stale together. Split into three
checks in Rust's order,
with a case in `wallet-sync.test.ts`; reverting the split fails it. Evidence
grade is lower than the rest of this branch: the ordering is read off five lines
of Rust control flow rather than generated, because the fixture builds each
wrong-material case wrong in only one way.

**A test left behind by the type rename.** `wallet/test/wallet.test.ts` built an
expected deposit row in the pre-port shape: `direction: "incoming"`, a top-level
`slot`, no `asset` or `amount`. Moved onto the Rust shape.

## Found and not fixed

**Test files are not type-checked, so a type rename can leave invalid values in
them and no gate notices.** `config/typecheck.mjs` compiles `src/**` per package
plus an opt-in `test/types` project; ordinary `test/**` is checked by nothing.
The stale row above is what that costs: it survived a type change that
contradicts it, and it was found by reading rather than by a gate. Closing it
means a project that compiles `test/**`, which is a tooling change owned by
whoever holds the CI rows, and it is likely to surface more than one finding when
it lands.

**Rust's free `decrypt_transactions` has no TypeScript counterpart, and its
oracle field is unasserted.** `sync.rs:940-962` exposes
`decrypt_transactions(key, transactions, registry) -> Balances`, which builds a
wallet, syncs it, and returns balances. TypeScript's `decryptTransactions` is the
`Wallet::sync` equivalent: it takes a wallet and returns a `SyncReport`. The
names collide and the free function is absent, so
`expected.decryptTransactionsBalance` in the fixture is generated and read by
nothing. Not fixed because the fix is a public-surface decision, not a defect:
either add the free function under a name that does not collide, or record a
disposition. Rust carries its own `TODO(separate PR)` saying the function should
move onto `Wallet`, so the shape is unsettled on that side too. This is a T15
item nobody has recorded.

**Two history branches the oracle does not reach.** `#recordReceived` maps a
decoded sender equal to the wallet's own viewing key to `selfTransfer`; no
fixture transaction does that, so only the `inbound` arm is exercised. And every
history scenario moves SOL alone, so `#recordOutboundTransfer` and `#recordSplit`
never emit a second asset row: `SENDER_HISTORY_ROW_BASE + row` is only ever seen
at `row == 0`, and the rule that a dropped zero-amount row still consumes its
index is unobserved. Both are Rust-faithful by construction and neither is
suspected wrong; they are uncovered, not divergent. Closing them means two more
transactions in `wallet_history_transactions`, which is a fixture regeneration.

**Ordering of the window check against the material fetch.** Rust's
`Wallet::sync` fetches `authority.sync_material()?` and only then rejects a zero
window; TypeScript rejects the window first and never calls the authority. Left
alone deliberately: Rust's order is an artifact of `sync` being a thin wrapper
over `sync_with_material`, and the TypeScript order avoids pulling key material
out of an authority for a call that is already invalid. Observable only when the
authority also fails. Recorded rather than changed, because it is the kind of
difference that should be ruled on rather than churned.

## Gates

`npm run build` before every run, per the standing note; the failures it prevents
look like logic errors. From `sdk-libs/ts`: `build`, `test:unit` (2006 passed, 1
skipped, 118 files), `typecheck`, `lint`. All green. Plus
`cargo run -p xtask --bin ts-fixtures -- --check`, clean.
