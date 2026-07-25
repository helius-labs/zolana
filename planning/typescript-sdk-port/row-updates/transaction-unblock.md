# Unblocking W06, W08, W09 and relaxing two over-strict guards

Landed in `d2ff553b`.

Four wallet rows were `BLOCKED` or carrying a strictness regression on state and
types that `@zolana/transaction` did not have. All of it now exists, and the
wallet sync code that read it is no longer inert.

Files changed: `sdk-libs/ts/transaction/src/` (wallet state, sync, authority,
zone-authority builder) and its tests, `sdk-libs/ts/wallet/src/actions.ts`, plus
the wallet package's re-export surface and the two wallet tests that covered the
missing field.

## W08: `Wallet` owns the viewing-key history

`sdk-libs/ts/wallet/src/sync.ts` derived its tag ranges from
`wallet.viewingKeyHistory`, a field no TypeScript type declared. The cast that
reached for it always read `undefined`, so every family fell back to the bare
window and the two shared families produced no tags at all. The test that
covered it wrote the field onto the instance with `Object.assign`, which is why
the suite stayed green over a field production code could not have.

`ViewingKeyEntry` and `CounterpartyCounter` now live in
`transaction/src/wallet/state.ts` next to the state they belong to, mirroring
`sdk-libs/transaction/src/wallet/state.rs:141`. `Wallet` seeds the identity
viewing key at construction exactly as Rust does
(`state.rs:160`), exposes the history as frozen snapshots, and carries it
through `_state()` / `_replace()` so a sync updates it atomically with the UTXO
set. Omitting the field from `_replace` leaves the scan position untouched,
which is what the balance-only callers want.

`decryptTransactions` advances it where Rust's `Wallet::sync` does
(`sdk-libs/transaction/src/wallet/sync.rs:781-905`):

- `ensure_viewing_key_entries` equivalent: a rotated-in viewing key gets an
  entry starting at zero rather than being skipped.
- `txCount` from the sender-bundle tag sites, `requestCount` from the recipient
  slot tag sites, both through the same window-extending `scan_stream` walk, so
  a gap shorter than the window does not end the scan.
- `knownSenders` from the sender of an anonymous recipient slot, recorded only
  once the decoded note matched its committed leaf.
- `knownRecipients` from two places, matching Rust: the recipient list inside a
  sender bundle this wallet authored, and the viewing key prefixed to each
  confidential recipient slot of a transfer this wallet sent
  (`record_confidential_send`, `sync.rs:377-438`). The second was missing
  entirely, so a wallet that sent a confidential transfer never asked for that
  pair's shared family again.

### Evidence that the sync path is live rather than inert

`sdk-libs/ts/transaction/test/wallet-viewing-key-history.test.ts` (new) covers
seeding, the sender counter, the request counter with its discovered sender, and
the confidential-send recipient. Removing the advance from `decryptTransactions`
fails the counter assertions, so the tests fail when the behaviour is removed.

End to end, `sdk-libs/ts/wallet/test/sync.test.ts` now drives `syncWallet`
against an indexer double that records every tag it is asked for: a note from an
unknown sender arrives on a request tag in the first round, and the sender's
shared family appears in a later round's query set. That family is derivable
only from `knownSenders`, which only the advance populates. The `Object.assign`
fabrication is gone; the counters test seeds through `_replace`.

## W06 and W09: the three authority names

Against `sdk-libs/transaction/src/authority.rs:48-62` and
`sdk-libs/wallet/src/wallet_authority.rs`:

- `EncryptedEnvelope<P>` exists, and `EncryptedTransfer` /`EncryptedSplit` are
  payload aliases of it rather than two unrelated interfaces. The payload types
  reuse `MessageData` from `@zolana/interface` instead of restating
  `{ viewTag, data }` twice.
- `ApprovalRequest` is named, and `WalletAuthority.requestUserApproval` takes it.
- `LocalWalletAuthority` moved to `@zolana/transaction`, where Rust keeps it.
  `@zolana/wallet` re-exports it and every authority type it exported before, so
  the wallet surface is unchanged for downstream code; `wallet-authority.ts` is
  now re-exports only, like its Rust counterpart.

## W04 and the two over-strict guards

1. `positiveAmount` in `wallet/src/actions.ts` rejected `amount === 0n`. Rust's
   `create_withdrawal` performs no amount check and `select_inputs` returns on
   the first note because `available >= 0` holds, so TypeScript refused a
   withdrawal Rust builds. The guard is now `u64Amount` and refuses only what
   the Rust `u64` cannot hold. `wallet/test/wallet.test.ts` asserts a
   zero-amount withdrawal builds and that `2^64` is still refused.
2. `prepareZoneAuthority` rejected any nonzero public amount, which refused a
   zone-authority *deposit* under an error named for withdrawal. Per
   `rejection-validation.md`, neither the program nor the circuit gates a public
   leg on the authority rail. The narrow relaxation to `amount < 0` landed in
   `d2ff553b`; the owner then ruled in `authority-rulings.md` (`2030aa2f`) that
   a zone authority may pay value out as well, on the strength of
   `double-spend-analysis.md` showing by execution that nullification and
   settlement share one instruction with no partial-application path. The guard
   and its error code `TRANSACTION_ZONE_AUTHORITY_WITHDRAWAL_NOT_ALLOWED` are
   therefore gone, and the test asserts a public leg builds in either direction.
   The Rust counterpart (`sdk-libs/transaction/src/instructions/zone_authority.rs:72-80`)
   still carries the `amount != 0` guard and needs the same removal; that crate
   is outside this change.
3. `LocalWalletAuthority.requestUserApproval` rejected a request naming another
   Solana address with `WALLET_APPROVAL_IDENTITY_MISMATCH`. Rust takes the trait
   default, which approves without inspecting the request, so the error code is
   gone and the e2e assertion expects resolution.

The comment above `prepareZoneAuthority` repeated the premise that nobody signs
a zone-authority spend. The zone's `zone_config` PDA signs and only the zone
program can sign for it; it is the UTXO owners who do not. Both that comment and
the one over its test now say so.

## Where TypeScript is still stricter than Rust

- A caller who builds `PreparedZoneAuthority` as an object literal skips its
  guards, because every field is public in both languages. Closing
  it in TypeScript means branding the interface, which would break
  `sdk-libs/ts/client`'s own literal construction, and that package is outside
  this change. Recorded rather than done.
- Nothing else. The diff adds no rejection that Rust does not perform:
  `u64Amount` keeps only the range the Rust `u64` enforces by type, the zone
  guard now covers only the outgoing direction, and every new sync helper
  (`tagSites`, `scanStream`, `confidentialSendRecipients`,
  `ensureViewingKeyEntries`) skips what it cannot decode instead of failing on
  it.

## Verification

- `cargo test -p zolana-transaction -p zolana-wallet`: green except
  `input_commitments_include_data_and_zone_hashes`
  (`sdk-libs/wallet/tests/transaction.rs:769`, `MissingZoneProgramId`), which
  fails on the committed tree with no Rust file modified here.
- `npm run test:unit` 453 passed / 1 skipped, `test:vectors`, `test:cross`,
  `typecheck`, `build`, `test:exports`, and `test:e2e:actions` 9 passed. Run
  after the deposit tag moved to the recipient signing pubkey (`1ff51a4c`,
  `114a5140`); nothing here derives that tag, and the wallet vector suite that
  pins it passes.
- Note for anyone reading a red run: the TypeScript packages resolve each other
  through `dist`, so a stale build after someone else's commit reports failures
  that a rebuild clears. Two deposit-vector failures seen mid-session were
  exactly that.
