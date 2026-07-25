# Deposit discovery tag: viewing pubkey -> signing pubkey

Implementation of option A2 from `interface-spec-conflicts.md`, on the protocol
owner's ruling that the deposit's discovery tag is the recipient's signing
pubkey, per `spec.md:373` ("every output is tagged by its owner pubkey"). Both
SDKs derived it from the recipient's viewing pubkey x-coordinate.

No program change, no circuit change, no key rotation, no sync change. The spec
half of the ruling belongs to a separate worker; `docs/spec.md` is untouched
here.

## Why the change is worth making

The divergence is invisible inside this repository, because both zolana wallets
scan the signing tag and the viewing (bootstrap) tag unconditionally. It becomes
visible at the interoperability boundary: a third-party wallet or indexer built
to `spec.md:373` scans owner pubkeys only and finds no zolana-SDK deposit. The
program copies the tag into the output slot without reading it
(`deposit/event.rs:44`), so a mistagged deposit is accepted, indexed, and simply
never discovered. No layer on the path raises anything.

That is also why a green test suite is weak evidence for this change, and why
the verification below isolates the tag rather than relying on suite colour.

## Sites changed

Rust:

- `sdk-libs/wallet/src/actions/deposit.rs`. `Deposit::new` now derives
  `view_tag` from `ShieldedAddress::confidential_view_tag()`. This is the
  production derivation; everything else follows it.
- `sdk-libs/program-test/src/wallet_data.rs`. `wallet_shield_fields`, the
  harness mirror of the SDK derivation.
- `program-tests/spp-test-validator/tests/deposit_action.rs`. The test crate's
  sender-driven deposit action, another mirror.
- `xtask/src/ts_fixtures_wallet.rs`. `deposit_vectors` builds `DepositIxData`
  inline (it needs a deterministic blinding, so it cannot call `create_deposit`)
  and therefore carried its own copy of the derivation.

TypeScript:

- `sdk-libs/ts/wallet/src/deposit.ts`. `createDeposit` now uses
  `recipient.confidentialViewTag()`.
- `sdk-libs/ts/test-kit/src/wallet-data.ts`. `walletDepositData`, the test-kit
  mirror.

Both SDKs already exposed the signing tag on `ShieldedAddress`, so no new input
reaches the depositor and no public surface changed.

Not changed, deliberately: `resolved_address_from_record` /
`resolveRegisteredAddress` still expose `ResolvedAddress.view_tag` as the
viewing pubkey x-coordinate (`sdk-libs/wallet/src/user_registry.rs:428`,
`sdk-libs/ts/wallet/src/registry.ts:341`). That field is a registry lookup
result, not the deposit derivation, and the ruling did not cover it. It is worth
a decision of its own: a third-party depositor that reads the recipient's tag
from the registry and writes it to a deposit reproduces exactly the bug this
change removes. The signing-tag accessor for that purpose already exists as
`recipient_confidential_view_tag`.

## Tests

Both languages gained a dedicated test that asserts the tag **is** the signing
tag and **is not** the viewing tag, so a reversion fails on the tag itself
rather than somewhere downstream:

- `sdk-libs/wallet/src/actions/deposit.rs::deposit_tags_the_recipient_signing_pubkey`
- `sdk-libs/ts/wallet/test/wallet.test.ts`, "tags a deposit with the recipient
  signing pubkey"

Updated assertions that pinned the old derivation:
`sdk-libs/ts/wallet/test/wallet.test.ts:90`,
`sdk-libs/ts/test-kit/test/test-kit.test.ts:251`. The tag assertion in
`prepared_sol_deposit_derives_consistent_material` moved into the dedicated test
rather than being duplicated.

## Fixtures

One fixture changed: `sdk-libs/ts/fixtures/wallet/deposit.json`, plus its
`sha256` entry in `sdk-libs/ts/fixtures/manifest.json`.

Within it, three values move, all for the same reason. The tag is the first
field of the deposit payload, so it is embedded in what the encoding produces:
`viewTagBytes`, `instruction.dataBytes`, and
`unsignedTransaction.messageBytes`. `ownerBytes`, `blindingBytes`, and
`utxoHashBytes` are unchanged, because the tag does not feed the commitment.

The frozen `workflows/deposit-v1.json` and `interface/deposit-instruction-v1.json`
oracles are unaffected: they feed a synthetic tag in as an *input* to the
encoder rather than deriving one.

### Separating this from the pre-existing `fixtures:check` failure

`fixtures:check` was already red before this change, and still is. The failure
is `assert_frozen_sources`, which refuses to run the generator while any
`BASELINE_SOURCE_PATHS` entry differs from the pinned revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`. At the start of this work four paths
already differed, none of them mine: `sdk-libs/client/src/prover`,
`sdk-libs/keypair/src`, `sdk-libs/transaction/src`, `sdk-libs/transaction/tests`.
`sdk-libs/wallet/src` was clean; this change adds it as a fifth.

That drift already leaves five fixtures differing from what the generator now
produces, and they are left untouched: `client/errors-v1.json`,
`client/lib.json`, `client/rpc-indexer-v1.json`, `transaction/utxo-v1.json`,
`wallet/wallet_sync.json`.

To attribute the fixture change precisely rather than regenerating over that
drift, the generator was run twice into a scratch directory, once with the
pre-change sources and once with the post-change sources, and the two trees
compared. The difference between those runs is exactly `wallet/deposit.json` and
the manifest, which is what was taken. The committed file is byte-identical to
the generator's output; nothing was hand-edited.

Clearing the frozen-source guard means bumping the pinned baseline revision,
which would absorb four other workers' drift in the same move. That is not this
change's call to make.

## Evidence that a deposit still becomes a spendable balance

`npm run test:e2e:actions` passes 9 of 9 in about 10s in process. That suite is
meaningful rather than incidental: its indexer double filters by tag
(`e2e/support/doubles.ts::tagged` -> `TestIndexer.byViewTag`), so a deposit whose
tag is absent from the wallet's query set is served to nobody and the wallet
syncs to a zero balance, failing the downstream transfer, merge, split, and
withdraw assertions.

But that suite passes under *either* derivation, because sync asks for both
tags. To isolate the tag, a throwaway script (not committed) served deposits
through an indexer restricted to one tag at a time:

| deposit | indexer answers | discovered |
| --- | --- | --- |
| new derivation | signing tag only | 42 |
| old derivation | signing tag only | 0 |
| old derivation | both tags | 42 |

Row 1 is the positive result: discovery works through the signing tag alone, so
a spec-conformant third party now finds zolana deposits. Row 2 is the failure
mode in miniature: no error, no exception, just a zero balance. Row 3 is why
the scan cannot yet be narrowed.

Also green: `cargo test -p zolana-wallet --lib` (83 passed), the wallet and
test-kit vitest suites (60 passed, 1 skipped), and `npm run typecheck`.

## Can the dual-tag scan be narrowed?

**No. It must stay.** Narrowing it would silently strand the deposits already
made under the old derivation, which is the same failure this change exists to
remove.

Both wallets add the signing tag and the bootstrap (viewing-x) tag to every
query: `sdk-libs/wallet/src/wallet_sync.rs:314` and `:322`,
`sdk-libs/ts/wallet/src/sync.ts:102` and `:105`. After this change the deposit
path no longer writes the bootstrap tag, and it was the last production writer
of it. Confidential and transfer outputs already derive their tag from
`confidential_view_tag()` (`transact/transfer.rs:485`, `slots.rs:49`,
`serialization/plaintext.rs:42`). So the bootstrap tag is now unwritten by both
SDKs but still read by both.

Two things would have to be true before dropping it:

1. No deposit made under the old derivation remains unspent and undiscovered.
   That is a chain-state question, not a code question. It needs an indexer
   query over historical deposits carrying a viewing-x tag whose UTXOs are not
   yet nullified, per deployment.
2. The bootstrap branch in sync is doing nothing else. It is not only a
   deposit path: `sdk-libs/transaction/src/wallet/sync.rs:798-808` documents it
   as the anonymous policy-zone bootstrap scan that "also catches proofless
   deposits", and it populates `known_senders` from what it decodes. Removing
   the tag removes that scan too, so the anonymous rail would need its own
   answer first.

A migration would therefore be: confirm (2) by settling what the anonymous rail
tags its recipient slots with; then, per deployment, sweep or wait out the
remaining old-derivation deposits from (1); only then drop the bootstrap tag
from the query set. Until then the extra tag costs one entry per viewing key in
each indexer query, which is cheap next to silently unspendable funds.

A guard is worth adding when someone attempts that narrowing: a sync test that
stages an old-derivation deposit and asserts it is still discovered. It belongs
in `sdk-libs/ts/wallet/test/sync.test.ts` or beside the Rust sync tests. It was
not added here because the Rust `MockIndexer`
(`sdk-libs/wallet/src/wallet_sync.rs:641`) ignores the tag filter entirely, so
the existing Rust sync tests cannot express it without a tag-filtering mock, and
the TypeScript sync test file is held by another worker in this tree.

## Follow-up: the resolved tag (commit `c3aa8f5a`)

The "not changed, deliberately" paragraph above is now closed. A reconciliation
pass ruled that `ResolvedAddress.view_tag` had to follow the deposit derivation:
registry resolution is where a sender who knows only a Solana address learns
where to send, so it is the common path rather than an edge case, and it was the
last place handing out the viewing-x tag.

Both languages now derive it from the shared accessor:

- `sdk-libs/wallet/src/user_registry.rs::resolved_address_from_record` builds the
  `ShieldedAddress` first and takes `address.confidential_view_tag()`.
- `sdk-libs/ts/wallet/src/registry.ts::resolvedAddressFromRecord` mirrors it with
  `address.confidentialViewTag()`.

The two are identical, and the change carries a second correctness effect beyond
the deposit case: the resolved tag no longer moves when a sync delegate rotates
the record's viewing key. It is the owner tag, which is what a scanning wallet
looks for, and it survives delegation and revocation.

No in-repo caller reads the field. `create_transfer` /`createTransfer` and the
CLI deposit both take `resolved.address` and re-derive from it, so nothing
internal changed behaviour; the field is consumed only across the SDK boundary,
which is exactly why it was silently wrong.

### Tests

- `resolved_address_from_record_maps_registered_keys` and
  `resolve_registered_address_fetches_and_maps_record` now assert the signing
  tag; the first also asserts it **is not** the bootstrap (viewing-x) tag, so a
  reversion fails on the tag itself.
- `sdk-libs/ts/wallet/test/registry.test.ts` gained the same positive and
  negative assertions against the derivation rather than only against the
  fixture, so regenerating the fixture cannot re-pin the old value.
- The delegated-resolution test previously asserted the tag equalled the
  delegate's latest epoch key x-coordinate. It now asserts the owner tag and
  that it is *not* the epoch key.

### Fixture

One value moved: `viewTagBytes` in `sdk-libs/ts/fixtures/wallet/user_registry.json`,
from `ae140a14...` (viewing pubkey x) to `3250fcf6...` (signing pubkey x), plus
its `manifest.json` `sha256`. Both are the generator's own output, obtained the
same way as last time: the frozen-source guard was lifted locally, the generator
run into `target/ts-fixtures-check`, and only this file taken. The scratch run
differed in exactly the five pre-existing drifted fixtures plus this one, which
confirms the change's blast radius. The guard edit was reverted and not
committed.

No other fixture or oracle encodes the value. `workflows/deposit-v1.json` and
`interface/deposit-instruction-v1.json` still feed a synthetic tag as input.

### Is the derivation duplicated?

**No, but the call sites bypass it.** Each language has exactly one derivation:
`ShieldedPublicKey::confidential_view_tag()`, which `ShieldedAddress` forwards to
(`sdk-libs/keypair/src/shielded.rs:29`, `sdk-libs/ts/keypair/src/shielded.ts:62`).
Both bugs were sites that reached past that accessor for `viewing_pubkey.x()`
instead of calling it. After this change the only remaining readers of the
viewing-x value are the sync scan, which must keep it (see above), and the
negative assertions in the tests.

There is a smaller redundancy worth folding, and it is a call-path duplication
rather than a derivation one: `recipient_confidential_view_tag(_sync)` /
`recipientConfidentialViewTag` fetches the record and derives the tag itself,
which is now precisely `resolved_address_from_record(..).view_tag` with a zero
tag substituted for an unregistered owner. Expressing the accessor in terms of
the resolver would leave one path from record to tag per language. It is a
public-surface change in both SDKs, so it belongs in its own change rather than
here.

### Verification

Rust: `cargo test -p zolana-wallet` (83 + 13 passed) and
`cargo test -p zolana-transaction` (all suites green).

TypeScript, after a rebuild: `test:unit` 776 passed, `test:vectors` all green,
`test:cross` 66 passed, `typecheck`, `build`, `test:exports`, and
`npm run test:e2e:actions` 9 of 9. The two remaining `test:unit` failures are in
`sdk-libs/ts/client/test/merge.test.ts`, another worker's in-flight legacy
message-compilation change, and reproduce without this one.
