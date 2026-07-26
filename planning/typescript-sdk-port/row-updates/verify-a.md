# Independent verification: I37, K11–K14, W04

Branch `port/verify-a`, from the integration tip. This is a second pair of eyes
on the adverse residues those six rows still carry in
`review-checklist.md`, and on the closing claims in
[rereview-cluster.md](rereview-cluster.md),
[interface-keypair-stragglers.md](interface-keypair-stragglers.md),
[rulings-implementation.md](rulings-implementation.md), and
[stragglers.md](stragglers.md). Nothing in those reports was taken as true.
`review-checklist.md` was not edited.

**Result: all six close at `PARITY`.** Every residual clause on the checklist
rows is either false at this HEAD, or true but owned by another row or by
planning documentation rather than by the TypeScript surface the row names.

No production code was changed.

## I37 `program-libs/interface/src/lib.rs` -> PARITY

The checklist residue is the frozen-revision fixture gate failing with
`baseline fixture sources differ from revision 43fde8e4`, tracked as G8-1.

**False and stale.** `npm run fixtures:check` at this HEAD reports
`verified 58 fixtures and 182 inventory rows` and exits 0. The revision strings
in `sdk-libs/ts/fixtures/manifest.json` are provenance stamps:
`canonicalSourceRevisions.baseline` and `.interface` are both `8ce9897c`, while
`frozenCommit` / `historicalBaselineCommit` still quote `43fde8e4` as history.
The gate regenerates fixtures from the working tree and byte-compares them
(`xtask/src/bin/ts-fixtures.rs`), so a `43fde8e4` string mismatch is no longer
what fails the check.

The interface half the row also named is present: `interface/src/index.ts`
exports the root constants, and `interface/test/vectors/rust-oracle.test.ts`
pins `SHIELDED_POOL_PROGRAM_ID` against the Rust oracle.

**True but out of scope for the port:**
[production-readiness-issues.md](../production-readiness-issues.md) G8-1 and
[testing-and-conformance.md](../testing-and-conformance.md) still describe the
old red gate and the old `43fde8e4` baseline pin. That is planning prose, not an
`interface` behaviour gap, and it is what the fixture-gate / docs owners should
update.

## K11 `sdk-libs/keypair/src/traits/view_key.rs` -> PARITY

The checklist residue is that three call sites still bind the concrete
`ViewingKey`, that the `test/types/` project does not exist, and that
`typecheck.mjs` does not compile it.

**All three claims are false at this HEAD.**

`transaction/src/wallet/sync.ts`, `transaction/src/serialization/codecs.ts`, and
`wallet/src/sync.ts` each take `ViewingKeyLike` at the call sites the row named
(`ensureViewingKeyEntries`, `#authored`, `decodeSlot`, the encrypt/decrypt
helpers, `viewingKeyCounters`). Three bindings stay concrete on purpose:
`DecodeContext.viewingKey` and `decodeContextForSlot`
(`codecs.ts:1153,1171`) mirror Rust's `DecodeCx { viewing_key: &'a ViewingKey }`
(`sdk-libs/transaction/src/serialization/mod.rs:21-22,31`), and
`WalletSyncMaterial.viewingKeys` (`authority.ts:69`) mirrors
`viewing_keys: Vec<ViewingKey>`. Widening those would make TypeScript the more
permissive side.

The type gate exists: `transaction/test/types/viewing-key-like.types.ts`
asserts the seven codec signatures accept a `ViewingKeyLike` and pins the three
deliberate concrete bindings with `@ts-expect-error` controls;
`config/typecheck.mjs:19,48-49` compiles `test/types/tsconfig.json` for any
package that has one. `ViewingKeyLike` itself is synchronous
(`keypair/src/shielded.ts:148-181`), matching Rust's `ViewingKeyTrait`, and
`keypair/test/vectors/trait-surface.test.ts:105-109` scrapes both sources for
the absence of `async fn` / `Promise<`.

The parked-handoff story in the checklist row
([rulings-handoff.md](rulings-handoff.md)) is therefore also stale: the work
landed, and the three remaining concrete bindings are the ones Rust also
declares concrete.

## K12 `sdk-libs/keypair/src/traits/shielded_keypair.rs` -> PARITY

The checklist residue is that Rust's trait still hands out the nullifier secret
via `nullifier_key()` while TypeScript offers only `nullifierPublicKey()`.

**False and stale.** `ShieldedKeypairTrait` declares `nullifier_pubkey()` at
`sdk-libs/keypair/src/traits/shielded_keypair.rs:50` and no `nullifier_key()`;
the change landed at `9123db9d`. `trait-surface.test.ts:121-126` asserts both
halves, so a re-added secret accessor fails the TypeScript suite.
`ShieldedKeypairLike.nullifierPublicKey()` (`shielded.ts:135`) is the matching
capability.

The remaining asymmetry, Rust's `try_sign` (`shielded_keypair.rs:38`) with no
TypeScript twin, needs none: TypeScript has one throwing `sign`, which is the
catchable form Rust added `try_sign` to provide. The scrape records it as the
one Rust-only name (`trait-surface.test.ts:77,91`) rather than hiding it.

The interface is executed rather than only declared:
`keypair/test/api-surface.test.ts` runs an async `RemoteBackend` through it, and
`transaction/test/capability-call-sites.test.ts` runs the four keypair-rail
builders against a proxy that throws if the builder reaches for `viewingKey()`
or `nullifierKey()`, with a control that the guard fires.

## K13 `sdk-libs/keypair/src/traits/mod.rs` -> PARITY

The checklist residues are the absent trait-specific fixture and the claim that
the three higher-package call sites still bind the concrete class (via K11).

**Both false at this HEAD.** A trait declares no values, so there is nothing for
a Rust oracle to emit; `keypair/test/vectors/trait-surface.test.ts` scrapes the
two Rust trait blocks and asserts set equality against the TypeScript
interfaces through exhaustive `Record` maps, which is stronger than a generated
fixture would have been. The K11 call-site half is closed above.

`keypair/src/traits/index.ts` is type-only, as `traits/mod.rs` is: both
re-export the two trait/interface names and no runtime item.
`api-surface.test.ts` asserts the subpath ships no value, `./traits` is in the
package export map, and the packed-package / `globalThis.process` blocker the
row once carried is gone (`npm run check:packaging` was already green when
recorded at `ecfda044`; nothing at this HEAD reopens it).

## K14 `sdk-libs/keypair/src/lib.rs` -> PARITY

The checklist residue is that `inventory-keypair.md` still dispositions
`sdk-libs/keypair/src/constants.rs` as `internal`.

**False and stale.** The inventory cell is `port` as of `14bb9267`, and names
the seven exported constants plus the reason the `INFO_*` labels and HPKE
prefixes stay behind (Rust keeps them `pub(crate)`). The package root re-exports
those seven by name (`keypair/src/index.ts:17-25`), which is what `port` means.
`api-surface.test.ts` pins the root and subpath allowlists to literal sorted
lists.

A neighbouring claim in [rereview-cluster.md](rereview-cluster.md) — that
`hash.rs` and `encryption.rs` still sat as `internal` in the same inconsistent
position — is half stale itself. `hash.rs` is `port` as of `af34520c`, matching
the root re-exports of `hashField`, `ownerHash`, `sha256Be`, `sha256Bytes`, and
`splitBigEndian128`. `encryption.rs` correctly stays `internal`: Rust declares
`pub(crate) mod encryption` (`sdk-libs/keypair/src/lib.rs:42`), and the
TypeScript package does not re-export the encryption primitives from the root
either. That is not a K14 gap.

The packed-package / tarball half the row once blocked on is closed under K13.

## W04 `sdk-libs/wallet/src/actions/transaction.rs` -> PARITY

The checklist carries a long chain of residues. Checked one by one against the
tree rather than against the reports:

| Clause | Status at HEAD |
| --- | --- |
| `applyP256Signature` picks the rail from input UTXO owners | **False and stale.** It reads `address.signingPublicKey.signatureType()` (`private-transaction.ts:82-89`), matching `apply_p256_signature` (`transaction.rs:761-775`). |
| `matchingInput` re-checks only hash/nullifier/asset/amount/blinding | **False and stale.** It compares tree, commitment, nullifier, `dataHash`, `zoneDataHash`, and the whole note through `sameUtxo` (`private-transaction.ts:41-75`), the same field set `validate_unsigned_inputs` compares via `Utxo`'s `PartialEq` (`transaction.rs:884-904`). |
| `createSplit` collapses zone-bound and data-carrying refusals | **False and stale.** `WALLET_SPLIT_INPUT_ZONE_MISMATCH` and `WALLET_SPLIT_INPUT_HAS_DATA` are raised separately (`actions.ts:361-363`). |
| `WALLET_MULTIPLE_INPUT_TREES` lists every tree address | **False and stale.** It reports `treeCount` (`actions.ts:195-197`, `submit.ts:147-149`). |
| `positiveAmount` rejects `amount === 0n` | **False and stale.** `u64Amount` refuses only values outside the `u64` range (`actions.ts:160-167`). |
| Signing half unproven | **False and stale.** `wallet-actions-v1.json` records the rail matrix and eleven single-field substitutions from the crate; `wallet/test/vectors/wallet-actions.test.ts` replays both through `signPrivateTransaction`. |
| Merge path named the wrong rejection / dropped details | **False and stale** (found by the re-review, not by the checklist). `createMerge` resolves the spend tree through `namedInputTree` / `sweepTree` before counting inputs (`submit.ts:91-119`), and the six rejections with details are pinned by `wallet.test.ts` ("names the merge rejection Rust names for each way the inputs are wrong"). |

**True but out of scope for this row:** the rail rule itself is not
discriminable through the public TypeScript surface. Rust will build a P256
authority spending ed25519-owned notes; `ConfidentialTransfer`'s constructor
refuses that input with `TRANSACTION_INPUT_OWNER_MISMATCH` before
`signPrivateTransaction` is reached (`transact.ts`). That refusal lives on T25,
not in `actions/transaction.rs` / `private-transaction.ts`. The wallet-actions
suite pins the earlier refusal on the mixed-rail cases and agrees with Rust on
the same-key cases where the rule is observable. Loosening the constructor to
observe the rule would be a T25 change, and TypeScript being stricter there is
already the recorded finding.

What W04 owns — rail selection from the authority address, the whole-note
re-check, the split refusals, the tree-count detail, the zero-amount tolerance,
and the merge rejection order — matches Rust and has executed evidence.

## Encrypt-half blind spot (the known item in this range)

The brief asked whether the `encryptConfidential` unwrapped-cipher defect
(leaking a raw `KeypairError` where Rust's `?` yields `TransactionError::Keypair`)
could have been missed the same way T05's decrypt-only sweep missed it.

It was not missed in a way that reopens any of these six rows.
`encryptConfidential` goes through `inTransactionCategory`
(`codecs.ts:956-967,1020-1030`), and
`serialization.test.ts` ("reports a cipher failure in Rust's category on every
rail") drives a destroyed key through `encryptConfidential` alongside the
anonymous rails and asserts `TRANSACTION_KEYPAIR`. The K11 type-assertion file
calls `encryptConfidential` only to prove the parameter type accepts a
`ViewingKeyLike`; it never claimed to cover error categories. W04 reaches
encryption through `LocalWalletAuthority.encryptConfidentialTransfer`, which
calls the same wrapped helper. No fresh leak was found on the encrypt half of
any path these rows own.

## What nobody had recorded

Two documentation residues, neither a TypeScript gap:

1. G8-1 and the fixture-provenance prose in
   `production-readiness-issues.md` / `testing-and-conformance.md` still describe
   a red `43fde8e4` baseline gate that no longer fails.
2. The re-review's aside that `hash.rs` and `encryption.rs` were left `internal`
   in the same inconsistent state is itself half stale: `hash` is `port`, and
   `encryption` is correctly `internal` because Rust keeps the module
   `pub(crate)`.
