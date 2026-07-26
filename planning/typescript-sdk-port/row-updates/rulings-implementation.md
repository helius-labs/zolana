# Implementing the owner's rulings

Six items, taken in the order the dispatch gave them. Branch `port/rulings-impl`,
worktree `zolana-ts-rulings-impl`. Every row transition below is proposed here
rather than written into [`review-checklist.md`](../review-checklist.md), which
has a single writer.

Item 2 landed in part, losing its TypeScript half to a collision, and hands off
below with the call sites named, which is the deliverable for what it does not
do. Item 3 is withdrawn: T28 belongs to `port/t28-close`, and section 3 records
what the two versions did and did not share rather than any work of mine.

## 1. C18, the zone-authority rail carries four shapes, not ten

**Commit** `71f7f319`.

`docs/spec.md`, "Zone-authority instantiation", lists four supported shapes, and
`program-libs/interface/src/verifying_keys/` holds exactly four matching keys,
`transfer_zone_authority_{1_1,2_2,3_3,4_4}`. Both SDKs resolved against
`SPP_SUPPORTED_SHAPES`, which carries ten, so a caller could assemble a 2x3
zone-authority request and learn at proving time that nothing can verify it.

Rust `ZoneAuthorityProver::build` and TypeScript `assembleZoneAuthority` now
refuse the six non-square shapes with a named error,
`ClientError::UnsupportedZoneAuthorityShape` and
`CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE`, whose message states the set the rail
supports. `SPP_SUPPORTED_SHAPES` in `program-libs` is untouched: it is the
transfer rail's set and the ruling does not reach it. No key was generated, and
no program or circuit changed.

**Evidence.** The Rust oracle in `sdk-libs/client/src/prover/ts_zone_oracle.rs`
emits the four accepted shapes and generates the six rejections by calling
`ZoneAuthorityProver::build` itself, so `zone-oracle.test.ts` compares against
executed Rust rather than a transcription of it. The error variant reaches the
TypeScript error test through the regenerated `client/errors-v1.json` fixture, 59
variants where there were 58. Control edit: removing the shape check from
`zone.ts` fails the six rejection cases.

**Row transition.** C18: adverse to closed.

## 2. K11, `ViewingKeyLike` returns values rather than promises

**Commit** `335a026c`, and the wording follow-up the reconciler took at
`dd497dce`.

An out-of-process viewing-key backend is not a supported deployment, so
`T | Promise<T>` bought a capability nobody can use and cost the interface its
callers: a scan loop cannot await per view tag, so every call site bound the
concrete `ViewingKey` instead. Rust's `ViewingKeyTrait` is synchronous and always
was. `ShieldedKeypairLike` keeps its promise unions, because a remote signer is
supported.

The test backend in `keypair/test/api-surface.test.ts` now models that split:
signing over the wire, viewing answered directly.

**Evidence.** `keypair/test/vectors/trait-surface.test.ts` scrapes both sources
rather than restating them. The Rust trait must declare no `async fn`, the
TypeScript interface no `Promise<`, and `ShieldedKeypairLike` must still show
one, which is what proves the scrape can see a promise when there is one to see.
Control edit: widening `senderViewTag` back to `ViewTag | Promise<ViewTag>` fails
it. A runtime case in `api-surface.test.ts` additionally asserts that three
implementers, the concrete key, a full keypair, and the wire-backed test
backend, return no promise from the viewing operations.

Note for whoever adds a type-level assertion here: `npm run typecheck` compiles
`src/**` only, so a `@ts-expect-error` or an assignability trick in a test file
is checked by nothing. That is why the evidence above is a source scrape.

**Row transition.** K11: adverse to closed for `@zolana/keypair`. The three call
sites the row also named stay open; see the handoff below.

### Handoff: the `transaction` call sites this run did not take

`sdk-libs/ts/transaction/**` is held by the export-surface agent on
`port/tx-surface`, and a collision detector reported both of us holding
`serialization/codecs.ts`. I reverted mine rather than commit it, because that
agent's changes carry fifteen rows and whichever of us merged second would have
dropped the other's silently. Line numbers below are read at `origin/ts-sdk-port`
after that agent's merge, so they are current.

`sdk-libs/ts/transaction/src/serialization/codecs.ts`. Five functions take
`ViewingKey` and call nothing outside the interface, so the parameter type is the
whole change:

- `encryptConfidential` (805) and `encryptAnonymous` (818), which call
  `encryptSlot`.
- `decryptAnonymous` (828) and `decryptConfidential` (878), which call
  `decryptUtxo`.
- `decryptConfidentialAsSender` (891), which calls `decryptSlotEphemeral`.

Two more need a body change first, because they reach for `secretBytes`, which
the interface excludes on purpose:

- `encryptMerge` (969) exports the secret and hands it to the free
  `encryptVerifiable` from `@zolana/keypair/merge`. The interface carries
  `encryptVerifiable` as a method, and Rust's `Merge::encrypt` calls
  `cx.tx.encrypt_verifiable`, so `txViewingKey.encryptVerifiable(...)` is both the
  narrowing and the closer match. It also drops the manual zeroization, which the
  method makes unnecessary.
- `decryptMerge` (982), the same shape against `decryptVerifiable`. One behaviour
  moves: a destroyed key currently escapes as a raw `KeypairError`, and inside
  `inTransactionCategory` it becomes `TRANSACTION_KEYPAIR`, which is what Rust's
  `?` conversion does.

With those seven done, the import on line 2 drops `ViewingKey` and line 3 drops
`@zolana/keypair/merge` entirely.

`DecodeContext.viewingKey` (1005) and `decodeContextForSlot` (1023) may stay
concrete: Rust's `DecodeCx` binds `&'a ViewingKey`, so narrowing them would make
TypeScript the more permissive of the two.

`sdk-libs/ts/transaction/src/wallet/sync.ts`. Type annotations only, at 425
(`confidentialSendRecipients`), 463 (`ensureViewingKeyEntries`), 478
(`advanceViewingKeyEntry`), 562 (the `counterparties` closure), and the import at
line 2. `decodeCandidate` (168) now takes a `DecodeContext` and follows whatever
that type does; it also calls `decryptMerge`, so it cannot narrow before that one
does.

`WalletSyncMaterial.viewingKeys` must stay `readonly ViewingKey[]`. Rust's
`WalletSyncMaterial.viewing_keys` is `Vec<ViewingKey>`, and widening it would be a
divergence rather than a narrowing.

`sdk-libs/ts/wallet/src/sync.ts` was uncontested and is done in `335a026c`:
`viewingKeyCounters` takes `ViewingKeyLike`.

## 3. T28, withdrawn in favour of `port/t28-close`

**Commit** `994574a0`, dropped. T28 was dispatched to another worker, whose
version is the one to keep: it carries the TypeScript half in
`sdk-libs/ts/transaction/src/utxo.ts`, which is the point of the port, and it
pins the address clause the owner held back.

`994574a0` was rebased out of this branch, but it had already reached
`ts-sdk-port` through the reconciler's merge at `ec0ec8ea`, before the dispatch
arrived. History alone therefore does not remove the code, so the merge here is
followed by a revert that does. Two normalizers cannot share three call sites,
and this yields them, leaving `port/t28-close` a clean apply.

**What mine covered that theirs does not.** Nothing in behaviour. Both change
the same three builders -- `SppProofInputUtxo::with_zone_data_hash`,
`SppProofOutputUtxo::with_zone_data`, `SppProofOutputUtxo::with_zone_data_hash`
-- through one helper in `utxo.rs`, and both leave the zone address alone. The
74-against-40 line count is an artefact of packaging: mine carried its tests in
one commit, theirs split them into `725c8b84`, which adds 58 more.

Two test cases are mine alone, and one of them is worth restating if anyone
extends that suite:

- **A non-zero hash is still kept**, asserted directly on both sides. Theirs
  leaves that to `preserves_input_and_output_zone_data_hashes` in
  `instructions/transact/merge_zone.rs`, which does catch a helper that returns
  `None` unconditionally, so the case is covered, just not locally.
- **Equality of the whole prepared struct**, where theirs asserts the commitment
  and the two fields it names. Mine also compared nullifiers, which the
  commitment equality already implies.

Theirs holds something mine does not, and it is the more valuable of the two: a
zero zone **address** still commits to `pk_field(0)` and still moves the hash,
asserted on both sides, so the half the owner declined cannot be normalized by a
later reader who sees only the data-hash rule. Their helper is `pub(crate)`
where mine was `pub`, which is also the better call.

**One observation outlives the commit**, because neither version addresses it.
The canonical-dummy rule still rejects a zero-owner input whose `zone_data_hash`
field was assigned directly rather than through the builder, at
`instructions/types.rs:79`. That is defensible -- the fields are public, the
builder is the caller-facing path, and the rule exists to catch a dummy built
wrong -- but the same `unwrap_or_default` gap exists for `data_hash`, which no
ruling covers and no builder normalizes.

**Row transition.** T28: no change from this branch. `port/t28-close` carries
the row.

## 4. The frozen-source gate is gone

**Commits** `aa78d855`, and `2682b91a` for the fixture re-stamp it unblocked.

`assert_frozen_sources` refused to run the generator, and so failed
`npm run fixtures:check`, whenever any file under twelve paths differed from a
pinned revision. Those paths include `sdk-libs/transaction/src`,
`sdk-libs/keypair/src` and `program-libs/interface/src`, so every row this port
closed by fixing Rust turned the gate red whether or not a fixture could have
moved. It had been red on unrelated drift for several batches, tracked as G8-1,
which is the state a tripwire is worth least in. The three revision constants
stay, because the manifest stamps them as provenance.

`xtask` is in scope under `run-authorizations.md`.

**What still catches fixture drift.** `--check` regenerates all 58 fixtures from
the working tree and compares them byte for byte with the committed ones, which
is what the check spent most of its runtime doing all along. Control edit: adding
one to the UTXO domain constant in `sdk-libs/transaction/src/utxo.rs`, inside a
formerly frozen path, fails it on `api/prover-request-v1.json`.

**What the removal takes with it.** The tripwire on Rust changes no fixture
observes. The generator records error codes and detail shapes rather than
messages, for instance, so rewording a `ClientError` display string passes both
before and after the removal, which I checked. Before, the gate would still have
stopped the run and made someone look at the diff. Anything
TypeScript ports by hand from a Rust source no fixture exercises now changes
silently. Closing that gap properly means a fixture for the behaviour, not a
revision pin over the file it lives in.

The `--reports-only` escape hatch stays. It existed to work around the gate, but
it is still the fast path to regenerate the inventory reports without the full
run behind them.

**Row transition.** G8-1: proposed closed, in
[`production-readiness-issues.md`](../production-readiness-issues.md), which I
have not edited.

## 5. The Browserslist is declared, and nothing gates it

**Commit** `9ad5401c`.

`npm run test:browser` bundles every browser package with esbuild at
`target: "es2022"` and refuses a Node global or a `node:` import in the graph, so
the packages hold a browser property that was nowhere stated. The declaration is
that target read back as browser versions:

```json
"browserslist": [
  "chrome >= 94",
  "edge >= 94",
  "firefox >= 93",
  "safari >= 16.4",
  "ios >= 16.4"
]
```

Class static blocks and the RegExp `d` flag are the last ES2022 features to land,
in Chrome 94, Firefox 93 and Safari 16.4, so those are the floors the bundle
target implies. The five queries resolve against current caniuse data.

No gate was added, per the ruling. The cost is that the declaration can drift
from the esbuild target without anything noticing; a one-line assertion beside
the `engines.node` check in `workspace-check.mjs` would hold them together if the
owner ever wants it.

**Left to another owner.** Four browser packages are held this run and are
missing the same five lines: `hasher`, `transaction`, `indexer-api` and `api`.
The other six carry it: `interface`, `keypair`, `client`, `wallet`,
`merkle-tree`, `smart-account-client`. `test-kit` is not a browser package and
should not.

One incidental fix rode along: the `@zolana/keypair` doc comment lost the phrase
"in process", which the browser gate reads as `process.` and refuses. The
reconciler had already reached the same line at `dd497dce` with "in memory".

## 6. M02 closes without an error mapping

No code. Eleven `MerkleTreeErrorCode` values face eight
`ReferenceMerkleTreeError` variants, and a mapping asserted without evidence is
worth less than the absence of one. The row's behavioural half compares outcomes
rather than error names and is already satisfied by the Rust traces replayed in
`merkle-tree/test/vectors/merkle-semantics.test.ts`, and the surface half was
settled at `ecfda044`. Light is not a model here: `js/stateless.js/src/errors.ts`
defines nine unused enums under a cleanup TODO and throws bare `Error` everywhere
that matters.

**Row transition.** M02: done, with the error-mapping residual withdrawn rather
than owed. Open question 24 closes with it.

## Gates run

`npm run build` before every suite, which is now the standing rule. The run
below is on the merged state, `ts-sdk-port` at `ec0ec8ea` folded in, with the
T28 revert applied.

- `npm run build`, `npm run typecheck`, `npm run lint`, `npm run format:check`
- `npm run check:packaging` (inventory, exports, dependencies, api, browser, pack)
- `npm run test:unit`, 1942 passed and 1 skipped
- `npm run fixtures:check`, 58 fixtures and 182 inventory rows verified, with the
  frozen-source gate gone and the tip's Rust sources moved under it
- `cargo test -p zolana-transaction`, 61 passed across the crate's suites

## Not touched

`docs/spec.md`. The `Integer encoding` paragraph still states the capped option
the owner declined while TypeScript implements the per-field union, but Rust does
not accept the string form yet, and the amendment rule wants Rust to have moved
first. Recorded, not corrected.
