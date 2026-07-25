# Interface and keypair stragglers

Worker for the `I`, `K`, `X`, `S`, and `M` rows still carrying an adverse
verdict, on branch `port/interface-b` from `87b434ac`. One section per row:
what was found, what changed, and which test pins it.

Scope held: every code change is under `sdk-libs/**`. Nothing in `programs/`,
`program-libs/`, `prover/`, `xtask/`, or `docs/spec.md` was touched. Two rows
needed a change I could not make inside that boundary and say so below.

One fix is recorded against Rust rather than TypeScript, per the standing
instruction that the Rust SDK is as fixable as the port. It is
[K12](#k12-shieldedkeypairtrait-handed-out-the-nullifier-secret), and the
consequence it has for the frozen-source gate is
[Open question 2](#open-question-2-the-frozen-source-gate-against-rust-side-fixes).

## Contents

- [Open question 1: the merge encrypted-UTXO prefix (I08, I09, I20, I21)](#open-question-1-the-merge-encrypted-utxo-prefix-i08-i09-i20-i21)
- [Open question 2: the frozen-source gate against Rust-side fixes](#open-question-2-the-frozen-source-gate-against-rust-side-fixes)
- [I07, I19, I26: the deposit-tag residue](#i07-i19-i26-the-deposit-tag-residue)
- [I37: the interface root](#i37-the-interface-root)
- [K11: least-powerful capability at the call sites](#k11-least-powerful-capability-at-the-call-sites)
- [K12: ShieldedKeypairTrait handed out the nullifier secret](#k12-shieldedkeypairtrait-handed-out-the-nullifier-secret)
- [K13: the traits subpath](#k13-the-traits-subpath)
- [K14: the keypair root](#k14-the-keypair-root)
- [M02: the merkle-tree crate root](#m02-the-merkle-tree-crate-root)
- [Correction to the checklist's known-failing block](#correction-to-the-checklists-known-failing-block)

## Open question 1: the merge encrypted-UTXO prefix (I08, I09, I20, I21)

**The ruling is genuinely absent.** `authority-rulings.md` has no section for
this conflict; its open items are G7-1, T23, and C04, and none covers the merge
prefix. I did not guess it. What follows is the work common to both outcomes,
plus the decision that remains.

### What is in dispute

`MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` (`2`) is not part of the serialized layout.
`MergeTransactIxData` and `MergeZoneIxData` read and write any first byte, and
the shielded-pool program is what refuses a non-canonical one, with
`InvalidMergeOutputScheme` (7014). The TypeScript codec refuses it at both ends.

The row text treats this as one divergence. It is two, and they are worth ruling
on separately, because the arguments differ:

- **Decode.** Hard to defend. A payload with a non-canonical prefix reaches the
  chain inside a failed transaction, and a TypeScript indexer or debugger cannot
  read it while the Rust one can. Nothing is protected by refusing to read bytes
  that already exist.
- **Encode.** Defensible on its merits. Refusing to *build* a payload the program
  will reject with 7014 turns a wasted transaction into a local error with a
  precise name. This is the shape of strictness the C08 ruling approved: early
  refusal of something that cannot succeed later.

Recommendation, if it helps: **relax decode, keep encode.** That restores
TypeScript's ability to read anything Rust reads, which is the reported harm, and
keeps the guard where it prevents a loss. It is not the symmetric answer, which
is why it needs a ruling rather than a reviewer.

### What changed

No behaviour on either side. The guard is now one named function,
`checkMergeOutputScheme`, that both merge codecs call, reading constants instead
of the bare `2`, `8`, and `110` literals the codec previously duplicated in four
places. The package already exported `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX`,
`MERGE_ENCRYPTED_UTXO_LENGTH`, and `MERGE_INPUT_COUNT` and pinned them against
Rust, while the code enforcing them read none of them. They now live in a leaf
module, `interface/src/constants.ts`, because the package root imports the codecs
and a value import the other way would close a cycle. The three published export
lists are unchanged.

The point is that whichever way the ruling goes, applying it is one edit in one
function rather than a hunt through four literals.

### What pins it

In `interface/test/vectors/rust-oracle.test.ts`:

- `pins the merge encrypted-UTXO prefix asymmetry against Rust`, the decode half,
  which already existed.
- `pins the merge prefix guard on the encode side against Rust's own bytes`, new.
  I20 and I21 are *encode*-side rows and had no test; their divergence was
  recorded in prose, so deleting the encode guard would have landed green. The
  new pin also asserts that Rust's recorded non-canonical bytes differ from the
  canonical encoding at the prefix offset and at no other position, which is what
  makes the prefix rather than some other field the reason TypeScript refuses to
  build them.

Both were checked red before green: neutering the guard fails both.

No twin of the guard exists elsewhere. `mergeZoneInstructionDataCodec` shares
`readMergeData` and `writeMergeData`, and a search of the ten packages' `src`
trees for the literal prefix and length checks found no second copy.

Commit `ee6aa10b`.

## Open question 2: the frozen-source gate against Rust-side fixes

**This needs a decision and it affects more workers than me.**

`npm run fixtures:check` runs `assert_frozen_sources`, which fails if any file
under twelve canonical paths differs from `BASELINE_SHA`
(`e51ad12bda102d1c7649411a985b0b4c3f6707c2`). Those paths include
`sdk-libs/keypair/src`, `sdk-libs/transaction/src`, and
`sdk-libs/client/src/prover`.

The gate was **green** at my branch point, `87b434ac`. My K12 commit is now the
only drift against the baseline, so the gate is red and I am the cause.

The change is behaviour-neutral for the captured values: it renames one trait
method and changes no computation. `cargo test -p zolana-keypair -p
zolana-transaction` passes, including `parity_vectors`, which reads the committed
fixtures back. Re-pinning `BASELINE_SHA` would regenerate identical content.

I did not re-pin it, because `BASELINE_SHA` lives in
`xtask/src/bin/ts-fixtures.rs`, outside the boundary I was given.

The structural problem is larger than my row. The C08 ruling directs a worker to
fix `sdk-libs/client/src/prover/proof.rs`, also a frozen path, so that row's
correct fix will redden the same gate. Any row closed by fixing Rust does.
Options:

1. **Re-pin `BASELINE_SHA` after each landed Rust SDK fix.** Correct but serial,
   and the gate is red on the integration branch between fixes.
2. **Re-pin once at the end of the parity phase.** Accepts a red gate for the
   duration, which is what the checklist's known-failing block was already doing
   for a different reason.
3. **Narrow the frozen path set to the files whose bytes feed a fixture.**
   Removes the false-positive class rather than the instance. A trait declaration
   feeds no fixture.

Recommendation: **option 3**, with option 2 in the interim. The gate exists to
catch Rust drifting away from captured fixtures, and it currently fires on source
edits that cannot change a captured value.

Whichever is chosen, the checklist's known-failing block needs correcting; see
the last section.

## I07, I19, I26: the deposit-tag residue

All three rows carried the same single residue: nobody had confirmed the
regenerated wallet deposit fixture writes the discovery tag the owner ruled for.

**It does.** The Rust-captured `fixtures/wallet/deposit.json` records
`viewTagBytes = 0e91c723...`, which is `confidentialViewTag()` for the recipient
its own `recipientSigningSecretBytes` and `recipientViewingSeedBytes` derive. The
viewing pubkey `x` for that recipient is `3f07c6ea...`, so the two are
distinguishable and the fixture is on the ruled-on side. Rust
(`wallet/src/actions/deposit.rs:53`) and TypeScript (`wallet/src/deposit.ts:89`)
both derive it through the same call; no code needed changing.

The confirmation existed only transitively before. One test compared
`createDeposit` against the fixture, another compared `createDeposit` against
`confidentialViewTag()` for a different, randomly generated recipient. Both could
stay green through a change that broke the claim.

Pinned by `wallet/test/vectors/deposit-vector.test.ts` in
`derives the recipient owner hash and view tag through createDeposit`, which now
asserts the identity against the fixture's own recipient. Checked falsifiable:
pointing it at the viewing pubkey `x` fails.

The interface half of these rows carries the tag as 32 bytes it never
interprets, so nothing in `interface/` bears on it. Commit `34f2bbcb`.

## I37: the interface root

The row's own residue is the frozen-fixture gate, G8-1, dispositioned to the
fixture-gate worker. That is now
[Open question 2](#open-question-2-the-frozen-source-gate-against-rust-side-fixes),
and it is different from what the row describes: the gate had been fixed by a
re-pin to `e51ad12b`, and the row's text still names `43fde8e4`.

Everything else this root inherits is closed or pinned. Its children I07, I19,
and I26 are resolved above; the export surface and root constants are pinned by
`interface/test/exports.test.ts` and the Rust oracle, and both are unchanged by
my edits. I checked that deliberately, because moving the merge constants into a
leaf module would otherwise have been a silent change to a published surface.

No fix of mine. The row turns on the gate decision.

## K11: least-powerful capability at the call sites

**Not closed, and I recommend this branch does not close it.**

The row's own half is done: `ViewingKeyLike` declares all 14 operations and is
proved satisfiable by an async backend. The residue is that
`transaction/src/wallet/sync.ts`, `transaction/src/serialization/codecs.ts`, and
`wallet/src/sync.ts` still bind the concrete `ViewingKey`.

I left it deliberately, for a reason beyond ownership. `ViewingKeyLike` returns
`T | Promise<T>` on each method, which is what lets an HSM implement it.
Accepting it at those call sites therefore makes each one `async`, and both are
synchronous today. That is a propagating signature change across two packages
owned by other rows and, at the moment, by other running workers. Doing it here
would collide.

It is real work rather than a phantom: no consumer can pass a backend even though
one typechecks. It belongs with the transaction and wallet rows, sequenced after
them rather than beside them.

## K12: ShieldedKeypairTrait handed out the nullifier secret

**Closed by fixing Rust.** The row left the direction to the owner:
`ShieldedKeypairTrait::nullifier_key()` cloned the nullifier secret out of a
backend, while TypeScript's `ShieldedKeypairLike` offered `nullifierPublicKey()`
alone.

The trait's only generic consumer settles it. `validate_merge_inputs`
(`sdk-libs/transaction/src/instructions/merge.rs:116`) called
`keypair.nullifier_key().pubkey()?`, taking the public key and discarding the
secret. The trait was requiring every backend to surrender a secret so one caller
could compute a public value. Narrowing it to
`nullifier_pubkey() -> Result<[u8; 32], KeypairError>` loses no capability, and it
is what the custody ruling asks of a backend surface.

This is not the port bending to Rust or Rust bending to the port. The weaker
surface is the correct one and TypeScript already had it.

Callers holding a concrete type are untouched: `ShieldedKeypair.nullifier_key`
remains a public field, so only the generic bound moved. Verified with
`cargo check --workspace --all-targets`, which is green, so nothing outside
`sdk-libs` needed an edit, including `xtask`, which I checked specifically.

Pinned by `keypair/test/vectors/trait-surface.test.ts`. Checked red before green.

Commit `9123db9d`. Note its cost in
[Open question 2](#open-question-2-the-frozen-source-gate-against-rust-side-fixes).

## K13: the traits subpath

Both residues are gone.

**The missing trait fixture now exists**, in the only form it can. A trait
declares no values, so there is nothing for a Rust oracle to emit and no fixture
file to generate. `keypair/test/vectors/trait-surface.test.ts` instead scrapes
the two trait declarations out of the Rust source and compares them against an
explicit Rust-name to TypeScript-name map, the same technique the interface
package uses for its re-export ledgers. The map is exhaustive over the TypeScript
interfaces by construction, `Record<keyof ShieldedKeypairLike, string>`, so a
method added to or removed from either side fails to typecheck before it can fail
an assertion.

The map is explicit rather than a snake-to-camel rule because the port renames
deliberately: `get_sender_view_tag` to `senderViewTag`, `pubkey` to `publicKey`.
A mechanical rule would hide a rename behind a passing test.

One asymmetry is recorded in the test rather than papered over. Rust's `try_sign`
has no TypeScript counterpart, because TypeScript has one throwing `sign` and no
panic-against-`Result` split for a caller to choose between.

**The packed-package gate passes.** `node sdk-libs/ts/config/pack-check.mjs
keypair` is green at this commit. The `packed browser bundle contains
globalThis.process` failure does not reproduce for `keypair`, `merkle-tree`, or
`interface`. It was, as the row guessed, a gate or dependency defect rather than a
port defect, and it has resolved.

## K14: the keypair root

The gate half is unblocked. The row said the tarball and consumer allowlists
could not be closed while the packed-package gate failed, and it no longer fails.
`pack-check.mjs keypair` checks what the row asks for, being the tarball file
allowlist, the absence of `.tsbuildinfo`, and a node, type, and browser consumer
smoke test against the packed artifact, and it passes.

One residue stands, and it is documentation owned by the inventory rather than
behaviour. `inventory-keypair.md` is stale in two specific ways, which I checked
rather than repeated:

- It dispositions `constants.rs` as `internal` when seven of its constants are
  exported and pinned.
- It names three fixture files that do not exist: `fixtures/keypair/mod.json`,
  `shielded_keypair.json`, and `view_key.json`. The other ten it names do exist.
  It also names `src/traits/shielded-keypair.ts` and `src/traits/view-key.ts`;
  both interfaces live in `src/shielded.ts` and are re-exported by
  `src/traits/index.ts`.

## M02: the merkle-tree crate root

The behavioural half was settled by the replayed Rust traces. The surface half
rested on a relayed report nobody had rerun, and now does not.

`merkle-tree/test/exports.test.ts` pins the eight root exports as a literal
sorted list and asserts the single entry point against `package.json`, so a new
subpath has to be a decision rather than a side effect of adding a file. Checked
falsifiable by dropping a name from the expected list.

The three surface gates pass at this commit: `browser-check.mjs merkle-tree`,
`pack-check.mjs merkle-tree`, and the workspace `exports`, `inventory`,
`dependencies`, and `api` checks.

I did not map the TypeScript error codes onto the Rust enum variants. They are
not one to one, being 11 `MerkleTreeErrorCode` values against 8
`ReferenceMerkleTreeError` variants, and inventing a mapping would assert a
correspondence I could not evidence. That is an open question for whoever owns
the error taxonomy, and it is smaller than it looks, because the row's
behavioural half compares outcomes rather than error names.

Commit `c96ff2e4`.

## Correction to the checklist's known-failing block

The block says default-mode `fixtures:check` fails on baseline drift from
`43fde8e4` across 13 `sdk-libs/transaction` paths, joined by
`sdk-libs/keypair/src/signing_key.rs`.

That is stale in a way that matters. `BASELINE_SHA` has since been re-pinned to
`e51ad12b`, and at `87b434ac` the gate was **green**. Treating it as
known-failing means the next worker to redden it will not notice, which is what
happened to me until I checked.
