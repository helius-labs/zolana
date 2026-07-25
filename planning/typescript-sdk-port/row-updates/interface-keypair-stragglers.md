# Interface and keypair stragglers

Worker for the `I`, `K`, `X`, `S`, and `M` rows still carrying an adverse
verdict, on branch `port/interface-b` from `87b434ac`. One section per row:
what was found, what changed, and which test pins it.

Scope held: every code change is under `sdk-libs/**`. Nothing in `programs/`,
`program-libs/`, `prover/`, `xtask/`, or `docs/spec.md` was touched. Four things
needed a change I could not make inside that boundary: the `BASELINE_SHA` re-pin
in [Open question 2](#open-question-2-the-frozen-source-gate-against-rust-side-fixes),
the fallible builder signature and the 1232-byte guard in
[S01](#s01-the-smart-account-client-index-boundary), and the spec-against-Photon
conflict that is the whole of [X01](#x01-the-indexer-api-scalars).

Two fixes are recorded against Rust rather than TypeScript, per the standing
instruction that the Rust SDK is as fixable as the port:
[K12](#k12-shieldedkeypairtrait-handed-out-the-nullifier-secret), whose
consequence for the frozen-source gate is
[Open question 2](#open-question-2-the-frozen-source-gate-against-rust-side-fixes),
and the Rust half of [S01](#s01-the-smart-account-client-index-boundary), where
the truncation was the more serious of the two defects.

## Contents

- [Open question 1: the merge encrypted-UTXO prefix (I08, I09, I20, I21)](#open-question-1-the-merge-encrypted-utxo-prefix-i08-i09-i20-i21)
- [Open question 2: the frozen-source gate against Rust-side fixes](#open-question-2-the-frozen-source-gate-against-rust-side-fixes)
- [Note: this branch moved worktrees mid-session](#note-this-branch-moved-worktrees-mid-session)
- [I07, I19, I26: the deposit-tag residue](#i07-i19-i26-the-deposit-tag-residue)
- [I37: the interface root](#i37-the-interface-root)
- [K11: least-powerful capability at the call sites](#k11-least-powerful-capability-at-the-call-sites)
- [K12: ShieldedKeypairTrait handed out the nullifier secret](#k12-shieldedkeypairtrait-handed-out-the-nullifier-secret)
- [K13: the traits subpath](#k13-the-traits-subpath)
- [K14: the keypair root](#k14-the-keypair-root)
- [M02: the merkle-tree crate root](#m02-the-merkle-tree-crate-root)
- [S01: the smart-account-client index boundary](#s01-the-smart-account-client-index-boundary)
- [X01: the indexer-api scalars](#x01-the-indexer-api-scalars)
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

### Someone else is answering this, differently

Mid-session the owner added a standing instruction (`README.md`, `515a2fb4`):
do not stop at an open question, copy Light Protocol's answer if it has one, and
otherwise take the recommended path and record it.

By then a second worker had taken this row. `port/merge-prefix` exists and its
working tree removes **both** guards, decode and encode, which is the symmetric
answer rather than the one recommended above. I have not touched it, and I am
not reopening it; whoever reconciles should know only that the two halves were
argued separately here and were closed together there. If the encode guard is
wanted back it is one call to `checkMergeOutputScheme`, which is why the refactor
below was worth doing either way.

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

Light Protocol was checked, as the standing instruction requires. It has no
answer to copy because it has no such gate: `BASELINE_SHA`, `frozen_sources`,
and `assert_frozen` return nothing across that repository. Light does export
test data from Rust, through `xtask/src/export_photon_test_data.rs`, and pins
nothing about the source files that produced it. So the mature lineage's answer
to this class of drift is not a source hash, which is evidence for option 3
rather than for scheduling around the gate.

Recorded rather than done, because the one-line fix is `BASELINE_SHA` in
`xtask/src/bin/ts-fixtures.rs` and the standing instruction is explicit that it
does not outrank the scope rule.

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

## S01: the smart-account-client index boundary

**Closed, by fixing both languages.** The row records an overflow-policy
conflict, and it is a conflict in which neither side was right.

The compiled payload names accounts by u8 index. The list therefore holds 256
entries, and the 257th is the first that cannot be named. Neither side had that
number.

Rust allocated index 256 and let `idx as u8` truncate it to 0. The result is the
bad kind of wrong: the payload deserializes cleanly and the CPI runs against the
first account in the list instead of the intended one. TypeScript refused one
slot early, at 256 entries rather than 257, because the guard compared the list
length before the push against the maximum index. So the port rejected a payload
Rust compiles correctly, which is the stricter-than-Rust regression this project
has already reverted once.

The boundary is unreachable in practice, since 256 accounts is 8192 bytes of
keys against a 1232-byte transaction. That makes it the same shape as the T21
ruling, which chose the loud refusal over the quiet truncation at a boundary no
caller reaches, so I followed T21 rather than re-deciding it.

Rust refuses through `checked_u8` on every narrowing in the builder, not just
the index. It panics rather than returning an error, which deserves the
objection it invites. `execute_sync_ix` returns `Instruction` and already panics
on a failed serialize, so the panic matches the contract the function already
has; making it fallible is the better fix and moves `xtask`, `forester`, and
four `sdk-tests` crates with it, which is outside this branch. Recorded here
rather than half-done.

Pinned by `compiles_the_full_u8_index_range` and
`refuses_an_account_index_past_u8` in the Rust crate, which had no tests at all
before, and by the reworked 256-and-257 case in `boundaries.test.ts`. All three
were checked red first. The Rust pair needed both narrowings reverted to fail,
which is worth knowing: reverting only one leaves the other catching the
overflow a step later.

The row's other two residues are in different states. The export surface is now
pinned by `smart-account-client/test/exports.test.ts`, which maps every `pub
const` and `pub fn` to its ported name so a Rust addition fails here until the
port answers it; the declaration ledger it joins catches a removal but not an
addition.

The execute case needs a distinction I first glossed over. `vectors.test.ts` does
compare the execute payload, indexes, and account flags against Rust bytes, so
the behaviour is covered. But it is covered by hex written inline in the test,
not by a generated fixture: the only file under
`fixtures/smart-account-client/` is `standard-create-v1.json`, and the
`lib.json` the inventory promises does not exist. If the row means fixture
evidence in the sense the other packages have it, generated by
`xtask/src/bin/ts-fixtures.rs` from a real `execute_sync_ix` call, then it is
**not** closed and cannot be, since the generator is outside the boundary. The
create entry there is the template to copy.

The 1232-byte limit is **not closed and cannot be closed here**. TypeScript
enforces it, Rust does not, and neither direction fits inside the boundary:
relaxing TypeScript would have it hand back an instruction that can never land,
and adding the guard to Rust needs a fallible signature and the same caller
migration described above. Unlike the index boundary, this one is reachable by
an ordinary caller, so a panic is not an acceptable stand-in.

Commits `1d84539b` and `09012b2f`.

## X01: the indexer-api scalars

**Partly closed.** The row's headline, that `docs/spec.md` defines different
context, UTXO, transaction, and output schemas from the ones Rust and Photon
implement, is out of reach from here in every direction: the spec is
uneditable by instruction, Photon is outside `sdk-libs/**`, and changing Rust
alone would align the port with neither. It needs the owner to say which of the
three is authoritative before any code moves.

Two residues were real, and both were the port dropping a capability rather than
disagreeing about a value.

Rust's `Base64String` holds `Vec<u8>` and encodes only at the serde boundary, so
`From<Base64String> for Vec<u8>` is a field read. The port brands the wire string
instead, which is reasonable for a JSON client, but it shipped no way back to the
bytes. A caller had to reach for `atob` or `Buffer`, neither of which enforces
the canonical form this package requires on the way in. `base64Bytes` is the
inverse of the existing `base64String` and shares its decoder, so both
directions agree on what canonical means.

`ParseHashError` names two failures, `WrongSize` and `Invalid`, and the port
reported both as `INDEXER_SCHEMA_INVALID_HASH`, so a caller could not tell a
truncated hash from a corrupted one. Rust reaches `WrongSize` two ways, an
over-long string and a decode that is not 32 bytes, and both map to the one code
here. The accept and reject sets do not move, so this is a naming fix and not a
tightening.

Pinned by `indexer-api/test/scalar-parity.test.ts`, which reads the enum and the
struct out of `lib.rs` so a change on the Rust side fails here. Checked red
first. Two existing assertions expected the collapsed code for inputs that are
wrong-size, and now say so.

Still open on this row, beyond the spec conflict: the promised Rust fixture,
`fixtures/indexer-api/lib.json`, which does not exist and needs a generator in
`xtask`, and the live-Photon evidence, which needs a running indexer. Neither is
reachable from `sdk-libs/**`. The fixture that does exist,
`indexer-api/schema-v1.json`, holds path bounds and a block time rather than wire
payloads, and no test reads it; the wire vectors are inline.

Two details worth carrying forward. `get_nullifier_queue_elements` appears in
Rust, in the port, and in Photon, and **nowhere in `docs/spec.md`**, so it is an
undocumented extension rather than a divergence from the spec. And the port's
rename of `ShieldedTransaction` to `IndexedShieldedTransaction` is deliberate,
disambiguating it from `@zolana/transaction`, so it should not be read as drift.

### `base64Bytes` is a name for an existing helper, not a new one

Worth stating plainly, because the duplicated-helper trap is the one this port
keeps falling into. `@zolana/client` already carries this decoder at
`client/src/internal.ts:265`, and it is identical to the indexer-api one
character for character: same regex, same padding arithmetic, same re-encode
check for canonical form. Only the error differs, `CLIENT_INVALID_BASE64` against
`INDEXER_SCHEMA_INVALID_BASE64`. `@zolana/wallet` and `@zolana/interface` each
carry their own base58 pair as well.

`client/src/indexer.ts` shows the cost: it imports `hashBytes` from
`@zolana/indexer-api` for hashes, then uses its own local `decodeBase64` for the
payloads on the same responses, at six call sites. So one response is validated
by two decoders that happen to agree.

The end state is for those six call sites to import `base64Bytes` and for the
local copy to go, which collapses the pair rather than adding to it. I did not do
it: `client` is owned by another row and by a worker running now on
`port/client-b`, and this is a cross-package edit that would collide. Recorded
for whoever holds that row, and it is now a one-line import rather than a
reimplementation.

Commit `ee650188`.

## Note: this branch moved worktrees mid-session

`port/interface-b` was started in `zolana-ts-programlibs` as instructed. Partway
through, that tree was checked out onto `port/merge-prefix` at `515a2fb4` by
another worker, with the merge-guard edit described above uncommitted in it.

No work was lost and nothing of theirs was disturbed. All seven commits made to
that point were already on `port/interface-b`; I copied my uncommitted
indexer-api work out, returned their two files to the exact bytes I found them
at, and moved to a new worktree, `zolana-ts-interface-b`, for the rest.

Worth flagging for two reasons beyond the near miss. The one-tree-one-branch rule
held only because the commits were frequent, which is the argument for committing
incrementally rather than at the end. And a gate run immediately after the switch
reported two unrelated interface failures and a missing `@zolana/hasher`, which
looked like the stale-cache phantom the brief warns about and was not: the tree
was simply on a newer branch that has a package my branch predates. Anyone who
sees that pair of symptoms should check `git branch --show-current` before
clearing caches.

## Correction to the checklist's known-failing block

The block says default-mode `fixtures:check` fails on baseline drift from
`43fde8e4` across 13 `sdk-libs/transaction` paths, joined by
`sdk-libs/keypair/src/signing_key.rs`.

That is stale in a way that matters. `BASELINE_SHA` has since been re-pinned to
`e51ad12b`, and at `87b434ac` the gate was **green**. Treating it as
known-failing means the next worker to redden it will not notice, which is what
happened to me until I checked.
