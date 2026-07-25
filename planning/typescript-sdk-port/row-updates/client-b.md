# Client batch B: prover subtree

Rows whose ID begins with `C`, worked on branch `port/client-b`. One section per
row, each naming the verdict, the evidence by file and test, and the commit.

Every verdict of `PARITY` below rests on a Rust-generated oracle replayed by a
TypeScript test, and on control edits that were applied and shown to fail. Where
a control edit is not recorded, the row is not `PARITY`.

## Evidence built in this pass

Two generators, both inside `sdk-libs/client` rather than under
`xtask/src/bin/`. The brief asked for `xtask`, and that is not reachable: the
serializers these rows exist to pin (`to_json_merge`, `to_json_merge_zone`,
`to_json_zone`, `to_json_p256_zone`, `to_json_zone_authority`) are all
`pub(crate)` in `sdk-libs/client/src/prover/json.rs`. An `xtask` binary can only
call them if that visibility widens, which would enlarge the Rust public API to
serve a test. The generators are `#[cfg(test)]` modules in the crate instead, and
write the same committed-fixture, replayed-by-TypeScript artefact.

| Generator | Fixture | Replay |
| --- | --- | --- |
| `sdk-libs/client/src/prover/ts_merge_oracle.rs` | `sdk-libs/ts/client/test/oracles/merge-v1.json` | `sdk-libs/ts/client/test/vectors/merge-oracle.test.ts` |
| `sdk-libs/client/src/prover/ts_zone_oracle.rs` | `sdk-libs/ts/client/test/oracles/zone-v1.json` | `sdk-libs/ts/client/test/vectors/zone-oracle.test.ts` |

Regenerate either with `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client
--lib ts_merge_oracle` (or `ts_zone_oracle`).

## C09, prover request bodies: PARITY

`sdk-libs/client/src/prover/json.rs` against `client/src/prover/client.ts` and
`merge.ts`. The row was open on two counts and both are closed.

The merge body was checked against a hand-written key list that existed
separately in each language, so a renamed field or a reordered chain would have
been answered by the prover with a proof of a different statement. It is now
compared as exact request bytes against `to_json_merge` and `to_json_merge_zone`
output, for both rails.

The four missing circuit types were the second count. Three are built (C13, C14,
C18 below); the fourth is `address-append` and stays out.

Evidence: `merge-oracle.test.ts`, "sends the request body Rust serializes", both
rails; and `zone-oracle.test.ts`, "sends the NxM request body Rust serializes",
thirty cases. Control edits that fail the merge replay: swapping two elements of
the shared public-input prefix, zeroing the zone binding in the zone rail's tail,
swapping the two owner-identity elements of the default rail's tail.

One change to make the bytes match rather than merely the object: the TypeScript
P256 request key order now follows the Rust struct. It previously appended the
seven P256 fields after `publicInputHash`, where Rust interleaves them. The Go
server does not care, but two serializers that disagree on order are two
serializers one of which was edited alone.

Commits: `2f2654f1`, `6de00db6`.

## C17, merge public-input values: PARITY

`MergeProver::common` against `assembleMergeRailUnchecked`. The fixture pins the
public input hash, output hash, private tx hash, external data hash, the eight
nullifiers, both root-index vectors, the ciphertext, and the tx viewing key, so a
failure names the field that moved rather than only the final hash.

Independent corroboration that the Rust reconstruction of the TypeScript scenario
is faithful: the generator reproduces `outputHashBytes` from the frozen
`sdk-libs/ts/fixtures/transaction/merge-v1.json` exactly, without being given it.

Evidence: `merge-oracle.test.ts`, "assembles the values Rust assembled".
Commit: `2f2654f1`.

## C13, zone transfer on the ed25519 rail: PARITY

`sdk-libs/client/src/prover/transact/zone_eddsa.rs` ported to
`sdk-libs/ts/client/src/prover/zone.ts` as `assembleZone`.

The owner's reading was right: this is the confidential ed25519 rail with the
confidential appendix dropped and the zone field in place of the zero. Thirteen
elements, closing on the input-owner chain, because owners are named on this rail
so SPP can route the per-input signer check. A P256-owned input is rejected as
`CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED`, matching Rust's
`OwnerMode::ConfidentialEddsa`.

Evidence: `zone-oracle.test.ts`, all ten supported shapes, values and request
bytes. Commit: `6de00db6`.

## C14, zone transfer on the P256 rail: PARITY

`transact/zone_p256.rs` ported as `assembleZoneP256`, returning the Rust
`ZoneTransferP256ProofResult` surface including `p256SigningPublicKeyField` and
`p256SigningPublicKeyX`.

The trap here is that the shared signing field is in the witness and not in the
hash, while a P256-owned input contributes the zero sentinel rather than its own
field. Both are pinned: a test asserts every input owner field is zero and that
the signing field matches Rust's while the public input hash is unchanged by its
presence.

Evidence: `zone-oracle.test.ts`, all ten shapes, plus "keeps P256 owner identities
out of the zone chain". Commit: `6de00db6`.

## C18, the zone-authority transition: PARITY

`sdk-libs/client/src/prover/zone_authority.rs` ported as `assembleZoneAuthority`.
Twelve elements, no input-owner chain at all: the zone's `zone_config` PDA
authorizes on-chain, so no owner signs and no owner is named. Owner fields stay
private witnesses bound only through their nullifier secrets.

Evidence: `zone-oracle.test.ts`, all ten shapes, plus "gives the zone authority a
shorter chain than the zone transfer", which builds both rails over identical
inputs and asserts the private tx hashes match while the public input hashes do
not. Commit: `6de00db6`.

### Control edits for the three zone rows

Applied and observed to fail, then reverted:

| Edit | Result |
| --- | --- |
| Give the zone authority the owner chain the zone transfer has | 21 of 66 fail |
| Fold the P256 signing field into the zone hash | 21 of 66 fail |
| Let P256 owners contribute their identity instead of the sentinel | 21 of 66 fail |
| Replace the zone binding with the confidential zero | 62 of 66 fail |

### Two places TypeScript was deliberately not made stricter than Rust

Both are hazards for PKP-05 rather than defects to fix here, and fixing either on
one side only would have been the over-strict failure the brief warns about.

The Rust zone provers take `zone_program_id: Option<Address>` and do not reject
`None`, which `program_id_field` turns into a literal zero, leaving the proof
bound to nothing. The TypeScript signature takes a required `Address`, so the case is
unrepresentable without rejecting an input Rust accepts. Recorded rather than
guarded.

`ZoneAuthorityProver::build` resolves against all ten `SPP_SUPPORTED_SHAPES`, but
`program-libs/interface/src/verifying_keys/` holds only four zone-authority keys:
`transfer_zone_authority_{1_1,2_2,3_3,4_4}`. Rust will therefore build a 2x3
zone-authority request the prover server cannot serve. The oracle emits all ten
shapes so the parity claim covers what Rust does; narrowing the accepted set
belongs in one change to both languages, not a TypeScript-only guard.

Neither needs a change outside the SDK.

## C06, field alignment: no change, and the reason

`prover::field` is pinned by `field-alignment-v1.json` and
`vectors/field-alignment.test.ts`, generated from Rust, covering each length and
both sides of the BN254 modulus. The Poseidon partial-round table in
`internal.ts` is bounded at twelve entries with a range check, so the arity
concern the row raised does not reach an out-of-bounds read. No divergence found;
the row's remaining content is inventory bookkeeping owned by the reconciler.

## `create_two_inputs_hash_chain`, ported: PARITY

The queue recorded seven callers on the Rust proof path and no TypeScript port.
It has none: every reference in the workspace is the function's own test in
`program-libs/hasher/tests/hash_chain.rs` or the `xtask` parity oracle. A
divergence could not have produced a bad proof, so this was never the functional
gap it was recorded as.

What was real is that `xtask/src/bin/program-libs-parity.rs` already commits
vectors for it into `sdk-libs/ts/vectors/program-libs-parity-v1.json` and nothing
on the TypeScript side read them. Rather than argue the disposition, the function
is ported to `internal.ts::twoInputsHashChain` and the committed vectors are
replayed, including the length-mismatch rejection and the empty case.

The single-pair case seeds on a two-input Poseidon rather than folding a zero
into a three-input one; a control edit making that substitution fails three of
the six vectors.

Evidence: `sdk-libs/ts/client/test/vectors/two-inputs-hash-chain.test.ts`.
Commit: `889262d5`.

## C22, crate-root exports: residual closed

The re-review left one divergence: `MERGE_INPUTS` was `pub` in Rust and exported
from `@zolana/transaction`, while the client's merge assembly restated it as a
module-private literal, which made the recorded disposition false at the one
place the constant decides a rejection. `prover/merge.ts` now imports it.
Commit: `778747a1`.

## C19, the prover client: residual verified closed

The re-review left the status poll carrying no per-request bound, so a status
endpoint that accepted the connection and never answered would hang past
`maxWaitMs`. It is fixed at HEAD: `#poll` composes
`{ signal, timeoutMs: REQUEST_TIMEOUT_MS }` around the status fetch as the prove
request does. No change needed.

The row's other residual, "6 of the 8 prove entry points are absent", is now 1 of
8: the three zone rails route through `prover.prove()`, which accepts
`ZoneProverInputs` and selects the commitment expectation per rail.

## Prover shape inventory, definitive

Rust `prover::json` writes eight circuit types. TypeScript reaches seven.

| Circuit type | TypeScript | Entry point |
| --- | --- | --- |
| `transfer-confidential` | yes | `assemble` |
| `transfer-p256-confidential` | yes | `assemble` |
| `merge` | yes | `proveMerge` |
| `merge-zone` | yes | `proveMergeZone` |
| `transfer-zone` | yes, new | `assembleZone` |
| `transfer-p256-zone` | yes, new | `assembleZoneP256` |
| `transfer-zone-authority` | yes, new | `assembleZoneAuthority` |
| `address-append` | no | none, by disposition |

`address-append` is the forester's nullifier-tree rail. TypeScript ships no
forester, so nothing in the language would call the builder or read its output,
and an SDK exporting it would export an instruction whose proof it cannot
generate. C07 keeps `NOT_APPLICABLE` under the owner's ruling.

This inventory is enforced, not asserted.
`sdk-libs/ts/client/test/prover/circuit-types.test.ts` scans every shipped source
file: it fails if any names `address-append`, and fails if the reachable set is
anything other than the seven above. `test/prover/exports.test.ts` freezes the
`@zolana/client/prover` runtime surface, which now carries the three assemblers.

## Blocked on nothing outside the SDK

None of the three zone rails needed a program, circuit, or prover-server change.
Both remaining hazards, the `None` zone binding and the four-key zone-authority
shape set, are recorded above for PKP-05 and are changes to Rust and TypeScript
together rather than to anything outside `sdk-libs`.

## Branch hazard encountered

At 22:16 the worktree `/Users/tilohelius/Workspace/zolana-ts-wallet-misc` was
switched from `port/client-b` to `port/wallet-misc` by a concurrently running
wallet-batch agent, which then committed twice on that branch. The two branches
have diverged, with `port/client-b` carrying 63 commits `port/wallet-misc` does
not, so work done in the interval was built and tested against the wrong base.

Recovered without loss: `port/wallet-misc` was reset to the wallet agent's tip
`24ce8a6c` and is byte-identical to how they left it, and the merge oracle was
re-applied to `port/client-b`, regenerated, and re-verified there before being
committed. The oracle was byte-identical on both bases and the four gates pass on
`port/client-b`.

Worth an owner decision: this worktree is named for the wallet batch and another
agent treats it as theirs. Two agents sharing one worktree cannot both hold a
branch.
