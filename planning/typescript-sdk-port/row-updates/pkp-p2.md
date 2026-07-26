# P2. Prover request parity

Suite P2 of [proof-and-key-parity.md](../proof-and-key-parity.md): for each
public-input case from the P1 matrix that TypeScript can serialize, the JSON
body the production client would send is captured from Rust’s serializers and
rebuilt independently in TypeScript. The suite compares `circuitType`, key
names and encounter order, omission versus null, field encoding, array order,
dummy witnesses, P256 limbs and signatures, Merkle and non-inclusion paths, and
merge ciphertext, public-contribution, and zone fields. Unknown keys and
malformed hex leaves must fail with a stable error category. The prover
protocol revision is recorded as the SHA-256 of
`sdk-libs/client/src/prover/json.rs`.

## Bottom line

**P2 certifies for the seven request shapes TypeScript can assemble.** Exact
request bodies match Rust production serializers for confidential (all shapes,
both rails, mixed owners), zone, zone-p256, zone-authority, merge, and
merge-zone. No Rust-versus-TypeScript serializer divergence turned up on those
paths.

**Address-append has no TypeScript path.** The eighth circuit type is present
in the fixture with `typescriptPaths["address-append"] = false` and a Rust
snapshot for key-set documentation only. That gap is prominent, not silent.

The evidence rating is **strong for request wire-format parity, not for live
proving**. This suite never asks a prover for a proof and never runs the
verifier. It would catch a TypeScript serializer that renamed a field, omitted
a key Rust still emits as null or `0x0`, reordered top-level keys, or accepted
unknown or non-hex leaves. It does not certify that a proof for that request
verifies.

## P1 gaps closed in this branch

Zone named intermediates now live in `xtask/src/bin/public-input-assembly`
(same seeds as the former `ts_zone_oracle` cargo-test path) and are covered by
`fixtures-check.mjs`. Zone mixed-owner was added as a P1 case and is reused
here for the zone request body. Those closures landed in commit `f2f74877`
before the request-parity work.

## What already covered P2 clauses

Several vector suites already exercised request bodies and were folded in by
reference rather than rewritten.

`prover-inputs.test.ts` against `prover-shapes-v1.json` already compared
confidential `proverJson` values for every supported shape on both rails. That
fixture BTreeMap-canonicalizes object key order, so it proves value and
encoding parity, not serde encounter order. P2 reuses those values and asserts
encounter order against the new Rust raw-serializer snapshot.

`zone-oracle.test.ts` and `merge-oracle.test.ts` already compared full request
bodies for every zone and zone-authority shape and both merge rails, including
the explicit `zoneProgramId: "0x0"` on default merge. P2 folds those suites and
adds the zone mixed-owner body against the new fixture.

`prover-request.test.ts` already had a single dummy Ed25519 request snapshot.
`prover-poll-oracle.test.ts` covers poll transport, not request shape, and was
left alone.

## What this suite added

`xtask/src/bin/prover-request` (with `--check`, registered in
`fixtures-check.mjs`) drives the production `ProverClient` against a local HTTP
mock so each `requestBodyJson` is the exact UTF-8 body the serializer emits,
not a hand-authored object. The fixture
`sdk-libs/ts/fixtures/client/prover-request-parity-v1.json` stores those raw
strings, the eight circuit types, per-circuit known key lists in encounter
order, the protocol revision, mixed-owner confidential and zone bodies, and one
representative per circuit including address-append.

`checkedProverRequest` in the TypeScript client rejects unknown keys, missing
keys, explicit nulls, and non-`0x`-hex string leaves with
`CLIENT_INVALID_FIELD`. It does not enforce the BN254 modulus on wire hex:
P256 coordinates and signatures are secp256r1 integers and routinely exceed
that modulus. Field-range checks belong in assembly, not request validation.

`sdk-libs/ts/client/test/vectors/prover-request-parity.test.ts` rebuilds every
TypeScript-reachable case through the public assemblers and `proverRequest` /
`mergeProverRequest`, compares bodies to the folded fixtures or the new
snapshots, asserts key order against the Rust-emitted known keys, and covers
the rejection clauses. Mixed confidential and zone mixed reuse the P1 case
matrix; the confidential mixed path must rebuild the second input’s Merkle
paths to the Rust mixed-owner indices, because public-input hashes ignore path
bytes while the request body does not.

## Control edits

Four production edits were made, each watched failing, then reverted.

Removing the unknown-key guard made the rejection test fail with
`expected CLIENT_INVALID_FIELD` on an injected `unexpectedField`. Without that
control the rejection clause would also pass against a validator that accepts
everything.

Removing the malformed-hex guard failed the same rejection test when
`publicInputHash` was set to `not-hex`.

Removing the explicit-null guard failed when a known key was set to `null`.
Serde never emits null for these structs; omission versus null is part of the
wire contract.

Moving `privateTxHash` after the public-amount tail on the Ed25519 path failed
the folded confidential key-order assertion while value equality against the
canonicalized prover-shapes fixture would still have passed. Encounter order
is therefore checked against the P2 knownKeys snapshot, not against
alphabetically sorted `proverJson`.

## Gaps

Address-append remains without a TypeScript serializer. The fixture records
its Rust body and marks the path absent. Closing that requires a forester
client surface, which this port does not ship.

`ts-fixtures --check` currently fails on this branch with “generated file set
differs from checked-in P00 outputs” even with the P2 files stashed. That is
pre-existing relative to this suite; `prover-request --check` and
`public-input-assembly --check` both pass.

P2 does not certify proof response parsing (P3), live prove-and-verify (P4),
or end-to-end flows (P5).

## Verdict

P2 is complete for the seven TypeScript-reachable request shapes: circuit
type, keys, encoding, paths, P256 limbs, merge and zone fields, rejection of
unknown and malformed leaves, and a recorded protocol revision all agree with
Rust production serializers. Address-append is documented as uncovered. The
honest rating is strong request-parity evidence, not a proof-certification
verdict.
