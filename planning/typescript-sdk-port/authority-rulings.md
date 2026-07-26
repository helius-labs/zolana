# Authority rulings ledger

Per-conflict record for the TypeScript SDK port. One section per disputed
behavior: what `docs/spec.md` says, what each implementation does, whether they
disagree, the options with their consequences, and the artifacts a change would
touch. This is the artifact register `G7-2` reports as missing. It is not a
statement of the authority order.

The `Ruling` block in each section is left blank for the protocol owner. Fill
the ruling and the date; leave the evidence untouched so a later reader can see
what the ruling was made against.

Line numbers are as of branch `ts-sdk-port` on 2026-07-25. Claims that could
not be settled from the repository are labelled unverified with the missing
piece named.

## Contents

- [Open: owner-hash encoding (G7-1)](#open-owner-hash-encoding-g7-1)
- [Ruled: confidential owner tag (T23)](#ruled-confidential-owner-tag-t23)
- [Ruled: ECDSA malleability policy (G2-1)](#ruled-ecdsa-malleability-policy-g2-1)
- [Ruled: Ed25519 acceptance (G2-2)](#ruled-ed25519-acceptance-g2-2)
- [Open: the u64 integer domain (C04)](#open-the-u64-integer-domain-c04)
- [Closed rulings](#closed-rulings)

## Ruled: owner-hash encoding (G7-1)

### What the spec says

`docs/spec.md:265-278` defines one `pk_field(pk)`:

- P256: `x_hash := Poseidon(x_low_128, x_high_128)`, then
  `pk_field(pk) := Poseidon(y_is_odd, x_hash)`.
- Ed25519: `pk_field(pk) := Poseidon(pk_low_128, pk_high_128)`.

Line 267 calls this "the canonical form used wherever a pubkey appears inside a
Poseidon hash anywhere in this spec". Line 278 argues that the P256 `y_is_odd`
layer keeps the two encodings apart, so no scheme tag is needed. Line 283 gives
`owner_hash := Poseidon(pk_field(signing_pk), nullifier_pk)`, and line 286 says
the proof recomputes `pk_field(signing_pk)` from a witnessed P256 point.

### What each implementation does

Two encodings exist in the codebase and are used for different key roles.

Owner identity, parity-free `Poseidon(x_low_128, x_high_128)`:

| Surface | Symbol | Location |
| --- | --- | --- |
| Go circuit gadget | `OwnerPkFieldGadget.DefineGadget` | `prover/server/circuits/spp_transaction/p256.go:88-90` |
| Go circuit entry | `OwnerPkFieldFromPubkeyCircuit` | `prover/server/circuits/spp_transaction/p256.go:94-118` |
| Go host helper | `OwnerPkField` | `prover/server/prover-test/spp/protocol/owner.go:63-69` |
| Solana program | `verifier::hash_field` | `programs/shielded-pool/src/instructions/verifier.rs:27-37` |
| Solana program, Ed25519 rail | `solana_pk_hash` | `programs/shielded-pool/src/instructions/hash.rs:24-29` |
| Interface crate | `merge_utils::owner_pk_field_compressed` | `program-libs/interface/src/merge_utils.rs:37-52` |
| Rust keypair | `PublicKey::owner_pk_field` | `sdk-libs/keypair/src/pubkey.rs:170-172` |
| TypeScript interface | `ownerPkFieldCompressed` | `sdk-libs/ts/interface/src/merge-utils.ts:92-94` |
| TypeScript keypair | `ShieldedPublicKey.ownerPublicKeyField` | `sdk-libs/ts/keypair/src/public-key.ts:118-127` |

Viewing keys, parity-inclusive `Poseidon(y_is_odd, x_hash)`:

| Surface | Symbol | Location |
| --- | --- | --- |
| Go circuit gadget | `P256PkFieldGadget.DefineGadget` | `prover/server/circuits/spp_transaction/p256.go:33-36` |
| Go merge circuit call site | user viewing key | `prover/server/circuits/spp_merge/circuit.go:185` |
| Go host helper | `P256PkField` | `prover/server/prover-test/spp/protocol/owner.go:73-86` |
| Interface crate | `merge_utils::pk_field_compressed` | `program-libs/interface/src/merge_utils.rs:15-30` |
| Solana program, merge | `merge::verify::pk_field` over `record.viewing_pubkey` | `programs/shielded-pool/src/instructions/merge/verify.rs:133-135`, called at `merge/processor.rs:50` |
| Rust keypair | `PublicKey::hash` | `sdk-libs/keypair/src/pubkey.rs:153-162` |
| TypeScript keypair | `ShieldedPublicKey.hash` | `sdk-libs/ts/keypair/src/public-key.ts:107-116` |

Which encoding enters `owner_hash` in the transfer circuit: `Circuit.Define`
sets `env.p256PkField` from `OwnerPkFieldFromPubkeyCircuit`
(`prover/server/circuits/spp_transaction/circuit.go:156-164`). `constrainInput`
feeds that value as `OwnerKeyHash` into `OwnerHashGadget`
(`prover/server/circuits/spp_transaction/inputs.go:89-104`), and
`OwnerHashGadget` is `Poseidon(OwnerKeyHash, NullifierPk)`
(`prover/server/circuits/spp_transaction/utxo.go:40-47`). The recomputed
`ownerHash` is then constrained equal to the input UTXO's `owner` field
(`inputs.go:104`). So the transfer circuit's `owner_hash` uses the parity-free
form.

The Solana program uses the parity-free form for owner identity in the two
places it derives one. `transact` computes
`p256_signing_pk_field = hash_field(p256_signing_pk_x)`
(`programs/shielded-pool/src/instructions/transact/processor.rs:97-99`) and the
confidential output tags as `hash_field(output.owner_tag)`
(`transact/processor.rs:298`). `merge_transact` reads the registry record and
derives the owner field with `owner_pk_field_compressed` for a P256 owner and
`solana_pk_hash` for an Ed25519 owner
(`programs/shielded-pool/src/instructions/merge/account.rs:65-74`). The
parity-inclusive form appears once, over the registered viewing key
(`merge/processor.rs:50`).

The keypair fixture records the split the reviewer noted:
`sdk-libs/ts/fixtures/keypair/hash.json:3-6` has
`ed25519OwnerFieldBytes == ed25519PublicHashBytes` and
`p256OwnerFieldBytes != p256PublicHashBytes`. That follows from
`sdk-libs/keypair/src/pubkey.rs:153-172`: the Ed25519 branch of `hash()` and of
`owner_pk_field()` both reduce to `hash_field` over the same 32 bytes, while the
P256 branch of `hash()` adds the parity layer and `owner_pk_field()` does not.

### Whether they conflict

They conflict. The spec defines a single `pk_field` and puts it inside
`owner_hash`; the deployed circuit, the program, both Rust SDK crates, and both
TypeScript packages put the parity-free form there and reserve the
parity-inclusive form for viewing keys. The four implementations agree with each
other and disagree with the spec text.

### The collision argument at line 278

The argument at `docs/spec.md:278` rests on the P256 encoding carrying an extra
`y_is_odd` layer that the Ed25519 encoding lacks. For the owner-identity form
that layer is absent, so the two rails compute the identical function over a
32-byte value: `Poseidon(low_128, high_128)` over a P256 x-coordinate
(`p256.go:88-90`) or over an Ed25519 public key (`hash.rs:24-29`). Nothing in
the encoding distinguishes the rails, so a P256 x-coordinate equal byte for byte
to an Ed25519 public key produces the same owner field. The line 278 argument
does not carry over to the form the code uses.

Reachability of a spend built on such a coincidence, from the constraints:

- The recomputed `owner_hash` also covers `nullifier_pk`, which the proof
  derives from the private `NullifierSecret`
  (`circuit.go:188-193`, `inputs.go:100-112`), and `nullifier_secret` is derived
  from the signing secret (`sdk-libs/keypair/src/nullifier_key.rs:24-26`,
  `docs/spec.md:310`).
- A P256-routed input additionally requires the one ECDSA signature over
  `private_tx_hash` to verify (`inputs.go:105`, `circuit.go:165-170`).
- An Ed25519-routed input additionally requires the named account to be a
  transaction signer (`transact/processor.rs:272-278`).

Producing the coincidence in the attacking direction means finding an Ed25519
keypair whose public key equals a target P256 x-coordinate, or a P256 keypair
whose x-coordinate equals a target Ed25519 public key. This analysis found no
construction for either, and no path that reaches a spend without the victim's
`nullifier_secret`. Treat that as analysis, not as a ruling: the residual
question of whether the missing separation still warrants a scheme tag is a
judgment for the protocol owner.

### Options

**Option 1: amend the spec to describe two encodings.** Define `pk_field`
(parity-inclusive, viewing keys) and an owner-identity form (parity-free), state
which one enters `owner_hash`, and restate the separation argument for the
parity-free form or replace it. Code changes: none. Artifacts touched:
`docs/spec.md` only. Unblocks the eight checklist rows without a key rotation.

**Option 2: change the implementations to the parity-inclusive form for owner
identity.** Circuit change in `p256.go` and `inputs.go`, program change in
`verifier.rs`, `hash.rs`, `transact/processor.rs`, and `merge/account.rs`,
matching changes in `merge_utils.rs`, `sdk-libs/keypair`,
`sdk-libs/ts/interface`, and `sdk-libs/ts/keypair`. This is a hard fork of the
owner commitment: an existing UTXO whose `owner` was computed under the
parity-free form becomes unspendable, because the recomputed `owner_hash` no
longer matches the tree leaf.

### Artifacts a change would break

Option 1 breaks nothing.

Option 2 changes the transfer constraint system and the merge registry
derivation, so it regenerates the committed verifying keys and rotates the
proving keys:

- 44 transfer modules under `program-libs/interface/src/verifying_keys/`
  (`transfer_confidential_*`, `transfer_p256_confidential_*`, `transfer_zone_*`,
  `transfer_p256_zone_*`, `transfer_zone_authority_*`).
- `merge_8_1.rs` and `merge_zone_8_1.rs` in the same directory.
- `prover/server/prover/provingkeys/proving-keys.lock` plus the S3 or CloudFront
  key folder, via `prover/server/scripts/rotate_proving_keys.sh`.
- `sdk-libs/ts/fixtures/keypair/hash.json` and the Rust-captured
  `sdk-libs/ts/fixtures/client/prover-shapes-v1.json`.
- Any UTXO already in a tree, as described above.

### Ruling

| Field | Value |
| --- | --- |
| Ruling | Option 1. Amend `docs/spec.md` to match the implementations. The parity-free `Poseidon(x_low_128, x_high_128)` is canonical for `owner_hash`; the parity-inclusive form stays canonical for viewing keys. The divergence was deliberate, not drift. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `docs/spec.md` lines 265 to 286, and the collision argument at line 278 |

The owner's words were that it "seems like it was on purpose", which the evidence
supports: `merge_utils.rs:32-37` carries a comment giving the reason, that a P256
owner should have the same `pk_field` shape as an Ed25519 owner, and nine
surfaces across the circuit, the program, both SDKs and the interface crate agree
with each other. A specification that eleven implementations contradict is the
artifact that is wrong.

This ruling authorises editing `docs/spec.md`, which the port's standing
constraint otherwise forbids. The authorisation covers this conflict only.

Line 278 needs more than a correction. It argues that P256 and Ed25519 encodings
cannot collide *because* the P256 form carries the extra `y_is_odd` layer. That
argument does not hold for the parity-free form actually deployed, so the
amendment has to restate collision resistance on the encoding in use rather than
delete the claim and leave nothing in its place.

## Ruled: indexer-api schema authority (X01)

| Field | Value |
| --- | --- |
| Conflict | `docs/spec.md` defines context, UTXO, transaction and output schemas that neither Rust nor Photon implements, and `get_nullifier_queue_elements` appears in Rust, the port and Photon but nowhere in the spec. |
| Ruling | Where Rust, the port and Photon already agree, that agreement is authoritative and the specification is the stale artifact. The port is correct as it stands. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `docs/spec.md` indexer schemas; no SDK code moves |

The owner's test was direct: if a surface exists in Rust, in the port and in
Photon, the port is correct. That resolves the row without touching code, because
the disagreement was never three ways on those surfaces. It was the
specification against a consensus of implementations, which is the same shape as
G7-1 and gets the same answer.

Two consequences worth stating. `get_nullifier_queue_elements` is an undocumented
extension rather than a divergence, so it needs a specification entry rather than
removal. And the port's rename of `ShieldedTransaction` to
`IndexedShieldedTransaction` is deliberate disambiguation from
`@zolana/transaction`, not drift, so no one should later read it as one.

What this ruling does not settle: the promised Rust fixture
`fixtures/indexer-api/lib.json` still does not exist and needs an `xtask`
generator, and live-Photon evidence still needs a running indexer. Both sit
outside `sdk-libs/**`.

## Ruled: least-powerful capability at the call sites (K11)

| Field | Value |
| --- | --- |
| Conflict | Recorded as an open question. It is not one. |
| Ruling | Answered already. The design half is settled and what remains is sequenced work, not a decision. |
| Ruled by | Coordinator, correcting a mis-classification, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `transaction/src/wallet/sync.ts`, `transaction/src/serialization/codecs.ts`, `wallet/src/sync.ts` |

`ViewingKeyLike` declares its fourteen operations and is proven satisfiable by an
async backend. The related trait question, K12, is closed: Rust's
`nullifier_key()` was handing out the nullifier secret so that its one generic
consumer could compute a public value, and narrowing it to `nullifier_pubkey()`
lost no capability.

What is left is three call sites still binding the concrete `ViewingKey`. Because
`ViewingKeyLike` returns `T | Promise<T>` so an HSM can implement it, accepting it
there makes those functions `async`, and that signature change propagates across
two packages. It was deferred to avoid colliding with the workers editing them,
not because anyone is unsure what to do. It belongs after the transaction and
wallet rows, and it is real: no consumer can pass a backend today, even though one
typechecks.

## Ruled: confidential owner tag (T23)

The line numbers below cite `docs/spec.md` as it read before the ruling landed.
The amendment moved them; read the section through its anchors rather than its
line numbers.

### What the spec says

`docs/spec.md:884` describes `solana_owner_pk_hashes` as the `pk_field` of the
input's Solana or Ed25519 owner, and `0` for a P256-owned input.
`docs/spec.md:885` describes `p256_signing_pk` as `hash_field(p256_signing_pk_x)`
and says the circuit routes P256-owned inputs by equality against it. The
zero-sentinel rule is repeated twice more, in the ownership check row at
`docs/spec.md:944` and in step 2 of the ownership check text at
`docs/spec.md:959`. None of those four places names a circuit variant, although
the spec does define the confidential and anonymous axis at `docs/spec.md:966`.
So the two rules read as contradictory.

### What the circuit does

The routing sits in `constrainInput`
(`prover/server/circuits/spp_transaction/inputs.go:89-99`):

```go
var isP256, ownerKeyHash frontend.Variable
if env.confidential {
    isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
    ownerKeyHash = in.OwnerPkHash
} else {
    isP256 = api.IsZero(in.OwnerPkHash)
    ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
}
```

The confidential branch constrains a P256-owned input to carry
`p256SigningPkField` in `OwnerPkHash` and uses that value directly as the owner
key hash. The anonymous branch constrains it to carry `0` and substitutes the
recomputed P256 key. `env.confidential` comes from the compile-time flag set by
the constructors at `circuit.go:80-99`: `NewTransferP256ConfidentialCircuit`
and `NewTransferConfidentialCircuit` pass `true`; the three zone constructors
pass `false`.

So the reviewer did not conflate the branches. They genuinely differ, and the
difference is per circuit variant.

The two forms select the same inputs and reach the same `ownerKeyHash`, because
the confidential variant pins `P256SigningPkField` to the recomputed key:
`api.AssertIsEqual(c.P256SigningPkField, env.p256PkField)` at `circuit.go:183-185`.
On the Solana-only confidential rail `env.p256PkField` is the constant `0`
(`circuit.go:177`), so the equality test reduces to the zero test there.

### What the program and the clients do

`check_input_signers` writes the per-input owner field and splits on the same
axis (`programs/shielded-pool/src/instructions/transact/processor.rs:259-285`):
for `eddsa_signer_index == P256_OWNED_SIGNER` it writes `[0u8; 32]` when
`IS_ZONE` and `p256_signing_pk_field` otherwise. That field is
`hash_field(p256_signing_pk_x)` (`transact/processor.rs:97-99`).

The Rust client encodes the same split as `OwnerMode`
(`sdk-libs/client/src/prover/transact/p256_and_eddsa.rs:228-246`), selecting
`ConfidentialP256(signing_pk_field)` for the confidential path
(`p256_and_eddsa.rs:99-102`, applied at `p256_and_eddsa.rs:299-308`) and the `0`
sentinel for `Merge` and `Zone`.

The TypeScript client implements the confidential equality form only:
`assembly.ts:103-106` computes `p256SigningField` from the signer's
`ownerPublicKeyField()`, and `assembly.ts:149-152` assigns it to a P256-owned
input's owner field.

### Whether they conflict

The four implementations agree. The spec's own two statements conflict with each
other, and its zero-sentinel statement conflicts with the confidential circuit.

### Public input layout

Changing the confidential branch would not change the Groth16 public input
count. Each committed verifying key declares `nr_pubinputs: 1`
(`program-libs/interface/src/verifying_keys/transfer_p256_confidential_2_3.rs:31`,
`transfer_confidential_2_3.rs:24`,
`transfer_p256_zone_2_3.rs:31`,
`transfer_zone_authority_2_2.rs:24`), because the single public input is the
folded `PublicInputHash` (`circuit.go:47`, `circuit.go:232-261`). The
`vk_ic` length follows from that count plus the BSB22 commitment: three entries
for `transfer_p256_confidential_2_3.rs:6-28` with
`vk_commitment: Some(..)` at line 76, and `vk_commitment: None` for
`transfer_confidential_2_3.rs:69`.

What does change is the constraint system, and therefore the Groth16 setup
output. Both directions are breaking in the sense that the committed verifying
keys and the distributed proving keys must be regenerated together.

### Options

**Option 1: amend the spec to the variant split.** Rewrite `docs/spec.md:884`,
`docs/spec.md:944`, and `docs/spec.md:959` so the zero sentinel is stated as the
anonymous and zone-authority rule and the equality form as the confidential
rule. Code
changes: none. Verifying keys: unchanged.

**Option 2: move the confidential branch to the zero sentinel.** Changes
`inputs.go:89-99`, `transact/processor.rs:259-285`,
`p256_and_eddsa.rs:228-246`, and `assembly.ts:103-152`. The proven statement is
unchanged, per the pinning at `circuit.go:183-185`, so this buys representational
uniformity rather than a security property.

**Option 3: move the anonymous branch to the equality form.** The mirror image.
This one is not representation-neutral: the anonymous variants exist so a
P256-owned input's identity stays private, and `p256SigningPkField` is folded
into the public hash only in the confidential variant (`circuit.go:254-259`).
Exposing an owner tag on the anonymous rail would remove that property.

### Artifacts a change would break

Option 1 breaks nothing.

Option 2 regenerates the 20 confidential verifying keys:
`transfer_confidential_{1_1,1_2,1_8,2_2,2_3,3_3,4_3,4_4,5_3,5_4}.rs` and
`transfer_p256_confidential_{1_1,1_2,1_8,2_2,2_3,3_3,4_3,4_4,5_3,5_4}.rs`, plus
`prover/server/prover/provingkeys/proving-keys.lock` and the distributed key
folder.

Option 3 regenerates the 24 anonymous verifying keys:
`transfer_zone_*` (10), `transfer_p256_zone_*` (10), and
`transfer_zone_authority_*` (4), plus the same lockfile and key folder.

Either option invalidates the P256 rail of
`sdk-libs/ts/fixtures/client/prover-shapes-v1.json`, which pins
`p256SigningPkField` per shape.

### Ruling

| Field | Value |
| --- | --- |
| Ruling | Option 1. Amend the spec to the variant split: the zero sentinel is the anonymous and zone-authority rule, the equality form is the confidential rule. No code moves and no verifying key is regenerated. Landed in `25b13fa2`, under the `owner-tag-by-variant` anchor. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | None for the tag itself: no circuit, program, client, verifying key or fixture changed. The row's other half, the BN254 range check that TypeScript performs and `sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs` does not, is a separate matter and still open; [`remaining-work.md`](remaining-work.md) tracks it. |

Same principle as G7-1 and X01, and the evidence here is stronger than in either:
the four implementations agree with each other, and the specification contradicts
*itself* in two places before it contradicts the code.

Option 3 was not viable, and the reason is worth keeping. The anonymous variants
exist so a P256-owned input's identity stays private, and `p256SigningPkField` is
folded into the public hash only in the confidential variant
(`circuit.go:254-259`). Moving the anonymous rail to the equality form would
expose an owner tag and destroy that property. A future reader tempted by the
symmetry should know it was rejected on a security ground, not on cost.

## Ruled: ECDSA malleability policy (G2-1)

### What the spec says

`docs/spec.md` does not constrain the ECDSA `s` value. `docs/spec.md:244` types
`ECDSASignature` as `[u8; 64]` (`r‖s`). The `owner_signature` private input at
`docs/spec.md:897`, the `private_tx_hash_digest` public input at
`docs/spec.md:877`, and step 1 of the ownership check at `docs/spec.md:958`
describe the signature and the digest it is checked against without a range rule
for `s`. Searching the spec for a low-S or canonical-S requirement returns
nothing.

### What the circuit does

The circuit calls the gnark gadget:
`env.p256SigValid = c.P256Pub.IsValid(api, ..., p256Message, &c.P256Sig)` at
`prover/server/circuits/spp_transaction/circuit.go:165-170`, and requires it for
a P256-routed input at `inputs.go:105`.

`IsValid` (`github.com/consensys/gnark@v0.14.0/std/signature/ecdsa/ecdsa.go:36-45`)
calls `prepareVerification` (`ecdsa.go:49-79`), which computes
`Q = [r/s]PK + [m/s]G` and compares the bits of `Q.x` against `r`. The only
range checks it performs are:

```go
scalarApi.AssertIsLessOrEqual(&sig.S, scalarApi.Modulus())
scalarApi.AssertIsLessOrEqual(&sig.R, scalarApi.Modulus())
```

at `ecdsa.go:63-64`. There is no comparison against `n/2`. The gadget therefore
accepts a high-S signature. It is indifferent to the malleability question,
not permissive by accident and not restrictive.

The gnark version is pinned at `prover/server/go.mod:6`
(`github.com/consensys/gnark v0.14.0`).

### What the Rust signer produces

`SigningKey::sign` for the P256 arm calls `sign_prehash`
(`sdk-libs/keypair/src/signing_key.rs:99-112`). The wallet authority path does
the same (`sdk-libs/transaction/src/wallet/authority.rs:375-394`). Both resolve
to `ecdsa` 0.16.9 (`Cargo.lock:2240-2242`):

- `PrehashSigner::sign_prehash` calls `try_sign_prehashed_rfc6979`
  (`ecdsa-0.16.9/src/signing.rs:158-164`).
- `try_sign_prehashed_rfc6979` (`ecdsa-0.16.9/src/hazmat.rs:94-112`) derives `k`
  through RFC 6979 and calls `try_sign_prehashed`, whose default body is
  `sign_prehashed` (`hazmat.rs:74-83`).
- `sign_prehashed` computes `s = k_inv * (z + r * d)` at `hazmat.rs:253` and
  returns it with no normalization (`hazmat.rs:224-259`). `normalize_s` exists at
  `ecdsa-0.16.9/src/lib.rs:318` and is not called on this path.
- `p256` 0.13.2 (`Cargo.lock:4406-4408`) takes the default trait bodies; its
  `ecdsa.rs` supplies empty `impl SignPrimitive<NistP256> for Scalar {}` at
  `p256-0.13.2/src/ecdsa.rs:72` and `impl VerifyPrimitive<NistP256> for
  AffinePoint {}` at `ecdsa.rs:75`.

So the Rust signer does not enforce low-S, and `verify_prehashed`
(`hazmat.rs:270-292`) compares `r` against the recomputed x-coordinate with no
`s` range test, so it does not reject high-S either.

### What the TypeScript library does

`sdk-libs/ts/keypair/src/signing-key.ts:56-67` signs with `lowS: true` at line 64 and
`signing-key.ts:79-83` verifies with `lowS: true`. In `@noble/curves` 2.2.0,
`lowS: true` on the signing side flips `s` into the lower half
(`node_modules/@noble/curves/src/abstract/weierstrass.ts:1857-1858`) and on the
verifying side returns `false` for a high-S signature
(`weierstrass.ts:1920`).

`sdk-libs/ts/client/test/helpers/prover-vectors.ts:174-178` signs with
`lowS: false`.

### Whether they conflict

Yes, and the divergence is live rather than hypothetical. For a given key and
digest, RFC 6979 fixes `k`, so `r` matches across the two languages, but `s` is
`n - s` in TypeScript whenever the deterministic value lands in the upper half.
Both signatures verify under the circuit and under Rust; the TypeScript verifier
rejects the Rust one.

The committed, Rust-captured fixture already contains high-S signatures.
`sdk-libs/ts/fixtures/client/prover-shapes-v1.json` is generated by
`xtask/src/bin/ts-fixtures.rs:1917` from a loop over `SPP_SUPPORTED_SHAPES`
(`program-libs/interface/src/shape.rs:68-79`, driven at
`xtask/src/ts_fixtures_client.rs:541-556`), with
the signature taken from `SppProofInputs::sign_p256`
(`xtask/src/ts_fixtures_client.rs:506`,
`sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs:106-116`).
Reading `proverJson.p256SigS` for the ten P256 shapes against `n/2`:

| Shape | s half |
| --- | --- |
| 1x1, 1x2, 2x2, 2x3, 3x3, 5x4, 1x8 | low |
| 4x3, 4x4, 5x3 | high |

That is why the test helper pins `lowS: false`: with the library default the
regenerated signature would differ from the Rust fixture in three of ten shapes.

### Consequences of each direction

If the circuit accepts high-S, which it does, then `lowS: true` in
`signing-key.ts` rejects signatures a conforming Rust signer produces, and a
hardware signer that does not normalize would hit the same rejection. The
signing side is self-consistent (a TypeScript-produced signature verifies under
TypeScript), so the failure surfaces at cross-language verification and at
fixture comparison, not at proving.

The alternative direction, having the circuit reject high-S, is not the current
state, so the question of whether the test helper generates refused vectors does
not arise. It does not: the three high-S fixtures prove under the deployed keys,
subject to the note below.

Unverified: this analysis did not run the prover against a high-S witness. The
claim that the gadget accepts high-S rests on reading `ecdsa.go:63-64` and
finding no `n/2` comparison. Settling it empirically needs a proving run over
one of the three high-S fixture shapes.

### Options

**Option 1: relax TypeScript to `lowS: false` in `sign` and `verify`.** Matches
Rust, the circuit, and the test helper, and lets the helper drop its override.
Changes `signing-key.ts:64` and `signing-key.ts:82`. Accepts that a signature is
malleable in `s`, which matters only where a signature is compared by bytes or
used as an identifier; the protocol uses it as a proof witness.

**Option 2: enforce low-S in both languages.** Adds `normalize_s` to
`sdk-libs/keypair/src/signing_key.rs:99-112` and
`sdk-libs/transaction/src/wallet/authority.rs:375-394`, keeps
`signing-key.ts` unchanged, and regenerates the Rust-captured fixture. The
circuit stays indifferent, so this is a client convention rather than a protocol
rule unless an `s < n/2` check is added to the gadget, which would change the
constraint system and rotate keys.

**Option 3: keep the split and record it.** Document that the protocol does not
canonicalize `s`, that the library default is strict, and that a caller
verifying a foreign signature must pass `lowS: false`. No code change.

### Artifacts a change would break

Option 1 changes no committed vector; the existing fixture stays valid and the
`lowS: false` override in `prover-vectors.ts` becomes redundant.

Option 2 regenerates `sdk-libs/ts/fixtures/client/prover-shapes-v1.json` (three
of ten P256 shapes change `p256SigS`, `publicInputHashBytes` is unaffected since
the signature is not in the public hash) and any wallet or transaction fixture
holding a P256 signature, including the `p256Signature` blocks in
`xtask/src/ts_fixtures_transaction.rs:1178-1183` and
`xtask/src/ts_fixtures_wallet.rs:1371-1375`. Adding a gadget-level check on top
would regenerate the 20 P256 verifying keys and rotate the proving keys.

Option 3 breaks nothing.

### Ruling

| Field | Value |
| --- | --- |
| Ruling | Option 1. TypeScript drops the low-S constraint on both `sign` and `verify`. The deployed circuit accepts a high-S signature, so the SDK accepts and produces one too. Malleability in `s` is a property of the deployed protocol; the SDK does not remove it unilaterally. |
| Ruled by | Protocol owner |
| Date | 2026-07-25 |
| Follow-up artifacts | `sdk-libs/ts/keypair/src/signing-key.ts`, `sdk-libs/ts/client/test/helpers/prover-vectors.ts` (override dropped), `sdk-libs/ts/client/test/vectors/p256-malleability.test.ts` (new). No committed vector changed. Implemented in `65100a09`. |

The prover run against a high-S witness that this section lists as unverified is
still unverified. The three high-S shapes are exercised as signing and
verification vectors, not through the prover.

## Ruled: Ed25519 acceptance (G2-2)

### What the spec says

`docs/spec.md` names no Ed25519 verification convention. It states that the
Ed25519 signature check is performed by SPP rather than by the proof
(`docs/spec.md:304`, and step 2 of the ownership check at `docs/spec.md:959`).

### What the Solana runtime accepts

`solana-signature` resolves at two versions in this workspace, 2.3.0 and 3.4.1
(`Cargo.lock:8347-8354`, `Cargo.lock:8357-8369`). The verification code is in
3.4.1: `Signature::verify` at `solana-signature-3.4.1/src/lib.rs:157` calls
`verify_verbose` at `lib.rs:142-150`, which calls
`ed25519_dalek::VerifyingKey::verify_strict` at `lib.rs:149`. Batch verification
runs the same extra checks before entering `verify_batch`
(`lib.rs:47-68`).

`verify_strict` in `ed25519-dalek` 2.2.0 (`Cargo.lock:2287-2299`):

- parses the signature through `InternalSignature` at `verifying.rs:362`, whose
  `check_scalar` requires a canonical `s` below the group order
  (`ed25519-dalek-2.2.0/src/signature.rs:91-96`, applied at
  `signature.rs:151-163`);
- rejects a small-order `R` and a small-order public key
  (`ed25519-dalek-2.2.0/src/verifying.rs:370-372`);
- compares the recomputed `R` against the signature's `R`, which is the
  cofactorless equation (`verifying.rs:375-380`). The function spans
  `verifying.rs:357-381`.

It does not reject a non-canonical `y` encoding: `CompressedEdwardsY::decompress`
builds the field element with `FieldElement::from_bytes`
(`curve25519-dalek-4.1.3/src/edwards.rs:194-219`), which masks the sign bit and
reduces rather than rejecting `y >= p`.

`solana-ed25519-program` 2.2.3 (`Cargo.lock:7025-7027`) is the precompile and is
not on the SPP authorization path. It depends on `ed25519-dalek` 1.0.1
(`Cargo.lock:7032`), a different version from the one the runtime signature type
uses.

### What the Rust helper in this repository accepts

`sdk-libs/keypair/src/signing_key.rs:114-131` verifies through
`ed25519_dalek::Verifier`, that is `VerifyingKey::verify`, not `verify_strict`.
`verify` uses the cofactored equation and omits the small-order rejections, so
the SDK helper is looser than the Solana runtime. Signing uses
`DalekSigningKey::sign` (`signing_key.rs:110`).

### What the TypeScript helper accepts

`sdk-libs/ts/keypair/src/signing-key.ts:85` verifies with `zip215: false`. In
`@noble/curves` 2.2.0 that setting rejects a `y` at or above the field modulus
for both the public key and `R`
(`node_modules/@noble/curves/src/abstract/edwards.ts:378-409`, the
`aInRange('point.y', y, _0n, max)` check at line 393), rejects a small-order
public key (`edwards.ts:936`), and then evaluates the cofactored equation
(`edwards.ts:941-945`).

### Whether they conflict

They differ in two directions at once, and none of the three agrees exactly with
either of the others.

| Case | Solana runtime `verify_strict` | Rust SDK helper `verify` | TypeScript `zip215: false` |
| --- | --- | --- | --- |
| Non-canonical `y` encoding (`y >= p`) | accepts | accepts | rejects |
| Small-order `R` | rejects | accepts | accepts |
| Small-order public key | rejects | accepts | rejects |
| Residual in the torsion subgroup | rejects (cofactorless) | accepts (cofactored) | accepts (cofactored) |
| Non-canonical `s` | rejects | rejects | rejects |

So a signature exists that one convention accepts and another rejects, in both
directions. A signature whose verification residual is a nonzero torsion point
passes the TypeScript check and fails the Solana runtime check. A signature over
a non-canonically encoded public key passes the runtime check and fails the
TypeScript check.

Whether such a signature can reach the protocol path: it cannot reach the
authorization decision. An Ed25519-owned input is authorized by
`check_signer(account)` inside `check_input_signers`
(`programs/shielded-pool/src/instructions/transact/processor.rs:272-278`), which
reads the runtime's `is_signer` flag. The program does not receive Ed25519
signature bytes, and the transfer circuit contains no Ed25519 gadget: the
Solana-only rail pins the P256 message limbs to zero and sets `p256SigValid` to
the constant `1` (`circuit.go:175-178`). `SigningKey.verify` in TypeScript is a
library helper with no caller in protocol code: a search of `sdk-libs/ts` finds
it called from tests under `keypair/test` and from
`sdk-libs/ts/transaction/test/wallet-sync.test.ts:131`, and from no source
module outside `keypair/src/signing-key.ts` itself.

Unverified: this analysis did not construct a concrete divergent signature. The
table above is derived from the three verification implementations. Settling it
by example needs a torsion-point test vector run through the three verifiers.

### Options

**Option 1: keep `zip215: false` and record the reasoning.** No code change.
The recorded rationale would state that the helper is not on the authorization
path and that its strictness on non-canonical encodings is deliberate.

**Option 2: mirror the Solana runtime.** Replace the helper with a check that is
cofactorless and rejects a small-order `R`. `@noble/curves` does not expose that
combination through the `zip215` flag, so this needs code in
`sdk-libs/ts/keypair`. It would also mean changing the Rust helper at
`sdk-libs/keypair/src/signing_key.rs:114-131` from `verify` to `verify_strict`,
which is the larger of the two gaps against the runtime.

**Option 3: remove the Ed25519 arm from the SDK verify surface.** The protocol
does not consume an Ed25519 signature; the helper's presence invites callers to
treat it as authoritative.

### Artifacts a change would break

Option 1 breaks nothing.

Option 2 changes the public behavior of `SigningKey.verify` in both languages
and the vectors that exercise it:
`sdk-libs/ts/fixtures/keypair/signing_key.json`, generated by
`xtask/src/bin/ts-fixtures.rs:1296-1302`.

Option 3 removes a public method from `sdk-libs/ts/keypair` and
`sdk-libs/keypair`, so it is a breaking SDK change and touches the same fixture.

### Ruling

| Field | Value |
| --- | --- |
| Ruling | Option 2. Both SDK helpers mirror the Solana runtime's `verify_strict`, so a caller asking the SDK whether a signature is valid gets the runtime's answer. |
| Ruled by | Protocol owner |
| Date | 2026-07-25 |
| Follow-up artifacts | `sdk-libs/keypair/src/signing_key.rs`, `sdk-libs/ts/keypair/src/signing-key.ts`, `sdk-libs/ts/keypair/test/ed25519-acceptance.test.ts` (new). `sdk-libs/ts/fixtures/keypair/signing_key.json` is unchanged: its `verified` flags stay `true` under `verify_strict`. Implemented in `65100a09`. |

Correction recorded with the ruling, against the evidence above. In
`ed25519-dalek` 2.2.0 both `raw_verify` (`verifying.rs:201-217`) and
`verify_strict` (`verifying.rs:357-380`) compare `expected_R == signature.R` as
`CompressedEdwardsY` bytes, so the Rust helper was already cofactorless and
already refused a non-canonical `R` encoding. The two functions differ only in
that `verify_strict` decompresses `R` and refuses a small-order `R`, and refuses
a small-order public key. The row for the Rust SDK helper in the comparison
table above overstates its looseness in the first and fourth cases.

Reachability through the SDK surface: `SigningKey::verify` derives the public
key from the secret, so a small-order or non-canonically encoded public key
cannot reach it. Only the small-order `R` case is reachable, and it is the one
the new tests exercise in both languages.

## Ruled: the u64 integer domain (C04)

### What the spec says

`docs/spec.md:1772-1786` defines the response wrapper:

```rust
struct Context {
    /// Solana slot at which the indexer assembled this response.
    slot: u64,
}
```

The indexer integers the spec declares are Rust types, among them `slot: u64` on
`EncryptedUtxoMatch` (`docs/spec.md:1806`) and on `ShieldedTransaction`
(`docs/spec.md:1834`); `leaf_index: u64` and `root_seq: u64` on `MerkleProof`
(`docs/spec.md:1888-1892`); `low_element_index: u64`, `high_element_index: u64`,
and `root_seq: u64` on `NonInclusionProof` (`docs/spec.md:1923-1931`);
`root_index: u16` on both proofs.

The spec does not constrain the JSON encoding of those integers. It contains no
mention of JSON, of a decimal-string convention, or of a safe-integer bound. It
declares Rust struct shapes and nothing about how they are carried in a request
or a response. It also does not mention `block_time` anywhere.

### What each implementation does

Both Rust implementations declare `Context { block_time: i64 }`, not the spec's
`Context { slot: u64 }`:

- `sdk-libs/indexer-api/src/lib.rs:474-479`.
- `sdk-libs/client/src/rpc.rs:30-33`.

TypeScript mirrors that: `IndexerContext { readonly blockTime: bigint }`
(`sdk-libs/ts/indexer-api/src/types.ts:7-9`).

Photon fills the field from the maximum indexed block time
(`services/photon/src/common/indexer_context.rs:16-27`) and keeps a separate
`extract_slot` helper (`indexer_context.rs:29`).

### What the indexer sends today

Photon serializes the `zolana-indexer-api` structs with `serde`, so each
integer is a JSON number. The generated schema records the format:

- `Context.block_time`: `type: integer, format: int64`
  (`services/photon/src/openapi/specs/rings.yaml:643-651`).
- `slot`, `leaf_index`, `root_seq`, `low_element_index`, `seq`:
  `type: integer, format: u-int64, minimum: 0`
  (`rings.yaml:666-668`, `711-714`, `727-730`, `756-759`, `784-787`,
  `811-814`, `869-872`).

There is no string encoding and no `serde(with = "...")` stringifier on those
fields (`sdk-libs/indexer-api/src/lib.rs:474-479` and the proof structs in the
same file). A round-trip test asserts the snake_case JSON field names and the
value shapes (`services/photon/src/api/method/rings.rs:85-211`).

Photon therefore sends unquoted JSON numbers that can, in principle, exceed
`2^53 - 1`. In practice the values are a Solana slot, a Unix block time, a merkle
leaf index below `2^32` (state tree height 32,
`sdk-libs/client/src/rpc.rs:27-28`), and a monotonic root sequence, so a value
above the safe-integer bound is not reachable from current mainnet data.
That is an operational observation, not a constraint Photon enforces.

### What the TypeScript decoder does

`sdk-libs/ts/indexer-api/src/codec.ts:68-82` rejects any JSON number outside the
double-precision safe-integer range before the range check:

```ts
function wireInteger(value: unknown, path: string, minimum: bigint, maximum: bigint): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a safe JSON integer", value);
  }
  ...
}
```

`u64` and `i64` both route through it (`codec.ts:84-90`), as does the encoder
side (`codec.ts:118-145`). The decoded value is a `bigint`, so the public
TypeScript type is wide while the accepted input range is not.

### Whether they conflict

Two separate findings sit under this row.

The `Context` field is a spec-versus-implementation conflict: the spec says
`slot: u64`, the three implementations say `block_time` as a signed 64-bit
value. This is a plain disagreement and does not depend on the JSON question.

The u64 encoding question is not a conformance question. The spec is silent on
the JSON representation, so no implementation can be measured against it. The
current TypeScript behavior narrows the accepted domain relative to what Photon
can produce, and the spec neither authorizes nor forbids that.

### Options

For the `Context` field:

**Option C1: amend the spec to `block_time: i64`.** Matches the three
implementations. Changes `docs/spec.md:1775-1778`.

**Option C2: change the implementations to `slot: u64`.** Changes
`sdk-libs/indexer-api/src/lib.rs:474-479`, `sdk-libs/client/src/rpc.rs:30-33`,
`sdk-libs/ts/indexer-api/src/types.ts:7-9`, and
`services/photon/src/common/indexer_context.rs:16-27` (which already has the
slot query at line 29). Breaks the JSON field name for existing indexer clients
and the `context` assertions in
`services/photon/src/api/method/rings.rs:199-211`, plus the
`sdk-libs/ts/fixtures/client/rpc-indexer-v1.json` vectors.

For the integer domain, the spec supports none of the four candidates, because
it does not address the JSON payload. Recording them with their consequences:

**Option I1: decimal strings in the JSON payload.** A protocol change. Requires
`serde(with)` on the u64 and i64 fields of `sdk-libs/indexer-api`, a matching
OpenAPI schema change, and a decoder change in
`sdk-libs/ts/indexer-api/src/codec.ts`. Breaks each existing indexer client,
including the Rust one.

**Option I2: a lossless JSON parser in TypeScript.** Keeps the payload as JSON
numbers and reads large integers without precision loss. Contained to
`sdk-libs/ts/indexer-api` and its transport. Adds a dependency and a parse path
that differs from `JSON.parse`.

**Option I3: restrict the spec to safe integers.** Declares the affected fields
as bounded below `2^53`. Makes the current TypeScript behavior conformant and
turns a Photon value above the bound into a Photon defect. Requires a
corresponding check in Photon or the Rust encoder to stay honest.

**Option I4: keep the current TypeScript rejection with no spec change.** The
status quo. The failure mode is an `INDEXER_SCHEMA_INVALID_INTEGER` error at
`codec.ts:70` on a payload the Rust client would accept.

Because the spec is silent, choosing among I1 through I4 is a new decision, not
a conformance ruling.

### Artifacts a change would break

Listed per option above. The shared items are
`sdk-libs/ts/fixtures/client/rpc-indexer-v1.json`, the OpenAPI document
`services/photon/src/openapi/specs/rings.yaml`, and the serialization tests in
`services/photon/src/api/method/rings.rs`.

### Ruling

| Field | Value |
| --- | --- |
| Ruling (Context field) | Option C1. Amend the spec to `block_time: i64`, matching the three implementations. Same principle as G7-1 and X01: where the implementations agree, the specification is the stale artifact. |
| Ruling (integer domain) | Adopt Light Protocol's encoding, described below. It is neither of the two options originally offered. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `docs/spec.md:1775-1778`; `sdk-libs/ts/indexer-api/src/codec.ts`; the indexer schema |

#### What Light does, and why it settles this question

The owner asked how Light Protocol handles it before choosing between decimal
strings and a safe-integer bound. Light does both, as a union, and the
distinction it draws is per-field rather than global.

`js/stateless.js/src/rpc-interface.ts:316-328` defines `BNFromStringOrNumber`,
which accepts a JSON string or a JSON number. A number that is not a safe
integer is refused outright, with a message naming precision loss. A string is
parsed base 10 with no ceiling.

```316:328:js/stateless.js/src/rpc-interface.ts
const BNFromStringOrNumber = coerce(
    instance(BN),
    union([string(), number()]),
    value => {
        if (typeof value === 'number') {
            if (!Number.isSafeInteger(value)) {
                throw new Error(`Unsafe integer. Precision loss: ${value}`);
            }
            return bn(value); // Safe number → BN
        }
        return bn(value, 10); // String → BN
    },
);
```

Light applies it selectively. `lamports`, `seq`, `slotCreated` and
`discriminator` take the coercion, because those can genuinely exceed `2^53`.
`slot` and `leafIndex` are declared as plain `number()`
(`rpc-interface.ts:429`, `:83`), with no coercion and no safe-integer check,
because they cannot.

Two things follow, and the first is the one that changes the framing of this
conflict. **Zolana's TypeScript rejection is already Light's behaviour** for the
number case: Light throws on an unsafe JSON number exactly as
`codec.ts:68-82` does. The rejection was recorded here as TypeScript being
stricter than Rust, and it is, but it is also what the reference implementation
does, so it is not the defect. What Zolana lacks is Light's escape hatch.

Adopt the union. Accepting a decimal string alongside a number removes the
ceiling without breaking a single existing caller, because numbers stay valid,
which is the objection that ruled out decimal strings on their own. Keep the
precision-loss refusal, since silently truncating a slot is the failure this
prevents. Follow Light in applying the coercion only to fields whose domain can
actually exceed `2^53`, rather than uniformly, so a field that cannot overflow
does not acquire a parse path it never needs.

## Thirteen rulings from the open-questions register, 2026-07-26

The protocol owner ruled on thirteen questions in one sitting. The numbering is
[`open-questions.md`](open-questions.md)'s, and each entry below is the record
that register's status line points at.

Three went against the recommendation on the table, Q19, Q22 and the shape of
Q10. Each says so, because an undocumented override reads later as an oversight
and gets quietly reversed.

Several authorise editing `docs/spec.md`, which this port's standing constraint
otherwise forbids. Each such entry says so, and the authorisation covers that
conflict only.

### Q5: a zone authority moving value out of a zone

| Field | Value |
| --- | --- |
| Conflict | `docs/spec.md:983` states that value cannot leave a zone through a zone-authority transition. The program settles a zone-authority public leg through the same path as an ordinary `transact`, and the protocol's own builder carries a `withdrawal` field for it. |
| Ruling | Amend the specification to match the program. Same principle as G7-1 and X01: the implementations agree and the document is the stale artifact. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | The `docs/spec.md:983` paragraph. No SDK code moves; the guard was already removed under [Zone-authority withdrawals](#zone-authority-withdrawals). Row T29's text still describes the guard and needs rewriting to the current behaviour. |

This ruling authorises editing `docs/spec.md`. The authorisation covers this
conflict only.

Three independent readings agree that nothing on chain gates a public leg on the
zone-authority variant, and [`row-updates/rejection-validation.md`](row-updates/rejection-validation.md)
collects all three. `zone_authority_transact` calls
`process_transact_core::<true, true>`
(`zone_authority_transact/processor.rs:45-52`), and that function settles through
a match that consults neither const parameter (`transact/processor.rs:170-176`);
`IS_ZONE` and `IS_AUTHORITY` are read in exactly two places and neither touches
the public amounts. The circuit applies `assertBalanceConservation`
(`balance.go:15-72`) to every variant, and the only variant-specific constraints
in `Define` are the two zone-field assertions at `circuit.go:216-221`. And
`program-libs/interface/src/instruction/builders/zone_authority_transact.rs:21`
declares `pub withdrawal: Option<TransactWithdrawal>` and pushes the settlement
accounts for it, which is a protocol statement about what the instruction can
carry.

The specification paragraph is not careless, which is why it needs amending
rather than deleting. `git log -S` places it in `39465e8c`, the commit that added
the zone circuits, so it predates the port and is not a fixer writing their own
justification. What it gets wrong is the inference: the mechanism it cites is the
strict UTXO zone binding, and the conclusion that mechanism supports is that a
default-zone UTXO can neither be spent nor created. A withdrawal creates no
default-zone UTXO. It settles to an external account through the public leg,
which the binding does not touch. The amendment has to state the binding it
actually has and drop the containment claim, not restate the claim in different
words.

What would reopen this: someone intending containment as a real invariant. That
is a program change constraining the public amounts on the authority rail, and
the key rotation behind it, rather than a document edit. The confirming test the
register names, a `program-tests` scenario submitting a negative
`public_sol_amount` with a real proof, is still worth having, but as
confirmation. [`row-updates/double-spend-analysis.md`](row-updates/double-spend-analysis.md)
already established that nullification and public-leg settlement happen in one
instruction with no path that applies one without the other, so the safety
question that held this open is answered.

### Q6: the frozen-source gate

| Field | Value |
| --- | --- |
| Conflict | `npm run fixtures:check` fails when any file under twelve canonical paths differs from a pinned revision, so every row closed by fixing Rust reddens the gate whether or not the fix can change a fixture byte. |
| Ruling | Drop the source-hash gate entirely, as Light does. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `assert_frozen_sources` and its three revision constants and three path lists in `xtask/src/bin/ts-fixtures.rs`; the `canonicalSourceRevisions` block those constants also feed; the checklist's G8-1 drift line. `xtask` sits outside the `sdk-libs/**` scope rule, so this needs a worker allowed to touch it. |

This went further than the recommendation on the table, which was to narrow the
frozen set to files whose bytes feed a fixture. The owner chose removal. Record
it as a choice: a later reader finding no source pin should not conclude it was
lost.

The gate is `assert_frozen_sources` (`ts-fixtures.rs:268-295`), which runs
`git diff --quiet <revision> -- <paths>` for three revisions and fails the run on
any difference. Its baseline list is twelve paths (`ts-fixtures.rs:38-50`) and
includes `sdk-libs/keypair/src`, `sdk-libs/transaction/src` and
`sdk-libs/client/src/prover`, so a fix anywhere in three of the packages this
port is actively repairing turns the gate red. K12 already did it, and the C08
ruling sends the next worker into `client/src/prover`, another frozen path.

Light's absence here was checked as a negative rather than assumed:
`BASELINE_SHA`, `frozen_sources` and `assert_frozen` return nothing anywhere in
that repository, and it does export test data from Rust
(`xtask/src/export_photon_test_data.rs`) while pinning nothing about the sources
that produced it.

The consequence, stated plainly: fixture drift will no longer be caught by
hashing sources. What remains is the fixtures' own comparison, the regenerate
into `target/ts-fixtures-check` and compare against the committed tree at
`ts-fixtures.rs:133-145`, plus `EXPECTED_FIXTURE_COUNT` and the manifest hashes.
That comparison catches a source change that moves a fixture byte and is silent
about one that does not, which is the trade being accepted: the gate that fired
on a harmless edit is also the gate that would have caught a fixture nobody
regenerated. Two things follow for whoever removes it. The regenerate-and-compare
run has to actually run in CI rather than be assumed. And the three revision
constants also populate `canonicalSourceRevisions` in the manifest, so the
removal has to decide whether they stay as provenance labels or go with the
gate; leaving a constant named `BASELINE_SHA` behind with nothing enforcing it is
the outcome to avoid.

What would reopen this: a fixture divergence reaching `main` because nobody
regenerated. If that happens the answer is a stronger comparison, not a restored
source hash.

### Q7: `@solana/kit` and versioned transactions

| Field | Value |
| --- | --- |
| Conflict | Whether to take `@solana/kit`, and with it versioned transactions and address lookup tables, against a hand-written legacy message compiler. |
| Ruling | Stay on legacy messages. Revisit when a second pool tree ships. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | None to implement. Step A of [`remaining-work.md`](remaining-work.md) closes with this answer. The interim work [`versioned-transactions.md`](versioned-transactions.md) recommends stands on its own merits: the size measurement is landed, and consolidating the three hand-written compilers is justified by the duplication rather than by v0. |

The measurement is what decides it. A shielded transfer names three accounts at
any supported shape against a runtime ceiling of 128, and the count does not grow
with the proof shape, because `InputUtxo` carries a `tree_index: u8` and
`TransactAccounts` loads exactly one tree (`transact/account.rs:24-27`). Going
from one input to five adds 38 bytes and no accounts. A lookup table costs a
shielded transfer 5 bytes and saves an SPL withdrawal 57, because break-even is
two compressible addresses and a transfer has exactly one: the fee payer is a
signer, and a program id cannot be loaded from a table.

"Light adopted it" is not an argument its code supports, and this was checked
twice. Light did not migrate to v0, it started there, with no migration commit
and so no recorded trigger; its lookup tables are an append-only address registry
never passed to `compileToV0Message`; and its `@solana/kit` dependency is an
interop shim that compiles no transactions.

The decision is cheap to defer, which is the other half of the reasoning. The
boundary type is `Transaction = { messageBytes, signatures }`
(`interface/src/index.ts:72-75`), so a v0 message is still bytes and adopting v0
later ripples into no caller, no signer, and no wallet surface. What does accrete
is the duplication a version change would have to cross: one message compiler
became three and one `compactU16` became five, in four commits, in a package two
days old.

The revisit trigger the owner named is a second pool tree, which is Q9. Two
others from the study are real and should not be crowded out by it:
`OwnerTag::Account` coming into use, which makes the account list grow with
output count, and a wallet integration requiring `VersionedTransaction`, which is
an interoperation reason rather than a size one and belongs with finding F1.

### Q8: the ciphertext format change

| Field | Value |
| --- | --- |
| Conflict | Three of the ten supported shapes compile to transfers past the 1232-byte limit today and a fourth joins them as a withdrawal. The already-specified ciphertext format brings nine of the ten under the limit. |
| Ruling | Not scheduled. Plan as though it is not coming. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `SPP_SUPPORTED_SHAPES` and the resolution that reads it, `sdk-libs/ts/interface/src/shape.ts:12-42` and `program-libs/interface/src/shape.rs:68-79`. Both languages move together or the narrowing becomes a divergence. |

The register recorded the conditional: if the format change slips, narrowing
`SPP_SUPPORTED_SHAPES` stops being bookkeeping. It has slipped indefinitely, so
the conditional fires and the narrowing is necessary work.

What is unsendable today, measured rather than modelled
([`versioned-transactions.md`](versioned-transactions.md)): 4 in 4 out at 1294
bytes as a transfer, 5 in 4 out at 1332, 1 in 8 out at 2108, and 5 in 3 out at
1240 as a withdrawal. The last of those is the reason a flat removal of shapes
from the list would be wrong: 5 in 3 out sends fine as a transfer at 1100 bytes
and fails only as a withdrawal, so the narrowing has to distinguish the role
rather than the shape alone. The 1 in 8 out case is reachable from the public API
without doing anything unusual, because a single-input transfer to six recipients
resolves to it, and today nothing refuses it: the transaction is built, submitted,
rejected, and reported as a confirmation timeout.

The interaction with Q7 is the part worth recording. The recommendation against
versioned transactions rested partly on this change arriving, since it makes v0
unnecessary for size. That leg is gone. Q7's answer now stands on the size check
instead: a lookup table costs a transfer 5 bytes and rescues exactly one shape
across the ten, the 5 in 3 out withdrawal, from 1240 bytes to 1183. Versioned
transactions were never the fix for the three oversized transfers, and that
remains true with the format change unscheduled, but the argument is now the
measured arithmetic alone.

Coordinate with Q16 before editing the shape list. Two separate narrowings land
on the same surface for unrelated reasons: this one for size across the rails,
Q16's for zone-authority key coverage on one rail.

### Q9: a second pool tree

| Field | Value |
| --- | --- |
| Conflict | The account arithmetic behind Q7 rests on `TransactAccounts` loading exactly one tree, and no roadmap statement existed either way. |
| Ruling | No plan currently. Proceed on the one-tree assumption, recorded as an assumption with a named dependency rather than as a fact. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | None to implement. Q7's answer depends on this, and a second tree is Q7's named revisit trigger. |

The distinction the ruling asks for is the whole content of it. "No plan
currently" is the absence of a roadmap statement, not a commitment that a second
tree will never ship, so anything resting on it has to be written as conditional.
The load-bearing use is Q7: `InputUtxo::tree_index` is a `u8` that is zero
everywhere today because `TransactAccounts` loads one tree
(`transact/account.rs:24-27`), and the moment a spend can name two, a transfer
has two compressible protocol-owned addresses, which is exactly the lookup-table
break-even. A five-input spend across five trees would put four more 32-byte
addresses inline, and the account count would start scaling with input count.

Nobody will announce this in a form the SDK sees, so name the tells. A change to
`TransactAccounts::validate_and_parse` that reads more than one tree account is
the direct one. The indirect check is one command, `cargo run -p xtask -- tx-size`
over the shapes of interest, which should be re-run after any change to the
`transact` account list, the proof layout, or the ciphertext format, and compared
against the tables in [`versioned-transactions.md`](versioned-transactions.md).

### Q10: an explicitly-passed zero at a zone binding (T28)

| Field | Value |
| --- | --- |
| Conflict | T28 proposed refusing an explicitly-passed zero where the SDK constructors take an `Option`. The prepared struct distinguishes `Some(zero)` from `None` and the commitment does not. |
| Ruling | Normalize an explicitly-passed zero to absent rather than refusing it. The counterargument, that the dummy-canonicity check refuses an explicit zero rather than normalizing, was considered and not taken. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | `sdk-libs/transaction/src/instructions/types.rs:124` and the constructors that take these options, with the TypeScript counterparts. Rust first, TypeScript second, per the standing order for a change to what a constructor accepts. Row T28. |

This went against [`row-updates/t28-zone-binding.md`](row-updates/t28-zone-binding.md)
in shape for one of the two clauses it covers, and the register should be read
with that in mind: clause one was recommended as a refusal and clause two as a
normalization. The ruling normalizes.

Read the ruling as a principle over both explicit-zero clauses, because the
sentence names the zone address while the counterargument it dismisses belongs to
the zone data hash, and the two clauses had opposite recommendations. The
principle is that an explicitly-passed zero means absence and is normalized to
it. The consequence differs by clause and an implementer needs both.

For the zone data hash, normalization is free. The mechanism is
`types.rs:124`, which takes `spend.zone_data_hash.unwrap_or_default()`, so
`Some([0u8; 32])` and `None` already reach the commitment as the same value while
the prepared struct keeps them apart. That gap is the defect. Normalizing closes
it and moves no commitment, because the committed field was already zero.

For the zone address, normalization changes what is committed. `Some(zero)`
commits to `pk_field(0) = Poseidon(0, 0)`, a specific non-zero field element, so
a UTXO built that way is read as zone-bound and held to the public zone rather
than being unbound. Normalizing makes it unbound instead. That is safe on the
evidence: no caller in the SDK tests, client tests, program tests or TypeScript
fixtures passes the zero zone address, and a build that did could not settle,
because `merge_zone` reads the public zone from a signing `zone_config` and
`create_zone_config` requires that account to sign and to sit at the
`zone_auth` PDA derived under the zone program (`zone_config/create.rs:30`,
`:33-38`, `:76-78`). One trap for whoever implements it: do not cite
`circuit.go:219-221` as the chain-side equivalent. The circuit compares the field
element, and `pk_field(0)` is non-zero, so it would accept what the SDK refuses.

The counterargument, recorded because it was close. The SDKs already refuse an
explicit zero rather than normalize it in the canonical-dummy check
(`types.rs:79-80`, its test at `:209-211`, mirrored at
`ts/transaction/src/utxo.ts:284`), so refusing would have been consistent and
normalizing leaves the SDK doing two different things with the same input in two
places. What carries the ruling over that is the difference in what the two rules
are for: the dummy rule exists to catch a caller who built a dummy wrong, where
masking the mistake is the harm, and no equivalent mistake is being masked on a
real output. The caller shape is not hypothetical either, since the zone-deposit
fixtures use a zero `[u8; 32]` as the no-zone-data value in a fixed-width struct
(`program-tests/zone-test-program/tests/steps/zone_deposit.rs:46`), so an adapter
onto the `Option` API lands on `Some([0u8; 32])` without meaning anything by it.

What this ruling does not settle, both of which question 10 also carried. T28's
third clause, refusing a zone data hash at or above the BN254 modulus, is
untouched; it refuses nothing that succeeds today, relabels a deferred Poseidon
failure, and can be taken alone in either language first. And S01, the 1232-byte
guard, is untouched: question 13 supplied Light's partial answer, measure without
refusing, and the measurement landed in `0e26c397`, but whether Rust gains the
fallible builder signature is still open.

### Q11: the two program defects

| Field | Value |
| --- | --- |
| Conflict | PD-1 and PD-2 are program and circuit defects with executed reproductions, and the port's SDK-only scope forbids fixing either on this branch. |
| Ruling | Each gets its own pull request against the program, tracked outside this port. Neither blocks this port from landing. |
| Ruled by | Protocol owner, 2026-07-26 |
| Date | 2026-07-26 |
| Follow-up artifacts | PD-1 has no branch. PD-2 has branch `fix/merge-user-record-binding`, commit `a811b20e`, and PR #160, which is open rather than merged and whose commit is not an ancestor of `main`. [`scope-and-denominator.md`](scope-and-denominator.md)'s outside-scope table and the checklist's protocol-defect table both carry the route. |

The route is the same one this ledger already set twice, for the padding
nullifier against PR #142 and for the `user_record` binding defect. Confirming it
for both defects at once is most of what this ruling does. The new half is that
neither blocks the port: the completion criteria do not include either fix, so a
reviewer counting adverse rows should not count PD-1 or PD-2 among them, and a
worker finding one of them in a file they are porting should not stop.

PD-1 is a liveness risk rather than a double spend, and the distinction matters
because the investigation that found it answered the double-spend question the
other way. A padding dummy input's public nullifier column is unconstrained in
the circuit and the program inserts it anyway, so a padding dummy carrying
nullifier `0` lands on chain, and `0` is already a nullifier-tree leaf that
cannot be appended again. A chosen padding nullifier can wedge the queue and
freeze every shielded balance. Established by execution in
`program-tests/shielded-pool/tests/transact/double_spend.rs`.

PD-2 is that `merge_transact` does not bind its `user_record` to the owner whose
UTXOs are merged. [Where the `user_record` binding defect lands](#where-the-user_record-binding-defect-lands)
carries the analysis and should be read before the fix is attempted, in
particular that the P256 rail probably does not close without a registry change.

## Closed rulings

Recorded so the ledger is complete from the start. These four were decided
before this document existed; the evidence sections are intentionally short.

### DataRecord::Memo tag 3

| Field | Value |
| --- | --- |
| Conflict | The `Memo` variant at tag 3 is implemented but absent from `docs/spec.md`. |
| Ruling | Amend the spec to define tag 3. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `docs/spec.md` |

### CI tiering

| Field | Value |
| --- | --- |
| Conflict | Whether the merge gate runs a reduced suite. |
| Ruling | The merge gate runs the full suite, including the prover and both end-to-end suites. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | CI workflow definitions |

### Custody seam

| Field | Value |
| --- | --- |
| Conflict | Whether a custodian holding only signing key material is a supported configuration. |
| Ruling | A signing-only custodian is not supported. A custodian must hold nullifier and viewing key material. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | Wallet authority surface and its documentation |

### Indexer error `method` detail

| Field | Value |
| --- | --- |
| Conflict | Whether the `method` detail on an indexer error uses one naming convention across languages. |
| Ruling | Keep each language's existing naming convention. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | None |

### Breaking changes to the SDK crates

| Field | Value |
| --- | --- |
| Conflict | Whether the port may break the published Rust SDK surface, and whether the error enums should be extensible. |
| Ruling | Breaking changes are free. The four SDK crates sit at `0.1.0` with no consumers, so a break costs nothing today and the port need not preserve the surface it inherited. Both `TransactionError` and `ClientError` stay closed rather than `#[non_exhaustive]`: a closed set on each side is what lets the cross-language mapping fixture pair the two enums one to one, and extensibility protects consumers who do not exist. Revisit at the first release. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `rust-sdk-changes.md` breaking-change sections, the cross-language error mapping fixture |

This ruling covers the shape of the surface, not its behaviour. An SDK that refuses input the program and circuit accept is still a defect, because it makes a legal operation impossible to express, and having no users neither causes nor excuses it.

### Merge order against PR #158

| Field | Value |
| --- | --- |
| Conflict | Whether the signature-lookup PR or this port lands first. |
| Ruling | PR #158 lands first and the port rebases onto it. Both branch from `43fde8e4`, but #158 is five commits against an unmoved base where this branch is 206, and the port is not verified enough to hold up a focused change. The port then owes one method, three wire types, two error variants, and a rename: the TypeScript `indexer-api` already exports `IndexedShieldedTransaction` for a different type than #158 claims the name for. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/pr-158-impact.md` |

Whoever performs that rebase should read `row-updates/pr-158-impact.md` first. The rebase has one visible conflict, in `indexer_error` in `sdk-libs/client/src/indexer.rs`, and one invisible hazard that matters more: `error.rs` merges without complaint into a type holding both error representations, after which `should_retry` matches `IndexerUnavailable`, a variant this branch's `indexer_error` does not produce, since it returns `Indexer { method, retryable }` instead. The result compiles, passes, and leaves the confirmation path unable to retry. Three of #158's tests also call the single-argument `indexer_error` from outside the conflicted region, so resolving the marked lines leaves the build broken in three call sites the conflict does not point at.

### Zone-authority withdrawals

| Field | Value |
| --- | --- |
| Conflict | The SDK raises `ZoneAuthorityWithdrawalNotAllowed` on a public leg the program accepts. |
| Ruling | Allow them. The SDK is over-strict and relaxes to match the program; the check goes away rather than narrowing. A zone authority may move value out through a public leg, and an SDK that refuses makes a legal operation impossible to express. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/rejection-validation.md`, `row-updates/transaction-unblock.md` |

This was held open on a safety question that has since been answered by execution. `row-updates/double-spend-analysis.md` establishes that nullification and public-leg settlement occur in a single instruction, in that order, with no path that applies one without the other, so a public leg can neither strand value nor spend a note twice. Containment was therefore a policy preference rather than an invariant, and it is not the preference.

The narrower relaxation already in flight, admitting `amount > 0` so the check stops refusing deposits, is a subset of this ruling rather than a conflict with it. Removing the check subsumes it.

**Do not close row T29 by restoring the guard.** Its row text still describes a withdrawal guard rejecting the public leg on the zone-authority rail, and an exhaustive Rust-to-TypeScript error map confirms no such variant exists in either language now. Both permit the leg deliberately, under this ruling. Restoring it would also resurrect a second defect that the removal exposed: `PublicAmounts::default()` was correct only while the guard existed, so with a leg permitted, a hardcoded default proves zero public amounts over a nonzero leg. That is a valid proof of the wrong statement. T29 needs its text rewritten to describe the current, correct behaviour, not a fix.

### The padding-nullifier finding against PR #142

| Field | Value |
| --- | --- |
| Conflict | Whether the port rebases onto PR #142 the way it rebases onto #158. |
| Ruling | It does not. The padding-nullifier queue wedge is a circuit and program defect with no parity surface, so #142 lands on its own schedule and this port neither waits for it nor tracks it. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/double-spend-analysis.md`, secondary finding |

The finding stands as independent confirmation of work already underway rather than as a new obligation. Nothing in the TypeScript SDK constructs padding nullifiers, so no row changes either way and the fix arrives through the program rather than through this branch.

### Where the `user_record` binding defect lands

| Field | Value |
| --- | --- |
| Conflict | Three failing tests sit on the port branch for a program defect the SDK-only scope forbids fixing there. |
| Ruling | Its own branch and pull request against the program, containing both the tests and the fix. The port branch drops the tests and stays green. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/registry-merge-verification.md`, commit `cbf197e7` |

Same disposition as the padding nullifier, for a different reason. That one already had a fix in flight and needed only to be left alone; this one had none anywhere, so leaving it alone would have dropped it. A separate pull request keeps the port free of protocol work without losing the finding.

The fix must reckon with the two rails separately. Re-deriving the record's address may close the eddsa rail, because the circuit computes the input and output owner hashes from `signing_pk_field`, so a substituted key produces hashes that fail the inclusion check. The P256 rail probably does not close without a registry change: `owner_p256` is copied from instruction data at registration with no signature showing the registrant holds the matching private key, so establishing that the record is the canonical one for `record.owner` still leaves `owner_p256` an unverified claim. Requiring the record to sign is unavailable, because the spec makes merges callable by anyone (`docs/spec.md:1667`).

### Whether the zone prover paths are built now or deferred

| Field | Value |
| --- | --- |
| Conflict | `inventory-client.md:61` dispositions the zone-authority prover as `port` and names the file it would live in; the checklist defers rows C13, C14, and C18 to PKP-05. Both cannot hold. |
| Ruling | Build them now, in the parity phase, and check them again in the cryptographic phase. The inventory is correct and the deferral is withdrawn. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/zone-prover-ruling.md`, `proof-and-key-parity.md` PKP-05 |

The deciding fact is that the gap is not at the edge of the pipeline but one step from its end. The
transaction and interface packages already build zone instruction data and the prepared
zone-authority object, so a TypeScript caller assembles a complete zone transaction and then finds
no way to prove it. A missing capability at the boundary of an SDK reads as scope; a missing
capability in the middle of a working path reads as a defect, and callers discover it late.

The three zone shapes are in scope: zone transfer on the Ed25519 rail, zone transfer on the P256
rail, and the zone-authority transition. The forester's `address-append` shape is not, and its
`NOT_APPLICABLE` disposition on row C07 stands. That is a separate judgement resting on a separate
fact: TypeScript ships no forester, so an address-append builder would have neither a producer nor a
consumer in that language. Light Protocol reached the same conclusion for the same reason and ports
only the decode half of tree maintenance.

Deferral would not have saved work, only moved it. PKP-05 already listed the zone inputs as
deliverables, so the same code had to be written either way; the only question was whether it
would be written while the parity harness was warm or months later against a colder tree.

### The forester instruction builder on the TypeScript public surface

| Field | Value |
| --- | --- |
| Conflict | `interface/src/instructions/index.ts:76` exports `batchUpdateNullifierTreeInstruction`, whose `BatchUpdateNullifierTreeData` requires a `compressedProof` that no TypeScript path can produce. |
| Ruling | Withdraw the builder from the public surface. Do not port the address-append witness. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | Row C07, `row-updates/forester-and-poseidon-rulings.md` |

This closes the half of C07 that did not survive checking. The row's `NOT_APPLICABLE` disposition
rested on there being neither a caller nor a reader for the forester types in TypeScript. The caller
half was right and the reader half was wrong, because we publish and test the final instruction of
the pipeline while shipping none of the steps before it.

WebAssembly does not offer a third way here, and it was considered. Light Protocol compiles its Rust
Poseidon to WebAssembly, but for hashing only; proofs still come from a Go prover server over HTTP,
as ours do. Producing an address-append proof needs witness generation and gnark proving, which is a
different order of work from hashing, so the choice stays between porting the witness and dropping
the builder.

Withdrawal is a breaking change to `@zolana/interface`. That is acceptable under the standing ruling
that pre-1.0 SDK crates with no users may break. Decoding stays: a TypeScript tool should still read
a `batch_update_nullifier_tree` instruction it finds in a transaction, because reading it needs
nothing we cannot do.

### Poseidon in TypeScript

| Field | Value |
| --- | --- |
| Conflict | Five hand-written TypeScript Poseidon implementations, one of which carried a partial-round table for widths the verifier cannot reproduce. |
| Ruling | Compile the Rust Poseidon to WebAssembly and have the TypeScript packages call it, as Light Protocol does. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `row-updates/forester-and-poseidon-rulings.md`, the `H` rows |

The deciding fact is that the duplication is a defect generator rather than untidiness, and it has
already fired. `client/src/internal.ts:26` listed partial-round counts for widths 14 through 17 when
the syscall accepts at most twelve arguments, so a thirteen-input call returned a digest that no
verifier can reproduce: a wrong answer wearing the shape of a right one. It was the copy with no
parity suite, which is why it was the copy that was wrong. Parity suites now cover the five, but
that arrangement asks five implementations to stay correct indefinitely, and the next helper
duplicated across packages starts the same clock again.

One compiled artifact removes the class rather than the instance. The costs are real and should be
tracked: a WebAssembly build to produce, version, and publish; larger bundles; and more friction in
some browser and edge runtimes. The browser and packaging gates are where those costs show up, so
they are the gates that decide whether this lands.

A second question falls out and should not be answered by reflex. Light's production SDK barely
hashes, because its prover server and indexer supply what would otherwise need local hashing; its
WebAssembly hasher sits in test helpers apart from one hash chain in `rpc.ts`. Ours hashes across
five packages. Some of that difference is genuine, since we carry a P256 rail and zone transactions
Light has no counterpart for. Some may be work sitting on the wrong side of a boundary. Worth
measuring before assuming each current call site needs to be there.

### Whether the WebAssembly Poseidon may use a module-scope await

| Field | Value |
| --- | --- |
| Conflict | Keeping `poseidon()` synchronous forces an `await` at module scope, which a consumer bundling to a CommonJS target cannot represent. |
| Ruling | Keep the compiled artifact, replace the module-scope await with an explicit one-time async initializer, and add a CommonJS build beside the ESM one. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-25 |
| Follow-up artifacts | `poseidon-wasm-and-packaging.md` |

This supersedes the shape of the earlier Poseidon ruling without reversing its substance. The
compiled Rust hasher stays; how it loads changes.

The coordinator argued twice and was wrong once. It first treated the CommonJS constraint as
decisive, then reversed on the ground that the ten TypeScript packages are already `"type":
"module"` with no `require` condition, so no CommonJS consumer was being served in the first place.
Reading Light Protocol's packaging settled it the other way: `js/stateless.js` builds
`dist/cjs/node`, `dist/cjs/browser`, and `dist/es/browser`, with `main` pointing at
`dist/cjs/node/index.cjs`. A shipped SDK with users in this ecosystem maintains four targets rather
than drop CommonJS, so our ESM-only packaging reflects a decision nobody made rather than a settled
direction.

Light also shows that a compiled hasher and a CommonJS build can coexist, by keeping the hasher out
of module scope and passing it as an argument (`js/stateless.js/src/rpc.ts:495`). We take the
property and not the technique: Light's production code hashes in one place, ours hashes across five
packages, so a module-level singleton with an explicit initializer buys the same freedom from
module-scope await without changing many public signatures.

The cost accepted is 585 KB gzipped once per application, and a named error when `poseidon()` runs
before initialization. A clear failure is the price of the design; a silent wrong digest would not
have been.

### The external-data length prefix (T21)

| Field | Value |
| --- | --- |
| Conflict | `program-libs/interface` truncates the `ExternalDataHash` length prefix through a `u16` cast. Erroring instead would change a preimage the deployed program computes. |
| Ruling | Leave the program alone. Make both SDKs refuse the input loudly rather than truncate it quietly, and document the divergence. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-26 |
| Follow-up artifacts | Row T21 |

The trigger is more than 65,535 outputs or messages in one transaction, which a Solana transaction
has no room to carry. So this is a divergence at a boundary no caller reaches, and buying agreement
there with a program change and the key rotation behind it is a poor trade.

Note what the two options actually produce, because the intuitive reading is backwards. Silent
truncation in the SDK would *agree* with the program, since both would truncate identically. Raising
an error disagrees with the program, but only for an input that cannot arrive. The ruling takes the
loud disagreement: a caller who somehow constructs such a transaction learns immediately, rather than
receiving a hash computed over a silently shortened preimage.

Both SDKs move together. TypeScript already raises `TRANSACTION_TOO_MANY_OUTPUTS` past `0xffff`, and
the Rust SDK gets the matching guard. Neither side may change alone: removing the TypeScript guard
by itself would restore quiet truncation in one language, and that is the state this ruling exists to
end. The cross-language vector at the boundary, `0xffff` accepted against `0x10000` refused, is owed
by both and exists in neither.

The revert question hanging over `bc55a9b9` is settled by this: the checked `length_prefix` in
`program-libs/interface` stays reverted, the program keeps truncating, and the guard lives in the
SDKs where this branch is allowed to put it.

### Rail inference when parsing a proof (C08)

| Field | Value |
| --- | --- |
| Conflict | Rust infers the proof rail from which fields are present, so an Ed25519 request answered with a commitment-bearing proof yields a P256 proof that cannot verify. TypeScript refuses it. |
| Ruling | Fix Rust. TypeScript is correct. |
| Ruled by | Protocol owner |
| Date | Recorded 2026-07-26 |
| Follow-up artifacts | Row C08, `sdk-libs/client/src/prover/proof.rs` |

Recorded partly to correct the coordinator, which listed this among the rows needing a change outside
the branch. It does not. The defect is in `sdk-libs/client/src/prover/proof.rs`, an SDK crate the
scope rule covers, and no program or circuit is involved.

This inverts the usual direction and is worth noticing for that reason. Most divergences this port
found were TypeScript refusing what Rust accepts, and the standing instruction has been to relax
TypeScript, because a port that is stricter than its original silently breaks callers. Here the
strictness is right: a proof whose commitment does not match the requested rail cannot verify, so
refusing it early converts a confusing verification failure into a clear parse error. Rust should
refuse it too.

Three sibling findings on the same row were already fixed at `52ca1e25` and each is pinned by a case
in `client/test/prover.test.ts`: an unknown JSON key no longer fails where `serde_json` ignores it,
an empty `proof_commitment` array reads as absent, and a coordinate without the `0x` prefix parses.
Those three were TypeScript being wrong. This fourth is Rust being wrong, and the row stays open
until the Rust side moves.
