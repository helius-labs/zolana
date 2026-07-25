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
- [Open: confidential owner tag (T23)](#open-confidential-owner-tag-t23)
- [Ruled: ECDSA malleability policy (G2-1)](#ruled-ecdsa-malleability-policy-g2-1)
- [Ruled: Ed25519 acceptance (G2-2)](#ruled-ed25519-acceptance-g2-2)
- [Open: the u64 integer domain (C04)](#open-the-u64-integer-domain-c04)
- [Closed rulings](#closed-rulings)

## Open: owner-hash encoding (G7-1)

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
| Ruling | |
| Ruled by | |
| Date | |
| Follow-up artifacts | |

## Open: confidential owner tag (T23)

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
| Ruling | |
| Ruled by | |
| Date | |
| Follow-up artifacts | |

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

## Open: the u64 integer domain (C04)

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
| Ruling (Context field) | |
| Ruling (integer domain) | |
| Ruled by | |
| Date | |
| Follow-up artifacts | |

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
