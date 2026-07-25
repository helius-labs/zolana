# Owner-hash cross-rail collision audit

Independent adversarial review of the collision argument at `docs/spec.md:278`,
requested before the spec is amended to the parity-free owner encoding. This
review does not adopt the conclusion recorded in
`planning/typescript-sdk-port/authority-rulings.md:122-140`; it re-derives the
question from the circuit, the program, the registry program, and both SDKs.

Line numbers are as of branch `ts-sdk-port` on 2026-07-25. Each section below is
labelled either **Verified**, meaning read from the named file and line, or
**Analysis**, meaning reasoned from those readings rather than executed or
measured.

## Bottom line

Amending the spec to describe the parity-free owner form is safe in the narrow
sense: no reachable theft depends on the change, and the change describes code
that already ships. It is not safe to amend by deleting the line 278 argument
and putting nothing in its place. The `y_is_odd` layer was doing real work in one
place this review found reachable, and two properties that used to be structural
are now assumptions that the code does not state.

Three results:

1. **No collision-based spend.** The owner hash covers `nullifier_pk`, and the
   proof recomputes `nullifier_pk` from a free `nullifier_secret` witness.
   Spending someone else's UTXO through a cross-rail alias is therefore a
   Poseidon **preimage** problem against a fixed target, not a birthday
   collision. This is a stronger result than "the encodings are separated" and it
   survives the loss of the parity layer. Verified below.

2. **Rail choice moves from the owner to the attacker.** Because both rails hash
   the same 32 bytes with the same function, an Ed25519 owner at Solana address
   `S` is simultaneously the P256 owner of x-coordinate `S`. An attacker can
   route that owner's input through the P256 rail, which skips the Solana signer
   check in the program and substitutes the ECDSA check the proof performs.
   Nothing is broken today, because the substituted check needs the P256 discrete
   log of the point at x = `S`, but an Ed25519 owner's safety now rests on P256
   as well as on Ed25519. The spec should say so.

3. **One reachable finding, in the merge registry path.** `owner_p256` in a user
   registry record is written with no proof of possession, and `merge_transact`
   accepts any registry-owned account as the `user_record`. Under the
   parity-inclusive form an Ed25519 owner was structurally out of reach of this
   defect; under the parity-free form they are not. The gate that remains is the
   victim's `nullifier_secret`, which the spec hands to the sync delegate by
   design. A current or former sync delegate can therefore freeze an Ed25519
   owner's balance. Details and the concrete path in
   [Finding 1](#finding-1-registry-record-substitution-in-merge_transact).

### Replacement argument the spec should carry

Replace `docs/spec.md:278` with a statement of what separates the rails, not of
what encodes them:

> The owner field is an identity commitment, not an authorization. Both rails
> compute the same function over 32 bytes, `hash_field` over the P256
> x-coordinate or over the full Ed25519 key, so the encoding does not distinguish
> them and a P256 x-coordinate equal to an Ed25519 public key produces the same
> owner field. Separation comes from two independent properties, either of which
> is sufficient:
>
> 1. `owner_hash = Poseidon(pk_field, nullifier_pk)` and `nullifier_pk =
>    Poseidon(nullifier_secret)`, with `nullifier_secret` a private witness.
>    Reusing another owner's `owner_hash` requires a Poseidon preimage on a fixed
>    target, not a collision.
> 2. Each rail authorizes against the same 32 bytes through a different hardness
>    assumption. The Ed25519 rail requires the named Solana account to sign the
>    transaction; the P256 rail requires an ECDSA signature that the proof checks
>    against a witnessed point whose x-coordinate is those bytes.
>
> Consequence, stated as an assumption rather than left implicit: an Ed25519
> owner at address `S` may also be addressed as the P256 owner of x = `S`, so
> that owner's spend authorization is the weaker of Ed25519 signing and the P256
> discrete log at x = `S`.
>
> Any surface that derives the owner field from bytes that were not authenticated
> as a key the submitter controls is equivalent to impersonating an Ed25519
> address. The user registry `owner_p256` field is such a surface.

The parity-inclusive form remains correct for viewing keys and should keep the
name `pk_field`. The owner form needs its own name in the spec so the two are not
substituted for each other.

## What enters `owner_hash`, field by field

### Verified: the two encodings

Parity-inclusive, used for viewing keys only:

| Surface | Symbol | Location |
| --- | --- | --- |
| Circuit gadget | `P256PkFieldGadget` | `prover/server/circuits/spp_transaction/p256.go:33-36` |
| Merge circuit, user viewing key | `P256PkFieldFromPointCircuit` | `prover/server/circuits/spp_merge/circuit.go:185` |
| Program, merge | `pk_field` over `record.viewing_pubkey` | `programs/shielded-pool/src/instructions/merge/verify.rs:133-135`, called at `merge/processor.rs:50` |
| Interface crate | `pk_field_compressed` | `program-libs/interface/src/merge_utils.rs:15-30` |
| Rust keypair | `PublicKey::hash` | `sdk-libs/keypair/src/pubkey.rs:153-162` |
| TypeScript interface | `pkFieldCompressed` | `sdk-libs/ts/interface/src/merge-utils.ts:87-90` |
| TypeScript keypair | `ShieldedPublicKey.hash` | `sdk-libs/ts/keypair/src/public-key.ts:107-116` |

Parity-free, used for owner identity:

| Surface | Symbol | Location |
| --- | --- | --- |
| Circuit gadget | `OwnerPkFieldGadget` | `prover/server/circuits/spp_transaction/p256.go:88-90` |
| Circuit entry, asserts on-curve | `OwnerPkFieldFromPubkeyCircuit` | `p256.go:94-118`, assertion at `p256.go:106` |
| Program, P256 | `verifier::hash_field` | `programs/shielded-pool/src/instructions/verifier.rs:27-37` |
| Program, Ed25519 | `solana_pk_hash` | `programs/shielded-pool/src/instructions/hash.rs:24-29` |
| Interface crate | `owner_pk_field_compressed` | `program-libs/interface/src/merge_utils.rs:37-52` |
| Rust keypair | `PublicKey::owner_pk_field` | `sdk-libs/keypair/src/pubkey.rs:170-172` |
| TypeScript interface | `ownerPkFieldCompressed` | `sdk-libs/ts/interface/src/merge-utils.ts:92-94` |
| TypeScript keypair | `ShieldedPublicKey.ownerPublicKeyField` | `sdk-libs/ts/keypair/src/public-key.ts:118-127` |

The two rails compute the identical function. `hash_field` splits its 32-byte
input at byte 16 and hashes `Poseidon(low, high)` with each half right-aligned
into a field element (`verifier.rs:27-37`, `verifier.rs:56-60`). `solana_pk_hash`
does the same split over the Ed25519 key (`hash.rs:24-29`). The circuit takes the
low 128 bits and the high 128 bits of the canonical x-coordinate bit
decomposition and hashes them in the same order (`p256.go:111-117`). Both SDKs
route both rails through one function keyed on the "view tag", which is the P256
x-coordinate or the full Ed25519 key
(`sdk-libs/keypair/src/pubkey.rs:146-151` and `170-172`;
`sdk-libs/ts/keypair/src/public-key.ts:102-105` and `118-127`).

Byte order agrees across the circuit, the program, and the two SDKs. The
circuit's `ToBitsCanonical` yields little-endian bits, so `xBits[:128]` is the
low half, matching `hash_field`'s low 16 bytes (`p256.go:111-113` against
`verifier.rs:31-36`).

The collision question is therefore not a question about Poseidon. It is a
question about whether the same 32 bytes can be a valid identity on both rails,
which is a statement about key encodings.

### Verified: `nullifier_pk` is covered on both rails, and is bound to a secret

`OwnerHashGadget` is `Poseidon(OwnerKeyHash, NullifierPk)`
(`prover/server/circuits/spp_transaction/utxo.go:40-47`). In the transfer
circuit, `constrainInput` builds the owner hash from the routed `ownerKeyHash`
and the per-input `nullifierPk` and constrains it equal to the input UTXO's
`owner` field (`inputs.go:100-104`). The routing above it selects
`ownerKeyHash`; neither branch removes `NullifierPk` from the hash
(`inputs.go:89-96`). So `nullifier_pk` is covered on both rails, in the
confidential and the anonymous variant alike.

`nullifierPk` is not a free public value. It comes from `NullifierPkGadget`,
which is `Poseidon(NullifierSecret)` (`inputs.go:140-147`), evaluated per input
in `Circuit.Define` (`circuit.go:188-193`). The same `NullifierSecret` witness
feeds the nullifier itself (`inputs.go:107-112`, gadget at `inputs.go:149-163`).
The merge circuit does the same thing explicitly:
`nullifierPk := Poseidon(userNullifierSecret)` and
`AssertIsEqual(userNullifierPk, nullifierPk)`
(`prover/server/circuits/spp_merge/circuit.go:143-144`).

**Correction to a premise in the prior write-up.** The prior investigation says
`nullifier_secret` is "derived from the signing secret"
(`authority-rulings.md:124-128`, citing
`sdk-libs/keypair/src/nullifier_key.rs:24-26` and `docs/spec.md:310`). That holds
for the honest client, but it is not a circuit constraint. Inside the circuit,
`NullifierSecret` is an unconstrained private witness with no tie to a signing
key. Verified by absence: no such assertion appears in
`spp_transaction/circuit.go` or `spp_transaction/inputs.go`, and the merge
circuit's only binding is the `nullifier_pk` equality at
`spp_merge/circuit.go:144`.

The distinction matters. If `nullifier_secret` were constrained to derive from
the signing secret, the attacker's problem would be to find a signing key whose
derived pair reproduces the target. Because it is free, the attacker's problem is
to find any `(A, s)` with `Poseidon(A, Poseidon(s)) = O`, where `A` is an
identity they can authorize and `O` is the victim's fixed owner field. The
freedom does not help the attacker, and it makes the security claim cleaner: the
protection is preimage resistance against a fixed target, roughly 2^-254, not
collision resistance at 2^-127. The prior write-up reached the right answer
through a premise that the constraint system does not enforce.

## Adversarial cases

### Analysis: what an attacker controls on each rail

On the Ed25519 rail the identity is a 32-byte Solana address that must be a
transaction signer (`transact/processor.rs:272-278`). An attacker can generate
unlimited Ed25519 keypairs, and can also sign as a program-derived address
through a CPI from a program they deploy, since `check_signer` reads the runtime
`is_signer` flag and does not distinguish the two. Either way the identity bytes
are the output of key generation or of SHA-256 over seeds, so the attacker can
search a large space cheaply but cannot aim at a specific 32-byte target.

On the P256 rail the identity is the x-coordinate of a point the attacker must
know the discrete log of, because `env.p256PkField` and `env.p256SigValid` are
computed from the same witness `c.P256Pub` (`circuit.go:155-170`) and a
P256-routed input requires the signature to verify (`inputs.go:105`). Generating
random keypairs gives uniformly distributed x-coordinates; aiming at a specific x
is a discrete log.

The attacker's reachable identity set on each rail is therefore large but not
targetable. This is the property that replaces the encoding separation.

### Verified: full cross-rail spend is a preimage, not a collision

To spend a victim UTXO with owner field `O`, the circuit requires
`Poseidon(A, Poseidon(s)) = O` for an `A` the attacker can authorize and an `s`
they choose freely (`inputs.go:100-104`). The victim's UTXO fixes `O`, so the
attacker cannot run a birthday search: they must hit one specific output. With
`A` ranging over a searchable set and `s` free, the cheapest attack remains a
2^-254 per-trial preimage search.

The one shortcut would be knowing the victim's `nullifier_secret`, which
collapses the problem to authorizing as `A`. That shortcut is real and is the
subject of Finding 1.

### Verified: the program's Ed25519 signer check is bypassable by rail choice

This is the sharpest consequence of the parity-free form, and neither the code
nor the spec records it.

An input's rail is chosen by `eddsa_signer_index` in instruction data. When it
equals `P256_OWNED_SIGNER` (255, `transact/verify.rs:35`), `check_input_signers`
performs no signer check and writes either the zero sentinel or
`p256_signing_pk_field` (`transact/processor.rs:266-278`).
`p256_signing_pk_field` is `hash_field(ix.p256_signing_pk_x)`, and
`p256_signing_pk_x` is raw attacker-supplied instruction data
(`transact/processor.rs:97-100`,
`program-libs/interface/src/instruction/instruction_data/transact.rs:222`).

An attacker targeting a victim's Ed25519-owned UTXO can therefore set
`p256_signing_pk_x` to the victim's Solana address `S`. The program writes
`hash_field(S)`, which is exactly `solana_pk_hash(S)`, the victim's Ed25519 owner
field, and it does not check that a signature for `S` was present. In the
confidential branch the circuit routes the input as P256 by the equality test
(`inputs.go:90-92`); in the anonymous branch the sentinel selects
`env.p256PkField` (`inputs.go:93-96`), which the attacker sets by witnessing a
point with x = `S`.

What stops it: `OwnerPkFieldFromPubkeyCircuit` asserts the witnessed point is on
the curve (`p256.go:106`), and `inputs.go:105` requires the ECDSA signature to
verify under that same point. The attacker needs the P256 private key for the
point at x = `S`. They also need the victim's `nullifier_secret`, since the owner
hash covers it.

Analysis of the cost: the P256 field modulus is within 2^-32 of 2^256, so a
32-byte Solana address falls below it except with probability about 2^-32, and
roughly half of those have a valid y. Around half of Solana addresses are
therefore addressable as P256 x-coordinates. For those, the barrier is a P256 discrete log at a specific point,
about 2^128 work, which is not practical. The substitution is still structural:
the program's Ed25519 signer check is not a required check for an Ed25519-owned
UTXO, it is one of two alternatives, and the attacker picks. Under the
parity-inclusive form the P256 branch could not produce a value in the Ed25519
identity space, so no such alternative existed.

### Verified: the reverse direction has no cheaper route

To spend a P256-owned UTXO through the Ed25519 rail, the attacker needs a
transaction signer whose 32-byte address equals the victim's x-coordinate `X`.
Either an Ed25519 keypair whose public key encodes to `X`, which is a discrete
log if `X` decodes to a curve point, or a program-derived address equal to `X`,
which is a SHA-256 preimage on a fixed 32-byte target. Neither is approachable,
and the victim's `nullifier_secret` is still required.

A program-derived address is required to be off-curve for Ed25519, and a P256
x-coordinate read as an Ed25519 compressed point is off-curve about half the
time, so the off-curve rule is not the obstacle. The SHA-256 preimage is.

### Verified: partial control does not add up to an attack

The attacker can search over one limb of the preimage only in the sense that both
the low and the high 128-bit limb come from the same 32-byte identity, so
searching keypairs moves both together. No surface supplies the two limbs
independently: `hash_field` derives both from one array (`verifier.rs:31-36`),
and the circuit derives both from one bit decomposition (`p256.go:111-113`).
Neither SDK exposes a path that sets them separately
(`sdk-libs/ts/interface/src/merge-utils.ts:82-85`,
`program-libs/interface/src/merge_utils.rs:44-51`).

The other half of the preimage, `nullifier_pk`, is attacker-chosen through the
free `nullifier_secret` witness, so the attacker already holds that half. It
does not help, because `owner_hash` is a fixed target and Poseidon does not
decompose.

### Analysis and unresolved: the degenerate P256 point

`AssertIsOnCurve` in the pinned gnark accepts `(0,0)` by design, treating it as
the point at infinity
(`~/go/pkg/mod/github.com/consensys/gnark@v0.14.0/std/algebra/emulated/sw_emulated/point.go:210-226`,
comment at line 211). `OwnerPkFieldFromPubkeyCircuit` therefore admits a witness
with x = 0, which folds to `Poseidon(0, 0)`.

Under the parity-free form, `Poseidon(0, 0)` is exactly
`hash_field([0u8; 32])`, the Ed25519 owner field of the zero Solana address.
It is also the constant the circuits use as the native SOL asset field
(`prover/server/circuits/spp_transaction/circuit.go:380-389`). Under the
parity-inclusive form the degenerate point would produce
`Poseidon(y_is_odd, Poseidon(0,0))`, which lands nowhere near the Ed25519
identity space. The parity-free change merges a degenerate P256 witness into an
Ed25519 identity.

Whether the signature check can be satisfied for that witness is unresolved. The
ECDSA gadget computes `Q = [r/s]PK + [m/s]G` through `JointScalarMulBase`
(`gnark@v0.14.0/std/signature/ecdsa/ecdsa.go:49-79`, call at line 71, with no
`algopts` passed). P256 declares `Eigenvalue: nil`
(`sw_emulated/params.go:91-99`), so the call dispatches to
`jointScalarMulFakeGLV` (`point.go:790-807`), whose documented precondition at
`point.go:802` is that the points differ from `(0,0)` unless complete arithmetic
is requested, which it is not. The gadget is being used outside its stated domain
for this witness.

Impact if it is satisfiable: an attacker could spend a UTXO whose owner field is
`Poseidon(hash_field([0u8; 32]), nullifier_pk)`, that is, one owned by the
zero Solana address, and only if they also hold that owner's
`nullifier_secret`. No party can sign for the zero address, so no such UTXO
should exist in a tree, and the practical value is close to zero. It is recorded
because it is a case where the boundary between the two encodings matters, and
because the underlying gadget-precondition question is worth settling on its own
terms.

What would settle it: a `test.IsSolved` run on one transfer P256 shape with
`P256Pub = (0, 0)`, `P256SigningPkField = Poseidon(0,0)`, and an `(r, s)` chosen
by the prover. If the constraint system is satisfiable, the P256 rail admits a
signature-free witness for one specific identity, and the fix is an explicit
`AssertIsDifferent` on the witnessed x, or passing
`algopts.WithCompleteArithmetic`.

## Finding 1: registry record substitution in `merge_transact`

This is the one place where the loss of encoding separation is reachable today.

### Verified: the merge instruction trusts an unauthenticated record

`merge_transact` takes three accounts: the tree, a payer that must sign, and the
`user_record` (`merge/account.rs:20-24`). The payer is any signer; the owner of
the UTXOs being merged signs nothing, and the merge proof checks no signature on
either rail (`docs/spec.md:1026`, and the absence of an ECDSA gadget anywhere in
`prover/server/circuits/spp_merge/circuit.go`).

`load_user_record` validates only that the account is owned by the registry
program and carries a `UserRecord` discriminator
(`merge/account.rs:54-62`; the discriminator check is the whole of
`program-libs/user-registry-interface/src/state.rs:52-57`). It does not check the
record PDA, and it does not tie the record to any signer.

The rail is selected by `ix.eddsa_owner`, a caller-supplied instruction field
(`merge/processor.rs:41`). On the P256 branch the owner field is
`owner_pk_field_compressed(record.owner_p256)`; on the Ed25519 branch it is
`solana_pk_hash(record.owner)` (`merge/account.rs:65-74`). The merge opt-in
`merging_enabled` is read from that same record (`merge/processor.rs:41-47`), so
it is the submitted record's opt-in rather than the victim's.

### Verified: `owner_p256` has no proof of possession

`process_register` writes `data.owner_p256` straight from instruction data into
the record; the only authenticated field is `owner`, taken from the signing
account (`programs/user-registry/src/instructions/register.rs:29-55`, assignment
at line 46 and line 48). `process_update_keys` lets the record owner overwrite
`owner_p256` with arbitrary bytes at any time
(`programs/user-registry/src/instructions/update_keys.rs:20-33`, assignment at
line 30). `process_set_merging_enabled` is per record and checks only that the
signer is that record's own owner
(`programs/user-registry/src/instructions/set_merging_enabled.rs:19-31`).

Any user can therefore create a record whose `owner_p256` is 33 bytes of their
choosing, whose `viewing_pubkey` is their own key, and whose `merging_enabled` is
true.

### Verified: the circuit's rail is a private witness, not the program's rail

In the merge circuit, `isP256 := api.IsZero(s.ownerPkHash)` and
`pkField := api.Select(isP256, p256PkField, s.ownerPkHash)`
(`prover/server/circuits/spp_merge/circuit.go:138-139`). The selected `pkField`
is the value hashed into the public input chain
(`spp_merge/circuit.go:190`, consumed at `spp_merge/circuit.go:193-204`). The
program hashes its registry-derived `signing_pk_field` into the same position
(`merge/verify.rs:111-126`).

One 32-byte value is the only coupling between the program's rail and the
circuit's rail. The prover may take the Ed25519 path in the proof, supplying
`ownerPkHash` directly and a throwaway on-curve point for `P256Pub`, while the
program takes the P256 path from the record. Under the parity-free form the two
produce the same bytes, so the mismatch is invisible.

### Analysis: the attack path

Attacker: a current or former sync delegate of the victim. The spec assigns the
delegate the victim's `nullifier_secret` by design (`docs/spec.md:1028`,
`docs/spec.md:997`), and `docs/spec.md:2225` acknowledges that a revoked delegate
keeps both the secret and the `blinding` of the UTXOs whose ciphertexts it
decrypted.

Victim: an Ed25519-owned wallet at Solana address `S`.

Steps:

1. The attacker registers their own record and sets
   `owner_p256 = 0x02 || S`, `viewing_pubkey` to a key they hold, and
   `merging_enabled = true` (`register.rs:45-55`, `update_keys.rs:30-32`,
   `set_merging_enabled.rs:30`). No possession of any key at x = `S` is required,
   and `S` need not be a valid P256 x-coordinate.
2. The attacker builds a merge proof over up to eight of the victim's UTXOs,
   using the victim's `nullifier_secret`, the blindings the delegate already
   decrypted, `ownerPkHash = solana_pk_hash(S)` on the circuit's Ed25519 path,
   and their own viewing key as `UserViewingPubkey`.
3. The attacker calls `merge_transact` with their own record and
   `eddsa_owner = false`. The program computes
   `owner_pk_field_compressed(0x02 || S)`, which is `Poseidon(low, high)` over
   `S` (`merge_utils.rs:44-51`), byte-identical to `solana_pk_hash(S)`
   (`hash.rs:24-29`). It matches the proof's public value. `viewing_pk_field` is
   derived from the attacker's key (`merge/processor.rs:50`) and matches the
   encryption the proof performed (`spp_merge/circuit.go:179-188`).
   `merging_enabled` comes from the attacker's record. The proof verifies.

What the attacker gains: the victim's eight UTXOs are nullified
(`merge/processor.rs:146-148`) and the merged output is appended
(`merge/processor.rs:164-165`) with an unchanged owner hash
(`spp_merge/circuit.go:140`, `162`), so the attacker cannot spend it. The output
ciphertext is encrypted with the attacker's viewing key, so the victim does not
learn the merged UTXO's blinding and cannot compute its nullifier. The balance is
frozen permanently. The event's view tag is still `S`
(`merge/processor.rs:55`, `merge/account.rs:66`), so the victim sees the event
and cannot decrypt it.

What stops it today: only the `nullifier_secret`. The path has no signature, no
PDA check, and no owner opt-in.

### Analysis: which part the encoding change caused

For a **P256-owned** victim this attack already works and has nothing to do with
the parity question. The victim's compressed key is public in their own record,
and the attacker copies those exact 33 bytes; both encodings then agree by
construction. The root cause is the missing possession proof plus the
unauthenticated record in `load_user_record`, and it should be fixed on its own
merits.

For an **Ed25519-owned** victim, the parity-inclusive form blocked it. The
program's P256 branch would produce `Poseidon(y_is_odd, Poseidon(low, high))`,
which cannot equal `solana_pk_hash(S)` short of a Poseidon collision, and the
Ed25519 branch reads `record.owner`, which the signer authenticates at
registration and cannot be set to someone else's address (`register.rs:29-46`,
`update_keys.rs:26-28`). The parity-free change is what extends this attack from
P256 owners to Ed25519 owners. That is the concrete answer to the question this
review was asked: line 278's argument was load-bearing, in one place, and this is
it.

### Suggested remediation, in priority order

1. Tie the record to the owner in `merge_transact`. Derive the expected record
   PDA from the owner identity, or require the record's `owner` to sign. This
   closes the attack for both rails independently of the encoding.
2. Require proof of possession for `owner_p256` at `register` and `update_keys`,
   so an unauthenticated key cannot enter an owner field.
3. Read `merging_enabled` only from a record the program has tied to the owner
   being merged. As written, a victim who did not opt into merging can still be
   merged through someone else's record.

None of these blocks the spec amendment. They are separate changes and should be
separate work.

## Boundary between the two encodings

**Verified: nothing compares or substitutes them.** Across the call sites of both
forms, the parity-inclusive function is called only over viewing keys
(`merge/verify.rs:133-135` over `record.viewing_pubkey`,
`spp_merge/circuit.go:185` over the witnessed viewing point) and the parity-free
function only over owner identities (`transact/processor.rs:97-99` and `:298`,
`merge/account.rs:66-73`, `circuit.go:156`, `spp_merge/circuit.go:134`). No
public input, account field, or fixture holds one where the other is expected.
The two are not equated, and no code path derives one from the other.

The residual risk at the boundary is naming rather than substitution. Both SDKs
expose the two forms as sibling methods on one type with names that do not say
which is which: `hash()` against `ownerPublicKeyField()`
(`sdk-libs/ts/keypair/src/public-key.ts:107-127`) and `hash()` against
`owner_pk_field()` (`sdk-libs/keypair/src/pubkey.rs:153-172`). On the Ed25519
rail both return the same bytes (`pubkey.rs:160` and `171`; the fixture records
this at `sdk-libs/ts/fixtures/keypair/hash.json`), so a caller who reaches for
the wrong one gets correct results on the rail they are testing and wrong results
on the other. That is a defect-injection risk in future code rather than a live
bug. Naming the owner form distinctly in the spec, and matching that name in the
SDKs, would remove it.

**Verified: the same x-coordinate as both a P256 owner and an Ed25519 owner.**
The two produce byte-identical owner fields, so the protocol treats them as one
owner. Two people can independently reach the same owner field: whoever holds the
P256 discrete log at x, and whoever holds the Ed25519 secret for the key encoding
to x. Each still needs the matching `nullifier_secret` to spend, and the owner
hash pins one `nullifier_pk`, so only one of them can be the UTXO's actual owner.
The realistic version of this is not two honest parties colliding by accident,
which analysis puts at 2^-256 per pair, but the deliberate version in Finding 1.

**Verified: the confidential owner tag is rail-blind.** The public tag hashed
into `output_owner_pk_hashes` is `hash_field(owner_tag)`
(`transact/processor.rs:287-301`), and the resolved tag is the raw 32 bytes: an
account address, an inline value, or the P256 x-coordinate
(`instruction_data/transact.rs:272-286`,
`sdk-libs/keypair/src/pubkey.rs:146-151`). An observer or an indexer reading the
confidential rail cannot tell from the tag which rail an owner is on, and cannot
tell an attacker-chosen inline tag from a real address. This is a labelling
property rather than an authorization one, but any compliance or policy layer
that keys on these tags should be told that the tag proves nothing about the rail
or about possession.

## What could not be ruled out

1. **The degenerate P256 witness.** Whether `P256Pub = (0,0)` yields a
   satisfiable ECDSA constraint is unresolved. Evidence that would settle it: the
   `test.IsSolved` run described above. Impact is bounded by the fact that the
   aliased identity is the zero Solana address, which nobody can own.

2. **The ECDSA gadget's soundness for non-degenerate witnesses.** This review
   read the gadget (`gnark@v0.14.0/std/signature/ecdsa/ecdsa.go:36-79`) but did
   not audit `scalarMulFakeGLV` or its hints. Because the parity-free form maps
   the P256 identity space onto the Ed25519 identity space, a soundness gap in
   that gadget is now a cross-rail issue rather than a P256-only one. Settling it
   needs a dedicated review of the emulated arithmetic, which is out of scope
   here.

3. **The zone-authority variant sits outside this argument.** It omits input
   owner fields from the public inputs (`circuit.go:251-253`,
   `transact/verify.rs:184-186`) and proves no owner authorization
   (`docs/spec.md:983`). Whatever the spec says about encoding separation, that
   variant does not rely on it. Amended text should say so rather than imply the
   argument covers each variant.

4. **Empirical confirmation of the aliasing claims.** The claims in the
   "Adversarial cases" section are derived from reading the constraint system and
   the program. This review did not build a transaction that routes an Ed25519
   owner through the P256 rail, nor a merge with a substituted record. The
   cheapest confirmation of Finding 1 is a program test that submits
   `merge_transact` with a record whose `owner_p256` is `0x02 ||` another
   wallet's Solana address and asserts the program derives the same
   `signing_pk_field` the Ed25519 branch would. That test needs no prover run:
   the derivation is a pure function of the record, and asserting
   `owner_pk_field_compressed(0x02 || S) == solana_pk_hash(S)` is enough to
   demonstrate the aliasing.
