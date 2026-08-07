# One outer proof over a third-party leg

Status: not built. No circuit, no key, and no instruction exists for it.

Every outer circuit here embeds its inner verifying key as a compile-time
constant, which fits a catalogue of keys this repository owns. An app key cannot
be a constant of ours, so an integration today is two proofs. The app verifies
its own proof in its own program and CPIs into SPP, which verifies ours under
our constant. No ceremony of ours gates that.

The alternative makes one side a witness. The SPP leg keeps its fixed key with
precomputed lines, and the app leg takes its verifying key as a witness bound by
a public digest.

A witness key does not admit arbitrary circuits. gnark's placeholder key fixes
the inner public-input count, the commitment count, and
`PublicAndCommitmentCommitted` at compile time, and none of those is witness
data. Composition therefore needs a published ABI, and our own rails already
obey one. Exactly one public input, the Poseidon chain over the app statement,
and zero or one BSB22 commitment over private wires. The zero-or-one fork is
structural, so the design is two outer circuits in total rather than one per
integration.

Permissionless key registration stays sound. A trapdoored app key lets its
holder prove any app statement, but the SPP leg still verifies under our fixed
key, so the pool stays sound and the blast radius is the app that chose the key.
The one requirement is that a registry entry cannot be borrowed across apps.

A verifying-key registry is the validating home for such keys. Its
PDA address commits to the key material, and init runs `g2_prepare`, which
enforces curve and r-order subgroup membership, and `pairing_map`, which fixes
the GT target. An in-circuit witness path omits all three.

One gap remains. The registry digests keccak over canonical bytes while the
circuit needs Poseidon over emulated limbs, so the same key would carry two
digests. Keccak in circuit costs far more than the Poseidon digest, so the
circuit would take Poseidon-of-limbs and init would compute the same digest
once, chunked across the existing resize steps.

The composition buys one pairing instead of two, one proof in the transaction
instead of two, and a binding that lives in a circuit rather than in each
integrator's program. It changes compute, size, and uniformity, not soundness.
Measure the composed compute before building it.
