<!-- cargo-rdme start -->

# zolana-hasher

Trait for generic hash function usage on Solana.

| Type | Description |
|------|-------------|
| [`Hasher`] | Trait with `hash`, `hashv`, and `zero_bytes` |
| [`Poseidon`] | Poseidon hash over BN254 |
| [`Keccak`] | Keccak-256 hash |
| [`Sha256`] | SHA-256 hash |
| [`HasherError`] | Error type for hash operations |
| [`hash_chain`] | Sequential hash chaining |
| [`primitives`] | Fixed-length byte packing and Poseidon commitments |
| [`zero_bytes`] | Precomputed zero-leaf hashes per hasher |

<!-- cargo-rdme end -->
