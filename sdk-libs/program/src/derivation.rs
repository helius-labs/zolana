//! Blinding seed derivations: the values an SPP transact proof derives
//! from its single private `blinding_seed` and its first nullifier. Mirrors Go
//! `circuits/spp_transaction/shared/derivation.go`. The first nullifier enters
//! the nullifier tree once, so every derived value is unique to one accepted
//! transaction even if a client reuses a root seed. The three derivations are
//! separated by 32-bit ASCII tags, which keeps a disclosed output blinding seed
//! from reaching the private transaction blinding of the same root seed.

use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

/// Domain separator for SPP transaction output blindings: ASCII `"TXOB"`.
/// This must match `OutputBlindingDomainV1` in the Go circuit.
pub const DOMAIN_TRANSACT_OUTPUT_BLINDING_V1: u32 = 0x5458_4f42;

/// Domain separator for the SPP transaction output blinding seed: ASCII
/// `"TXOS"`. This must match `OutputBlindingSeedDomainV1` in the Go circuit.
pub const DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1: u32 = 0x5458_4f53;

/// Domain separator for the private transaction blinding: ASCII `"TXPB"`.
/// This must match `PrivateTxBlindingDomainV1` in the Go circuit.
pub const DOMAIN_PRIVATE_TX_BLINDING_V1: u32 = 0x5458_5042;

/// `Poseidon(TXOS, first_nullifier, blinding_seed)`: the seed every physical output
/// blinding of one transaction comes from. `blinding_seed` is the transaction's
/// private random root seed. The derived output seed is disclosed to the reader
/// of an anonymous Sender bundle, a plaintext transfer, or a split bundle, which
/// is why it is domain-separated from [`derive_private_tx_blinding`].
pub fn derive_output_blinding_seed(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &right_align(&DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1.to_be_bytes()),
        first_nullifier,
        &right_align(blinding_seed),
    ])
}

/// `Poseidon(TXPB, first_nullifier, secret)`: the final `private_tx_hash`
/// preimage element. It is never published: every other preimage element is
/// public or computable, so a known blinding would let an observer test
/// candidate input UTXO hashes against the published hash. `secret` is the
/// blinding seed on the transact rails and the owner's nullifier secret on
/// the merge rails.
pub fn derive_private_tx_blinding(
    first_nullifier: &[u8; 32],
    secret: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &right_align(&DOMAIN_PRIVATE_TX_BLINDING_V1.to_be_bytes()),
        first_nullifier,
        &right_align(secret),
    ])
}

/// `Poseidon(TXOB, first_nullifier, seed, output_index)`: the final blinding of
/// one physical SPP transaction output slot. The first nullifier makes the
/// derivation unique across accepted transactions, while `output_index` makes
/// every slot unique within one transaction. Only the final result is shared
/// with the output recipient.
pub fn derive_transact_output_blinding(
    first_nullifier: &[u8; 32],
    seed: &[u8; 32],
    output_index: u32,
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &right_align(&DOMAIN_TRANSACT_OUTPUT_BLINDING_V1.to_be_bytes()),
        first_nullifier,
        &right_align(seed),
        &right_align(&output_index.to_be_bytes()),
    ])
}
