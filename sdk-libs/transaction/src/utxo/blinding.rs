use crate::error::TransactionError;

/// A UTXO blinding: a 32-byte big-endian BN254 field element. Poseidon-derived
/// blindings use the full field width; random values right-align 31 bytes to
/// stay below the field modulus.
pub type Blinding = [u8; 32];

// The blinding seed derivations live in `zolana_program::derivation` so
// programs can recompute them on-chain; this module keeps the SDK entry points
// and maps the hasher error into `TransactionError`.
pub use zolana_program::derivation::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

/// `Poseidon(TXOS, first_nullifier, blinding_seed)`: the seed every physical output
/// blinding of one transaction comes from. `blinding_seed` is the transaction's
/// private random root seed. The derived output seed is disclosed to the reader
/// of an anonymous Sender bundle, a plaintext transfer, or a split bundle, which
/// is why it is domain-separated from [`derive_private_tx_blinding`].
pub fn derive_output_blinding_seed(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_program::derive_output_blinding_seed(
        first_nullifier,
        blinding_seed,
    )?)
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
) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_program::derive_private_tx_blinding(
        first_nullifier,
        secret,
    )?)
}

/// `Poseidon(TXOB, first_nullifier, seed, output_index)`: the final blinding of
/// one physical SPP transaction output slot. The first nullifier makes the
/// derivation unique across accepted transactions, while `output_index` makes
/// every slot unique within one transaction. Only the final result is shared
/// with the output recipient.
pub fn derive_transact_output_blinding(
    first_nullifier: &[u8; 32],
    seed: &Blinding,
    output_index: u32,
) -> Result<Blinding, TransactionError> {
    Ok(zolana_program::derive_transact_output_blinding(
        first_nullifier,
        seed,
        output_index,
    )?)
}
