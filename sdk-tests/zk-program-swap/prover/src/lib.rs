pub mod cancel;
pub mod create;
pub mod ffi;
pub mod fill;
pub mod fill_verifiable_encryption;
pub mod order_terms;
pub mod utxo;

pub use cancel::{CancelError, CancelProofInputs, CancelProofResult};
pub use create::{CreateError, CreateProofInputs, CreateProofResult, OrderProof};
pub use ffi::{preload, prove, setup, CircuitId, Error, ProveOutput, Result, WitnessMap};
pub use fill::{derive_destination_blinding, FillError, FillProofInputs, FillProofResult};
pub use fill_verifiable_encryption::{
    FillVerifiableEncryptionError, FillVerifiableEncryptionProofInputs,
    FillVerifiableEncryptionProofResult,
};
use num_bigint::BigUint;
pub use order_terms::{OrderTerms, FILL_MODE_DERIVED, FILL_MODE_VERIFIABLE};
pub use utxo::UtxoFieldElements;
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, poseidon},
    KeypairError, NullifierKey,
};

/// The escrow UTXO's nullifier pubkey is fixed to the zero-secret nullifier key
/// (`NullifierKey::from_secret([0u8; 31]).pubkey()`), so the opening is the full
/// spend capability and the escrow needs no per-order secret.
fn zero_nullifier_pk() -> core::result::Result<[u8; 32], KeypairError> {
    NullifierKey::from_secret([0u8; BLINDING_LEN]).pubkey()
}

/// Owner hash of the escrow UTXO: the escrow-authority PDA is the owner key and
/// the nullifier secret is hardcoded to 0, so
/// `owner_hash = Poseidon(hash_field(escrow_authority), zero_nullifier_pk())`.
pub fn escrow_owner_hash(
    escrow_authority: &[u8; 32],
) -> core::result::Result<[u8; 32], KeypairError> {
    let pk_field = hash_field(escrow_authority)?;
    let nullifier_pk = zero_nullifier_pk()?;
    poseidon(&[&pk_field, &nullifier_pk])
}

pub fn asset_field(mint: &[u8; 32]) -> core::result::Result<[u8; 32], KeypairError> {
    hash_field(mint)
}

/// Owner hash from its parts: `Poseidon(owner_pk_field, nullifier_pk)`. Matches
/// `zolana_keypair::hash::owner_hash` and the cancel circuit's binding of the
/// maker signing pubkey to the escrow's committed `maker_owner_hash`.
pub fn owner_hash(
    owner_pk_field: &[u8; 32],
    nullifier_pk: &[u8; 32],
) -> core::result::Result<[u8; 32], KeypairError> {
    poseidon(&[owner_pk_field, nullifier_pk])
}

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
