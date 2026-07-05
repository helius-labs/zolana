//! Per-owner viewing key account: the shared viewing key, the ciphertexts that
//! let recovery keys and the auditor recover the shared private key, and the
//! encrypted nullifier secret.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::discriminator;
use crate::{
    types::{Address, EncryptedNullifierSecret, P256Pubkey, SharedKeyCiphertext},
    VIEWING_KEY_ACCOUNT_PDA_SEED,
};

/// Per-owner viewing key record, derived at `[b"viewing_key_account", owner]`.
/// Variable-length (recovery/auditor key vectors), so it (de)serializes with
/// wincode rather than a zero-copy `bytemuck` cast.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ViewingKeyAccount {
    pub discriminator: u8,
    pub owner: Address,
    pub state: u8,
    pub encryption_scheme: u8,
    /// `OWNER_KIND_KEYPAIR` (P256 rail) or `OWNER_KIND_SMART_ACCOUNT` (signatureless
    /// zone-authority rail). Selects the SPP settlement rail for spends of this
    /// account's UTXOs; not bound by any proof.
    pub owner_kind: u8,
    pub shared_viewing_key: P256Pubkey,
    pub shared_viewing_key_commitment: [u8; 32],
    pub key_nonce: u64,
    pub nullifier_pubkey: [u8; 32],
    pub key_ciphertext_ephemeral: P256Pubkey,
    pub encrypted_nullifier_secret: EncryptedNullifierSecret,
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub recovery_keys: Vec<P256Pubkey>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub recovery_key_ciphertexts: Vec<SharedKeyCiphertext>,
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub auditor_keys: Vec<P256Pubkey>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub auditor_key_ciphertexts: Vec<SharedKeyCiphertext>,
}

impl ViewingKeyAccount {
    pub const DISCRIMINATOR: u8 = discriminator::VIEWING_KEY_ACCOUNT;
    pub const SEED: &'static [u8] = VIEWING_KEY_ACCOUNT_PDA_SEED;

    /// Allocation size for `recovery` recovery entries and `auditor` auditor
    /// entries. Each entry is a 33-byte key plus a 32-byte ciphertext (65 bytes);
    /// the fixed part (209) covers the scalar fields (including the 1-byte
    /// `owner_kind`) and the four 1-byte wincode length prefixes.
    pub fn account_size(recovery: usize, auditor: usize) -> usize {
        209 + 65 * (recovery + auditor)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
