//! Key update proposal account: a queued async update to a viewing key account's
//! recovery keys, buffering the new shared-key ciphertexts the executor fills in.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::discriminator;
use crate::{
    types::{Address, P256Pubkey, SharedKeyCiphertext},
    KEY_UPDATE_PROPOSAL_PDA_SEED,
};

/// A single recovery-key change (or auditor update) applied to the target
/// viewing key account in array order. Fixed-size (35 bytes): `op` + `index` +
/// the 33-byte key.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct KeyOperation {
    pub op: u8,
    pub index: u8,
    pub key: P256Pubkey,
}

/// Async key-update proposal, derived at
/// `[b"key_update_proposal", target, domain]`. Variable-length (the operations
/// and new-ciphertext vectors), so it (de)serializes with wincode.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct KeyUpdateProposal {
    pub discriminator: u8,
    pub domain: u16,
    pub target: Address,
    #[wincode(with = "containers::Vec<KeyOperation, FixIntLen<u8>>")]
    pub operations: Vec<KeyOperation>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub new_key_ciphertexts: Vec<SharedKeyCiphertext>,
    pub expiry: i64,
    pub executor: Address,
    pub rent_payer: Address,
}

impl KeyUpdateProposal {
    pub const DISCRIMINATOR: u8 = discriminator::KEY_UPDATE_PROPOSAL;
    pub const SEED: &'static [u8] = KEY_UPDATE_PROPOSAL_PDA_SEED;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: u16,
        target: Address,
        operations: Vec<KeyOperation>,
        new_key_ciphertexts: Vec<SharedKeyCiphertext>,
        expiry: i64,
        executor: Address,
        rent_payer: Address,
    ) -> Self {
        Self {
            discriminator: Self::DISCRIMINATOR,
            domain,
            target,
            operations,
            new_key_ciphertexts,
            expiry,
            executor,
            rent_payer,
        }
    }

    /// Allocation size for `operations` key operations and `ciphertexts`
    /// buffered shared-key ciphertexts. Each operation is 35 bytes and each
    /// ciphertext 32; the fixed part (109) covers the scalar fields and the two
    /// 1-byte wincode length prefixes.
    pub fn account_size(operations: usize, ciphertexts: usize) -> usize {
        109 + 35 * operations + 32 * ciphertexts
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
