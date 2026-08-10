//! Proposal account: the parameters of a queued withdrawal or transfer, bound to
//! the hidden operation by `proposal_hash` (the private v2 core). At execution
//! the program adds the operation, asset, and checked destination to derive the
//! zone proof's public proposal commitment.

use wincode::{SchemaRead, SchemaWrite};

use super::discriminator;
use crate::{
    types::{Address, ProposalCiphertext},
    PROPOSAL_PDA_SEED,
};

/// Async proposal, derived at `[b"proposal", owner, cipher_text[0..33]]`. All
/// fields are fixed-size. It (de)serializes with wincode for symmetry with the
/// other zone accounts and to stamp/check the discriminator uniformly.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub discriminator: u8,
    pub owner: Address,
    pub recipient: Address,
    pub asset: Address,
    /// Domain-separated private proposal core. The on-chain program derives the
    /// full public proposal commitment from this value and the record context.
    pub proposal_hash: [u8; 32],
    pub cipher_text: ProposalCiphertext,
    pub expiry: i64,
    pub rent_payer: Address,
}

impl Proposal {
    pub const DISCRIMINATOR: u8 = discriminator::PROPOSAL;
    pub const SEED: &'static [u8] = PROPOSAL_PDA_SEED;
    /// Fixed serialized size: `1 + 32 + 32 + 32 + 32 + 88 + 8 + 32`.
    pub const SIZE: usize = 257;

    pub fn new(
        owner: Address,
        recipient: Address,
        asset: Address,
        proposal_hash: [u8; 32],
        cipher_text: ProposalCiphertext,
        expiry: i64,
        rent_payer: Address,
    ) -> Self {
        Self {
            discriminator: Self::DISCRIMINATOR,
            owner,
            recipient,
            asset,
            proposal_hash,
            cipher_text,
            expiry,
            rent_payer,
        }
    }

    /// Allocation size. It is constant for this account.
    pub fn account_size() -> usize {
        Self::SIZE
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
