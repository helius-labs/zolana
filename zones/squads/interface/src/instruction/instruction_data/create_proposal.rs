//! `create_proposal` (tag 11) instruction data (spec: squads `create_proposal`).

use wincode::{SchemaRead, SchemaWrite};

use crate::types::{Address, ProposalCiphertext};

/// `create_proposal` instruction data (spec: squads `create_proposal`). Queues
/// one withdrawal or transfer for async execution. The program sets the
/// proposal's `discriminator`, `owner` (= `viewing_key_account`), and
/// `rent_payer` (= `fee_payer`); these fields are copied verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateProposalIxData {
    /// Recipient owner for a transfer, SPL account for a withdrawal.
    pub recipient: Address,
    /// Asset mint. SOL is the default address.
    pub asset: Address,
    /// Operation commitment; a public input to the zone proof at execution.
    pub proposal_hash: [u8; 32],
    /// Amount and blinding encrypted to the shared viewing key.
    pub cipher_text: ProposalCiphertext,
    /// Unix timestamp after which execution fails.
    pub expiry: i64,
}

impl CreateProposalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
