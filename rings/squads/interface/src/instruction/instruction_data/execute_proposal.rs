//! `execute_proposal` (tag 13) instruction data (spec: squads
//! `execute_proposal`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::TransactIxData as SppTransactIxData;

use crate::types::ProofBytes;

/// `execute_proposal` instruction data (spec: squads `execute_proposal`).
///
/// Settles an approved proposal: the ring proof plus the forwarded SPP payload,
/// as in [`crate::instruction::TransactIxData`]. The proposal account supplies
/// `proposal_hash` (a ring proof public input) and the expiry, which must equal
/// `spp.expiry_unix_ts`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ExecuteProposalIxData {
    pub ring_proof: ProofBytes,
    pub spp: SppTransactIxData,
}

impl ExecuteProposalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
