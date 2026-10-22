//! `full_withdrawal` (tag 10) instruction data (spec: squads `full_withdrawal`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::TransactIxData as SppTransactIxData;

/// `full_withdrawal` instruction data (spec: squads `full_withdrawal`).
///
/// Escape-hatch public exit without the co-signer or backend. There is no ring
/// proof; the owner's Ed25519 signature inside the SPP proof authorizes the spend,
/// so only the SPP `ring_transact` payload is carried and forwarded unchanged.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FullWithdrawalIxData {
    pub spp: SppTransactIxData,
}

impl FullWithdrawalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
