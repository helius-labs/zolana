//! `transact` (tag 0) instruction data (spec: squads `transact`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::TransactIxData as SppTransactIxData;

use crate::types::ProofBytes;

/// `transact` instruction data (spec: squads `transact`): the ring proof and the
/// SPP `ring_transact` / `ring_authority_transact` payload the ring forwards
/// unchanged. The ring proof binds `spp.private_tx_hash`, the output ciphertexts
/// in `spp.outputs[..].data`, `spp.tx_viewing_pk`, and the public amount of the
/// single withdrawal leg in `spp.interface_transfers`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub ring_proof: ProofBytes,
    pub spp: SppTransactIxData,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
