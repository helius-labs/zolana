//! Ring-authority state transition (`ring_authority_transact`): an unsigned
//! transact over ring-owned UTXOs. The ring authority is authorized on-chain (the
//! `ring_config` PDA signs), so unlike [`SppProofInputs`](super::transact::SppProofInputs)
//! there is no owner signature. Mirrors the merge prepared form: it carries the
//! padded inputs (real first, dummies at the tail) and yields the input
//! commitments to fetch Merkle proofs for.

use solana_address::Address;

use crate::{
    error::TransactionError,
    instructions::{
        transact::{shape::Shape, spp_proof_inputs::PublicTransfers},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    ExternalData, SppProofOutputUtxo,
};

/// A prepared, unsigned ring-authority transact. `external_data`'s
/// `instruction_discriminator` must be `RING_AUTHORITY_TRANSACT` (tag 17) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedRingAuthority {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub public_transfers: PublicTransfers,
    pub external_data: ExternalData,
    pub payer: Address,
    /// The ring program; bound to the public `ring_program_id` and to each
    /// non-dummy UTXO's ring field by the circuit. Every input/output UTXO must
    /// already carry this `ring_program_id`.
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

impl PreparedRingAuthority {
    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }
}
