//! Zone-authority state transition (`zone_authority_transact`): an unsigned
//! transact over zone-owned UTXOs. The zone authority is authorized on-chain (the
//! `zone_config` PDA signs), so unlike [`SppProofInputs`](super::transact::SppProofInputs)
//! there is no owner signature. Mirrors the merge prepared form: it carries the
//! padded inputs (real first, dummies at the tail) and yields the input
//! commitments to fetch Merkle proofs for.

use solana_address::Address;

use crate::{
    error::TransactionError,
    instructions::{
        transact::{shape::Shape, spp_proof_inputs::PublicAmounts},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    ExternalData, SppProofOutputUtxo,
};

/// A prepared, unsigned zone-authority transact. `external_data`'s
/// `instruction_discriminator` must be `ZONE_AUTHORITY_TRANSACT` (Tag 3) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedZoneAuthority {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub public_amounts: PublicAmounts,
    pub external_data: ExternalData,
    pub payer_pubkey_hash: [u8; 32],
    /// The zone program; bound to the public `zone_program_id` and to each
    /// non-dummy UTXO's zone field by the circuit. Every input/output UTXO must
    /// already carry this `zone_program_id`.
    pub zone_program_id: Option<Address>,
    pub shape: Shape,
}

impl PreparedZoneAuthority {
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
