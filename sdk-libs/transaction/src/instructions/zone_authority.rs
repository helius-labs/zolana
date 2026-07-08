//! Zone-authority state transition (`zone_authority_transact`): an unsigned
//! transact over zone-owned UTXOs. The zone authority is authorized on-chain (the
//! `zone_config` PDA signs), so unlike [`SignedTransaction`](super::transact::SignedTransaction)
//! there is no owner signature. Mirrors the merge prepared form: it carries the
//! padded inputs (real first, dummies at the tail) and yields the input
//! commitments to fetch Merkle proofs for.

use solana_address::Address;

use crate::{
    error::TransactionError,
    instructions::{
        transact::{builder::Shape, signed_transaction::PublicAmounts},
        types::{InputUtxoContext, SpendUtxo},
    },
    ExternalData, OutputUtxo,
};

/// A prepared, unsigned zone-authority transact. `external_data`'s
/// `instruction_discriminator` must be `ZONE_AUTHORITY_TRANSACT` (Tag 3) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedZoneAuthority {
    pub inputs: Vec<SpendUtxo>,
    pub outputs: Vec<OutputUtxo>,
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
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(
                    &nullifier_pubkey,
                    &spend.data_hash.unwrap_or([0u8; 32]),
                    &spend.zone_data_hash.unwrap_or([0u8; 32]),
                )?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                Ok(InputUtxoContext {
                    index,
                    utxo_hash,
                    nullifier,
                })
            })
            .collect()
    }
}
