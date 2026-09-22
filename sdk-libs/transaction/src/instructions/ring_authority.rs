use solana_address::Address;

use crate::{
    error::TransactionError,
    instructions::transact::{shape::Shape, PublicTransfers},
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding, SppProofInputUtxo},
    ExternalData, SppProofOutputUtxo,
};

pub struct RingAuthorityProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub public_transfers: PublicTransfers,
    pub external_data: ExternalData,
    pub payer: Address,
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

impl RingAuthorityProofInputs {
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier())
    }

    pub fn output_blinding_seed(&self) -> Result<[u8; 32], TransactionError> {
        derive_output_blinding_seed(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn input_utxo_hashes(&self) -> Vec<&SppProofInputUtxo> {
        self.input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .collect()
    }
}
