use solana_address::Address;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::hash::sha256;
pub use zolana_program::PrivateTxHash;

use super::{
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    validate_input_tree_order, ExternalData, SppProofOutputUtxo,
};
use crate::{
    error::TransactionError,
    utxo::{derive_private_tx_blinding, SppProofInputUtxo},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheAccounts {
    pub read: Option<Address>,
    pub write: Option<Address>,
}

#[derive(Clone)]
pub struct SppProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub payer: Address,
    pub cache_accounts: CacheAccounts,
}

impl SppProofInputs {
    #[must_use]
    pub fn with_output_tree_id(mut self, output_tree_id: u16) -> Self {
        self.output_tree_id = output_tree_id;
        self
    }

    #[must_use]
    pub fn with_read_cache(mut self, cache: Address) -> Self {
        self.cache_accounts.read = Some(cache);
        self
    }

    #[must_use]
    pub fn with_write_cache(mut self, cache: Address) -> Self {
        self.cache_accounts.write = Some(cache);
        self
    }

    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn check_shape(&self) -> Result<Shape, TransactionError> {
        validate_input_tree_order(self.input_utxos.iter().map(|input| input.tree_id))?;
        let n_in = self.input_utxos.len();
        let n_out = self.output_utxos.len();
        SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == n_in && shape.n_outputs() == n_out)
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_input_tree_order(self.input_utxos.iter().map(|input| input.tree_id))?;
        let input_hashes = self.input_hashes();
        let output_hashes = self.output_hashes()?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &input_hashes,
            &output_hashes,
            &external_data_hash,
            &self.private_tx_blinding()?,
        )
        .hash()?;
        Ok(sha256(&private_tx))
    }

    pub fn padding_independent_private_tx_hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_input_tree_order(self.input_utxos.iter().map(|input| input.tree_id))?;
        Ok(Poseidon::hashv(&[
            nonzero_hash_chain(&self.input_hashes())?.as_slice(),
            nonzero_hash_chain(&self.output_hashes()?)?.as_slice(),
            nonzero_hash_chain(&[])?.as_slice(),
            self.private_tx_blinding()?.as_slice(),
        ])?)
    }

    fn input_hashes(&self) -> Vec<[u8; 32]> {
        self.input_utxos
            .iter()
            .map(|input_utxo| {
                if input_utxo.is_dummy() {
                    [0u8; 32]
                } else {
                    input_utxo.hash()
                }
            })
            .collect()
    }

    fn output_hashes(&self) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.output_utxos
            .iter()
            .map(|output| {
                if output.is_dummy() {
                    Ok([0u8; 32])
                } else {
                    output.hash(self.output_tree_id)
                }
            })
            .collect()
    }
}

fn nonzero_hash_chain(values: &[[u8; 32]]) -> Result<[u8; 32], TransactionError> {
    values
        .iter()
        .filter(|value| **value != [0u8; 32])
        .try_fold([0u8; 32], |chain, value| {
            Ok(Poseidon::hashv(&[chain.as_slice(), value.as_slice()])?)
        })
}
