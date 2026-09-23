use solana_address::Address;
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

    fn signing_external_data_hash(&self) -> Result<[u8; 32], TransactionError> {
        use zolana_interface::{
            state::cache::bind_cache_write,
            verifying_keys::{valid_cache_writes, CacheAccess, CacheWrite},
        };
        let mut writes = CacheAccess::NO_WRITES;
        let selected = self
            .output_utxos
            .iter()
            .enumerate()
            .filter_map(|(index, output)| output.cache_slot.map(|slot| (index, output, slot)));
        for (position, (index, output, slot)) in selected.enumerate() {
            let entry = writes
                .get_mut(position)
                .ok_or(TransactionError::InvalidCacheWrite)?;
            if output.is_dummy() || self.cache_accounts.write.is_none() {
                return Err(TransactionError::InvalidCacheWrite);
            }
            *entry = CacheWrite {
                output: u8::try_from(index).map_err(|_| TransactionError::InvalidCacheWrite)?,
                slot,
            };
        }
        if !valid_cache_writes(&writes, self.output_utxos.len())
            || (self.cache_accounts.write.is_some() && writes == CacheAccess::NO_WRITES)
        {
            return Err(TransactionError::InvalidCacheWrite);
        }
        Ok(bind_cache_write(
            self.external_data.hash()?,
            self.cache_accounts
                .write
                .as_ref()
                .map(|cache| (cache.as_array(), &writes)),
        )?)
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_input_tree_order(self.input_utxos.iter().map(|input| input.tree_id))?;
        let mut input_hashes = Vec::with_capacity(self.input_utxos.len());
        for input_utxo in &self.input_utxos {
            if input_utxo.is_dummy() {
                input_hashes.push([0u8; 32]);
            } else {
                input_hashes.push(input_utxo.hash());
            }
        }

        let mut output_hashes = Vec::with_capacity(self.output_utxos.len());
        for output in &self.output_utxos {
            if output.is_dummy() {
                output_hashes.push([0u8; 32]);
            } else {
                output_hashes.push(output.hash(self.output_tree_id)?);
            }
        }

        let external_data_hash = self.signing_external_data_hash()?;
        let private_tx = PrivateTxHash::new(
            &input_hashes,
            &output_hashes,
            &external_data_hash,
            &self.private_tx_blinding()?,
        )
        .hash()?;
        Ok(sha256(&private_tx))
    }
}
