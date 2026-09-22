use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_keypair::hash::{poseidon, sha256};

use super::{
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    validate_input_tree_order, ExternalData, SppProofOutputUtxo,
};
use crate::{
    error::TransactionError,
    utxo::{derive_private_tx_blinding, SppProofInputUtxo},
};

#[derive(Clone)]
pub struct SppProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub payer: Address,
}

impl SppProofInputs {
    #[must_use]
    pub fn with_output_tree_id(mut self, output_tree_id: u16) -> Self {
        self.output_tree_id = output_tree_id;
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
}

pub struct PrivateTxHash<'a> {
    pub input_hashes: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    /// One entry per input slot: the public nullifier of each address slot,
    /// which is the compressed address SPP inserts, and `0` for real spends
    /// and padding. `None` is a chain of zeros, a transaction that creates no
    /// address.
    pub address_nullifiers: Option<&'a [[u8; 32]]>,
    pub external_data_hash: &'a [u8; 32],
    /// Final preimage element. It is never published: every other element is
    /// public or computable, so an observer who knew it could test candidate
    /// input UTXO hashes against the published transaction hash.
    pub blinding: &'a [u8; 32],
}

impl<'a> PrivateTxHash<'a> {
    pub fn new(
        input_hashes: &'a [[u8; 32]],
        output_hashes: &'a [[u8; 32]],
        external_data_hash: &'a [u8; 32],
        blinding: &'a [u8; 32],
    ) -> Self {
        Self {
            input_hashes,
            output_hashes,
            address_nullifiers: None,
            external_data_hash,
            blinding,
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_chain = create_hash_chain_4_from_slice(self.input_hashes)?;
        let output_chain = create_hash_chain_4_from_slice(self.output_hashes)?;
        let address_chain = match self.address_nullifiers {
            Some(address_nullifiers) => create_hash_chain_4_from_slice(address_nullifiers)?,
            None => create_hash_chain_4_from_slice(&vec![[0u8; 32]; self.input_hashes.len()])?,
        };
        Ok(poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            self.external_data_hash,
            self.blinding,
        ])?)
    }
}
