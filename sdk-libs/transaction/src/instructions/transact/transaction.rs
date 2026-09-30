use solana_address::Address;
pub use zolana_instruction::PrivateTxHash;
use zolana_keypair::hash::sha256;

use super::{
    cache::{cache_bound_external_data_hash, cache_write_slots},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    ExternalData, SppProofOutputUtxo,
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
        private_tx_blinding(&self.input_utxos, &self.blinding_seed)
    }

    pub fn check_shape(&self) -> Result<Shape, TransactionError> {
        let n_in = self.input_utxos.len();
        let n_out = self.output_utxos.len();
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == n_in && shape.n_outputs() == n_out)
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })?;
        check_dummies_last(&self.input_utxos, &self.output_utxos)?;
        Ok(shape)
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        let private_tx = self.padding_independent_private_tx_hash()?;
        let external_data_hash = cache_bound_external_data_hash(
            &self.external_data,
            &cache_write_slots(&self.output_utxos, self.cache_accounts.write)?,
            self.cache_accounts.write,
        )?;
        Ok(transact_message_hash(&private_tx, &external_data_hash))
    }

    pub fn padding_independent_private_tx_hash(&self) -> Result<[u8; 32], TransactionError> {
        padding_independent_private_tx_hash(
            &self.input_utxos,
            &self.output_utxos,
            self.output_tree_id,
            &self.blinding_seed,
        )
    }
}

pub fn transact_message_hash(
    private_tx_hash: &[u8; 32],
    external_data_hash: &[u8; 32],
) -> [u8; 32] {
    sha256(&[private_tx_hash.as_slice(), external_data_hash.as_slice()].concat())
}

pub(super) fn check_dummies_last(
    input_utxos: &[SppProofInputUtxo],
    output_utxos: &[SppProofOutputUtxo],
) -> Result<(), TransactionError> {
    if let Some(index) = real_slot_after_dummy(input_utxos.iter().map(SppProofInputUtxo::is_dummy))
    {
        return Err(TransactionError::RealInputAfterDummy { index });
    }
    if let Some(index) =
        real_slot_after_dummy(output_utxos.iter().map(SppProofOutputUtxo::is_dummy))
    {
        return Err(TransactionError::RealOutputAfterDummy { index });
    }
    Ok(())
}

fn real_slot_after_dummy(mut dummies: impl Iterator<Item = bool>) -> Option<usize> {
    let mut padded = false;
    dummies.position(|dummy| {
        padded |= dummy;
        padded && !dummy
    })
}

pub(super) fn private_tx_blinding(
    input_utxos: &[SppProofInputUtxo],
    blinding_seed: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let first_nullifier = input_utxos
        .first()
        .ok_or(TransactionError::NoInputs)?
        .nullifier();
    derive_private_tx_blinding(&first_nullifier, blinding_seed)
}

pub(super) fn padding_independent_private_tx_hash(
    input_utxos: &[SppProofInputUtxo],
    output_utxos: &[SppProofOutputUtxo],
    output_tree_id: u16,
    blinding_seed: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    check_dummies_last(input_utxos, output_utxos)?;
    Ok(PrivateTxHash::new(
        &input_hashes(input_utxos),
        &output_hashes(output_utxos, output_tree_id)?,
        &private_tx_blinding(input_utxos, blinding_seed)?,
    )
    .hash()?)
}

fn input_hashes(input_utxos: &[SppProofInputUtxo]) -> Vec<[u8; 32]> {
    input_utxos
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

pub(super) fn output_hashes(
    output_utxos: &[SppProofOutputUtxo],
    output_tree_id: u16,
) -> Result<Vec<[u8; 32]>, TransactionError> {
    output_utxos
        .iter()
        .map(|output| {
            if output.is_dummy() {
                Ok([0u8; 32])
            } else {
                output.hash(output_tree_id)
            }
        })
        .collect()
}
