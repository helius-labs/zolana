use solana_address::Address;
use zolana_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use zolana_keypair::hash::{poseidon, sha256};

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
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn check_shape(&self) -> Result<Shape, TransactionError> {
        let n_in = self.input_utxos.len();
        let n_out = self.output_utxos.len();
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == n_in && shape.n_outputs() == n_out)
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })?;
        self.check_dummies_last()?;
        Ok(shape)
    }

    fn check_dummies_last(&self) -> Result<(), TransactionError> {
        if let Some(index) =
            real_slot_after_dummy(self.input_utxos.iter().map(SppProofInputUtxo::is_dummy))
        {
            return Err(TransactionError::RealInputAfterDummy { index });
        }
        if let Some(index) =
            real_slot_after_dummy(self.output_utxos.iter().map(SppProofOutputUtxo::is_dummy))
        {
            return Err(TransactionError::RealOutputAfterDummy { index });
        }
        Ok(())
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        self.check_dummies_last()?;
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

        let external_data_hash = cache_bound_external_data_hash(
            &self.external_data,
            &cache_write_slots(&self.output_utxos, self.cache_accounts.write)?,
            self.cache_accounts.write,
        )?;
        let private_tx =
            PrivateTxHash::new(&input_hashes, &output_hashes, &self.private_tx_blinding()?)
                .hash()?;
        Ok(transact_message_hash(&private_tx, &external_data_hash))
    }
}

fn real_slot_after_dummy(mut dummies: impl Iterator<Item = bool>) -> Option<usize> {
    let mut padded = false;
    dummies.position(|dummy| {
        padded |= dummy;
        padded && !dummy
    })
}

pub fn transact_message_hash(
    private_tx_hash: &[u8; 32],
    external_data_hash: &[u8; 32],
) -> [u8; 32] {
    sha256(&[private_tx_hash.as_slice(), external_data_hash.as_slice()].concat())
}

pub struct PrivateTxHash<'a> {
    pub input_hashes: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    /// The public nullifier of each address slot, which is the compressed
    /// address SPP inserts. `None` is a transaction that creates no address.
    pub address_nullifiers: Option<&'a [[u8; 32]]>,
    /// Final preimage element. It is never published: every other element is
    /// public or computable, so an observer who knew it could test candidate
    /// input UTXO hashes against the published transaction hash.
    pub blinding: &'a [u8; 32],
}

impl<'a> PrivateTxHash<'a> {
    pub fn new(
        input_hashes: &'a [[u8; 32]],
        output_hashes: &'a [[u8; 32]],
        blinding: &'a [u8; 32],
    ) -> Self {
        Self {
            input_hashes,
            output_hashes,
            address_nullifiers: None,
            blinding,
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_chain = create_nonzero_hash_chain_from_slice(self.input_hashes)?;
        let output_chain = create_nonzero_hash_chain_from_slice(self.output_hashes)?;
        let address_chain =
            create_nonzero_hash_chain_from_slice(self.address_nullifiers.unwrap_or_default())?;
        Ok(poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            self.blinding,
        ])?)
    }
}
