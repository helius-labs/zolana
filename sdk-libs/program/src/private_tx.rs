//! The `private_tx_hash` an SPP transact proof shares as a public input with
//! any co-proof over the same transaction, and that a program building its own
//! transact CPI recomputes.

use alloc::vec;

use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, Hasher, HasherError, Poseidon};

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

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let input_chain = create_hash_chain_4_from_slice(self.input_hashes)?;
        let output_chain = create_hash_chain_4_from_slice(self.output_hashes)?;
        let address_chain = match self.address_nullifiers {
            Some(address_nullifiers) => create_hash_chain_4_from_slice(address_nullifiers)?,
            None => create_hash_chain_4_from_slice(&vec![[0u8; 32]; self.input_hashes.len()])?,
        };
        Poseidon::hashv(&[
            &input_chain,
            &output_chain,
            &address_chain,
            self.external_data_hash,
            self.blinding,
        ])
    }
}
