//! The `private_tx_hash` an SPP transact proof shares as a public input with
//! any co-proof over the same transaction, and that a program building its own
//! transact CPI recomputes.

use zolana_hasher::{
    hash_chain::create_nonzero_hash_chain_from_slice, Hasher, HasherError, Poseidon,
};

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

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let input_chain = create_nonzero_hash_chain_from_slice(self.input_hashes)?;
        let output_chain = create_nonzero_hash_chain_from_slice(self.output_hashes)?;
        let address_chain =
            create_nonzero_hash_chain_from_slice(self.address_nullifiers.unwrap_or_default())?;
        Poseidon::hashv(&[&input_chain, &output_chain, &address_chain, self.blinding])
    }
}
