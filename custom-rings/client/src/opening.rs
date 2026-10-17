//! Interpret proved note fields independently of optional recipient ciphertext.

use solana_address::Address;
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::right_align;
use zolana_transaction::{
    utxo::{program_id_proof_input_hash, UTXO_DOMAIN},
    AssetRegistry, Mint, TransactionError,
};

pub(crate) struct NoteOpening<'a> {
    pub fields: &'a ProofInputUtxo,
    pub amount: u64,
}

impl<'a> NoteOpening<'a> {
    /// Dummy slots carry no note. Amount conversion never truncates a field.
    pub fn new(fields: &'a ProofInputUtxo) -> Option<Self> {
        if fields.domain != right_align(&UTXO_DOMAIN.to_be_bytes())
            || fields.amount[..24] != [0; 24]
        {
            return None;
        }
        Some(Self {
            fields,
            amount: u64::from_be_bytes(fields.amount[24..].try_into().ok()?),
        })
    }

    pub fn mint(&self, assets: &AssetRegistry) -> Result<Option<Mint>, TransactionError> {
        assets
            .address_for_field(&self.fields.asset)?
            .map(|address| assets.mint(&address))
            .transpose()
    }

    pub fn belongs_to_ring(&self, ring: Option<Address>) -> Result<bool, TransactionError> {
        Ok(self.fields.ring_program_id == program_id_proof_input_hash(&ring)?)
    }
}
