use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::{NullifierKey, PublicKey};

use super::{owner_utxo_hash, program_id_proof_input_hash, Blinding, UTXO_DOMAIN};
use crate::{
    data::Data, error::TransactionError, serialization::confidential::ConfidentialOutputPlaintext,
    Mint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub owner: PublicKey,
    /// The resolved mint. Commitments use its address; payloads use its ID.
    pub asset: Mint,
    pub amount: u64,
    pub blinding: Blinding,
    pub ring_program_id: Option<Address>,
    pub data: Data,
}

pub(crate) fn resolve_ring_program_id(
    ring_program_id: Option<Address>,
    data: &Data,
) -> Result<Option<Address>, TransactionError> {
    if data.ring_data().is_none() {
        return Ok(None);
    }
    if ring_program_id.is_none() {
        return Err(TransactionError::MissingRingProgramId);
    }
    Ok(ring_program_id)
}

impl Utxo {
    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        ring_data_hash: &[u8; 32],
        tree_id: u16,
    ) -> Result<[u8; 32], TransactionError> {
        let owner_hash = zolana_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        let asset = hash_bytes(self.asset.asset.as_array())?;
        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let ring_hash = Poseidon::hashv(&[ring_data_hash, &ring_program_id])?;
        let owner_utxo_hash = owner_utxo_hash(&owner_hash, &self.blinding)?;
        Ok(Poseidon::hashv(&[
            &right_align(&UTXO_DOMAIN.to_be_bytes()),
            &tree_id_field(tree_id),
            &asset,
            &right_align(&self.amount.to_be_bytes()),
            data_hash,
            &ring_hash,
            &owner_utxo_hash,
        ])?)
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        nullifier_key: &NullifierKey,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(nullifier_key.nullifier(utxo_hash, &self.blinding)?)
    }

    pub fn to_confidential_output_plaintext(&self) -> ConfidentialOutputPlaintext {
        ConfidentialOutputPlaintext {
            asset_id: self.asset.asset_id,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data.clone(),
        }
    }
}
