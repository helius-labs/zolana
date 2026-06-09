use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_address::Address;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey};

use crate::asset::AssetRegistry;
use crate::data::Data;
use crate::error::TransactionError;
use crate::transfer::TransferRecipientPlaintext;

fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], TransactionError> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|e| TransactionError::Poseidon(e.to_string()))?;
    hasher
        .hash_bytes_be(inputs)
        .map_err(|e| TransactionError::Poseidon(e.to_string()))
}

pub type Blinding = [u8; BLINDING_LEN];

pub const UTXO_DOMAIN: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub owner: PublicKey,
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub data: Data,
}

fn right_align(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

fn zone_program_id_field(zone_program_id: &Option<Address>) -> Result<[u8; 32], TransactionError> {
    // TODO: discuss whether we want to hash anything at all in this case or hashing 0s is ok (different pr)
    let id = zone_program_id.unwrap_or_default().to_bytes();
    zolana_keypair::hash::hash_field(&id).map_err(TransactionError::from)
}

impl Utxo {
    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        program_data_hash: &[u8; 32],
        policy_data_hash: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        let domain = right_align(&UTXO_DOMAIN.to_be_bytes());
        let owner_hash = zolana_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        let amount = right_align(&self.amount.to_be_bytes());
        let blinding = right_align(&self.blinding);
        let zone_program_id = zone_program_id_field(&self.zone_program_id)?;
        poseidon(&[
            &domain,
            &owner_hash,
            self.asset.as_array(),
            &amount,
            &blinding,
            program_data_hash,
            policy_data_hash,
            &zone_program_id,
        ])
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        nullifier_key: &NullifierKey,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(nullifier_key.nullifier(utxo_hash, &self.blinding)?)
    }

    pub fn to_recipient_plaintext(
        &self,
        sender_pubkey: P256Pubkey,
        assets: &AssetRegistry,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        Ok(TransferRecipientPlaintext {
            owner_pubkey: self.owner,
            sender_pubkey,
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            data: self.data.clone(),
        })
    }
}
