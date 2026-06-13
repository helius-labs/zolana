use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_address::Address;
pub use zolana_interface::UTXO_DOMAIN;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::hash::sha256_be;
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

pub fn derive_blinding(seed: &[u8; BLINDING_LEN], position: u8) -> Blinding {
    let mut preimage = [0u8; BLINDING_LEN + 1];
    preimage[..BLINDING_LEN].copy_from_slice(seed);
    preimage[BLINDING_LEN] = position;
    let digest = sha256_be(&preimage);
    let mut out = [0u8; BLINDING_LEN];
    out.copy_from_slice(&digest[1..]);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub owner: PublicKey,
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub data: Data,
}

fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 32) }
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(bytes);
    out
}

pub(crate) fn resolve_zone_program_id(
    zone_program_id: Option<Address>,
    data: &Data,
) -> Result<Option<Address>, TransactionError> {
    if data.zone_data().is_none() {
        return Ok(None);
    }
    if zone_program_id.is_none() {
        return Err(TransactionError::MissingZoneProgramId);
    }
    Ok(zone_program_id)
}

fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    zolana_keypair::hash::hash_field(asset.as_array()).map_err(TransactionError::from)
}

fn zone_program_id_field(zone_program_id: &Option<Address>) -> Result<[u8; 32], TransactionError> {
    match zone_program_id {
        Some(id) => zolana_keypair::hash::hash_field(id.as_array()).map_err(TransactionError::from),
        None => Ok([0u8; 32]),
    }
}

pub fn owner_utxo_hash(
    owner: &PublicKey,
    nullifier_pk: &[u8; 32],
    blinding: &Blinding,
) -> Result<[u8; 32], TransactionError> {
    let owner_hash = zolana_keypair::hash::owner_hash(owner, nullifier_pk)?;
    let blinding = right_align(blinding);
    poseidon(&[&owner_hash, &blinding])
}

impl Utxo {
    pub fn owner_utxo_hash(&self, nullifier_pk: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        owner_utxo_hash(&self.owner, nullifier_pk, &self.blinding)
    }

    pub fn commitment_from_owner_utxo_hash(
        asset: Address,
        amount: u64,
        program_data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
        zone_program_id: Option<Address>,
        owner_utxo_hash: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        let domain = right_align(&u64::from(UTXO_DOMAIN).to_be_bytes());
        let asset = asset_field(&asset)?;
        let amount = right_align(&amount.to_be_bytes());
        let zone_program_id = zone_program_id_field(&zone_program_id)?;
        poseidon(&[
            &domain,
            &asset,
            &amount,
            program_data_hash,
            zone_data_hash,
            &zone_program_id,
            owner_utxo_hash,
        ])
    }

    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        program_data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        let owner_utxo_hash = self.owner_utxo_hash(nullifier_pk)?;
        Self::commitment_from_owner_utxo_hash(
            self.asset,
            self.amount,
            program_data_hash,
            zone_data_hash,
            self.zone_program_id,
            &owner_utxo_hash,
        )
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
