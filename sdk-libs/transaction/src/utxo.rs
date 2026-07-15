use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_address::Address;
pub use zolana_interface::UTXO_DOMAIN;
use zolana_keypair::{constants::BLINDING_LEN, hash::sha256_be, NullifierKey, PublicKey};

use crate::{
    data::Data, error::TransactionError, serialization::confidential::TransferRecipientPlaintext,
    AssetRegistry,
};

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

pub fn zone_program_id_field(
    zone_program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    program_id_field(zone_program_id)
}

pub fn program_id_field(program_id: &Option<Address>) -> Result<[u8; 32], TransactionError> {
    match program_id {
        Some(id) => zolana_keypair::hash::hash_field(id.as_array()).map_err(TransactionError::from),
        None => Ok([0u8; 32]),
    }
}

pub fn owner_utxo_hash(
    owner_hash: &[u8; 32],
    blinding: &Blinding,
) -> Result<[u8; 32], TransactionError> {
    let blinding = right_align(blinding);
    poseidon(&[owner_hash, &blinding])
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProofInputUtxo {
    pub domain: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub zone_data_hash: [u8; 32],
    pub zone_program_id: [u8; 32],
}

impl ProofInputUtxo {
    pub fn new(
        owner_hash: [u8; 32],
        asset: &Address,
        amount: u64,
        blinding: &Blinding,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            owner_hash,
            asset: zolana_keypair::hash::hash_field(asset.as_array())?,
            amount: right_align(&amount.to_be_bytes()),
            blinding: right_align(blinding),
            data_hash: [0u8; 32],
            zone_data_hash: [0u8; 32],
            zone_program_id: [0u8; 32],
        })
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = data_hash;
        self
    }

    pub fn with_zone(
        mut self,
        zone_data_hash: [u8; 32],
        zone_program_id: &Option<Address>,
    ) -> Result<Self, TransactionError> {
        self.zone_data_hash = zone_data_hash;
        self.zone_program_id = program_id_field(zone_program_id)?;
        Ok(self)
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let zone_hash = poseidon(&[&self.zone_data_hash, &self.zone_program_id])?;
        let owner_utxo_hash = poseidon(&[&self.owner_hash, &self.blinding])?;
        poseidon(&[
            &self.domain,
            &self.asset,
            &self.amount,
            &self.data_hash,
            &zone_hash,
            &owner_utxo_hash,
        ])
    }
}

impl Utxo {
    pub fn proof_input(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
    ) -> Result<ProofInputUtxo, TransactionError> {
        let owner_hash = zolana_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        ProofInputUtxo::new(owner_hash, &self.asset, self.amount, &self.blinding)?
            .with_data_hash(*data_hash)
            .with_zone(*zone_data_hash, &self.zone_program_id)
    }

    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        self.proof_input(nullifier_pk, data_hash, zone_data_hash)?
            .hash()
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
        assets: &AssetRegistry,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        Ok(TransferRecipientPlaintext {
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: self.zone_program_id,
            data: self.data.clone(),
        })
    }

    pub fn to_confidential_recipient_plaintext(
        &self,
        assets: &AssetRegistry,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        Ok(TransferRecipientPlaintext {
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: self.zone_program_id,
            data: self.data.clone(),
        })
    }
}
