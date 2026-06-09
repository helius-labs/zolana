use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
use zolana_keypair::hash::sha256_be;
use zolana_keypair::{P256Pubkey, PublicKey};

use crate::asset::AssetRegistry;
use crate::data::Data;
use crate::error::TransactionError;
use crate::utxo::Utxo;
use crate::SPLIT;

pub fn split_blinding(seed: &[u8; BLINDING_LEN], i: u8) -> [u8; BLINDING_LEN] {
    let mut preimage = [0u8; BLINDING_LEN + 1];
    preimage[..BLINDING_LEN].copy_from_slice(seed);
    preimage[BLINDING_LEN] = i;
    let digest = sha256_be(&preimage);
    let mut out = [0u8; BLINDING_LEN];
    out.copy_from_slice(&digest[1..]);
    out
}

wincode::pod_wrapper! {
    unsafe struct PodP256Pubkey(P256Pubkey);
    unsafe struct PodPublicKey(PublicKey);
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitBundlePlaintext {
    #[wincode(with = "PodPublicKey")]
    pub owner_pubkey: PublicKey,
    pub num_outputs: u8,
    pub asset_id: u64,
    pub asset_amount: u64,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub data: Data,
}

impl SplitBundlePlaintext {
    pub fn output_blindings(&self) -> Vec<[u8; BLINDING_LEN]> {
        (0..self.num_outputs)
            .map(|i| split_blinding(&self.blinding_seed, i))
            .collect()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }

    pub fn into_utxos(self, assets: &AssetRegistry) -> Result<Vec<Utxo>, TransactionError> {
        let asset = assets.resolve(self.asset_id)?;
        Ok((0..self.num_outputs)
            .map(|i| Utxo {
                owner: self.owner_pubkey,
                asset,
                amount: self.asset_amount,
                blinding: split_blinding(&self.blinding_seed, i),
                zone_program_id: None,
                data: self.data.clone(),
            })
            .collect())
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitEncryptedUtxos {
    pub type_prefix: u8,
    #[wincode(with = "PodP256Pubkey")]
    pub tx_viewing_pk: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ciphertext: Vec<u8>,
}

impl SplitEncryptedUtxos {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if parsed.type_prefix != SPLIT {
            return Err(TransactionError::BadDiscriminator(parsed.type_prefix));
        }
        Ok(parsed)
    }
}
