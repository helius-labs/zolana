use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    P256Pubkey, PublicKey,
};

use crate::{
    asset::AssetRegistry,
    data::Data,
    error::TransactionError,
    utxo::{derive_blinding, resolve_zone_program_id, Utxo},
    P256PubkeySchema, PublicKeySchema, SPLIT,
};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitBundlePlaintext {
    #[wincode(with = "PublicKeySchema")]
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
            .map(|i| derive_blinding(&self.blinding_seed, i))
            .collect()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxos(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        if self.num_outputs == 0 && !self.data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let zone_program_id = resolve_zone_program_id(zone_program_id, &self.data)?;
        let asset = assets.resolve(self.asset_id)?;
        Ok((0..self.num_outputs)
            .map(|i| Utxo {
                owner: self.owner_pubkey,
                asset,
                amount: self.asset_amount,
                blinding: derive_blinding(&self.blinding_seed, i),
                zone_program_id,
                data: self.data.clone(),
            })
            .collect())
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitEncryptedUtxos {
    pub type_prefix: u8,
    #[wincode(with = "P256PubkeySchema")]
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
