use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    P256Pubkey, PublicKey, ViewingKey,
};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_blinding, resolve_zone_program_id, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SPLIT,
};

pub struct SplitEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
    pub blinding_seed: [u8; BLINDING_LEN],
}

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
                program_id: None,
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

pub struct Split;

impl UtxoSerialization for Split {
    const SCHEME: EncryptedScheme = EncryptedScheme::Split;
    type Plaintext = SplitBundlePlaintext;
    type EncodeCx = SplitEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        Ok(cx
            .viewing_key
            .decrypt_utxo(body, &tx_viewing_pk, salt, cx.slot_index)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        SplitBundlePlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        plaintext.into_utxos(cx.assets, cx.zone_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &SplitEncode,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        let num_outputs =
            u8::try_from(utxos.len()).map_err(|_| TransactionError::TooManyOutputs)?;
        Ok(SplitBundlePlaintext {
            owner_pubkey: first.owner,
            num_outputs,
            asset_id: owner.assets.asset_id(&first.asset)?,
            asset_amount: first.amount,
            blinding_seed: cx.blinding_seed,
            data: first.data.clone(),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &SplitEncode) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.recipient_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}
