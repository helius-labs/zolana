use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, PublicKey, ViewingKey};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{resolve_ring_program_id, Blinding, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SPLIT,
};

pub struct SplitEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitBundlePlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub num_outputs: u8,
    pub asset_id: u64,
    pub asset_amount: u64,
    /// Final protocol-derived blindings for all eight physical output slots.
    /// The private derivation seed is never disclosed to the recipient.
    pub output_blindings: [Blinding; 8],
    pub data: Data,
}

impl SplitBundlePlaintext {
    pub fn output_blindings(&self) -> Result<Vec<Blinding>, TransactionError> {
        let count = usize::from(self.num_outputs);
        if count > self.output_blindings.len() {
            return Err(TransactionError::SplitInvalidPartCount {
                num_outputs: self.num_outputs,
            });
        }
        Ok(self.output_blindings[..count].to_vec())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if usize::from(parsed.num_outputs) > parsed.output_blindings.len() {
            return Err(TransactionError::SplitInvalidPartCount {
                num_outputs: parsed.num_outputs,
            });
        }
        parsed.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxos(
        self,
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        if usize::from(self.num_outputs) > self.output_blindings.len() {
            return Err(TransactionError::SplitInvalidPartCount {
                num_outputs: self.num_outputs,
            });
        }
        if self.num_outputs == 0 && !self.data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let ring_program_id = resolve_ring_program_id(ring_program_id, &self.data)?;
        let asset = assets.resolve(self.asset_id)?;
        Ok(self.output_blindings[..usize::from(self.num_outputs)]
            .iter()
            .map(|blinding| Utxo {
                owner: self.owner_pubkey,
                asset,
                amount: self.asset_amount,
                blinding: *blinding,
                ring_program_id,
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
        plaintext.into_utxos(cx.assets, cx.ring_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        _cx: &SplitEncode,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        if utxos.len() > 8 {
            return Err(TransactionError::TooManyOutputs);
        }
        let num_outputs =
            u8::try_from(utxos.len()).map_err(|_| TransactionError::TooManyOutputs)?;
        Ok(SplitBundlePlaintext {
            owner_pubkey: first.owner,
            num_outputs,
            asset_id: owner.assets.asset_id(&first.asset)?,
            asset_amount: first.amount,
            output_blindings: core::array::from_fn(|index| {
                utxos
                    .get(index)
                    .map(|utxo| utxo.blinding)
                    .unwrap_or_default()
            }),
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
