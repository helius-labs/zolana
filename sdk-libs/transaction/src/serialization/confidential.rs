use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    P256Pubkey, PublicKey, ViewingKey,
};

use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_blinding, resolve_zone_program_id, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SOL_MINT,
};

use super::{DecodeCx, OwnerCx, UtxoSerialization};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferRecipientPlaintext {
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub data: Data,
}

impl TransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxo(
        self,
        owner: PublicKey,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Utxo, TransactionError> {
        if !self.data.is_empty() {
            return Err(TransactionError::UnsupportedOutputData);
        }
        Ok(Utxo {
            owner,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: resolve_zone_program_id(zone_program_id, &self.data)?,
            data: self.data,
        })
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferSenderPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey, // TODO: remove see spec.md
    pub spl_asset_id: u64,
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding_seed: [u8; BLINDING_LEN],
    #[wincode(with = "containers::Vec<P256PubkeySchema, FixIntLen<u8>>")]
    pub recipient_viewing_pks: Vec<P256Pubkey>,
    pub spl_data: Data,
    pub sol_data: Data,
}

impl TransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.spl_data.validate()?;
        self.sol_data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.spl_data.validate()?;
        parsed.sol_data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxos(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        if self.spl_amount == 0 && !self.spl_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        if self.sol_amount == 0 && !self.sol_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let mut utxos = Vec::new();
        if self.spl_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: assets.resolve(self.spl_asset_id)?,
                amount: self.spl_amount,
                blinding: derive_blinding(&self.blinding_seed, 0),
                zone_program_id: resolve_zone_program_id(zone_program_id, &self.spl_data)?,
                data: self.spl_data,
            });
        }
        if self.sol_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: SOL_MINT,
                amount: self.sol_amount,
                blinding: derive_blinding(&self.blinding_seed, 1),
                zone_program_id: resolve_zone_program_id(zone_program_id, &self.sol_data)?,
                data: self.sol_data,
            });
        }
        Ok(utxos)
    }
}

pub struct ConfidentialRecipientEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct ConfidentialRecipient;

impl UtxoSerialization for ConfidentialRecipient {
    const SCHEME: EncryptedScheme = EncryptedScheme::ConfidentialRecipient;
    type Plaintext = TransferRecipientPlaintext;
    type EncodeCx = ConfidentialRecipientEncode;

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
        TransferRecipientPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Ok(vec![plaintext.into_utxo(
            cx.owner,
            cx.assets,
            cx.zone_program_id,
        )?])
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        _cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        Ok(TransferRecipientPlaintext {
            asset_id: owner.assets.asset_id(&first.asset)?,
            amount: first.amount,
            blinding: first.blinding,
            data: first.data.clone(),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.recipient_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}

pub struct ConfidentialSenderEncode {
    pub tx: ViewingKey,
    pub self_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub recipient_viewing_pks: Vec<P256Pubkey>,
}

pub struct ConfidentialSenderBundle;

impl UtxoSerialization for ConfidentialSenderBundle {
    const SCHEME: EncryptedScheme = EncryptedScheme::ConfidentialSender;
    type Plaintext = TransferSenderPlaintext;
    type EncodeCx = ConfidentialSenderEncode;

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
        TransferSenderPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        plaintext.into_utxos(cx.assets, cx.zone_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        let owner_pubkey = first.owner;

        let mut spl_asset_id = 0u64;
        let mut spl_amount = 0u64;
        let mut spl_data = Data::default();
        let mut sol_amount = 0u64;
        let mut sol_data = Data::default();

        for utxo in utxos {
            if utxo.asset == SOL_MINT {
                sol_amount = utxo.amount;
                sol_data = utxo.data.clone();
            } else {
                spl_asset_id = owner.assets.asset_id(&utxo.asset)?;
                spl_amount = utxo.amount;
                spl_data = utxo.data.clone();
            }
        }

        Ok(TransferSenderPlaintext {
            owner_pubkey,
            spl_asset_id,
            spl_amount,
            sol_amount,
            blinding_seed: cx.blinding_seed,
            recipient_viewing_pks: cx.recipient_viewing_pks.clone(),
            spl_data,
            sol_data,
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.self_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}
