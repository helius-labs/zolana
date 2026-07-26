use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    P256Pubkey, PublicKey, ViewingKey,
};

use super::{single_utxo, validate_owner, validate_zone, DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_blinding, resolve_zone_program_id, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SOL_MINT,
};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    #[wincode(with = "P256PubkeySchema")]
    pub sender_pubkey: P256Pubkey,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub data: Data,
}

impl AnonymousTransferRecipientPlaintext {
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
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Utxo, TransactionError> {
        Ok(Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: resolve_zone_program_id(zone_program_id, &self.data)?,
            data: self.data,
        })
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferSenderPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub spl_asset_id: u64,
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding_seed: [u8; BLINDING_LEN],
    #[wincode(with = "containers::Vec<P256PubkeySchema, FixIntLen<u8>>")]
    pub recipient_viewing_pks: Vec<P256Pubkey>,
    pub spl_data: Data,
    pub sol_data: Data,
}

impl AnonymousTransferSenderPlaintext {
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

pub struct AnonymousRecipientEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub sender_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct AnonymousRecipient;

impl UtxoSerialization for AnonymousRecipient {
    const SCHEME: EncryptedScheme = EncryptedScheme::AnonymousRecipient;
    type Plaintext = AnonymousTransferRecipientPlaintext;
    type EncodeCx = AnonymousRecipientEncode;

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
        AnonymousTransferRecipientPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Ok(vec![plaintext.into_utxo(cx.assets, cx.zone_program_id)?])
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = single_utxo(utxos)?;
        validate_owner(first, owner.owner, 0)?;
        validate_zone(first, owner.zone_program_id, 0)?;
        Ok(AnonymousTransferRecipientPlaintext {
            owner_pubkey: first.owner,
            sender_pubkey: cx.sender_pubkey,
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

pub struct AnonymousSenderEncode {
    pub tx: ViewingKey,
    pub self_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub recipient_viewing_pks: Vec<P256Pubkey>,
}

pub struct AnonymousSenderBundle;

impl UtxoSerialization for AnonymousSenderBundle {
    const SCHEME: EncryptedScheme = EncryptedScheme::AnonymousSender;
    type Plaintext = AnonymousTransferSenderPlaintext;
    type EncodeCx = AnonymousSenderEncode;

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
        AnonymousTransferSenderPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        plaintext.into_utxos(cx.assets, cx.zone_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        if utxos.is_empty() {
            return Err(TransactionError::MissingOutput);
        }
        let owner_pubkey = owner.owner;
        let mut spl_asset_id = 0u64;
        let mut spl_amount = 0u64;
        let mut spl_data = Data::default();
        let mut sol_amount = 0u64;
        let mut sol_data = Data::default();
        let mut spl_seen = false;
        let mut sol_seen = false;
        for (index, utxo) in utxos.iter().enumerate() {
            validate_owner(utxo, owner.owner, index)?;
            validate_zone(utxo, owner.zone_program_id, index)?;
            if utxo.asset == SOL_MINT {
                if sol_seen || utxo.blinding != derive_blinding(&cx.blinding_seed, 1) {
                    return Err(TransactionError::InvalidOutputPosition { position: 1 });
                }
                sol_seen = true;
                sol_amount = utxo.amount;
                sol_data = utxo.data.clone();
            } else {
                if spl_seen || utxo.blinding != derive_blinding(&cx.blinding_seed, 0) {
                    return Err(TransactionError::InvalidOutputPosition { position: 0 });
                }
                spl_seen = true;
                spl_asset_id = owner.assets.asset_id(&utxo.asset)?;
                spl_amount = utxo.amount;
                spl_data = utxo.data.clone();
            }
        }
        Ok(AnonymousTransferSenderPlaintext {
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

#[cfg(test)]
mod tests {
    use zolana_keypair::{constants::BLINDING_LEN, PublicKey, ViewingKey};

    use super::*;
    use crate::{data::DataRecord, SOL_ASSET_ID};

    fn plaintext(data: Data) -> AnonymousTransferRecipientPlaintext {
        AnonymousTransferRecipientPlaintext {
            owner_pubkey: PublicKey::zeroed(),
            sender_pubkey: ViewingKey::new().pubkey(),
            asset_id: SOL_ASSET_ID,
            amount: 7,
            blinding: [3u8; BLINDING_LEN],
            data,
        }
    }

    #[test]
    fn memo_only_recipient_is_accepted() {
        let assets = AssetRegistry::default();
        let utxo = plaintext(Data::new(vec![DataRecord::Memo(b"hello".to_vec())]))
            .into_utxo(&assets, None)
            .unwrap();
        assert_eq!(utxo.data.memo(), Some(b"hello".as_slice()));
    }

    #[test]
    fn zone_and_utxo_data_recipient_are_preserved() {
        let assets = AssetRegistry::default();
        let utxo_data = plaintext(Data::new(vec![DataRecord::UtxoData(vec![1])]))
            .into_utxo(&assets, None)
            .unwrap();
        assert_eq!(utxo_data.data.utxo_data(), Some([1].as_slice()));

        let zone = Address::new_from_array([9u8; 32]);
        let zone_data = plaintext(Data::new(vec![DataRecord::ZoneData(vec![2])]))
            .into_utxo(&assets, Some(zone))
            .unwrap();
        assert_eq!(zone_data.zone_program_id, Some(zone));
        assert_eq!(zone_data.data.zone_data(), Some([2].as_slice()));
    }
}
