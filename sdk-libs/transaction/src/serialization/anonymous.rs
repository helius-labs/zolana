use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, PublicKey, ViewingKey};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_transact_output_blinding, resolve_ring_program_id, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SOL_MINT,
};

/// Physical output slots the sender bundle describes.
const SPL_CHANGE_SLOT: u32 = 0;
const SOL_CHANGE_SLOT: u32 = 1;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    #[wincode(with = "P256PubkeySchema")]
    pub sender_pubkey: P256Pubkey,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 32],
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
        ring_program_id: Option<Address>,
    ) -> Result<Utxo, TransactionError> {
        // Anonymous recipients may carry a memo, but not ring or utxo data.
        if self.data.ring_data().is_some() || self.data.utxo_data().is_some() {
            return Err(TransactionError::UnsupportedOutputData);
        }
        Ok(Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: resolve_ring_program_id(ring_program_id, &self.data)?,
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
    pub blinding_seed: [u8; 32],
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

    /// The bundle names the two sender change slots positionally and cannot say
    /// that one of them was dropped, so a slot's logical position is also its
    /// physical output index. `first_nullifier` is the transaction's; it is what
    /// makes each derived blinding unique to that transaction.
    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
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
                blinding: derive_transact_output_blinding(
                    first_nullifier,
                    &self.blinding_seed,
                    SPL_CHANGE_SLOT,
                )?,
                ring_program_id: resolve_ring_program_id(ring_program_id, &self.spl_data)?,
                data: self.spl_data,
            });
        }
        if self.sol_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: SOL_MINT,
                amount: self.sol_amount,
                blinding: derive_transact_output_blinding(
                    first_nullifier,
                    &self.blinding_seed,
                    SOL_CHANGE_SLOT,
                )?,
                ring_program_id: resolve_ring_program_id(ring_program_id, &self.sol_data)?,
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
        Ok(vec![plaintext.into_utxo(cx.assets, cx.ring_program_id)?])
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
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
    pub blinding_seed: [u8; 32],
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
        let first_nullifier = cx
            .first_nullifier
            .ok_or(TransactionError::MissingFirstNullifier)?;
        plaintext.into_utxos(&first_nullifier, cx.assets, cx.ring_program_id)
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
    use zolana_keypair::{PublicKey, ViewingKey};

    use super::*;
    use crate::{data::DataRecord, SOL_ASSET_ID};

    fn plaintext(data: Data) -> AnonymousTransferRecipientPlaintext {
        AnonymousTransferRecipientPlaintext {
            owner_pubkey: PublicKey::zeroed(),
            sender_pubkey: ViewingKey::new().pubkey(),
            asset_id: SOL_ASSET_ID,
            amount: 7,
            blinding: [3u8; 32],
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

    fn sender_plaintext() -> AnonymousTransferSenderPlaintext {
        AnonymousTransferSenderPlaintext {
            owner_pubkey: PublicKey::zeroed(),
            spl_asset_id: 0,
            spl_amount: 0,
            sol_amount: 9,
            blinding_seed: [5u8; 32],
            recipient_viewing_pks: Vec::new(),
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    }

    /// Decoding cannot derive a blinding without the transaction's first
    /// nullifier, so a context that omits it is refused rather than falling back
    /// to a value the circuit would never have accepted.
    #[test]
    fn sender_bundle_without_first_nullifier_is_rejected() {
        let assets = AssetRegistry::default();
        let owner_cx = OwnerCx {
            owner: PublicKey::zeroed(),
            assets: &assets,
            ring_program_id: None,
            first_nullifier: None,
        };
        assert_eq!(
            AnonymousSenderBundle::into_utxos(sender_plaintext(), &owner_cx).unwrap_err(),
            TransactionError::MissingFirstNullifier
        );
    }

    /// Each change slot takes the blinding the circuit recomputes for its
    /// physical output index.
    #[test]
    fn sender_change_takes_the_derived_blinding() {
        let assets = AssetRegistry::default();
        let first_nullifier = [7u8; 32];
        let utxos = sender_plaintext()
            .into_utxos(&first_nullifier, &assets, None)
            .unwrap();
        let expected = vec![Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 9,
            blinding: derive_transact_output_blinding(
                &first_nullifier,
                &[5u8; 32],
                SOL_CHANGE_SLOT,
            )
            .unwrap(),
            ring_program_id: None,
            data: Data::default(),
        }];
        assert_eq!(utxos, expected, "decoded sender change");
    }

    #[test]
    fn ring_or_utxo_data_recipient_is_rejected() {
        let assets = AssetRegistry::default();
        for data in [
            Data::new(vec![DataRecord::UtxoData(vec![1])]),
            Data::new(vec![DataRecord::RingData(vec![1])]),
        ] {
            assert_eq!(
                plaintext(data).into_utxo(&assets, None).unwrap_err(),
                TransactionError::UnsupportedOutputData
            );
        }
    }
}
