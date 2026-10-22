//! Scheme 11, a packed custom ring slot, its ring id read from the transaction.

use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::{constants::SALT_LEN, x25519::X25519_PUBKEY_LEN, ViewingKey};

use super::{
    confidential::{Confidential, ConfidentialEncode},
    DecodeCx, OwnerCx, UtxoSerialization,
};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{SppProofOutputUtxo, Utxo},
    EncryptedScheme,
};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct RingPackedPlaintext {
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data: Data,
}

impl RingPackedPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }
}

impl From<&SppProofOutputUtxo> for RingPackedPlaintext {
    fn from(output: &SppProofOutputUtxo) -> Self {
        Self {
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            data: output.data.clone(),
        }
    }
}

/// The scheme 3 key schedule and body, `recipient_pk || ciphertext`.
pub struct RingPacked;

impl RingPacked {
    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<RingPackedPlaintext, TransactionError> {
        let recipient_pubkey = Confidential::embedded_viewing_pk(body)?;
        let ciphertext = body
            .get(X25519_PUBKEY_LEN..)
            .ok_or(TransactionError::InvalidLength {
                expected: X25519_PUBKEY_LEN,
                actual: body.len(),
            })?;
        let bytes = tx.decrypt_slot_ephemeral(&recipient_pubkey, ciphertext, salt, slot_index)?;
        RingPackedPlaintext::deserialize(&bytes)
    }
}

impl UtxoSerialization for RingPacked {
    const SCHEME: EncryptedScheme = EncryptedScheme::RingConfidentialPacked;
    type Plaintext = RingPackedPlaintext;
    type EncodeCx = ConfidentialEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        Confidential::decrypt(body, cx)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        RingPackedPlaintext::deserialize(bytes)
    }

    /// A note outside any ring never takes scheme 11.
    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        let ring_program_id = cx
            .ring_program_id
            .ok_or(TransactionError::MissingRingProgramId)?;
        Ok(vec![Utxo {
            owner: cx.owner,
            asset: cx.assets.resolve(plaintext.asset_id)?,
            amount: plaintext.amount,
            blinding: plaintext.blinding,
            ring_program_id: Some(ring_program_id),
            data: plaintext.data,
        }])
    }

    fn from_utxos(
        utxos: &[Utxo],
        _: &OwnerCx,
        _: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        if first.ring_program_id.is_none() {
            return Err(TransactionError::MissingRingProgramId);
        }
        Ok(RingPackedPlaintext {
            asset_id: first.asset.asset_id,
            amount: first.amount,
            blinding: first.blinding,
            data: first.data.clone(),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Confidential::encrypt(bytes, cx)
    }
}
