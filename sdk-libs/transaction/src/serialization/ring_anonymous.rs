use zolana_event::{MessageData, OutputDataEncoding};
use zolana_keypair::{
    constants::SALT_LEN, x25519::X25519_PUBKEY_LEN, PublicKey, ViewingKey, X25519Pubkey,
};

use super::confidential::{ConfidentialEncode, ConfidentialOutputPlaintext};
use crate::{error::TransactionError, utxo::Utxo, AssetRegistry, EncryptedScheme};

/// The scheme-3 fields followed by the payer pseudonym toward the recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingAnonymousOutputPlaintext {
    pub output: ConfidentialOutputPlaintext,
    pub pair_pk: X25519Pubkey,
}

/// A decrypted scheme-9 note with the counterparty pseudonym the wallet records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingAnonymousOutput {
    pub utxo: Utxo,
    pub pair_pk: X25519Pubkey,
}

impl RingAnonymousOutputPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut bytes = self.output.serialize()?;
        bytes.extend_from_slice(self.pair_pk.as_bytes());
        Ok(bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let (output, pair_pk) = bytes.split_last_chunk::<X25519_PUBKEY_LEN>().ok_or(
            TransactionError::InvalidLength {
                expected: X25519_PUBKEY_LEN,
                actual: bytes.len(),
            },
        )?;
        Ok(Self {
            output: ConfidentialOutputPlaintext::deserialize(output)?,
            pair_pk: X25519Pubkey::from_bytes(*pair_pk)?,
        })
    }

    pub fn into_output(
        self,
        owner: PublicKey,
        assets: &AssetRegistry,
    ) -> Result<RingAnonymousOutput, TransactionError> {
        Ok(RingAnonymousOutput {
            utxo: self.output.into_utxo(owner, assets)?,
            pair_pk: self.pair_pk,
        })
    }
}

pub struct RingAnonymous;

impl RingAnonymous {
    /// Encrypts a ring output without publishing the recipient viewing key.
    /// The ring auditor receives that key through its proved disclosure.
    pub fn encode_plaintext(
        plaintext: &RingAnonymousOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        let bytes = plaintext.serialize()?;
        let ciphertext =
            cx.tx
                .encrypt_slot(&cx.recipient_pubkey, &bytes, cx.salt, cx.slot_index)?;
        let mut body = Vec::with_capacity(1 + ciphertext.len());
        body.push(EncryptedScheme::RingAnonymous.as_byte());
        body.extend_from_slice(&ciphertext);
        let data = borsh::to_vec(&OutputDataEncoding::Encrypted(body))
            .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
        Ok(MessageData { view_tag, data })
    }

    /// The recipient's opening of the body after the scheme byte.
    pub fn decrypt(
        viewing_key: &ViewingKey,
        body: &[u8],
        tx_viewing_pk: &X25519Pubkey,
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<RingAnonymousOutputPlaintext, TransactionError> {
        let bytes = viewing_key.decrypt_utxo(body, tx_viewing_pk, salt, slot_index)?;
        RingAnonymousOutputPlaintext::deserialize(&bytes)
    }

    /// The auditor's opening, `recipient` comes from the proved disclosure.
    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        recipient: &X25519Pubkey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<RingAnonymousOutputPlaintext, TransactionError> {
        let bytes = tx.decrypt_slot_ephemeral(recipient, body, salt, slot_index)?;
        RingAnonymousOutputPlaintext::deserialize(&bytes)
    }
}
