use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    P256Pubkey, ViewingKey,
};

use super::{confidential::TransferRecipientPlaintext, DecodeCx, OwnerCx, UtxoSerialization};
use crate::{error::TransactionError, utxo::Utxo, EncryptedScheme};

pub struct ConfidentialUnifiedEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct ConfidentialUnified;

fn split_embedded_pk(body: &[u8]) -> Result<(P256Pubkey, &[u8]), TransactionError> {
    let (prefix, rest) =
        body.split_at_checked(P256_PUBKEY_LEN)
            .ok_or(TransactionError::InvalidLength {
                expected: P256_PUBKEY_LEN,
                actual: body.len(),
            })?;
    let bytes: [u8; P256_PUBKEY_LEN] =
        prefix
            .try_into()
            .map_err(|_| TransactionError::InvalidLength {
                expected: P256_PUBKEY_LEN,
                actual: prefix.len(),
            })?;
    Ok((P256Pubkey::from_bytes(bytes)?, rest))
}

impl ConfidentialUnified {
    pub fn embedded_viewing_pk(body: &[u8]) -> Result<P256Pubkey, TransactionError> {
        Ok(split_embedded_pk(body)?.0)
    }

    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        let (recipient_pubkey, rest) = split_embedded_pk(body)?;
        let bytes = tx.decrypt_slot_ephemeral(&recipient_pubkey, rest, salt, slot_index)?;
        TransferRecipientPlaintext::deserialize(&bytes)
    }
}

impl UtxoSerialization for ConfidentialUnified {
    const SCHEME: EncryptedScheme = EncryptedScheme::ConfidentialUnified;
    type Plaintext = TransferRecipientPlaintext;
    type EncodeCx = ConfidentialUnifiedEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        let (_, rest) = split_embedded_pk(body)?;
        Ok(cx
            .viewing_key
            .decrypt_utxo(rest, &tx_viewing_pk, salt, cx.slot_index)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        TransferRecipientPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Ok(vec![plaintext.into_utxo(cx.owner, cx.assets)?])
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
            zone_program_id: first.zone_program_id,
            data: first.data.clone(),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        let ciphertext = cx
            .tx
            .encrypt_slot(&cx.recipient_pubkey, bytes, cx.salt, cx.slot_index)?;
        let mut body = Vec::with_capacity(P256_PUBKEY_LEN + ciphertext.len());
        body.extend_from_slice(cx.recipient_pubkey.as_bytes());
        body.extend_from_slice(&ciphertext);
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use zolana_event::OutputDataEncoding;
    use zolana_keypair::constants::BLINDING_LEN;

    use super::*;
    use crate::{data::Data, SOL_ASSET_ID};

    const SALT: [u8; SALT_LEN] = [9u8; SALT_LEN];
    const SLOT_INDEX: u32 = 2;

    fn plaintext() -> TransferRecipientPlaintext {
        TransferRecipientPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 42,
            blinding: [7u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        }
    }

    fn encoded_body(tx: &ViewingKey, recipient: &ViewingKey) -> Vec<u8> {
        let ciphertext = ConfidentialUnified::encode_plaintext(
            &plaintext(),
            [0u8; 32],
            &ConfidentialUnifiedEncode {
                tx: tx.clone(),
                recipient_pubkey: recipient.pubkey(),
                salt: SALT,
                slot_index: SLOT_INDEX,
            },
        )
        .expect("encode");
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(&ciphertext.data).expect("output data")
        else {
            panic!("expected encrypted output data");
        };
        let (&scheme_byte, body) = blob.split_first().expect("scheme byte");
        assert_eq!(scheme_byte, EncryptedScheme::ConfidentialUnified.as_byte());
        body.to_vec()
    }

    #[test]
    fn recipient_and_tx_key_both_decrypt_the_slot() {
        let tx = ViewingKey::new();
        let recipient = ViewingKey::new();
        let body = encoded_body(&tx, &recipient);

        let cx = DecodeCx {
            viewing_key: &recipient,
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(SALT),
            slot_index: SLOT_INDEX,
            first_nullifier: None,
        };
        assert_eq!(
            (
                ConfidentialUnified::decode(&body, &cx).expect("recipient decode"),
                ConfidentialUnified::decrypt_with_tx_key(&tx, &body, SALT, SLOT_INDEX)
                    .expect("tx key decode"),
            ),
            (plaintext(), plaintext())
        );
    }

    #[test]
    fn embedded_viewing_pk_is_the_recipient_pk() {
        let tx = ViewingKey::new();
        let recipient = ViewingKey::new();
        let body = encoded_body(&tx, &recipient);
        assert_eq!(
            ConfidentialUnified::embedded_viewing_pk(&body).expect("embedded pk"),
            recipient.pubkey()
        );
    }

    #[test]
    fn short_body_fails_with_invalid_length() {
        let short = [1u8; 10];
        let expected = TransactionError::InvalidLength {
            expected: P256_PUBKEY_LEN,
            actual: short.len(),
        };
        let tx = ViewingKey::new();
        let recipient = ViewingKey::new();
        let cx = DecodeCx {
            viewing_key: &recipient,
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(SALT),
            slot_index: SLOT_INDEX,
            first_nullifier: None,
        };
        assert_eq!(
            (
                ConfidentialUnified::decrypt(&short, &cx).unwrap_err(),
                ConfidentialUnified::embedded_viewing_pk(&short).unwrap_err(),
                ConfidentialUnified::decrypt_with_tx_key(&tx, &short, SALT, SLOT_INDEX)
                    .unwrap_err(),
            ),
            (expected.clone(), expected.clone(), expected)
        );
    }
}
