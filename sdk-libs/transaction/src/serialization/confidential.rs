use solana_address::Address;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::{BLINDING_LEN, P256_PUBKEY_LEN, SALT_LEN},
    P256Pubkey, PublicKey, ViewingKey,
};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{data::Data, error::TransactionError, utxo::Utxo, AssetRegistry, EncryptedScheme};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialOutputPlaintext {
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub zone_program_id: Option<Address>,
    pub data: Data,
}

impl ConfidentialOutputPlaintext {
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
    ) -> Result<Utxo, TransactionError> {
        if self.data.zone_data().is_some() && self.zone_program_id.is_none() {
            return Err(TransactionError::MissingZoneProgramId);
        }
        Ok(Utxo {
            owner,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: self.zone_program_id,
            data: self.data,
        })
    }
}

pub struct ConfidentialEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct Confidential;

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

impl Confidential {
    pub fn embedded_viewing_pk(body: &[u8]) -> Result<P256Pubkey, TransactionError> {
        Ok(split_embedded_pk(body)?.0)
    }

    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        let (recipient_pubkey, rest) = split_embedded_pk(body)?;
        let bytes = tx.decrypt_slot_ephemeral(&recipient_pubkey, rest, salt, slot_index)?;
        ConfidentialOutputPlaintext::deserialize(&bytes)
    }
}

impl UtxoSerialization for Confidential {
    const SCHEME: EncryptedScheme = EncryptedScheme::Confidential;
    type Plaintext = ConfidentialOutputPlaintext;
    type EncodeCx = ConfidentialEncode;

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
        ConfidentialOutputPlaintext::deserialize(bytes)
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
        Ok(ConfidentialOutputPlaintext {
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

    fn plaintext() -> ConfidentialOutputPlaintext {
        ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 42,
            blinding: [7u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        }
    }

    fn encoded_body(tx: &ViewingKey, recipient: &ViewingKey) -> Vec<u8> {
        let ciphertext = Confidential::encode_plaintext(
            &plaintext(),
            [0u8; 32],
            &ConfidentialEncode {
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
        assert_eq!(scheme_byte, EncryptedScheme::Confidential.as_byte());
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
                Confidential::decode(&body, &cx).expect("recipient decode"),
                Confidential::decrypt_with_tx_key(&tx, &body, SALT, SLOT_INDEX)
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
            Confidential::embedded_viewing_pk(&body).expect("embedded pk"),
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
                Confidential::decrypt(&short, &cx).unwrap_err(),
                Confidential::embedded_viewing_pk(&short).unwrap_err(),
                Confidential::decrypt_with_tx_key(&tx, &short, SALT, SLOT_INDEX).unwrap_err(),
            ),
            (expected.clone(), expected.clone(), expected)
        );
    }
}
