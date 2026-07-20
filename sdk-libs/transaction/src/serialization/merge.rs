use zolana_keypair::{
    constants::{BLINDING_LEN, P256_PUBKEY_LEN},
    P256Pubkey, ViewingKey,
};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{data::Data, error::TransactionError, utxo::Utxo, EncryptedScheme};

const MERGE_PLAINTEXT_LEN: usize = 8 + 32 + BLINDING_LEN;

pub struct MergePlaintext {
    pub amount: u64,
    pub asset_proof_input_hash: [u8; 32],
    pub blinding: [u8; BLINDING_LEN],
}

impl MergePlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut out = Vec::with_capacity(MERGE_PLAINTEXT_LEN);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.asset_proof_input_hash);
        out.extend_from_slice(&self.blinding);
        Ok(out)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() != MERGE_PLAINTEXT_LEN {
            return Err(TransactionError::InvalidLength {
                expected: MERGE_PLAINTEXT_LEN,
                actual: bytes.len(),
            });
        }
        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&bytes[..8]);
        let mut asset_proof_input_hash = [0u8; 32];
        asset_proof_input_hash.copy_from_slice(&bytes[8..40]);
        let mut blinding = [0u8; BLINDING_LEN];
        blinding.copy_from_slice(&bytes[40..MERGE_PLAINTEXT_LEN]);
        Ok(Self {
            amount: u64::from_be_bytes(amount_bytes),
            asset_proof_input_hash,
            blinding,
        })
    }
}

pub struct MergeEncode {
    pub tx: ViewingKey,
    pub user_viewing_pk: P256Pubkey,
}

pub struct Merge;

impl UtxoSerialization for Merge {
    const SCHEME: EncryptedScheme = EncryptedScheme::Merge;
    type Plaintext = MergePlaintext;
    type EncodeCx = MergeEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        if body.len() < P256_PUBKEY_LEN {
            return Err(TransactionError::InvalidLength {
                expected: P256_PUBKEY_LEN,
                actual: body.len(),
            });
        }
        let (pk_bytes, ciphertext) = body.split_at(P256_PUBKEY_LEN);
        let pk_array = <[u8; P256_PUBKEY_LEN]>::try_from(pk_bytes)
            .map_err(|_| TransactionError::Deserialize("merge tx_viewing_pk".to_string()))?;
        let tx_viewing_pk = P256Pubkey::from_bytes(pk_array)?;
        Ok(cx
            .viewing_key
            .decrypt_verifiable(&tx_viewing_pk, ciphertext)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        MergePlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        let asset = cx
            .assets
            .address_for_asset_hash(&plaintext.asset_proof_input_hash)?
            .ok_or_else(|| {
                TransactionError::Deserialize("merge asset field has no matching asset".to_string())
            })?;
        Ok(vec![Utxo {
            owner: cx.owner,
            asset,
            amount: plaintext.amount,
            blinding: plaintext.blinding,
            zone_program_id: None,
            data: Data::default(),
        }])
    }

    fn from_utxos(
        utxos: &[Utxo],
        _owner: &OwnerCx,
        _cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        Ok(MergePlaintext {
            amount: first.amount,
            asset_proof_input_hash: zolana_hasher::primitives::hash_bytes(first.asset.as_array())?,
            blinding: first.blinding,
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        let (ciphertext, tx_viewing_pk) = cx.tx.encrypt_verifiable(&cx.user_viewing_pk, bytes)?;
        let mut out = Vec::with_capacity(P256_PUBKEY_LEN + ciphertext.len());
        out.extend_from_slice(tx_viewing_pk.as_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}
