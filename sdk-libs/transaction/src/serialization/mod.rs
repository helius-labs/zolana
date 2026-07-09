use rings_event::OutputData;
use rings_interface::instruction::instruction_data::transact::OutputCiphertext;
use rings_keypair::{constants::SALT_LEN, P256Pubkey, PublicKey, ViewingKey};
use solana_address::Address;

use crate::{
    error::TransactionError, instructions::transact::ShieldedTransaction, utxo::Utxo,
    AssetRegistry, EncryptedScheme,
};

pub mod anonymous;
pub mod confidential;
pub mod merge;
pub mod plaintext;
pub mod proofless;
pub mod scheme;
pub mod split;

pub use proofless::{Proofless, ProoflessEncode};
pub use split::{Split, SplitBundlePlaintext, SplitEncryptedUtxos};

pub struct DecodeCx<'a> {
    pub viewing_key: &'a ViewingKey,
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; SALT_LEN]>,
    pub slot_index: u32,
    pub first_nullifier: Option<[u8; 32]>,
}

impl<'a> DecodeCx<'a> {
    pub fn for_slot(
        viewing_key: &'a ViewingKey,
        transaction: &ShieldedTransaction,
        slot_index: u32,
    ) -> Self {
        Self {
            viewing_key,
            tx_viewing_pk: transaction.tx_viewing_pk,
            salt: transaction.salt,
            slot_index,
            first_nullifier: transaction.nullifiers.first().copied(),
        }
    }
}

pub struct OwnerCx<'a> {
    pub owner: PublicKey,
    pub assets: &'a AssetRegistry,
    pub zone_program_id: Option<Address>,
}

pub trait UtxoSerialization {
    const SCHEME: EncryptedScheme;
    type Plaintext;
    type EncodeCx;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError>;

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError>;

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError>;

    fn decode(body: &[u8], cx: &DecodeCx) -> Result<Self::Plaintext, TransactionError> {
        let bytes = Self::decrypt(body, cx)?;
        Self::deserialize(&bytes)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError>;

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError>;

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError>;

    fn encode(
        utxos: &[Utxo],
        owner: &OwnerCx,
        view_tag: [u8; 32],
        cx: &Self::EncodeCx,
    ) -> Result<OutputCiphertext, TransactionError> {
        let plaintext = Self::from_utxos(utxos, owner, cx)?;
        Self::encode_plaintext(&plaintext, view_tag, cx)
    }

    /// Seal an already-built plaintext into an [`OutputCiphertext`]: serialize,
    /// encrypt, prefix the scheme byte, and wrap in the borsh `OutputData` the
    /// program expects. `encode` is `from_utxos` followed by this; a builder that
    /// owns plaintext construction calls this directly.
    fn encode_plaintext(
        plaintext: &Self::Plaintext,
        view_tag: [u8; 32],
        cx: &Self::EncodeCx,
    ) -> Result<OutputCiphertext, TransactionError> {
        let bytes = Self::serialize(plaintext)?;
        let ciphertext = Self::encrypt(&bytes, cx)?;
        let mut blob = Vec::with_capacity(1 + ciphertext.len());
        blob.push(Self::SCHEME.as_byte());
        blob.extend_from_slice(&ciphertext);
        let output_data = match Self::SCHEME {
            EncryptedScheme::Proofless | EncryptedScheme::PlaintextTransfer => {
                OutputData::Plaintext(blob)
            }
            EncryptedScheme::Merge => OutputData::VerifiablyEncrypted(blob),
            _ => OutputData::Encrypted(blob),
        };
        let data = borsh::to_vec(&output_data)
            .map_err(|e| TransactionError::Deserialize(e.to_string()))?;
        Ok(OutputCiphertext { view_tag, data })
    }
}
