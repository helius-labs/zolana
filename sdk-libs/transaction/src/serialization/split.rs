use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, PublicKey, ViewingKey};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_transact_output_blinding, resolve_ring_program_id, Blinding, Utxo},
    AssetRegistry, EncryptedScheme, P256PubkeySchema, PublicKeySchema, SPLIT,
};

/// Physical output slots a split commits. The bundle describes the first
/// `num_outputs` of them; the rest are zero-value pads the wallet never tracks.
pub const SPLIT_OUTPUT_SLOTS: u8 = 8;

pub struct SplitEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
    /// The derived output blinding seed the bundle discloses. See
    /// [`SplitBundlePlaintext::blinding_seed`].
    pub blinding_seed: [u8; 32],
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct SplitBundlePlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub num_outputs: u8,
    pub asset_id: u64,
    pub asset_amount: u64,
    /// The derived `output_blinding_seed = Poseidon(TXOS, nullifier_0,
    /// blinding_seed)`, never `blinding_seed` itself. The reader re-derives
    /// `blinding_i = Poseidon(TXOB, nullifier_0, blinding_seed, i)` for every
    /// slot `i < num_outputs`, so one 32-byte field covers all eight outputs
    /// and the bundle fits the transaction size limit. All eight outputs are
    /// self-owned and the bundle is encrypted to the owner's own viewing key,
    /// so disclosing the seed reveals nothing to another party.
    pub blinding_seed: [u8; 32],
    pub data: Data,
}

impl SplitBundlePlaintext {
    /// The blinding of every tracked slot `0..num_outputs`, derived from the
    /// transaction's `first_nullifier` and the disclosed seed.
    pub fn output_blindings(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<Blinding>, TransactionError> {
        if self.num_outputs > SPLIT_OUTPUT_SLOTS {
            return Err(TransactionError::SplitInvalidPartCount {
                num_outputs: self.num_outputs,
            });
        }
        (0..u32::from(self.num_outputs))
            .map(|slot| derive_transact_output_blinding(first_nullifier, &self.blinding_seed, slot))
            .collect()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if parsed.num_outputs > SPLIT_OUTPUT_SLOTS {
            return Err(TransactionError::SplitInvalidPartCount {
                num_outputs: parsed.num_outputs,
            });
        }
        parsed.data.validate()?;
        Ok(parsed)
    }

    /// A split's slot index is its physical output index, so slot `i` of the
    /// bundle takes `blinding_i` of the transaction whose first published
    /// nullifier is `first_nullifier`.
    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        let blindings = self.output_blindings(first_nullifier)?;
        if self.num_outputs == 0 && !self.data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let ring_program_id = resolve_ring_program_id(ring_program_id, &self.data)?;
        let asset = assets.resolve(self.asset_id)?;
        Ok(blindings
            .into_iter()
            .map(|blinding| Utxo {
                owner: self.owner_pubkey,
                asset,
                amount: self.asset_amount,
                blinding,
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
        let first_nullifier = cx
            .first_nullifier
            .ok_or(TransactionError::MissingFirstNullifier)?;
        plaintext.into_utxos(&first_nullifier, cx.assets, cx.ring_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &SplitEncode,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        let num_outputs = u8::try_from(utxos.len())
            .ok()
            .filter(|count| *count <= SPLIT_OUTPUT_SLOTS)
            .ok_or(TransactionError::TooManyOutputs)?;
        Ok(SplitBundlePlaintext {
            owner_pubkey: first.owner,
            num_outputs,
            asset_id: owner.assets.asset_id(&first.asset)?,
            asset_amount: first.amount,
            blinding_seed: cx.blinding_seed,
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
