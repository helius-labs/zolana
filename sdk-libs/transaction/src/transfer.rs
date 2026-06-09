use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
use zolana_keypair::hash::sha256_be;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{P256Pubkey, PublicKey};

use crate::asset::{AssetRegistry, SOL_MINT};
use crate::data::Data;
use crate::error::TransactionError;
use crate::utxo::Utxo;
use crate::TRANSFER;

pub fn sender_blinding(seed: &[u8; BLINDING_LEN], position: u8) -> [u8; BLINDING_LEN] {
    let mut preimage = [0u8; BLINDING_LEN + 1];
    preimage[..BLINDING_LEN].copy_from_slice(seed);
    preimage[BLINDING_LEN] = position;
    let digest = sha256_be(&preimage);
    let mut out = [0u8; BLINDING_LEN];
    out.copy_from_slice(&digest[1..]);
    out
}

wincode::pod_wrapper! {
    unsafe struct PodP256Pubkey(P256Pubkey);
    unsafe struct PodPublicKey(PublicKey);
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferRecipientPlaintext {
    #[wincode(with = "PodPublicKey")]
    pub owner_pubkey: PublicKey,
    #[wincode(with = "PodP256Pubkey")]
    pub sender_pubkey: P256Pubkey,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub data: Data,
}

impl TransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }

    pub fn into_utxo(self, assets: &AssetRegistry) -> Result<Utxo, TransactionError> {
        Ok(Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: self.data,
        })
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferSenderPlaintext {
    #[wincode(with = "PodPublicKey")]
    pub owner_pubkey: PublicKey,
    pub spl_asset_id: u64,
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding_seed: [u8; BLINDING_LEN],
    #[wincode(with = "containers::Vec<PodP256Pubkey, FixIntLen<u8>>")]
    pub recipient_viewing_pks: Vec<P256Pubkey>,
    pub data: Data,
}

impl TransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }

    pub fn into_utxos(self, assets: &AssetRegistry) -> Result<Vec<Utxo>, TransactionError> {
        let mut utxos = Vec::new();
        if self.spl_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: assets.resolve(self.spl_asset_id)?,
                amount: self.spl_amount,
                blinding: sender_blinding(&self.blinding_seed, 0),
                zone_program_id: None,
                data: self.data,
            });
        }
        if self.sol_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: SOL_MINT,
                amount: self.sol_amount,
                blinding: sender_blinding(&self.blinding_seed, 1),
                zone_program_id: None,
                data: Data::default(),
            });
        }
        Ok(utxos)
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct RecipientSlot {
    pub view_tag: ViewTag,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientOutput {
    pub view_tag: ViewTag,
    pub plaintext: TransferRecipientPlaintext,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferEncryptedUtxos {
    pub type_prefix: u8,
    #[wincode(with = "PodP256Pubkey")]
    pub tx_viewing_pk: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub sender_ciphertext: Vec<u8>,
    #[wincode(with = "containers::Vec<RecipientSlot, FixIntLen<u8>>")]
    pub recipient_slots: Vec<RecipientSlot>,
}

impl TransferEncryptedUtxos {
    pub fn num_recipients(&self) -> usize {
        self.recipient_slots.len()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if parsed.type_prefix != TRANSFER {
            return Err(TransactionError::BadDiscriminator(parsed.type_prefix));
        }
        Ok(parsed)
    }
}
