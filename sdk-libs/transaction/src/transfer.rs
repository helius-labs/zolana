use solana_address::Address;
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{P256Pubkey, PublicKey};

use crate::asset::{AssetRegistry, SOL_MINT};
use crate::data::Data;
use crate::error::TransactionError;
use crate::utxo::{derive_blinding, resolve_zone_program_id, Utxo};
use crate::{P256PubkeySchema, PublicKeySchema, TRANSFER};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferRecipientPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    #[wincode(with = "P256PubkeySchema")]
    pub sender_pubkey: P256Pubkey,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub data: Data,
}

impl TransferRecipientPlaintext {
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
pub struct TransferSenderPlaintext {
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

impl TransferSenderPlaintext {
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
    #[wincode(with = "P256PubkeySchema")]
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
