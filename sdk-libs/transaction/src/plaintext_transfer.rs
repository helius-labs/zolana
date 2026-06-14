use solana_address::Address;
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{PublicKey, SignatureType};

use crate::asset::{AssetRegistry, SOL_MINT};
use crate::data::Data;
use crate::error::TransactionError;
use crate::utxo::{derive_blinding, resolve_zone_program_id, Utxo};
use crate::{PublicKeySchema, TRANSFER_PLAINTEXT};

fn owner_view_tag(owner: &PublicKey) -> Result<ViewTag, TransactionError> {
    Ok(match owner.signature_type()? {
        SignatureType::P256 => owner.as_p256()?.x(),
        SignatureType::Ed25519 => owner.as_ed25519()?,
    })
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferPlaintextSplChange {
    pub amount: u64,
    pub asset_id: u64,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferPlaintextSender {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub spl: Option<TransferPlaintextSplChange>,
    pub sol_amount: Option<u64>,
    pub spl_data: Data,
    pub sol_data: Data,
}

impl TransferPlaintextSender {
    fn into_indexed_utxos(
        self,
        blinding_seed: &[u8; BLINDING_LEN],
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<(ViewTag, Utxo)>, TransactionError> {
        if self.spl.is_none() && !self.spl_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        if self.sol_amount.is_none() && !self.sol_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let view_tag = owner_view_tag(&self.owner_pubkey)?;
        let mut utxos = Vec::new();
        if let Some(spl) = self.spl {
            utxos.push((
                view_tag,
                Utxo {
                    owner: self.owner_pubkey,
                    asset: assets.resolve(spl.asset_id)?,
                    amount: spl.amount,
                    blinding: derive_blinding(blinding_seed, 0),
                    zone_program_id: resolve_zone_program_id(zone_program_id, &self.spl_data)?,
                    data: self.spl_data,
                },
            ));
        }
        if let Some(sol_amount) = self.sol_amount {
            utxos.push((
                view_tag,
                Utxo {
                    owner: self.owner_pubkey,
                    asset: SOL_MINT,
                    amount: sol_amount,
                    blinding: derive_blinding(blinding_seed, 1),
                    zone_program_id: resolve_zone_program_id(zone_program_id, &self.sol_data)?,
                    data: self.sol_data,
                },
            ));
        }
        Ok(utxos)
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferPlaintextRecipient {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub asset_id: u64,
    pub amount: u64,
    pub data: Data,
}

impl TransferPlaintextRecipient {
    fn into_indexed_utxo(
        self,
        blinding: [u8; BLINDING_LEN],
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<(ViewTag, Utxo), TransactionError> {
        let view_tag = owner_view_tag(&self.owner_pubkey)?;
        let utxo = Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding,
            zone_program_id: resolve_zone_program_id(zone_program_id, &self.data)?,
            data: self.data,
        };
        Ok((view_tag, utxo))
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferPlaintextUtxos {
    pub type_prefix: u8,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub sender: Option<TransferPlaintextSender>,
    #[wincode(with = "containers::Vec<TransferPlaintextRecipient, FixIntLen<u8>>")]
    pub recipient_slots: Vec<TransferPlaintextRecipient>,
}

impl TransferPlaintextUtxos {
    fn validate(&self) -> Result<(), TransactionError> {
        if let Some(sender) = &self.sender {
            sender.spl_data.validate()?;
            sender.sol_data.validate()?;
        }
        for recipient in &self.recipient_slots {
            recipient.data.validate()?;
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if parsed.type_prefix != TRANSFER_PLAINTEXT {
            return Err(TransactionError::BadDiscriminator(parsed.type_prefix));
        }
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn into_indexed_utxos(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<(ViewTag, Utxo)>, TransactionError> {
        let mut utxos = Vec::new();
        if let Some(sender) = self.sender {
            utxos.extend(sender.into_indexed_utxos(
                &self.blinding_seed,
                assets,
                zone_program_id,
            )?);
        }
        for (i, recipient) in self.recipient_slots.into_iter().enumerate() {
            let position = u8::try_from(i + 2).map_err(|_| TransactionError::TooManyOutputs)?;
            let blinding = derive_blinding(&self.blinding_seed, position);
            utxos.push(recipient.into_indexed_utxo(blinding, assets, zone_program_id)?);
        }
        Ok(utxos)
    }

    pub fn into_utxos(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        Ok(self
            .into_indexed_utxos(assets, zone_program_id)?
            .into_iter()
            .map(|(_, utxo)| utxo)
            .collect())
    }
}
