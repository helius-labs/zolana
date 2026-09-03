use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{viewing_key::ViewTag, PublicKey};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::instructions::transact::Shape;
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_transact_output_blinding, resolve_ring_program_id, Utxo},
    AssetRegistry, EncryptedScheme, PublicKeySchema, SOL_MINT, TRANSFER_PLAINTEXT,
};

/// Physical output slots the bundle describes. It names the two sender change
/// slots positionally and has no way to say that one was dropped, so a slot's
/// logical position is also its physical output index.
const SPL_CHANGE_SLOT: u32 = 0;
const SOL_CHANGE_SLOT: u32 = 1;
const RECIPIENT_SLOT_BASE: u32 = 2;

/// The widest supported shape has eight output slots, so no bundle describes a
/// slot beyond this.
const MAX_OUTPUT_SLOTS: u32 = 8;
const _: () = assert!(Shape::IN1_OUT8.n_outputs() == MAX_OUTPUT_SLOTS as usize);

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
        first_nullifier: &[u8; 32],
        blinding_seed: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<(ViewTag, Utxo)>, TransactionError> {
        if self.spl.is_none() && !self.spl_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        if self.sol_amount.is_none() && !self.sol_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let view_tag = self.owner_pubkey.confidential_view_tag()?;
        let mut utxos = Vec::new();
        if let Some(spl) = self.spl {
            utxos.push((
                view_tag,
                Utxo {
                    owner: self.owner_pubkey,
                    asset: assets.resolve(spl.asset_id)?,
                    amount: spl.amount,
                    blinding: derive_transact_output_blinding(
                        first_nullifier,
                        blinding_seed,
                        SPL_CHANGE_SLOT,
                    )?,
                    ring_program_id: resolve_ring_program_id(ring_program_id, &self.spl_data)?,
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
                    blinding: derive_transact_output_blinding(
                        first_nullifier,
                        blinding_seed,
                        SOL_CHANGE_SLOT,
                    )?,
                    ring_program_id: resolve_ring_program_id(ring_program_id, &self.sol_data)?,
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
        blinding: [u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<(ViewTag, Utxo), TransactionError> {
        let view_tag = self.owner_pubkey.confidential_view_tag()?;
        let utxo = Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding,
            ring_program_id: resolve_ring_program_id(ring_program_id, &self.data)?,
            data: self.data,
        };
        Ok((view_tag, utxo))
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferPlaintextUtxos {
    pub type_prefix: u8,
    pub blinding_seed: [u8; 32],
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
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<(ViewTag, Utxo)>, TransactionError> {
        let mut utxos = Vec::new();
        if let Some(sender) = self.sender {
            utxos.extend(sender.into_indexed_utxos(
                first_nullifier,
                &self.blinding_seed,
                assets,
                ring_program_id,
            )?);
        }
        for (i, recipient) in self.recipient_slots.into_iter().enumerate() {
            let slot = u32::try_from(i)
                .ok()
                .and_then(|i| i.checked_add(RECIPIENT_SLOT_BASE))
                .ok_or(TransactionError::TooManyOutputs)?;
            let blinding =
                derive_transact_output_blinding(first_nullifier, &self.blinding_seed, slot)?;
            utxos.push(recipient.into_indexed_utxo(blinding, assets, ring_program_id)?);
        }
        Ok(utxos)
    }

    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        Ok(self
            .into_indexed_utxos(first_nullifier, assets, ring_program_id)?
            .into_iter()
            .map(|(_, utxo)| utxo)
            .collect())
    }
}

pub struct PlaintextEncode {
    pub blinding_seed: [u8; 32],
    /// The transaction's first nullifier. Encoding recovers each output's slot
    /// by matching its blinding against the derivation, which is bound to this.
    pub first_nullifier: [u8; 32],
}

pub struct PlaintextTransfer;

impl UtxoSerialization for PlaintextTransfer {
    const SCHEME: EncryptedScheme = EncryptedScheme::PlaintextTransfer;
    type Plaintext = TransferPlaintextUtxos;
    type EncodeCx = PlaintextEncode;

    fn decrypt(body: &[u8], _cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(body.to_vec())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        TransferPlaintextUtxos::deserialize(bytes)
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
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let mut sender_owner = None;
        let mut spl = None;
        let mut sol_amount = None;
        let mut spl_data = Data::default();
        let mut sol_data = Data::default();
        let mut recipients: Vec<(u32, TransferPlaintextRecipient)> = Vec::new();
        // The blinding is the only record of which physical slot an output sat
        // in, and the derivation is not invertible, so recover the slot by
        // re-deriving every candidate a shape can hold.
        for utxo in utxos {
            let mut slot = None;
            for candidate in 0..MAX_OUTPUT_SLOTS {
                let blinding = derive_transact_output_blinding(
                    &cx.first_nullifier,
                    &cx.blinding_seed,
                    candidate,
                )?;
                if blinding == utxo.blinding {
                    slot = Some(candidate);
                    break;
                }
            }
            let position = slot.ok_or(TransactionError::MissingOutput)?;
            match position {
                SPL_CHANGE_SLOT => {
                    sender_owner = Some(utxo.owner);
                    spl = Some(TransferPlaintextSplChange {
                        amount: utxo.amount,
                        asset_id: owner.assets.asset_id(&utxo.asset)?,
                    });
                    spl_data = utxo.data.clone();
                }
                SOL_CHANGE_SLOT => {
                    sender_owner = Some(utxo.owner);
                    sol_amount = Some(utxo.amount);
                    sol_data = utxo.data.clone();
                }
                position => recipients.push((
                    position,
                    TransferPlaintextRecipient {
                        owner_pubkey: utxo.owner,
                        asset_id: owner.assets.asset_id(&utxo.asset)?,
                        amount: utxo.amount,
                        data: utxo.data.clone(),
                    },
                )),
            }
        }
        recipients.sort_by_key(|(position, _)| *position);
        let recipient_slots = recipients
            .into_iter()
            .map(|(_, recipient)| recipient)
            .collect();
        let sender = sender_owner.map(|owner_pubkey| TransferPlaintextSender {
            owner_pubkey,
            spl,
            sol_amount,
            spl_data,
            sol_data,
        });
        Ok(TransferPlaintextUtxos {
            type_prefix: TRANSFER_PLAINTEXT,
            blinding_seed: cx.blinding_seed,
            sender,
            recipient_slots,
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], _cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(bytes.to_vec())
    }
}
