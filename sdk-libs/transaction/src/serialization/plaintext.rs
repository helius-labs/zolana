use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_interface::MAX_OUTPUTS;
use zolana_keypair::{viewing_key::ViewTag, PublicKey};

use super::{change_slots, DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_transact_output_blinding, resolve_ring_program_id, Utxo},
    AssetRegistry, EncryptedScheme, Mint, PublicKeySchema, TRANSFER_PLAINTEXT,
};

/// The widest supported shape's output count. No transact output sits beyond
/// this slot, so it bounds both the derivation and the reverse lookup below.
const MAX_OUTPUT_SLOTS: u32 = MAX_OUTPUTS as u32;

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
    /// The change outputs at the slots after the `recipient_count` recipients.
    fn into_indexed_utxos(
        self,
        first_nullifier: &[u8; 32],
        blinding_seed: &[u8; 32],
        recipient_count: u32,
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
        let slots = change_slots(recipient_count, self.spl.is_some());
        let blinding = |slot: u32| {
            if slot >= MAX_OUTPUT_SLOTS {
                return Err(TransactionError::TooManyOutputs);
            }
            derive_transact_output_blinding(first_nullifier, blinding_seed, slot)
        };
        let mut utxos = Vec::new();
        if let Some(spl) = self.spl {
            utxos.push((
                view_tag,
                Utxo {
                    owner: self.owner_pubkey,
                    asset: assets.resolve(spl.asset_id)?,
                    amount: spl.amount,
                    blinding: blinding(slots.spl)?,
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
                    asset: Mint::SOL,
                    amount: sol_amount,
                    blinding: blinding(slots.sol)?,
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

    /// The outputs in slot order: recipient `i` at slot `i`, then the change.
    pub fn into_indexed_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<(ViewTag, Utxo)>, TransactionError> {
        let recipient_count = u32::try_from(self.recipient_slots.len())
            .ok()
            .filter(|count| *count <= MAX_OUTPUT_SLOTS)
            .ok_or(TransactionError::TooManyOutputs)?;
        let mut utxos = Vec::new();
        for (slot, recipient) in (0u32..).zip(self.recipient_slots) {
            let blinding =
                derive_transact_output_blinding(first_nullifier, &self.blinding_seed, slot)?;
            utxos.push(recipient.into_indexed_utxo(blinding, assets, ring_program_id)?);
        }
        if let Some(sender) = self.sender {
            utxos.extend(sender.into_indexed_utxos(
                first_nullifier,
                &self.blinding_seed,
                recipient_count,
                assets,
                ring_program_id,
            )?);
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
        // The blinding is the only record of which physical slot an output sat
        // in, and the derivation is not invertible, so recover the slot by
        // re-deriving every candidate a shape can hold.
        for (index, utxo) in utxos.iter().enumerate() {
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
            if usize::try_from(position).ok() != Some(index) {
                return Err(TransactionError::InvalidPlaintextOutputPosition { index, position });
            }
        }
        // The change trails the recipients, SPL before SOL, so the sender's
        // outputs are read off the end.
        let is_change = |utxo: &Utxo, sol: bool| {
            utxo.owner == owner.owner && (utxo.asset.asset == Mint::SOL.asset) == sol
        };
        let mut recipients = utxos;
        let mut take_change = |sol: bool| match recipients.split_last() {
            Some((last, rest)) if is_change(last, sol) => {
                recipients = rest;
                Some(last)
            }
            _ => None,
        };
        let sol = take_change(true);
        let spl = take_change(false);
        let sender = spl.or(sol).map(|change| TransferPlaintextSender {
            owner_pubkey: change.owner,
            spl: spl.map(|utxo| TransferPlaintextSplChange {
                amount: utxo.amount,
                asset_id: utxo.asset.asset_id,
            }),
            sol_amount: sol.map(|utxo| utxo.amount),
            spl_data: spl.map(|utxo| utxo.data.clone()).unwrap_or_default(),
            sol_data: sol.map(|utxo| utxo.data.clone()).unwrap_or_default(),
        });
        let recipient_slots = recipients
            .iter()
            .map(|utxo| TransferPlaintextRecipient {
                owner_pubkey: utxo.owner,
                asset_id: utxo.asset.asset_id,
                amount: utxo.amount,
                data: utxo.data.clone(),
            })
            .collect();
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
