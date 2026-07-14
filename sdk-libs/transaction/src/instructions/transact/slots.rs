use zolana_event::OutputData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{constants::SALT_LEN, random_salt, ViewingKey};

use super::OutputUtxo;
use crate::{
    error::TransactionError,
    serialization::{
        confidential::TransferRecipientPlaintext,
        confidential_unified::{ConfidentialUnified, ConfidentialUnifiedEncode},
        UtxoSerialization,
    },
    AssetRegistry, SOL_MINT,
};

pub struct SlotCx<'a> {
    pub tx: &'a ViewingKey,
    pub salt: [u8; SALT_LEN],
    /// AES ciphertext ordinal for this slot: the count of data-bearing outputs
    /// preceding it. Fed into the per-slot key/nonce derivation.
    pub slot_index: u32,
}

/// The encoded form of one output slot: its wire [`OwnerTag`], the resolved
/// 32-byte tag folded into the proof's owner-tag chain and republished as the
/// event `view_tag`, and the optional ciphertext (`None` when a preceding bundle
/// covers this slot).
pub struct EncodedSlot {
    pub owner_tag: OwnerTag,
    pub resolved_owner_tag: [u8; 32],
    pub data: Option<Vec<u8>>,
}

impl EncodedSlot {
    /// A self-contained data-bearing slot whose owner tag is embedded inline; the
    /// resolved tag is the same `view_tag` the ciphertext was sealed under.
    fn inline(ciphertext: OutputData) -> Self {
        Self {
            owner_tag: OwnerTag::Inline(ciphertext.view_tag),
            resolved_owner_tag: ciphertext.view_tag,
            data: Some(ciphertext.data),
        }
    }
}

pub trait EncodeOutputSlot {
    fn output(&self) -> &OutputUtxo;
    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError>;
}

pub struct ConfidentialSlot {
    output: OutputUtxo,
    asset_id: u64,
}

impl ConfidentialSlot {
    pub fn new(output: OutputUtxo, assets: &AssetRegistry) -> Result<Self, TransactionError> {
        if output.owner_address.is_none() {
            return Err(TransactionError::MissingOutput);
        }
        let asset_id = if output.asset == SOL_MINT {
            crate::SOL_ASSET_ID
        } else {
            assets.asset_id(&output.asset)?
        };
        Ok(Self { output, asset_id })
    }
}

impl EncodeOutputSlot for ConfidentialSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        let address = self
            .output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        Ok(EncodedSlot::inline(ConfidentialUnified::encode_plaintext(
            &TransferRecipientPlaintext {
                asset_id: self.asset_id,
                amount: self.output.amount,
                blinding: self.output.blinding,
                zone_program_id: self.output.zone_program_id,
                data: self.output.data.clone(),
            },
            address.signing_pubkey.confidential_view_tag()?,
            &ConfidentialUnifiedEncode {
                tx: cx.tx.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt: cx.salt,
                slot_index: cx.slot_index,
            },
        )?))
    }
}

pub struct EncodedOutputs {
    pub salt: [u8; SALT_LEN],
    pub output_utxos: Vec<OutputUtxo>,
    pub outputs: Vec<TransactOutput>,
    pub resolved_owner_tags: Vec<[u8; 32]>,
}

pub fn encode_slots(
    slots: &[ConfidentialSlot],
    tx: &ViewingKey,
) -> Result<EncodedOutputs, TransactionError> {
    let salt = random_salt();
    let mut output_utxos = Vec::with_capacity(slots.len());
    let mut outputs = Vec::with_capacity(slots.len());
    let mut resolved_owner_tags = Vec::with_capacity(slots.len());
    let mut ordinal = 0u32;
    for slot in slots {
        let encoded = slot.encode_slot(&SlotCx {
            tx,
            salt,
            slot_index: ordinal,
        })?;
        let output = slot.output().clone();
        let utxo_hash = output.hash()?;
        if encoded.data.is_some() {
            ordinal += 1;
        }
        outputs.push(TransactOutput {
            utxo_hash,
            owner_tag: encoded.owner_tag,
            data: encoded.data,
        });
        resolved_owner_tags.push(encoded.resolved_owner_tag);
        output_utxos.push(output);
    }
    Ok(EncodedOutputs {
        salt,
        output_utxos,
        outputs,
        resolved_owner_tags,
    })
}

/// A slot whose ciphertext is already sealed (e.g. by a zone/swap SDK), carried
/// through verbatim. Its owner tag is embedded inline from the ciphertext's
/// `view_tag`.
pub struct PrebuiltSlot {
    pub output: OutputUtxo,
    pub ciphertext: OutputData,
}

impl EncodeOutputSlot for PrebuiltSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, _cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        Ok(EncodedSlot::inline(self.ciphertext.clone()))
    }
}
