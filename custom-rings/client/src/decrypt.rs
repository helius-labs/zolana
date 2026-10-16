//! Every confidential slot of a transact is sealed under the per-transaction viewing key,
//! so the one key the auditor message carries opens the whole transaction.

use custom_ring_interface::AUDIT_OUTPUT_SLOTS;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_event::MessageData;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::event::{confidential_encrypted_output_body, OutputDataEncoding};
use zolana_keypair::{constants::SALT_LEN, ViewingKey, X25519Pubkey, X25519Secret};
use zolana_ring_policy::{spend_record_message_tag, SpendCounters, SpendRecord};
use zolana_transaction::{
    serialization::confidential::Confidential, utxo::program_id_proof_input_hash, AssetRegistry,
    EncryptedScheme, OutputSlot, ShieldedTransaction, SOL_MINT,
};

use crate::{
    counters::{find_counters_message, open_counters},
    encryption::{auditor_view_tag, AuditorMessage},
    types::{AuditedOutput, AuditedSpendRecord, AuditedTransaction},
    AuditError,
};

#[must_use]
pub struct TransactionAudit<'a> {
    pub auditor: &'a X25519Secret,
    pub transaction: &'a ShieldedTransaction,
    pub assets: &'a AssetRegistry,
}

impl TransactionAudit<'_> {
    pub fn run(self) -> Result<AuditedTransaction, AuditError> {
        let tx = self.transaction;
        let message = auditor_message(tx, &self.auditor.pubkey())?;
        let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
        let salt = tx.salt.ok_or(AuditError::MissingSalt)?;
        let tx_key = recover_tx_viewing_key(self.auditor, &message)?;
        // The ring proof binds the ciphertext to the published key, a mismatch is a forged message.
        if tx_key.pubkey() != tx_viewing_pk {
            return Err(AuditError::TxViewingKeyMismatch);
        }
        if tx.output_slots.len() > AUDIT_OUTPUT_SLOTS {
            return Err(AuditError::OutputDisclosureCount(tx.output_slots.len()));
        }
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            outputs: Vec::new(),
            output_openings: Vec::new(),
            spend_records: Vec::new(),
            undecryptable_slots: Vec::new(),
        };
        let openings = message.open_outputs(&tx_key, salt)?;
        for (position, (slot, opening)) in tx.output_slots.iter().zip(openings).enumerate() {
            let slot_index = position as u32;
            if opening.hash().ok() != Some(slot.output_context.hash) {
                return Err(AuditError::OutputCommitmentMismatch(slot_index));
            }
            let opened = open_output(&tx_key, slot, salt, slot_index, self.assets, &opening)?;
            audited.output_openings.push(opening);
            let last = position + 1 == tx.output_slots.len();
            match (carried_record(slot, &tx.messages, last)?, opened) {
                (Some(record), opened) => {
                    let plaintext =
                        matches!(slot.output_data(), Some(OutputDataEncoding::Plaintext(_)));
                    // A sealed carrier must be the zero SOL note the record names.
                    let carrier = opened.is_some_and(|output| {
                        output.asset == SOL_MINT
                            && output.amount == 0
                            && output.ring_program_id.is_none()
                            && output.recipient_viewing_pk == tx_viewing_pk
                            && *output.blinding == record.blinding
                    });
                    if !plaintext && !carrier {
                        return Err(AuditError::InvalidSpendRecordMessage);
                    }
                    audited.spend_records.push(AuditedSpendRecord {
                        slot_index,
                        counters: opened_counters(&tx_key, salt, &tx.messages, slot, &record)?,
                        record,
                    });
                }
                (None, Some(output)) => audited.outputs.push(output),
                (None, None) => audited.undecryptable_slots.push(slot_index),
            }
        }
        Ok(audited)
    }
}

/// The one auditor-tagged message, which the program requires to be the last message.
fn auditor_message(
    tx: &ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
) -> Result<AuditorMessage, AuditError> {
    let view_tag = auditor_view_tag(auditor_pk);
    let mut tagged = tx
        .messages
        .iter()
        .enumerate()
        .filter(|(_, message)| message.view_tag == view_tag);
    let (index, message) = tagged.next().ok_or(AuditError::MissingAuditorMessage)?;
    if tagged.next().is_some() {
        return Err(AuditError::DuplicateAuditorMessage);
    }
    let count = tx.messages.len();
    if index + 1 != count {
        return Err(AuditError::AuditorMessageNotLast { index, count });
    }
    AuditorMessage::parse(message, auditor_pk)
}

/// The circuit pins the secret below the P-256 order, so a representative above it is refused.
pub fn recover_tx_viewing_key(
    auditor: &X25519Secret,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    ViewingKey::from_bytes(&*message.decrypt(auditor)?)
        .map_err(|_| AuditError::NonCanonicalViewingKey)
}

/// `None` for a slot the transaction key does not open, which every dummy is.
fn open_output(
    tx_key: &ViewingKey,
    slot: &OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &AssetRegistry,
    opening: &ProofInputUtxo,
) -> Result<Option<AuditedOutput>, AuditError> {
    let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
        return Ok(None);
    };
    let Some((&scheme, body)) = blob.split_first() else {
        return Ok(None);
    };
    if !matches!(
        EncryptedScheme::from_byte(scheme),
        Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential)
    ) {
        return Ok(None);
    }
    let (Ok(recipient_viewing_pk), Ok(plaintext)) = (
        Confidential::embedded_viewing_pk(body),
        Confidential::decrypt_with_tx_key(tx_key, body, salt, slot_index),
    ) else {
        return Ok(None);
    };
    let asset = assets
        .resolve(plaintext.asset_id)
        .map_err(|source| AuditError::UnknownAsset {
            asset_id: plaintext.asset_id,
            source,
        })?;
    if hash_bytes(asset.asset.as_array())? != opening.asset
        || right_align(&plaintext.amount.to_be_bytes()) != opening.amount
        || plaintext.blinding != opening.blinding
        || program_id_proof_input_hash(&plaintext.ring_program_id)? != opening.ring_program_id
    {
        return Err(AuditError::OutputPlaintextMismatch(slot_index));
    }
    Ok(Some(AuditedOutput {
        slot_index,
        recipient_viewing_pk,
        owner_tag: slot.view_tag,
        asset: asset.asset,
        amount: plaintext.amount,
        blinding: Zeroizing::new(plaintext.blinding),
        ring_program_id: plaintext.ring_program_id,
        data: plaintext.data,
    }))
}

/// A registration carries its record inline, a successor in the one message its namespace
/// tags, from the last output slot.
fn carried_record(
    slot: &OutputSlot,
    messages: &[MessageData],
    last: bool,
) -> Result<Option<SpendRecord>, AuditError> {
    if let Some(record) = SpendRecord::from_output_data(&slot.payload) {
        return Ok((record.version == 0).then_some(record));
    }
    let tag = spend_record_message_tag(&slot.view_tag)?;
    let mut tagged = messages.iter().filter(|message| message.view_tag == tag);
    let Some(message) = tagged.next() else {
        return Ok(None);
    };
    if tagged.next().is_some()
        || !last
        || confidential_encrypted_output_body(&slot.payload).is_none()
    {
        return Err(AuditError::InvalidSpendRecordMessage);
    }
    SpendRecord::from_output_data(&message.data)
        .map(Some)
        .ok_or(AuditError::InvalidSpendRecordMessage)
}

/// `None` for a registration, else the counters that open the record's commitment.
fn opened_counters(
    tx_key: &ViewingKey,
    salt: [u8; SALT_LEN],
    messages: &[MessageData],
    slot: &OutputSlot,
    record: &SpendRecord,
) -> Result<Option<SpendCounters>, AuditError> {
    if record.version == 0 {
        return Ok(None);
    }
    find_counters_message(messages, &slot.view_tag)
        .ok()
        .flatten()
        .and_then(|message| open_counters(&message.data, salt, tx_key).ok())
        .filter(|counters| counters.commitment().ok() == Some(record.counters_commitment))
        .map(Some)
        .ok_or(AuditError::InvalidSpendCountersDisclosure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{seal_stream, AUDIT_ENC_INFO};

    /// The P-256 group order.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    fn with_last_byte(mut value: [u8; 32], last: u8) -> [u8; 32] {
        value[31] = last;
        value
    }

    /// Seals raw bytes as the transaction secret, no scalar check runs on the way in.
    fn recover(secret: [u8; 32]) -> Result<ViewingKey, AuditError> {
        let auditor = X25519Secret::new();
        let ephemeral = X25519Secret::new();
        let mut ciphertext = secret;
        seal_stream(
            &ephemeral,
            &auditor.pubkey(),
            AUDIT_ENC_INFO,
            &mut ciphertext,
        )
        .unwrap();
        recover_tx_viewing_key(
            &auditor,
            &AuditorMessage::new(ephemeral.pubkey(), ciphertext),
        )
    }

    #[test]
    fn the_largest_canonical_secret_opens() {
        let below = with_last_byte(N, 0x50);
        assert_eq!(*recover(below).unwrap().secret_bytes(), below);
    }

    /// A representative at or above the order would key another disclosure stream.
    #[test]
    fn a_secret_at_or_above_the_order_or_zero_is_refused() {
        for secret in [N, with_last_byte(N, 0x52), [0xff; 32], [0; 32]] {
            assert!(matches!(
                recover(secret),
                Err(AuditError::NonCanonicalViewingKey)
            ));
        }
    }
}
