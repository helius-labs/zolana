//! Recovering the transaction viewing key from an auditor message and opening
//! the transaction's confidential output slots with it.
//!
//! Why one key is enough: every confidential slot uses the per-transaction
//! viewing key. Regular slots carry the recipient viewing key in their body.
//! Anonymous-ring slots keep that key in the proved auditor disclosure.

use crate::encryption::{auditor_view_tag, AnonymousOutputOpening, AuditorMessage};
use custom_ring_interface::{DisclosureShape, RingMode};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::event::OutputDataEncoding;
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::{constants::SALT_LEN, ViewingKey};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_transaction::utxo::program_id_proof_input_hash;
use zolana_transaction::{
    serialization::confidential::Confidential, AssetRegistry, EncryptedScheme, OutputSlot,
    ShieldedTransaction, UtxoSerialization, SOL_MINT,
};

use zolana_event::MessageData;
use zolana_ring_policy::SpendRecord;
use zolana_ring_transaction::RingAnonymous;

use crate::{
    counters::{find_counters_message, SealedCounters},
    error::AuditError,
    record::RecordCarrier,
    types::{AuditedOutput, AuditedSpendRecord, AuditedTransaction},
};

#[must_use]
/// Opens every confidential output slot of `transaction` with the transaction
/// viewing key the auditor message carries.
pub struct TransactionAudit<'a> {
    pub auditor: &'a X25519Keypair,
    pub transaction: &'a ShieldedTransaction,
    pub assets: &'a AssetRegistry,
}

impl TransactionAudit<'_> {
    pub fn run(self) -> Result<AuditedTransaction, AuditError> {
        self.run_with_mode(RingMode::Off)
    }

    /// Uses the config mode to disambiguate disclosure sizes that coincide
    /// across normal and anonymous rings.
    pub fn run_with_mode(self, mode: RingMode) -> Result<AuditedTransaction, AuditError> {
        // The on-chain mode selects the parser even when both layouts have 36 fields.
        let anonymous = mode == RingMode::Anonymous;
        let shape = DisclosureShape {
            anonymous,
            inputs: self.transaction.nullifiers.len(),
            outputs: self.transaction.output_slots.len(),
        };
        let message = auditor_message_with_shape(
            self.transaction,
            &self.auditor.pubkey(),
            anonymous.then_some(shape),
        )?;
        let tx_viewing_pk = self
            .transaction
            .tx_viewing_pk
            .ok_or(AuditError::MissingTxViewingPk)?;
        let salt = self.transaction.salt.ok_or(AuditError::MissingSalt)?;

        let tx_key = recover_tx_viewing_key(self.auditor, &message)?;
        // The verified ring proof binds the ciphertext to `tx_viewing_pk`, so this
        // holds for any transaction the program accepted. Checking it anyway turns a
        // forged or misrouted message into one named error instead of a pile of
        // failed slot decryptions.
        if tx_key.pubkey() != tx_viewing_pk {
            return Err(AuditError::TxViewingKeyMismatch);
        }
        if self.transaction.output_slots.len() > custom_ring_interface::AUDIT_OUTPUT_SLOTS {
            return Err(AuditError::OutputDisclosureCount(
                self.transaction.output_slots.len(),
            ));
        }
        // Reconstruct each real commitment from the anonymous opening before
        // interpreting its encrypted output body.
        let (disclosed, anonymous_disclosure) = if anonymous {
            let disclosure = message.open_anonymous(&tx_key, salt, shape)?;
            let openings = self
                .transaction
                .output_slots
                .iter()
                .zip(&disclosure.outputs)
                .enumerate()
                .map(|(index, (slot, output))| {
                    anonymous_output_opening(output, slot, self.transaction.ring_program_id)
                        .ok_or(AuditError::OutputCommitmentMismatch(index as u32))
                })
                .collect::<Result<Vec<_>, _>>()?;
            (openings, Some(disclosure))
        } else {
            (message.open_outputs(&tx_key, salt)?.to_vec(), None)
        };

        let mut outputs = Vec::new();
        let mut output_openings = Vec::with_capacity(self.transaction.output_slots.len());
        let mut spend_records = Vec::new();
        let mut undecryptable_slots = Vec::new();
        for (position, slot) in self.transaction.output_slots.iter().enumerate() {
            let slot_index =
                u32::try_from(position).map_err(|_| AuditError::SlotIndexOverflow(position))?;
            let opening = disclosed[position];
            let committed = ProofInputUtxo {
                domain: opening.domain,
                tree_id: opening.tree_id,
                owner_hash: opening.owner_hash,
                asset: opening.asset,
                amount: opening.amount,
                blinding: opening.blinding,
                data_hash: opening.data_hash,
                ring_data_hash: opening.ring_data_hash,
                ring_program_id: opening.ring_program_id,
            };
            if !(anonymous && opening == Default::default())
                && committed.hash().ok() != Some(slot.output_context.hash)
            {
                return Err(AuditError::OutputCommitmentMismatch(slot_index));
            }
            output_openings.push(opening);
            let opened = OutputAudit {
                tx_key: &tx_key,
                slot,
                salt,
                slot_index,
                assets: self.assets,
                opening: &opening,
                anonymous: anonymous_disclosure
                    .as_ref()
                    .and_then(|disclosure| disclosure.outputs.get(position)),
            }
            .run()?;
            let record = match RecordCarrier::decode(slot, &self.transaction.messages)? {
                None => None,
                Some(RecordCarrier::Inline(record)) => Some(record),
                Some(RecordCarrier::Sidecar(record)) => {
                    if position + 1 != self.transaction.output_slots.len() {
                        return Err(AuditError::InvalidSpendRecordMessage);
                    }
                    Some(record)
                }
            };
            if let Some(record) = record {
                if !matches!(slot.output_data(), Some(OutputDataEncoding::Plaintext(_)))
                    && !opened.as_ref().is_some_and(|output| {
                        output.asset == SOL_MINT
                            && output.amount == 0
                            && output.ring_program_id.is_none()
                            && output.recipient_viewing_pk == tx_viewing_pk
                            && *output.blinding == record.blinding
                    })
                {
                    return Err(AuditError::InvalidSpendRecordMessage);
                }
                spend_records.push(AuditedSpendRecord {
                    slot_index,
                    counters: opened_counters(
                        &tx_key,
                        salt,
                        &self.transaction.messages,
                        slot,
                        &record,
                    )?,
                    record,
                });
            } else if let Some(output) = opened {
                outputs.push(output);
            } else {
                undecryptable_slots.push(slot_index);
            }
        }

        Ok(AuditedTransaction {
            tx_signature: self.transaction.tx_signature,
            slot: self.transaction.slot,
            tx_viewing_pk,
            outputs,
            output_openings,
            anonymous: anonymous_disclosure,
            spend_records,
            undecryptable_slots,
        })
    }
}

/// Locates the ring program's auditor message.
///
/// The program's convention (enforced on-chain) is exactly one message with the
/// auditor view tag, as the last entry of `TransactIxData::messages`; both parts
/// are re-checked here so a client audit of an unverified or replayed
/// transaction reports the deviation instead of silently reading a different
/// message.
fn auditor_message_with_shape(
    tx: &ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
    shape: Option<DisclosureShape>,
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
    Ok(match shape {
        Some(shape) => AuditorMessage::parse_with_shape(message, auditor_pk, shape)?,
        None => AuditorMessage::parse(message, auditor_pk)?,
    })
}

/// Reconstructs a real output from its identity and ring-note flag. Dummy
/// openings are zero in the circuit and carry no blinding to reconstruct.
fn anonymous_output_opening(
    output: &AnonymousOutputOpening,
    slot: &OutputSlot,
    ring: Option<Address>,
) -> Option<crate::AuditOutputOpening> {
    if *output == AnonymousOutputOpening::default() {
        return Some(crate::AuditOutputOpening::default());
    }
    let mut identity_bytes = [output.identity_tag; 33];
    identity_bytes[1..].copy_from_slice(&output.identity_key);
    let identity = hash_bytes(&identity_bytes).ok()?;
    let owner_hash = Poseidon::hashv(&[&identity, &output.nullifier_pk]).ok()?;
    let ring_program_id = match output.ring_note {
        0 => [0u8; 32],
        1 => program_id_proof_input_hash(&Some(ring?)).ok()?,
        _ => return None,
    };
    let opening = crate::AuditOutputOpening {
        domain: right_align(&zolana_transaction::utxo::UTXO_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(slot.output_context.tree_id),
        owner_hash,
        asset: output.asset,
        amount: right_align(&output.amount.to_be_bytes()),
        blinding: output.blinding,
        data_hash: output.data_hash,
        ring_data_hash: output.ring_data_hash,
        ring_program_id,
    };
    Some(opening)
}

/// Decrypts the auditor message into the transaction viewing key.
pub fn recover_tx_viewing_key(
    auditor: &X25519Keypair,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    let recovered = message.decrypt(auditor)?;
    ViewingKey::from_canonical_bytes(&recovered).map_err(AuditError::RecoveredKeyInvalid)
}

#[must_use]
/// `Ok(None)` for a slot the audit cannot open.
struct OutputAudit<'a> {
    tx_key: &'a ViewingKey,
    slot: &'a OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &'a AssetRegistry,
    opening: &'a crate::AuditOutputOpening,
    anonymous: Option<&'a AnonymousOutputOpening>,
}

impl OutputAudit<'_> {
    fn run(self) -> Result<Option<AuditedOutput>, AuditError> {
        let Some(OutputDataEncoding::Encrypted(blob)) = self.slot.output_data() else {
            return Ok(None);
        };
        let Some((&scheme_byte, body)) = blob.split_first() else {
            return Ok(None);
        };
        let (recipient_viewing_pk, plaintext, owner_tag) =
            match EncryptedScheme::from_byte(scheme_byte) {
                Ok(EncryptedScheme::RingAnonymous) => {
                    let Some(disclosed) = self.anonymous else {
                        return Ok(None);
                    };
                    let Ok(viewing_pk) = X25519Pubkey::from_bytes(disclosed.viewing_pk) else {
                        return Ok(None);
                    };
                    let Ok(bytes) = self.tx_key.decrypt_slot_ephemeral(
                        &viewing_pk,
                        body,
                        self.salt,
                        self.slot_index,
                    ) else {
                        return Ok(None);
                    };
                    let Ok(plaintext) = RingAnonymous::deserialize(&bytes) else {
                        return Ok(None);
                    };
                    (viewing_pk, plaintext, disclosed.identity_key)
                }
                Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential) => {
                    let Ok(viewing_pk) = Confidential::embedded_viewing_pk(body) else {
                        return Ok(None);
                    };
                    let Ok(plaintext) = Confidential::decrypt_with_tx_key(
                        self.tx_key,
                        body,
                        self.salt,
                        self.slot_index,
                    ) else {
                        return Ok(None);
                    };
                    (viewing_pk, plaintext, self.slot.view_tag)
                }
                _ => return Ok(None),
            };
        let asset =
            self.assets
                .resolve(plaintext.asset_id)
                .map_err(|source| AuditError::UnknownAsset {
                    asset_id: plaintext.asset_id,
                    source,
                })?;
        let asset_field = hash_bytes(asset.asset.as_array())
            .map_err(|_| AuditError::OutputPlaintextMismatch(self.slot_index))?;
        let ring_program_id = program_id_proof_input_hash(&plaintext.ring_program_id)
            .map_err(|_| AuditError::OutputPlaintextMismatch(self.slot_index))?;
        if asset_field != self.opening.asset
            || right_align(&plaintext.amount.to_be_bytes()) != self.opening.amount
            || plaintext.blinding != self.opening.blinding
            || ring_program_id != self.opening.ring_program_id
        {
            return Err(AuditError::OutputPlaintextMismatch(self.slot_index));
        }
        Ok(Some(AuditedOutput {
            slot_index: self.slot_index,
            recipient_viewing_pk,
            owner_tag,
            asset: asset.asset,
            amount: plaintext.amount,
            blinding: Zeroizing::new(plaintext.blinding),
            ring_program_id: plaintext.ring_program_id,
            data: plaintext.data,
        }))
    }
}

fn opened_counters(
    tx_key: &ViewingKey,
    salt: [u8; SALT_LEN],
    messages: &[MessageData],
    slot: &OutputSlot,
    record: &SpendRecord,
) -> Result<Option<zolana_ring_policy::SpendCounters>, AuditError> {
    if record.version == 0 {
        return Ok(None);
    }
    let message = find_counters_message(messages, &slot.view_tag)
        .map_err(|_| AuditError::InvalidSpendCountersDisclosure)?
        .ok_or(AuditError::InvalidSpendCountersDisclosure)?;
    let counters = SealedCounters {
        body: &message.data,
        salt,
    }
    .open(tx_key)
    .map_err(|_| AuditError::InvalidSpendCountersDisclosure)?;
    if counters
        .commitment()
        .map_err(|_| AuditError::InvalidSpendCountersDisclosure)?
        != record.counters_commitment
    {
        return Err(AuditError::InvalidSpendCountersDisclosure);
    }
    Ok(Some(counters))
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{symmetric_apply, KeypairError};

    use crate::encryption::{AuditSharedSecret, AUDIT_ENC_INFO};

    use super::*;

    /// Audit recovery rejects a noncanonical byte string even when its
    /// clamping would produce the published viewing key.
    #[test]
    fn recovery_rejects_a_noncanonical_secret() {
        let auditor = X25519Keypair::new();
        let scalar = [0x48u8; 32];
        let viewing_key = ViewingKey::from_bytes(&scalar);
        let mut plaintext = *viewing_key.secret_bytes();
        plaintext[0] |= 1;

        let ephemeral = X25519Keypair::new();
        let ephemeral_key = ephemeral.pubkey();
        let auditor_key = auditor.pubkey();
        let diffie_hellman_x = ephemeral.ecdh(&auditor_key).expect("ecdh");
        let shared = AuditSharedSecret {
            diffie_hellman_x: &diffie_hellman_x,
            ephemeral_key: &ephemeral_key,
            auditor_key: &auditor_key,
        }
        .derive()
        .expect("shared secret");
        symmetric_apply(&shared, AUDIT_ENC_INFO, &mut plaintext).expect("ciphertext");
        let message = AuditorMessage::new(ephemeral_key, plaintext);

        assert!(matches!(
            recover_tx_viewing_key(&auditor, &message),
            Err(AuditError::RecoveredKeyInvalid(
                KeypairError::InvalidSecretKey
            ))
        ));
    }
}
