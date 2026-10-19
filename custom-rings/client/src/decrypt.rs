//! Dedicated disclosure supplies the verified note openings. Recipient ciphertexts
//! supply optional delivery metadata and cannot erase those openings when malformed.

use custom_ring_interface::{DisclosureShape, RingMode, AUDIT_OUTPUT_SLOTS};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{event::OutputDataEncoding, tree_slot::tree_id_field};
use zolana_keypair::{constants::SALT_LEN, ViewingKey, X25519Pubkey, X25519Secret};
use zolana_transaction::{
    serialization::confidential::Confidential,
    utxo::{program_id_proof_input_hash, UTXO_DOMAIN},
    AssetRegistry, EncryptedScheme, OutputSlot, ShieldedTransaction, UtxoSerialization,
};

use crate::{
    encryption::{auditor_view_tag, AnonymousOutputOpening, AuditorMessage},
    opening::NoteOpening,
    types::{AuditedOutput, AuditedTransaction},
    AuditError,
};

#[must_use]
/// Checks disclosure against the supplied commitments. [`crate::RingScan::audit`]
/// also authenticates those commitments against confirmed settlement.
pub struct TransactionAudit<'a> {
    pub auditor: &'a X25519Secret,
    pub transaction: &'a ShieldedTransaction,
    pub assets: &'a AssetRegistry,
}

impl TransactionAudit<'_> {
    pub fn run(self) -> Result<AuditedTransaction, AuditError> {
        self.run_with_mode(RingMode::Off)
    }

    /// The config mode picks the parser, the two layouts can share a field count.
    pub fn run_with_mode(self, mode: RingMode) -> Result<AuditedTransaction, AuditError> {
        let tx = self.transaction;
        let anonymous = mode == RingMode::Anonymous;
        let shape = DisclosureShape {
            anonymous,
            inputs: tx.nullifiers.len(),
            outputs: tx.output_slots.len(),
        };
        let message = auditor_message(tx, &self.auditor.pubkey(), Some(shape))?;
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
        let (openings, disclosure) = match anonymous {
            true => {
                let disclosure = message.open_anonymous(&tx_key, salt, shape)?;
                let openings = tx
                    .output_slots
                    .iter()
                    .zip(&disclosure.outputs)
                    .enumerate()
                    .map(|(index, (slot, output))| {
                        anonymous_opening(output, slot, tx.ring_program_id)
                            .ok_or(AuditError::OutputCommitmentMismatch(index as u32))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (openings, Some(disclosure))
            }
            false => (message.open_outputs_for_shape(&tx_key, salt, shape)?, None),
        };
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            outputs: Vec::new(),
            output_contexts: tx
                .output_slots
                .iter()
                .map(|slot| slot.output_context.clone())
                .collect(),
            output_openings: Vec::new(),
            anonymous: None,
            undecryptable_slots: Vec::new(),
        };
        for (position, (slot, opening)) in tx.output_slots.iter().zip(openings).enumerate() {
            let slot_index = position as u32;
            // An anonymous dummy opens to zero, it has no blinding to rebuild its commitment.
            let dummy = anonymous && opening == ProofInputUtxo::default();
            if !dummy && opening.hash().ok() != Some(slot.output_context.hash) {
                return Err(AuditError::OutputCommitmentMismatch(slot_index));
            }
            let opened = OutputAudit {
                tx_key: &tx_key,
                slot,
                salt,
                slot_index,
                assets: self.assets,
                opening: &opening,
                anonymous: disclosure
                    .as_ref()
                    .and_then(|disclosure| disclosure.outputs.get(position)),
            }
            .run()?;
            audited.output_openings.push(opening);
            match opened {
                Some(output) => audited.outputs.push(output),
                None => audited.undecryptable_slots.push(slot_index),
            }
        }
        audited.anonymous = disclosure;
        Ok(audited)
    }
}

/// The one auditor-tagged message, which the program requires to be the last message.
fn auditor_message(
    tx: &ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
    anonymous: Option<DisclosureShape>,
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
    match anonymous {
        Some(shape) => AuditorMessage::parse_with_shape(message, auditor_pk, shape),
        None => AuditorMessage::parse(message, auditor_pk),
    }
}

/// Rebuilds a real output from its owner identity and ring flag, a dummy stays zero.
fn anonymous_opening(
    output: &AnonymousOutputOpening,
    slot: &OutputSlot,
    ring: Option<Address>,
) -> Option<ProofInputUtxo> {
    if *output == AnonymousOutputOpening::default() {
        return Some(ProofInputUtxo::default());
    }
    let mut identity = [output.identity_tag; 33];
    identity[1..].copy_from_slice(&output.identity_key);
    let owner_hash = Poseidon::hashv(&[&hash_bytes(&identity).ok()?, &output.nullifier_pk]).ok()?;
    let ring_program_id = match output.ring_note {
        0 => [0; 32],
        1 => program_id_proof_input_hash(&Some(ring?)).ok()?,
        _ => return None,
    };
    Some(ProofInputUtxo {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(slot.output_context.tree_id),
        owner_hash,
        asset: output.asset,
        amount: right_align(&output.amount.to_be_bytes()),
        blinding: output.blinding,
        data_hash: output.data_hash,
        ring_data_hash: output.ring_data_hash,
        ring_program_id,
    })
}

/// The circuit pins the clamped encoding, so an alias with the same public key is refused.
pub fn recover_tx_viewing_key(
    auditor: &X25519Secret,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    ViewingKey::from_canonical_bytes(&*message.decrypt(auditor)?)
        .map_err(|_| AuditError::NonCanonicalViewingKey)
}

#[must_use]
struct OutputAudit<'a> {
    tx_key: &'a ViewingKey,
    slot: &'a OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &'a AssetRegistry,
    opening: &'a ProofInputUtxo,
    /// The disclosed recipient of an anonymous ring slot.
    anonymous: Option<&'a AnonymousOutputOpening>,
}

impl OutputAudit<'_> {
    /// `None` for a slot the transaction key does not open, which every dummy is.
    fn run(self) -> Result<Option<AuditedOutput>, AuditError> {
        let Some(OutputDataEncoding::Encrypted(blob)) = self.slot.output_data() else {
            return Ok(None);
        };
        let Some((&scheme, body)) = blob.split_first() else {
            return Ok(None);
        };
        let opened = match EncryptedScheme::from_byte(scheme) {
            Ok(EncryptedScheme::RingAnonymous) => self.anonymous.and_then(|disclosed| {
                let viewing_pk = X25519Pubkey::from_bytes(disclosed.viewing_pk).ok()?;
                let bytes = self
                    .tx_key
                    .decrypt_slot_ephemeral(&viewing_pk, body, self.salt, self.slot_index)
                    .ok()?;
                let plaintext = Confidential::deserialize(&bytes).ok()?;
                Some((viewing_pk, plaintext, disclosed.identity_key))
            }),
            Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential) => {
                match (
                    Confidential::embedded_viewing_pk(body),
                    Confidential::decrypt_with_tx_key(
                        self.tx_key,
                        body,
                        self.salt,
                        self.slot_index,
                    ),
                ) {
                    (Ok(viewing_pk), Ok(plaintext)) => {
                        Some((viewing_pk, plaintext, self.slot.view_tag))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let Some((recipient_viewing_pk, plaintext, owner_tag)) = opened else {
            return Ok(None);
        };
        let Some(opening) = NoteOpening::new(self.opening) else {
            return Ok(None);
        };
        let Some(asset) = opening.mint(self.assets)? else {
            return Ok(None);
        };
        if asset.asset_id != plaintext.asset_id
            || plaintext.amount != opening.amount
            || plaintext.blinding != opening.fields.blinding
            || !opening.belongs_to_ring(plaintext.ring_program_id)?
        {
            return Ok(None);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{seal_stream, AUDIT_ENC_INFO};

    /// Seals raw bytes as the transaction secret, no clamping runs on the way in.
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
    fn the_canonical_secret_opens_byte_for_byte() {
        let canonical = *ViewingKey::from_bytes(&[0x48; 32]).unwrap().secret_bytes();
        assert_eq!(*recover(canonical).unwrap().secret_bytes(), canonical);
    }

    /// Clamping maps every alias onto the published key, so only the clamped bytes may open.
    #[test]
    fn an_unclamped_alias_of_the_published_key_is_refused() {
        let key = ViewingKey::from_bytes(&[0x48; 32]).unwrap();
        let mut low_bit = *key.secret_bytes();
        low_bit[0] |= 1;
        let mut high_bit = *key.secret_bytes();
        high_bit[31] |= 0x80;
        let mut cleared = *key.secret_bytes();
        cleared[31] &= !0x40;
        for alias in [low_bit, high_bit, cleared] {
            assert_eq!(
                ViewingKey::from_bytes(&alias).unwrap().pubkey(),
                key.pubkey(),
                "alias must clamp onto the published key"
            );
            assert!(matches!(
                recover(alias),
                Err(AuditError::NonCanonicalViewingKey)
            ));
        }
        for unclamped in [[0xff; 32], [0; 32]] {
            assert!(matches!(
                recover(unclamped),
                Err(AuditError::NonCanonicalViewingKey)
            ));
        }
    }
}
