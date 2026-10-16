//! Every confidential slot of a transact is sealed under the per-transaction viewing key,
//! so the one key the auditor message carries opens the whole transaction.

use custom_ring_interface::AUDIT_OUTPUT_SLOTS;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{constants::SALT_LEN, ViewingKey, X25519Pubkey, X25519Secret};
use zolana_transaction::{
    serialization::confidential::Confidential, utxo::program_id_proof_input_hash, AssetRegistry,
    EncryptedScheme, OutputSlot, ShieldedTransaction,
};

use crate::{
    encryption::{auditor_view_tag, AuditorMessage},
    types::{AuditedOutput, AuditedTransaction},
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
            match opened {
                Some(output) => audited.outputs.push(output),
                None => audited.undecryptable_slots.push(slot_index),
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

/// The circuit pins the clamped encoding, so an alias with the same public key is refused.
pub fn recover_tx_viewing_key(
    auditor: &X25519Secret,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    ViewingKey::from_canonical_bytes(&*message.decrypt(auditor)?)
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
