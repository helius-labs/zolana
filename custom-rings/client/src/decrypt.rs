//! Dedicated disclosure supplies the verified note openings. Recipient ciphertexts
//! supply optional delivery metadata and cannot erase those openings when malformed.
//! In an anonymous ring a ring body is proven, the auditor opens the note from it.

use custom_ring_interface::{DisclosureShape, RingMode, AUDIT_OUTPUT_SLOTS};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::{primitives::hash_bytes, Hasher, Poseidon};
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{constants::SALT_LEN, ViewingKey, X25519Keypair, X25519Pubkey};
use zolana_transaction::{
    serialization::{
        confidential::{Confidential, ConfidentialOutputPlaintext},
        ring_anonymous::{pair_hint, RingAnonymousSlot},
    },
    AssetRegistry, Data, EncryptedScheme, OutputSlot, ShieldedTransaction, TransactionError,
};

use crate::{
    encryption::{auditor_view_tag, AnonymousOutputOpening, AuditorMessage},
    opening::NoteOpening,
    types::{AuditedOutput, AuditedTransaction, OutputPayloadError, OutputPayloadErrorKind},
    AuditError,
};

#[must_use]
/// Checks disclosure against the supplied commitments. [`crate::RingScan::audit`]
/// also authenticates those commitments against confirmed settlement.
pub struct TransactionAudit<'a> {
    pub auditor: &'a X25519Keypair,
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
            payload_errors: Vec::new(),
        };
        if anonymous {
            let disclosure = message.open_anonymous(&tx_key, salt, shape)?;
            let ring = tx.ring_program_id.ok_or(AuditError::DisclosureShape)?;
            for (position, (slot, disclosed)) in
                tx.output_slots.iter().zip(&disclosure.outputs).enumerate()
            {
                let slot_index = position as u32;
                // A padding slot discloses no address and carries no note.
                if *disclosed == AnonymousOutputOpening::default() {
                    audited.output_openings.push(ProofInputUtxo::default());
                    continue;
                }
                if let Some(body) = slot.encrypted_body(EncryptedScheme::Confidential) {
                    let exit = OutputAudit {
                        tx_key: &tx_key,
                        slot,
                        salt,
                        slot_index,
                        assets: self.assets,
                    }
                    .run_exit(&body, disclosed);
                    match exit {
                        Ok((opening, output)) => {
                            audited.output_openings.push(opening);
                            audited.outputs.push(output);
                        }
                        Err(kind) => {
                            audited.output_openings.push(ProofInputUtxo::default());
                            audited
                                .payload_errors
                                .push(OutputPayloadError { slot_index, kind });
                        }
                    }
                    continue;
                }
                let opened = AnonymousSlotAudit {
                    tx_key: &tx_key,
                    slot,
                    salt,
                    slot_index,
                    ring,
                    disclosed,
                }
                .open();
                match opened {
                    Ok(note) => {
                        match note.output(self.assets) {
                            Ok(output) => audited.outputs.push(output),
                            Err(kind) => audited
                                .payload_errors
                                .push(OutputPayloadError { slot_index, kind }),
                        }
                        if pair_hint(note.pair_u).is_none() {
                            audited.payload_errors.push(OutputPayloadError {
                                slot_index,
                                kind: OutputPayloadErrorKind::PairHint,
                            });
                        }
                        audited.output_openings.push(note.opening);
                    }
                    Err(kind) => {
                        audited.output_openings.push(ProofInputUtxo::default());
                        audited
                            .payload_errors
                            .push(OutputPayloadError { slot_index, kind });
                    }
                }
            }
            audited.anonymous = Some(disclosure);
            return Ok(audited);
        }
        let openings = message.open_outputs_for_shape(&tx_key, salt, shape)?;
        for (position, (slot, opening)) in tx.output_slots.iter().zip(openings).enumerate() {
            let slot_index = position as u32;
            if opening.hash().ok() != Some(slot.output_context.hash) {
                return Err(AuditError::OutputCommitmentMismatch(slot_index));
            }
            let opened = OutputAudit {
                tx_key: &tx_key,
                slot,
                salt,
                slot_index,
                assets: self.assets,
            }
            .run(&opening);
            audited.output_openings.push(opening);
            match opened {
                Ok(output) => audited.outputs.push(output),
                Err(kind) => audited
                    .payload_errors
                    .push(OutputPayloadError { slot_index, kind }),
            }
        }
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

/// The circuit pins the clamped encoding, so an alias with the same public key is refused.
pub fn recover_tx_viewing_key(
    auditor: &X25519Keypair,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    ViewingKey::from_canonical_bytes(&*message.decrypt(auditor)?)
        .map_err(|_| AuditError::NonCanonicalViewingKey)
}

/// One real anonymous slot, the body opened under the disclosed viewing key.
struct AnonymousSlotAudit<'a> {
    tx_key: &'a ViewingKey,
    slot: &'a OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    ring: Address,
    disclosed: &'a AnonymousOutputOpening,
}

/// A body that opened to the published commitment.
struct AnonymousNote {
    slot_index: u32,
    opening: ProofInputUtxo,
    recipient_viewing_pk: X25519Pubkey,
    identity_key: [u8; 32],
    asset_address: Address,
    amount: u64,
    blinding: [u8; 32],
    pair_u: [u8; 32],
    ring: Address,
}

impl AnonymousSlotAudit<'_> {
    /// The commitment binds the disclosed owner, the public ring and the tree id
    /// of the slot, a body of another note or key fails here.
    fn open(self) -> Result<AnonymousNote, OutputPayloadErrorKind> {
        use OutputPayloadErrorKind::{Commitment, Decrypt, Frame};
        let body = self
            .slot
            .encrypted_body(EncryptedScheme::RingAnonymous)
            .ok_or(Frame)?;
        let slot = u8::try_from(self.slot_index).map_err(|_| Frame)?;
        let recipient_viewing_pk =
            X25519Pubkey::from_bytes(self.disclosed.viewing_pk).map_err(|_| Decrypt)?;
        let opened = RingAnonymousSlot {
            tx_viewing_pk: self.tx_key.pubkey(),
            recipient_pk: recipient_viewing_pk,
            salt: self.salt,
            slot,
        }
        .open_with_tx_key(self.tx_key, &body)
        .map_err(|error| match error {
            TransactionError::InvalidLength { .. } => Frame,
            _ => Decrypt,
        })?;
        let owner_hash = disclosed_owner_hash(self.disclosed)?;
        let asset_address = Address::new_from_array(opened.asset_address);
        let opening = ProofInputUtxo::new(
            owner_hash,
            &asset_address,
            opened.amount,
            &opened.blinding,
            self.slot.output_context.tree_id,
        )
        .and_then(|opening| opening.with_ring([0; 32], &Some(self.ring)))
        .map_err(|_| Commitment)?;
        if opening.hash().ok() != Some(self.slot.output_context.hash) {
            return Err(Commitment);
        }
        Ok(AnonymousNote {
            slot_index: self.slot_index,
            opening,
            recipient_viewing_pk,
            identity_key: self.disclosed.identity_key,
            asset_address,
            amount: opened.amount,
            blinding: opened.blinding,
            pair_u: opened.pair_u,
            ring: self.ring,
        })
    }
}

impl AnonymousNote {
    fn output(&self, assets: &AssetRegistry) -> Result<AuditedOutput, OutputPayloadErrorKind> {
        let asset = assets
            .mint(&self.asset_address)
            .map_err(|_| OutputPayloadErrorKind::Asset)?;
        Ok(AuditedOutput {
            slot_index: self.slot_index,
            recipient_viewing_pk: self.recipient_viewing_pk,
            owner_tag: self.identity_key,
            asset: asset.asset,
            amount: self.amount,
            blinding: Zeroizing::new(self.blinding),
            ring_program_id: Some(self.ring),
            data: Data::default(),
        })
    }
}

/// The owner hash the commitment binds, from the proven disclosure.
fn disclosed_owner_hash(
    disclosed: &AnonymousOutputOpening,
) -> Result<[u8; 32], OutputPayloadErrorKind> {
    let mut identity = [disclosed.identity_tag; 33];
    identity[1..].copy_from_slice(&disclosed.identity_key);
    hash_bytes(&identity)
        .and_then(|identity| Poseidon::hashv(&[&identity, &disclosed.nullifier_pk]))
        .map_err(|_| OutputPayloadErrorKind::Commitment)
}

#[must_use]
struct OutputAudit<'a> {
    tx_key: &'a ViewingKey,
    slot: &'a OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &'a AssetRegistry,
}

/// A confidential body is not proven, only a matching opening makes it a note.
struct ConfidentialBody {
    recipient_viewing_pk: X25519Pubkey,
    plaintext: ConfidentialOutputPlaintext,
}

impl OutputAudit<'_> {
    fn run(&self, opening: &ProofInputUtxo) -> Result<AuditedOutput, OutputPayloadErrorKind> {
        use OutputPayloadErrorKind::Frame;
        let Some(OutputDataEncoding::Encrypted(blob)) = self.slot.output_data() else {
            return Err(Frame);
        };
        let (&scheme, body) = blob.split_first().ok_or(Frame)?;
        if !matches!(
            EncryptedScheme::from_byte(scheme),
            Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential)
        ) {
            return Err(Frame);
        }
        self.check(self.open(body)?, opening)
    }

    /// An anonymous exit discloses its owner, the body supplies the rest of a default-ring opening.
    fn run_exit(
        &self,
        body: &[u8],
        disclosed: &AnonymousOutputOpening,
    ) -> Result<(ProofInputUtxo, AuditedOutput), OutputPayloadErrorKind> {
        use OutputPayloadErrorKind::{Asset, Commitment};
        let body = self.open(body)?;
        // The opening binds a zero data hash.
        if !body.plaintext.data.is_empty() {
            return Err(Commitment);
        }
        let mint = self
            .assets
            .resolve(body.plaintext.asset_id)
            .map_err(|_| Asset)?;
        let opening = ProofInputUtxo::new(
            disclosed_owner_hash(disclosed)?,
            &mint.asset,
            body.plaintext.amount,
            &body.plaintext.blinding,
            self.slot.output_context.tree_id,
        )
        .map_err(|_| Commitment)?;
        if opening.hash().ok() != Some(self.slot.output_context.hash) {
            return Err(Commitment);
        }
        let output = self.check(body, &opening)?;
        Ok((opening, output))
    }

    fn open(&self, body: &[u8]) -> Result<ConfidentialBody, OutputPayloadErrorKind> {
        use OutputPayloadErrorKind::{Decrypt, Frame};
        Ok(ConfidentialBody {
            recipient_viewing_pk: Confidential::embedded_viewing_pk(body).map_err(|_| Frame)?,
            plaintext: Confidential::decrypt_with_tx_key(
                self.tx_key,
                body,
                self.salt,
                self.slot_index,
            )
            .map_err(|_| Decrypt)?,
        })
    }

    fn check(
        &self,
        body: ConfidentialBody,
        opening: &ProofInputUtxo,
    ) -> Result<AuditedOutput, OutputPayloadErrorKind> {
        use OutputPayloadErrorKind::{Asset, Commitment};
        let ConfidentialBody {
            recipient_viewing_pk,
            plaintext,
        } = body;
        let opening = NoteOpening::new(opening).ok_or(Commitment)?;
        let asset = opening.mint(self.assets).map_err(|_| Asset)?.ok_or(Asset)?;
        if asset.asset_id != plaintext.asset_id
            || plaintext.amount != opening.amount
            || plaintext.blinding != opening.fields.blinding
            || !opening
                .belongs_to_ring(plaintext.ring_program_id)
                .map_err(|_| Commitment)?
        {
            return Err(Commitment);
        }
        Ok(AuditedOutput {
            slot_index: self.slot_index,
            recipient_viewing_pk,
            owner_tag: self.slot.view_tag,
            asset: asset.asset,
            amount: plaintext.amount,
            blinding: Zeroizing::new(plaintext.blinding),
            ring_program_id: plaintext.ring_program_id,
            data: plaintext.data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{seal_stream, AUDIT_ENC_INFO};

    /// Seals raw bytes as the transaction secret, no clamping runs on the way in.
    fn recover(secret: [u8; 32]) -> Result<ViewingKey, AuditError> {
        let auditor = X25519Keypair::new();
        let ephemeral = X25519Keypair::new();
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
        let canonical = *ViewingKey::from_bytes(&[0x48; 32]).secret_bytes();
        assert_eq!(*recover(canonical).unwrap().secret_bytes(), canonical);
    }

    /// Clamping maps every alias onto the published key, so only the clamped bytes may open.
    #[test]
    fn an_unclamped_alias_of_the_published_key_is_refused() {
        let key = ViewingKey::from_bytes(&[0x48; 32]);
        let mut low_bit = *key.secret_bytes();
        low_bit[0] |= 1;
        let mut high_bit = *key.secret_bytes();
        high_bit[31] |= 0x80;
        let mut cleared = *key.secret_bytes();
        cleared[31] &= !0x40;
        for alias in [low_bit, high_bit, cleared] {
            assert_eq!(
                ViewingKey::from_bytes(&alias).pubkey(),
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
