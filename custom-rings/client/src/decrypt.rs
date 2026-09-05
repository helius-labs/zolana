//! Recovering the transaction viewing key from an auditor message and opening
//! the transaction's confidential output slots with it.
//!
//! Why one key is enough: every confidential slot of an SPP transact is HPKE'd
//! under the per-transaction viewing key and carries the recipient's viewing
//! pubkey in its own body
//! (`sdk-libs/transaction/src/serialization/confidential.rs`), so
//! [`Confidential::decrypt_with_tx_key`] needs the transaction key and nothing
//! else. Recovering that one scalar therefore opens everything the recipients
//! see.

use crate::encryption::{auditor_view_tag, AuditorMessage};
use p256::{elliptic_curve::ops::Reduce, FieldBytes, Scalar, U256};
use zeroize::Zeroizing;
use zolana_interface::output_data::OutputDataEncoding;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_transaction::{
    serialization::confidential::Confidential, AssetRegistry, EncryptedScheme, OutputSlot,
    ShieldedTransaction,
};

use crate::{
    error::AuditError,
    types::{AuditedOutput, AuditedTransaction},
};

#[must_use]
/// Opens every confidential output slot of `transaction` with the transaction
/// viewing key the auditor message carries.
pub struct TransactionAudit<'a> {
    pub auditor: &'a ViewingKey,
    pub transaction: &'a ShieldedTransaction,
    pub assets: &'a AssetRegistry,
}

impl TransactionAudit<'_> {
    pub fn run(self) -> Result<AuditedTransaction, AuditError> {
        let message = auditor_message(self.transaction, &self.auditor.pubkey())?;
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

        let mut outputs = Vec::new();
        let mut undecryptable_slots = Vec::new();
        for (position, slot) in self.transaction.output_slots.iter().enumerate() {
            let slot_index =
                u32::try_from(position).map_err(|_| AuditError::SlotIndexOverflow(position))?;
            match (OutputAudit {
                tx_key: &tx_key,
                slot,
                salt,
                slot_index,
                assets: self.assets,
            })
            .run()?
            {
                Some(output) => outputs.push(output),
                None => undecryptable_slots.push(slot_index),
            }
        }

        Ok(AuditedTransaction {
            tx_signature: self.transaction.tx_signature,
            slot: self.transaction.slot,
            tx_viewing_pk,
            outputs,
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
pub fn auditor_message(
    tx: &ShieldedTransaction,
    auditor_pk: &P256Pubkey,
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
    Ok(AuditorMessage::parse(message, auditor_pk)?)
}

/// Decrypts the auditor message into the transaction viewing key.
pub fn recover_tx_viewing_key(
    auditor: &ViewingKey,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    let recovered = message.decrypt(auditor)?;
    let canonical = reduce_mod_group_order(&recovered);
    ViewingKey::from_bytes(&canonical).map_err(AuditError::RecoveredKeyInvalid)
}

#[must_use]
/// `Ok(None)` for a slot this audit cannot open: an unparseable payload, another
/// encryption scheme, or a ciphertext under a different transaction key.
struct OutputAudit<'a> {
    tx_key: &'a ViewingKey,
    slot: &'a OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &'a AssetRegistry,
}

impl OutputAudit<'_> {
    fn run(self) -> Result<Option<AuditedOutput>, AuditError> {
        let Some(OutputDataEncoding::Encrypted(blob)) = self.slot.output_data() else {
            return Ok(None);
        };
        let Some((&scheme_byte, body)) = blob.split_first() else {
            return Ok(None);
        };
        if !matches!(
            EncryptedScheme::from_byte(scheme_byte),
            Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential)
        ) {
            return Ok(None);
        }
        let Ok(recipient_viewing_pk) = Confidential::embedded_viewing_pk(body) else {
            return Ok(None);
        };
        let Ok(plaintext) =
            Confidential::decrypt_with_tx_key(self.tx_key, body, self.salt, self.slot_index)
        else {
            return Ok(None);
        };
        let asset =
            self.assets
                .resolve(plaintext.asset_id)
                .map_err(|source| AuditError::UnknownAsset {
                    asset_id: plaintext.asset_id,
                    source,
                })?;
        Ok(Some(AuditedOutput {
            slot_index: self.slot_index,
            recipient_viewing_pk,
            owner_tag: self.slot.view_tag,
            asset,
            amount: plaintext.amount,
            blinding: Zeroizing::new(plaintext.blinding),
            ring_program_id: plaintext.ring_program_id,
        }))
    }
}

/// Reduces the recovered 32 bytes modulo the P-256 group order `n`.
///
/// The circuit witnesses the secret key as 32 big-endian bytes and only ever
/// uses them through the emulated-field gadgets, i.e. it binds `bytes mod n`.
/// A prover can therefore encrypt any representative of the scalar class -
/// `sk`, `sk + n`, ... - and still satisfy
/// `ScalarMulGenerator(bytes) == tx_viewing_pk`. Reducing here maps every such
/// representative back to the canonical one that `ViewingKey::from_bytes`
/// accepts. Any 256-bit integer is below `2n`, so p256's single conditional
/// subtraction is a complete reduction.
fn reduce_mod_group_order(bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(*bytes));
    let mut reduced = Zeroizing::new([0u8; 32]);
    reduced.copy_from_slice(scalar.to_bytes().as_slice());
    reduced
}

#[cfg(test)]
mod tests {
    use p256::{
        elliptic_curve::{bigint::ArrayEncoding, Curve},
        NistP256,
    };
    use zolana_keypair::symmetric_apply;

    use crate::encryption::{AuditSharedSecret, AUDIT_ENC_INFO};

    use super::*;

    /// The circuit binds `bytes mod n`, so a prover may encrypt another
    /// representative of the scalar class. Client-side reduction must recover the
    /// canonical transaction viewing key.
    #[test]
    fn recovery_reduces_a_noncanonical_scalar() {
        let auditor = ViewingKey::new();
        let mut scalar = [0u8; 32];
        scalar[24..].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
        let viewing_key = ViewingKey::from_bytes(&scalar).expect("viewing key");
        let shifted = p256::U256::from_be_slice(&scalar)
            .wrapping_add(&NistP256::ORDER)
            .to_be_byte_array();
        let mut plaintext = [0u8; 32];
        plaintext.copy_from_slice(shifted.as_slice());

        let ephemeral = ViewingKey::new();
        let ephemeral_key = ephemeral.pubkey();
        let auditor_key = auditor.pubkey();
        let diffie_hellman_x = Zeroizing::new(ephemeral.ecdh(&auditor_key).expect("ecdh"));
        let shared = AuditSharedSecret {
            diffie_hellman_x: &diffie_hellman_x,
            ephemeral_key: &ephemeral_key,
            auditor_key: &auditor_key,
        }
        .derive()
        .expect("shared secret");
        symmetric_apply(&shared, AUDIT_ENC_INFO, &mut plaintext).expect("ciphertext");
        let message = AuditorMessage::new(ephemeral_key, plaintext);

        assert_eq!(
            recover_tx_viewing_key(&auditor, &message)
                .expect("recovered key")
                .pubkey(),
            viewing_key.pubkey()
        );
    }
}
