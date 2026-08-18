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

use custom_ring_sdk::{auditor_view_tag, decrypt_tx_viewing_sk, AuditorMessage};
use p256::{elliptic_curve::ops::Reduce, FieldBytes, Scalar, U256};
use zeroize::Zeroizing;
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_transaction::{
    serialization::confidential::Confidential, AssetRegistry, EncryptedScheme, OutputSlot,
    ShieldedTransaction,
};

use crate::{
    error::AuditError,
    types::{AuditedOutput, AuditedTransaction},
};

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

/// Decrypts the auditor message into the transaction viewing key.
pub fn recover_tx_viewing_key(
    auditor: &ViewingKey,
    message: &AuditorMessage,
) -> Result<ViewingKey, AuditError> {
    let eph_pk = message.ephemeral_pubkey()?;
    let recovered = decrypt_tx_viewing_sk(auditor, &eph_pk, &message.ciphertext)?;
    let canonical = reduce_mod_group_order(&recovered);
    ViewingKey::from_bytes(&canonical).map_err(AuditError::RecoveredKeyInvalid)
}

/// Opens every confidential output slot of `tx` with the transaction viewing key
/// the auditor message carries.
pub fn audit_transaction(
    auditor: &ViewingKey,
    tx: &ShieldedTransaction,
    assets: &AssetRegistry,
) -> Result<AuditedTransaction, AuditError> {
    let message = auditor_message(tx, &auditor.pubkey())?;
    let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
    let salt = tx.salt.ok_or(AuditError::MissingSalt)?;

    let tx_key = recover_tx_viewing_key(auditor, &message)?;
    // The verified ring proof binds the ciphertext to `tx_viewing_pk`, so this
    // holds for any transaction the program accepted. Checking it anyway turns a
    // forged or misrouted message into one named error instead of a pile of
    // failed slot decryptions.
    if tx_key.pubkey() != tx_viewing_pk {
        return Err(AuditError::TxViewingKeyMismatch);
    }

    let mut outputs = Vec::new();
    let mut undecryptable_slots = Vec::new();
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let slot_index =
            u32::try_from(position).map_err(|_| AuditError::SlotIndexOverflow(position))?;
        match audit_slot(&tx_key, slot, salt, slot_index, assets)? {
            Some(output) => outputs.push(output),
            None => undecryptable_slots.push(slot_index),
        }
    }

    Ok(AuditedTransaction {
        tx_signature: tx.tx_signature,
        slot: tx.slot,
        tx_viewing_pk,
        outputs,
        undecryptable_slots,
    })
}

/// `Ok(None)` for a slot this audit cannot open: an unparseable payload (dummy
/// slots are length-matched random bytes), another encryption scheme, or a
/// ciphertext under a different transaction key. `Err` is reserved for a slot
/// that did decrypt but references an asset the caller's registry lacks - that
/// is a registry gap the auditor must fix, and silently dropping the output
/// would understate the audited amounts.
///
/// `slot_index` is the slot's position in `output_slots`, counted over all
/// slots. That is the index the encryptor used
/// (`instructions/transact/slots.rs::encode_confidential_slots`, "slot_index ==
/// output position", where dummy positions also consume an index) and the index
/// the canonical tx-key decryptor uses (`wallet/sync.rs`, `position as u32`).
/// Counting only the slots that parse - as the swap example's `unified_slots`
/// does - would shift every index after a dummy slot and break decryption.
fn audit_slot(
    tx_key: &ViewingKey,
    slot: &OutputSlot,
    salt: [u8; SALT_LEN],
    slot_index: u32,
    assets: &AssetRegistry,
) -> Result<Option<AuditedOutput>, AuditError> {
    let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
        return Ok(None);
    };
    let Some((&scheme_byte, body)) = blob.split_first() else {
        return Ok(None);
    };
    if EncryptedScheme::from_byte(scheme_byte) != Ok(EncryptedScheme::Confidential) {
        return Ok(None);
    }
    let Ok(plaintext) = Confidential::decrypt_with_tx_key(tx_key, body, salt, slot_index) else {
        return Ok(None);
    };
    let asset = assets
        .resolve(plaintext.asset_id)
        .map_err(|source| AuditError::UnknownAsset {
            asset_id: plaintext.asset_id,
            source,
        })?;
    Ok(Some(AuditedOutput {
        slot_index,
        asset,
        amount: plaintext.amount,
        blinding: plaintext.blinding,
        ring_program_id: plaintext.ring_program_id,
    }))
}
