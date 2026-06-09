use zolana_keypair::{random_salt, ViewingKey};

use crate::error::TransactionError;
use crate::split::{SplitBundlePlaintext, SplitEncryptedUtxos};
use crate::transfer::{
    RecipientOutput, RecipientSlot, TransferEncryptedUtxos, TransferRecipientPlaintext,
    TransferSenderPlaintext,
};
use crate::{SPLIT, TRANSFER};

pub trait TransactionEncryption {
    fn encrypt_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> Result<TransferEncryptedUtxos, TransactionError>;

    fn decrypt_transfer(
        &self,
        first_nullifier: &[u8; 32],
        blob: &TransferEncryptedUtxos,
    ) -> Result<(TransferSenderPlaintext, Vec<TransferRecipientPlaintext>), TransactionError>;

    fn decrypt_transfer_recipient(
        &self,
        blob: &TransferEncryptedUtxos,
        slot: usize,
    ) -> Result<TransferRecipientPlaintext, TransactionError>;

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        bundle: &SplitBundlePlaintext,
    ) -> Result<SplitEncryptedUtxos, TransactionError>;

    fn decrypt_split(
        &self,
        blob: &SplitEncryptedUtxos,
    ) -> Result<SplitBundlePlaintext, TransactionError>;
}

impl TransactionEncryption for ViewingKey {
    fn encrypt_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> Result<TransferEncryptedUtxos, TransactionError> {
        if sender.recipient_viewing_pks.len() != recipients.len() {
            return Err(TransactionError::InvalidLength {
                expected: recipients.len(),
                actual: sender.recipient_viewing_pks.len(),
            });
        }
        let tx = self.get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let sender_ciphertext = tx.encrypt_slot(&self.pubkey(), &sender.serialize()?, salt, 0)?;
        let mut recipient_slots = Vec::with_capacity(recipients.len());
        for (i, (output, pubkey)) in recipients
            .iter()
            .zip(&sender.recipient_viewing_pks)
            .enumerate()
        {
            let ciphertext =
                tx.encrypt_slot(pubkey, &output.plaintext.serialize()?, salt, i as u32 + 1)?;
            recipient_slots.push(RecipientSlot {
                view_tag: output.view_tag,
                ciphertext,
            });
        }
        Ok(TransferEncryptedUtxos {
            type_prefix: TRANSFER,
            tx_viewing_pk: tx.pubkey(),
            salt,
            sender_ciphertext,
            recipient_slots,
        })
    }

    fn decrypt_transfer(
        &self,
        first_nullifier: &[u8; 32],
        blob: &TransferEncryptedUtxos,
    ) -> Result<(TransferSenderPlaintext, Vec<TransferRecipientPlaintext>), TransactionError> {
        let tx = self.get_transaction_viewing_key(first_nullifier)?;
        let sender_bytes =
            self.decrypt_utxo(&blob.sender_ciphertext, &blob.tx_viewing_pk, blob.salt, 0)?;
        let sender = TransferSenderPlaintext::deserialize(&sender_bytes)?;
        if blob.recipient_slots.len() != sender.recipient_viewing_pks.len() {
            return Err(TransactionError::InvalidLength {
                expected: sender.recipient_viewing_pks.len(),
                actual: blob.recipient_slots.len(),
            });
        }
        let mut recipients = Vec::with_capacity(blob.recipient_slots.len());
        for (i, (slot, pubkey)) in blob
            .recipient_slots
            .iter()
            .zip(&sender.recipient_viewing_pks)
            .enumerate()
        {
            let plaintext =
                tx.decrypt_slot_ephemeral(pubkey, &slot.ciphertext, blob.salt, i as u32 + 1)?;
            recipients.push(TransferRecipientPlaintext::deserialize(&plaintext)?);
        }
        Ok((sender, recipients))
    }

    fn decrypt_transfer_recipient(
        &self,
        blob: &TransferEncryptedUtxos,
        slot: usize,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        let entry = blob
            .recipient_slots
            .get(slot)
            .ok_or(TransactionError::InvalidLength {
                expected: blob.recipient_slots.len(),
                actual: slot,
            })?;
        let plaintext = self.decrypt_utxo(
            &entry.ciphertext,
            &blob.tx_viewing_pk,
            blob.salt,
            slot as u32 + 1,
        )?;
        TransferRecipientPlaintext::deserialize(&plaintext)
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        bundle: &SplitBundlePlaintext,
    ) -> Result<SplitEncryptedUtxos, TransactionError> {
        let tx = self.get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let ciphertext = tx.encrypt_slot(&self.pubkey(), &bundle.serialize()?, salt, 0)?;
        Ok(SplitEncryptedUtxos {
            type_prefix: SPLIT,
            tx_viewing_pk: tx.pubkey(),
            salt,
            ciphertext,
        })
    }

    fn decrypt_split(
        &self,
        blob: &SplitEncryptedUtxos,
    ) -> Result<SplitBundlePlaintext, TransactionError> {
        let bytes = self.decrypt_utxo(&blob.ciphertext, &blob.tx_viewing_pk, blob.salt, 0)?;
        SplitBundlePlaintext::deserialize(&bytes)
    }
}
