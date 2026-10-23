//! A transaction read as the wallet that sent it.
//!
//! Every confidential output of a transfer is encrypted between the
//! transaction viewing key and its recipient's viewing key. The sender derives
//! that transaction key from its own viewing key and the transaction's first
//! nullifier, so it opens what it paid each recipient as well as its own
//! change. Nobody else derives the key the transaction publishes, so a match
//! also proves the wallet sent it.

use std::collections::BTreeSet;

use zolana_event::OutputDataEncoding;
use zolana_keypair::X25519Pubkey;

use crate::{
    asset::{AssetRegistry, Mint},
    error::TransactionError,
    indexer_types::ShieldedTransaction,
    keys::{ShieldedKeys, TransactionKeyRequest},
    serialization::{confidential::Confidential, scheme::EncryptedScheme},
};

/// One confidential output of a transaction this wallet sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentOutput {
    /// The output's position among the transaction's outputs.
    pub slot_index: u32,
    /// The viewing key the output is encrypted to: its recipient's.
    pub recipient_viewing_pk: X25519Pubkey,
    pub asset: Mint,
    pub amount: u64,
    /// Encrypted to one of this wallet's viewing keys: its change, or a
    /// payment to itself.
    pub owned: bool,
}

/// What [`decrypt_sent`] opens of a transaction this wallet sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SentTransaction {
    /// In output order. Padding opens under no key and is left out.
    pub outputs: Vec<SentOutput>,
    /// Asset ids that outputs name and the registry does not know. Those
    /// outputs are left out.
    pub unknown_asset_ids: BTreeSet<u64>,
}

/// `tx` as the wallet that sent it reads it: `None` unless the transaction
/// viewing key `tx` publishes is one that `shielded_keys` derives from the
/// first nullifier. Confidential and ring-confidential outputs open; outputs
/// of other schemes, such as an anonymous sender bundle, are not read.
pub fn decrypt_sent<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    tx: &ShieldedTransaction,
    assets: &AssetRegistry,
) -> Result<Option<SentTransaction>, TransactionError> {
    let (Some(published), Some(salt), Some(&first_nullifier)) =
        (tx.tx_viewing_pk, tx.salt, tx.nullifiers.first())
    else {
        return Ok(None);
    };
    let viewing_pubkeys = shielded_keys.viewing_public_keys();
    let requests: Vec<_> = viewing_pubkeys
        .iter()
        .map(|&viewing_pubkey| TransactionKeyRequest {
            viewing_pubkey,
            first_nullifier,
        })
        .collect();
    let Some(tx_key) = shielded_keys
        .transaction_keys(&requests)?
        .into_iter()
        .find(|key| key.pubkey() == published)
    else {
        return Ok(None);
    };
    let mut sent = SentTransaction::default();
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let slot_index = u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
        let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
            continue;
        };
        let Some((&scheme, body)) = blob.split_first() else {
            continue;
        };
        if !matches!(
            EncryptedScheme::from_byte(scheme),
            Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential)
        ) {
            continue;
        }
        let (Ok(recipient_viewing_pk), Ok(plaintext)) = (
            Confidential::embedded_viewing_pk(body),
            Confidential::decrypt_with_tx_key(&tx_key, body, salt, slot_index),
        ) else {
            continue;
        };
        let asset = match assets.resolve(plaintext.asset_id) {
            Ok(asset) => asset,
            Err(TransactionError::UnknownAsset(asset_id)) => {
                sent.unknown_asset_ids.insert(asset_id);
                continue;
            }
            Err(error) => return Err(error),
        };
        sent.outputs.push(SentOutput {
            slot_index,
            recipient_viewing_pk,
            asset,
            amount: plaintext.amount,
            owned: viewing_pubkeys.contains(&recipient_viewing_pk),
        });
    }
    Ok(Some(sent))
}
