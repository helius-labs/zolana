//! Finding the transactions an auditor can open.
//!
//! The auditor scans for its own view tag, which is the auditor key's
//! x-coordinate (`custom_ring_sdk::auditor_view_tag`). Photon's
//! `get_shielded_transactions_by_tags` matches the requested tags against both
//! output view tags and MESSAGE view tags (an OR of two EXISTS subqueries in
//! `services/photon/src/api/method/rings/get_shielded_transactions_by_tags.rs`)
//! and hydrates the matching transactions' messages back, which is what makes it
//! usable here. `get_encrypted_utxos_by_tags` matches outputs only and would
//! never see an auditor message.

use custom_ring_sdk::auditor_view_tag;
use zolana_client::Rpc;
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::{decrypt::audit_transaction, error::AuditError, types::AuditedTransaction};

/// Every indexed transaction that carries a message tagged for `auditor_pk`,
/// oldest first, walking the indexer's cursor to the last page.
///
/// The tag match is re-applied to the returned messages: the indexer's filter is
/// an OR over output tags and message tags, so a transaction can come back
/// because one of its output view tags collided with the auditor tag rather than
/// because it carries an auditor message.
pub fn scan_ring_transactions<I: Rpc>(
    indexer: &I,
    auditor_pk: &P256Pubkey,
) -> Result<Vec<ShieldedTransaction>, AuditError> {
    let view_tag = auditor_view_tag(auditor_pk);
    let mut found = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer.get_shielded_transactions_by_tags(vec![view_tag], cursor, None, None)?;
        found.extend(page.transactions.into_iter().filter(|tx| {
            tx.messages
                .iter()
                .any(|message| message.view_tag == view_tag)
        }));
        let Some(next) = page.next_cursor else {
            return Ok(found);
        };
        cursor = Some(next);
    }
}

/// Scans and audits in one call: the typed decrypted view of everything the
/// auditor key can currently open.
pub fn audit_ring_transactions<I: Rpc>(
    indexer: &I,
    auditor: &ViewingKey,
    assets: &AssetRegistry,
) -> Result<Vec<AuditedTransaction>, AuditError> {
    scan_ring_transactions(indexer, &auditor.pubkey())?
        .iter()
        .map(|tx| audit_transaction(auditor, tx, assets))
        .collect()
}
