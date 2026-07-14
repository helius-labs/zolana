use std::collections::HashSet;

use rayon::prelude::*;
use zolana_keypair::{viewing_key::ViewTag, KeypairError, P256Pubkey};

use super::{
    state::{SyncReport, ViewingKeyEntry, Wallet},
    sync::{SyncCtx, TxIndex},
};
use crate::{
    error::TransactionError, instructions::transact::ShieldedTransaction, SyncWalletAuthority,
    WalletSyncMaterial,
};

type StreamHits = Vec<(u64, Vec<(usize, usize)>)>;

fn probe_recipient_stream(
    index: &TxIndex,
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
) -> Result<StreamHits, TransactionError> {
    let mut hits = Vec::new();
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if let Some(sites) = index.recipient_sites.get(&tag) {
                window_hit = true;
                hits.push((n, sites.clone()));
            }
        }
        if !window_hit || start.checked_add(window).is_none() {
            return Ok(hits);
        }
        start += window;
    }
}

fn probe_sender_stream(
    index: &TxIndex,
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
) -> Result<Vec<(u64, Vec<usize>)>, TransactionError> {
    let mut hits = Vec::new();
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if let Some(sites) = index.sender_sites.get(&tag) {
                window_hit = true;
                hits.push((n, sites.clone()));
            }
        }
        if !window_hit || start.checked_add(window).is_none() {
            return Ok(hits);
        }
        start += window;
    }
}

fn probe_presence_stream(
    index: &TxIndex,
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
) -> Result<Option<u64>, TransactionError> {
    let mut max_present = None;
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if index.recipient_sites.contains_key(&tag) {
                window_hit = true;
                max_present = Some(n);
            }
        }
        if !window_hit || start.checked_add(window).is_none() {
            return Ok(max_present);
        }
        start += window;
    }
}

impl Wallet {
    pub fn sync_parallel<A: SyncWalletAuthority + ?Sized>(
        &mut self,
        authority: &A,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let material = authority.sync_material()?;
        self.sync_parallel_with_material(&material, transactions, synced_at, window)
    }

    pub fn sync_parallel_with_material(
        &mut self,
        material: &WalletSyncMaterial,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let identity = material.identity;
        if identity != self.identity {
            return Err(TransactionError::WalletAuthorityMismatch);
        }
        let viewing_keys = &material.viewing_keys;
        if viewing_keys
            .iter()
            .all(|key| key.pubkey() != identity.viewing_pubkey)
        {
            return Err(TransactionError::MissingCurrentViewingKey);
        }
        self.ensure_viewing_key_entries(viewing_keys.iter().map(|key| key.pubkey()));
        if material.nullifier_key.pubkey()? != identity.nullifier_pubkey {
            return Err(TransactionError::WalletAuthorityMismatch);
        }

        let mut report = SyncReport::default();
        let index = TxIndex::build(transactions, &mut report);

        let assets = &self.registry;
        let owner_tag = identity.signing_pubkey.confidential_view_tag()?;
        let mut ctx = SyncCtx {
            owner: identity.signing_pubkey,
            nullifier_pk: identity.nullifier_pubkey,
            nullifier_key: &material.nullifier_key,
            self_viewing_pubkey: identity.viewing_pubkey,
            utxos: &mut self.utxos,
            transactions: &mut self.transactions,
            processed_slots: HashSet::new(),
            processed_outbound: HashSet::new(),
            report,
        };

        for entry in self.viewing_key_history.iter_mut() {
            let ViewingKeyEntry {
                viewing_pubkey,
                tx_count,
                request_count,
                known_senders,
                known_recipients,
                ..
            } = entry;
            let Some(key) = viewing_keys
                .iter()
                .find(|key| key.pubkey() == *viewing_pubkey)
            else {
                continue;
            };

            // Anonymous policy-zone bootstrap scan (recipient viewing-pubkey
            // x-coordinate); also catches proofless deposits.
            let bootstrap = key.recipient_bootstrap_view_tag();
            if let Some(sites) = index.recipient_sites.get(&bootstrap) {
                for site in sites {
                    let outcome = ctx.decode_slot(transactions, key, assets, *site)?;
                    if let Some(sender) = outcome.sender {
                        known_senders.entry(sender).or_insert(0);
                    }
                }
            }
            // Confidential default-zone scan: every confidential output is tagged by
            // the owner signing pubkey. Recipient slots and merge outputs live in
            // `recipient_sites`; the owner's own change rides the sender bundle in
            // `sender_sites` (decoded at slot 0).
            if let Some(sites) = index.recipient_sites.get(&owner_tag) {
                for site in sites {
                    ctx.decode_slot(transactions, key, assets, *site)?;
                }
            }
            if let Some(txs) = index.sender_sites.get(&owner_tag) {
                for &t in txs {
                    ctx.decode_slot(transactions, key, assets, (t, 0))?;
                }
            }

            let sender_hits = probe_sender_stream(&index, window, |n| key.get_sender_view_tag(n))?;
            if let Some((m, _)) = sender_hits.last() {
                *tx_count = *m + 1;
            }
            for (_, sites) in &sender_hits {
                for &t in sites {
                    let outcome = ctx.decode_slot(transactions, key, assets, (t, 0))?;
                    for pk in outcome.recipients {
                        known_recipients.entry(pk).or_insert(0);
                    }
                }
            }

            let request_hits =
                probe_recipient_stream(&index, window, |n| key.get_recipient_request_view_tag(n))?;
            if let Some((m, _)) = request_hits.last() {
                *request_count = *m + 1;
            }
            for (_, sites) in &request_hits {
                for site in sites {
                    if let Some(sender) = ctx.decode_slot(transactions, key, assets, *site)?.sender
                    {
                        known_senders.entry(sender).or_insert(0);
                    }
                }
            }

            let senders: Vec<P256Pubkey> = known_senders.keys().copied().collect();
            let shared_in: Vec<(P256Pubkey, StreamHits)> = senders
                .par_iter()
                .map(|s| {
                    probe_recipient_stream(&index, window, |n| {
                        key.get_recipient_shared_view_tag(s, n)
                    })
                    .map(|hits| (*s, hits))
                })
                .collect::<Result<_, _>>()?;
            for (s, hits) in &shared_in {
                if let Some((m, _)) = hits.last() {
                    known_senders.insert(*s, *m + 1);
                }
                for (_, sites) in hits {
                    for site in sites {
                        ctx.decode_slot(transactions, key, assets, *site)?;
                    }
                }
            }

            let recipients: Vec<P256Pubkey> = known_recipients.keys().copied().collect();
            let shared_out: Vec<(P256Pubkey, Option<u64>)> = recipients
                .par_iter()
                .map(|r| {
                    probe_presence_stream(&index, window, |n| key.get_send_shared_view_tag(r, n))
                        .map(|max| (*r, max))
                })
                .collect::<Result<_, _>>()?;
            for (r, max) in shared_out {
                if let Some(m) = max {
                    known_recipients.insert(r, m + 1);
                }
            }
        }

        let report = ctx.report;

        self.nullifiers.extend(
            transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied()),
        );
        for utxo in self.utxos.iter_mut() {
            if self.nullifiers.contains(&utxo.nullifier) {
                utxo.spent = true;
            }
        }
        self.transactions.sort_by(|a, b| {
            (a.id.slot, &a.id.signature, a.id.index).cmp(&(b.id.slot, &b.id.signature, b.id.index))
        });
        self.last_synced = synced_at;
        Ok(report)
    }
}
