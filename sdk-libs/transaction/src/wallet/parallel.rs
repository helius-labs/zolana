use std::collections::HashSet;

use rayon::prelude::*;
use zolana_keypair::{viewing_key::ViewTag, KeypairError, P256Pubkey, ViewingKey};

use super::{
    state::{SyncReport, ViewingKeyEntry, Wallet},
    sync::{SyncCtx, TxIndex},
};
use crate::{error::TransactionError, instructions::transact::ShieldedTransaction, AssetRegistry};

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
    pub fn sync_parallel(
        &mut self,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let mut report = SyncReport::default();
        let index = TxIndex::build(transactions, &mut report);

        let owner_tag = self.keypair.signing_pubkey().confidential_view_tag()?;
        let mut ctx = SyncCtx {
            owner: self.keypair.signing_pubkey(),
            nullifier_pk: self.keypair.nullifier_key.pubkey()?,
            keypair: &self.keypair,
            utxos: &mut self.utxos,
            transactions: &mut self.transactions,
            processed_slots: HashSet::new(),
            processed_outbound: HashSet::new(),
            record_history: true,
            report,
        };

        for entry in self.viewing_key_history.iter_mut() {
            let ViewingKeyEntry {
                key,
                tx_count,
                request_count,
                known_senders,
                known_recipients,
                ..
            } = entry;
            let key: &ViewingKey = key;

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
