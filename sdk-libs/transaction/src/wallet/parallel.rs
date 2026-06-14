use std::collections::{HashMap, HashSet};
use std::mem;

use rayon::prelude::*;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{KeypairError, P256Pubkey, PublicKey};

use super::{
    ParsedBlob, SyncReport, SyncTransaction, TxIndex, ViewingKeyEntry, Wallet, WalletKeyProvider,
    WalletUtxo,
};
use crate::asset::AssetRegistry;
use crate::error::TransactionError;
use crate::utxo::Utxo;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Site {
    Sender(usize),
    Slot(usize, usize),
}

type StreamHits = Vec<(u64, Vec<Site>)>;
type PairStreams = Vec<(P256Pubkey, StreamHits)>;

enum SiteOutcome {
    Decrypted {
        utxos: Vec<WalletUtxo>,
        sender: Option<P256Pubkey>,
        recipients: Vec<P256Pubkey>,
        undecryptable: usize,
    },
    Failed,
}

struct DecryptEnv<'a, C: WalletKeyProvider + Sync> {
    index: &'a TxIndex,
    transactions: &'a [SyncTransaction],
    crypto: &'a C,
    assets: &'a AssetRegistry,
    owner: PublicKey,
    nullifier_pk: [u8; 32],
}

struct ReduceState<'a> {
    utxos: &'a mut Vec<WalletUtxo>,
    stored_hashes: HashSet<[u8; 32]>,
    consumed: HashSet<Site>,
    report: SyncReport,
}

enum Applied {
    Missed,
    Consumed(bool),
    Stored {
        sender: Option<P256Pubkey>,
        recipients: Vec<P256Pubkey>,
    },
}

fn probe_stream(
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
    lookup: impl Fn(&ViewTag) -> Option<Vec<Site>>,
) -> Result<StreamHits, TransactionError> {
    let mut hits = Vec::new();
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if let Some(sites) = lookup(&tag) {
                window_hit = true;
                hits.push((n, sites));
            }
        }
        if !window_hit || start.checked_add(window).is_none() {
            return Ok(hits);
        }
        start += window;
    }
}

fn sender_sites_for(index: &TxIndex, tag: &ViewTag) -> Option<Vec<Site>> {
    index
        .sender_sites
        .get(tag)
        .map(|txs| txs.iter().map(|&t| Site::Sender(t)).collect())
}

fn slot_sites_for(index: &TxIndex, tag: &ViewTag) -> Option<Vec<Site>> {
    index
        .recipient_sites
        .get(tag)
        .map(|sites| sites.iter().map(|&(t, slot)| Site::Slot(t, slot)).collect())
}

fn shared_out_sites_for(index: &TxIndex, tag: &ViewTag) -> Option<Vec<Site>> {
    index
        .recipient_sites
        .get(tag)
        .map(|sites| sites.iter().map(|&(t, _)| Site::Sender(t)).collect())
}

fn build_wallet_utxo<C: WalletKeyProvider + Sync>(
    env: &DecryptEnv<'_, C>,
    utxo: Utxo,
) -> Result<Option<WalletUtxo>, TransactionError> {
    if utxo.owner != env.owner {
        return Ok(None);
    }
    let hash = utxo.hash(&env.nullifier_pk, &[0u8; 32], &[0u8; 32])?;
    let nullifier = env.crypto.nullifier(&hash, &utxo.blinding)?;
    Ok(Some(WalletUtxo {
        utxo,
        hash,
        nullifier,
        spent: false,
    }))
}

fn decrypt_slot_site<C: WalletKeyProvider + Sync>(
    env: &DecryptEnv<'_, C>,
    t: usize,
    slot: usize,
) -> Result<SiteOutcome, TransactionError> {
    let Some(ParsedBlob::Transfer(blob)) = env.index.parsed.get(t) else {
        return Ok(SiteOutcome::Failed);
    };
    let Some(entry) = blob.recipient_slots.get(slot) else {
        return Ok(SiteOutcome::Failed);
    };
    let decrypted = env
        .crypto
        .decrypt_root_slot(
            &blob.tx_viewing_pk,
            &entry.ciphertext,
            blob.salt,
            slot as u32 + 1,
        )
        .and_then(|bytes| crate::transfer::TransferRecipientPlaintext::deserialize(&bytes))
        .and_then(|pt| {
            let sender = pt.sender_pubkey;
            pt.into_utxo(env.assets, None).map(|utxo| (sender, utxo))
        });
    let Ok((sender, utxo)) = decrypted else {
        return Ok(SiteOutcome::Failed);
    };
    Ok(SiteOutcome::Decrypted {
        utxos: build_wallet_utxo(env, utxo)?.into_iter().collect(),
        sender: Some(sender),
        recipients: Vec::new(),
        undecryptable: 0,
    })
}

fn decrypt_sender_site<C: WalletKeyProvider + Sync>(
    env: &DecryptEnv<'_, C>,
    t: usize,
) -> Result<SiteOutcome, TransactionError> {
    let Some(first_nullifier) = env.transactions.get(t).and_then(|tx| tx.nullifiers.first()) else {
        return Ok(SiteOutcome::Failed);
    };
    match env.index.parsed.get(t) {
        Some(ParsedBlob::Transfer(blob)) => {
            let Ok(sender_bytes) = env.crypto.decrypt_root_slot(
                &blob.tx_viewing_pk,
                &blob.sender_ciphertext,
                blob.salt,
                0,
            ) else {
                return Ok(SiteOutcome::Failed);
            };
            let Ok(sender) = crate::transfer::TransferSenderPlaintext::deserialize(&sender_bytes)
            else {
                return Ok(SiteOutcome::Failed);
            };
            if blob.recipient_slots.len() != sender.recipient_viewing_pks.len() {
                return Ok(SiteOutcome::Failed);
            }

            let recipients = sender.recipient_viewing_pks.clone();
            let Ok(change) = sender.into_utxos(env.assets, None) else {
                return Ok(SiteOutcome::Failed);
            };
            let mut utxos = Vec::new();
            for utxo in change {
                utxos.extend(build_wallet_utxo(env, utxo)?);
            }

            let mut undecryptable = 0;
            for (i, (slot, pubkey)) in blob.recipient_slots.iter().zip(&recipients).enumerate() {
                let decrypted = env
                    .crypto
                    .decrypt_transaction_slot(
                        first_nullifier,
                        pubkey,
                        &slot.ciphertext,
                        blob.salt,
                        i as u32 + 1,
                    )
                    .and_then(|bytes| {
                        crate::transfer::TransferRecipientPlaintext::deserialize(&bytes)
                    });
                let Ok(pt) = decrypted else {
                    undecryptable += 1;
                    continue;
                };
                if pt.owner_pubkey != env.owner {
                    continue;
                }
                match pt.into_utxo(env.assets, None) {
                    Ok(utxo) => utxos.extend(build_wallet_utxo(env, utxo)?),
                    Err(_) => undecryptable += 1,
                }
            }

            Ok(SiteOutcome::Decrypted {
                utxos,
                sender: None,
                recipients,
                undecryptable,
            })
        }
        Some(ParsedBlob::Split(blob)) => {
            let decrypted = env
                .crypto
                .decrypt_root_slot(&blob.tx_viewing_pk, &blob.ciphertext, blob.salt, 0)
                .and_then(|bytes| crate::split::SplitBundlePlaintext::deserialize(&bytes))
                .and_then(|bundle| bundle.into_utxos(env.assets, None));
            let Ok(outputs) = decrypted else {
                return Ok(SiteOutcome::Failed);
            };
            let mut utxos = Vec::new();
            for utxo in outputs {
                utxos.extend(build_wallet_utxo(env, utxo)?);
            }
            Ok(SiteOutcome::Decrypted {
                utxos,
                sender: None,
                recipients: Vec::new(),
                undecryptable: 0,
            })
        }
        _ => Ok(SiteOutcome::Failed),
    }
}

fn decrypt_site<C: WalletKeyProvider + Sync>(
    env: &DecryptEnv<'_, C>,
    site: Site,
) -> Result<SiteOutcome, TransactionError> {
    match site {
        Site::Sender(t) => decrypt_sender_site(env, t),
        Site::Slot(t, slot) => decrypt_slot_site(env, t, slot),
    }
}

fn decrypt_new_sites<C: WalletKeyProvider + Sync>(
    env: &DecryptEnv<'_, C>,
    outcomes: &mut HashMap<Site, SiteOutcome>,
    consumed: &HashSet<Site>,
    occurrences: impl Iterator<Item = Site>,
) -> Result<(), TransactionError> {
    let mut seen = HashSet::new();
    let mut sites = Vec::new();
    for site in occurrences {
        if consumed.contains(&site) || outcomes.contains_key(&site) || !seen.insert(site) {
            continue;
        }
        sites.push(site);
    }
    let decrypted = sites
        .par_iter()
        .map(|&site| decrypt_site(env, site).map(|outcome| (site, outcome)))
        .collect::<Result<Vec<_>, TransactionError>>()?;
    outcomes.extend(decrypted);
    Ok(())
}

impl ReduceState<'_> {
    fn store(&mut self, utxo: WalletUtxo) {
        if self.stored_hashes.insert(utxo.hash) {
            self.utxos.push(utxo);
            self.report.stored_utxos += 1;
        }
    }

    fn apply(&mut self, outcomes: &mut HashMap<Site, SiteOutcome>, site: Site) -> Applied {
        if self.consumed.contains(&site) {
            return Applied::Consumed(matches!(site, Site::Sender(_)));
        }
        match outcomes.get_mut(&site) {
            Some(SiteOutcome::Decrypted {
                utxos,
                sender,
                recipients,
                undecryptable,
            }) => {
                for utxo in mem::take(utxos) {
                    self.store(utxo);
                }
                self.report.undecryptable_candidates += *undecryptable;
                let applied = Applied::Stored {
                    sender: *sender,
                    recipients: mem::take(recipients),
                };
                self.consumed.insert(site);
                applied
            }
            _ => {
                self.report.undecryptable_candidates += 1;
                Applied::Missed
            }
        }
    }
}

fn reduce_stream(
    state: &mut ReduceState<'_>,
    outcomes: &mut HashMap<Site, SiteOutcome>,
    hits: &[(u64, Vec<Site>)],
    mut on_stored: impl FnMut(Option<P256Pubkey>, Vec<P256Pubkey>),
) -> Option<u64> {
    let mut max_success = None;
    for (n, sites) in hits {
        let mut decrypted = false;
        for &site in sites {
            match state.apply(outcomes, site) {
                Applied::Stored { sender, recipients } => {
                    decrypted = true;
                    on_stored(sender, recipients);
                }
                Applied::Consumed(success) => {
                    if success {
                        decrypted = true;
                    }
                }
                Applied::Missed => {}
            }
        }
        if decrypted {
            max_success = Some(*n);
        }
    }
    max_success
}

impl Wallet {
    pub fn sync_parallel<C: WalletKeyProvider + Sync>(
        &mut self,
        crypto: &C,
        transactions: &[SyncTransaction],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let mut report = SyncReport::default();
        let index = TxIndex::build(transactions, &mut report);
        let stored_hashes: HashSet<[u8; 32]> = self.utxos.iter().map(|u| u.hash).collect();
        let mut state = ReduceState {
            utxos: &mut self.utxos,
            stored_hashes,
            consumed: HashSet::new(),
            report,
        };
        let owner = self.signing_pubkey;
        let nullifier_pk = self.nullifier_pubkey;

        for entry in self.viewing_key_history.iter_mut() {
            let ViewingKeyEntry {
                tx_count,
                request_count,
                known_senders,
                known_recipients,
                ..
            } = entry;
            let env = DecryptEnv {
                index: &index,
                transactions,
                crypto,
                assets,
                owner,
                nullifier_pk,
            };
            let mut outcomes: HashMap<Site, SiteOutcome> = HashMap::new();

            let bootstrap_sites: Vec<Site> = index
                .recipient_sites
                .get(&crypto.recipient_bootstrap_view_tag())
                .map(|sites| sites.iter().map(|&(t, slot)| Site::Slot(t, slot)).collect())
                .unwrap_or_default();

            let sender_hits = probe_stream(
                window,
                |n| crypto.get_sender_view_tag(n),
                |tag| sender_sites_for(&index, tag),
            )?;
            let request_hits = probe_stream(
                window,
                |n| crypto.get_recipient_request_view_tag(n),
                |tag| slot_sites_for(&index, tag),
            )?;

            decrypt_new_sites(
                &env,
                &mut outcomes,
                &state.consumed,
                bootstrap_sites
                    .iter()
                    .copied()
                    .chain(sender_hits.iter().flat_map(|(_, s)| s.iter().copied()))
                    .chain(request_hits.iter().flat_map(|(_, s)| s.iter().copied())),
            )?;

            for site in bootstrap_sites {
                if let Applied::Stored {
                    sender: Some(pk), ..
                } = state.apply(&mut outcomes, site)
                {
                    known_senders.entry(pk).or_insert(0);
                }
            }

            let max_sender =
                reduce_stream(&mut state, &mut outcomes, &sender_hits, |_, recipients| {
                    for pk in recipients {
                        known_recipients.entry(pk).or_insert(0);
                    }
                });
            if let Some(m) = max_sender {
                *tx_count = m + 1;
            }

            let max_request =
                reduce_stream(&mut state, &mut outcomes, &request_hits, |sender, _| {
                    if let Some(pk) = sender {
                        known_senders.entry(pk).or_insert(0);
                    }
                });
            if let Some(m) = max_request {
                *request_count = m + 1;
            }

            let mut senders: Vec<P256Pubkey> = known_senders.keys().copied().collect();
            senders.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let mut recipients: Vec<P256Pubkey> = known_recipients.keys().copied().collect();
            recipients.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            let shared_in: PairStreams = senders
                .par_iter()
                .map(|s| {
                    probe_stream(
                        window,
                        |n| crypto.get_recipient_shared_view_tag(s, n),
                        |tag| slot_sites_for(&index, tag),
                    )
                    .map(|hits| (*s, hits))
                })
                .collect::<Result<_, _>>()?;
            let shared_out: PairStreams = recipients
                .par_iter()
                .map(|r| {
                    probe_stream(
                        window,
                        |n| crypto.get_send_shared_view_tag(r, n),
                        |tag| shared_out_sites_for(&index, tag),
                    )
                    .map(|hits| (*r, hits))
                })
                .collect::<Result<_, _>>()?;

            decrypt_new_sites(
                &env,
                &mut outcomes,
                &state.consumed,
                shared_in
                    .iter()
                    .flat_map(|(_, hits)| hits.iter().flat_map(|(_, s)| s.iter().copied()))
                    .chain(
                        shared_out
                            .iter()
                            .flat_map(|(_, hits)| hits.iter().flat_map(|(_, s)| s.iter().copied())),
                    ),
            )?;

            for (s, hits) in &shared_in {
                if let Some(m) = reduce_stream(&mut state, &mut outcomes, hits, |_, _| {}) {
                    known_senders.insert(*s, m + 1);
                }
            }
            for (r, hits) in &shared_out {
                let max = reduce_stream(&mut state, &mut outcomes, hits, |_, recipients| {
                    for pk in recipients {
                        known_recipients.entry(pk).or_insert(0);
                    }
                });
                if let Some(m) = max {
                    known_recipients.insert(*r, m + 1);
                }
            }
        }

        let report = state.report;
        for utxo in self.utxos.iter_mut() {
            if index.nullifiers.contains(&utxo.nullifier) {
                utxo.spent = true;
            }
        }
        self.last_synced = synced_at;
        Ok(report)
    }
}
