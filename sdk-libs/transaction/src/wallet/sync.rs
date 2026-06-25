use std::collections::{HashMap, HashSet};

use zolana_event::OutputData;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{KeypairError, P256Pubkey, PublicKey, ShieldedKeypair, ViewingKey};

use crate::error::TransactionError;
use crate::instructions::transact::{OutputContext, ShieldedTransaction};
use crate::serialization::anonymous::{AnonymousRecipient, AnonymousSenderBundle};
use crate::serialization::confidential::{ConfidentialRecipient, ConfidentialSenderBundle};
use crate::serialization::merge::Merge;
use crate::serialization::plaintext::PlaintextTransfer;
use crate::serialization::proofless::Proofless;
use crate::serialization::split::Split;
use crate::serialization::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::utxo::Utxo;
use crate::AssetRegistry;
use crate::EncryptedScheme;

use super::state::{SyncReport, ViewingKeyEntry, Wallet, WalletUtxo};

pub(super) struct TxIndex {
    pub(super) sender_sites: HashMap<ViewTag, Vec<usize>>,
    pub(super) recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>>,
}

impl TxIndex {
    pub(super) fn build(transactions: &[ShieldedTransaction], report: &mut SyncReport) -> Self {
        let mut sender_sites: HashMap<ViewTag, Vec<usize>> = HashMap::new();
        let mut recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>> = HashMap::new();
        for (t, tx) in transactions.iter().enumerate() {
            let mut classified = false;
            for (slot_index, slot) in tx.output_slots.iter().enumerate() {
                let blob = match slot.output_data() {
                    Some(
                        OutputData::Encrypted(blob)
                        | OutputData::VerifiablyEncrypted(blob)
                        | OutputData::Plaintext(blob),
                    ) => blob,
                    None => continue,
                };
                let Some(scheme) = blob
                    .first()
                    .and_then(|b| EncryptedScheme::from_byte(*b).ok())
                else {
                    continue;
                };
                match scheme {
                    EncryptedScheme::AnonymousRecipient
                    | EncryptedScheme::ConfidentialRecipient
                    | EncryptedScheme::Proofless
                    | EncryptedScheme::PlaintextTransfer
                    | EncryptedScheme::Merge => {
                        recipient_sites
                            .entry(slot.view_tag)
                            .or_default()
                            .push((t, slot_index));
                        classified = true;
                    }
                    EncryptedScheme::AnonymousSender
                    | EncryptedScheme::ConfidentialSender
                    | EncryptedScheme::Split => {
                        sender_sites.entry(slot.view_tag).or_default().push(t);
                        classified = true;
                    }
                }
            }
            if !classified {
                report.unparsed_transactions += 1;
            }
        }
        Self {
            sender_sites,
            recipient_sites,
        }
    }
}

#[derive(Default)]
pub(super) struct SlotOutcome {
    pub(super) sender: Option<P256Pubkey>,
    pub(super) recipients: Vec<P256Pubkey>,
}

pub(super) struct SyncCtx<'a> {
    pub(super) keypair: &'a ShieldedKeypair,
    pub(super) owner: PublicKey,
    pub(super) nullifier_pk: [u8; 32],
    pub(super) utxos: &'a mut Vec<WalletUtxo>,
    pub(super) processed_slots: HashSet<(usize, usize)>,
    pub(super) report: SyncReport,
}

impl SyncCtx<'_> {
    fn push(&mut self, utxo: Utxo, output_context: OutputContext, nullifier: [u8; 32]) {
        self.utxos.push(WalletUtxo {
            utxo,
            output_context,
            nullifier,
            spent: false,
        });
        self.report.stored_utxos += 1;
    }

    fn store(&mut self, utxo: Utxo, output_context: OutputContext) -> Result<(), TransactionError> {
        if utxo.owner != self.owner {
            return Ok(());
        }
        if self
            .utxos
            .iter()
            .any(|stored| stored.output_context.hash == output_context.hash)
        {
            return Ok(());
        }
        let nullifier = utxo.nullifier(&output_context.hash, &self.keypair.nullifier_key)?;
        self.push(utxo, output_context, nullifier);
        Ok(())
    }

    fn store_in_tx(
        &mut self,
        utxo: Utxo,
        tx: &ShieldedTransaction,
    ) -> Result<(), TransactionError> {
        let hash = utxo.hash(&self.nullifier_pk, &[0u8; 32], &[0u8; 32])?;
        let Some(output_context) = tx
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == hash)
            .map(|slot| slot.output_context.clone())
        else {
            self.report.undecryptable_candidates += 1;
            return Ok(());
        };
        self.store(utxo, output_context)
    }

    /// Verify each 1:1 recipient utxo against the slot's committed leaf and store it.
    fn store_recipient_utxos(
        &mut self,
        utxos: Vec<Utxo>,
        output_context: &OutputContext,
        program_data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
    ) -> Result<bool, TransactionError> {
        let mut stored = false;
        for utxo in utxos {
            let hash = utxo.hash(&self.nullifier_pk, program_data_hash, zone_data_hash)?;
            if hash != output_context.hash {
                self.report.undecryptable_candidates += 1;
                continue;
            }
            self.store(utxo, output_context.clone())?;
            stored = true;
        }
        Ok(stored)
    }

    /// Decode one candidate slot, dispatching on its scheme byte. Recipient
    /// slots are 1:1 and verified against the slot's committed leaf; sender
    /// bundles (passed as slot 0) store their change against the whole
    /// transaction. The returned [`SlotOutcome`] carries the counterparty
    /// pubkeys that drive `known_senders` / `known_recipients`.
    pub(super) fn decode_slot(
        &mut self,
        transactions: &[ShieldedTransaction],
        key: &ViewingKey,
        assets: &AssetRegistry,
        site: (usize, usize),
    ) -> Result<SlotOutcome, TransactionError> {
        let mut outcome = SlotOutcome::default();
        if self.processed_slots.contains(&site) {
            return Ok(outcome);
        }
        let Some(tx) = transactions.get(site.0) else {
            self.report.undecryptable_candidates += 1;
            return Ok(outcome);
        };
        let Some(slot) = tx.output_slots.get(site.1) else {
            self.report.undecryptable_candidates += 1;
            return Ok(outcome);
        };
        let Some(output_data) = slot.output_data() else {
            self.report.undecryptable_candidates += 1;
            return Ok(outcome);
        };
        let output_context = slot.output_context.clone();
        let encrypted_slot_index = tx
            .output_slots
            .iter()
            .take(site.1 + 1)
            .filter(|slot| slot.output_data().is_some())
            .count()
            .saturating_sub(1) as u32;
        let cx = DecodeCx::for_slot(key, tx, encrypted_slot_index);
        let owner_cx = OwnerCx {
            owner: self.owner,
            assets,
            zone_program_id: None,
        };
        match output_data {
            OutputData::Plaintext(blob) => {
                let Some((&scheme_byte, body)) = blob.split_first() else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                match scheme {
                    EncryptedScheme::Proofless => {
                        let Ok(plaintext) = Proofless::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let program_data_hash = plaintext.program_data_hash.unwrap_or([0u8; 32]);
                        let zone_data_hash = plaintext.policy_data_hash.unwrap_or([0u8; 32]);
                        let Ok(utxos) = Proofless::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        if self.store_recipient_utxos(
                            utxos,
                            &output_context,
                            &program_data_hash,
                            &zone_data_hash,
                        )? {
                            self.processed_slots.insert(site);
                        }
                    }
                    EncryptedScheme::PlaintextTransfer => {
                        let Ok(plaintext) = PlaintextTransfer::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let Ok(utxos) = PlaintextTransfer::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        for utxo in utxos {
                            self.store_in_tx(utxo, tx)?;
                        }
                        self.processed_slots.insert(site);
                    }
                    _ => {
                        self.report.undecryptable_candidates += 1;
                    }
                }
            }
            OutputData::Encrypted(blob) => {
                let Some((&scheme_byte, body)) = blob.split_first() else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                match scheme {
                    EncryptedScheme::AnonymousRecipient => {
                        let Ok(plaintext) = AnonymousRecipient::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let sender = plaintext.sender_pubkey;
                        let Ok(utxos) = AnonymousRecipient::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        if self.store_recipient_utxos(
                            utxos,
                            &output_context,
                            &[0u8; 32],
                            &[0u8; 32],
                        )? {
                            self.processed_slots.insert(site);
                            outcome.sender = Some(sender);
                        }
                    }
                    EncryptedScheme::ConfidentialRecipient => {
                        let Ok(plaintext) = ConfidentialRecipient::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let Ok(utxos) = ConfidentialRecipient::into_utxos(plaintext, &owner_cx)
                        else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        if self.store_recipient_utxos(
                            utxos,
                            &output_context,
                            &[0u8; 32],
                            &[0u8; 32],
                        )? {
                            self.processed_slots.insert(site);
                        }
                    }
                    EncryptedScheme::AnonymousSender => {
                        let Ok(plaintext) = AnonymousSenderBundle::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let pks = plaintext.recipient_viewing_pks.clone();
                        let Ok(utxos) = AnonymousSenderBundle::into_utxos(plaintext, &owner_cx)
                        else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        for utxo in utxos {
                            self.store_in_tx(utxo, tx)?;
                        }
                        self.processed_slots.insert(site);
                        outcome.recipients = pks;
                    }
                    EncryptedScheme::ConfidentialSender => {
                        let Ok(plaintext) = ConfidentialSenderBundle::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let pks = plaintext.recipient_viewing_pks.clone();
                        let Ok(utxos) = ConfidentialSenderBundle::into_utxos(plaintext, &owner_cx)
                        else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        for utxo in utxos {
                            self.store_in_tx(utxo, tx)?;
                        }
                        self.processed_slots.insert(site);
                        outcome.recipients = pks;
                    }
                    EncryptedScheme::Split => {
                        let Ok(plaintext) = Split::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let Ok(utxos) = Split::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        for utxo in utxos {
                            self.store_in_tx(utxo, tx)?;
                        }
                        self.processed_slots.insert(site);
                    }
                    _ => {
                        self.report.undecryptable_candidates += 1;
                    }
                }
            }
            OutputData::VerifiablyEncrypted(blob) => {
                let Some((&scheme_byte, body)) = blob.split_first() else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                match scheme {
                    EncryptedScheme::Merge => {
                        let Ok(plaintext) = Merge::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let Ok(utxos) = Merge::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        if self.store_recipient_utxos(
                            utxos,
                            &output_context,
                            &[0u8; 32],
                            &[0u8; 32],
                        )? {
                            self.processed_slots.insert(site);
                        }
                    }
                    _ => {
                        self.report.undecryptable_candidates += 1;
                    }
                }
            }
        }
        Ok(outcome)
    }
}

fn scan_stream(
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
    mut visit: impl FnMut(&ViewTag) -> Result<bool, TransactionError>,
) -> Result<Option<u64>, TransactionError> {
    let mut max_present = None;
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if visit(&tag)? {
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
    pub fn sync(
        &mut self,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let mut report = SyncReport::default();
        let index = TxIndex::build(transactions, &mut report);

        let owner_tag = self.keypair.owner_hash()?;
        let mut ctx = SyncCtx {
            owner: self.keypair.signing_pubkey(),
            nullifier_pk: self.keypair.nullifier_key.pubkey()?,
            keypair: &self.keypair,
            utxos: &mut self.utxos,
            processed_slots: HashSet::new(),
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

            let bootstrap = key.recipient_bootstrap_view_tag();
            if let Some(sites) = index.recipient_sites.get(&bootstrap) {
                for site in sites {
                    let outcome = ctx.decode_slot(transactions, key, assets, *site)?;
                    if let Some(sender) = outcome.sender {
                        known_senders.entry(sender).or_insert(0);
                    }
                }
            }
            if let Some(sites) = index.recipient_sites.get(&owner_tag) {
                for site in sites {
                    ctx.decode_slot(transactions, key, assets, *site)?;
                }
            }

            let tx_max = scan_stream(
                window,
                |n| key.get_sender_view_tag(n),
                |tag| {
                    let Some(sites) = index.sender_sites.get(tag) else {
                        return Ok(false);
                    };
                    for &t in sites {
                        let outcome = ctx.decode_slot(transactions, key, assets, (t, 0))?;
                        for pk in outcome.recipients {
                            known_recipients.entry(pk).or_insert(0);
                        }
                    }
                    Ok(true)
                },
            )?;
            if let Some(m) = tx_max {
                *tx_count = m + 1;
            }

            let request_max = scan_stream(
                window,
                |n| key.get_recipient_request_view_tag(n),
                |tag| {
                    let Some(sites) = index.recipient_sites.get(tag) else {
                        return Ok(false);
                    };
                    for site in sites {
                        if let Some(sender) =
                            ctx.decode_slot(transactions, key, assets, *site)?.sender
                        {
                            known_senders.entry(sender).or_insert(0);
                        }
                    }
                    Ok(true)
                },
            )?;
            if let Some(m) = request_max {
                *request_count = m + 1;
            }

            let senders: Vec<P256Pubkey> = known_senders.keys().copied().collect();
            for s in senders {
                let max = scan_stream(
                    window,
                    |n| key.get_recipient_shared_view_tag(&s, n),
                    |tag| {
                        let Some(sites) = index.recipient_sites.get(tag) else {
                            return Ok(false);
                        };
                        for site in sites {
                            ctx.decode_slot(transactions, key, assets, *site)?;
                        }
                        Ok(true)
                    },
                )?;
                if let Some(m) = max {
                    known_senders.insert(s, m + 1);
                }
            }

            let recipients: Vec<P256Pubkey> = known_recipients.keys().copied().collect();
            for r in recipients {
                let max = scan_stream(
                    window,
                    |n| key.get_send_shared_view_tag(&r, n),
                    |tag| Ok(index.recipient_sites.contains_key(tag)),
                )?;
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
        self.last_synced = synced_at;
        Ok(report)
    }
}
