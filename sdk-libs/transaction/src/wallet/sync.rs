use std::collections::{HashMap, HashSet};

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_keypair::{
    hash::owner_hash, viewing_key::ViewTag, KeypairError, NullifierKey, P256Pubkey, PublicKey,
    ViewingKey,
};

use super::state::{
    Balances, CursorStream, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus, SyncReport, ViewingKeyEntry, Wallet,
    WalletUtxo, DEFAULT_TAG_WINDOW, SENDER_HISTORY_ROW_BASE,
};

use crate::{
    data::Data,
    error::TransactionError,
    instructions::{
        merge::{merge_dummy_nullifier, merge_output_blinding},
        transact::{OutputContext, ShieldedTransaction, SENDER_SLOT_COUNT},
    },
    serialization::{
        anonymous::{AnonymousRecipient, AnonymousSenderBundle},
        confidential::Confidential,
        plaintext::PlaintextTransfer,
        proofless::Proofless,
        ring_deposit::RingDepositPlaintext,
        split::Split,
        DecodeCx, OwnerCx, UtxoSerialization,
    },
    utxo::Utxo,
    AssetRegistry, EncryptedScheme, SyncWalletAuthority, WalletSyncMaterial,
};

pub(super) struct TxIndex {
    pub(super) sender_sites: HashMap<ViewTag, Vec<usize>>,
    pub(super) recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>>,
    pub(super) merge_sites: HashMap<ViewTag, Vec<(usize, usize)>>,
}

/// A merge publishes no per-transaction encryption material: no
/// `tx_viewing_pk`, no `salt`, and it is not a proofless deposit. The index and
/// the decoder must agree on this test, or a site routed to the merge path
/// would be decoded with a viewing key it has no ciphertext for.
fn is_merge_site(tx: &ShieldedTransaction) -> bool {
    !tx.proofless && tx.tx_viewing_pk.is_none() && tx.salt.is_none()
}

impl TxIndex {
    pub(super) fn build(transactions: &[ShieldedTransaction], report: &mut SyncReport) -> Self {
        let mut sender_sites: HashMap<ViewTag, Vec<usize>> = HashMap::new();
        let mut recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>> = HashMap::new();
        let mut merge_sites: HashMap<ViewTag, Vec<(usize, usize)>> = HashMap::new();
        for (t, tx) in transactions.iter().enumerate() {
            let mut classified = false;
            if is_merge_site(tx) {
                for (slot_index, slot) in tx.output_slots.iter().enumerate() {
                    merge_sites
                        .entry(slot.view_tag)
                        .or_default()
                        .push((t, slot_index));
                    classified = true;
                }
                if !classified {
                    report.unparsed_transactions += 1;
                }
                continue;
            }
            for (slot_index, slot) in tx.output_slots.iter().enumerate() {
                let blob = match slot.output_data() {
                    Some(
                        OutputDataEncoding::Encrypted(blob)
                        | OutputDataEncoding::VerifiablyEncrypted(blob)
                        | OutputDataEncoding::Plaintext(blob),
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
                    | EncryptedScheme::Confidential
                    | EncryptedScheme::RingConfidential
                    | EncryptedScheme::Proofless
                    | EncryptedScheme::PlaintextTransfer
                    | EncryptedScheme::Merge
                    | EncryptedScheme::RingDeposit => {
                        recipient_sites
                            .entry(slot.view_tag)
                            .or_default()
                            .push((t, slot_index));
                        classified = true;
                    }
                    EncryptedScheme::AnonymousSender | EncryptedScheme::Split => {
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
            merge_sites,
        }
    }
}

#[derive(Default)]
pub(super) struct SlotOutcome {
    pub(super) sender: Option<P256Pubkey>,
    pub(super) recipients: Vec<P256Pubkey>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MergeResolution {
    Complete,
    Pending,
}

pub(super) struct SyncCtx<'a> {
    pub(super) nullifier_key: &'a NullifierKey,
    /// Every viewing key this wallet has held, current and rotated-out. A
    /// transfer addressed to a retired key is still addressed to this wallet,
    /// so `self`-recognition must not narrow to the current key.
    pub(super) self_viewing_pubkeys: HashSet<P256Pubkey>,
    pub(super) owner: PublicKey,
    pub(super) nullifier_pk: [u8; 32],
    pub(super) utxos: &'a mut Vec<WalletUtxo>,
    pub(super) transactions: &'a mut Vec<PrivateTransaction>,
    pub(super) processed_slots: HashSet<(usize, usize)>,
    pub(super) processed_outbound: HashSet<usize>,
    pub(super) report: SyncReport,
}

impl SyncCtx<'_> {
    fn push(
        &mut self,
        utxo: Utxo,
        output_context: OutputContext,
        nullifier: [u8; 32],
        data_hash: Option<[u8; 32]>,
        ring_data_hash: Option<[u8; 32]>,
    ) {
        self.utxos.push(WalletUtxo {
            utxo,
            output_context,
            nullifier,
            data_hash,
            ring_data_hash,
            spent: false,
        });
        self.report.stored_utxos += 1;
    }

    fn store(
        &mut self,
        utxo: Utxo,
        output_context: OutputContext,
        data_hash: Option<[u8; 32]>,
        ring_data_hash: Option<[u8; 32]>,
    ) -> Result<bool, TransactionError> {
        if utxo.owner != self.owner {
            return Ok(false);
        }
        if self
            .utxos
            .iter()
            .any(|stored| stored.output_context.hash == output_context.hash)
        {
            return Ok(false);
        }
        let nullifier = utxo.nullifier(&output_context.hash, self.nullifier_key)?;
        self.push(utxo, output_context, nullifier, data_hash, ring_data_hash);
        Ok(true)
    }

    fn store_in_tx(
        &mut self,
        utxo: Utxo,
        tx: &ShieldedTransaction,
    ) -> Result<bool, TransactionError> {
        let hash = utxo.hash(&self.nullifier_pk, &[0u8; 32], &[0u8; 32])?;
        let Some(output_context) = tx
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == hash)
            .map(|slot| slot.output_context.clone())
        else {
            self.report.undecryptable_candidates += 1;
            return Ok(false);
        };
        self.store(utxo, output_context, None, None)
    }

    /// Keyed on identity and amounts, not on `direction` or `status`: a rescan
    /// must overwrite a row whose classification has since been refined (an
    /// outbound row later recognized as a self transfer) rather than add a
    /// second row for the same event.
    fn record(&mut self, tx: PrivateTransaction) {
        let stored = self.transactions.iter_mut().find(|stored| {
            stored.id == tx.id
                && stored.kind == tx.kind
                && stored.asset == tx.asset
                && stored.amount == tx.amount
                && stored.counterparty_viewing_pubkey == tx.counterparty_viewing_pubkey
        });
        match stored {
            Some(stored) => *stored = tx,
            None => self.transactions.push(tx),
        }
    }

    fn is_self(&self, viewing_pubkey: &P256Pubkey) -> bool {
        self.self_viewing_pubkeys.contains(viewing_pubkey)
    }

    /// A transfer whose every real recipient is this wallet moved nothing out,
    /// so it is a self transfer on any rail. An empty recipient set stays
    /// outbound: that is a public withdrawal, and the value did leave.
    fn transfer_direction(&self, recipients: &[P256Pubkey]) -> PrivateTransactionDirection {
        if !recipients.is_empty() && recipients.iter().all(|recipient| self.is_self(recipient)) {
            PrivateTransactionDirection::SelfTransfer
        } else {
            PrivateTransactionDirection::Outbound
        }
    }

    fn spent_amounts(&self, nullifiers: &[[u8; 32]]) -> HashMap<Address, u64> {
        let nullifiers = nullifiers.iter().copied().collect::<HashSet<_>>();
        let mut by_asset = HashMap::new();
        for wallet_utxo in self
            .utxos
            .iter()
            .filter(|utxo| nullifiers.contains(&utxo.nullifier))
        {
            let entry = by_asset.entry(wallet_utxo.utxo.asset).or_insert(0u64);
            *entry = entry.saturating_add(wallet_utxo.utxo.amount);
        }
        by_asset
    }

    fn record_received(
        &mut self,
        tx: &ShieldedTransaction,
        slot_index: usize,
        sender: Option<P256Pubkey>,
        utxo: &Utxo,
    ) {
        let direction = match sender {
            Some(sender) if self.is_self(&sender) => PrivateTransactionDirection::SelfTransfer,
            _ => PrivateTransactionDirection::Inbound,
        };
        let index = tx
            .output_slots
            .get(slot_index)
            .map(|slot| slot.output_context.leaf_index)
            .unwrap_or(slot_index as u64);
        self.record(PrivateTransaction {
            id: PrivateTransactionId {
                signature: tx.tx_signature.to_string(),
                slot: tx.slot,
                index,
            },
            kind: PrivateTransactionKind::PrivateTransfer,
            direction,
            status: PrivateTransactionStatus::Confirmed,
            asset: utxo.asset,
            amount: utxo.amount,
            counterparty_viewing_pubkey: sender,
        });
    }

    fn record_deposit(
        &mut self,
        tx: &ShieldedTransaction,
        output_context: &OutputContext,
        utxo: &Utxo,
    ) {
        self.record(PrivateTransaction {
            id: PrivateTransactionId {
                signature: tx.tx_signature.to_string(),
                slot: tx.slot,
                index: output_context.leaf_index,
            },
            kind: PrivateTransactionKind::Deposit,
            direction: PrivateTransactionDirection::Inbound,
            status: PrivateTransactionStatus::Confirmed,
            asset: utxo.asset,
            amount: utxo.amount,
            counterparty_viewing_pubkey: None,
        });
    }

    fn record_outbound_transfer(
        &mut self,
        tx: &ShieldedTransaction,
        spent: HashMap<Address, u64>,
        change: &[Utxo],
        kind: PrivateTransactionKind,
        counterparty: Option<P256Pubkey>,
        direction: PrivateTransactionDirection,
    ) {
        let mut by_asset = spent;
        for utxo in change {
            if let Some(total) = by_asset.get_mut(&utxo.asset) {
                *total = total.saturating_sub(utxo.amount);
            }
        }
        let mut rows = by_asset.into_iter().collect::<Vec<_>>();
        rows.sort_by_key(|(asset, _)| *asset);
        for (row, (asset, amount)) in rows.into_iter().enumerate() {
            if amount == 0 {
                continue;
            }
            self.record(PrivateTransaction {
                id: PrivateTransactionId {
                    signature: tx.tx_signature.to_string(),
                    slot: tx.slot,
                    index: SENDER_HISTORY_ROW_BASE + row as u64,
                },
                kind,
                direction,
                status: PrivateTransactionStatus::Confirmed,
                asset,
                amount,
                counterparty_viewing_pubkey: counterparty,
            });
        }
    }

    fn record_split(&mut self, tx: &ShieldedTransaction, spent: HashMap<Address, u64>) {
        let mut rows = spent.into_iter().collect::<Vec<_>>();
        rows.sort_by_key(|(asset, _)| *asset);
        for (row, (asset, amount)) in rows.into_iter().enumerate() {
            if amount == 0 {
                continue;
            }
            self.record(PrivateTransaction {
                id: PrivateTransactionId {
                    signature: tx.tx_signature.to_string(),
                    slot: tx.slot,
                    index: SENDER_HISTORY_ROW_BASE + row as u64,
                },
                kind: PrivateTransactionKind::Split,
                direction: PrivateTransactionDirection::SelfTransfer,
                status: PrivateTransactionStatus::Confirmed,
                asset,
                amount,
                counterparty_viewing_pubkey: None,
            });
        }
    }

    fn record_merge(
        &mut self,
        tx: &ShieldedTransaction,
        output_context: &OutputContext,
        utxo: &Utxo,
    ) {
        self.record(PrivateTransaction {
            id: PrivateTransactionId {
                signature: tx.tx_signature.to_string(),
                slot: tx.slot,
                index: output_context.leaf_index,
            },
            kind: PrivateTransactionKind::Merge,
            direction: PrivateTransactionDirection::SelfTransfer,
            status: PrivateTransactionStatus::Confirmed,
            asset: utxo.asset,
            amount: utxo.amount,
            counterparty_viewing_pubkey: None,
        });
    }

    /// Verify each 1:1 recipient utxo against the slot's committed leaf and store it.
    fn store_recipient_utxos(
        &mut self,
        utxos: Vec<Utxo>,
        output_context: &OutputContext,
        data_hash: Option<[u8; 32]>,
        ring_data_hash: Option<[u8; 32]>,
    ) -> Result<bool, TransactionError> {
        let mut stored = false;
        for utxo in utxos {
            let hash = utxo.hash(
                &self.nullifier_pk,
                &data_hash.unwrap_or([0u8; 32]),
                &ring_data_hash.unwrap_or([0u8; 32]),
            )?;
            if hash != output_context.hash {
                self.report.undecryptable_candidates += 1;
                continue;
            }
            self.store(utxo, output_context.clone(), data_hash, ring_data_hash)?;
            stored = true;
        }
        Ok(stored)
    }

    /// Record a slot that failed to turn its plaintext into UTXOs. Counts it as
    /// an undecryptable candidate and, when the failure was an unknown asset id,
    /// remembers the id so the client sync layer can backfill the registry and
    /// retry. `resolve()` is the only source of `UnknownAsset`, so this is the
    /// single seam where a stale registry surfaces during decode.
    fn note_undecryptable(&mut self, err: &TransactionError) {
        if let TransactionError::UnknownAsset(id) = err {
            self.report.unknown_asset_ids.insert(*id);
        }
        self.report.undecryptable_candidates += 1;
    }

    /// Whether `key` is the viewing key that authored `tx`: the transaction
    /// viewing key derived from the first nullifier reproduces the published
    /// `tx_viewing_pk` only for the spending wallet.
    fn authored(tx: &ShieldedTransaction, key: &ViewingKey) -> Result<bool, TransactionError> {
        match (tx.tx_viewing_pk, tx.nullifiers.first()) {
            (Some(published_pk), Some(first_nullifier)) => {
                Ok(key.get_transaction_viewing_key(first_nullifier)?.pubkey() == published_pk)
            }
            _ => Ok(false),
        }
    }

    fn record_confidential_send(
        &mut self,
        tx: &ShieldedTransaction,
        t: usize,
        key: &ViewingKey,
        assets: &AssetRegistry,
        known_recipients: &mut HashMap<P256Pubkey, u64>,
    ) -> Result<(), TransactionError> {
        let (Some(published_pk), Some(first_nullifier), Some(salt)) =
            (tx.tx_viewing_pk, tx.nullifiers.first(), tx.salt)
        else {
            return Ok(());
        };
        let tx_key = key.get_transaction_viewing_key(first_nullifier)?;
        if tx_key.pubkey() != published_pk {
            return Ok(());
        }
        if !self.processed_outbound.insert(t) {
            return Ok(());
        }

        let mut change = Vec::new();
        let mut recipient_pks = Vec::new();
        for (position, slot) in tx.output_slots.iter().enumerate() {
            let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
                continue;
            };
            let Some((&scheme_byte, body)) = blob.split_first() else {
                continue;
            };
            if !matches!(
                EncryptedScheme::from_byte(scheme_byte),
                Ok(EncryptedScheme::Confidential | EncryptedScheme::RingConfidential)
            ) {
                continue;
            }
            let encrypted_slot_index = position as u32;
            let Ok(plaintext) =
                Confidential::decrypt_with_tx_key(&tx_key, body, salt, encrypted_slot_index)
            else {
                continue;
            };
            let Ok(recipient_pk) = Confidential::embedded_viewing_pk(body) else {
                continue;
            };
            // Change sits in sender slots only, a send to self keeps its recipient rows.
            if position < SENDER_SLOT_COUNT && recipient_pk == key.pubkey() {
                if let Ok(candidate) = plaintext.into_utxo(self.owner, assets) {
                    let matches_commitment = candidate
                        .hash(&self.nullifier_pk, &[0; 32], &[0; 32])
                        .is_ok_and(|hash| hash == slot.output_context.hash);
                    if matches_commitment {
                        change.push(candidate);
                        continue;
                    }
                }
            }
            recipient_pks.push(recipient_pk);
        }

        let spent = self.spent_amounts(&tx.nullifiers);
        let kind = if recipient_pks.is_empty() {
            PrivateTransactionKind::PublicWithdrawal
        } else {
            PrivateTransactionKind::PrivateTransfer
        };
        let counterparty = (recipient_pks.len() == 1)
            .then(|| recipient_pks.first().copied())
            .flatten();
        let direction = self.transfer_direction(&recipient_pks);
        self.record_outbound_transfer(tx, spent, &change, kind, counterparty, direction);
        for pubkey in recipient_pks {
            known_recipients.entry(pubkey).or_insert(0);
        }
        Ok(())
    }

    fn decode_merge_site(
        &mut self,
        transactions: &[ShieldedTransaction],
        site: (usize, usize),
    ) -> Result<MergeResolution, TransactionError> {
        if self.processed_slots.contains(&site) {
            return Ok(MergeResolution::Complete);
        }
        let Some(tx) = transactions.get(site.0) else {
            self.report.undecryptable_candidates += 1;
            return Ok(MergeResolution::Complete);
        };
        if tx.output_slots.get(site.1).is_none() || !is_merge_site(tx) {
            self.report.undecryptable_candidates += 1;
            return Ok(MergeResolution::Complete);
        }
        self.reconstruct_merge(tx, site)
    }

    fn resolve_merge_sites(
        &mut self,
        transactions: &[ShieldedTransaction],
        sites: &[(usize, usize)],
    ) -> Result<(), TransactionError> {
        let mut pending = sites.to_vec();
        while !pending.is_empty() {
            let pending_count = pending.len();
            let mut unresolved = Vec::new();
            for site in pending {
                if self.decode_merge_site(transactions, site)? == MergeResolution::Pending {
                    unresolved.push(site);
                }
            }
            if unresolved.len() == pending_count {
                self.report.undecryptable_candidates += unresolved.len();
                break;
            }
            pending = unresolved;
        }
        Ok(())
    }

    /// Decode one candidate slot, dispatching on its scheme byte. Recipient and
    /// confidential slots are 1:1 and verified against the slot's committed leaf;
    /// the anonymous/split sender bundles (passed as slot 0) store their change
    /// against the whole transaction. The returned [`SlotOutcome`] carries the
    /// counterparty pubkeys that drive `known_senders` / `known_recipients`.
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
        let encrypted_slot_index = site.1 as u32;
        let cx = DecodeCx::for_slot(key, tx, encrypted_slot_index);
        let owner_cx = OwnerCx {
            owner: self.owner,
            assets,
            ring_program_id: None,
            first_nullifier: cx.first_nullifier,
        };
        match output_data {
            OutputDataEncoding::Plaintext(blob) => {
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
                        let data_hash = plaintext.data_hash;
                        let ring_data_hash = plaintext.ring_data_hash;
                        let Ok(utxos) = Proofless::into_utxos(plaintext, &owner_cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        if self.store_recipient_utxos(
                            utxos.clone(),
                            &output_context,
                            data_hash,
                            ring_data_hash,
                        )? {
                            self.processed_slots.insert(site);
                            if let Some(utxo) = utxos.first() {
                                self.record_deposit(tx, &output_context, utxo);
                            }
                        }
                    }
                    EncryptedScheme::PlaintextTransfer => {
                        let Ok(plaintext) = PlaintextTransfer::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let utxos = match PlaintextTransfer::into_utxos(plaintext, &owner_cx) {
                            Ok(utxos) => utxos,
                            Err(err) => {
                                self.note_undecryptable(&err);
                                return Ok(outcome);
                            }
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
            OutputDataEncoding::Encrypted(blob) => {
                let Some((&scheme_byte, body)) = blob.split_first() else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(outcome);
                };
                match scheme {
                    EncryptedScheme::RingDeposit => {
                        let Ok(output) = EncryptedRingDepositOutput::try_from_slice(body) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let Ok(plaintext) = RingDepositPlaintext::decrypt(&output.encrypted, key)
                        else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let owner = owner_hash(&self.owner, &self.nullifier_pk)?;
                        let actual_owner_utxo_hash =
                            crate::owner_utxo_hash(&owner, &plaintext.blinding)?;
                        if actual_owner_utxo_hash != output.owner_utxo_hash {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        }
                        let utxo = plaintext.into_utxo(
                            self.owner,
                            Address::new_from_array(output.asset),
                            output.amount,
                            Address::new_from_array(output.ring_program_id),
                        );
                        if self.store_recipient_utxos(
                            vec![utxo.clone()],
                            &output_context,
                            output.data_hash,
                            Some(output.ring_data_hash),
                        )? {
                            self.processed_slots.insert(site);
                            self.record_deposit(tx, &output_context, &utxo);
                        }
                    }
                    EncryptedScheme::AnonymousRecipient => {
                        let Ok(plaintext) = AnonymousRecipient::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let sender = plaintext.sender_pubkey;
                        let utxos = match AnonymousRecipient::into_utxos(plaintext, &owner_cx) {
                            Ok(utxos) => utxos,
                            Err(err) => {
                                self.note_undecryptable(&err);
                                return Ok(outcome);
                            }
                        };
                        if self.store_recipient_utxos(utxos.clone(), &output_context, None, None)? {
                            self.processed_slots.insert(site);
                            outcome.sender = Some(sender);
                            if let Some(utxo) = utxos.first() {
                                // Per-slot, unlike the confidential rail, which
                                // suppresses an authored slot's receipt: an
                                // anonymous recipient slot names its sender, so
                                // a self-send's receipt carries the sender the
                                // sender-bundle row cannot show per recipient.
                                self.record_received(tx, site.1, Some(sender), utxo);
                            }
                        }
                    }
                    EncryptedScheme::Confidential | EncryptedScheme::RingConfidential => {
                        let Ok(plaintext) = Confidential::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let utxos = match Confidential::into_utxos(plaintext, &owner_cx) {
                            Ok(utxos) => utxos,
                            Err(err) => {
                                self.note_undecryptable(&err);
                                return Ok(outcome);
                            }
                        };
                        if self.store_recipient_utxos(utxos.clone(), &output_context, None, None)? {
                            self.processed_slots.insert(site);
                            // A slot the wallet itself authored is its own change or
                            // self-send output; its outbound history is recorded once
                            // per transaction by `record_confidential_send`, so
                            // it must not also be logged here as an inbound receipt.
                            if !Self::authored(tx, key)? {
                                if let Some(utxo) = utxos.first() {
                                    self.record_received(tx, site.1, None, utxo);
                                }
                            }
                        }
                    }
                    EncryptedScheme::AnonymousSender => {
                        let Ok(plaintext) = AnonymousSenderBundle::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let pks = plaintext.recipient_viewing_pks.clone();
                        let real_recipient_count = pks.len();
                        let change = match AnonymousSenderBundle::into_utxos(plaintext, &owner_cx) {
                            Ok(change) => change,
                            Err(err) => {
                                self.note_undecryptable(&err);
                                return Ok(outcome);
                            }
                        };
                        for utxo in &change {
                            self.store_in_tx(utxo.clone(), tx)?;
                        }
                        self.processed_slots.insert(site);
                        outcome.recipients = pks.clone();
                        if self.processed_outbound.insert(site.0) {
                            let spent = self.spent_amounts(&tx.nullifiers);
                            let kind = if real_recipient_count == 0 {
                                PrivateTransactionKind::PublicWithdrawal
                            } else {
                                PrivateTransactionKind::PrivateTransfer
                            };
                            let counterparty = (real_recipient_count == 1)
                                .then(|| pks.first().copied())
                                .flatten();
                            let direction = self.transfer_direction(&pks);
                            self.record_outbound_transfer(
                                tx,
                                spent,
                                &change,
                                kind,
                                counterparty,
                                direction,
                            );
                        }
                    }
                    EncryptedScheme::Split => {
                        let Ok(plaintext) = Split::decode(body, &cx) else {
                            self.report.undecryptable_candidates += 1;
                            return Ok(outcome);
                        };
                        let utxos = match Split::into_utxos(plaintext, &owner_cx) {
                            Ok(utxos) => utxos,
                            Err(err) => {
                                self.note_undecryptable(&err);
                                return Ok(outcome);
                            }
                        };
                        for utxo in &utxos {
                            self.store_in_tx(utxo.clone(), tx)?;
                        }
                        self.processed_slots.insert(site);
                        if self.processed_outbound.insert(site.0) {
                            let spent = self.spent_amounts(&tx.nullifiers);
                            self.record_split(tx, spent);
                        }
                    }
                    _ => {
                        self.report.undecryptable_candidates += 1;
                    }
                }
            }
            OutputDataEncoding::VerifiablyEncrypted(blob) => {
                // Merge outputs no longer carry verifiable encryption; the only
                // remaining VerifiablyEncrypted payloads are legacy merge
                // ciphertexts, which are undecodable here.
                let _ = blob;
                self.report.undecryptable_candidates += 1;
            }
        }
        Ok(outcome)
    }

    /// Reconstruct a merge output deterministically: the wallet recomputes the
    /// candidate UTXO from its spent inputs and the published first nullifier,
    /// and stores it only if the canonical UTXO hash matches the on-chain
    /// output commitment (`store_recipient_utxos` performs the check).
    fn reconstruct_merge(
        &mut self,
        tx: &ShieldedTransaction,
        site: (usize, usize),
    ) -> Result<MergeResolution, TransactionError> {
        let Some(slot) = tx.output_slots.get(site.1) else {
            self.report.undecryptable_candidates += 1;
            return Ok(MergeResolution::Complete);
        };
        let output_context = slot.output_context.clone();

        let Some(first_nullifier) = tx.nullifiers.first() else {
            return Ok(MergeResolution::Pending);
        };
        // The first nullifier must be one of ours: it both confirms the merge
        // is this wallet's and seeds the deterministic dummy/output
        // derivations (keyed by the owner's nullifier secret).
        if !self.utxos.iter().any(|u| &u.nullifier == first_nullifier) {
            return Ok(MergeResolution::Pending);
        }

        // Match this wallet's spent inputs in slot order; deterministic dummy
        // nullifiers are skipped. A real nullifier we do not own means the
        // merge is not ours (the proof binds a single owner).
        let mut matched = Vec::new();
        for (i, nullifier) in tx.nullifiers.iter().enumerate() {
            if *nullifier == merge_dummy_nullifier(self.nullifier_key, first_nullifier, i as u8)? {
                continue;
            }
            let Some(wallet_utxo) = self.utxos.iter().find(|u| &u.nullifier == nullifier) else {
                return Ok(MergeResolution::Pending);
            };
            matched.push((
                wallet_utxo.utxo.asset,
                wallet_utxo.utxo.amount,
                wallet_utxo.utxo.blinding,
                wallet_utxo.utxo.ring_program_id,
            ));
        }
        let Some(&(asset, _, _, ring_program_id)) = matched.first() else {
            self.report.undecryptable_candidates += 1;
            return Ok(MergeResolution::Complete);
        };
        if matched.iter().any(|m| m.0 != asset) {
            self.report.undecryptable_candidates += 1;
            return Ok(MergeResolution::Complete);
        }
        let mut amount = 0u64;
        for m in &matched {
            amount = amount
                .checked_add(m.1)
                .ok_or(TransactionError::SelectedBalanceOverflow)?;
        }
        let blinding = merge_output_blinding(self.nullifier_key, first_nullifier)?;
        // A ring merge publishes the output ring-data hash as the slot payload.
        let ring_data_hash: Option<[u8; 32]> = if ring_program_id.is_some() {
            let Ok(hash) = <&[u8; 32]>::try_from(slot.payload.as_slice()) else {
                self.report.undecryptable_candidates += 1;
                return Ok(MergeResolution::Complete);
            };
            Some(*hash)
        } else {
            None
        };
        let utxo = Utxo {
            owner: self.owner,
            asset,
            amount,
            blinding,
            ring_program_id,
            data: Data::default(),
        };
        if self.store_recipient_utxos(vec![utxo.clone()], &output_context, None, ring_data_hash)? {
            self.processed_slots.insert(site);
            self.record_merge(tx, &output_context, &utxo);
        }
        Ok(MergeResolution::Complete)
    }
}

/// Every hit in one tag stream: the counter that produced the tag, and the
/// sites filed under it.
pub(super) type StreamHits<S> = Vec<(u64, Vec<S>)>;

/// Walks a tag stream in `window`-sized batches, collecting hits, and stops
/// after the first batch that hits nothing.
///
/// Probing is separated from decoding on purpose. Probing is pure -- it derives
/// tags and reads `TxIndex` -- so it can be fanned out across counterparties
/// (see [`ProbeFanout`]); decoding mutates [`SyncCtx`] and stays serial. The
/// two phases are equivalent to interleaving them: hits come back in ascending
/// counter order, and a batch's presence decision does not depend on decoding.
fn probe_stream<'i, S: Clone + 'i>(
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
    lookup: impl Fn(&ViewTag) -> Option<&'i Vec<S>>,
) -> Result<StreamHits<S>, TransactionError> {
    let mut hits = Vec::new();
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if let Some(sites) = lookup(&tag) {
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

/// The highest counter whose tag is present, without collecting sites. Used by
/// the send-shared stream, which only advances a watermark.
fn probe_presence(
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
    present: impl Fn(&ViewTag) -> bool,
) -> Result<Option<u64>, TransactionError> {
    let mut max_present = None;
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if present(&tag) {
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

/// How the per-counterparty stream probes fan out.
///
/// This is the *only* difference between [`Wallet::sync`] and
/// [`Wallet::sync_parallel`]: one scan body, parameterized here. Probing is
/// pure, so both strategies return identical hits and the two entry points
/// agree by construction rather than by two implementations being kept in step.
pub(super) trait ProbeFanout {
    fn probe_each<T, R>(
        items: &[T],
        probe: impl Fn(&T) -> Result<R, TransactionError> + Send + Sync,
    ) -> Result<Vec<R>, TransactionError>
    where
        T: Send + Sync,
        R: Send;
}

/// One counterparty at a time. The default, and the only strategy without the
/// `parallel` feature.
pub(super) struct SerialProbe;

impl ProbeFanout for SerialProbe {
    fn probe_each<T, R>(
        items: &[T],
        probe: impl Fn(&T) -> Result<R, TransactionError> + Send + Sync,
    ) -> Result<Vec<R>, TransactionError>
    where
        T: Send + Sync,
        R: Send,
    {
        items.iter().map(probe).collect()
    }
}

impl Wallet {
    pub fn sync<A: SyncWalletAuthority + ?Sized>(
        &mut self,
        authority: &A,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let material = authority.sync_material()?;
        self.sync_with_material(&material, transactions, synced_at, window)
    }

    pub fn sync_with_material(
        &mut self,
        material: &WalletSyncMaterial,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.scan::<SerialProbe>(material, transactions, synced_at, window)
    }

    /// The one scan. `F` decides only how the per-counterparty tag probes fan
    /// out; every classification, history, and bookkeeping rule lives here once.
    pub(super) fn scan<F: ProbeFanout>(
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

        // Borrow the registry up front, before `ctx` takes `&mut self.utxos`;
        // disjoint-field borrows let this immutable borrow of `self.registry`
        // coexist with the mutable UTXO/transaction borrows below.
        let assets = &self.registry;
        // Snapshot before `ctx` borrows the wallet mutably.
        let self_viewing_pubkeys = self.self_viewing_pubkeys();
        let owner_tag = identity.signing_pubkey.confidential_view_tag()?;
        let mut ctx = SyncCtx {
            owner: identity.signing_pubkey,
            nullifier_pk: identity.nullifier_pubkey,
            nullifier_key: &material.nullifier_key,
            self_viewing_pubkeys,
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

            // Anonymous policy-ring bootstrap scan (recipient viewing-pubkey
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
            // Confidential default-ring outputs use the owner signing tag.
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

            let sender_hits = probe_stream(
                window,
                |n| key.get_sender_view_tag(n),
                |tag| index.sender_sites.get(tag),
            )?;
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

            let request_hits = probe_stream(
                window,
                |n| key.get_recipient_request_view_tag(n),
                |tag| index.recipient_sites.get(tag),
            )?;
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
            let shared_in = F::probe_each(&senders, |sender| {
                probe_stream(
                    window,
                    |n| key.get_recipient_shared_view_tag(sender, n),
                    |tag| index.recipient_sites.get(tag),
                )
                .map(|hits| (*sender, hits))
            })?;
            for (sender, hits) in &shared_in {
                if let Some((m, _)) = hits.last() {
                    known_senders.insert(*sender, *m + 1);
                }
                for (_, sites) in hits {
                    for site in sites {
                        ctx.decode_slot(transactions, key, assets, *site)?;
                    }
                }
            }

            for (t, tx) in transactions.iter().enumerate() {
                ctx.record_confidential_send(tx, t, key, assets, known_recipients)?;
            }

            let recipients: Vec<P256Pubkey> = known_recipients.keys().copied().collect();
            let shared_out = F::probe_each(&recipients, |recipient| {
                probe_presence(
                    window,
                    |n| key.get_send_shared_view_tag(recipient, n),
                    |tag| index.recipient_sites.contains_key(tag),
                )
                .map(|max| (*recipient, max))
            })?;
            for (recipient, max) in shared_out {
                if let Some(m) = max {
                    known_recipients.insert(recipient, m + 1);
                }
            }
        }

        if let Some(sites) = index.merge_sites.get(&owner_tag) {
            ctx.resolve_merge_sites(transactions, sites)?;
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
        // A spent nullifier is never queried again, so its watermark is dead
        // weight.
        self.cursors.retain(|stream, _| match stream {
            CursorStream::Nullifiers(nullifier) => !self.nullifiers.contains(nullifier),
            _ => true,
        });
        self.transactions.sort_by(|a, b| {
            (a.id.slot, &a.id.signature, a.id.index).cmp(&(b.id.slot, &b.id.signature, b.id.index))
        });
        self.last_synced = synced_at;
        Ok(report)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SyncConfig {
    pub window: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_TAG_WINDOW,
        }
    }
}

pub fn decrypt_transactions<K: SyncWalletAuthority + ?Sized>(
    key: &K,
    transactions: &[ShieldedTransaction],
    registry: &AssetRegistry,
) -> Result<Balances, TransactionError> {
    decrypt_transactions_with_config(key, transactions, registry, SyncConfig::default())
}

pub fn decrypt_transactions_with_config<K: SyncWalletAuthority + ?Sized>(
    key: &K,
    transactions: &[ShieldedTransaction],
    registry: &AssetRegistry,
    config: SyncConfig,
) -> Result<Balances, TransactionError> {
    // TODO(separate PR): move this construct-sync-extract sequence onto Wallet
    // itself (e.g. Wallet::decrypt), so this free function is a thin wrapper
    // instead of open-coding Wallet's own logic.
    let mut wallet = Wallet::new(key.shielded_address()?, registry.clone())?;
    wallet.sync(key, transactions, 0, config.window)?;
    Ok(Balances {
        assets: wallet.balances(false)?,
    })
}
