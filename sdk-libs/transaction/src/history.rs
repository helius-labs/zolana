//! A wallet's history, seen from its own side: what each transaction that
//! created or spent one of its UTXOs did to its balance of each asset.
//!
//! A published transaction shows neither its public amounts nor whether it
//! withdrew, so [`History::entries`] reads the kind from the wallet's
//! UTXOs alone, per asset:
//!
//! - It spent none of them: a [`Deposit`](HistoryKind::Deposit) when it came
//!   through the deposit instruction, [`Received`](HistoryKind::Received)
//!   otherwise.
//! - It gave back exactly what it spent: a
//!   [`SelfTransfer`](HistoryKind::SelfTransfer).
//! - It gave back more than it spent: a [`Deposit`](HistoryKind::Deposit) of
//!   the difference. A transact balances its inputs against its outputs and
//!   public transfers, so the extra is a public deposit, or the UTXOs of
//!   another owner who signed the same transaction. A spend the wallet builds
//!   holds only its own UTXOs, and the published transaction does not tell
//!   the two apart, so the extra counts as a deposit.
//! - It has an output that is not the wallet's and is published under a tag
//!   that is not the wallet's: [`Sent`](HistoryKind::Sent) to another wallet.
//! - Otherwise: a [`Withdrawal`](HistoryKind::Withdrawal) of what did not come
//!   back as change. A spend publishes its dummy outputs under the spender's
//!   tag, so an output under one of [`History::view_tags`] that the
//!   wallet does not own is padding of its own spend, not a payment.
//!
//! Amounts are net per asset. So a transaction that both pays another wallet
//! and withdraws reads as `Sent` for the whole amount, one that deposits and
//! pays another wallet reads as the net `Deposit` or `Sent`, and a deposit
//! made through a proof with no UTXO of the wallet's spent reads as
//! `Received`.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};

use solana_address::Address;
use solana_signature::Signature;
use zolana_event::{OutputDataEncoding, SplTransfer};

use crate::{
    asset::{AssetRegistry, SOL_MINT},
    decrypt::{decrypt, verify_owned},
    error::TransactionError,
    indexer_types::ShieldedTransaction,
    keys::ShieldedKeys,
    sent::{decrypt_sent, SentOutput},
    serialization::scheme::EncryptedScheme,
    utxo::WalletUtxo,
};

/// What a transaction did to the wallet's balance of one asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistoryKind {
    /// Public funds moved into the wallet's private balance.
    Deposit,
    /// A transfer from another wallet.
    Received,
    /// A transfer to another wallet.
    Sent,
    /// Private funds moved to a public account.
    Withdrawal,
    /// UTXOs moved within the wallet: a merge, or a transfer to itself.
    SelfTransfer,
}

/// One asset that one transaction moved. `amount` is in the mint's base units
/// (lamports for SOL). For [`HistoryKind::Sent`] and
/// [`HistoryKind::Withdrawal`] it is what left the private balance, change
/// excluded, for [`HistoryKind::SelfTransfer`] what was spent, and for a
/// [`HistoryKind::Deposit`] what came in beyond what was spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub kind: HistoryKind,
    pub mint: Address,
    pub amount: u64,
    pub tx_signature: Signature,
    pub slot: u64,
}

/// The transactions that created or spent a wallet's UTXOs, and every UTXO it
/// owns among their outputs, spent or not, as
/// [`verify_owned`] returns them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    pub transactions: Vec<ShieldedTransaction>,
    pub utxos: Vec<WalletUtxo>,
    /// As on [`DecryptionResult`](crate::DecryptionResult). UTXOs in these
    /// assets are missing from the history.
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`](crate::DecryptionResult).
    pub unknown_mints: BTreeSet<Address>,
    /// The owner tag and each viewing key's tag the wallet reads its transactions by.
    pub view_tags: BTreeSet<[u8; 32]>,
}

impl History {
    /// One entry per asset each transaction moved, newest first. The events of
    /// one Solana transaction count together. A transaction that moved none of
    /// an asset, such as a zero-amount change output, has no entry for it.
    pub fn entries(&self) -> Vec<HistoryEntry> {
        let mut entries: Vec<_> = self
            .balance_changes()
            .into_iter()
            .flat_map(|(tx_signature, change)| change.entries(tx_signature))
            .collect();
        entries.sort_by_key(|entry| (Reverse(entry.slot), entry.tx_signature, entry.mint));
        entries
    }

    fn balance_changes(&self) -> BTreeMap<Signature, BalanceChange> {
        let by_hash: HashMap<_, _> = self
            .utxos
            .iter()
            .map(|utxo| (utxo.utxo_hash, utxo))
            .collect();
        let by_nullifier: HashMap<_, _> = self
            .utxos
            .iter()
            .map(|utxo| (utxo.nullifier, utxo))
            .collect();
        let mut balance_changes: BTreeMap<Signature, BalanceChange> = BTreeMap::new();
        for tx in &self.transactions {
            let change = balance_changes.entry(tx.tx_signature).or_default();
            change.slot = tx.slot;
            change.deposit |= tx.proofless;
            // The indexer can list a transaction's UTXO under more than one
            // event, such as a merge's output, which it also lists as a
            // proofless one: each UTXO counts once.
            for slot in &tx.output_slots {
                match by_hash.get(&slot.output_context.hash) {
                    Some(utxo) if change.counted.insert(utxo.utxo_hash) => {
                        add(&mut change.received, utxo)
                    }
                    Some(_) => {}
                    None if self.view_tags.contains(&slot.view_tag) => {}
                    None => change.pays_another = true,
                }
            }
            for utxo in tx
                .nullifiers
                .iter()
                .filter_map(|nullifier| by_nullifier.get(nullifier))
            {
                if change.counted.insert(utxo.nullifier) {
                    add(&mut change.spent, utxo);
                }
            }
        }
        balance_changes
    }
}

/// One Solana transaction as a wallet that took part in it reads it, without
/// the rest of its history: what [`History::entries`] reports for it and,
/// when the wallet sent it, every output it paid.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionDetail {
    /// One entry per asset the transaction moved for the wallet, as
    /// [`History::entries`] classifies it.
    pub entries: Vec<HistoryEntry>,
    /// When the wallet sent the transaction, its confidential outputs in
    /// order, the recipients' included; empty otherwise.
    pub sent: Vec<SentOutput>,
    /// As on [`DecryptionResult`](crate::DecryptionResult). Outputs in these
    /// assets are missing from the entries.
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`](crate::DecryptionResult).
    pub unknown_mints: BTreeSet<Address>,
}

impl TransactionDetail {
    /// `events` are the shielded-pool events of one Solana transaction, as
    /// an indexer lists them by signature, each with its `event_index`.
    /// An event whose [`ShieldedTransaction::spl_transfers`] is `Some` uses
    /// those legs, including an empty list when it settled nothing. `public`
    /// supplies the legs of an event that left the field `None`, at that
    /// event's `event_index`, as
    /// `zolana_client::SolanaRpc::public_transfers` rebuilds them from the
    /// confirmed transaction. An event with neither has none.
    ///
    /// [`History::entries`] needs the UTXOs a transaction spent, which come
    /// from the wallet's earlier transactions. Each event says what the
    /// wallet spent in it without them. In an event the wallet sent, it opens
    /// every confidential output with the transaction viewing key
    /// ([`decrypt_sent`]), and a transact balances its inputs and public
    /// deposits against its outputs and public withdrawals. A merge gives back
    /// exactly what it spent. In any other event the wallet spent nothing and
    /// only receives. The events then add up as `History::entries` adds them.
    pub fn read<K: ShieldedKeys + ?Sized>(
        shielded_keys: &K,
        events: &[ShieldedTransaction],
        public: &[Vec<SplTransfer>],
        assets: &AssetRegistry,
    ) -> Result<Self, TransactionError> {
        let Some(first) = events.first() else {
            return Ok(Self::default());
        };
        let owned = verify_owned(shielded_keys, &decrypt(shielded_keys, events, assets)?)?;
        // The indexer can list one output under more than one event, such as
        // a merge's output, which it also lists as a proofless one: each
        // counts once, in the first event that lists it.
        let mut unclaimed: HashMap<[u8; 32], &WalletUtxo> = owned
            .utxos
            .iter()
            .map(|utxo| (utxo.utxo_hash, utxo))
            .collect();
        let mut detail = Self {
            unknown_asset_ids: owned.unknown_asset_ids.clone(),
            unknown_mints: owned.unknown_mints.clone(),
            ..Self::default()
        };
        let mut change = BalanceChange {
            slot: first.slot,
            deposit: events.iter().any(|tx| tx.proofless),
            ..BalanceChange::default()
        };
        for tx in events {
            let mut received = BTreeMap::new();
            for slot in &tx.output_slots {
                if let Some(utxo) = unclaimed.remove(&slot.output_context.hash) {
                    add(&mut received, utxo);
                }
            }
            let legs = settlement_legs(tx, public);
            let spent = match decrypt_sent(shielded_keys, tx, assets)? {
                Some(sent) => {
                    let paid: Vec<&SentOutput> =
                        sent.utxos.iter().filter(|output| !output.owned).collect();
                    change.pays_another |= !paid.is_empty();
                    let spent = sender_spent(&received, &paid, legs);
                    detail.unknown_asset_ids.extend(sent.unknown_asset_ids);
                    detail.sent.extend(sent.utxos);
                    spent
                }
                None if is_merge(tx) && !received.is_empty() => received.clone(),
                None => BTreeMap::new(),
            };
            merge_into(&mut change.received, &received);
            merge_into(&mut change.spent, &spent);
        }
        detail.entries = change.entries(first.tx_signature).collect();
        Ok(detail)
    }
}

/// Legs the event itself recorded, or the chain list at `event_index` when
/// the indexer has not stored them.
fn settlement_legs<'a>(
    tx: &'a ShieldedTransaction,
    public: &'a [Vec<SplTransfer>],
) -> &'a [SplTransfer] {
    if let Some(legs) = &tx.spl_transfers {
        return legs;
    }
    tx.event_index
        .and_then(|index| public.get(usize::from(index)))
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// What the wallet spent in an event it sent, per mint: what came back to it,
/// what it paid others and what it withdrew, less what it deposited. The
/// outflows add up before the deposits come off, so the order of the legs
/// does not matter.
fn sender_spent(
    received: &BTreeMap<Address, u64>,
    paid: &[&SentOutput],
    legs: &[SplTransfer],
) -> BTreeMap<Address, u64> {
    let mut outflow = received.clone();
    let mut deposited: BTreeMap<Address, u64> = BTreeMap::new();
    for output in paid {
        let amount = outflow.entry(output.asset.asset).or_default();
        *amount = amount.saturating_add(output.amount);
    }
    for leg in legs {
        let mint = leg.asset.map_or(SOL_MINT, Address::new_from_array);
        let total = if leg.is_deposit {
            deposited.entry(mint).or_default()
        } else {
            outflow.entry(mint).or_default()
        };
        *total = total.saturating_add(leg.amount);
    }
    outflow
        .into_iter()
        .map(|(mint, amount)| {
            let deposited = deposited.get(&mint).copied().unwrap_or_default();
            (mint, amount.saturating_sub(deposited))
        })
        .collect()
}

/// Whether `tx` has a merge's shape and only merge outputs. A plaintext
/// transfer has the shape too.
fn is_merge(tx: &ShieldedTransaction) -> bool {
    tx.may_be_merge()
        && !tx.nullifiers.is_empty()
        && tx.output_slots.iter().all(|slot| {
            matches!(slot.output_data(), Some(OutputDataEncoding::Encrypted(blob))
                if blob.first() == Some(&EncryptedScheme::Merge.as_byte()))
        })
}

fn merge_into(total: &mut BTreeMap<Address, u64>, amounts: &BTreeMap<Address, u64>) {
    for (mint, amount) in amounts {
        let sum = total.entry(*mint).or_default();
        *sum = sum.saturating_add(*amount);
    }
}

/// What one Solana transaction did to the wallet's UTXOs, over all its
/// shielded-pool events.
#[derive(Debug, Default)]
struct BalanceChange {
    slot: u64,
    deposit: bool,
    /// An output that is not the wallet's, under another wallet's tag.
    pays_another: bool,
    received: BTreeMap<Address, u64>,
    spent: BTreeMap<Address, u64>,
    /// The hashes of the UTXOs received and the nullifiers of those spent.
    counted: HashSet<[u8; 32]>,
}

impl BalanceChange {
    fn entries(self, tx_signature: Signature) -> impl Iterator<Item = HistoryEntry> {
        let mints: BTreeSet<Address> = self
            .received
            .keys()
            .chain(self.spent.keys())
            .copied()
            .collect();
        mints.into_iter().filter_map(move |mint| {
            let (kind, amount) = self.kind(&mint);
            (amount > 0).then_some(HistoryEntry {
                kind,
                mint,
                amount,
                tx_signature,
                slot: self.slot,
            })
        })
    }

    /// The rule in the module documentation.
    fn kind(&self, mint: &Address) -> (HistoryKind, u64) {
        let received = self.received.get(mint).copied().unwrap_or(0);
        let spent = self.spent.get(mint).copied().unwrap_or(0);
        if spent == 0 {
            let kind = if self.deposit {
                HistoryKind::Deposit
            } else {
                HistoryKind::Received
            };
            (kind, received)
        } else if received == spent {
            (HistoryKind::SelfTransfer, spent)
        } else if received > spent {
            (HistoryKind::Deposit, received - spent)
        } else if self.pays_another {
            (HistoryKind::Sent, spent - received)
        } else {
            (HistoryKind::Withdrawal, spent - received)
        }
    }
}

fn add(amounts: &mut BTreeMap<Address, u64>, utxo: &WalletUtxo) {
    let amount = amounts.entry(utxo.utxo.asset.asset).or_default();
    *amount = amount.saturating_add(utxo.utxo.amount);
}
