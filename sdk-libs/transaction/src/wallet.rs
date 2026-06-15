use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use solana_address::Address;
use zolana_keypair::constants::SALT_LEN;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{KeypairError, P256Pubkey, PublicKey, ShieldedKeypair, ViewingKey};

use crate::asset::AssetRegistry;
use crate::data::Data;
use crate::encryption::TransactionEncryption;
use crate::error::TransactionError;
use crate::split::SplitEncryptedUtxos;
use crate::transfer::TransferEncryptedUtxos;
use crate::utxo::{owner_utxo_hash, utxo_hash, Blinding, Utxo};
use crate::{SPLIT, TRANSFER};

#[cfg(feature = "parallel")]
mod parallel;

pub const DEFAULT_TAG_WINDOW: u64 = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTransaction {
    pub encrypted_utxos: Vec<u8>,
    pub sender_view_tag: ViewTag,
    pub nullifiers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProoflessDepositEvent {
    pub view_tag: ViewTag,
    pub utxo_hash: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; SALT_LEN],
    pub asset: Address,
    pub amount: u64,
    pub zone_program_id: Option<Address>,
    pub program_data_hash: [u8; 32],
    pub zone_data_hash: [u8; 32],
    pub data: Data,
}

pub struct ViewingKeyEntry {
    pub key: ViewingKey,
    pub created_at: i64,
    pub tx_count: u64,
    pub request_count: u64,
    pub known_senders: HashMap<P256Pubkey, u64>,
    pub known_recipients: HashMap<P256Pubkey, u64>,
}

impl ViewingKeyEntry {
    pub fn new(key: ViewingKey, created_at: i64) -> Self {
        Self {
            key,
            created_at,
            tx_count: 0,
            request_count: 0,
            known_senders: HashMap::new(),
            known_recipients: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub spent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: u64,
    pub mint: Address,
    pub amount: u64,
    pub utxos: Vec<Utxo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub stored_utxos: usize,
    pub unparsed_transactions: usize,
    pub undecryptable_candidates: usize,
}

pub struct Wallet {
    pub keypair: ShieldedKeypair,
    pub viewing_key_history: Vec<ViewingKeyEntry>,
    pub utxos: Vec<WalletUtxo>,
    pub last_synced: i64,
}

enum ParsedBlob {
    Transfer(TransferEncryptedUtxos),
    Split(SplitEncryptedUtxos),
    Invalid,
}

struct TxIndex {
    parsed: Vec<ParsedBlob>,
    sender_sites: HashMap<ViewTag, Vec<usize>>,
    recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>>,
    nullifiers: HashSet<[u8; 32]>,
}

impl TxIndex {
    fn build(transactions: &[SyncTransaction], report: &mut SyncReport) -> Self {
        let mut parsed = Vec::with_capacity(transactions.len());
        let mut sender_sites: HashMap<ViewTag, Vec<usize>> = HashMap::new();
        let mut recipient_sites: HashMap<ViewTag, Vec<(usize, usize)>> = HashMap::new();
        let mut nullifiers = HashSet::new();
        for (t, tx) in transactions.iter().enumerate() {
            nullifiers.extend(tx.nullifiers.iter().copied());
            let blob = match tx.encrypted_utxos.first() {
                Some(&TRANSFER) => TransferEncryptedUtxos::deserialize(&tx.encrypted_utxos)
                    .map(ParsedBlob::Transfer)
                    .unwrap_or(ParsedBlob::Invalid),
                Some(&SPLIT) => SplitEncryptedUtxos::deserialize(&tx.encrypted_utxos)
                    .map(ParsedBlob::Split)
                    .unwrap_or(ParsedBlob::Invalid),
                _ => ParsedBlob::Invalid,
            };
            match &blob {
                ParsedBlob::Invalid => report.unparsed_transactions += 1,
                ParsedBlob::Transfer(b) => {
                    sender_sites.entry(tx.sender_view_tag).or_default().push(t);
                    for (slot, entry) in b.recipient_slots.iter().enumerate() {
                        recipient_sites
                            .entry(entry.view_tag)
                            .or_default()
                            .push((t, slot));
                    }
                }
                ParsedBlob::Split(_) => {
                    sender_sites.entry(tx.sender_view_tag).or_default().push(t);
                }
            }
            parsed.push(blob);
        }
        Self {
            parsed,
            sender_sites,
            recipient_sites,
            nullifiers,
        }
    }
}

struct SyncCtx<'a> {
    keypair: &'a ShieldedKeypair,
    owner: PublicKey,
    nullifier_pk: [u8; 32],
    utxos: &'a mut Vec<WalletUtxo>,
    stored_hashes: HashSet<[u8; 32]>,
    processed_senders: HashSet<usize>,
    processed_slots: HashSet<(usize, usize)>,
    report: SyncReport,
}

impl SyncCtx<'_> {
    fn push(&mut self, utxo: Utxo, hash: [u8; 32], nullifier: [u8; 32]) {
        self.utxos.push(WalletUtxo {
            utxo,
            hash,
            nullifier,
            spent: false,
        });
        self.report.stored_utxos += 1;
    }

    fn store(&mut self, utxo: Utxo) -> Result<(), TransactionError> {
        if utxo.owner != self.owner {
            return Ok(());
        }
        let hash = utxo.hash(&self.nullifier_pk, &[0u8; 32], &[0u8; 32])?;
        if !self.stored_hashes.insert(hash) {
            return Ok(());
        }
        let nullifier = utxo.nullifier(&hash, &self.keypair.nullifier_key)?;
        self.push(utxo, hash, nullifier);
        Ok(())
    }

    /// Discover a proofless deposit under `key`. The blinding is derived from
    /// the recipient viewing key, so each key in the wallet's history must be
    /// tried — a deposit made to a rotated-away key still belongs to this
    /// wallet. The public `owner_utxo_hash`/`utxo_hash` are recomputed and must
    /// match, then the UTXO is stored through the same dedup path as transfer
    /// outputs so the spent pass covers it too.
    fn discover_proofless(
        &mut self,
        key: &ViewingKey,
        event: &ProoflessDepositEvent,
    ) -> Result<(), TransactionError> {
        let blinding = key.derive_proofless_blinding(&event.salt)?;
        let owner_utxo_hash = owner_utxo_hash(&self.keypair.owner_hash()?, &blinding)?;
        if owner_utxo_hash != event.owner_utxo_hash {
            return Ok(());
        }
        let hash = utxo_hash(
            event.asset,
            event.amount,
            &event.program_data_hash,
            &event.zone_data_hash,
            event.zone_program_id,
            &event.owner_utxo_hash,
        )?;
        if hash != event.utxo_hash || !self.stored_hashes.insert(hash) {
            return Ok(());
        }
        let utxo = Utxo {
            owner: self.owner,
            asset: event.asset,
            amount: event.amount,
            blinding,
            zone_program_id: event.zone_program_id,
            data: event.data.clone(),
        };
        let nullifier = utxo.nullifier(&hash, &self.keypair.nullifier_key)?;
        self.push(utxo, hash, nullifier);
        Ok(())
    }

    fn decrypt_recipient_slot(
        &mut self,
        index: &TxIndex,
        key: &ViewingKey,
        assets: &AssetRegistry,
        site: (usize, usize),
    ) -> Result<Option<P256Pubkey>, TransactionError> {
        if self.processed_slots.contains(&site) {
            return Ok(None);
        }
        let Some(ParsedBlob::Transfer(blob)) = index.parsed.get(site.0) else {
            self.report.undecryptable_candidates += 1;
            return Ok(None);
        };
        let decrypted = key.decrypt_transfer_recipient(blob, site.1).and_then(|pt| {
            let sender = pt.sender_pubkey;
            pt.into_utxo(assets, None).map(|utxo| (sender, utxo))
        });
        match decrypted {
            Ok((sender, utxo)) => {
                self.store(utxo)?;
                self.processed_slots.insert(site);
                Ok(Some(sender))
            }
            Err(_) => {
                self.report.undecryptable_candidates += 1;
                Ok(None)
            }
        }
    }

    fn decrypt_sender_side(
        &mut self,
        index: &TxIndex,
        transactions: &[SyncTransaction],
        key: &ViewingKey,
        assets: &AssetRegistry,
        t: usize,
    ) -> Result<Option<Vec<P256Pubkey>>, TransactionError> {
        if self.processed_senders.contains(&t) {
            return Ok(Some(Vec::new()));
        }
        let Some(first_nullifier) = transactions.get(t).and_then(|tx| tx.nullifiers.first()) else {
            self.report.undecryptable_candidates += 1;
            return Ok(None);
        };
        match index.parsed.get(t) {
            Some(ParsedBlob::Transfer(blob)) => {
                let Ok((sender, recipients)) = key.decrypt_transfer(first_nullifier, blob) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(None);
                };
                let pks = sender.recipient_viewing_pks.clone();
                let Ok(change) = sender.into_utxos(assets, None) else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(None);
                };
                for utxo in change {
                    self.store(utxo)?;
                }
                for pt in recipients {
                    if pt.owner_pubkey != self.owner {
                        continue;
                    }
                    match pt.into_utxo(assets, None) {
                        Ok(utxo) => self.store(utxo)?,
                        Err(_) => self.report.undecryptable_candidates += 1,
                    }
                }
                self.processed_senders.insert(t);
                Ok(Some(pks))
            }
            Some(ParsedBlob::Split(blob)) => {
                let decrypted = key
                    .decrypt_split(blob)
                    .and_then(|bundle| bundle.into_utxos(assets, None));
                let Ok(utxos) = decrypted else {
                    self.report.undecryptable_candidates += 1;
                    return Ok(None);
                };
                for utxo in utxos {
                    self.store(utxo)?;
                }
                self.processed_senders.insert(t);
                Ok(Some(Vec::new()))
            }
            _ => {
                self.report.undecryptable_candidates += 1;
                Ok(None)
            }
        }
    }
}

fn scan_stream(
    window: u64,
    mut derive: impl FnMut(u64) -> Result<ViewTag, KeypairError>,
    mut on_match: impl FnMut(&ViewTag) -> Result<Option<bool>, TransactionError>,
) -> Result<Option<u64>, TransactionError> {
    let mut max_success = None;
    let mut start = 0u64;
    loop {
        let mut window_hit = false;
        for n in start..start.saturating_add(window) {
            let tag = derive(n)?;
            if let Some(decrypted) = on_match(&tag)? {
                window_hit = true;
                if decrypted {
                    max_success = Some(n);
                }
            }
        }
        if !window_hit || start.checked_add(window).is_none() {
            return Ok(max_success);
        }
        start += window;
    }
}

impl Wallet {
    pub fn new(keypair: ShieldedKeypair) -> Result<Self, TransactionError> {
        let key = ViewingKey::from_bytes(&keypair.viewing_key.secret_bytes())?;
        Ok(Self {
            keypair,
            viewing_key_history: vec![ViewingKeyEntry::new(key, 0)],
            utxos: Vec::new(),
            last_synced: 0,
        })
    }

    pub fn proofless_owner_utxo_hash(
        &self,
        blinding: &Blinding,
    ) -> Result<[u8; 32], TransactionError> {
        let owner_hash = self.keypair.owner_hash()?;
        owner_utxo_hash(&owner_hash, blinding)
    }

    pub fn proofless_blinding(&self, salt: &[u8; SALT_LEN]) -> Result<Blinding, TransactionError> {
        Ok(self.keypair.viewing_key.derive_proofless_blinding(salt)?)
    }

    pub fn sync(
        &mut self,
        transactions: &[SyncTransaction],
        proofless_deposits: &[ProoflessDepositEvent],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let mut report = SyncReport::default();
        let index = TxIndex::build(transactions, &mut report);

        // Proofless deposits are public, so there is no ciphertext to decrypt;
        // each carries the recipient bootstrap view tag (see `wallet_shield`),
        // exactly the tag the loop below already scans. Index them by that tag
        // so discovery rides the same per-viewing-key path as transfer outputs.
        let mut proofless_sites: HashMap<ViewTag, Vec<usize>> = HashMap::new();
        for (p, event) in proofless_deposits.iter().enumerate() {
            proofless_sites.entry(event.view_tag).or_default().push(p);
        }

        let stored_hashes: HashSet<[u8; 32]> = self.utxos.iter().map(|u| u.hash).collect();
        let mut ctx = SyncCtx {
            owner: self.keypair.signing_pubkey(),
            nullifier_pk: self.keypair.nullifier_key.pubkey()?,
            keypair: &self.keypair,
            utxos: &mut self.utxos,
            stored_hashes,
            processed_senders: HashSet::new(),
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
                    if let Some(sender) = ctx.decrypt_recipient_slot(&index, key, assets, *site)? {
                        known_senders.entry(sender).or_insert(0);
                    }
                }
            }
            if let Some(sites) = proofless_sites.get(&bootstrap) {
                for &p in sites {
                    ctx.discover_proofless(key, &proofless_deposits[p])?;
                }
            }

            let max_sender = scan_stream(
                window,
                |n| key.get_sender_view_tag(n),
                |tag| {
                    let Some(sites) = index.sender_sites.get(tag) else {
                        return Ok(None);
                    };
                    let mut decrypted = false;
                    for &t in sites {
                        if let Some(pks) =
                            ctx.decrypt_sender_side(&index, transactions, key, assets, t)?
                        {
                            decrypted = true;
                            for pk in pks {
                                known_recipients.entry(pk).or_insert(0);
                            }
                        }
                    }
                    Ok(Some(decrypted))
                },
            )?;
            if let Some(m) = max_sender {
                *tx_count = m + 1;
            }

            let max_request = scan_stream(
                window,
                |n| key.get_recipient_request_view_tag(n),
                |tag| {
                    let Some(sites) = index.recipient_sites.get(tag) else {
                        return Ok(None);
                    };
                    let mut decrypted = false;
                    for site in sites {
                        if let Some(sender) =
                            ctx.decrypt_recipient_slot(&index, key, assets, *site)?
                        {
                            decrypted = true;
                            known_senders.entry(sender).or_insert(0);
                        }
                    }
                    Ok(Some(decrypted))
                },
            )?;
            if let Some(m) = max_request {
                *request_count = m + 1;
            }

            let senders: Vec<P256Pubkey> = known_senders.keys().copied().collect();
            for s in senders {
                let max = scan_stream(
                    window,
                    |n| key.get_recipient_shared_view_tag(&s, n),
                    |tag| {
                        let Some(sites) = index.recipient_sites.get(tag) else {
                            return Ok(None);
                        };
                        let mut decrypted = false;
                        for site in sites {
                            if ctx
                                .decrypt_recipient_slot(&index, key, assets, *site)?
                                .is_some()
                            {
                                decrypted = true;
                            }
                        }
                        Ok(Some(decrypted))
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
                    |tag| {
                        let Some(sites) = index.recipient_sites.get(tag) else {
                            return Ok(None);
                        };
                        let mut decrypted = false;
                        for &(t, _) in sites {
                            if let Some(pks) =
                                ctx.decrypt_sender_side(&index, transactions, key, assets, t)?
                            {
                                decrypted = true;
                                for pk in pks {
                                    known_recipients.entry(pk).or_insert(0);
                                }
                            }
                        }
                        Ok(Some(decrypted))
                    },
                )?;
                if let Some(m) = max {
                    known_recipients.insert(r, m + 1);
                }
            }
        }

        let report = ctx.report;

        for utxo in self.utxos.iter_mut() {
            if index.nullifiers.contains(&utxo.nullifier) {
                utxo.spent = true;
            }
        }
        self.last_synced = synced_at;
        Ok(report)
    }

    fn unspent(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.utxos.iter().filter(|u| !u.spent)
    }

    pub fn balances(
        &self,
        assets: &AssetRegistry,
        skip_utxos: bool,
    ) -> Result<Vec<AssetBalance>, TransactionError> {
        let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
        for wallet_utxo in self.unspent() {
            let balance = match by_mint.entry(wallet_utxo.utxo.asset) {
                Entry::Occupied(occupied) => occupied.into_mut(),
                Entry::Vacant(vacant) => vacant.insert(AssetBalance {
                    asset_id: assets.asset_id(&wallet_utxo.utxo.asset)?,
                    mint: wallet_utxo.utxo.asset,
                    amount: 0,
                    utxos: Vec::new(),
                }),
            };
            balance.amount = balance.amount.saturating_add(wallet_utxo.utxo.amount);
            if !skip_utxos {
                balance.utxos.push(wallet_utxo.utxo.clone());
            }
        }
        let mut balances: Vec<AssetBalance> = by_mint.into_values().collect();
        balances.sort_by_key(|b| b.asset_id);
        Ok(balances)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::SOL_MINT;
    use zolana_keypair::constants::VIEW_TAG_LEN;

    /// Build a proofless deposit event the `wallet` is guaranteed to own, by
    /// reusing the wallet's own blinding/owner-hash derivation so the embedded
    /// `owner_utxo_hash` and `utxo_hash` match what discovery recomputes.
    fn self_consistent_deposit(wallet: &Wallet, amount: u64) -> ProoflessDepositEvent {
        let salt = [9u8; SALT_LEN];
        let blinding = wallet.proofless_blinding(&salt).unwrap();
        let owner_utxo_hash = wallet.proofless_owner_utxo_hash(&blinding).unwrap();
        let utxo_hash = utxo_hash(
            SOL_MINT,
            amount,
            &[0u8; 32],
            &[0u8; 32],
            None,
            &owner_utxo_hash,
        )
        .unwrap();
        ProoflessDepositEvent {
            view_tag: wallet.keypair.recipient_bootstrap_view_tag(),
            utxo_hash,
            owner_utxo_hash,
            salt,
            asset: SOL_MINT,
            amount,
            zone_program_id: None,
            program_data_hash: [0u8; 32],
            zone_data_hash: [0u8; 32],
            data: Data::new(Vec::new()),
        }
    }

    #[test]
    fn sync_discovers_and_spends_proofless_deposit() {
        let mut wallet = Wallet::new(ShieldedKeypair::new().unwrap()).unwrap();
        let assets = AssetRegistry::default();
        let deposit = self_consistent_deposit(&wallet, 1_234);

        // A single `sync` discovers the public deposit with no transfers present.
        wallet
            .sync(
                &[],
                std::slice::from_ref(&deposit),
                &assets,
                1,
                DEFAULT_TAG_WINDOW,
            )
            .unwrap();
        assert_eq!(wallet.utxos.len(), 1, "deposit discovered");
        assert_eq!(wallet.utxos[0].hash, deposit.utxo_hash);
        assert!(!wallet.utxos[0].spent);
        let nullifier = wallet.utxos[0].nullifier;

        // Re-syncing the same deposit must not duplicate it.
        wallet
            .sync(
                &[],
                std::slice::from_ref(&deposit),
                &assets,
                2,
                DEFAULT_TAG_WINDOW,
            )
            .unwrap();
        assert_eq!(wallet.utxos.len(), 1, "idempotent on re-sync");

        // A later transaction that nullifies the deposit marks it spent, proving
        // proofless UTXOs flow through the same spent pass as transfer outputs.
        let spend = SyncTransaction {
            encrypted_utxos: Vec::new(),
            sender_view_tag: [0u8; VIEW_TAG_LEN],
            nullifiers: vec![nullifier],
        };
        wallet
            .sync(
                std::slice::from_ref(&spend),
                &[],
                &assets,
                3,
                DEFAULT_TAG_WINDOW,
            )
            .unwrap();
        assert!(wallet.utxos[0].spent, "deposit spent by its nullifier");
    }
}
