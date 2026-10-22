//! A wallet's spendable UTXOs and its history, read from the indexer.
//!
//! Stateless: [`UtxoScan::fetch`] reads the transactions tagged for the
//! wallet and decrypts them, then reads the transactions that spent the UTXOs
//! it found, until a round finds nothing new. A merge, or a spend another
//! client made, can carry none of the wallet's tags; only the nullifier rounds
//! find those. Each round decrypts only the transactions it fetched and queries
//! only the nullifiers it has not queried, so with a remote key holder a round
//! costs round trips for what is new, not for everything found so far. The
//! [`UtxoScanResult`] it returns holds the spendable UTXOs and the history, the
//! transactions read and the spent UTXOs as well.
//!
//! It reads UTXOs only in the assets of the [`AssetRegistry`] it is given and
//! reports the others as unknown; [`fetch_asset_id`] reads the id the pool
//! registered for a mint, to add it. Opt into [`UtxoScan::with_asset_discovery`]
//! to learn registered SPL assets and decrypt the fetched transactions again,
//! without repeating the indexer reads. An indexer that lags misses the latest
//! spends; [`UtxoScan::with_indexer_config`] makes every read wait for a
//! slot first. Every spendable UTXO carries the output tree the indexer
//! named on the last page read, as its
//! [`latest_tree_id`](zolana_transaction::WalletUtxo::latest_tree_id).

use std::collections::HashSet;

use solana_address::Address;
use solana_signature::Signature;
use zolana_interface::{
    pda,
    state::{discriminator::SPL_ASSET_REGISTRY, SplAssetRegistry},
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::X25519Pubkey;
use zolana_transaction::{
    verify_owned, AssetRegistry, DecryptionResult, DepositPayload, History, Mint, OwnedUtxos,
    ShieldedKeys, SpendableDecryptionResult, SOL_ASSET_ID, SOL_MINT,
};

use crate::{
    error::ClientError,
    rpc::{
        ChainPosition, EncryptedUtxoMatch, IndexerRpcConfig, ProgramAccountsFilter, Rpc,
        ShieldedTransaction,
    },
};

const PAGE_LIMIT: u32 = 1_000;

/// What [`UtxoScan::fetch`] read. Outputs in unresolved assets are omitted
/// from the UTXOs and reported in `spendable` and `history` through their
/// `unknown_asset_ids` and `unknown_mints` fields, even with discovery enabled.
#[derive(Clone, Debug)]
pub struct UtxoScanResult {
    /// The registry used to decrypt this scan, including mappings learned by
    /// asset discovery. Reuse it on the next scan to avoid another lookup.
    pub asset_registry: AssetRegistry,
    /// The UTXOs not spent, and the balances they add up to.
    pub spendable: SpendableDecryptionResult,
    /// Every transaction read, every UTXO the wallet owns among them, spent or
    /// not, and the tags they were read by. [`History::entries`] classifies
    /// them.
    pub history: History,
}

/// One read of a wallet's UTXOs and history: configure it, then
/// [`fetch`](Self::fetch). It holds no connection and no state between reads.
pub struct UtxoScan<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    ring_deposit_payload: Option<(Address, DepositPayload)>,
    indexer_config: Option<IndexerRpcConfig>,
    discover_assets: bool,
}

impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            ring_deposit_payload: None,
            indexer_config: None,
            discover_assets: false,
        }
    }

    /// Every indexer read waits, as `config` says, until the indexer has
    /// persisted `config.require_slot`, and fails with
    /// [`ClientError::IndexerNotCaughtUp`] when it does not. Pass a recent
    /// Solana slot, so a spend another client just made is read, not missed:
    /// selecting a UTXO the chain already spent costs a proof and a failed
    /// transaction.
    #[must_use]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    /// Resolve unknown asset ids and mints through the pool's on-chain SPL
    /// registrations. Requires [`Rpc::get_program_accounts_filtered`].
    ///
    /// At most one filtered registry read is made, only when an unknown
    /// asset is encountered. Already fetched transactions are decrypted
    /// again and newly discovered nullifiers are followed normally.
    /// The registry read requires the greater of `indexer_config.require_slot`
    /// and every transaction slot fetched so far; a lagging Solana RPC fails
    /// rather than returning a stale registry listing.
    /// Outputs in assets still unknown after discovery are skipped and reported
    /// in the result's `unknown_asset_ids` and `unknown_mints` fields. Unknown
    /// ids are sender-provided and unverified; they do not fail the scan.
    /// RPC failures and invalid or conflicting registrations still fail it.
    /// The supplied registry is unchanged; the result carries the updated
    /// registry. Leave this disabled to scan an explicit asset allowlist.
    #[must_use]
    pub fn with_asset_discovery(mut self) -> Self {
        self.discover_assets = true;
        self
    }

    /// For a ring program that frames the ciphertexts of its deposits. It
    /// reads only that ring's deposits, and [`fetch`](Self::fetch) fails on
    /// framing that does not parse.
    pub fn with_ring_deposit_payload(
        mut self,
        ring_program_id: Address,
        deposit_payload: DepositPayload,
    ) -> Self {
        self.ring_deposit_payload = Some((ring_program_id, deposit_payload));
        self
    }

    /// Reads the transactions tagged with the owner tag, which confidential
    /// outputs carry, and with each held viewing key's tag, which deposits
    /// carry, then the transactions that spent what they hold. Anonymous
    /// transfers, tagged per counterparty, are not read.
    pub fn fetch<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<UtxoScanResult, ClientError> {
        let fetched = self.fetch_rounds(indexer)?;
        Ok(UtxoScanResult {
            asset_registry: fetched.asset_registry,
            spendable: fetched.spendable,
            history: History {
                utxos: fetched.owned.utxos,
                transactions: fetched.transactions,
                unknown_asset_ids: fetched.owned.unknown_asset_ids,
                unknown_mints: fetched.owned.unknown_mints,
                view_tags: fetched.tags.into_iter().collect(),
            },
        })
    }

    fn fetch_rounds<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<Fetched, ClientError> {
        let mut assets = self.assets.clone();
        let mut registry_refreshed = false;
        let address = self.keys.address()?;
        let mut tags = vec![address.signing_pubkey.confidential_view_tag()?];
        tags.extend(self.keys.viewing_public_keys().iter().map(X25519Pubkey::u));

        // The output tree the last page read named; every page reports it.
        let mut output_tree_id = None;
        let mut seen = HashSet::new();
        let mut batch = self.unseen(
            &mut seen,
            tagged_transactions(indexer, &tags, self.indexer_config, &mut output_tree_id)?,
        )?;
        let mut transactions = Vec::new();
        let mut decrypted = DecryptionResult::default();
        let mut queried = HashSet::new();
        loop {
            decrypted.extend(self.keys, &batch, &assets)?;
            transactions.append(&mut batch);
            if self.discover_assets && !registry_refreshed && has_unknown_assets(&decrypted) {
                let min_context_slot = transactions
                    .iter()
                    .map(|tx| tx.slot)
                    .chain(self.indexer_config.and_then(|config| config.require_slot))
                    .max();
                for mint in fetch_spl_asset_registrations(indexer, min_context_slot)? {
                    match assets.asset_id(&mint.asset) {
                        Ok(asset_id) if asset_id == mint.asset_id => continue,
                        Ok(_) => {
                            return Err(ClientError::InvalidSplAssetRegistry { mint: mint.asset })
                        }
                        Err(_) => assets.insert(mint.asset_id, mint.asset)?,
                    }
                }
                registry_refreshed = true;
                decrypted = DecryptionResult::default();
                decrypted.extend(self.keys, &transactions, &assets)?;
            }
            let owned = verify_owned(self.keys, &decrypted)?;
            let spendable = owned.spendable();
            // The spends of a UTXO queried in an earlier round are fetched.
            let nullifiers: Vec<_> = spendable
                .utxos()
                .map(|utxo| utxo.nullifier)
                .filter(|nullifier| queried.insert(*nullifier))
                .collect();
            batch = self.unseen(
                &mut seen,
                spending_transactions(
                    indexer,
                    &nullifiers,
                    self.indexer_config,
                    &mut output_tree_id,
                )?,
            )?;
            if batch.is_empty() {
                return Ok(Fetched {
                    asset_registry: assets,
                    tags,
                    transactions,
                    owned,
                    spendable: spendable
                        .with_latest_tree_id(output_tree_id)
                        .with_transaction_keys(self.keys)?,
                });
            }
        }
    }

    /// The transactions not fetched before, their ring deposits unwrapped. A
    /// proofless deposit arrives one output at a time, so its leaf is part of
    /// its identity.
    fn unseen(
        &self,
        seen: &mut HashSet<(Signature, Option<u16>, Option<u64>)>,
        transactions: Vec<ShieldedTransaction>,
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        transactions
            .into_iter()
            .filter(|tx| {
                let leaf = tx
                    .proofless
                    .then(|| tx.output_slots.first())
                    .flatten()
                    .map(|slot| slot.output_context.leaf_index);
                seen.insert((tx.tx_signature, tx.event_index, leaf))
            })
            .map(|tx| self.unwrap_ring_deposits(tx))
            .collect()
    }

    fn unwrap_ring_deposits(
        &self,
        mut tx: ShieldedTransaction,
    ) -> Result<ShieldedTransaction, ClientError> {
        if let Some((ring_program_id, deposit_payload)) = &self.ring_deposit_payload {
            for slot in &mut tx.output_slots {
                slot.unwrap_ring_deposit(ring_program_id, *deposit_payload)?;
            }
        }
        Ok(tx)
    }
}

fn has_unknown_assets(decrypted: &DecryptionResult) -> bool {
    !(decrypted.unknown_asset_ids.is_empty() && decrypted.unknown_mints.is_empty())
}

/// Every SPL asset registration held by the shielded pool. The request is
/// filtered by account size and discriminator; every returned account is
/// checked again, including its owner and canonical mint PDA. A malformed,
/// conflicting listing or an unsupported RPC method fails instead of reading
/// as empty. An asset absent from the listing is simply not returned.
/// `min_context_slot` requires a node caught up to that slot; a lagging node
/// fails the lookup instead of returning an incomplete registry listing.
pub fn fetch_spl_asset_registrations<R: Rpc + ?Sized>(
    rpc: &R,
    min_context_slot: Option<u64>,
) -> Result<Vec<Mint>, ClientError> {
    let mut filter =
        ProgramAccountsFilter::new(SplAssetRegistry::SIZE).with_memcmp(0, [SPL_ASSET_REGISTRY]);
    if let Some(slot) = min_context_slot {
        filter = filter.with_min_context_slot(slot);
    }
    let accounts = rpc.get_program_accounts_filtered(PROGRAM_ID_PUBKEY, &filter)?;
    let mut assets = AssetRegistry::default();
    let mut registrations = Vec::with_capacity(accounts.len());
    for (address, account) in accounts {
        let invalid = || ClientError::InvalidSplAssetRegistration { address };
        if account.owner != PROGRAM_ID_PUBKEY || !filter.matches(&account.data) {
            return Err(invalid());
        }
        let registration =
            SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
        if address != pda::spl_asset_registry(&registration.mint) || registration.mint == SOL_MINT {
            return Err(invalid());
        }
        assets
            .insert(registration.asset_id, registration.mint)
            .map_err(|_| invalid())?;
        registrations.push(Mint::new(registration.mint, registration.asset_id));
    }
    Ok(registrations)
}

/// The asset id the shielded pool uses for `asset`: [`SOL_ASSET_ID`] for SOL,
/// without a request, and for an SPL mint the id in the registry account the
/// pool wrote when it registered the mint.
pub fn fetch_asset_id<R: Rpc + ?Sized>(rpc: &R, asset: Address) -> Result<u64, ClientError> {
    if asset == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    let not_registered = || ClientError::SplAssetNotRegistered { mint: asset };
    let account = rpc
        .get_account(pda::spl_asset_registry(&asset))?
        .ok_or_else(not_registered)?;
    // Only the pool can create an account at the registry address. Any other
    // owner means lamports were sent there, not that the mint was registered.
    if account.owner != PROGRAM_ID_PUBKEY {
        return Err(not_registered());
    }
    let invalid = || ClientError::InvalidSplAssetRegistry { mint: asset };
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
    if registry.mint != asset {
        return Err(invalid());
    }
    Ok(registry.asset_id)
}

/// What the rounds of one fetch read and decrypted.
struct Fetched {
    asset_registry: AssetRegistry,
    tags: Vec<[u8; 32]>,
    transactions: Vec<ShieldedTransaction>,
    /// The final round's [`verify_owned`], spent UTXOs included.
    owned: OwnedUtxos,
    spendable: SpendableDecryptionResult,
}

/// The transactions tagged with any of `tags`. Deposits come from the
/// encrypted-output stream, one transaction per output: a deposit transaction
/// can shield several outputs. Each page read sets `output_tree_id` to the
/// output tree it names.
fn tagged_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    tags: &[[u8; 32]],
    config: Option<IndexerRpcConfig>,
    output_tree_id: &mut Option<u16>,
) -> Result<Vec<ShieldedTransaction>, ClientError> {
    let mut transactions = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer.get_shielded_transactions_by_tags(
            tags.to_vec(),
            cursor,
            Some(PAGE_LIMIT),
            config,
        )?;
        *output_tree_id = page.output_tree_id;
        transactions.extend(page.transactions.into_iter().filter(|tx| !tx.proofless));
        match next_page(&cursor, page.next, page.latest)? {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let mut cursor = None;
    loop {
        let page =
            indexer.get_encrypted_utxos_by_tags(tags.to_vec(), cursor, Some(PAGE_LIMIT), config)?;
        *output_tree_id = page.output_tree_id;
        transactions.extend(
            page.matches
                .into_iter()
                .filter_map(EncryptedUtxoMatch::into_proofless_transaction),
        );
        match next_page(&cursor, page.next, page.latest)? {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(transactions)
}

/// The transactions that spent any of `nullifiers`. Each page read sets
/// `output_tree_id` to the output tree it names.
fn spending_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    nullifiers: &[[u8; 32]],
    config: Option<IndexerRpcConfig>,
    output_tree_id: &mut Option<u16>,
) -> Result<Vec<ShieldedTransaction>, ClientError> {
    let mut transactions = Vec::new();
    for chunk in nullifiers.chunks(PAGE_LIMIT as usize) {
        let mut cursor = None;
        loop {
            let page = indexer.get_shielded_transactions_by_nullifiers(
                chunk.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
                config,
            )?;
            *output_tree_id = page.output_tree_id;
            transactions.extend(page.transactions);
            match next_page(&cursor, page.next, page.latest)? {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    Ok(transactions)
}

/// A continuation exists only on a truncated page and must move forward.
fn next_page(
    cursor: &Option<ChainPosition>,
    next: Option<ChainPosition>,
    latest: Option<ChainPosition>,
) -> Result<Option<ChainPosition>, ClientError> {
    if next.is_some() && latest.is_some() {
        return Err(ClientError::IndexerCursorNotAdvanced);
    }
    if next.is_some_and(|next| cursor.is_some_and(|cursor| next <= cursor)) {
        return Err(ClientError::IndexerCursorNotAdvanced);
    }
    Ok(next)
}
