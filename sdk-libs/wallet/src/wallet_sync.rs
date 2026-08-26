use std::{
    collections::{HashMap, HashSet},
    panic::resume_unwind,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use solana_address::Address;

use zolana_client::timing;
use zolana_interface::{
    event::{decode_encrypted_ring_deposit_output_data, decode_output_data},
    state::SplAssetRegistry,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{
    AssetBalance, CursorStream, OutputContext, OutputSlot, PrivateTransaction, ShieldedTransaction,
    SyncReport, SyncWalletAuthority, TransactionError, Wallet, WalletAuthority, WalletSyncMaterial,
    DEFAULT_TAG_WINDOW,
};

use zolana_client::{
    error::ClientError,
    retry::{IndexerPollConfig, IndexerRpcConfig},
    rpc::{AsyncRpc, EncryptedUtxoMatch, Rpc, ShieldedTransaction as RpcShieldedTransaction},
};

const DEFAULT_TAG_QUERY_CHUNK: usize = 64;
const DEFAULT_PAGE_LIMIT: u32 = 1_000;
const DEFAULT_SYNC_ROUNDS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncWalletConfig {
    pub tag_window: u64,
    pub tag_query_chunk: usize,
    pub page_limit: u32,
    pub rounds: usize,
    pub retry: IndexerPollConfig,
    /// Slot the indexer must have persisted before its answers are accepted.
    /// `None` accepts whatever it currently has. Read the slot from the RPC the
    /// caller submits through, so both sides of the comparison are slots.
    pub require_slot: Option<u64>,
}

impl Default for SyncWalletConfig {
    fn default() -> Self {
        Self {
            tag_window: DEFAULT_TAG_WINDOW,
            tag_query_chunk: DEFAULT_TAG_QUERY_CHUNK,
            page_limit: DEFAULT_PAGE_LIMIT,
            rounds: DEFAULT_SYNC_ROUNDS,
            retry: IndexerPollConfig::default(),
            require_slot: None,
        }
    }
}

impl SyncWalletConfig {
    /// Require the indexer to have persisted `slot` before its answers are used.
    pub fn at_slot(slot: u64) -> Self {
        Self {
            require_slot: Some(slot),
            ..Self::default()
        }
    }
}

pub fn sync_wallet<A, I>(
    wallet: &mut Wallet,
    authority: &A,
    indexer: &I,
) -> Result<SyncReport, ClientError>
where
    A: SyncWalletAuthority + ?Sized,
    I: Rpc + Sync,
{
    sync_wallet_with_config(wallet, authority, indexer, SyncWalletConfig::default())
}

pub fn sync_wallet_with_config<A, I>(
    wallet: &mut Wallet,
    authority: &A,
    indexer: &I,
    config: SyncWalletConfig,
) -> Result<SyncReport, ClientError>
where
    A: SyncWalletAuthority + ?Sized,
    I: Rpc + Sync,
{
    let config = normalized_config(config);
    let material = authority.sync_material()?;
    let mut transactions: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, ShieldedTransaction> = HashMap::new();
    // Tags read to the tip during THIS sync. Unlike `wallet.sync_cursors` this
    // is deliberately not persisted: "the tip" means the tip as of now.
    let mut scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    // Separate stream, separate watermark: reaching the tip of the transaction
    // stream says nothing about the encrypted-utxo stream.
    let mut proofless_scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    let mut nullifier_scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    let mut report = SyncReport::default();
    let mut txs: Vec<ShieldedTransaction> = Vec::new();

    let mut freshness_gate = indexer_rpc_config(config);

    let _total = timing::Phase::start("sync_wallet_total", 0);
    for round in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = {
            let _t = timing::Phase::start("query_tags", round);
            wallet_query_tags(wallet, &material, config.tag_window)?
        };
        let nullifiers = wallet_query_nullifiers(wallet);
        timing::note(round, "tags", tags.len());
        timing::note(round, "nullifiers", nullifiers.len());
        {
            let _t = timing::Phase::start("fetch_round", round);
            // The three queries are independent: different indexer methods,
            // disjoint cursor state, and separate accumulators. Run sequentially
            // a round cost the sum of three round trips (866 + 521 + 503ms
            // measured on devnet) when it need only cost the slowest.
            //
            // Cursors come out of the wallet and go back rather than staying
            // borrowed, because `wallet` is needed mutably further down.
            // Three threads, three `&mut`. Variants keep the keys disjoint, so
            // the merge after the join is lossless.
            let (mut cursors, mut nullifier_cursors, mut proofless_cursors) =
                split_by_stream(std::mem::take(&mut wallet.cursors));
            let tag_keys = stream_keys(&tags, CursorStream::Tags);
            let nullifier_keys = stream_keys(&nullifiers, CursorStream::Nullifiers);
            let proofless_keys = stream_keys(&tags, CursorStream::Proofless);
            let mut by_nullifier: HashMap<String, ShieldedTransaction> = HashMap::new();
            // One gate for the whole round, not one per call: every query in a
            // round should read the chain at the same freshness bound, and
            // `take()`ing it three times would gate only the first.
            let gate = freshness_gate.take();

            let (tag_result, nullifier_result, proofless_result) = thread::scope(|scope| {
                let tag_keys_ref = &tag_keys;
                let proofless_keys_ref = &proofless_keys;
                let tag_handle = scope.spawn(|| {
                    let _t = timing::Phase::start("fetch_shielded_by_tags", round);
                    fetch_shielded_transactions_incremental(
                        indexer,
                        tag_keys_ref,
                        &mut transactions,
                        config,
                        gate,
                        &mut cursors,
                        &mut scanned_to_tip,
                    )
                });
                let nullifier_handle = scope.spawn(|| {
                    let _t = timing::Phase::start("fetch_shielded_by_nullifiers", round);
                    fetch_shielded_transactions_by_nullifiers(
                        indexer,
                        &nullifier_keys,
                        &mut by_nullifier,
                        config,
                        gate,
                        &mut nullifier_cursors,
                        &mut nullifier_scanned_to_tip,
                    )
                });
                let proofless_handle = scope.spawn(|| {
                    let _t = timing::Phase::start("fetch_proofless_deposits", round);
                    fetch_proofless_deposits(
                        indexer,
                        proofless_keys_ref,
                        &mut proofless_deposits,
                        config,
                        gate,
                        &mut proofless_cursors,
                        &mut proofless_scanned_to_tip,
                    )
                });
                (
                    tag_handle.join(),
                    nullifier_handle.join(),
                    proofless_handle.join(),
                )
            });

            wallet.cursors = cursors;
            wallet.cursors.extend(nullifier_cursors);
            wallet.cursors.extend(proofless_cursors);
            // Propagate a panic rather than swallowing it into a sync error: a
            // panicked fetch means a bug here, not an unreachable indexer.
            let tag_result = tag_result.unwrap_or_else(|payload| resume_unwind(payload));
            let nullifier_result =
                nullifier_result.unwrap_or_else(|payload| resume_unwind(payload));
            let proofless_result =
                proofless_result.unwrap_or_else(|payload| resume_unwind(payload));
            tag_result?;
            nullifier_result?;
            proofless_result?;

            // Both queries return transactions; the by-tag map wins ties, which
            // is the same precedence the sequential version had via `or_insert`.
            for (key, tx) in by_nullifier {
                transactions.entry(key).or_insert(tx);
            }
            timing::note(
                round,
                "tag_cursors",
                stream_len(wallet, |key| matches!(key, CursorStream::Tags(_))),
            );
            timing::note(
                round,
                "nullifier_cursors",
                stream_len(wallet, |key| matches!(key, CursorStream::Nullifiers(_))),
            );
        }
        timing::note(round, "transactions", transactions.len());
        timing::note(round, "proofless_deposits", proofless_deposits.len());
        let _round_tail = timing::Phase::start("collect_sort_and_decrypt", round);

        txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|a| (a.slot, a.tx_signature));
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by(|a, b| {
            (
                a.output_slots
                    .first()
                    .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                a.slot,
                a.tx_signature,
            )
                .cmp(&(
                    b.output_slots
                        .first()
                        .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                    b.slot,
                    b.tx_signature,
                ))
        });
        txs.extend(deposits);
        timing::note(round, "txs_to_decrypt", txs.len());
        report = {
            let _t = timing::Phase::start("sync_with_material", round);
            wallet.sync_with_material(&material, &txs, now_unix_ts(), config.tag_window)?
        };

        if before == (transactions.len(), proofless_deposits.len()) {
            timing::note(round, "converged", 1);
            break;
        }
    }

    // Lazy registry backfill: if decode hit asset ids the wallet's registry did
    // not know, refresh the id->mint map from the on-chain SplAssetRegistry
    // accounts and re-run sync once. Single pass — if an id is still unknown
    // after the refresh it is genuinely not on chain, so we stop rather than
    // loop. A refresh source that cannot enumerate accounts (RPC without
    // `get_program_accounts`) is a soft miss: sync keeps today's behaviour.
    if !report.unknown_asset_ids.is_empty() && refresh_registry_from_chain(wallet, indexer)? > 0 {
        report = wallet.sync_with_material(&material, &txs, now_unix_ts(), config.tag_window)?;
    }

    Ok(report)
}

pub async fn sync_wallet_async<A, I>(
    wallet: &mut Wallet,
    authority: &A,
    indexer: &I,
) -> Result<SyncReport, ClientError>
where
    A: WalletAuthority + ?Sized,
    I: AsyncRpc,
{
    sync_wallet_with_config_async(wallet, authority, indexer, SyncWalletConfig::default()).await
}

pub async fn sync_wallet_with_config_async<A, I>(
    wallet: &mut Wallet,
    authority: &A,
    indexer: &I,
    config: SyncWalletConfig,
) -> Result<SyncReport, ClientError>
where
    A: WalletAuthority + ?Sized,
    I: AsyncRpc,
{
    let config = normalized_config(config);
    let mut freshness_gate = indexer_rpc_config(config);
    let material = authority.sync_material().await?;
    let mut transactions: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, ShieldedTransaction> = HashMap::new();
    // Tags read to the tip during THIS sync. Unlike `wallet.sync_cursors` this
    // is deliberately not persisted: "the tip" means the tip as of now.
    let mut scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    // Separate stream, separate watermark: reaching the tip of the transaction
    // stream says nothing about the encrypted-utxo stream.
    let mut proofless_scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    let mut nullifier_scanned_to_tip: HashSet<CursorStream> = HashSet::new();
    let mut report = SyncReport::default();
    let mut txs = Vec::new();

    for _ in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(wallet, &material, config.tag_window)?;
        let nullifiers = wallet_query_nullifiers(wallet);
        // Sequential here, so one borrow serves all three.
        let mut cursors = std::mem::take(&mut wallet.cursors);
        let tag_keys = stream_keys(&tags, CursorStream::Tags);
        let nullifier_keys = stream_keys(&nullifiers, CursorStream::Nullifiers);
        let proofless_keys = stream_keys(&tags, CursorStream::Proofless);

        let fetched = fetch_shielded_transactions_incremental_async(
            indexer,
            &tag_keys,
            &mut transactions,
            config,
            freshness_gate.take(),
            &mut cursors,
            &mut scanned_to_tip,
        )
        .await;
        let nullifiers_fetched = if fetched.is_ok() {
            fetch_shielded_transactions_by_nullifiers_async(
                indexer,
                &nullifier_keys,
                &mut transactions,
                config,
                freshness_gate.take(),
                &mut cursors,
                &mut nullifier_scanned_to_tip,
            )
            .await
        } else {
            Ok(())
        };
        let fetched_proofless = if fetched.is_ok() && nullifiers_fetched.is_ok() {
            fetch_proofless_deposits_async(
                indexer,
                &proofless_keys,
                &mut proofless_deposits,
                config,
                freshness_gate.take(),
                &mut cursors,
                &mut proofless_scanned_to_tip,
            )
            .await
        } else {
            Ok(())
        };
        wallet.cursors = cursors;
        fetched?;
        nullifiers_fetched?;
        fetched_proofless?;

        txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|a| (a.slot, a.tx_signature));
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by(|a, b| {
            (
                a.output_slots
                    .first()
                    .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                a.slot,
                a.tx_signature,
            )
                .cmp(&(
                    b.output_slots
                        .first()
                        .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                    b.slot,
                    b.tx_signature,
                ))
        });
        txs.extend(deposits);
        report = wallet.sync_with_material(&material, &txs, now_unix_ts(), config.tag_window)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    if !report.unknown_asset_ids.is_empty()
        && refresh_registry_from_chain_async(wallet, indexer).await? > 0
    {
        report = wallet.sync_with_material(&material, &txs, now_unix_ts(), config.tag_window)?;
    }

    Ok(report)
}

/// Fetch every `SplAssetRegistry` account owned by the shielded-pool program and
/// insert any new `asset_id -> mint` pairs into the wallet's registry. Returns
/// the number of newly inserted ids. `get_program_accounts` being unsupported on
/// the RPC is treated as zero new ids (soft miss), not an error.
fn refresh_registry_from_chain<I>(wallet: &mut Wallet, indexer: &I) -> Result<usize, ClientError>
where
    I: Rpc,
{
    let program_id = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let accounts = match indexer.get_program_accounts(program_id) {
        Ok(accounts) => accounts,
        Err(ClientError::UnsupportedRpcMethod(_)) => return Ok(0),
        Err(err) => return Err(err),
    };

    let mut inserted = 0;
    for (_, account) in accounts {
        let Ok(registry) = SplAssetRegistry::from_account_bytes(&account.data) else {
            continue;
        };
        // `insert` rejects the reserved SOL id and duplicates; a dup just means
        // the id is already known, which is not an error for a refresh.
        if wallet
            .registry
            .insert(registry.asset_id, registry.mint)
            .is_ok()
        {
            inserted += 1;
        }
    }
    Ok(inserted)
}

async fn refresh_registry_from_chain_async<I>(
    wallet: &mut Wallet,
    indexer: &I,
) -> Result<usize, ClientError>
where
    I: AsyncRpc,
{
    let program_id = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let accounts = match indexer.get_program_accounts(program_id).await {
        Ok(accounts) => accounts,
        Err(ClientError::UnsupportedRpcMethod(_)) => return Ok(0),
        Err(err) => return Err(err),
    };

    let mut inserted = 0;
    for (_, account) in accounts {
        let Ok(registry) = SplAssetRegistry::from_account_bytes(&account.data) else {
            continue;
        };
        if wallet
            .registry
            .insert(registry.asset_id, registry.mint)
            .is_ok()
        {
            inserted += 1;
        }
    }
    Ok(inserted)
}

pub fn get_private_transactions(wallet: &Wallet) -> &[PrivateTransaction] {
    wallet.private_transactions()
}

pub fn get_private_token_balances(wallet: &Wallet) -> Result<Vec<AssetBalance>, ClientError> {
    Ok(wallet.balances(true)?)
}

fn normalized_config(config: SyncWalletConfig) -> SyncWalletConfig {
    SyncWalletConfig {
        tag_window: config.tag_window,
        tag_query_chunk: config.tag_query_chunk.max(1),
        page_limit: config.page_limit.max(1),
        rounds: config.rounds.max(1),
        require_slot: config.require_slot,
        retry: IndexerPollConfig {
            num_retries: config.retry.num_retries.max(1),
            ..config.retry
        },
    }
}

fn wallet_query_tags(
    wallet: &Wallet,
    material: &WalletSyncMaterial,
    window: u64,
) -> Result<Vec<ViewTag>, ClientError> {
    let identity = material.identity;
    if identity != wallet.identity {
        return Err(TransactionError::WalletAuthorityMismatch.into());
    }
    let viewing_keys = &material.viewing_keys;
    if viewing_keys
        .iter()
        .all(|key| key.pubkey() != identity.viewing_pubkey)
    {
        return Err(TransactionError::MissingCurrentViewingKey.into());
    }

    let mut tags = HashSet::new();
    // Confidential default-ring outputs (sender change, recipients, merge) are all
    // tagged by the owner signing pubkey.
    tags.insert(identity.signing_pubkey.confidential_view_tag()?);
    for key in viewing_keys {
        let state = wallet
            .viewing_key_history
            .iter()
            .find(|entry| entry.viewing_pubkey == key.pubkey());
        let tx_count = state.map_or(0, |entry| entry.tx_count);
        let request_count = state.map_or(0, |entry| entry.request_count);
        tags.insert(key.recipient_bootstrap_view_tag());
        for n in 0..tx_count.saturating_add(window) {
            tags.insert(key.get_sender_view_tag(n)?);
        }
        for n in 0..request_count.saturating_add(window) {
            tags.insert(key.get_recipient_request_view_tag(n)?);
        }
        if let Some(state) = state {
            for (sender, count) in &state.known_senders {
                for n in 0..count.saturating_add(window) {
                    tags.insert(key.get_recipient_shared_view_tag(sender, n)?);
                }
            }
            for (recipient, count) in &state.known_recipients {
                for n in 0..count.saturating_add(window) {
                    tags.insert(key.get_send_shared_view_tag(recipient, n)?);
                }
            }
        }
    }
    Ok(tags.into_iter().collect())
}

fn indexer_rpc_config(config: SyncWalletConfig) -> Option<IndexerRpcConfig> {
    Some(IndexerRpcConfig {
        poll: config.retry,
        require_slot: config.require_slot,
    })
}

/// Nullifiers of unspent UTXOs.
///
/// A nullifier appears at most once on chain, so once its spend is known the
/// answer is final. Cost tracks the unspent count, not history.
fn wallet_query_nullifiers(wallet: &Wallet) -> Vec<[u8; 32]> {
    wallet
        .utxos
        .iter()
        .filter(|utxo| !utxo.spent)
        .map(|utxo| utxo.nullifier)
        .collect()
}

/// Buckets keys by the position their stream was last read to.
///
/// A chunk carries one cursor, so keys at different positions cannot share a
/// request. `None` (never queried) is its own group. Keys already read to the
/// tip in this sync are dropped.
fn group_by_resume_point<K: Copy + Eq + std::hash::Hash>(
    keys: &[K],
    cursors: &HashMap<K, Vec<u8>>,
    scanned_to_tip: &HashSet<K>,
) -> HashMap<Option<Vec<u8>>, Vec<K>> {
    let mut groups: HashMap<Option<Vec<u8>>, Vec<K>> = HashMap::new();
    for key in keys {
        if scanned_to_tip.contains(key) {
            continue;
        }
        groups
            .entry(cursors.get(key).cloned())
            .or_default()
            .push(*key);
    }
    groups
}

/// One page of a cursor-ordered stream, reduced to what paging needs.
struct Page {
    next_cursor: Option<Vec<u8>>,
    /// Where the server's scan reached. Reported only by the nullifier stream,
    /// whose pages are normally empty and so carry no last row.
    scanned_through: Option<Vec<u8>>,
}

/// Reads one chunk until the stream offers no further cursor, returning the
/// position reached.
fn read_chunk<F>(start: Option<Vec<u8>>, mut request: F) -> Result<Option<Vec<u8>>, ClientError>
where
    F: FnMut(Option<Vec<u8>>) -> Result<Page, ClientError>,
{
    let mut cursor = start.clone();
    let mut furthest = start;
    loop {
        let page = request(cursor)?;
        let Some(next) = advance(&mut furthest, page) else {
            return Ok(furthest);
        };
        cursor = Some(next);
    }
}

/// Per key, the position read through.
type StreamCursors = HashMap<CursorStream, Vec<u8>>;

/// One map per stream, so concurrent fetches borrow disjointly. Caller merges.
fn split_by_stream(cursors: StreamCursors) -> (StreamCursors, StreamCursors, StreamCursors) {
    let mut tags = HashMap::new();
    let mut nullifiers = HashMap::new();
    let mut proofless = HashMap::new();
    for (key, position) in cursors {
        match key {
            CursorStream::Tags(_) => tags.insert(key, position),
            CursorStream::Nullifiers(_) => nullifiers.insert(key, position),
            CursorStream::Proofless(_) => proofless.insert(key, position),
        };
    }
    (tags, nullifiers, proofless)
}

/// Labels a stream's keys with the stream.
fn stream_keys(values: &[[u8; 32]], stream: fn([u8; 32]) -> CursorStream) -> Vec<CursorStream> {
    values.iter().copied().map(stream).collect()
}

/// Keys with a watermark on one stream.
fn stream_len(wallet: &Wallet, matches: fn(&CursorStream) -> bool) -> usize {
    wallet.cursors.keys().filter(|key| matches(key)).count()
}

/// Records one position for every key in the chunk.
///
/// Sound because the ordering is global: a position from a query over
/// {A, B, C} holds for each of them individually.
fn record_chunk<K: Copy + Eq + std::hash::Hash>(
    chunk: &[K],
    furthest: Option<Vec<u8>>,
    cursors: &mut HashMap<K, Vec<u8>>,
    scanned_to_tip: &mut HashSet<K>,
) {
    if let Some(position) = furthest {
        for key in chunk {
            cursors.insert(*key, position.clone());
        }
    }
    scanned_to_tip.extend(chunk.iter().copied());
}

/// Folds one page into the position read so far. `None` ends the read.
///
/// A cursor means there may be more, whatever the page size. Stopping on a short
/// page would make the non-advancing-cursor guard unreachable.
///
/// The async paths keep their own loop and share only this: an `AsyncFnMut`
/// cannot carry the `Send` bound their callers require.
fn advance(furthest: &mut Option<Vec<u8>>, page: Page) -> Option<Vec<u8>> {
    // The server's scan position if reported, else the last row, else unchanged.
    *furthest = page
        .scanned_through
        .or_else(|| page.next_cursor.clone())
        .or_else(|| furthest.take());
    page.next_cursor
}

/// Fetch shielded transactions for `tags`, resuming each tag from where it was
/// last seen.
///
/// The cursor photon returns is a position in a GLOBAL ordering -- slot, then
/// signature, then event index -- and that ordering does not depend on which tags
/// were requested. So a cursor obtained from a query over {A, B, C} is a valid
/// statement about each of A, B and C individually: everything matching that tag
/// up to this position has been seen. It says nothing about a tag that was not in
/// the query, which is exactly why a single shared cursor is unsafe.
///
/// Tags are therefore grouped by the cursor they carry, and one query is issued
/// per group. In the steady state every known tag shares one cursor and newly
/// derived tags have none, so this is two queries regardless of how many tags the
/// wallet has -- against one query per 64-tag chunk, repeated every sync, before.
///
/// Without this, a tag that becomes relevant only after the cursor advanced past
/// its transactions would never be scanned for them. That is not hypothetical: a
/// wallet's tag set is derived from a local counter plus a window of 64, and a
/// second device spending further ahead than that window makes the counter lag by
/// more than the window can absorb.
fn fetch_shielded_transactions_incremental<I: Rpc>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError> {
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let furthest = read_chunk(start.clone(), |cursor| {
                let response = indexer.get_shielded_transactions_by_tags(
                    chunk.iter().copied().map(CursorStream::value).collect(),
                    cursor,
                    Some(config.page_limit),
                    rpc_config,
                )?;
                for tx in response.transactions {
                    if tx.proofless || tx.tx_viewing_pk.is_none() || tx.salt.is_none() {
                        continue;
                    }
                    let key = tx.tx_signature.to_string();
                    out.entry(key).or_insert(convert_sync_transaction(tx)?);
                }
                Ok(Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                })
            })?;

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

/// Async twin of [`fetch_shielded_transactions_incremental`]. Drives its own
/// loop rather than calling [`read_chunk`]; see [`advance`].
async fn fetch_shielded_transactions_incremental_async<I: AsyncRpc>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError> {
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let mut cursor = start.clone();
            let mut furthest = start.clone();
            loop {
                let response = indexer
                    .get_shielded_transactions_by_tags(
                        chunk.iter().copied().map(CursorStream::value).collect(),
                        cursor,
                        Some(config.page_limit),
                        rpc_config,
                    )
                    .await?;
                for tx in response.transactions {
                    if tx.proofless || tx.tx_viewing_pk.is_none() || tx.salt.is_none() {
                        continue;
                    }
                    let key = tx.tx_signature.to_string();
                    out.entry(key).or_insert(convert_sync_transaction(tx)?);
                }
                let page = Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                };
                let Some(next) = advance(&mut furthest, page) else {
                    break;
                };
                cursor = Some(next);
            }

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

/// Fetches spends of `nullifiers`, resuming each from where it was last checked.
///
/// The resume point comes from `scanned_through`, not from rows: an unspent
/// nullifier matches nothing. Positions are per nullifier, since a scan over
/// {A, B, C} says nothing about D. A nullifier with no entry is read from
/// zero.
fn fetch_shielded_transactions_by_nullifiers<I: Rpc>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError> {
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let furthest = read_chunk(start.clone(), |cursor| {
                let response = indexer.get_shielded_transactions_by_nullifiers(
                    chunk.iter().copied().map(CursorStream::value).collect(),
                    cursor,
                    Some(config.page_limit),
                    rpc_config,
                )?;
                for tx in response.transactions.into_iter().filter(|tx| !tx.proofless) {
                    let key = tx.tx_signature.to_string();
                    out.entry(key).or_insert(convert_sync_transaction(tx)?);
                }
                Ok(Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                })
            })?;

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

/// Async twin of [`fetch_shielded_transactions_by_nullifiers`]. Drives its own
/// loop rather than calling [`read_chunk`]; see [`advance`].
async fn fetch_shielded_transactions_by_nullifiers_async<I: AsyncRpc>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError> {
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let mut cursor = start.clone();
            let mut furthest = start.clone();
            loop {
                let response = indexer
                    .get_shielded_transactions_by_nullifiers(
                        chunk.iter().copied().map(CursorStream::value).collect(),
                        cursor,
                        Some(config.page_limit),
                        rpc_config,
                    )
                    .await?;
                for tx in response.transactions.into_iter().filter(|tx| !tx.proofless) {
                    let key = tx.tx_signature.to_string();
                    out.entry(key).or_insert(convert_sync_transaction(tx)?);
                }
                let page = Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                };
                let Some(next) = advance(&mut furthest, page) else {
                    break;
                };
                cursor = Some(next);
            }

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

/// Reads new proofless deposits from the encrypted-utxo stream, resuming from
/// where the last sync stopped.
///
/// Resume points are per tag and persisted, as for the transaction stream: a tag
/// learned late must be read from the beginning while others are far ahead.
fn fetch_proofless_deposits<I>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError>
where
    I: Rpc,
{
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let furthest = read_chunk(start.clone(), |cursor| {
                let response = indexer.get_encrypted_utxos_by_tags(
                    chunk.iter().copied().map(CursorStream::value).collect(),
                    cursor,
                    Some(config.page_limit),
                    rpc_config,
                )?;
                for item in response.matches {
                    if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                        continue;
                    }
                    let key = format!(
                        "{}:{}",
                        item.tx_signature, item.output_slot.output_context.leaf_index
                    );
                    if out.contains_key(&key) {
                        continue;
                    }
                    if let Some(view) = proofless_deposit_from_indexed_match(item)? {
                        out.insert(key, view);
                    }
                }
                Ok(Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                })
            })?;

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

/// Async twin of [`fetch_proofless_deposits`]. Drives its own loop rather than
/// calling [`read_chunk`]; see [`advance`].
async fn fetch_proofless_deposits_async<I: AsyncRpc>(
    indexer: &I,
    keys: &[CursorStream],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
    cursors: &mut HashMap<CursorStream, Vec<u8>>,
    scanned_to_tip: &mut HashSet<CursorStream>,
) -> Result<(), ClientError> {
    for (start, group) in group_by_resume_point(keys, cursors, scanned_to_tip) {
        for chunk in group.chunks(config.tag_query_chunk) {
            let mut cursor = start.clone();
            let mut furthest = start.clone();
            loop {
                let response = indexer
                    .get_encrypted_utxos_by_tags(
                        chunk.iter().copied().map(CursorStream::value).collect(),
                        cursor,
                        Some(config.page_limit),
                        rpc_config,
                    )
                    .await?;
                for item in response.matches {
                    if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                        continue;
                    }
                    let key = format!(
                        "{}:{}",
                        item.tx_signature, item.output_slot.output_context.leaf_index
                    );
                    if out.contains_key(&key) {
                        continue;
                    }
                    if let Some(view) = proofless_deposit_from_indexed_match(item)? {
                        out.insert(key, view);
                    }
                }
                let page = Page {
                    next_cursor: response.next_cursor,
                    scanned_through: response.scanned_through,
                };
                let Some(next) = advance(&mut furthest, page) else {
                    break;
                };
                cursor = Some(next);
            }

            record_chunk(chunk, furthest, cursors, scanned_to_tip);
        }
    }
    Ok(())
}

fn proofless_deposit_from_indexed_match(
    item: EncryptedUtxoMatch,
) -> Result<Option<ShieldedTransaction>, ClientError> {
    // The wallet deserializes the `ProoflessOutput` from the slot payload itself;
    // here we only confirm the payload is a decodable proofless output before
    // wrapping the slot into a proofless `ShieldedTransaction`.
    if decode_output_data(&item.output_slot.payload).is_err()
        && decode_encrypted_ring_deposit_output_data(&item.output_slot.payload).is_err()
    {
        return Ok(None);
    }

    Ok(Some(ShieldedTransaction {
        slot: item.slot,
        tx_signature: item.tx_signature,
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: item.output_slot.view_tag,
            output_context: OutputContext {
                hash: item.output_slot.output_context.hash,
                tree: item.output_slot.output_context.tree,
                leaf_index: item.output_slot.output_context.leaf_index,
            },
            payload: item.output_slot.payload,
        }],
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
    }))
}

fn convert_sync_transaction(
    tx: RpcShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    let output_slots = tx
        .output_slots
        .into_iter()
        .map(|slot| OutputSlot {
            view_tag: slot.view_tag,
            output_context: OutputContext {
                hash: slot.output_context.hash,
                tree: slot.output_context.tree,
                leaf_index: slot.output_context.leaf_index,
            },
            payload: slot.payload,
        })
        .collect();
    Ok(ShieldedTransaction {
        slot: tx.slot,
        tx_signature: tx.tx_signature,
        tx_viewing_pk: tx.tx_viewing_pk,
        salt: tx.salt,
        output_slots,
        messages: tx.messages,
        nullifiers: tx.nullifiers,
        proofless: false,
    })
}

fn now_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use solana_signature::Signature;
    use zolana_interface::event::{encode_output_data, ProoflessOutput};
    use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
    use zolana_transaction::{
        instructions::{
            merge::Merge as MergePlan,
            transact::{
                ConfidentialTransfer, SettlementTarget, SppProofInputs, SPP_SUPPORTED_SHAPES,
            },
            types::SppProofInputUtxo,
        },
        serialization::Proofless,
        Address, AssetRegistry, Data, KeypairWalletAuthority, OwnerCx, PrivateTransaction,
        PrivateTransactionDirection, PrivateTransactionKind, PrivateTransactionStatus, Utxo,
        UtxoSerialization, WalletUtxo, SOL_MINT,
    };

    use super::*;
    use zolana_client::rpc::{
        Context, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsByTagsResponse, OutputContext, OutputSlot,
    };

    /// A mock that behaves like photon: filters by tag, honours the cursor, and
    /// orders globally by slot.
    ///
    /// The existing `MockIndexer` ignores both tags and cursor, which is fine for
    /// decryption tests and useless for this one -- the bug being pinned here is
    /// precisely an interaction between the two.
    #[derive(Default)]
    struct TaggedIndexer {
        /// (slot, view tag) pairs. Signature is derived from the slot so the sort
        /// key is total, as it is in photon.
        entries: Vec<(u64, ViewTag)>,
        /// (slot, nullifier) pairs: the transaction at `slot` spent `nullifier`.
        spends: Vec<(u64, [u8; 32])>,
        /// (slot, view tag) pairs in the encrypted-utxo stream. Paged separately
        /// from `entries`.
        utxo_entries: Vec<(u64, ViewTag)>,
        /// Every (tags, cursor) pair the client asked for, for call accounting.
        calls: std::sync::Mutex<Vec<(usize, Option<u64>)>>,
        /// The same, for the nullifier stream.
        nullifier_calls: std::sync::Mutex<Vec<(usize, Option<u64>)>>,
        /// The same, for the encrypted-utxo stream.
        utxo_calls: std::sync::Mutex<Vec<(usize, Option<u64>)>>,
    }

    impl TaggedIndexer {
        /// Cursor is the slot of the last row returned, encoded as 8 bytes. Real
        /// photon encodes (slot, signature, event_index); slot alone is a total
        /// order here because each fixture uses a distinct slot.
        fn matching(
            &self,
            tags: &[ViewTag],
            cursor: Option<Vec<u8>>,
            limit: usize,
        ) -> (Vec<ShieldedTransaction>, Option<Vec<u8>>) {
            let after = cursor.as_ref().map(|bytes| {
                u64::from_be_bytes(bytes.as_slice().try_into().expect("8-byte cursor"))
            });
            self.calls
                .lock()
                .expect("calls poisoned")
                .push((tags.len(), after));

            let mut rows: Vec<_> = self
                .entries
                .iter()
                .filter(|(slot, tag)| tags.contains(tag) && after.is_none_or(|after| *slot > after))
                .collect();
            rows.sort_by_key(|(slot, _)| *slot);

            // Photon's rule (`next_cursor_from_rows`): the position of the last
            // row returned, or None when there were none. A short page still
            // carries a cursor, so the client can resume from the tip next sync
            // instead of rescanning; the loop ends on the following empty page.
            rows.truncate(limit);
            let next = rows.last().map(|(slot, _)| slot.to_be_bytes().to_vec());
            let transactions = rows
                .into_iter()
                .map(|(slot, tag)| ShieldedTransaction {
                    slot: *slot,
                    tx_signature: Signature::from([*slot as u8; 64]),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![OutputSlot {
                        view_tag: *tag,
                        output_context: OutputContext {
                            hash: [0u8; 32],
                            tree: Address::default(),
                            leaf_index: *slot,
                        },
                        payload: Vec::new(),
                    }],
                    messages: Vec::new(),
                    nullifiers: Vec::new(),
                    proofless: false,
                })
                .collect();
            (transactions, next)
        }

        /// The nullifier stream, same ordering and cursor rule.
        fn matching_nullifiers(
            &self,
            nullifiers: &[[u8; 32]],
            cursor: Option<Vec<u8>>,
            limit: usize,
        ) -> (Vec<ShieldedTransaction>, Option<Vec<u8>>, Option<Vec<u8>>) {
            let after = cursor.as_ref().map(|bytes| {
                u64::from_be_bytes(bytes.as_slice().try_into().expect("8-byte cursor"))
            });
            self.nullifier_calls
                .lock()
                .expect("calls poisoned")
                .push((nullifiers.len(), after));

            let mut rows: Vec<_> = self
                .spends
                .iter()
                .filter(|(slot, nullifier)| {
                    nullifiers.contains(nullifier) && after.is_none_or(|after| *slot > after)
                })
                .collect();
            rows.sort_by_key(|(slot, _)| *slot);
            rows.truncate(limit);

            let next = rows.last().map(|(slot, _)| slot.to_be_bytes().to_vec());
            // Photon reports the position only when the limit did not cut the
            // scan short, and it is the tip of the whole stream, not of the
            // matching rows.
            let scanned_through = (rows.len() < limit)
                .then(|| self.stream_tip().map(|slot| slot.to_be_bytes().to_vec()))
                .flatten();
            let transactions = rows
                .into_iter()
                .map(|(slot, nullifier)| ShieldedTransaction {
                    slot: *slot,
                    tx_signature: Signature::from([*slot as u8; 64]),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: Vec::new(),
                    messages: Vec::new(),
                    nullifiers: vec![*nullifier],
                    proofless: false,
                })
                .collect();
            (transactions, next, scanned_through)
        }

        /// The greatest position in the stream, matching or not, as photon reads
        /// it straight off `rings_transactions`.
        fn stream_tip(&self) -> Option<u64> {
            self.entries
                .iter()
                .map(|(slot, _)| *slot)
                .chain(self.spends.iter().map(|(slot, _)| *slot))
                .max()
        }
    }

    #[derive(Default)]
    struct MockIndexer {
        transactions: Vec<ShieldedTransaction>,
        matches: Vec<EncryptedUtxoMatch>,
        /// Canned SplAssetRegistry accounts returned by `get_program_accounts`,
        /// used to exercise the lazy registry backfill during sync.
        program_accounts: Vec<(Address, solana_account::Account)>,
    }

    impl Rpc for MockIndexer {
        fn get_program_accounts(
            &self,
            _program_id: Address,
        ) -> Result<Vec<(Address, solana_account::Account)>, ClientError> {
            Ok(self.program_accounts.clone())
        }

        fn get_encrypted_utxos_by_tags(
            &self,
            _tags: Vec<ViewTag>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            Ok(GetEncryptedUtxosByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                matches: self.matches.clone(),
                next_cursor: None,
                scanned_through: None,
            })
        }

        fn get_shielded_transactions_by_tags(
            &self,
            _tags: Vec<ViewTag>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                transactions: self.transactions.clone(),
                next_cursor: None,
                scanned_through: None,
            })
        }

        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<ViewTag>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                transactions: self
                    .transactions
                    .iter()
                    .filter(|tx| tx.nullifiers.iter().any(|nf| nullifiers.contains(nf)))
                    .cloned()
                    .collect(),
                next_cursor: None,
                // Answers in one page and never paginates; resumption is covered
                // by TaggedIndexer.
                scanned_through: None,
            })
        }
    }

    impl Rpc for TaggedIndexer {
        fn get_program_accounts(
            &self,
            _program_id: Address,
        ) -> Result<Vec<(Address, solana_account::Account)>, ClientError> {
            Ok(Vec::new())
        }

        /// Pages the encrypted-utxo stream on the same rule as the tag stream,
        /// so a resume can be observed rather than assumed. The rows carry no
        /// decryptable payload -- this pins which positions were asked for, not
        /// what came back.
        fn get_encrypted_utxos_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            let limit = limit.unwrap_or(1_000).max(1) as usize;
            let after = cursor.as_ref().map(|bytes| {
                u64::from_be_bytes(bytes.as_slice().try_into().expect("8-byte cursor"))
            });
            self.utxo_calls
                .lock()
                .expect("calls poisoned")
                .push((tags.len(), after));

            let mut rows: Vec<_> = self
                .utxo_entries
                .iter()
                .filter(|(slot, tag)| tags.contains(tag) && after.is_none_or(|after| *slot > after))
                .collect();
            rows.sort_by_key(|(slot, _)| *slot);
            rows.truncate(limit);

            let next_cursor = rows.last().map(|(slot, _)| slot.to_be_bytes().to_vec());
            let matches = rows
                .into_iter()
                .map(|(slot, tag)| EncryptedUtxoMatch {
                    slot: *slot,
                    tx_signature: Signature::from([*slot as u8; 64]),
                    output_slot: OutputSlot {
                        view_tag: *tag,
                        output_context: OutputContext {
                            hash: [0u8; 32],
                            tree: Address::default(),
                            leaf_index: *slot,
                        },
                        payload: Vec::new(),
                    },
                    tx_viewing_pk: None,
                    salt: None,
                })
                .collect();
            Ok(GetEncryptedUtxosByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                matches,
                next_cursor,
                scanned_through: None,
            })
        }

        fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            let limit = limit.unwrap_or(1_000).max(1) as usize;
            let (transactions, next_cursor) = self.matching(&tags, cursor, limit);
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                transactions,
                next_cursor,
                scanned_through: None,
            })
        }

        /// Faithful to the server in the same way the tag method is: it honours
        /// the cursor and reports the last row's position even on a short page.
        /// The previous stub ignored both and always answered `None`, which is
        /// what let the nullifier path look incremental in tests while rescanning
        /// from zero against real photon.
        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            let limit = limit.unwrap_or(1_000).max(1) as usize;
            let (transactions, next_cursor, scanned_through) =
                self.matching_nullifiers(&nullifiers, cursor, limit);
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                transactions,
                next_cursor,
                scanned_through,
            })
        }
    }

    /// A tag that becomes relevant only AFTER an earlier sync has already moved
    /// past the slot its transactions live at must still be scanned from zero.
    ///
    /// This is the multi-device case. Tags are derived from a local counter plus a
    /// window of 64; when another device spends far enough ahead, this wallet's
    /// counter lags by more than the window and it does not yet know to ask for
    /// those tags. It learns the counter later -- by which time a single global
    /// cursor has advanced past the slots involved, and those transactions would
    /// be skipped permanently.
    ///
    /// A sync runs several rounds so that tags discovered by decrypting round N
    /// can be queried in round N+1. Tags already scanned to the tip of the
    /// stream must not be re-queried in the later rounds: on devnet that repeat
    /// was refetching the wallet's entire history a second time, and it is the
    /// single largest cost in a sync.
    ///
    /// Anything that lands mid-sync is picked up by the next sync, the same as
    /// a transaction landing a millisecond after the sync returns.
    #[test]
    fn a_tag_scanned_to_the_tip_is_not_requeried_in_a_later_round() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let viewing = keypair.viewing_key.clone();
        let early = viewing.get_sender_view_tag(0).expect("early tag");
        let late = viewing.get_sender_view_tag(500).expect("late tag");

        let indexer = TaggedIndexer {
            entries: vec![(10, early), (50, late)],
            ..Default::default()
        };

        let config = SyncWalletConfig::default();
        let mut out = HashMap::new();
        let mut cursors: HashMap<CursorStream, Vec<u8>> = HashMap::new();
        let mut scanned = HashSet::new();

        // Round 0: only the early tag is known.
        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags(early)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut scanned,
        )
        .expect("round 0");

        // Round 1: decryption revealed the late tag. The early tag is already
        // scanned to the tip, so only the late one is worth a request.
        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags(early), CursorStream::Tags(late)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut scanned,
        )
        .expect("round 1");

        // Two requests per round: one for the rows, one that comes back empty
        // and ends the stream. What matters is that no request ever carries two
        // tags -- the early tag is never re-queried.
        assert_eq!(
            *indexer.calls.lock().expect("calls poisoned"),
            vec![(1, None), (1, Some(10)), (1, None), (1, Some(50))],
            "round 1 must ask for the late tag alone, not both tags again"
        );
    }

    /// A wallet whose whole history fits in one page must still record where it
    /// got to. Photon used to return no cursor for a short page, which is right
    /// for pagination and wrong for resumption: such a wallet recorded nothing
    /// and refetched its entire history on every sync, growing with every
    /// transfer. On devnet an 881-transaction wallet spent 2.4s of a 5.0s sync
    /// doing exactly that.
    ///
    /// The stream now ends on the following empty page instead.
    #[test]
    fn a_short_page_still_advances_the_cursor_to_the_tip() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let tag = keypair.viewing_key.get_sender_view_tag(0).expect("tag");

        let indexer = TaggedIndexer {
            entries: vec![(10, tag), (50, tag)],
            ..Default::default()
        };

        let mut out = HashMap::new();
        let mut cursors: HashMap<CursorStream, Vec<u8>> = HashMap::new();
        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags(tag)],
            &mut out,
            SyncWalletConfig::default(),
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("sync");

        assert_eq!(
            cursors
                .get(&CursorStream::Tags(tag))
                .map(|c| u64::from_be_bytes(c.as_slice().try_into().expect("8-byte cursor"))),
            Some(50),
            "a short page still records the tip, so the next sync resumes there"
        );
        assert_eq!(
            *indexer.calls.lock().expect("calls poisoned"),
            vec![(1, None), (1, Some(50))],
            "one request for the rows, one more that returns none and ends the loop"
        );
    }

    /// A spent UTXO is never asked about again.
    ///
    /// A nullifier appears at most once on chain -- that is what it is for -- so
    /// once the spending transaction is in hand the answer is final. Asking again
    /// returns the same row forever. The query set therefore tracks the unspent
    /// UTXO count rather than growing with history: on a devnet wallet holding
    /// 293 UTXOs of which 237 were already spent, dropping them took the round-0
    /// nullifier fetch from 732ms to 83ms, a third of total sync time to a
    /// twentieth.
    #[test]
    fn spent_utxos_drop_out_of_the_nullifier_query() {
        let owner = ShieldedKeypair::new_p256().expect("keypair");
        let mut wallet = wallet_with_utxos(&owner, &[(SOL_MINT, 100, 1), (SOL_MINT, 200, 2)]);

        assert_eq!(
            wallet_query_nullifiers(&wallet).len(),
            2,
            "both UTXOs are unspent, so both are still open questions"
        );

        let spent_nullifier = wallet.utxos.first().expect("first utxo").nullifier;
        wallet.utxos.first_mut().expect("first utxo").spent = true;

        let queried = wallet_query_nullifiers(&wallet);
        assert_eq!(queried.len(), 1, "the spent UTXO is no longer asked about");
        assert!(
            !queried.contains(&spent_nullifier),
            "and it is specifically the spent one that was dropped"
        );

        // The narrowed set is what actually reaches the indexer.
        let indexer = TaggedIndexer {
            spends: vec![(10, spent_nullifier)],
            ..Default::default()
        };
        fetch_shielded_transactions_by_nullifiers(
            &indexer,
            &stream_keys(&queried, CursorStream::Nullifiers),
            &mut HashMap::new(),
            SyncWalletConfig::default(),
            None,
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("fetch");

        assert_eq!(
            *indexer.nullifier_calls.lock().expect("calls poisoned"),
            vec![(1, None)],
            "one request carrying one nullifier, not the whole utxo history"
        );
    }

    /// A cursor means there may be more; only its absence ends the read. Every
    /// stream pages through [`advance`], so this is the rule for all three.
    ///
    /// Guessing from page size instead would save a request per chunk, and was
    /// tried: it makes the non-advancing-cursor guard unreachable, and stakes
    /// correctness on every endpoint returning a short page only when genuinely
    /// out of rows. Skipping a spend silently is not worth a round trip.
    #[test]
    fn only_a_missing_cursor_ends_the_read() {
        let cursor = |slot: u64| Some(slot.to_be_bytes().to_vec());

        let mut furthest = None;
        assert_eq!(
            advance(
                &mut furthest,
                Page {
                    next_cursor: cursor(50),
                    scanned_through: None,
                },
            ),
            cursor(50),
            "a cursor is an invitation to read on"
        );

        let mut furthest = cursor(10);
        assert!(
            advance(
                &mut furthest,
                Page {
                    next_cursor: None,
                    scanned_through: None,
                },
            )
            .is_none(),
            "no cursor ends it"
        );
        assert_eq!(furthest, cursor(10), "and the earlier position is kept");

        // The nullifier stream's pages are normally empty, so its position comes
        // from the server rather than from a row.
        let mut furthest = None;
        assert!(advance(
            &mut furthest,
            Page {
                next_cursor: None,
                scanned_through: cursor(99),
            },
        )
        .is_none());
        assert_eq!(furthest, cursor(99));
    }

    /// The async twins page and resume like the blocking ones.
    ///
    /// They drive their own loop, so a change to one is not caught by the other
    /// even though they share [`advance`]. Covers all three streams at once.
    #[tokio::test]
    async fn the_async_paths_resume_every_stream() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let tag = keypair.viewing_key.get_sender_view_tag(0).expect("tag");
        let unspent = [7u8; 32];
        let indexer = TaggedIndexer {
            entries: vec![(10, tag), (50, tag)],
            spends: vec![(20, [9u8; 32])],
            utxo_entries: vec![(30, tag)],
            ..Default::default()
        };
        let config = SyncWalletConfig::default();

        let mut tag_cursors = HashMap::new();
        fetch_shielded_transactions_incremental_async(
            &indexer,
            &[CursorStream::Tags(tag)],
            &mut HashMap::new(),
            config,
            None,
            &mut tag_cursors,
            &mut HashSet::new(),
        )
        .await
        .expect("tags");
        assert_eq!(
            tag_cursors.get(&CursorStream::Tags(tag)).map(slot_of),
            Some(50)
        );

        let mut nullifier_cursors = HashMap::new();
        fetch_shielded_transactions_by_nullifiers_async(
            &indexer,
            &[CursorStream::Nullifiers(unspent)],
            &mut HashMap::new(),
            config,
            None,
            &mut nullifier_cursors,
            &mut HashSet::new(),
        )
        .await
        .expect("nullifiers");
        assert_eq!(
            nullifier_cursors
                .get(&CursorStream::Nullifiers(unspent))
                .map(slot_of),
            Some(50),
            "no spend matched, so the position comes from the reported scan"
        );

        let mut proofless_cursors = HashMap::new();
        fetch_proofless_deposits_async(
            &indexer,
            &[CursorStream::Proofless(tag)],
            &mut HashMap::new(),
            config,
            None,
            &mut proofless_cursors,
            &mut HashSet::new(),
        )
        .await
        .expect("proofless");
        assert_eq!(
            proofless_cursors
                .get(&CursorStream::Proofless(tag))
                .map(slot_of),
            Some(30)
        );

        // The streams that return rows take a second request to reach the empty
        // page that ends them. The nullifier stream matches nothing, so its
        // first page is already the last.
        assert_eq!(indexer.calls.lock().expect("calls poisoned").len(), 2);
        assert_eq!(indexer.utxo_calls.lock().expect("calls poisoned").len(), 2);
        assert_eq!(
            indexer
                .nullifier_calls
                .lock()
                .expect("calls poisoned")
                .len(),
            1
        );
    }

    fn slot_of(cursor: &Vec<u8>) -> u64 {
        u64::from_be_bytes(cursor.as_slice().try_into().expect("8-byte cursor"))
    }

    /// A second sync resumes the nullifier stream instead of walking it again.
    ///
    /// This is what the indexer's `scanned_through` buys. The rows cannot supply
    /// it: an unspent nullifier matches nothing, so there is no last row whose
    /// position could be remembered, and every sync would start from zero.
    #[test]
    fn a_second_sync_resumes_the_nullifier_stream() {
        let unspent = [7u8; 32];
        // A stream with traffic in it, none of which spends `unspent`.
        let indexer = TaggedIndexer {
            spends: vec![(10, [9u8; 32]), (50, [9u8; 32])],
            ..Default::default()
        };

        let config = SyncWalletConfig::default();
        let mut out = HashMap::new();
        let mut cursors: HashMap<CursorStream, Vec<u8>> = HashMap::new();

        fetch_shielded_transactions_by_nullifiers(
            &indexer,
            &[CursorStream::Nullifiers(unspent)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("first sync");

        assert_eq!(
            cursors
                .get(&CursorStream::Nullifiers(unspent))
                .map(|c| u64::from_be_bytes(c.as_slice().try_into().expect("8-byte cursor"))),
            Some(50),
            "nothing matched, but the scan still reached the tip of the stream"
        );

        // A fresh scanned_to_tip, as a later sync would have.
        indexer
            .nullifier_calls
            .lock()
            .expect("calls poisoned")
            .clear();
        fetch_shielded_transactions_by_nullifiers(
            &indexer,
            &[CursorStream::Nullifiers(unspent)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("second sync");

        assert_eq!(
            *indexer.nullifier_calls.lock().expect("calls poisoned"),
            vec![(1, Some(50))],
            "the second sync resumes at 50 rather than rescanning from zero"
        );
    }

    /// A second sync resumes the encrypted-utxo stream instead of re-reading it.
    ///
    /// This is the test the change that introduced `proofless_cursors` said it
    /// could not write: the old mock answered every page with `next_cursor:
    /// None`, so the client looked incremental while re-reading everything. It
    /// pins what the client *sends* -- that the second sync carries the position
    /// the first one reached. Whether photon reports that position the same way
    /// is the local stack's job, not this one's.
    #[test]
    fn a_second_sync_resumes_the_proofless_stream() {
        let tag = ViewTag::from([5u8; 32]);
        let indexer = TaggedIndexer {
            utxo_entries: vec![(10, tag), (50, tag)],
            ..Default::default()
        };

        let config = SyncWalletConfig::default();
        let mut out = HashMap::new();
        let mut cursors: HashMap<CursorStream, Vec<u8>> = HashMap::new();

        fetch_proofless_deposits(
            &indexer,
            &[CursorStream::Proofless(tag)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("first sync");

        assert_eq!(
            cursors
                .get(&CursorStream::Proofless(tag))
                .map(|c| u64::from_be_bytes(c.as_slice().try_into().expect("8-byte cursor"))),
            Some(50),
            "the scan read to the last row, so that is where it resumes"
        );

        // A fresh scanned_to_tip, as a later sync would have.
        indexer.utxo_calls.lock().expect("calls poisoned").clear();
        fetch_proofless_deposits(
            &indexer,
            &[CursorStream::Proofless(tag)],
            &mut out,
            config,
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("second sync");

        assert_eq!(
            *indexer.utxo_calls.lock().expect("calls poisoned"),
            vec![(1, Some(50))],
            "the second sync resumes at 50 rather than re-reading the stream"
        );
    }

    /// Guards the fix: cursors are tracked PER TAG, so a newly-discovered tag
    /// starts from None regardless of how far other tags have advanced.
    #[test]
    fn a_late_discovered_tag_is_scanned_from_the_beginning() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let viewing = keypair.viewing_key.clone();

        // The tag this wallet knows about from the start, and one far outside the
        // initial window -- what a second device would have been using.
        let early = viewing.get_sender_view_tag(0).expect("early tag");
        let late = viewing.get_sender_view_tag(500).expect("late tag");
        assert_ne!(early, late);

        let indexer = TaggedIndexer {
            // The late tag's transaction sits at a LOWER slot than the early
            // one's, so a global cursor advanced past slot 50 would skip it.
            entries: vec![(10, late), (50, early)],
            ..Default::default()
        };

        // page_limit 1 so every page is full and photon hands back a cursor.
        // At the default limit these two rows are one short page, which by
        // photon's rule carries no cursor at all -- see
        // `a_short_page_ends_the_stream_and_advances_no_cursor`.
        let config = SyncWalletConfig {
            page_limit: 1,
            ..SyncWalletConfig::default()
        };
        let mut cursors: HashMap<CursorStream, Vec<u8>> = HashMap::new();

        // First sync knows only the early tag, and advances past slot 50.
        let mut first = HashMap::new();
        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags(early)],
            &mut first,
            config,
            None,
            &mut cursors,
            // A fresh set per sync: "scanned to the tip" is only true of the
            // sync that did the scanning.
            &mut HashSet::new(),
        )
        .expect("first sync");
        assert_eq!(
            cursors
                .get(&CursorStream::Tags(early))
                .map(|c| u64::from_be_bytes(c.as_slice().try_into().unwrap())),
            Some(50),
            "the early tag should have advanced to the last row it saw"
        );
        assert!(
            !cursors.contains_key(&CursorStream::Tags(late)),
            "a tag that was never queried must not carry a cursor"
        );

        // Second sync has learned the late tag.
        indexer.calls.lock().expect("calls poisoned").clear();
        let mut second = HashMap::new();
        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags(early), CursorStream::Tags(late)],
            &mut second,
            config,
            None,
            &mut cursors,
            &mut HashSet::new(),
        )
        .expect("second sync");

        // Asserting on what was REQUESTED rather than what was decrypted: the
        // invariant is which rows the indexer was asked for, and fabricating
        // decryptable P256 payloads would test the crypto instead.
        let calls = indexer.calls.lock().expect("calls poisoned");
        assert!(
            calls.iter().any(|(_, after)| after.is_none()),
            "the newly discovered tag must be scanned from the beginning, not from \
             the cursor another tag advanced to; calls were {calls:?}"
        );
        assert!(
            calls.iter().any(|(_, after)| *after == Some(50)),
            "the already-synced tag should resume rather than rescan; calls were {calls:?}"
        );
    }

    /// Delegates to the blocking impl so the async paths can be driven by the
    /// same paging mock. They keep their own loop, so nothing else checks that
    /// they page and resume the way the blocking paths do.
    #[async_trait::async_trait]
    impl AsyncRpc for TaggedIndexer {
        async fn get_program_accounts(
            &self,
            program_id: Address,
        ) -> Result<Vec<(Address, solana_account::Account)>, ClientError> {
            Rpc::get_program_accounts(self, program_id)
        }

        async fn get_encrypted_utxos_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            Rpc::get_encrypted_utxos_by_tags(self, tags, cursor, limit, config)
        }

        async fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Rpc::get_shielded_transactions_by_tags(self, tags, cursor, limit, config)
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Rpc::get_shielded_transactions_by_nullifiers(self, nullifiers, cursor, limit, config)
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for MockIndexer {
        async fn get_program_accounts(
            &self,
            program_id: Address,
        ) -> Result<Vec<(Address, solana_account::Account)>, ClientError> {
            Rpc::get_program_accounts(self, program_id)
        }

        async fn get_encrypted_utxos_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            Rpc::get_encrypted_utxos_by_tags(self, tags, cursor, limit, config)
        }

        async fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Rpc::get_shielded_transactions_by_tags(self, tags, cursor, limit, config)
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<ViewTag>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Rpc::get_shielded_transactions_by_nullifiers(self, nullifiers, cursor, limit, config)
        }
    }

    const SPL_ASSET_ID: u64 = 2;
    const SPL_MINT: Address = Address::new_from_array([2u8; 32]);

    fn local_authority(keypair: &ShieldedKeypair) -> KeypairWalletAuthority<'_> {
        KeypairWalletAuthority::new(Address::default(), keypair)
    }

    fn ed25519_keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("Ed25519 keypair")
    }

    #[tokio::test]
    async fn async_sync_future_is_send_and_keeps_wallet_keyless() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let authority = local_authority(&keypair);
        let indexer = MockIndexer::default();
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let future = sync_wallet_async(&mut wallet, &authority, &indexer);
        fn assert_send<T: Send>(value: T) -> T {
            value
        }

        let report = assert_send(future).await.expect("async sync");

        assert_eq!(report, SyncReport::default());
        assert!(wallet.utxos.is_empty());
    }

    #[test]
    fn sync_wallet_records_confidential_transfer_history_without_duplicates() {
        let assets = AssetRegistry::default();
        let alice = ed25519_keypair(1);
        let bob = ed25519_keypair(2);
        let funding = confidential_transfer_tx(&bob, &alice, SOL_MINT, 100, 1, &assets);

        let mut wallet = Wallet::new(
            alice.shielded_address().expect("shielded address"),
            assets.clone(),
        )
        .expect("wallet");
        sync_wallet(
            &mut wallet,
            &local_authority(&alice),
            &MockIndexer {
                transactions: vec![funding.clone()],
                matches: Vec::new(),
                program_accounts: Vec::new(),
            },
        )
        .expect("sync funding");
        assert_eq!(wallet.private_transactions().len(), 1);
        let inbound = wallet.private_transactions().first().expect("inbound");
        assert_eq!(inbound.kind, PrivateTransactionKind::PrivateTransfer);
        assert_eq!(inbound.direction, PrivateTransactionDirection::Inbound);
        assert_eq!(inbound.amount, 100);
        assert_eq!(inbound.counterparty_viewing_pubkey, None);

        let spend = SppProofInputUtxo::new(wallet.utxos[0].utxo.clone(), &alice);
        let outbound = signed_to_shielded_tx(
            confidential_send(&alice, vec![spend], &bob, SOL_MINT, 40, &assets),
            2,
        );
        let indexer = MockIndexer {
            transactions: vec![funding, outbound],
            matches: Vec::new(),
            program_accounts: Vec::new(),
        };

        sync_wallet(&mut wallet, &local_authority(&alice), &indexer).expect("sync outbound");
        sync_wallet(&mut wallet, &local_authority(&alice), &indexer).expect("resync is idempotent");

        assert_eq!(wallet.private_transactions().len(), 2);
        let outbound = wallet
            .private_transactions()
            .iter()
            .find(|tx| tx.direction == PrivateTransactionDirection::Outbound)
            .expect("outbound row");
        assert_eq!(outbound.kind, PrivateTransactionKind::PrivateTransfer);
        assert_eq!(outbound.asset, SOL_MINT);
        assert_eq!(outbound.amount, 40);
        assert_eq!(
            outbound.counterparty_viewing_pubkey,
            Some(bob.viewing_pubkey())
        );
    }

    #[test]
    fn sync_wallet_classifies_confidential_send_to_self() {
        let assets = AssetRegistry::default();
        let alice = ed25519_keypair(3);
        let mut wallet = wallet_with_utxo(&alice, SOL_MINT, 100, 4);
        let funded = wallet
            .utxos
            .first()
            .expect("the wallet was funded with one UTXO")
            .utxo
            .clone();
        let spend = SppProofInputUtxo::new(funded, &alice);
        let transfer = signed_to_shielded_tx(
            confidential_send(&alice, vec![spend], &alice, SOL_MINT, 40, &assets),
            1,
        );
        let indexer = MockIndexer {
            transactions: vec![transfer],
            matches: Vec::new(),
            program_accounts: Vec::new(),
        };

        sync_wallet(&mut wallet, &local_authority(&alice), &indexer).expect("sync self transfer");

        // A wallet synced by an older build carries the outbound classification.
        // The rescan must replace that row, not add a second one beside it.
        wallet
            .transactions
            .first_mut()
            .expect("the first sync recorded the row")
            .direction = PrivateTransactionDirection::Outbound;
        sync_wallet(&mut wallet, &local_authority(&alice), &indexer)
            .expect("replace stale outbound classification");

        let transactions = wallet.private_transactions();
        let [row] = transactions else {
            panic!("expected exactly one row, got {}", transactions.len());
        };
        assert_eq!(
            *row,
            PrivateTransaction {
                // Derived from the built transaction, so it is read back rather
                // than hardcoded; every other field is pinned.
                id: row.id.clone(),
                kind: PrivateTransactionKind::PrivateTransfer,
                direction: PrivateTransactionDirection::SelfTransfer,
                status: PrivateTransactionStatus::Confirmed,
                asset: SOL_MINT,
                amount: 40,
                counterparty_viewing_pubkey: Some(alice.viewing_pubkey()),
            }
        );
    }

    /// A self transfer addressed to a viewing key the wallet has since rotated
    /// out is still a self transfer. Recognizing only the current key would
    /// classify it as `Outbound` -- and only wallets that use the historical-key
    /// support can reach it, since a rotated-out key has no other way in.
    #[test]
    fn sync_wallet_classifies_a_send_to_a_rotated_out_viewing_key_as_self() {
        let assets = AssetRegistry::default();
        let signing = SigningKey::from_ed25519_bytes(&[11u8; 32]);
        // Same signing and nullifier roles, two viewing keys: the wallet before
        // and after a rotation. The UTXO owner and nullifiers are unchanged, so
        // the pre-rotation transaction is still this wallet's to decode.
        let retired = ShieldedKeypair::with_viewing_key(
            signing.clone(),
            ViewingKey::from_bytes(&[21u8; 32]).expect("retired viewing key"),
        )
        .expect("pre-rotation keypair");
        let current = ShieldedKeypair::with_viewing_key(
            signing,
            ViewingKey::from_bytes(&[22u8; 32]).expect("current viewing key"),
        )
        .expect("post-rotation keypair");

        let mut wallet = wallet_with_utxo(&current, SOL_MINT, 100, 12);
        let funded = wallet
            .utxos
            .first()
            .expect("the wallet was funded with one UTXO")
            .utxo
            .clone();
        let transfer = signed_to_shielded_tx(
            confidential_send(
                &retired,
                vec![SppProofInputUtxo::new(funded, &retired)],
                &retired,
                SOL_MINT,
                40,
                &assets,
            ),
            1,
        );
        let authority = KeypairWalletAuthority::with_viewing_keys(
            Address::default(),
            &current,
            vec![current.viewing_key.clone(), retired.viewing_key.clone()],
        )
        .expect("current key is present alongside the retired one");

        sync_wallet(
            &mut wallet,
            &authority,
            &MockIndexer {
                transactions: vec![transfer],
                matches: Vec::new(),
                program_accounts: Vec::new(),
            },
        )
        .expect("sync across the rotation");

        let self_rows = wallet
            .private_transactions()
            .iter()
            .filter(|tx| tx.direction == PrivateTransactionDirection::SelfTransfer)
            .map(|tx| (tx.asset, tx.amount, tx.counterparty_viewing_pubkey))
            .collect::<Vec<_>>();
        assert_eq!(
            self_rows,
            vec![(SOL_MINT, 40, Some(retired.viewing_pubkey()))],
            "history={:?}",
            wallet.private_transactions()
        );
        assert!(
            !wallet
                .private_transactions()
                .iter()
                .any(|tx| tx.direction == PrivateTransactionDirection::Outbound),
            "a send to a retired own key must leave no outbound row; history={:?}",
            wallet.private_transactions()
        );
    }

    #[test]
    fn sync_wallet_decodes_confidential_recipient_across_supported_shapes() {
        let assets = AssetRegistry::default();

        for (case, shape) in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= 3)
            .enumerate()
        {
            let sender = ed25519_keypair(3);
            let recipient = ed25519_keypair(4);
            let recipient_count = shape.n_outputs() - 2;
            let input = SppProofInputUtxo::new(
                test_utxo(&sender, SOL_MINT, recipient_count as u64, case as u8),
                &sender,
            );
            let mut transfer = ConfidentialTransfer::new(
                sender.shielded_address().expect("sender address"),
                vec![input],
                Address::default(),
            )
            .with_shape(shape);

            for _ in 1..recipient_count {
                let decoy = ed25519_keypair(5);
                transfer
                    .send(
                        &decoy.shielded_address().expect("decoy address"),
                        SOL_MINT,
                        1,
                    )
                    .expect("send to decoy");
            }
            transfer
                .send(
                    &recipient.shielded_address().expect("recipient address"),
                    SOL_MINT,
                    1,
                )
                .expect("send to recipient");

            let proof_inputs = transfer.sign(&sender, &assets).expect("sign");
            assert_eq!(proof_inputs.check_shape().expect("shape"), shape);
            let tx = signed_to_shielded_tx(proof_inputs, case as u64 + 1);
            let mut wallet = Wallet::new(
                recipient.shielded_address().expect("recipient address"),
                assets.clone(),
            )
            .expect("wallet");

            sync_wallet(
                &mut wallet,
                &local_authority(&recipient),
                &MockIndexer {
                    transactions: vec![tx],
                    matches: Vec::new(),
                    program_accounts: Vec::new(),
                },
            )
            .expect("sync recipient");

            assert_eq!(wallet.utxos.len(), 1, "shape {shape:?}");
            assert_eq!(wallet.utxos[0].utxo.amount, 1, "shape {shape:?}");
        }
    }

    #[test]
    fn sync_wallet_records_confidential_public_withdrawal_history() {
        let assets = AssetRegistry::default();
        let alice = ed25519_keypair(6);
        let input = SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 100, 7), &alice);
        let withdrawal = signed_to_shielded_tx(
            confidential_withdrawal(&alice, vec![input], SOL_MINT, 30, &assets),
            1,
        );
        let mut wallet = wallet_with_utxo(&alice, SOL_MINT, 100, 7);

        sync_wallet(
            &mut wallet,
            &local_authority(&alice),
            &MockIndexer {
                transactions: vec![withdrawal],
                matches: Vec::new(),
                program_accounts: Vec::new(),
            },
        )
        .expect("sync withdrawal");

        let txs = wallet.private_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].kind, PrivateTransactionKind::PublicWithdrawal);
        assert_eq!(txs[0].direction, PrivateTransactionDirection::Outbound);
        assert_eq!(txs[0].asset, SOL_MINT);
        assert_eq!(txs[0].amount, 30);
        assert_eq!(txs[0].counterparty_viewing_pubkey, None);
    }

    #[test]
    fn sync_wallet_records_confidential_multi_asset_outbound_rows() {
        let assets = AssetRegistry::new([(SPL_ASSET_ID, SPL_MINT)]).expect("assets");
        let alice = ed25519_keypair(7);
        let bob = ed25519_keypair(8);
        let inputs = vec![
            SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 100, 8), &alice),
            SppProofInputUtxo::new(test_utxo(&alice, SPL_MINT, 100, 9), &alice),
        ];
        let tx = signed_to_shielded_tx(
            confidential_send_and_withdraw(
                &alice, inputs, &bob, SPL_MINT, 60, SOL_MINT, 30, &assets,
            ),
            1,
        );
        let mut wallet = wallet_with_utxos(&alice, &[(SOL_MINT, 100, 8), (SPL_MINT, 100, 9)]);

        sync_wallet(
            &mut wallet,
            &local_authority(&alice),
            &MockIndexer {
                transactions: vec![tx],
                matches: Vec::new(),
                program_accounts: Vec::new(),
            },
        )
        .expect("sync mixed outbound");

        let mut outbound = wallet
            .private_transactions()
            .iter()
            .filter(|tx| tx.direction == PrivateTransactionDirection::Outbound)
            .map(|tx| (tx.asset, tx.amount))
            .collect::<Vec<_>>();
        outbound.sort_by_key(|(asset, _)| *asset);
        let mut expected = vec![(SOL_MINT, 30), (SPL_MINT, 60)];
        expected.sort_by_key(|(asset, _)| *asset);
        assert_eq!(outbound, expected);
    }

    #[test]
    fn sync_wallet_records_merge_history() {
        let alice = ShieldedKeypair::new_p256().expect("alice");
        let inputs = vec![
            SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 30, 10), &alice),
            SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 70, 11), &alice),
        ];
        let tx = merge_tx(&alice, inputs, 1);
        let mut wallet = wallet_with_utxos(&alice, &[(SOL_MINT, 30, 10), (SOL_MINT, 70, 11)]);

        let report = sync_wallet(
            &mut wallet,
            &local_authority(&alice),
            &MockIndexer {
                transactions: vec![tx],
                matches: Vec::new(),
                program_accounts: Vec::new(),
            },
        )
        .expect("sync merge");
        assert_eq!(report.undecryptable_candidates, 0);

        let txs = wallet.private_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].kind, PrivateTransactionKind::Merge);
        assert_eq!(txs[0].direction, PrivateTransactionDirection::SelfTransfer);
        assert_eq!(txs[0].asset, SOL_MINT);
        assert_eq!(txs[0].amount, 100);
    }

    #[test]
    fn shielded_fetch_skips_rows_without_viewing_material() {
        let indexer = MockIndexer {
            transactions: vec![ShieldedTransaction {
                slot: 1,
                tx_signature: Signature::default(),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![OutputSlot {
                    view_tag: [1u8; 32],
                    output_context: OutputContext {
                        hash: [0u8; 32],
                        tree: Address::new_from_array([0u8; 32]),
                        leaf_index: 0,
                    },
                    payload: Vec::new(),
                }],
                messages: Vec::new(),
                nullifiers: Vec::new(),
                proofless: false,
            }],
            matches: Vec::new(),
            program_accounts: Vec::new(),
        };
        let mut out = HashMap::new();

        fetch_shielded_transactions_incremental(
            &indexer,
            &[CursorStream::Tags([1u8; 32])],
            &mut out,
            SyncWalletConfig::default(),
            None,
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("skip plaintext row");

        assert!(out.is_empty());
    }

    #[test]
    fn proofless_fetch_decodes_indexed_payload() {
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let output = proofless_output_for_keypair(&keypair, 1_234);
        let item = encrypted_match(&keypair, output.clone());
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![item],
            program_accounts: Vec::new(),
        };
        let mut out = HashMap::new();

        fetch_proofless_deposits(
            &indexer,
            &[CursorStream::Proofless(
                keypair.recipient_bootstrap_view_tag(),
            )],
            &mut out,
            SyncWalletConfig::default(),
            None,
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("decode proofless payload");

        let deposit = out.values().next().expect("proofless deposit");
        assert!(deposit.proofless);
        let slot = deposit.output_slots.first().expect("proofless slot");
        assert_eq!(slot.view_tag, keypair.recipient_bootstrap_view_tag());
        assert_eq!(slot.output_context.tree.to_bytes(), [7u8; 32]);
        assert_eq!(slot.output_context.leaf_index, 13);
        let decoded = decode_output_data(&slot.payload).expect("decode proofless output");
        assert_eq!(decoded.owner, output.owner);
        assert_eq!(decoded.blinding, output.blinding);
        assert_eq!(decoded.amount, output.amount);
    }

    #[test]
    fn sync_wallet_discovers_indexed_proofless_deposit() {
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_keypair(&keypair, 42);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&keypair, output)],
            program_accounts: Vec::new(),
        };

        sync_wallet(&mut wallet, &local_authority(&keypair), &indexer)
            .expect("sync indexed proofless deposit");

        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[0].utxo.amount, 42);
        assert!(!wallet.utxos[0].spent);
        assert_eq!(wallet.private_transactions().len(), 1);
        let tx = &wallet.private_transactions()[0];
        assert_eq!(tx.kind, zolana_transaction::PrivateTransactionKind::Deposit);
        assert_eq!(
            tx.direction,
            zolana_transaction::PrivateTransactionDirection::Inbound
        );
        assert_eq!(tx.amount, 42);
        assert_eq!(tx.id.slot, 1);
        assert_eq!(tx.id.index, 13);
    }

    #[test]
    fn get_private_token_balances_aggregates_unspent_utxos() {
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_keypair(&keypair, 42);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&keypair, output)],
            program_accounts: Vec::new(),
        };

        sync_wallet(&mut wallet, &local_authority(&keypair), &indexer)
            .expect("sync indexed proofless deposit");

        let balances = get_private_token_balances(&wallet).expect("balances");
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].amount, 42);
        assert_eq!(balances[0].mint, SOL_MINT);
        assert!(balances[0].utxos.is_empty());
    }

    #[test]
    fn get_private_transactions_matches_wallet_history() {
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_keypair(&keypair, 7);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&keypair, output)],
            program_accounts: Vec::new(),
        };

        sync_wallet(&mut wallet, &local_authority(&keypair), &indexer)
            .expect("sync indexed proofless deposit");

        let txs = get_private_transactions(&wallet);
        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0].kind,
            zolana_transaction::PrivateTransactionKind::Deposit
        );
        assert_eq!(txs[0].amount, 7);
    }

    #[test]
    fn proofless_fetch_skips_rows_with_viewing_material() {
        let keypair = ShieldedKeypair::new_p256().expect("shielded keypair");
        let mut item = encrypted_match(&keypair, proofless_output_for_keypair(&keypair, 1));
        item.salt = Some([1u8; 16]);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![item],
            program_accounts: Vec::new(),
        };
        let mut out = HashMap::new();

        fetch_proofless_deposits(
            &indexer,
            &[CursorStream::Proofless(
                keypair.recipient_bootstrap_view_tag(),
            )],
            &mut out,
            SyncWalletConfig::default(),
            None,
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("skip encrypted row");

        assert!(out.is_empty());
    }

    fn confidential_transfer_tx(
        sender: &ShieldedKeypair,
        recipient: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        slot: u64,
        assets: &AssetRegistry,
    ) -> ShieldedTransaction {
        let input = SppProofInputUtxo::new(test_utxo(sender, asset, amount, slot as u8), sender);
        signed_to_shielded_tx(
            confidential_send(sender, vec![input], recipient, asset, amount, assets),
            slot,
        )
    }

    fn confidential_send(
        sender: &ShieldedKeypair,
        inputs: Vec<SppProofInputUtxo>,
        recipient: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        assets: &AssetRegistry,
    ) -> SppProofInputs {
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        transfer
            .send(
                &recipient.shielded_address().expect("recipient address"),
                asset,
                amount,
            )
            .expect("send");
        transfer.sign(sender, assets).expect("sign")
    }

    #[allow(clippy::too_many_arguments)]
    fn confidential_send_and_withdraw(
        sender: &ShieldedKeypair,
        inputs: Vec<SppProofInputUtxo>,
        recipient: &ShieldedKeypair,
        send_asset: Address,
        send_amount: u64,
        withdraw_asset: Address,
        withdraw_amount: u64,
        assets: &AssetRegistry,
    ) -> SppProofInputs {
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        transfer
            .send(
                &recipient.shielded_address().expect("recipient address"),
                send_asset,
                send_amount,
            )
            .expect("send");
        transfer
            .withdraw(
                withdraw_asset,
                withdraw_amount,
                SettlementTarget::Sol {
                    user_sol_account: Address::new_from_array([9u8; 32]),
                },
            )
            .expect("withdraw");
        transfer.sign(sender, assets).expect("sign")
    }

    fn confidential_withdrawal(
        sender: &ShieldedKeypair,
        inputs: Vec<SppProofInputUtxo>,
        asset: Address,
        amount: u64,
        assets: &AssetRegistry,
    ) -> SppProofInputs {
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        transfer
            .withdraw(
                asset,
                amount,
                SettlementTarget::Sol {
                    user_sol_account: Address::new_from_array([9u8; 32]),
                },
            )
            .expect("withdraw");
        transfer.sign(sender, assets).expect("sign")
    }

    fn signed_to_shielded_tx(proof_inputs: SppProofInputs, slot: u64) -> ShieldedTransaction {
        let nullifiers = proof_inputs
            .input_utxo_hashes()
            .expect("input commitments")
            .into_iter()
            .map(|commitment| commitment.nullifier)
            .collect();
        let external = proof_inputs.external_data;
        let messages = external.messages.clone();
        // Mirror the on-chain event 1:1: every output publishes its resolved owner
        // tag as the `view_tag` and its optional ciphertext as the payload; a
        // change slot covered by the sender bundle carries the sender tag with an
        // empty payload, which `Wallet::sync` skips.
        let output_slots = external
            .outputs
            .iter()
            .zip(external.resolved_owner_tags.iter())
            .enumerate()
            .map(|(i, (output, view_tag))| OutputSlot {
                view_tag: *view_tag,
                output_context: OutputContext {
                    hash: output.utxo_hash,
                    tree: Address::new_from_array([slot as u8; 32]),
                    leaf_index: i as u64,
                },
                payload: output.data.clone().unwrap_or_default(),
            })
            .collect();
        ShieldedTransaction {
            slot,
            tx_signature: signature_for_slot(slot),
            tx_viewing_pk: Some(
                zolana_keypair::P256Pubkey::from_bytes(external.tx_viewing_pk)
                    .expect("tx viewing pk"),
            ),
            salt: Some(external.salt),
            output_slots,
            messages,
            nullifiers,
            proofless: false,
        }
    }

    fn merge_tx(
        owner: &ShieldedKeypair,
        inputs: Vec<SppProofInputUtxo>,
        slot: u64,
    ) -> ShieldedTransaction {
        let merge = MergePlan::new(owner, inputs).expect("merge plan");
        let prepared = merge.prepare();
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        let output = Utxo {
            owner: owner.signing_pubkey(),
            asset: prepared.output.asset,
            amount: prepared.output.amount,
            blinding: prepared.output.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let output_hash = output
            .hash(
                &owner.nullifier_key.pubkey().expect("nullifier pubkey"),
                &[0u8; 32],
                &[0u8; 32],
            )
            .expect("output hash");
        let output_view_tag = owner
            .signing_pubkey()
            .confidential_view_tag()
            .expect("owner tag");
        ShieldedTransaction {
            slot,
            tx_signature: signature_for_slot(slot),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: output_view_tag,
                output_context: OutputContext {
                    hash: output_hash,
                    tree: Address::new_from_array([slot as u8; 32]),
                    leaf_index: 0,
                },
                payload: Vec::new(),
            }],
            messages: Vec::new(),
            nullifiers: commitments
                .into_iter()
                .map(|commitment| commitment.nullifier)
                .collect(),
            proofless: false,
        }
    }

    fn signature_for_slot(slot: u64) -> Signature {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&slot.to_be_bytes());
        Signature::from(bytes)
    }

    fn wallet_with_utxo(owner: &ShieldedKeypair, asset: Address, amount: u64, seed: u8) -> Wallet {
        wallet_with_utxos(owner, &[(asset, amount, seed)])
    }

    fn wallet_with_utxos(owner: &ShieldedKeypair, entries: &[(Address, u64, u8)]) -> Wallet {
        let mut registry = AssetRegistry::default();
        let mut next_asset_id = 2u64;
        for &(asset, _, _) in entries {
            if asset != SOL_MINT && registry.asset_id(&asset).is_err() {
                registry
                    .insert(next_asset_id, asset)
                    .expect("register asset");
                next_asset_id += 1;
            }
        }
        let mut wallet = Wallet::new(
            owner.shielded_address().expect("shielded address"),
            registry,
        )
        .expect("wallet");
        for &(asset, amount, seed) in entries {
            let utxo = test_utxo(owner, asset, amount, seed);
            let nullifier_pk = owner.nullifier_key.pubkey().expect("nullifier pubkey");
            let hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
                .expect("utxo hash");
            let nullifier = utxo
                .nullifier(&hash, &owner.nullifier_key)
                .expect("nullifier");
            wallet.utxos.push(WalletUtxo {
                utxo,
                output_context: OutputContext {
                    hash,
                    tree: Address::default(),
                    leaf_index: u64::from(seed),
                },
                nullifier,
                data_hash: None,
                ring_data_hash: None,
                spent: false,
            });
        }
        wallet
    }

    fn test_utxo(owner: &ShieldedKeypair, asset: Address, amount: u64, seed: u8) -> Utxo {
        let mut blinding = [seed; 32];
        blinding[0] = 0;
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        }
    }

    fn proofless_output_for_keypair(keypair: &ShieldedKeypair, amount: u64) -> ProoflessOutput {
        let mut blinding = [9u8; 32];
        blinding[0] = 0;
        ProoflessOutput {
            owner: keypair.owner_hash().expect("owner hash"),
            blinding,
            asset: SOL_MINT.to_bytes(),
            amount,
            data_hash: None,
            utxo_data: None,
            ring_program_id: None,
            ring_data_hash: None,
            ring_data: None,
            memo: None,
        }
    }

    fn encrypted_match(keypair: &ShieldedKeypair, output: ProoflessOutput) -> EncryptedUtxoMatch {
        EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::default(),
            output_slot: OutputSlot {
                view_tag: keypair.recipient_bootstrap_view_tag(),
                output_context: OutputContext {
                    hash: proofless_leaf_hash(keypair, &output),
                    tree: Address::new_from_array([7u8; 32]),
                    leaf_index: 13,
                },
                payload: encode_output_data(output),
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    fn proofless_leaf_hash(keypair: &ShieldedKeypair, output: &ProoflessOutput) -> [u8; 32] {
        let assets = AssetRegistry::default();
        let owner_cx = OwnerCx {
            owner: keypair.signing_pubkey(),
            assets: &assets,
            ring_program_id: None,
        };
        let data_hash = output.data_hash.unwrap_or([0u8; 32]);
        let ring_data_hash = output.ring_data_hash.unwrap_or([0u8; 32]);
        let utxo = Proofless::into_utxos(output.clone(), &owner_cx)
            .expect("proofless into utxos")
            .into_iter()
            .next()
            .expect("proofless utxo");
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        utxo.hash(&nullifier_pk, &data_hash, &ring_data_hash)
            .expect("proofless leaf hash")
    }

    /// A canned on-chain `SplAssetRegistry` account (as `get_program_accounts`
    /// would return it), owned by the shielded-pool program, mapping `mint` to
    /// `asset_id`.
    fn spl_registry_account(mint: Address, asset_id: u64) -> (Address, solana_account::Account) {
        let data = SplAssetRegistry::account_bytes(mint, asset_id).to_vec();
        let pda = Address::new_from_array([9u8; 32]);
        let account = solana_account::Account {
            lamports: 1,
            data,
            owner: solana_pubkey::Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            executable: false,
            rent_epoch: 0,
        };
        (pda, account)
    }

    #[test]
    fn sync_backfills_unknown_asset_from_chain_then_decodes() {
        // Alice receives a confidential transfer in an SPL asset her wallet's
        // registry does not know yet (built SOL-only). Sync must hit the unknown
        // id, refresh the registry from the on-chain SplAssetRegistry account,
        // and decode the note on the retry.
        let full = AssetRegistry::new([(SPL_ASSET_ID, SPL_MINT)]).expect("full registry");
        let sender = ed25519_keypair(9);
        let alice = ed25519_keypair(10);
        let transfer = confidential_transfer_tx(&sender, &alice, SPL_MINT, 100, 1, &full);

        // Alice's wallet only knows SOL — the SPL id is unknown at first.
        let mut wallet = Wallet::new(
            alice.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let indexer = MockIndexer {
            transactions: vec![transfer],
            matches: Vec::new(),
            program_accounts: vec![spl_registry_account(SPL_MINT, SPL_ASSET_ID)],
        };

        let report = sync_wallet(&mut wallet, &local_authority(&alice), &indexer)
            .expect("sync with backfill");

        // The note decoded after the refresh: it is stored and no id remains
        // unknown in the final report.
        assert_eq!(report.stored_utxos, 1);
        assert!(report.unknown_asset_ids.is_empty());
        let balances = wallet.balances(true).expect("balances");
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].mint, SPL_MINT);
        assert_eq!(balances[0].amount, 100);
    }

    #[test]
    fn sync_without_gpa_leaves_unknown_asset_undecoded() {
        // Same stale-registry setup, but the RPC returns NO registry accounts
        // (e.g. get_program_accounts unavailable / empty). The note stays
        // undecoded and the refresh does not loop.
        let full = AssetRegistry::new([(SPL_ASSET_ID, SPL_MINT)]).expect("full registry");
        let sender = ed25519_keypair(11);
        let alice = ed25519_keypair(12);
        let transfer = confidential_transfer_tx(&sender, &alice, SPL_MINT, 100, 1, &full);

        let mut wallet = Wallet::new(
            alice.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let indexer = MockIndexer {
            transactions: vec![transfer],
            matches: Vec::new(),
            program_accounts: Vec::new(),
        };

        let report =
            sync_wallet(&mut wallet, &local_authority(&alice), &indexer).expect("sync no backfill");

        assert_eq!(report.stored_utxos, 0);
        assert!(report.unknown_asset_ids.contains(&SPL_ASSET_ID));
        assert!(wallet.balances(true).expect("balances").is_empty());
    }

    #[test]
    fn sync_known_asset_reports_no_unknown_ids() {
        // When the wallet already knows every asset, sync decodes on the first
        // pass and never records an unknown id.
        let full = AssetRegistry::new([(SPL_ASSET_ID, SPL_MINT)]).expect("full registry");
        let sender = ed25519_keypair(13);
        let alice = ed25519_keypair(14);
        let transfer = confidential_transfer_tx(&sender, &alice, SPL_MINT, 100, 1, &full);

        let mut wallet = Wallet::new(
            alice.shielded_address().expect("shielded address"),
            full.clone(),
        )
        .expect("wallet");
        let indexer = MockIndexer {
            transactions: vec![transfer],
            matches: Vec::new(),
            program_accounts: Vec::new(),
        };

        let report =
            sync_wallet(&mut wallet, &local_authority(&alice), &indexer).expect("sync known");
        // `stored_utxos` is per-sync-call and the multi-round loop re-syncs the
        // same tx (a duplicate store), so assert the durable wallet state and
        // that no id was ever unknown.
        assert!(report.unknown_asset_ids.is_empty());
        let balances = wallet.balances(true).expect("balances");
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].mint, SPL_MINT);
        assert_eq!(balances[0].amount, 100);
    }
}
