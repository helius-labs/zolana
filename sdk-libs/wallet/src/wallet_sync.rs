use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use solana_address::Address;
use zolana_interface::{
    event::decode_output_data, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{
    AssetBalance, EncryptedScheme, OutputContext, OutputSlot, PrivateTransaction,
    ShieldedTransaction, SyncReport, SyncWalletAuthority, TransactionError, Wallet,
    WalletAuthority, WalletSyncMaterial, DEFAULT_TAG_WINDOW,
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
    pub wait_for_indexer: bool,
    pub retry: IndexerPollConfig,
}

impl Default for SyncWalletConfig {
    fn default() -> Self {
        Self {
            tag_window: DEFAULT_TAG_WINDOW,
            tag_query_chunk: DEFAULT_TAG_QUERY_CHUNK,
            page_limit: DEFAULT_PAGE_LIMIT,
            rounds: DEFAULT_SYNC_ROUNDS,
            wait_for_indexer: false,
            retry: IndexerPollConfig::default(),
        }
    }
}

impl SyncWalletConfig {
    pub fn new() -> Self {
        Self {
            wait_for_indexer: true,
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
    I: Rpc,
{
    sync_wallet_with_config(wallet, authority, indexer, SyncWalletConfig::new())
}

pub fn sync_wallet_with_config<A, I>(
    wallet: &mut Wallet,
    authority: &A,
    indexer: &I,
    config: SyncWalletConfig,
) -> Result<SyncReport, ClientError>
where
    A: SyncWalletAuthority + ?Sized,
    I: Rpc,
{
    let config = normalized_config(config);
    let rpc_config = indexer_rpc_config(config);
    let material = authority.sync_material()?;
    let mut transactions: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut report = SyncReport::default();
    let mut txs: Vec<ShieldedTransaction> = Vec::new();

    for _ in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(wallet, &material, config.tag_window)?;
        fetch_shielded_transactions(indexer, &tags, &mut transactions, config, rpc_config)?;
        fetch_proofless_deposits(indexer, &tags, &mut proofless_deposits, config, rpc_config)?;

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
    let rpc_config = indexer_rpc_config(config);
    let material = authority.sync_material().await?;
    let mut transactions: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut report = SyncReport::default();
    let mut txs = Vec::new();

    for _ in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(wallet, &material, config.tag_window)?;
        fetch_shielded_transactions_async(indexer, &tags, &mut transactions, config, rpc_config)
            .await?;
        fetch_proofless_deposits_async(indexer, &tags, &mut proofless_deposits, config, rpc_config)
            .await?;

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
        wait_for_indexer: config.wait_for_indexer,
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
    // Confidential default-zone outputs (sender change, recipients, merge) are all
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
        wait_for_indexer: config.wait_for_indexer,
        poll: config.retry,
    })
}

fn fetch_shielded_transactions<I: Rpc>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
) -> Result<(), ClientError> {
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                chunk.to_vec(),
                cursor,
                Some(config.page_limit),
                rpc_config,
            )?;
            for tx in response.transactions {
                // Photon may surface proofless/plaintext deposits from this
                // endpoint before marking them as proofless. They are discovered
                // through `get_encrypted_utxos_by_tags` below, not as decryptable
                // shielded transfers.
                if tx.proofless
                    || ((tx.tx_viewing_pk.is_none() || tx.salt.is_none())
                        && !has_merge_ciphertext(&tx))
                {
                    continue;
                }
                let key = tx.tx_signature.to_string();
                out.entry(key).or_insert(convert_sync_transaction(tx)?);
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

async fn fetch_shielded_transactions_async<I: AsyncRpc>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
) -> Result<(), ClientError> {
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer
                .get_shielded_transactions_by_tags(
                    chunk.to_vec(),
                    cursor,
                    Some(config.page_limit),
                    rpc_config,
                )
                .await?;
            for tx in response.transactions {
                if tx.proofless
                    || ((tx.tx_viewing_pk.is_none() || tx.salt.is_none())
                        && !has_merge_ciphertext(&tx))
                {
                    continue;
                }
                let key = tx.tx_signature.to_string();
                out.entry(key).or_insert(convert_sync_transaction(tx)?);
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn has_merge_ciphertext(tx: &RpcShieldedTransaction) -> bool {
    tx.output_slots.iter().any(|slot| {
        let Ok(output_data) = borsh::from_slice::<zolana_event::OutputDataEncoding>(&slot.payload)
        else {
            return false;
        };
        let blob = match output_data {
            zolana_event::OutputDataEncoding::Encrypted(blob)
            | zolana_event::OutputDataEncoding::VerifiablyEncrypted(blob)
            | zolana_event::OutputDataEncoding::Plaintext(blob) => blob,
        };
        blob.first()
            .and_then(|b| EncryptedScheme::from_byte(*b).ok())
            == Some(EncryptedScheme::Merge)
    })
}

fn fetch_proofless_deposits<I>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
) -> Result<(), ClientError>
where
    I: Rpc,
{
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_encrypted_utxos_by_tags(
                chunk.to_vec(),
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
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

async fn fetch_proofless_deposits_async<I: AsyncRpc>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
    rpc_config: Option<IndexerRpcConfig>,
) -> Result<(), ClientError> {
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer
                .get_encrypted_utxos_by_tags(
                    chunk.to_vec(),
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
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
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
    if decode_output_data(&item.output_slot.payload).is_err() {
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
    use std::collections::HashMap;

    use solana_signature::Signature;
    use zolana_interface::event::{encode_output_data, ProoflessOutput};
    use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair, ViewingKey};
    use zolana_transaction::{
        instructions::{
            merge::Merge as MergePlan,
            transact::{
                ConfidentialTransfer, SppProofInputs, WithdrawalTarget, SPP_SUPPORTED_SHAPES,
            },
            types::SppProofInputUtxo,
        },
        serialization::{
            merge::{Merge, MergeEncode},
            Proofless,
        },
        Address, AssetRegistry, Data, LocalWalletAuthority, OwnerCx, PrivateTransactionDirection,
        PrivateTransactionKind, Utxo, UtxoSerialization, WalletUtxo, SOL_MINT,
    };

    use super::*;
    use zolana_client::rpc::{
        Context, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
        OutputContext, OutputSlot,
    };

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
                context: Context { block_time: 0 },
                matches: self.matches.clone(),
                next_cursor: None,
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
                context: Context { block_time: 0 },
                transactions: self.transactions.clone(),
                next_cursor: None,
            })
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
    }

    const SPL_ASSET_ID: u64 = 2;
    const SPL_MINT: Address = Address::new_from_array([2u8; 32]);

    fn local_authority(keypair: &ShieldedKeypair) -> LocalWalletAuthority<'_> {
        LocalWalletAuthority::new(Address::default(), keypair)
    }

    #[tokio::test]
    async fn async_sync_future_is_send_and_keeps_wallet_keyless() {
        let keypair = ShieldedKeypair::new().expect("keypair");
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
        let alice = ShieldedKeypair::new().expect("alice");
        let bob = ShieldedKeypair::new().expect("bob");
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
    fn sync_wallet_decodes_confidential_recipient_across_supported_shapes() {
        let assets = AssetRegistry::default();

        for (case, shape) in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= 3)
            .enumerate()
        {
            let sender = ShieldedKeypair::new().expect("sender");
            let recipient = ShieldedKeypair::new().expect("recipient");
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
                let decoy = ShieldedKeypair::new().expect("decoy recipient");
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
        let alice = ShieldedKeypair::new().expect("alice");
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
        let alice = ShieldedKeypair::new().expect("alice");
        let bob = ShieldedKeypair::new().expect("bob");
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
        let assets = AssetRegistry::default();
        let alice = ShieldedKeypair::new().expect("alice");
        let inputs = vec![
            SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 30, 10), &alice),
            SppProofInputUtxo::new(test_utxo(&alice, SOL_MINT, 70, 11), &alice),
        ];
        let tx = merge_tx(&alice, inputs, 1, &assets);
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

        fetch_shielded_transactions(
            &indexer,
            &[[1u8; 32]],
            &mut out,
            SyncWalletConfig::default(),
            None,
        )
        .expect("skip plaintext row");

        assert!(out.is_empty());
    }

    #[test]
    fn proofless_fetch_decodes_indexed_payload() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
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
            &[keypair.recipient_bootstrap_view_tag()],
            &mut out,
            SyncWalletConfig::default(),
            None,
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
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
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
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
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
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
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
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
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
            &[keypair.recipient_bootstrap_view_tag()],
            &mut out,
            SyncWalletConfig::default(),
            None,
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
                WithdrawalTarget::Sol {
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
                WithdrawalTarget::Sol {
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
        assets: &AssetRegistry,
    ) -> ShieldedTransaction {
        let merge = MergePlan::new(owner, inputs).expect("merge plan");
        let prepared = merge.prepare();
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        let output = Utxo {
            owner: owner.signing_pubkey(),
            asset: prepared.output.asset,
            amount: prepared.output.amount,
            blinding: prepared.output.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let output_hash = output
            .hash(
                &owner.nullifier_key.pubkey().expect("nullifier pubkey"),
                &[0u8; 32],
                &[0u8; 32],
            )
            .expect("output hash");
        let tx_key = ViewingKey::new();
        let ciphertext = Merge::encode(
            std::slice::from_ref(&output),
            &OwnerCx {
                owner: owner.signing_pubkey(),
                assets,
                zone_program_id: None,
            },
            owner
                .signing_pubkey()
                .confidential_view_tag()
                .expect("owner tag"),
            &MergeEncode {
                tx: tx_key,
                user_viewing_pk: owner.viewing_pubkey(),
            },
        )
        .expect("merge ciphertext");
        ShieldedTransaction {
            slot,
            tx_signature: signature_for_slot(slot),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: ciphertext.view_tag,
                output_context: OutputContext {
                    hash: output_hash,
                    tree: Address::new_from_array([slot as u8; 32]),
                    leaf_index: 0,
                },
                payload: ciphertext.data,
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
                zone_data_hash: None,
                spent: false,
            });
        }
        wallet
    }

    fn test_utxo(owner: &ShieldedKeypair, asset: Address, amount: u64, seed: u8) -> Utxo {
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: [seed; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        }
    }

    fn proofless_output_for_keypair(keypair: &ShieldedKeypair, amount: u64) -> ProoflessOutput {
        ProoflessOutput {
            owner: keypair.owner_hash().expect("owner hash"),
            blinding: [9u8; BLINDING_LEN],
            asset: SOL_MINT.to_bytes(),
            amount,
            data_hash: None,
            utxo_data: None,
            zone_program_id: None,
            zone_data_hash: None,
            zone_data: None,
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
            zone_program_id: None,
        };
        let data_hash = output.data_hash.unwrap_or([0u8; 32]);
        let zone_data_hash = output.zone_data_hash.unwrap_or([0u8; 32]);
        let utxo = Proofless::into_utxos(output.clone(), &owner_cx)
            .expect("proofless into utxos")
            .into_iter()
            .next()
            .expect("proofless utxo");
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        utxo.hash(&nullifier_pk, &data_hash, &zone_data_hash)
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
        let sender = ShieldedKeypair::new().expect("sender");
        let alice = ShieldedKeypair::new().expect("alice");
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
        let sender = ShieldedKeypair::new().expect("sender");
        let alice = ShieldedKeypair::new().expect("alice");
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
        let sender = ShieldedKeypair::new().expect("sender");
        let alice = ShieldedKeypair::new().expect("alice");
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
