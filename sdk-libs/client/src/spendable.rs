//! A wallet's spendable UTXOs and its history, read from the indexer.
//!
//! Stateless: [`SpendableUtxos::fetch`] reads the transactions tagged for the
//! wallet and decrypts them, then reads the transactions that spent the UTXOs
//! it found, until a round finds nothing new. A merge, or a spend another
//! client made, can carry none of the wallet's tags; only the nullifier rounds
//! find those. Each round decrypts only the transactions it fetched and queries
//! only the nullifiers it has not queried, so with a remote key holder a round
//! costs round trips for what is new, not for everything found so far.
//! [`SpendableUtxos::fetch_history`] makes the same reads and keeps the
//! transactions and the spent UTXOs as well.
//!
//! Both read UTXOs only in the assets of the [`AssetRegistry`] they are given
//! and report the others as unknown; [`fetch_asset_id`] reads the id the pool
//! registered for a mint, to add it. An indexer that lags misses the latest
//! spends; [`SpendableUtxos::with_indexer_config`] makes every read wait for a
//! slot first.

use std::collections::HashSet;

use solana_address::Address;
use solana_signature::Signature;
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use zolana_keypair::P256Pubkey;
use zolana_transaction::{
    verify_owned, AssetRegistry, DecryptionResult, DepositPayload, History, OwnedUtxos,
    ShieldedKeys, SpendableDecryptionResult, SOL_ASSET_ID, SOL_MINT,
};

use crate::{
    error::ClientError,
    rpc::{EncryptedUtxoMatch, IndexerRpcConfig, Rpc, ShieldedTransaction},
};

const PAGE_LIMIT: u32 = 1_000;

pub struct SpendableUtxos<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    ring_deposit_payload: Option<(Address, DepositPayload)>,
    indexer_config: Option<IndexerRpcConfig>,
}

impl<'a, K: ShieldedKeys + ?Sized> SpendableUtxos<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            ring_deposit_payload: None,
            indexer_config: None,
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
    /// carry. Anonymous transfers, tagged per counterparty, are not read.
    pub fn fetch<I: Rpc + ?Sized>(
        &self,
        indexer: &I,
    ) -> Result<SpendableDecryptionResult, ClientError> {
        Ok(self.fetch_rounds(indexer)?.spendable)
    }

    /// The reads of [`fetch`](Self::fetch), keeping every transaction read,
    /// every UTXO the wallet owns among them, spent or not, and the tags they
    /// were read by. [`History::entries`] classifies them. It asks the
    /// key holder no more than `fetch` does.
    pub fn fetch_history<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<History, ClientError> {
        let fetched = self.fetch_rounds(indexer)?;
        Ok(History {
            utxos: fetched.owned.utxos,
            transactions: fetched.transactions,
            unknown_asset_ids: fetched.owned.unknown_asset_ids,
            unknown_mints: fetched.owned.unknown_mints,
            view_tags: fetched.tags.into_iter().collect(),
        })
    }

    fn fetch_rounds<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<Fetched, ClientError> {
        let address = self.keys.address()?;
        let mut tags = vec![address.signing_pubkey.confidential_view_tag()?];
        tags.extend(self.keys.viewing_public_keys().iter().map(P256Pubkey::x));

        let mut seen = HashSet::new();
        let mut batch = self.unseen(
            &mut seen,
            tagged_transactions(indexer, &tags, self.indexer_config)?,
        )?;
        let mut transactions = Vec::new();
        let mut decrypted = DecryptionResult::default();
        let mut queried = HashSet::new();
        loop {
            decrypted.extend(self.keys, &batch, self.assets)?;
            transactions.append(&mut batch);
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
                spending_transactions(indexer, &nullifiers, self.indexer_config)?,
            )?;
            if batch.is_empty() {
                return Ok(Fetched {
                    tags,
                    transactions,
                    owned,
                    spendable,
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
    tags: Vec<[u8; 32]>,
    transactions: Vec<ShieldedTransaction>,
    /// The final round's [`verify_owned`], spent UTXOs included.
    owned: OwnedUtxos,
    spendable: SpendableDecryptionResult,
}

/// The transactions tagged with any of `tags`. Deposits come from the
/// encrypted-output stream, one transaction per output: a deposit transaction
/// can shield several outputs.
fn tagged_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    tags: &[[u8; 32]],
    config: Option<IndexerRpcConfig>,
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
        transactions.extend(page.transactions.into_iter().filter(|tx| !tx.proofless));
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    let mut cursor = None;
    loop {
        let page =
            indexer.get_encrypted_utxos_by_tags(tags.to_vec(), cursor, Some(PAGE_LIMIT), config)?;
        transactions.extend(
            page.matches
                .into_iter()
                .filter_map(EncryptedUtxoMatch::into_proofless_transaction),
        );
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    Ok(transactions)
}

/// The transactions that spent any of `nullifiers`.
fn spending_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    nullifiers: &[[u8; 32]],
    config: Option<IndexerRpcConfig>,
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
            transactions.extend(page.transactions);
            let Some(next) = page.next_cursor else { break };
            cursor = Some(next);
        }
    }
    Ok(transactions)
}
