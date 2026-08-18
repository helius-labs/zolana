//! Reading ring transactions by the auditor tag and opening them.

use std::{collections::HashMap, future::Future, sync::Mutex, time::Duration};

use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::{error, warn};
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as NonblockingRpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransaction, UiTransactionEncoding,
};
use thiserror::Error;
use zolana_api::ZolanaApi;
use zolana_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse,
};
use zolana_interface::{state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::ViewingKey;
use zolana_ring_client::{audit_transaction, auditor_view_tag, AuditedTransaction};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::api::{
    DecryptedOutput, DecryptedTransaction, DecryptedTransactionsPage,
    GetDecryptedTransactionsResponse, SkippedTransaction, PAGE_LIMIT,
};

/// Where the service reads from. Photon serves the tagged transactions and the
/// Solana RPC the signers; tests provide both in memory.
pub trait TransactionSource: Send + Sync {
    fn transactions_by_tag(
        &self,
        tag: [u8; 32],
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    /// The Solana signers of a confirmed transaction.
    fn signers(
        &self,
        signature: Signature,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send;
}

/// The production source: a Photon indexer plus the Solana RPC it follows.
pub struct ChainSource {
    indexer: AsyncZolanaIndexer,
    rpc: AsyncSolanaRpc,
}

impl ChainSource {
    /// Every upstream call is bounded by `timeout`, so a stalled indexer or RPC
    /// turns into an error instead of a hung request.
    pub fn new(indexer_url: &str, rpc_url: &str, timeout: Duration) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ClientError::Rpc(format!("http client: {error}")))?;
        Ok(Self {
            indexer: AsyncZolanaIndexer::with_api(ZolanaApi::with_client(indexer_url, http)),
            rpc: AsyncSolanaRpc::with_client(
                NonblockingRpcClient::new_with_timeout_and_commitment(
                    rpc_url.to_owned(),
                    timeout,
                    CommitmentConfig::confirmed(),
                ),
            ),
        })
    }

    pub fn rpc(&self) -> &AsyncSolanaRpc {
        &self.rpc
    }
}

impl TransactionSource for ChainSource {
    fn transactions_by_tag(
        &self,
        tag: [u8; 32],
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        self.indexer
            .get_shielded_transactions_by_tags(vec![tag], cursor, limit, None)
    }

    // One read of the confirmed transaction: the JSON encoding lists the static
    // keys with the signers first. The audit itself comes from the indexer;
    // signers are enrichment, so an RPC that no longer holds the transaction
    // (a pruned ledger) leaves them empty instead of failing the page.
    async fn signers(&self, signature: Signature) -> Result<Vec<Address>, ClientError> {
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };
        let confirmed = match self
            .rpc
            .client()
            .get_transaction_with_config(&signature, config)
            .await
        {
            Ok(confirmed) => confirmed,
            Err(error) => {
                warn!("signers of {signature} unavailable from the rpc: {error}");
                return Ok(Vec::new());
            }
        };
        let EncodedTransaction::Json(UiTransaction {
            message: UiMessage::Raw(message),
            ..
        }) = confirmed.transaction.transaction
        else {
            return Err(ClientError::Rpc(format!(
                "transaction {signature} did not come back as a raw JSON message"
            )));
        };
        let required = usize::from(message.header.num_required_signatures);
        message
            .account_keys
            .iter()
            .take(required)
            .map(|key| {
                key.parse::<Address>().map_err(|error| {
                    ClientError::Rpc(format!("transaction {signature} signer {key}: {error}"))
                })
            })
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("limit must be between 1 and {PAGE_LIMIT}, got {0}")]
    InvalidLimit(u32),
    #[error(transparent)]
    Indexer(#[from] ClientError),
}

impl From<RingRpcError> for ErrorObjectOwned {
    fn from(error: RingRpcError) -> Self {
        match error {
            RingRpcError::InvalidLimit(_) => ErrorObjectOwned::owned(
                ErrorCode::InvalidRequest.code(),
                error.to_string(),
                None::<()>,
            ),
            RingRpcError::Indexer(inner) => {
                error!("indexer request failed: {inner}");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "indexer request failed",
                    None::<()>,
                )
            }
        }
    }
}

/// The auditor key plus a transaction source. Every method reads one page and
/// opens what the key can open.
/// Confirmed transactions never change signers, so one fetch per signature is
/// enough; the map is bounded so a long-running instance stays flat.
const SIGNER_CACHE_ENTRIES: usize = 4096;

pub struct AuditService<S> {
    auditor: ViewingKey,
    view_tag: [u8; 32],
    source: S,
    assets: AssetRegistry,
    signers: Mutex<HashMap<Signature, Vec<Address>>>,
}

impl<S: TransactionSource> AuditService<S> {
    pub fn new(auditor: ViewingKey, source: S, assets: AssetRegistry) -> Self {
        let view_tag = auditor_view_tag(&auditor.pubkey());
        Self {
            auditor,
            view_tag,
            source,
            assets,
            signers: Mutex::new(HashMap::new()),
        }
    }

    /// The indexer answers and is this ring's source of truth. Used by
    /// readiness so a stale instance is taken out of rotation.
    pub async fn probe_indexer(&self) -> Result<u64, RingRpcError> {
        let page = self
            .source
            .transactions_by_tag(self.view_tag, None, Some(1))
            .await?;
        Ok(page.context.slot)
    }

    async fn signers(&self, signature: Signature) -> Result<Vec<Address>, ClientError> {
        if let Some(cached) = self.cached_signers(signature) {
            return Ok(cached);
        }
        let signers = self.source.signers(signature).await?;
        if !signers.is_empty() {
            let mut cache = self
                .signers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache.len() >= SIGNER_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(signature, signers.clone());
        }
        Ok(signers)
    }

    fn cached_signers(&self, signature: Signature) -> Option<Vec<Address>> {
        self.signers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&signature)
            .cloned()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// One page of transactions tagged for this auditor, opened with the
    /// recovered transaction viewing keys.
    ///
    /// The indexer matches the tag against output tags and message tags, so a
    /// transaction can arrive without an auditor message; those are dropped. A
    /// tagged transaction that fails to audit is reported under `skipped`.
    pub async fn decrypted_transactions(
        &self,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        if let Some(limit) = limit {
            if limit == 0 || u64::from(limit) > PAGE_LIMIT {
                return Err(RingRpcError::InvalidLimit(limit));
            }
        }
        let page = self
            .source
            .transactions_by_tag(self.view_tag, cursor, limit)
            .await?;

        let mut items = Vec::new();
        let mut skipped = Vec::new();
        for tx in page
            .transactions
            .into_iter()
            .filter(|tx| self.carries_auditor_message(tx))
        {
            match audit_transaction(&self.auditor, &tx, &self.assets) {
                Ok(audited) => {
                    let signers = self.signers(tx.tx_signature).await?;
                    items.push(decrypted_transaction(audited, signers, tx.nullifiers));
                }
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    reason: reason.to_string(),
                }),
            }
        }

        Ok(GetDecryptedTransactionsResponse {
            context: zolana_indexer_api::Context {
                block_time: page.context.block_time,
                slot: page.context.slot,
            },
            value: DecryptedTransactionsPage {
                items,
                skipped,
                cursor: page.next_cursor.map(Into::into),
            },
        })
    }

    fn carries_auditor_message(&self, tx: &ShieldedTransaction) -> bool {
        tx.messages
            .iter()
            .any(|message| message.view_tag == self.view_tag)
    }
}

fn decrypted_transaction(
    audited: AuditedTransaction,
    signers: Vec<Address>,
    nullifiers: Vec<[u8; 32]>,
) -> DecryptedTransaction {
    DecryptedTransaction {
        slot: audited.slot,
        tx_signature: audited.tx_signature.into(),
        signers: signers
            .into_iter()
            .map(|signer| signer.to_bytes().into())
            .collect(),
        tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
        outputs: audited
            .outputs
            .into_iter()
            .map(|output| DecryptedOutput {
                slot_index: output.slot_index,
                recipient_viewing_pk: output.recipient_viewing_pk.as_bytes().to_vec().into(),
                asset: output.asset.to_bytes().into(),
                amount: output.amount,
                blinding: output.blinding.to_vec().into(),
                ring_program_id: output.ring_program_id.map(|id| id.to_bytes().into()),
            })
            .collect(),
        undecryptable_slots: audited.undecryptable_slots,
        nullifiers: nullifiers.into_iter().map(Into::into).collect(),
    }
}

/// The SPL asset registry as SPP publishes it: every `SplAssetRegistry` account
/// under the shielded-pool program. SOL is implicit in the registry.
pub async fn asset_registry_from_chain<R: AsyncRpc>(rpc: &R) -> Result<AssetRegistry, ClientError> {
    let accounts = rpc
        .get_program_accounts(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID))
        .await?;
    let entries = accounts.iter().filter_map(|(_, account)| {
        SplAssetRegistry::from_account_bytes(&account.data)
            .ok()
            .map(|registry| (registry.asset_id, registry.mint))
    });
    AssetRegistry::new(entries).map_err(ClientError::from)
}
