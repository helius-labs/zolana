//! Reading ring transactions by the auditor tag and opening them. Photon indexes
//! messages by view tag, so one query for `auditor_view_tag` returns every
//! transaction of the ring.

use std::{future::Future, sync::Arc, time::Duration};

use custom_ring_program::{state::RingProgramConfig, CONFIG_PDA_SEED};
use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::{error, warn};
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as NonblockingRpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransaction, UiTransactionEncoding,
};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_api::ZolanaApi;
use zolana_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse,
};
use zolana_indexer_api::Limit;
use zolana_interface::{state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{P256Pubkey, PublicKey, ViewingKey};
use zolana_ring_client::{audit_transaction, auditor_view_tag, AuditError, AuditedTransaction};
use zolana_transaction::AssetRegistry;

use crate::api::{
    read_attestation, DecryptedOutput, DecryptedTransaction, DecryptedTransactionsPage,
    GetDecryptedTransactionsResponse, ReadAuth, ReadScope, SkippedTransaction,
};

/// Where the service reads from. Photon serves the tagged transactions and the
/// Solana RPC the signers. Tests provide both in memory.
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

    /// The authority the ring's on-chain config records, `None` when the ring
    /// has no config.
    fn ring_authority(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send;
}

/// The production source, a Photon indexer plus the Solana RPC it follows.
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

    // One read of the confirmed transaction. The JSON encoding lists the static
    // keys with the signers first. The audit itself comes from the indexer and
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

    async fn ring_authority(&self, ring: Address) -> Result<Option<Address>, ClientError> {
        let config = Address::find_program_address(&[CONFIG_PDA_SEED], &ring).0;
        let Some(account) = self.rpc.get_account(config).await? else {
            return Ok(None);
        };
        if !account.owner.to_bytes().eq(&ring.to_bytes()) {
            return Ok(None);
        }
        let config =
            bytemuck::try_from_bytes::<RingProgramConfig>(&account.data).map_err(|_| {
                ClientError::Rpc(format!("ring config of {ring} has an unexpected layout"))
            })?;
        Ok(config.has_discriminator().then_some(config.authority))
    }
}

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("ring_program_id is required, this instance serves keys per ring")]
    RingRequired,
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("key derivation failed: {0}")]
    Derivation(#[from] zolana_keypair::KeypairError),
    #[error(transparent)]
    Indexer(#[from] ClientError),
}

impl From<RingRpcError> for ErrorObjectOwned {
    fn from(error: RingRpcError) -> Self {
        match error {
            RingRpcError::RingRequired
            | RingRpcError::Unauthorized(_)
            | RingRpcError::Derivation(_) => ErrorObjectOwned::owned(
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
pub struct AuditService<S> {
    ring: Address,
    auditor: ViewingKey,
    view_tag: [u8; 32],
    source: Arc<S>,
    assets: AssetRegistry,
}

/// How far a read's `timestamp` may sit from this clock, either way.
const READ_SKEW: Duration = Duration::from_secs(60);

impl<S: TransactionSource> AuditService<S> {
    pub fn new(ring: Address, auditor: ViewingKey, source: Arc<S>, assets: AssetRegistry) -> Self {
        let view_tag = auditor_view_tag(&auditor.pubkey());
        Self {
            ring,
            auditor,
            view_tag,
            source,
            assets,
        }
    }

    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> P256Pubkey {
        self.auditor.pubkey()
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

    /// Checks the request's signature and freshness, then what the reader may
    /// see. Ring scope needs the ring's on-chain authority. Participant scope
    /// accepts any key and returns a filter that keeps only the reader's own
    /// side of each transaction.
    pub async fn authorize_read(
        &self,
        auth: &ReadAuth,
        cursor: Option<&[u8]>,
        limit: Option<Limit>,
    ) -> Result<ReadFilter, RingRpcError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default();
        if now.abs_diff(auth.timestamp) > READ_SKEW.as_secs() {
            return Err(RingRpcError::Unauthorized("request timestamp is stale"));
        }
        let reader = Reader::parse(&auth.reader.0).ok_or(RingRpcError::Unauthorized(
            "reader is not an ed25519 or P-256 key",
        ))?;
        let message = read_attestation(
            auth.scope,
            &self.ring,
            auth.timestamp,
            cursor,
            limit.map(|l| l.value()),
        );
        if !reader.verify(&message, &auth.signature.0) {
            return Err(RingRpcError::Unauthorized(
                "signature does not cover this request",
            ));
        }
        match (auth.scope, reader) {
            (ReadScope::Ring, Reader::Ed25519(reader)) => {
                match self.source.ring_authority(self.ring).await? {
                    Some(authority) if authority == reader => Ok(ReadFilter::Ring),
                    Some(_) => Err(RingRpcError::Unauthorized(
                        "reader is not the ring authority",
                    )),
                    None => Err(RingRpcError::Unauthorized("ring has no config on chain")),
                }
            }
            (ReadScope::Ring, Reader::P256(_)) => Err(RingRpcError::Unauthorized(
                "ring scope needs the ring authority's ed25519 key",
            )),
            (ReadScope::Participant, reader) => Ok(ReadFilter::Participant(reader)),
        }
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// One page of transactions tagged for this auditor, opened with the
    /// recovered transaction viewing keys.
    ///
    /// The indexer matches the tag against output tags and message tags, so a
    /// transaction can arrive without an auditor message. Those are dropped. A
    /// tagged transaction that fails to audit is reported under `skipped`.
    pub async fn decrypted_transactions(
        &self,
        cursor: Option<Vec<u8>>,
        limit: Option<Limit>,
        filter: &ReadFilter,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let limit = limit.and_then(|limit| u32::try_from(limit.value()).ok());
        let page = self
            .source
            .transactions_by_tag(self.view_tag, cursor, limit)
            .await?;

        let mut items = Vec::new();
        let mut skipped = Vec::new();
        for tx in page.transactions {
            match audit_transaction(&self.auditor, &tx, &self.assets) {
                Ok(audited) => {
                    let signers = self.source.signers(tx.tx_signature).await?;
                    if let Some(item) =
                        filter.apply(decrypted_transaction(audited, signers, tx.nullifiers))
                    {
                        items.push(item);
                    }
                }
                Err(AuditError::MissingAuditorMessage) => {}
                // A transaction nobody could attribute is the auditor's
                // business, not a participant's.
                Err(reason) if matches!(filter, ReadFilter::Ring) => {
                    skipped.push(SkippedTransaction {
                        slot: tx.slot,
                        tx_signature: tx.tx_signature.into(),
                        reason: reason.to_string(),
                    })
                }
                Err(_) => {}
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
}

/// A key that signed a read, either curve the protocol uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// A Solana signer, what `signers` of a transaction are.
    Ed25519(Address),
    /// A viewing key, what outputs are encrypted to.
    P256(P256Pubkey),
}

impl Reader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if let Ok(ed25519) = <[u8; 32]>::try_from(bytes) {
            return Some(Self::Ed25519(Address::new_from_array(ed25519)));
        }
        let p256 = <[u8; 33]>::try_from(bytes).ok()?;
        Some(Self::P256(P256Pubkey::from_bytes(p256).ok()?))
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        match self {
            Self::Ed25519(address) => Signature::from(signature).verify(address.as_ref(), message),
            Self::P256(pubkey) => PublicKey::from_p256(pubkey).verify_message(message, &signature),
        }
    }
}

/// What a read may see, decided by [`AuditService::authorize_read`].
pub enum ReadFilter {
    Ring,
    Participant(Reader),
}

impl ReadFilter {
    /// Ring scope passes everything. A sender sees the transactions it signed
    /// in full, a recipient only the outputs encrypted to its key.
    fn apply(&self, mut item: DecryptedTransaction) -> Option<DecryptedTransaction> {
        match self {
            Self::Ring => Some(item),
            Self::Participant(Reader::Ed25519(reader)) => item
                .signers
                .iter()
                .any(|signer| signer.0 == *reader)
                .then_some(item),
            Self::Participant(Reader::P256(reader)) => {
                item.outputs
                    .retain(|output| output.recipient_viewing_pk.0 == reader.as_bytes());
                (!item.outputs.is_empty()).then_some(item)
            }
        }
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

/// The SPL asset registry as SPP publishes it, every `SplAssetRegistry` account
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

/// Domain of the derived auditor keys. Bumping it rotates every derived key.
const DERIVATION_INFO: &[u8] = b"zolana/ring-auditor/v1";
/// Domain of the service signing key, derived from the same secret as the
/// auditor keys so a restart keeps it.
const SERVICE_KEY_INFO: &[u8] = b"zolana/ring-rpc-service/v1";

/// `HKDF(root_secret, genesis_hash || ring_program_id)`. The genesis hash keeps
/// a ring id on one cluster from reaching the key of the same id on another.
pub fn derive_auditor_key(
    root: &[u8; 32],
    genesis_hash: &[u8; 32],
    ring: Address,
) -> Result<ViewingKey, RingRpcError> {
    Ok(ViewingKey::from_hkdf(
        root,
        &[DERIVATION_INFO, genesis_hash, ring.as_ref()],
    )?)
}

/// The ed25519 key this instance signs auditor key attestations with, so a
/// ring can pin the instance and refuse a key handed to it by anyone else.
fn service_keypair(secret: &[u8]) -> Keypair {
    let mut seed = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret)
        .expand(SERVICE_KEY_INFO, seed.as_mut_slice())
        .expect("32 bytes are within the HKDF-SHA256 output bound");
    Keypair::new_from_array(*seed)
}

/// Resolves a ring to its audit service.
pub enum Hub<S> {
    /// One key from a file, one ring per instance.
    Local {
        service: Arc<AuditService<S>>,
        signer: Keypair,
    },
    /// A key per ring, derived on every request. Nothing is kept per ring, so
    /// asking for arbitrary ring ids costs the caller, not this process.
    Derived {
        root: Zeroizing<[u8; 32]>,
        genesis_hash: [u8; 32],
        source: Arc<S>,
        assets: AssetRegistry,
        signer: Keypair,
    },
}

impl<S: TransactionSource> Hub<S> {
    /// `ring` is the one ring this key serves; reads are authorized against
    /// its on-chain authority.
    pub fn local(ring: Address, auditor: ViewingKey, source: S, assets: AssetRegistry) -> Self {
        let signer = service_keypair(auditor.secret_bytes().as_slice());
        Self::Local {
            service: Arc::new(AuditService::new(ring, auditor, Arc::new(source), assets)),
            signer,
        }
    }

    pub fn derived(
        root: Zeroizing<[u8; 32]>,
        genesis_hash: [u8; 32],
        source: S,
        assets: AssetRegistry,
    ) -> Self {
        let signer = service_keypair(root.as_slice());
        Self::Derived {
            root,
            genesis_hash,
            source: Arc::new(source),
            assets,
            signer,
        }
    }

    pub fn is_derived(&self) -> bool {
        matches!(self, Self::Derived { .. })
    }

    pub fn signer(&self) -> &Keypair {
        match self {
            Self::Local { signer, .. } | Self::Derived { signer, .. } => signer,
        }
    }

    /// The service for `ring`. The local key ignores `ring`.
    pub fn ring(&self, ring: Option<Address>) -> Result<Arc<AuditService<S>>, RingRpcError> {
        match self {
            Self::Local { service, .. } => Ok(service.clone()),
            Self::Derived {
                root,
                genesis_hash,
                source,
                assets,
                ..
            } => {
                let ring = ring.ok_or(RingRpcError::RingRequired)?;
                Ok(Arc::new(AuditService::new(
                    ring,
                    derive_auditor_key(root, genesis_hash, ring)?,
                    source.clone(),
                    assets.clone(),
                )))
            }
        }
    }

    /// The local key's service, `None` when keys are derived per ring.
    pub fn local_service(&self) -> Option<Arc<AuditService<S>>> {
        match self {
            Self::Local { service, .. } => Some(service.clone()),
            Self::Derived { .. } => None,
        }
    }
}
