use std::{
    collections::{HashMap, HashSet},
    future::Future,
    marker::PhantomData,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytemuck::Pod;
use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::error;
use serde::{Deserialize, Serialize};
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as NonblockingRpcClient;
use solana_rpc_client_api::{
    config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    filter::RpcFilterType,
};
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use zeroize::Zeroizing;
use zolana_api::ZolanaApi;
use zolana_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse, Shape, SPP_SUPPORTED_SHAPES,
};
use zolana_indexer_api::{Base64String, Limit};
use zolana_interface::{
    custom_ring::{
        ReaderRecord, RingProgramConfig, CONFIG_PDA_SEED, READER_RECORD, RING_PROGRAM_CONFIG,
    },
    is_reserved_p256_derivation_point,
    state::SplAssetRegistry,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_client::{
    auditor_view_tag, AuditError, AuditedTransaction, ConfirmedTransaction, OriginError, ReaderKey,
    TransactionAudit, ORIGIN_TRANSACTION_CONFIG,
};
use zolana_transaction::AssetRegistry;

use crate::{
    api::{
        unix_now, DecryptedOutput, DecryptedTransaction, DecryptedTransactionsPage,
        GetDecryptedTransactionsResponse, ReadAttestation, ReadAuth, SkippedReason,
        SkippedTransaction, AUDIT_CURSOR_LIMIT, AUDIT_PAGE_LIMIT,
    },
    authorize::{ReadCheck, Unauthorized, READ_SKEW},
    config::RootSecret,
    origins::Origins,
};

const MAX_REPLAY_ENTRIES: usize = 65_536;
const ASSET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_READS: usize = 32;
const MAX_READS_PER_SECOND: usize = 256;
const MAX_ASSET_REGISTRY_ACCOUNTS: usize = 4_096;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    cursor: Option<Vec<u8>>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
}

#[derive(Default)]
#[must_use]
pub struct PageOptions {
    cursor: Option<Vec<u8>>,
    limit: Option<Limit>,
}

pub trait TransactionSource: Send + Sync {
    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn ring_invoked(
        &self,
        signature: Signature,
        ring: Address,
    ) -> impl Future<Output = Result<bool, OriginError>> + Send;

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send;

    fn reader_granted(
        &self,
        request: ReaderGrant,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send;

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send;

    fn asset_registry(&self) -> impl Future<Output = Result<AssetRegistry, ClientError>> + Send;
}

#[must_use]
pub struct TransactionPage<'a> {
    pub tag: [u8; 32],
    pub page: &'a Page,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct ReaderGrant {
    pub ring: Address,
    pub reader: ReaderKey,
}

#[derive(Clone, Copy)]
pub struct RingConfiguration {
    pub auditor_pubkey: P256Pubkey,
}

#[must_use]
pub struct Upstreams<'a> {
    pub indexer_url: &'a str,
    pub rpc_url: &'a str,
    pub timeout: Duration,
}

pub struct ChainSource {
    indexer: AsyncZolanaIndexer,
    rpc: AsyncSolanaRpc,
}

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("ring_program_id is required when keys are derived per ring")]
    RingRequired,
    #[error("ring is not served by the local auditor key")]
    RingNotServed,
    #[error("audit page is invalid")]
    InvalidPage,
    #[error("request is unauthorized because {0}")]
    Unauthorized(#[from] Unauthorized),
    #[error("key derivation failed because {0}")]
    Derivation(#[from] zolana_keypair::KeypairError),
    #[error(transparent)]
    Upstream(#[from] ClientError),
    #[error(transparent)]
    Origin(#[from] OriginError),
    #[error("indexer returned data outside the audit bounds")]
    InvalidIndexerResponse,
    #[error("audit service state is unavailable")]
    StateUnavailable,
    #[error("audit service is busy")]
    Busy,
}

pub struct AuditService<S> {
    ring: Address,
    auditor: ViewingKey,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
}

#[must_use]
pub struct AuditRead<'a> {
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    Local,
    Derived,
}

pub struct Hub<S> {
    signer: Keypair,
    shared: Arc<Shared<S>>,
    keys: KeySource,
}

#[must_use]
pub struct HubBuilder<S> {
    source: S,
    assets: AssetRegistry,
    origins: Origins,
}

impl PageOptions {
    #[must_use = "use the updated options"]
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, RingRpcError> {
        if cursor.0.is_empty() || cursor.0.len() > AUDIT_CURSOR_LIMIT {
            return Err(RingRpcError::InvalidPage);
        }
        self.cursor = Some(cursor.0);
        Ok(self)
    }

    #[must_use = "use the updated options"]
    pub fn with_limit(mut self, limit: Limit) -> Result<Self, RingRpcError> {
        if limit.value() > AUDIT_PAGE_LIMIT {
            return Err(RingRpcError::InvalidPage);
        }
        self.limit = Some(limit);
        Ok(self)
    }

    pub fn build(self) -> Result<Page, RingRpcError> {
        let attested_limit = self.limit;
        let limit = attested_limit
            .as_ref()
            .map_or(AUDIT_PAGE_LIMIT, Limit::value);
        let limit = u32::try_from(limit)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(RingRpcError::InvalidPage)?;
        Ok(Page {
            cursor: self.cursor,
            limit,
            attested_limit,
        })
    }
}

impl Page {
    pub fn cursor(&self) -> Option<&[u8]> {
        self.cursor.as_deref()
    }

    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }
}

impl ChainSource {
    pub fn connect(upstreams: Upstreams<'_>) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(upstreams.timeout)
            .build()
            .map_err(|error| ClientError::Rpc(format!("http client: {error}")))?;
        Ok(Self {
            indexer: AsyncZolanaIndexer::with_api(ZolanaApi::with_client(
                upstreams.indexer_url,
                http,
            )),
            rpc: AsyncSolanaRpc::with_client(
                NonblockingRpcClient::new_with_timeout_and_commitment(
                    upstreams.rpc_url.to_owned(),
                    upstreams.timeout,
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
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        self.indexer.get_shielded_transactions_by_tags(
            vec![request.tag],
            request.page.cursor().map(ToOwned::to_owned),
            Some(request.page.limit().get()),
            None,
        )
    }

    async fn ring_invoked(&self, signature: Signature, ring: Address) -> Result<bool, OriginError> {
        let transaction = self
            .rpc
            .client()
            .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
            .await
            .map_err(|error| OriginError::Unavailable {
                signature,
                message: error.to_string(),
            })?;
        ConfirmedTransaction {
            signature,
            transaction,
        }
        .ring_invoked(ring)
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, ClientError> {
        let (address, bump) = Address::find_program_address(&[CONFIG_PDA_SEED], &ring);
        let Some(account) = self.rpc.get_account(address).await? else {
            return Ok(None);
        };
        let auditor_pubkey = ConfigAccount {
            account: &account,
            ring,
            bump,
        }
        .decode()?;
        Ok(Some(RingConfiguration { auditor_pubkey }))
    }

    async fn reader_granted(&self, request: ReaderGrant) -> Result<bool, ClientError> {
        let address = request.reader.record_address(&request.ring);
        let Some(account) = self.rpc.get_account(address).await? else {
            return Ok(false);
        };
        ReaderAccount {
            account: &account,
            grant: request,
        }
        .validate()?;
        Ok(true)
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(vec![[0; 32]], None, Some(1), None)
            .await?;
        self.rpc.health().await
    }

    async fn asset_registry(&self) -> Result<AssetRegistry, ClientError> {
        let program = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let accounts = self
            .rpc
            .client()
            .get_program_ui_accounts_with_config(
                &program,
                RpcProgramAccountsConfig {
                    filters: Some(vec![RpcFilterType::DataSize(SplAssetRegistry::SIZE as u64)]),
                    account_config: RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..RpcAccountInfoConfig::default()
                    },
                    ..RpcProgramAccountsConfig::default()
                },
            )
            .await
            .map_err(|_| ClientError::Rpc("asset registry request failed".to_owned()))?;
        if accounts.len() > MAX_ASSET_REGISTRY_ACCOUNTS {
            return Err(ClientError::Rpc(
                "asset registry response is too large".to_owned(),
            ));
        }
        let entries = accounts.into_iter().filter_map(|(_, account)| {
            let account = account.to_account()?;
            SplAssetRegistry::from_account_bytes(&account.data)
                .ok()
                .map(|registry| (registry.asset_id, registry.mint))
        });
        AssetRegistry::new(entries).map_err(ClientError::from)
    }
}

struct ConfigAccount<'a> {
    account: &'a solana_account::Account,
    ring: Address,
    bump: u8,
}

impl ConfigAccount<'_> {
    fn decode(self) -> Result<P256Pubkey, ClientError> {
        let config = AccountCheck::<RingProgramConfig> {
            account: self.account,
            owner: self.ring,
            discriminator: RING_PROGRAM_CONFIG,
            error: "custom ring config account is invalid",
            account_type: PhantomData,
        }
        .decode()?;
        if config.bump != self.bump || is_reserved_p256_derivation_point(&config.auditor_pubkey) {
            return Err(ClientError::Rpc(
                "custom ring config account is invalid".to_owned(),
            ));
        }
        P256Pubkey::from_bytes(config.auditor_pubkey)
            .map_err(|_| ClientError::Rpc("custom ring config account is invalid".to_owned()))
    }
}

struct ReaderAccount<'a> {
    account: &'a solana_account::Account,
    grant: ReaderGrant,
}

impl ReaderAccount<'_> {
    fn validate(self) -> Result<(), ClientError> {
        let record = AccountCheck::<ReaderRecord> {
            account: self.account,
            owner: self.grant.ring,
            discriminator: READER_RECORD,
            error: "custom ring reader account is invalid",
            account_type: PhantomData,
        }
        .decode()?;
        let reader = self.grant.reader.to_bytes();
        let seed_hash = ReaderRecord::seed_hash(&reader)
            .map_err(|_| ClientError::Rpc("custom ring reader account is invalid".to_owned()))?;
        let bump =
            Address::find_program_address(&[ReaderRecord::SEED, &seed_hash], &self.grant.ring).1;
        if record.reader != reader || record.bump != bump {
            return Err(ClientError::Rpc(
                "custom ring reader account is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

struct AccountCheck<'a, T> {
    account: &'a solana_account::Account,
    owner: Address,
    discriminator: u8,
    error: &'static str,
    account_type: PhantomData<T>,
}

impl<T: Pod + Copy> AccountCheck<'_, T> {
    fn decode(self) -> Result<T, ClientError> {
        if self.account.owner.to_bytes() != self.owner.to_bytes()
            || self.account.data.len() != core::mem::size_of::<T>()
        {
            return Err(ClientError::Rpc(self.error.to_owned()));
        }
        let value = bytemuck::try_from_bytes::<T>(&self.account.data)
            .copied()
            .map_err(|_| ClientError::Rpc(self.error.to_owned()))?;
        if self.account.data.first().copied() != Some(self.discriminator) {
            return Err(ClientError::Rpc(self.error.to_owned()));
        }
        Ok(value)
    }
}

impl From<RingRpcError> for ErrorObjectOwned {
    fn from(error: RingRpcError) -> Self {
        match error {
            RingRpcError::RingRequired
            | RingRpcError::RingNotServed
            | RingRpcError::InvalidPage
            | RingRpcError::Unauthorized(_) => ErrorObjectOwned::owned(
                ErrorCode::InvalidRequest.code(),
                error.to_string(),
                None::<()>,
            ),
            RingRpcError::Upstream(inner) => {
                error!("upstream request failed {inner}");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "upstream request failed",
                    None::<()>,
                )
            }
            RingRpcError::Origin(inner) => {
                error!("transaction origin lookup failed {inner}");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "upstream request failed",
                    None::<()>,
                )
            }
            RingRpcError::InvalidIndexerResponse => {
                error!("indexer returned data outside the audit bounds");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "indexer response is invalid",
                    None::<()>,
                )
            }
            RingRpcError::Derivation(inner) => {
                let _ = inner;
                error!("auditor key derivation failed");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "auditor key is unavailable",
                    None::<()>,
                )
            }
            RingRpcError::StateUnavailable => {
                error!("audit service state is unavailable");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "audit service is unavailable",
                    None::<()>,
                )
            }
            RingRpcError::Busy => ErrorObjectOwned::owned(
                ErrorCode::ServerIsBusy.code(),
                "audit service is busy",
                None::<()>,
            ),
        }
    }
}

struct Shared<S> {
    source: S,
    assets: AsyncMutex<AssetCache>,
    origins: Origins,
    replay: ReplayGuard,
    active_readers: Mutex<HashSet<(Address, ReaderKey)>>,
    read_limit: Semaphore,
    request_rate: RequestRate,
}

struct AssetCache {
    registry: AssetRegistry,
    refresh: RefreshState,
}

enum RefreshState {
    Never,
    Succeeded(Instant),
    Failed(Instant),
}

struct RequestRate(Mutex<RequestWindow>);

struct RequestWindow {
    started_at: Instant,
    accepted: usize,
}

struct AuditServiceInit<S> {
    ring: Address,
    auditor: ViewingKey,
    shared: Arc<Shared<S>>,
}

impl<S> AuditServiceInit<S> {
    fn build(self) -> AuditService<S> {
        let view_tag = auditor_view_tag(&self.auditor.pubkey());
        AuditService {
            ring: self.ring,
            auditor: self.auditor,
            view_tag,
            shared: self.shared,
        }
    }
}

#[derive(Default)]
struct ReplayGuard(Mutex<HashMap<Address, HashMap<[u8; 32], u64>>>);

#[must_use]
struct ReplayCheck {
    ring: Address,
    nonce: [u8; 32],
    timestamp: u64,
    now: u64,
}

impl ReplayGuard {
    fn accept(&self, check: ReplayCheck) -> Result<(), Unauthorized> {
        if check.now.abs_diff(check.timestamp) > READ_SKEW.as_secs() {
            return Err(Unauthorized::StaleTimestamp);
        }
        let mut rings = self.0.lock().map_err(|_| Unauthorized::Replay)?;
        let accepted = rings.entry(check.ring).or_default();
        accepted.retain(|_, timestamp| check.now.abs_diff(*timestamp) <= READ_SKEW.as_secs());
        if accepted.len() >= MAX_REPLAY_ENTRIES {
            return Err(Unauthorized::Replay);
        }
        if accepted.insert(check.nonce, check.timestamp).is_some() {
            return Err(Unauthorized::Replay);
        }
        Ok(())
    }
}

impl Default for RequestRate {
    fn default() -> Self {
        Self(Mutex::new(RequestWindow {
            started_at: Instant::now(),
            accepted: 0,
        }))
    }
}

impl RequestRate {
    fn accept(&self, now: Instant) -> Result<(), RingRpcError> {
        let mut window = self.0.lock().map_err(|_| RingRpcError::StateUnavailable)?;
        if now.duration_since(window.started_at) >= Duration::from_secs(1) {
            window.started_at = now;
            window.accepted = 0;
        }
        if window.accepted >= MAX_READS_PER_SECOND {
            return Err(RingRpcError::Busy);
        }
        window.accepted += 1;
        Ok(())
    }
}

struct ReaderPermit<'a> {
    active: &'a Mutex<HashSet<(Address, ReaderKey)>>,
    key: (Address, ReaderKey),
}

impl<'a> ReaderPermit<'a> {
    fn acquire(
        active: &'a Mutex<HashSet<(Address, ReaderKey)>>,
        key: (Address, ReaderKey),
    ) -> Result<Self, RingRpcError> {
        let mut readers = active.lock().map_err(|_| RingRpcError::StateUnavailable)?;
        if !readers.insert(key) {
            return Err(RingRpcError::Busy);
        }
        Ok(Self { active, key })
    }
}

impl Drop for ReaderPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut readers) = self.active.lock() {
            readers.remove(&self.key);
        }
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> P256Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.shared.request_rate.accept(Instant::now())?;
        let _global = self
            .shared
            .read_limit
            .try_acquire()
            .map_err(|_| RingRpcError::Busy)?;
        let _reader = self.authorize_read(request.auth, request.page).await?;
        self.decrypted_transactions(request.page).await
    }

    async fn authorize_read<'a>(
        &'a self,
        auth: &ReadAuth,
        page: &Page,
    ) -> Result<ReaderPermit<'a>, RingRpcError> {
        let nonce = auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::InvalidNonce)?;
        let attestation = ReadAttestation {
            ring: self.ring,
            timestamp: auth.timestamp,
            nonce: &nonce,
            cursor: page.cursor.as_deref(),
            limit: page.attested_limit.clone(),
        };
        let claim = ReadCheck::new(auth, &attestation)
            .at(unix_now().map_err(|_| RingRpcError::StateUnavailable)?)
            .against(&self.shared.origins)
            .decide()?;
        let permit =
            ReaderPermit::acquire(&self.shared.active_readers, (self.ring, claim.reader_key()))?;
        let config = self
            .shared
            .source
            .ring_config(self.ring)
            .await?
            .ok_or(Unauthorized::NoConfig)?;
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        self.shared
            .source
            .reader_granted(ReaderGrant {
                ring: self.ring,
                reader: claim.reader_key(),
            })
            .await?
            .then_some(())
            .ok_or(Unauthorized::NotGranted)?;
        self.shared.replay.accept(ReplayCheck {
            ring: self.ring,
            nonce: claim.nonce(),
            timestamp: auth.timestamp,
            now: unix_now().map_err(|_| RingRpcError::StateUnavailable)?,
        })?;
        Ok(permit)
    }

    async fn decrypted_transactions(
        &self,
        page: &Page,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let response = self
            .shared
            .source
            .transactions_by_tag(TransactionPage {
                tag: self.view_tag,
                page,
            })
            .await?;
        validate_indexer_response(&response, page, self.view_tag)?;
        let mut assets = self.shared.cached_assets().await;
        let mut refreshed_assets = false;

        let mut audited = Vec::new();
        let mut skipped = Vec::new();
        let mut origins: HashMap<Signature, bool> = HashMap::new();
        for tx in response.transactions {
            let ring_invoked = match origins.get(&tx.tx_signature) {
                Some(known) => *known,
                None => {
                    let invoked = self
                        .shared
                        .source
                        .ring_invoked(tx.tx_signature, self.ring)
                        .await?;
                    origins.insert(tx.tx_signature, invoked);
                    invoked
                }
            };
            if !ring_invoked {
                continue;
            }
            let mut result = (TransactionAudit {
                auditor: &self.auditor,
                transaction: &tx,
                assets: &assets,
            })
            .run();
            if matches!(result, Err(AuditError::UnknownAsset { .. })) && !refreshed_assets {
                assets = self.shared.refresh_assets().await?;
                refreshed_assets = true;
                result = (TransactionAudit {
                    auditor: &self.auditor,
                    transaction: &tx,
                    assets: &assets,
                })
                .run();
            }
            match result {
                Ok(opened) => audited.push((opened, tx.nullifiers)),
                Err(reason) => skipped.push(SkippedTransaction {
                    slot: tx.slot,
                    tx_signature: tx.tx_signature.into(),
                    reason: skipped_reason(&reason),
                }),
            }
        }
        let items = audited
            .into_iter()
            .map(|(opened, nullifiers)| decrypted_transaction(opened, nullifiers))
            .collect();

        Ok(GetDecryptedTransactionsResponse {
            context: zolana_indexer_api::Context {
                block_time: response.context.block_time,
                slot: response.context.slot,
            },
            value: DecryptedTransactionsPage {
                items,
                skipped,
                cursor: response.next_cursor.map(Into::into),
            },
        })
    }
}

impl<S: TransactionSource> Shared<S> {
    async fn cached_assets(&self) -> AssetRegistry {
        self.assets.lock().await.registry.clone()
    }

    async fn refresh_assets(&self) -> Result<AssetRegistry, RingRpcError> {
        let mut cache = self.assets.lock().await;
        let refresh_due = match cache.refresh {
            RefreshState::Never => true,
            RefreshState::Succeeded(at) | RefreshState::Failed(at) => {
                at.elapsed() >= ASSET_REFRESH_INTERVAL
            }
        };
        if refresh_due {
            cache.refresh = RefreshState::Failed(Instant::now());
            cache.registry = self.source.asset_registry().await?;
            cache.refresh = RefreshState::Succeeded(Instant::now());
        } else if matches!(cache.refresh, RefreshState::Failed(_)) {
            return Err(ClientError::Rpc("asset registry is unavailable".to_owned()).into());
        }
        Ok(cache.registry.clone())
    }
}

fn skipped_reason(error: &AuditError) -> SkippedReason {
    match error {
        AuditError::MissingAuditorMessage => SkippedReason::MissingAuditorMessage,
        _ => SkippedReason::InvalidAuditData,
    }
}

fn validate_indexer_response(
    response: &GetShieldedTransactionsByTagsResponse,
    page: &Page,
    auditor_tag: [u8; 32],
) -> Result<(), RingRpcError> {
    if response.transactions.len() > page.limit.get() as usize
        || response.next_cursor.as_ref().is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > AUDIT_CURSOR_LIMIT
                || page.cursor.as_ref() == Some(cursor)
        })
    {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    for transaction in &response.transactions {
        let has_auditor_message = transaction
            .messages
            .iter()
            .any(|message| message.view_tag == auditor_tag);
        let supported_shape = SPP_SUPPORTED_SHAPES.contains(&Shape::new(
            transaction.nullifiers.len(),
            transaction.output_slots.len(),
        ));
        if has_auditor_message && !supported_shape {
            return Err(RingRpcError::InvalidIndexerResponse);
        }
    }
    Ok(())
}

fn decrypted_transaction(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
) -> DecryptedTransaction {
    DecryptedTransaction {
        slot: audited.slot,
        tx_signature: audited.tx_signature.into(),
        tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
        outputs: audited
            .outputs
            .into_iter()
            .map(|output| DecryptedOutput {
                slot_index: output.slot_index,
                recipient_viewing_pk: output.recipient_viewing_pk.as_bytes().to_vec().into(),
                asset: output.asset.to_bytes().into(),
                amount: output.amount,
                ring_program_id: output.ring_program_id.map(|id| id.to_bytes().into()),
            })
            .collect(),
        undecryptable_slots: audited.undecryptable_slots,
        nullifiers: nullifiers.into_iter().map(Into::into).collect(),
    }
}

/// The auditor and service domains must stay distinct.
const DERIVATION_INFO: &[u8] = b"zolana/ring-auditor/v1";
const SERVICE_KEY_INFO: &[u8] = b"zolana/ring-rpc-service/v1";

/// The cluster and ring bind each auditor key.
#[must_use]
struct AuditorKeyDerivation<'a> {
    pub root: &'a RootSecret,
    pub genesis_hash: &'a [u8; 32],
    pub ring: Address,
}

impl AuditorKeyDerivation<'_> {
    pub fn derive(self) -> Result<ViewingKey, RingRpcError> {
        let mut info = Vec::with_capacity(
            DERIVATION_INFO.len() + self.genesis_hash.len() + self.ring.as_ref().len() + 1,
        );
        info.extend_from_slice(DERIVATION_INFO);
        info.extend_from_slice(self.genesis_hash);
        info.extend_from_slice(self.ring.as_ref());
        info.push(0);
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, self.root.as_bytes());
        for counter in 0..=u8::MAX {
            *info.last_mut().ok_or(zolana_keypair::KeypairError::Hkdf)? = counter;
            let mut secret = Zeroizing::new([0u8; 32]);
            hkdf.expand(&info, secret.as_mut_slice())
                .map_err(|_| zolana_keypair::KeypairError::Hkdf)?;
            if let Ok(key) = ViewingKey::from_bytes(&secret) {
                return Ok(key);
            }
        }
        Err(zolana_keypair::KeypairError::ZeroScalar.into())
    }
}

fn service_keypair(secret: &[u8]) -> Result<Keypair, RingRpcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret)
        .expand(SERVICE_KEY_INFO, seed.as_mut_slice())
        .map_err(|_| zolana_keypair::KeypairError::Hkdf)?;
    Ok(Keypair::new_from_array(*seed))
}

enum KeySource {
    Local {
        ring: Address,
        auditor: ViewingKey,
    },
    Derived {
        root: RootSecret,
        genesis_hash: [u8; 32],
    },
}

impl<S: TransactionSource> Hub<S> {
    pub fn builder(source: S) -> HubBuilder<S> {
        HubBuilder {
            source,
            assets: AssetRegistry::default(),
            origins: Origins::default(),
        }
    }

    pub fn mode(&self) -> KeyMode {
        match self.keys {
            KeySource::Local { .. } => KeyMode::Local,
            KeySource::Derived { .. } => KeyMode::Derived,
        }
    }

    pub fn service_pubkey(&self) -> Address {
        self.signer.pubkey()
    }

    pub(crate) fn sign_attestation(&self, attestation: &[u8]) -> Signature {
        self.signer.sign_message(attestation)
    }

    pub fn origins(&self) -> &Origins {
        &self.shared.origins
    }

    pub fn local_view_tag(&self) -> Option<[u8; 32]> {
        match &self.keys {
            KeySource::Local { auditor, .. } => Some(auditor_view_tag(&auditor.pubkey())),
            KeySource::Derived { .. } => None,
        }
    }

    pub fn service(&self) -> Result<AuditService<S>, RingRpcError> {
        let KeySource::Local { ring, auditor } = &self.keys else {
            return Err(RingRpcError::RingRequired);
        };
        Ok((AuditServiceInit {
            ring: *ring,
            auditor: auditor.clone(),
            shared: self.shared.clone(),
        })
        .build())
    }

    pub fn service_for(&self, ring: Address) -> Result<AuditService<S>, RingRpcError> {
        match &self.keys {
            KeySource::Local {
                ring: configured,
                auditor,
            } => {
                if ring != *configured {
                    return Err(RingRpcError::RingNotServed);
                }
                Ok((AuditServiceInit {
                    ring: *configured,
                    auditor: auditor.clone(),
                    shared: self.shared.clone(),
                })
                .build())
            }
            KeySource::Derived { root, genesis_hash } => {
                let auditor = AuditorKeyDerivation {
                    root,
                    genesis_hash,
                    ring,
                }
                .derive()?;
                Ok((AuditServiceInit {
                    ring,
                    auditor,
                    shared: self.shared.clone(),
                })
                .build())
            }
        }
    }

    pub async fn probe_upstreams(&self) -> Result<(), RingRpcError> {
        self.shared.source.health().await?;
        if let KeySource::Local { ring, auditor } = &self.keys {
            let config = self
                .shared
                .source
                .ring_config(*ring)
                .await?
                .ok_or(Unauthorized::NoConfig)?;
            if config.auditor_pubkey != auditor.pubkey() {
                return Err(Unauthorized::AuditorKeyMismatch.into());
            }
        }
        Ok(())
    }
}

impl<S: TransactionSource> HubBuilder<S> {
    #[must_use = "use the updated builder"]
    pub fn with_assets(mut self, assets: AssetRegistry) -> Self {
        self.assets = assets;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_origins(mut self, origins: Origins) -> Self {
        self.origins = origins;
        self
    }

    pub fn local(self, ring: Address, auditor: ViewingKey) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(auditor.secret_bytes().as_slice())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Local { ring, auditor },
        })
    }

    pub fn derived(self, root: RootSecret, genesis_hash: [u8; 32]) -> Result<Hub<S>, RingRpcError> {
        let signer = service_keypair(root.as_bytes())?;
        Ok(Hub {
            signer,
            shared: self.shared(),
            keys: KeySource::Derived { root, genesis_hash },
        })
    }

    fn shared(self) -> Arc<Shared<S>> {
        Arc::new(Shared {
            source: self.source,
            assets: AsyncMutex::new(AssetCache {
                registry: self.assets,
                refresh: RefreshState::Never,
            }),
            origins: self.origins,
            replay: ReplayGuard::default(),
            active_readers: Mutex::new(HashSet::new()),
            read_limit: Semaphore::new(MAX_CONCURRENT_READS),
            request_rate: RequestRate::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::{bytes_of, Zeroable};
    use solana_account::Account;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use zolana_interface::P_CONST_SEC1;

    use super::*;

    fn account<T: Pod>(owner: Address, value: &T) -> Account {
        Account {
            lamports: 1,
            data: bytes_of(value).to_vec(),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn config_account(ring: Address, key: [u8; 33], bump: u8) -> Account {
        let mut config = RingProgramConfig::zeroed();
        config.discriminator = RING_PROGRAM_CONFIG;
        config.auditor_pubkey = key;
        config.bump = bump;
        account(ring, &config)
    }

    #[test]
    fn config_accounts_require_the_canonical_layout() {
        let ring = Address::new_from_array([9; 32]);
        let bump = Address::find_program_address(&[CONFIG_PDA_SEED], &ring).1;
        let key = ViewingKey::new().pubkey();
        let valid = config_account(ring, *key.as_bytes(), bump);
        assert_eq!(
            ConfigAccount {
                account: &valid,
                ring,
                bump,
            }
            .decode()
            .expect("config"),
            key
        );

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = Address::new_from_array([8; 32]);
        let mut wrong_size = valid.clone();
        wrong_size.data.push(0);
        let mut wrong_discriminator = valid.clone();
        wrong_discriminator.data[0] = 0;
        for invalid in [wrong_owner, wrong_size, wrong_discriminator] {
            assert!(ConfigAccount {
                account: &invalid,
                ring,
                bump,
            }
            .decode()
            .is_err());
        }
        assert!(ConfigAccount {
            account: &valid,
            ring,
            bump: bump.wrapping_add(1),
        }
        .decode()
        .is_err());
        for invalid_key in [P_CONST_SEC1, [0; 33]] {
            let invalid = config_account(ring, invalid_key, bump);
            assert!(ConfigAccount {
                account: &invalid,
                ring,
                bump,
            }
            .decode()
            .is_err());
        }
    }

    fn reader_account(ring: Address, reader: ReaderKey, bump: u8) -> Account {
        let mut record = ReaderRecord::zeroed();
        record.discriminator = READER_RECORD;
        record.reader = reader.to_bytes();
        record.bump = bump;
        account(ring, &record)
    }

    #[test]
    fn reader_accounts_bind_both_reader_schemes() {
        let ring = Address::new_from_array([9; 32]);
        let readers = [
            ReaderKey::ed25519(Keypair::new().pubkey()).expect("Ed25519 reader"),
            ReaderKey::p256(ViewingKey::new().pubkey()).expect("P256 reader"),
        ];
        for reader in readers {
            let grant = ReaderGrant { ring, reader };
            let bump = Address::find_program_address(
                &[
                    ReaderRecord::SEED,
                    &ReaderRecord::seed_hash(&reader.to_bytes()).expect("seed"),
                ],
                &ring,
            )
            .1;
            let valid = reader_account(ring, reader, bump);
            assert!(ReaderAccount {
                account: &valid,
                grant,
            }
            .validate()
            .is_ok());

            let mut wrong_reader = valid.clone();
            wrong_reader.data[1] ^= 1;
            let wrong_bump = reader_account(ring, reader, bump.wrapping_add(1));
            for invalid in [&wrong_reader, &wrong_bump] {
                assert!(ReaderAccount {
                    account: invalid,
                    grant,
                }
                .validate()
                .is_err());
            }
        }
    }

    #[test]
    fn request_rate_recovers_after_its_window() {
        let rate = RequestRate::default();
        let now = Instant::now();
        for _ in 0..MAX_READS_PER_SECOND {
            rate.accept(now).expect("accepted request");
        }
        assert!(matches!(rate.accept(now), Err(RingRpcError::Busy)));
        rate.accept(now + Duration::from_secs(1))
            .expect("new window");
    }
}
