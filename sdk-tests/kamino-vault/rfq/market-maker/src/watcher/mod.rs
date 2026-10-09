pub mod polling;
pub mod websocket;

use std::sync::Arc;

use futures::stream::BoxStream;
use solana_address::Address;
use tokio::sync::watch;
use zolana_client::AsyncRpc;
use zolana_interface::state::cache::CACHE_CAPACITY;

use super::{cache_pool::parse_cache_account, config::WatcherConfig, error::MakerError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheUpdate {
    pub cache: Address,
    pub context_slot: u64,
    pub exists: bool,
    pub utxo_hashes: [[u8; 32]; CACHE_CAPACITY],
}

impl CacheUpdate {
    pub fn from_account(
        cache: Address,
        context_slot: u64,
        data: Option<&[u8]>,
    ) -> Result<Self, MakerError> {
        let Some(data) = data else {
            return Ok(Self {
                cache,
                context_slot,
                exists: false,
                utxo_hashes: [[0; 32]; CACHE_CAPACITY],
            });
        };
        let account = parse_cache_account(data).ok_or(MakerError::InvalidCacheAccount { cache })?;
        Ok(Self {
            cache,
            context_slot,
            exists: true,
            utxo_hashes: account.utxo_hashes,
        })
    }
}

pub trait CacheWatcher: Send + Sync {
    fn subscribe(&self, caches: watch::Receiver<Vec<Address>>) -> BoxStream<'static, CacheUpdate>;
}

pub async fn read_caches(
    rpc: &dyn AsyncRpc,
    caches: &[Address],
) -> Result<Vec<CacheUpdate>, MakerError> {
    if caches.is_empty() {
        return Ok(Vec::new());
    }
    let context_slot = rpc.get_slot().await.map_err(MakerError::Rpc)?;
    let accounts = rpc
        .get_multiple_accounts(caches.to_vec())
        .await
        .map_err(MakerError::Rpc)?;
    caches
        .iter()
        .zip(accounts)
        .map(|(cache, account)| {
            CacheUpdate::from_account(
                *cache,
                context_slot,
                account.as_ref().map(|account| account.data.as_slice()),
            )
        })
        .collect()
}

pub fn build_watcher(config: &WatcherConfig, rpc: Arc<dyn AsyncRpc>) -> Arc<dyn CacheWatcher> {
    match config {
        WatcherConfig::Polling { interval } => {
            Arc::new(polling::PollingWatcher::new(rpc, *interval))
        }
        WatcherConfig::Websocket { url } => {
            Arc::new(websocket::WebsocketWatcher::new(rpc, url.clone()))
        }
    }
}
