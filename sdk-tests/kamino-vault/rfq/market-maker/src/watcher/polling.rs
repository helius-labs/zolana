use std::{sync::Arc, time::Duration};

use futures::{stream::BoxStream, StreamExt};
use solana_address::Address;
use tokio::sync::watch;
use zolana_client::AsyncRpc;

use super::{read_caches, CacheUpdate, CacheWatcher};

pub struct PollingWatcher {
    rpc: Arc<dyn AsyncRpc>,
    interval: Duration,
}

impl PollingWatcher {
    pub fn new(rpc: Arc<dyn AsyncRpc>, interval: Duration) -> Self {
        Self { rpc, interval }
    }
}

impl CacheWatcher for PollingWatcher {
    fn subscribe(&self, caches: watch::Receiver<Vec<Address>>) -> BoxStream<'static, CacheUpdate> {
        let rpc = self.rpc.clone();
        let interval = self.interval;
        futures::stream::unfold((rpc, caches), move |(rpc, caches)| async move {
            tokio::time::sleep(interval).await;
            let addresses = caches.borrow().clone();
            let updates = match read_caches(rpc.as_ref(), &addresses).await {
                Ok(updates) => updates,
                Err(error) => {
                    tracing::warn!(%error, "cache poll failed");
                    Vec::new()
                }
            };
            Some((futures::stream::iter(updates), (rpc, caches)))
        })
        .flatten()
        .boxed()
    }
}
