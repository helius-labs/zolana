use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::{stream::BoxStream, StreamExt};
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_pubsub_client::nonblocking::pubsub_client::PubsubClient;
use solana_rpc_client_api::config::RpcAccountInfoConfig;
use tokio::{sync::mpsc, sync::watch, task::JoinHandle};
use zolana_client::AsyncRpc;

use super::{read_caches, CacheUpdate, CacheWatcher};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub struct WebsocketWatcher {
    rpc: Arc<dyn AsyncRpc>,
    url: String,
}

impl WebsocketWatcher {
    pub fn new(rpc: Arc<dyn AsyncRpc>, url: String) -> Self {
        Self { rpc, url }
    }
}

impl CacheWatcher for WebsocketWatcher {
    fn subscribe(&self, caches: watch::Receiver<Vec<Address>>) -> BoxStream<'static, CacheUpdate> {
        let (updates, receiver) = mpsc::unbounded_channel();
        tokio::spawn(watch_caches(
            self.url.clone(),
            self.rpc.clone(),
            caches,
            updates,
        ));
        futures::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|update| (update, receiver))
        })
        .boxed()
    }
}

async fn watch_caches(
    url: String,
    rpc: Arc<dyn AsyncRpc>,
    mut caches: watch::Receiver<Vec<Address>>,
    updates: mpsc::UnboundedSender<CacheUpdate>,
) {
    loop {
        if updates.is_closed() {
            return;
        }
        let client = match PubsubClient::new(url.as_str()).await {
            Ok(client) => Arc::new(client),
            Err(error) => {
                tracing::warn!(%error, "cache websocket connect failed");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        let (ended, mut ended_receiver) = mpsc::unbounded_channel();
        let mut subscriptions: HashMap<Address, JoinHandle<()>> = HashMap::new();
        let mut watched = caches.borrow_and_update().clone();
        resubscribe(&client, &watched, &mut subscriptions, &updates, &ended);
        match read_caches(rpc.as_ref(), &watched).await {
            Ok(snapshot) => {
                for update in snapshot {
                    let _ = updates.send(update);
                }
            }
            Err(error) => tracing::warn!(%error, "cache snapshot after connect failed"),
        }
        loop {
            tokio::select! {
                changed = caches.changed() => {
                    if changed.is_err() {
                        abort_all(subscriptions);
                        return;
                    }
                    watched = caches.borrow_and_update().clone();
                    subscriptions.retain(|cache, handle| {
                        let keep = watched.contains(cache);
                        if !keep {
                            handle.abort();
                        }
                        keep
                    });
                    resubscribe(&client, &watched, &mut subscriptions, &updates, &ended);
                }
                Some(cache) = ended_receiver.recv() => {
                    if watched.contains(&cache) {
                        tracing::warn!(%cache, "cache subscription ended, reconnecting");
                        break;
                    }
                }
                _ = updates.closed() => {
                    abort_all(subscriptions);
                    return;
                }
            }
        }
        abort_all(subscriptions);
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn resubscribe(
    client: &Arc<PubsubClient>,
    watched: &[Address],
    subscriptions: &mut HashMap<Address, JoinHandle<()>>,
    updates: &mpsc::UnboundedSender<CacheUpdate>,
    ended: &mpsc::UnboundedSender<Address>,
) {
    for cache in watched {
        if subscriptions.contains_key(cache) {
            continue;
        }
        let handle = tokio::spawn(subscribe_cache(
            client.clone(),
            *cache,
            updates.clone(),
            ended.clone(),
        ));
        subscriptions.insert(*cache, handle);
    }
}

fn abort_all(subscriptions: HashMap<Address, JoinHandle<()>>) {
    for handle in subscriptions.into_values() {
        handle.abort();
    }
}

async fn subscribe_cache(
    client: Arc<PubsubClient>,
    cache: Address,
    updates: mpsc::UnboundedSender<CacheUpdate>,
    ended: mpsc::UnboundedSender<Address>,
) {
    let config = RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..RpcAccountInfoConfig::default()
    };
    match client.account_subscribe(&cache, Some(config)).await {
        Ok((mut stream, unsubscribe)) => {
            while let Some(response) = stream.next().await {
                let data = response.value.data.decode();
                match CacheUpdate::from_account(cache, response.context.slot, data.as_deref()) {
                    Ok(update) => {
                        if updates.send(update).is_err() {
                            break;
                        }
                    }
                    Err(error) => tracing::warn!(%error, "cache notification did not parse"),
                }
            }
            unsubscribe().await;
        }
        Err(error) => tracing::warn!(%error, %cache, "cache subscribe failed"),
    }
    let _ = ended.send(cache);
}
