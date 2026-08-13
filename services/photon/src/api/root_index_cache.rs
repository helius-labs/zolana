//! Which root-history slot the chain holds a given UTXO root in.
//!
//! A client quotes this index with its proof and the program loads the root it
//! verifies against from that slot, so an index that does not describe the
//! proof's root fails verification while looking like a proof problem. photon
//! used to derive it by counting indexed transactions, which only tracks the
//! chain's `root_history_cursor` for as long as the two happen to advance in
//! step. They drifted, and every transfer failed.
//!
//! The tree account is authoritative and holds the whole 200-slot ring, so the
//! answer is a lookup rather than a count. The account is ~1.2 MB, far too
//! large to fetch per request, and one fetch brings back every root in the
//! window -- so it is cached, refreshed on a miss, and rate limited so a root
//! the chain genuinely does not have cannot turn into a fetch per request.
//!
//! Held per process. Only the API serves proofs, and a cache that belongs to
//! the process reading it needs no coordination with the indexer.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use solana_pubkey::Pubkey;

use crate::api::error::PhotonApiError;
use crate::monitor::tree_metadata_sync::rings_utxo_root_history;
use crate::rpc::RpcClient;

/// Floor between account fetches for one tree. A miss is normal -- photon
/// indexes a new root slightly before the next refresh -- but repeated misses
/// for a root that is not on chain must not become a 1.2 MB fetch per request.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Default)]
struct TreeRoots {
    indices: HashMap<[u8; 32], u16>,
    refreshed: Option<Instant>,
}

#[derive(Default)]
pub struct RootIndexCache {
    trees: RwLock<HashMap<Pubkey, TreeRoots>>,
}

impl RootIndexCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache already holding `roots` for `tree`, so lookups within them never
    /// reach for the account. Lets a caller that has the ring in hand -- a test
    /// with a fixture tree, most of all -- exercise the proof path without an
    /// RPC endpoint.
    pub fn with_roots(tree: Pubkey, roots: impl IntoIterator<Item = (u16, [u8; 32])>) -> Self {
        let cache = Self::new();
        if let Ok(mut trees) = cache.trees.write() {
            trees.insert(
                tree,
                TreeRoots {
                    indices: roots
                        .into_iter()
                        .map(|(index, root)| (root, index))
                        .collect(),
                    refreshed: Some(Instant::now()),
                },
            );
        }
        cache
    }

    /// Root-history slot holding `root`, refreshing from the tree account when
    /// the cached ring does not have it.
    pub async fn index_for(
        &self,
        rpc_client: &RpcClient,
        tree: Pubkey,
        root: [u8; 32],
    ) -> Result<u16, PhotonApiError> {
        if let Some(index) = self.lookup(tree, &root) {
            return Ok(index);
        }
        if !self.due_for_refresh(tree) {
            return Err(self.missing(tree));
        }

        self.refresh(rpc_client, tree).await?;
        self.lookup(tree, &root).ok_or_else(|| self.missing(tree))
    }

    fn lookup(&self, tree: Pubkey, root: &[u8; 32]) -> Option<u16> {
        let trees = self.trees.read().ok()?;
        trees.get(&tree)?.indices.get(root).copied()
    }

    fn due_for_refresh(&self, tree: Pubkey) -> bool {
        let Ok(trees) = self.trees.read() else {
            return false;
        };
        trees
            .get(&tree)
            .and_then(|roots| roots.refreshed)
            .is_none_or(|at| at.elapsed() >= MIN_REFRESH_INTERVAL)
    }

    fn missing(&self, tree: Pubkey) -> PhotonApiError {
        PhotonApiError::StaleRoot(format!(
            "Indexed root for tree {tree} is not in the chain's root history; \
             retry once the indexer catches up"
        ))
    }

    async fn refresh(&self, rpc_client: &RpcClient, tree: Pubkey) -> Result<(), PhotonApiError> {
        let account = rpc_client.get_account(&tree).await.map_err(|error| {
            PhotonApiError::UnexpectedError(format!("Failed to fetch tree {tree}: {error}"))
        })?;
        let history = rings_utxo_root_history(tree, &account).ok_or_else(|| {
            PhotonApiError::UnexpectedError(format!("Account {tree} is not a Rings tree"))
        })?;

        let mut trees = self.trees.write().map_err(|_| {
            PhotonApiError::UnexpectedError("Root index cache is poisoned".to_string())
        })?;
        // Replaced wholesale: a root evicted from the ring must stop resolving,
        // or its stale index outlives the root it described.
        trees.insert(
            tree,
            TreeRoots {
                indices: history
                    .into_iter()
                    .map(|(index, root)| (root, index))
                    .collect(),
                refreshed: Some(Instant::now()),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(
        tree: Pubkey,
        entries: &[([u8; 32], u16)],
        refreshed: Option<Instant>,
    ) -> RootIndexCache {
        let cache = RootIndexCache::new();
        cache.trees.write().unwrap().insert(
            tree,
            TreeRoots {
                indices: entries.iter().copied().collect(),
                refreshed,
            },
        );
        cache
    }

    #[test]
    fn resolves_a_root_anywhere_in_the_ring() {
        // Not just the newest root: photon serves proofs against the root it has
        // indexed, which trails the chain by however far it is behind.
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[([1; 32], 155), ([2; 32], 41)], Some(Instant::now()));

        assert_eq!(cache.lookup(tree, &[155; 32]), None);
        assert_eq!(cache.lookup(tree, &[1; 32]), Some(155));
        assert_eq!(cache.lookup(tree, &[2; 32]), Some(41));
    }

    #[test]
    fn a_fresh_miss_does_not_refetch() {
        // Rate limit: a root the chain does not have must not cost a 1.2 MB
        // account fetch on every request that asks for it.
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[([1; 32], 155)], Some(Instant::now()));

        assert!(!cache.due_for_refresh(tree));
    }

    #[test]
    fn a_stale_miss_refetches() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(
            tree,
            &[([1; 32], 155)],
            Instant::now().checked_sub(MIN_REFRESH_INTERVAL * 2),
        );

        assert!(cache.due_for_refresh(tree));
    }

    #[test]
    fn an_unseen_tree_refetches() {
        assert!(RootIndexCache::new().due_for_refresh(Pubkey::new_from_array([7; 32])));
    }
}
