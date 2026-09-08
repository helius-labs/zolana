//! Which root-history entry the chain currently holds a given UTXO root in.
//!
//! A client quotes an index with its proof and the program loads the root it
//! verifies against from that entry. State-root history advances once per slot
//! that changes the tree, not once per Solana slot, so the completed block slot
//! cannot be converted into a history index. This cache resolves the exact root
//! against the authoritative on-chain ring and returns the entry that holds it.
//!
//! The tree account is authoritative and holds the whole root-history ring. It
//! is too large to fetch per request, and one fetch brings back every root in
//! the window, so it is cached, refreshed on a mismatch, and that on-demand
//! fetch is rate limited so a root the chain genuinely does not have cannot
//! turn into a fetch per request.
//!
//! Held per process. Only the API serves proofs, and a cache that belongs to
//! the process reading it needs no coordination with the indexer.
//!
//! Refreshed ahead of the request, not on it. A mismatch is normal while Photon
//! has committed a newer slot than the last account refresh, and fetching the
//! account on that critical path adds an upstream RPC round trip to the proof
//! request.
//!
//! [`RootIndexCache::refresh_loop`] watches the indexed root's completed block
//! slot in Postgres, which is cheap, and fetches the account only when that slot
//! moves. Block ingestion is atomic, so only the final root for a slot becomes
//! visible. The on-demand fetch stays as the fallback for a request that arrives
//! between a tree update and the next refresh. Refresher fetches therefore do
//! not count against the on-demand floor: letting them close that window would
//! starve the fallback on exactly the busy tree that needs it.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use solana_pubkey::Pubkey;

use crate::api::error::PhotonApiError;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::{state_trees, tree_metadata};
use crate::monitor::tree_metadata_sync::rings_utxo_root_history;
use crate::rpc::RpcClient;

/// Floor between account fetches for one tree. A miss is normal -- photon
/// indexes a new root slightly before the next refresh -- but repeated misses
/// for a root that is not on chain must not become an account fetch per request.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// How often the refresher asks Postgres whether the tree moved. This is a
/// single-row primary-key read, not the account fetch, so it can be far shorter
/// than [`MIN_REFRESH_INTERVAL`].
const CHANGE_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Default)]
struct TreeRoots {
    indices: HashMap<[u8; 32], u16>,
    /// When the on-demand path last fetched this account, and nothing else. The
    /// floor is there to stop a caller turning a root the chain does not have
    /// into a fetch per request; the refresher is already gated on the root slot
    /// moving, so its fetches must not stamp this.
    fetched_on_miss: Option<Instant>,
}

/// Which path is bringing roots in. Only the on-demand one is throttled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fetch {
    OnMiss,
    Refresher,
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
                    fetched_on_miss: Some(Instant::now()),
                },
            );
        }
        cache
    }

    /// Return the root-history entry holding `root`, refreshing from the tree
    /// account when the cached ring does not contain it.
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

        self.refresh(rpc_client, tree, Fetch::OnMiss).await?;
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
            .and_then(|roots| roots.fetched_on_miss)
            .is_none_or(|at| at.elapsed() >= MIN_REFRESH_INTERVAL)
    }

    fn missing(&self, tree: Pubkey) -> PhotonApiError {
        PhotonApiError::StaleRoot(format!(
            "Indexed root for tree {tree} is not in the chain's root history; \
             retry once the indexer catches up"
        ))
    }

    /// Keep every known state tree's ring current, so `index_for` answers from
    /// memory.
    ///
    /// Change detection is the point: refreshing on a timer would fetch every
    /// tree account per tick whether or not anything moved, and refreshing on a
    /// request puts that fetch in front of the caller. The indexed root's slot
    /// moves whenever a later slot's final root is committed, and reading it is
    /// a primary-key lookup.
    pub async fn refresh_loop(&self, db: &DatabaseConnection, rpc_client: &RpcClient) {
        let mut seen: HashMap<Pubkey, Option<i64>> = HashMap::new();
        loop {
            match known_state_trees(db).await {
                Ok(trees) => {
                    for tree in trees {
                        let slot = match root_slot(db, tree).await {
                            Ok(slot) => slot,
                            Err(error) => {
                                log::warn!(
                                    "root index refresher: reading {tree} root slot: {error}"
                                );
                                continue;
                            }
                        };
                        // First sight of a tree refreshes it; after that only a
                        // later completed root slot does.
                        if seen.get(&tree).is_some_and(|last| *last == slot) {
                            continue;
                        }
                        match self.refresh(rpc_client, tree, Fetch::Refresher).await {
                            Ok(()) => {
                                seen.insert(tree, slot);
                            }
                            // Leave `seen` alone so the next tick tries again.
                            Err(error) => {
                                log::warn!("root index refresher: refreshing {tree}: {error}")
                            }
                        }
                    }
                }
                Err(error) => log::warn!("root index refresher: listing trees: {error}"),
            }
            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
        }
    }

    async fn refresh(
        &self,
        rpc_client: &RpcClient,
        tree: Pubkey,
        fetch: Fetch,
    ) -> Result<(), PhotonApiError> {
        let account = rpc_client.get_account(&tree).await.map_err(|error| {
            PhotonApiError::UnexpectedError(format!("Failed to fetch tree {tree}: {error}"))
        })?;
        let history = rings_utxo_root_history(tree, &account).ok_or_else(|| {
            PhotonApiError::UnexpectedError(format!("Account {tree} is not a Rings tree"))
        })?;

        self.store(tree, history, fetch)
    }

    fn store(
        &self,
        tree: Pubkey,
        history: impl IntoIterator<Item = (u16, [u8; 32])>,
        fetch: Fetch,
    ) -> Result<(), PhotonApiError> {
        let mut trees = self.trees.write().map_err(|_| {
            PhotonApiError::UnexpectedError("Root index cache is poisoned".to_string())
        })?;
        let entry = trees.entry(tree).or_default();
        // Replaced wholesale: a root evicted from the ring must stop resolving,
        // or its stale index outlives the root it described.
        entry.indices = history
            .into_iter()
            .map(|(index, root)| (root, index))
            .collect();
        if fetch == Fetch::OnMiss {
            entry.fetched_on_miss = Some(Instant::now());
        }
        Ok(())
    }
}

/// State trees the indexer knows about. The refresher covers every one rather
/// than only the trees already asked for, so the first proof after a restart
/// does not pay the fetch.
async fn known_state_trees(db: &DatabaseConnection) -> Result<Vec<Pubkey>, PhotonApiError> {
    let rows = tree_metadata::Entity::find()
        .all(db)
        .await
        .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?;
    rows.into_iter()
        .map(|row| {
            <[u8; 32]>::try_from(row.tree_pubkey.as_slice())
                .map(Pubkey::new_from_array)
                .map_err(|_| {
                    PhotonApiError::UnexpectedError("tree_metadata pubkey is not 32 bytes".into())
                })
        })
        .collect()
}

/// Completed block slot stamped on the indexed tree's root node. Block
/// ingestion commits atomically, so an observed value describes that slot's
/// final root rather than an intermediate transaction root.
async fn root_slot(db: &DatabaseConnection, tree: Pubkey) -> Result<Option<i64>, PhotonApiError> {
    let root = state_trees::Entity::find()
        .filter(
            state_trees::Column::Tree
                .eq(tree.to_bytes().to_vec())
                .and(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
                .and(state_trees::Column::NodeIdx.eq(1)),
        )
        .one(db)
        .await
        .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?;
    Ok(root.and_then(|node| node.seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(
        tree: Pubkey,
        entries: &[(u16, [u8; 32])],
        fetched_on_miss: Option<Instant>,
    ) -> RootIndexCache {
        let cache = RootIndexCache::new();
        cache.trees.write().unwrap().insert(
            tree,
            TreeRoots {
                indices: entries
                    .iter()
                    .map(|(index, root)| (*root, *index))
                    .collect(),
                fetched_on_miss,
            },
        );
        cache
    }

    #[test]
    fn lookup_returns_the_authoritative_history_index() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[(155, [1; 32]), (41, [2; 32])], Some(Instant::now()));

        assert_eq!(cache.lookup(tree, &[1; 32]), Some(155));
        assert_eq!(cache.lookup(tree, &[2; 32]), Some(41));
        assert_eq!(cache.lookup(tree, &[3; 32]), None);
    }

    /// The point of refreshing ahead: a request for a root the refresher has
    /// already brought in must not consult the RPC at all. `index_for` takes an
    /// `RpcClient`, so the only honest way to assert "did not fetch" is that the
    /// answer comes back from a cache whose refresh window is closed -- with a
    /// stale window the on-miss path would fire instead.
    #[tokio::test]
    async fn a_root_the_refresher_brought_in_is_answered_without_the_rpc() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[(12, [9; 32])], Some(Instant::now()));

        // An unreachable endpoint: reaching for it at all is the failure.
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        assert_eq!(cache.index_for(&rpc, tree, [9; 32]).await.unwrap(), 12);
    }

    #[tokio::test]
    async fn root_index_is_not_derived_from_the_completed_slot() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[(12, [9; 32])], Some(Instant::now()));

        // The completed slot may be any value; only the account can tell us
        // that this root is stored at index 12.
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        assert_eq!(cache.index_for(&rpc, tree, [9; 32]).await.unwrap(), 12);
    }

    /// And the fallback still has to work: a request that arrives between a tree
    /// update and the next refresh is answered, not failed.
    #[tokio::test]
    async fn a_root_the_refresher_has_not_reached_still_reaches_for_the_account() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(
            tree,
            &[(12, [9; 32])],
            Instant::now().checked_sub(MIN_REFRESH_INTERVAL * 2),
        );

        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        // Unreachable, so this surfaces the fetch as an error rather than a
        // StaleRoot -- which is the proof that the fetch was attempted.
        let error = cache.index_for(&rpc, tree, [4; 32]).await.unwrap_err();
        assert!(
            matches!(error, PhotonApiError::UnexpectedError(_)),
            "expected the on-miss fetch to be attempted, got {error:?}"
        );
    }

    /// The regression this pairs with: the refresher fetches whenever the tree
    /// moves, so if its fetches stamped the on-miss floor, each newly indexed
    /// updating slot would hold that window shut and the fallback would never
    /// fire. A miss right after a refresher pass -- a root indexed between the
    /// pass and the request -- then failed as StaleRoot instead of being fetched,
    /// which is a hard error on a chain that is merely busy.
    ///
    /// Driven through `store`, so it is the code both fetch paths share that is
    /// under test rather than a hand-built cache.
    #[test]
    fn the_refreshers_fetches_do_not_close_the_on_miss_window() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = RootIndexCache::new();

        cache
            .store(tree, [(12u16, [9u8; 32])], Fetch::Refresher)
            .expect("store");
        assert_eq!(cache.lookup(tree, &[9; 32]), Some(12), "roots are cached");
        assert!(
            cache.due_for_refresh(tree),
            "a miss must still be able to reach for the account"
        );

        cache
            .store(tree, [(12u16, [9u8; 32])], Fetch::OnMiss)
            .expect("store");
        assert!(
            !cache.due_for_refresh(tree),
            "and an on-demand fetch still closes it"
        );
    }

    #[test]
    fn a_fresh_miss_does_not_refetch() {
        // Rate limit: a root the chain does not have must not cost an account
        // fetch on every request that asks for it.
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(tree, &[(155, [1; 32])], Some(Instant::now()));

        assert!(!cache.due_for_refresh(tree));
    }

    #[test]
    fn a_stale_miss_refetches() {
        let tree = Pubkey::new_from_array([7; 32]);
        let cache = cache_with(
            tree,
            &[(155, [1; 32])],
            Instant::now().checked_sub(MIN_REFRESH_INTERVAL * 2),
        );

        assert!(cache.due_for_refresh(tree));
    }

    #[test]
    fn an_unseen_tree_refetches() {
        assert!(RootIndexCache::new().due_for_refresh(Pubkey::new_from_array([7; 32])));
    }
}
