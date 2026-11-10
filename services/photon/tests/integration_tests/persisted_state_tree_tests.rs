use photon_indexer::{
    common::rings_tree::RingsTreeKind,
    ingester::persist::{persist_leaf_nodes, persisted_state_tree::get_proof_nodes, LeafNode},
    migration::RingsMigrator,
};
use sea_orm::{Database, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use solana_pubkey::Pubkey;
use spr_indexer_api::Hash;

/// A replayed snapshot batch adds about 10,000 leaves to one tree at once;
/// reading their proof nodes in one statement exceeded SQLite's bind limit.
#[tokio::test]
async fn persists_a_batch_of_leaves_larger_than_one_proof_node_query() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let tree = Pubkey::new_unique().to_bytes().to_vec();
    let kind = RingsTreeKind::State;
    let height = kind.tree_height() + 1;
    let leaves: Vec<LeafNode> = (0..12_000u64)
        .map(|leaf_index| {
            let mut hash = [0u8; 32];
            hash[24..].copy_from_slice(&(leaf_index + 1).to_be_bytes());
            LeafNode {
                tree: tree.clone(),
                tree_kind: kind,
                leaf_index,
                hash: Hash::from(hash),
                seq: Some(1),
            }
        })
        .collect();
    let locations: Vec<_> = leaves
        .iter()
        .map(|leaf| {
            (
                tree.clone(),
                i32::from(kind),
                leaf.node_index(height).unwrap(),
            )
        })
        .collect();

    let txn = db.begin().await.unwrap();
    persist_leaf_nodes(&txn, leaves, height).await.unwrap();
    let nodes = get_proof_nodes(&txn, locations.clone(), true, false, height)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    assert!(locations
        .iter()
        .all(|location| nodes.contains_key(location)));
}
