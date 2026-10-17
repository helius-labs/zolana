use super::storage::RingRoot;
use crate::{
    common::rings_tree::RingsTreeKind,
    ingester::persist::persisted_state_tree::{get_proof_nodes, zero_hash_for_level},
};
use anyhow::{bail, Context, Result};
use custom_ring_interface::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_HEIGHT};
use sea_orm::DatabaseTransaction;
pub(crate) use zolana_ring_indexer::proof::LeafPath;

pub(crate) async fn path(
    tx: &DatabaseTransaction,
    root: &RingRoot,
    index: u64,
) -> Result<LeafPath> {
    if index >= MEMBER_REGISTRY_CAPACITY {
        bail!("member registry index out of range");
    }
    let kind = RingsTreeKind::MemberRegistry;
    let mut node = i64::try_from(MEMBER_REGISTRY_CAPACITY + index)?;
    let values = get_proof_nodes(
        tx,
        vec![(root.address.to_vec(), kind.into(), node)],
        true,
        true,
        kind.tree_height() + 1,
    )
    .await?;
    let lookup = |node, level| -> Result<[u8; 32]> {
        match values.get(&(root.address.to_vec(), kind.into(), node)) {
            Some(value) => value
                .hash
                .clone()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid member registry node")),
            None => zero_hash_for_level(level).context("member registry zero level out of range"),
        }
    };
    let leaf = lookup(node, 0)?;
    let mut siblings = Vec::with_capacity(MEMBER_REGISTRY_HEIGHT);
    for level in 0..MEMBER_REGISTRY_HEIGHT {
        siblings.push(lookup(node ^ 1, level)?);
        node >>= 1;
    }
    let path = LeafPath { leaf, siblings };
    if path.root(index)? != root.root {
        bail!("persisted member registry path does not match its root");
    }
    Ok(path)
}
