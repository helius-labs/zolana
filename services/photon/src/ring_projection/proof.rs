use super::{storage::RingRoot, Projection};
use crate::ingester::persist::persisted_state_tree::{get_proof_nodes, zero_hash_for_level};
use anyhow::{bail, Context, Result};
use custom_ring_interface::{HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT};
use sea_orm::DatabaseTransaction;
pub(crate) use zolana_ring_indexer::proof::{LeafPath, PathOverlay};

pub(crate) async fn path<P: Projection>(
    tx: &DatabaseTransaction,
    root: &RingRoot,
    index: u64,
) -> Result<LeafPath> {
    if index >= HEAD_MAP_CAPACITY {
        bail!("{} index out of range", P::KIND);
    }
    let kind = P::KIND.tree();
    let mut node = i64::try_from(HEAD_MAP_CAPACITY + index)?;
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
                .map_err(|_| anyhow::anyhow!("invalid {} node", P::KIND)),
            None => zero_hash_for_level(level)
                .with_context(|| format!("{} zero level out of range", P::KIND)),
        }
    };
    let leaf = lookup(node, 0)?;
    let mut siblings = Vec::with_capacity(HEAD_MAP_HEIGHT);
    for level in 0..HEAD_MAP_HEIGHT {
        siblings.push(lookup(node ^ 1, level)?);
        node >>= 1;
    }
    let path = LeafPath { leaf, siblings };
    if path.root(index)? != root.root {
        bail!("persisted {} path does not match its root", P::KIND);
    }
    Ok(path)
}
