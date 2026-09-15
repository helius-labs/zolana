use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use custom_ring_interface::{MerklePath, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT};
use sea_orm::DatabaseTransaction;
use zolana_hasher::{Hasher, Poseidon};

use super::{storage::RingRoot, Projection};
use crate::ingester::persist::persisted_state_tree::{get_proof_nodes, zero_hash_for_level};

pub(crate) struct LeafPath {
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl LeafPath {
    pub fn root(&self, index: u64) -> Result<[u8; 32]> {
        MerklePath {
            index,
            siblings: &self.siblings,
        }
        .root_of(self.leaf)
        .map_err(|error| anyhow::anyhow!("invalid path ({error:?})"))
    }
}

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

/// The append path must bind the root after the predecessor splice.
pub(crate) struct PathOverlay<'a> {
    pub updated_index: u64,
    pub updated_leaf: [u8; 32],
    pub updated_path: &'a [[u8; 32]],
}

impl PathOverlay<'_> {
    pub fn apply(&self, target_index: u64, target: &mut LeafPath) -> Result<()> {
        if self.updated_index >= HEAD_MAP_CAPACITY
            || target_index >= HEAD_MAP_CAPACITY
            || self.updated_path.len() != HEAD_MAP_HEIGHT
            || target.siblings.len() != HEAD_MAP_HEIGHT
        {
            bail!("invalid overlay path");
        }
        let mut changed = HashMap::new();
        let mut node = HEAD_MAP_CAPACITY + self.updated_index;
        let mut leaf = self.updated_leaf;
        changed.insert(node, leaf);
        for sibling in self.updated_path {
            leaf = if node & 1 == 0 {
                parent(&leaf, sibling)?
            } else {
                parent(sibling, &leaf)?
            };
            node >>= 1;
            changed.insert(node, leaf);
        }
        let mut target_node = HEAD_MAP_CAPACITY + target_index;
        for sibling in &mut target.siblings {
            if let Some(replacement) = changed.get(&(target_node ^ 1)) {
                *sibling = *replacement;
            }
            target_node >>= 1;
        }
        Ok(())
    }
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    Poseidon::hashv(&[left, right])
        .map_err(|error| anyhow::anyhow!("parent hash failed ({error:?})"))
}
