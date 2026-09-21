use anyhow::{bail, Result};
use custom_ring_interface::{MerklePath, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT};
use std::collections::HashMap;
use zolana_hasher::{Hasher, Poseidon};

pub struct LeafPath {
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

/// The append path must bind the root after the predecessor splice.
pub struct PathOverlay<'a> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_indices_cannot_alias_above_the_circuit_height() {
        let path = LeafPath {
            leaf: [0; 32],
            siblings: vec![[0; 32]; HEAD_MAP_HEIGHT],
        };
        assert!(path.root(HEAD_MAP_CAPACITY).is_err());
        assert!(LeafPath {
            leaf: [0; 32],
            siblings: vec![[0; 32]; HEAD_MAP_HEIGHT + 1],
        }
        .root(0)
        .is_err());
        let mut target = LeafPath {
            leaf: [0; 32],
            siblings: vec![[0; 32]; HEAD_MAP_HEIGHT],
        };
        assert!(PathOverlay {
            updated_index: HEAD_MAP_CAPACITY,
            updated_leaf: [0; 32],
            updated_path: &[[0; 32]; HEAD_MAP_HEIGHT],
        }
        .apply(1, &mut target)
        .is_err());
    }
}
