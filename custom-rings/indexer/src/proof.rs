use anyhow::{Context, Result};
use custom_ring_interface::MerklePath;

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
        .context("invalid path")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_HEIGHT};

    #[test]
    fn path_indices_cannot_alias_above_the_circuit_height() {
        let path = LeafPath {
            leaf: [0; 32],
            siblings: vec![[0; 32]; MEMBER_REGISTRY_HEIGHT],
        };
        assert!(path.root(MEMBER_REGISTRY_CAPACITY).is_err());
        assert!(LeafPath {
            leaf: [0; 32],
            siblings: vec![[0; 32]; MEMBER_REGISTRY_HEIGHT + 1],
        }
        .root(0)
        .is_err());
    }
}
