use crate::{BorshDeserialize, BorshSerialize};

pub const NULLIFIER_MARKER_SEED: &[u8] = b"nullifier";
pub const NULLIFIER_MARKER_SIZE: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NullifierMarker {
    pub queue_index: u64,
    pub bump: u8,
}

impl NullifierMarker {
    pub fn is_closable(&self, close_before_index: u64) -> bool {
        self.queue_index < close_before_index
    }
}

pub fn nullifier_marker_seeds<'a>(tree: &'a [u8; 32], nullifier: &'a [u8; 32]) -> [&'a [u8]; 3] {
    [NULLIFIER_MARKER_SEED, tree, nullifier]
}

#[cfg(not(target_os = "solana"))]
pub mod host {
    use std::{
        collections::HashMap,
        sync::{LazyLock, Mutex, MutexGuard, PoisonError},
    };

    use super::NullifierMarker;
    use crate::errors::BatchedMerkleTreeError;

    type MarkerKey = ([u8; 32], [u8; 32]);

    static MARKERS: LazyLock<Mutex<HashMap<MarkerKey, u64>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn markers() -> MutexGuard<'static, HashMap<MarkerKey, u64>> {
        MARKERS.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn contains(tree: &[u8; 32], nullifier: &[u8; 32]) -> bool {
        markers().contains_key(&(*tree, *nullifier))
    }

    pub fn reserve(tree: &[u8; 32], nullifier: &[u8; 32], queue_index: u64) {
        markers().insert((*tree, *nullifier), queue_index);
    }

    pub fn close(
        tree: &[u8; 32],
        nullifier: &[u8; 32],
        close_before_index: u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        let mut markers = markers();
        let key = (*tree, *nullifier);
        let queue_index = *markers
            .get(&key)
            .ok_or(BatchedMerkleTreeError::NullifierMarkerMissing)?;
        let marker = NullifierMarker {
            queue_index,
            bump: 0,
        };
        if !marker.is_closable(close_before_index) {
            return Err(BatchedMerkleTreeError::NullifierMarkerNotClosable);
        }
        markers.remove(&key);
        Ok(())
    }

    pub fn queue_index(tree: &[u8; 32], nullifier: &[u8; 32]) -> Option<u64> {
        markers().get(&(*tree, *nullifier)).copied()
    }

    pub fn clear_tree(tree: &[u8; 32]) {
        markers().retain(|(marker_tree, _), _| marker_tree != tree);
    }
}
