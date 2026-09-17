use crate::ingester::error::IngesterError;
use zolana_hasher::{Hasher, HasherError, Poseidon, Poseidon2};
use zolana_interface::state::{
    NULLIFIER_TREE_HEIGHT, NULLIFIER_TREE_ROOT_HISTORY_CAPACITY, STATE_HEIGHT,
    STATE_ROOT_HISTORY_CAPACITY,
};

const _: () = assert!(STATE_HEIGHT <= u32::MAX as usize);
const _: () = assert!(STATE_ROOT_HISTORY_CAPACITY <= u64::MAX as usize);

/// Rings tree roles used by Photon API proof contexts and role-specific
/// persistence tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RingsTreeKind {
    /// UTXO/state inclusion proofs.
    State = 1,
    /// Nullifier non-inclusion proofs.
    Nullifier = 2,
}

impl RingsTreeKind {
    pub fn tree_height(self) -> u32 {
        match self {
            Self::State => STATE_HEIGHT as u32,
            Self::Nullifier => NULLIFIER_TREE_HEIGHT,
        }
    }

    pub fn root_history_capacity(self) -> u64 {
        match self {
            Self::State => STATE_ROOT_HISTORY_CAPACITY as u64,
            Self::Nullifier => u64::from(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY),
        }
    }

    /// The tree's 2-to-1 node hash: Poseidon for the state tree, which the
    /// program appends to on chain through the Poseidon syscall, Poseidon2 for
    /// the nullifier tree, which is only hashed in circuits and off chain.
    pub fn parent_hash(self, left: &[u8], right: &[u8]) -> Result<[u8; 32], HasherError> {
        match self {
            Self::State => Poseidon::hashv(&[left, right]),
            Self::Nullifier => Poseidon2::hashv(&[left, right]),
        }
    }

    /// Root of an empty subtree of height `level` under [`Self::parent_hash`].
    pub fn zero_hash(self, level: usize) -> Option<[u8; 32]> {
        match self {
            Self::State => Poseidon::zero_bytes(),
            Self::Nullifier => Poseidon2::zero_bytes(),
        }
        .get(level)
        .copied()
    }
}

impl TryFrom<i32> for RingsTreeKind {
    type Error = IngesterError;

    fn try_from(kind: i32) -> Result<Self, IngesterError> {
        match kind {
            1 => Ok(Self::State),
            2 => Ok(Self::Nullifier),
            other => Err(IngesterError::ParserError(format!(
                "Unknown Rings tree kind {other}"
            ))),
        }
    }
}

impl From<RingsTreeKind> for i32 {
    fn from(kind: RingsTreeKind) -> Self {
        kind as i32
    }
}

impl From<RingsTreeKind> for u16 {
    fn from(kind: RingsTreeKind) -> Self {
        kind as u16
    }
}
