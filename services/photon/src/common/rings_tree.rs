use zolana_interface::state::{
    ADDRESS_TREE_HEIGHT, ADDRESS_TREE_ROOT_HISTORY_CAPACITY, STATE_HEIGHT,
};
use zolana_tree::smt::ROOT_HISTORY_CAPACITY;

const _: () = assert!(STATE_HEIGHT <= u32::MAX as usize);
const _: () = assert!(ROOT_HISTORY_CAPACITY <= u64::MAX as usize);

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
            Self::Nullifier => ADDRESS_TREE_HEIGHT,
        }
    }

    pub fn root_history_capacity(self) -> u64 {
        match self {
            Self::State => ROOT_HISTORY_CAPACITY as u64,
            Self::Nullifier => u64::from(ADDRESS_TREE_ROOT_HISTORY_CAPACITY),
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
