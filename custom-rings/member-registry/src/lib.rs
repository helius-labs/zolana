//! The 4-ary indexed record tree of a ring's member registry, one apply and one
//! opening over any [`RecordStore`].

mod memory;
mod path;
mod record;
mod tree;

use thiserror::Error;
use zolana_hasher::HasherError;

pub use memory::MemberRegistryTree;
pub use path::{quad_node, NodePosition, QuadPath, ZERO_SUBTREES};
pub use record::MemberRecord;
pub use tree::{
    ApplyProofInputs, IndexedRecord, OpeningCheck, RecordOpening, RecordStore, RecordTree,
    RecordWriteProofInput,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RecordTreeError {
    #[error("record tree hashing failed")]
    Hashing,
    #[error("member lies outside the record range")]
    MemberOutOfRange,
    #[error("a queued list value leaves its mask")]
    ValueOutsideMask,
    #[error("the record tree is full")]
    Full,
    #[error("leaf index lies outside the tree")]
    IndexOutOfRange,
    #[error("the store holds no node at level {level} position {position}")]
    NodeMissing { level: usize, position: u64 },
    #[error("the store holds no record at index {0}")]
    RecordMissing(u64),
    #[error("the record at index {0} belongs to another member")]
    ForeignRecord(u64),
    #[error("the low record does not bracket the member")]
    NotBracketed,
    #[error("the path does not reach the root")]
    RootMismatch,
    #[error("the first record is not the sentinel")]
    MissingSentinel,
    #[error("a member holds two records")]
    DuplicateMember,
}

impl From<HasherError> for RecordTreeError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}
