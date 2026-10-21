use custom_ring_interface::{
    queue_chain, ApplyRecordsStatement, QueueEntry, MEMBER_REGISTRY_CAPACITY, QUAD_ARITY,
    QUAD_HEIGHT,
};

use crate::{
    path::{children, quad_node, NodePosition, QuadPath, ZERO_SUBTREES},
    record::check_member,
    MemberRecord, RecordTreeError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedRecord {
    pub index: u64,
    pub record: MemberRecord,
}

/// One registry's nodes and records, the tree reads no node of an empty subtree from it.
pub trait RecordStore {
    type Error: From<RecordTreeError>;

    /// The leaf the next insert takes.
    fn next_index(&self) -> Result<u64, Self::Error>;

    /// A node the store does not hold is an error, never a zero.
    fn node(&self, at: NodePosition) -> Result<[u8; 32], Self::Error>;

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), Self::Error>;

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, Self::Error>;

    /// The record of the greatest member below `member`.
    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, Self::Error>;

    /// Replaces the record at `index`, or appends it when `index` is `next_index`.
    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), Self::Error>;
}

/// A member under one root, its record or the low record bracketing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOpening {
    Present {
        record: MemberRecord,
        path: QuadPath,
    },
    Absent {
        low: MemberRecord,
        path: QuadPath,
    },
}

impl RecordOpening {
    /// The member's record under `root`, `None` for an absent member.
    pub fn verify(
        &self,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<Option<MemberRecord>, RecordTreeError> {
        check_member(member)?;
        let (leaf, path, present) = match self {
            Self::Present { record, path } if record.member == *member => {
                (record, path, Some(*record))
            }
            Self::Absent { low, path } if low.brackets(member) => (low, path, None),
            Self::Present { .. } | Self::Absent { .. } => {
                return Err(RecordTreeError::NotBracketed)
            }
        };
        if path.root(leaf.hash()?)? != *root {
            return Err(RecordTreeError::RootMismatch);
        }
        Ok(present)
    }
}

/// One queued write's proof input, mirror `RecordWrite` of
/// `prover/server/custom_rings/circuits/registry/apply.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordWriteProofInput {
    pub entry: QueueEntry,
    pub exists: bool,
    /// The old record's fields, an absent member reads its low record's `next` and nothing else.
    pub old_next: [u8; 32],
    pub old_lists: u64,
    pub old_escrow: [u8; 32],
    /// The record's leaf, an absent member's `next_index` leaf after the relink or low leaf when full.
    pub slot: QuadPath,
    /// An absent member's low record and its path before the relink, empty for a present member.
    pub low: MemberRecord,
    pub low_path: QuadPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyProofInputs {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: [u8; 32],
    pub chain_end: [u8; 32],
    /// Queue order.
    pub writes: Vec<RecordWriteProofInput>,
}

impl ApplyProofInputs {
    pub fn statement(&self) -> Result<ApplyRecordsStatement, RecordTreeError> {
        let index = |value: u64| u32::try_from(value).map_err(|_| RecordTreeError::IndexOutOfRange);
        Ok(ApplyRecordsStatement {
            old_root: self.old_root,
            new_root: self.new_root,
            old_next_index: index(self.old_next_index)?,
            new_next_index: index(self.new_next_index)?,
            chain_start: self.chain_start,
            chain_end: self.chain_end,
            count: self.writes.len() as u64,
        })
    }
}

/// The one implementation of the tree over every store.
pub trait RecordTree: RecordStore {
    fn root(&self) -> Result<[u8; 32], Self::Error> {
        node_at(self, self.next_index()?, NodePosition::ROOT)
    }

    fn path(&self, index: u64) -> Result<QuadPath, Self::Error> {
        path_at(self, self.next_index()?, index)
    }

    fn opening(&self, member: &[u8; 32]) -> Result<RecordOpening, Self::Error> {
        check_member(member)?;
        Ok(match self.record(member)? {
            Some(IndexedRecord { index, record }) => RecordOpening::Present {
                record,
                path: self.path(index)?,
            },
            None => {
                let IndexedRecord { index, record } = self.low_record(member)?;
                if !record.brackets(member) {
                    return Err(RecordTreeError::NotBracketed.into());
                }
                RecordOpening::Absent {
                    low: record,
                    path: self.path(index)?,
                }
            }
        })
    }

    /// `entries` in queue order, one the program never queues fails before any write.
    fn apply(
        &mut self,
        chain_start: [u8; 32],
        entries: &[QueueEntry],
    ) -> Result<ApplyProofInputs, Self::Error> {
        entries.iter().try_for_each(check_entry)?;
        let old_root = self.root()?;
        let old_next_index = self.next_index()?;
        let mut next_index = old_next_index;
        let mut chain_end = chain_start;
        let mut writes = Vec::with_capacity(entries.len());
        for entry in entries {
            writes.push(apply_entry(self, &mut next_index, entry)?);
            chain_end = queue_chain(&chain_end, entry).map_err(RecordTreeError::from)?;
        }
        Ok(ApplyProofInputs {
            old_root,
            new_root: node_at(self, next_index, NodePosition::ROOT)?,
            old_next_index,
            new_next_index: next_index,
            chain_start,
            chain_end,
            writes,
        })
    }
}

impl<S: RecordStore + ?Sized> RecordTree for S {}

/// One write in the order the apply circuit proves its steps.
fn apply_entry<S: RecordStore + ?Sized>(
    store: &mut S,
    next_index: &mut u64,
    entry: &QueueEntry,
) -> Result<RecordWriteProofInput, S::Error> {
    if let Some(IndexedRecord { index, record }) = store.record(&entry.member)? {
        let slot = path_at(store, *next_index, index)?;
        write_leaf(store, *next_index, index, record.written(entry))?;
        return Ok(RecordWriteProofInput {
            entry: *entry,
            exists: true,
            old_next: record.next,
            old_lists: record.lists,
            old_escrow: record.escrow_key,
            slot,
            low: MemberRecord::default(),
            low_path: QuadPath::default(),
        });
    }
    let IndexedRecord {
        index: low_index,
        record: low,
    } = store.low_record(&entry.member)?;
    if !low.brackets(&entry.member) {
        return Err(RecordTreeError::NotBracketed.into());
    }
    let low_path = path_at(store, *next_index, low_index)?;
    let inserted = MemberRecord {
        member: entry.member,
        next: low.next,
        lists: 0,
        escrow_key: [0; 32],
    }
    .written(entry);
    let absent = |slot| RecordWriteProofInput {
        entry: *entry,
        exists: false,
        old_next: low.next,
        old_lists: 0,
        old_escrow: [0; 32],
        slot,
        low,
        low_path,
    };
    let full = *next_index >= MEMBER_REGISTRY_CAPACITY;
    // An empty record is never inserted, the write proves the absence and keeps the root.
    if inserted.is_empty() {
        // The circuit range-checks a no-op's slot and nothing else.
        let slot = if full {
            low_path
        } else {
            path_at(store, *next_index, *next_index)?
        };
        return Ok(absent(slot));
    }
    if full {
        return Err(RecordTreeError::Full.into());
    }
    write_leaf(
        store,
        *next_index,
        low_index,
        MemberRecord {
            next: entry.member,
            ..low
        },
    )?;
    let slot = path_at(store, *next_index, *next_index)?;
    write_leaf(store, *next_index, *next_index, inserted)?;
    *next_index += 1;
    Ok(absent(slot))
}

fn check_entry(entry: &QueueEntry) -> Result<(), RecordTreeError> {
    check_member(&entry.member)?;
    if entry.value & !entry.mask != 0 {
        return Err(RecordTreeError::ValueOutsideMask);
    }
    Ok(())
}

fn node_at<S: RecordStore + ?Sized>(
    store: &S,
    next_index: u64,
    at: NodePosition,
) -> Result<[u8; 32], S::Error> {
    if at.is_empty(next_index) {
        return Ok(ZERO_SUBTREES[at.level]);
    }
    store.node(at)
}

fn path_at<S: RecordStore + ?Sized>(
    store: &S,
    next_index: u64,
    index: u64,
) -> Result<QuadPath, S::Error> {
    let mut siblings = [[[0u8; 32]; QUAD_ARITY - 1]; QUAD_HEIGHT];
    for (level, positions) in QuadPath::sibling_positions(index)?.iter().enumerate() {
        for (sibling, at) in siblings[level].iter_mut().zip(positions) {
            *sibling = node_at(store, next_index, *at)?;
        }
    }
    Ok(QuadPath { index, siblings })
}

/// Writes the record and every node from its leaf to the root.
fn write_leaf<S: RecordStore + ?Sized>(
    store: &mut S,
    next_index: u64,
    index: u64,
    record: MemberRecord,
) -> Result<(), S::Error> {
    let path = path_at(store, next_index, index)?;
    store.set_record(index, record)?;
    let mut node = record.hash().map_err(RecordTreeError::from)?;
    for (level, siblings) in path.siblings.iter().enumerate() {
        let at = NodePosition::on_path(index, level);
        store.set_node(at, node)?;
        node = quad_node(&children(node, at.digit(), siblings)).map_err(RecordTreeError::from)?;
    }
    store.set_node(NodePosition::ROOT, node)
}
