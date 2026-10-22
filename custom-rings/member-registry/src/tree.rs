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

#[must_use]
pub struct OpeningCheck<'a> {
    pub opening: &'a RecordOpening,
    pub root: &'a [u8; 32],
    pub member: &'a [u8; 32],
}

impl OpeningCheck<'_> {
    /// The member's record under `root`, `None` for an absent member.
    pub fn verify(self) -> Result<Option<MemberRecord>, RecordTreeError> {
        let member = self.member;
        check_member(member)?;
        let (leaf, path, present) = match self.opening {
            RecordOpening::Present { record, path } if record.member == *member => {
                (record, path, Some(*record))
            }
            RecordOpening::Absent { low, path } if low.brackets(member) => (low, path, None),
            RecordOpening::Present { .. } | RecordOpening::Absent { .. } => {
                return Err(RecordTreeError::NotBracketed)
            }
        };
        if path.root(leaf.hash()?)? != *self.root {
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

pub trait RecordTree: RecordStore {
    fn root(&self) -> Result<[u8; 32], Self::Error> {
        Filled::of(self)?.node(NodePosition::ROOT)
    }

    fn path(&self, index: u64) -> Result<QuadPath, Self::Error> {
        Filled::of(self)?.path(index)
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
        let mut tree = Growing {
            store: self,
            next_index: old_next_index,
        };
        let mut chain_end = chain_start;
        let mut writes = Vec::with_capacity(entries.len());
        for entry in entries {
            writes.push(tree.apply(entry)?);
            chain_end = queue_chain(&chain_end, entry).map_err(RecordTreeError::from)?;
        }
        Ok(ApplyProofInputs {
            old_root,
            new_root: tree.filled().node(NodePosition::ROOT)?,
            old_next_index,
            new_next_index: tree.next_index,
            chain_start,
            chain_end,
            writes,
        })
    }
}

impl<S: RecordStore + ?Sized> RecordTree for S {}

/// The store with every leaf from `next_index` on empty.
struct Filled<'s, S: ?Sized> {
    store: &'s S,
    next_index: u64,
}

impl<'s, S: RecordStore + ?Sized> Filled<'s, S> {
    fn of(store: &'s S) -> Result<Self, S::Error> {
        Ok(Self {
            next_index: store.next_index()?,
            store,
        })
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], S::Error> {
        if at.is_empty(self.next_index) {
            return Ok(ZERO_SUBTREES[at.level]);
        }
        self.store.node(at)
    }

    fn path(&self, index: u64) -> Result<QuadPath, S::Error> {
        let mut siblings = [[[0u8; 32]; QUAD_ARITY - 1]; QUAD_HEIGHT];
        for (level, positions) in QuadPath::sibling_positions(index)?.iter().enumerate() {
            for (sibling, at) in siblings[level].iter_mut().zip(positions) {
                *sibling = self.node(*at)?;
            }
        }
        Ok(QuadPath { index, siblings })
    }
}

/// The store an application writes, `next_index` advancing at each insert.
struct Growing<'s, S: ?Sized> {
    store: &'s mut S,
    next_index: u64,
}

impl<S: RecordStore + ?Sized> Growing<'_, S> {
    fn filled(&self) -> Filled<'_, S> {
        Filled {
            store: self.store,
            next_index: self.next_index,
        }
    }

    /// One write in the order the apply circuit proves its steps.
    fn apply(&mut self, entry: &QueueEntry) -> Result<RecordWriteProofInput, S::Error> {
        if let Some(IndexedRecord { index, record }) = self.store.record(&entry.member)? {
            let slot = self.filled().path(index)?;
            self.write(index, record.written(entry))?;
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
        } = self.store.low_record(&entry.member)?;
        if !low.brackets(&entry.member) {
            return Err(RecordTreeError::NotBracketed.into());
        }
        let low_path = self.filled().path(low_index)?;
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
        let full = self.next_index >= MEMBER_REGISTRY_CAPACITY;
        // An empty record is never inserted, the write proves the absence and keeps the root.
        if inserted.is_empty() {
            // The circuit range-checks a no-op's slot and nothing else.
            let slot = if full {
                low_path
            } else {
                self.filled().path(self.next_index)?
            };
            return Ok(absent(slot));
        }
        if full {
            return Err(RecordTreeError::Full.into());
        }
        self.write(
            low_index,
            MemberRecord {
                next: entry.member,
                ..low
            },
        )?;
        let slot = self.filled().path(self.next_index)?;
        self.write(self.next_index, inserted)?;
        self.next_index += 1;
        Ok(absent(slot))
    }

    /// Writes the record and every node from its leaf to the root.
    fn write(&mut self, index: u64, record: MemberRecord) -> Result<(), S::Error> {
        let path = self.filled().path(index)?;
        self.store.set_record(index, record)?;
        let mut node = record.hash().map_err(RecordTreeError::from)?;
        for (level, siblings) in path.siblings.iter().enumerate() {
            let at = NodePosition::on_path(index, level);
            self.store.set_node(at, node)?;
            node =
                quad_node(&children(node, at.digit(), siblings)).map_err(RecordTreeError::from)?;
        }
        self.store.set_node(NodePosition::ROOT, node)
    }
}

fn check_entry(entry: &QueueEntry) -> Result<(), RecordTreeError> {
    check_member(&entry.member)?;
    if entry.value & !entry.mask != 0 {
        return Err(RecordTreeError::ValueOutsideMask);
    }
    Ok(())
}
