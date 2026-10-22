use std::collections::{BTreeMap, BTreeSet};

use custom_ring_interface::{QueueEntry, QUAD_HEIGHT};
use thiserror::Error;
use zolana_ring_member_registry::MemberRegistryTree;
pub use zolana_ring_member_registry::{
    ApplyProofInputs, IndexedRecord, MemberRecord, NodePosition, OpeningCheck, QuadPath,
    RecordOpening, RecordStore, RecordTree, RecordTreeError, RecordWriteProofInput,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRead {
    Present(IndexedRecord),
    Absent {
        member: [u8; 32],
        low: IndexedRecord,
    },
}

/// `nodes` holds every node `node_keys` names whose subtree holds a record.
pub struct ReadRows {
    pub next_index: u64,
    pub reads: Vec<MemberRead>,
    pub nodes: BTreeMap<NodePosition, [u8; 32]>,
}

impl ReadRows {
    pub fn into_tree(self) -> LoadedTree {
        let mut records = BTreeMap::new();
        let mut absent = BTreeSet::new();
        for read in self.reads {
            let record = match read {
                MemberRead::Present(record) => record,
                MemberRead::Absent { member, low } => {
                    absent.insert(member);
                    low
                }
            };
            records.insert(record.record.member, record);
        }
        LoadedTree {
            next_index: self.next_index,
            nodes: self.nodes,
            records,
            absent,
            written: WrittenRows::default(),
        }
    }
}

#[derive(Default)]
pub struct WrittenRows {
    pub records: BTreeMap<[u8; 32], IndexedRecord>,
    pub nodes: BTreeMap<NodePosition, [u8; 32]>,
}

impl WrittenRows {
    pub fn fresh() -> Result<Self, RecordTreeError> {
        let tree = MemberRegistryTree::new()?;
        let next_index = tree.next_index()?;
        let mut nodes = BTreeMap::new();
        for level in 0..=QUAD_HEIGHT {
            let populated = (0..)
                .map(|position| NodePosition { level, position })
                .take_while(|at| !at.is_empty(next_index));
            for at in populated {
                nodes.insert(at, tree.node(at)?);
            }
        }
        let records = (0..)
            .zip(tree.records())
            .map(|(index, record)| {
                let record = *record;
                (record.member, IndexedRecord { index, record })
            })
            .collect();
        Ok(Self { records, nodes })
    }
}

pub struct Application {
    pub inputs: ApplyProofInputs,
    pub rows: WrittenRows,
}

#[derive(Debug, Error)]
pub enum LoadedTreeError {
    #[error(transparent)]
    Tree(#[from] RecordTreeError),
    #[error("storage did not load the record of a member the tree reads")]
    RecordNotLoaded,
}

pub struct LoadedTree {
    next_index: u64,
    nodes: BTreeMap<NodePosition, [u8; 32]>,
    records: BTreeMap<[u8; 32], IndexedRecord>,
    /// Members storage read as absent, their low records are loaded.
    absent: BTreeSet<[u8; 32]>,
    written: WrittenRows,
}

impl LoadedTree {
    pub fn apply_batch(
        mut self,
        chain_start: [u8; 32],
        entries: &[QueueEntry],
    ) -> Result<Application, LoadedTreeError> {
        let inputs = self.apply(chain_start, entries)?;
        Ok(Application {
            inputs,
            rows: self.written,
        })
    }
}

impl RecordStore for LoadedTree {
    type Error = LoadedTreeError;

    fn next_index(&self) -> Result<u64, LoadedTreeError> {
        Ok(self.next_index)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], LoadedTreeError> {
        let missing = RecordTreeError::NodeMissing {
            level: at.level,
            position: at.position,
        };
        Ok(*self.nodes.get(&at).ok_or(missing)?)
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), LoadedTreeError> {
        self.nodes.insert(at, node);
        self.written.nodes.insert(at, node);
        Ok(())
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, LoadedTreeError> {
        match self.records.get(member) {
            Some(record) => Ok(Some(*record)),
            None if self.absent.contains(member) => Ok(None),
            None => Err(LoadedTreeError::RecordNotLoaded),
        }
    }

    /// The loaded low record, or a record the batch inserted closer below `member`.
    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, LoadedTreeError> {
        if !self.absent.contains(member) {
            return Err(LoadedTreeError::RecordNotLoaded);
        }
        let (_, low) = self
            .records
            .range(..*member)
            .next_back()
            .ok_or(RecordTreeError::NotBracketed)?;
        Ok(*low)
    }

    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), LoadedTreeError> {
        if index == self.next_index {
            self.next_index += 1;
        }
        let written = IndexedRecord { index, record };
        self.records.insert(record.member, written);
        self.written.records.insert(record.member, written);
        Ok(())
    }
}

/// The root and every node the openings of `leaves` read.
pub fn node_keys(
    leaves: impl IntoIterator<Item = u64>,
) -> Result<BTreeSet<NodePosition>, RecordTreeError> {
    let mut keys = BTreeSet::from([NodePosition::ROOT]);
    for leaf in leaves {
        keys.extend(QuadPath::sibling_positions(leaf)?.into_iter().flatten());
    }
    Ok(keys)
}
