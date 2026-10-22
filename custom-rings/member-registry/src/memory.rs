use std::collections::BTreeMap;

use custom_ring_interface::{MEMBER_REGISTRY_CAPACITY, QUAD_ARITY, QUAD_HEIGHT};

use crate::{
    path::{quad_node, NodePosition, ZERO_SUBTREES},
    record::check_member,
    IndexedRecord, MemberRecord, RecordStore, RecordTreeError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRegistryTree {
    /// The populated prefix of each level, leaves first.
    levels: Vec<Vec<[u8; 32]>>,
    records: Vec<MemberRecord>,
    members: BTreeMap<[u8; 32], u64>,
}

impl MemberRegistryTree {
    /// The tree holding only the sentinel, the state `CreateMemberRegistry` starts from.
    pub fn new() -> Result<Self, RecordTreeError> {
        Self::from_records(vec![MemberRecord::SENTINEL])
    }

    /// Records in leaf order, the sentinel first.
    pub fn from_records(records: Vec<MemberRecord>) -> Result<Self, RecordTreeError> {
        let (sentinel, rest) = records
            .split_first()
            .ok_or(RecordTreeError::MissingSentinel)?;
        // Inserts relink the sentinel's next, its member and fields stay zero.
        if sentinel.member != [0; 32] || !sentinel.is_empty() {
            return Err(RecordTreeError::MissingSentinel);
        }
        if records.len() as u64 > MEMBER_REGISTRY_CAPACITY {
            return Err(RecordTreeError::Full);
        }
        let mut members = BTreeMap::from([(sentinel.member, 0)]);
        for (index, record) in (1..).zip(rest) {
            check_member(&record.member)?;
            if members.insert(record.member, index).is_some() {
                return Err(RecordTreeError::DuplicateMember);
            }
        }
        let mut levels = Vec::with_capacity(QUAD_HEIGHT + 1);
        levels.push(
            records
                .iter()
                .map(MemberRecord::hash)
                .collect::<Result<Vec<_>, _>>()?,
        );
        for level in 0..QUAD_HEIGHT {
            let parents = levels[level]
                .chunks(QUAD_ARITY)
                .map(|chunk| {
                    let children = core::array::from_fn(|child| {
                        chunk.get(child).copied().unwrap_or(ZERO_SUBTREES[level])
                    });
                    quad_node(&children)
                })
                .collect::<Result<Vec<_>, _>>()?;
            levels.push(parents);
        }
        Ok(Self {
            levels,
            records,
            members,
        })
    }

    /// Leaf order.
    pub fn records(&self) -> &[MemberRecord] {
        &self.records
    }

    fn indexed(&self, index: u64) -> Result<IndexedRecord, RecordTreeError> {
        let record = *self
            .records
            .get(index as usize)
            .ok_or(RecordTreeError::RecordMissing(index))?;
        Ok(IndexedRecord { index, record })
    }
}

impl RecordStore for MemberRegistryTree {
    type Error = RecordTreeError;

    fn next_index(&self) -> Result<u64, RecordTreeError> {
        Ok(self.records.len() as u64)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], RecordTreeError> {
        self.levels
            .get(at.level)
            .and_then(|level| level.get(at.position as usize))
            .copied()
            .ok_or(RecordTreeError::NodeMissing {
                level: at.level,
                position: at.position,
            })
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), RecordTreeError> {
        let missing = RecordTreeError::NodeMissing {
            level: at.level,
            position: at.position,
        };
        let level = self.levels.get_mut(at.level).ok_or(missing)?;
        let position = at.position as usize;
        if position == level.len() {
            level.push(node);
        } else {
            *level.get_mut(position).ok_or(missing)? = node;
        }
        Ok(())
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, RecordTreeError> {
        self.members
            .get(member)
            .map(|index| self.indexed(*index))
            .transpose()
    }

    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, RecordTreeError> {
        let (_, index) = self
            .members
            .range(..*member)
            .next_back()
            .ok_or(RecordTreeError::NotBracketed)?;
        self.indexed(*index)
    }

    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), RecordTreeError> {
        let position = index as usize;
        if position == self.records.len() {
            if self.members.contains_key(&record.member) {
                return Err(RecordTreeError::DuplicateMember);
            }
            self.members.insert(record.member, index);
            self.records.push(record);
            return Ok(());
        }
        match self.records.get_mut(position) {
            Some(slot) if slot.member == record.member => {
                *slot = record;
                Ok(())
            }
            Some(_) => Err(RecordTreeError::ForeignRecord(index)),
            None => Err(RecordTreeError::RecordMissing(index)),
        }
    }
}
