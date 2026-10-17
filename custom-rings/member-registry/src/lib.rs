//! Reference member registry. Rebuilds the on-chain indexed tree, and derives the
//! record openings and batch witnesses the circuits take.

use std::collections::HashMap;

use custom_ring_interface::{
    MemberRecord, MemberUpdate, MerklePath, FIELD_MAX, MAX_MEMBER_BATCH, MEMBER_REGISTRY_CAPACITY,
    MEMBER_REGISTRY_HEIGHT,
};
use thiserror::Error;
use zolana_hasher::{Hasher, HasherError, Poseidon};
use zolana_merkle_tree::{MerkleTree, ReferenceMerkleTreeError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemberRegistryError {
    #[error("member registry hashing failed")]
    Hashing,
    #[error("member registry tree operation failed")]
    Tree,
    #[error("member registry is full")]
    Full,
    #[error("member is zero or past the sentinel range")]
    OutOfRange,
    #[error("batch is empty, too large or not strictly ascending")]
    Batch,
    #[error("item disagrees with the record it rewrites")]
    Mismatch,
    #[error("path has the wrong length or index")]
    Path,
}

impl From<HasherError> for MemberRegistryError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

impl From<ReferenceMerkleTreeError> for MemberRegistryError {
    fn from(error: ReferenceMerkleTreeError) -> Self {
        match error {
            ReferenceMerkleTreeError::Hasher(_) => Self::Hashing,
            _ => Self::Tree,
        }
    }
}

/// The record bracketing an inserted member, zero for a rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    pub lists: u64,
    pub escrow_key: [u8; 32],
    pub index: u64,
    pub path: Vec<[u8; 32]>,
}

/// One item's circuit wires. A rewrite opens the record at `index` under the root before
/// the item, an insert opens the empty leaf there after the low record is relinked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordUpdateInputs {
    pub exists: bool,
    pub next: [u8; 32],
    pub index: u64,
    pub path: Vec<[u8; 32]>,
    pub low: Option<LowRecord>,
}

/// A member's state under one root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    Present {
        record: MemberRecord,
        index: u64,
        path: Vec<[u8; 32]>,
    },
    Absent {
        low: MemberRecord,
        low_index: u64,
        path: Vec<[u8; 32]>,
    },
}

#[derive(Clone)]
pub struct MemberRegistryTree {
    tree: MerkleTree<Poseidon>,
    /// Leaf order, `records[i]` sits at index `i`.
    records: Vec<MemberRecord>,
}

impl MemberRegistryTree {
    pub fn new() -> Result<Self, MemberRegistryError> {
        let mut tree = MerkleTree::<Poseidon>::new(MEMBER_REGISTRY_HEIGHT, 0);
        tree.append(&MemberRecord::SENTINEL.hash()?)?;
        Ok(Self {
            tree,
            records: vec![MemberRecord::SENTINEL],
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn next_index(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn records(&self) -> &[MemberRecord] {
        &self.records
    }

    pub fn find(&self, member: &[u8; 32]) -> Option<(u64, &MemberRecord)> {
        self.records
            .iter()
            .position(|record| record.member == *member)
            .map(|index| (index as u64, &self.records[index]))
    }

    /// The record at `index`, as a `MerklePath` would open it.
    pub fn path(&self, index: u64) -> Result<Vec<[u8; 32]>, MemberRegistryError> {
        if index >= MEMBER_REGISTRY_CAPACITY {
            return Err(MemberRegistryError::Path);
        }
        Ok(self.tree.get_proof_of_leaf(index as usize, true)?)
    }

    /// Siblings of the empty leaf at `next_index`.
    pub fn append_path(&self) -> Result<Vec<[u8; 32]>, MemberRegistryError> {
        if self.next_index() >= MEMBER_REGISTRY_CAPACITY {
            return Err(MemberRegistryError::Full);
        }
        self.path(self.next_index())
    }

    pub fn opening(&self, member: &[u8; 32]) -> Result<Opening, MemberRegistryError> {
        check_member(member)?;
        if let Some((index, record)) = self.find(member) {
            return Ok(Opening::Present {
                record: *record,
                index,
                path: self.path(index)?,
            });
        }
        let low_index = self.low_of(member)?;
        Ok(Opening::Absent {
            low: self.records[low_index as usize],
            low_index,
            path: self.path(low_index)?,
        })
    }

    /// The item that keeps `member`'s lists and sets `escrow_key`, an insert for a new member.
    pub fn register_item(
        &self,
        member: &[u8; 32],
        escrow_key: [u8; 32],
    ) -> Result<MemberUpdate, MemberRegistryError> {
        check_member(member)?;
        let (index, lists) = match self.find(member) {
            Some((index, record)) => (index, record.lists),
            None => (self.next_index(), 0),
        };
        Ok(MemberUpdate {
            member: *member,
            old_lists: lists,
            old_escrow_key: [0; 32],
            lists,
            escrow_key,
            index,
        })
    }

    /// Items writing `lists` per member, sorted and indexed as `apply` takes them.
    pub fn list_items(
        &self,
        writes: &[([u8; 32], u64)],
    ) -> Result<Vec<MemberUpdate>, MemberRegistryError> {
        let mut writes = writes.to_vec();
        writes.sort_by_key(|(member, _)| *member);
        let mut items = Vec::with_capacity(writes.len());
        let mut inserts = 0;
        for (member, lists) in writes {
            check_member(&member)?;
            let item = match self.find(&member) {
                Some((index, record)) => MemberUpdate {
                    member,
                    old_lists: record.lists,
                    old_escrow_key: record.escrow_key,
                    lists,
                    escrow_key: record.escrow_key,
                    index,
                },
                None => {
                    inserts += 1;
                    MemberUpdate {
                        member,
                        lists,
                        index: self.next_index() + inserts - 1,
                        ..MemberUpdate::default()
                    }
                }
            };
            items.push(item);
        }
        Ok(items)
    }

    /// Applies `items` in order, returning each item's wires. Nothing is written when
    /// an item fails the checks the program makes.
    pub fn apply(
        &mut self,
        items: &[MemberUpdate],
    ) -> Result<Vec<RecordUpdateInputs>, MemberRegistryError> {
        check_batch(items)?;
        let mut inserts = 0;
        for item in items {
            check_member(&item.member)?;
            match self.find(&item.member) {
                Some((index, record)) => {
                    if item.index != index
                        || item.old_lists != record.lists
                        || item.old_escrow_key != record.escrow_key
                    {
                        return Err(MemberRegistryError::Mismatch);
                    }
                }
                None => {
                    if item.index != self.next_index() + inserts
                        || item.old_lists != 0
                        || item.old_escrow_key != [0; 32]
                    {
                        return Err(MemberRegistryError::Mismatch);
                    }
                    inserts += 1;
                }
            }
        }
        if self.next_index() + inserts > MEMBER_REGISTRY_CAPACITY {
            return Err(MemberRegistryError::Full);
        }
        items.iter().map(|item| self.apply_item(item)).collect()
    }

    fn apply_item(
        &mut self,
        item: &MemberUpdate,
    ) -> Result<RecordUpdateInputs, MemberRegistryError> {
        if let Some((index, record)) = self.find(&item.member) {
            let after = MemberRecord {
                lists: item.lists,
                escrow_key: item.escrow_key,
                ..*record
            };
            let path = self.path(index)?;
            self.tree.update(&after.hash()?, index as usize)?;
            self.records[index as usize] = after;
            return Ok(RecordUpdateInputs {
                exists: true,
                next: after.next,
                index,
                path,
                low: None,
            });
        }
        let low_index = self.low_of(&item.member)?;
        let low = self.records[low_index as usize];
        let low_path = self.path(low_index)?;
        let relinked = MemberRecord {
            next: item.member,
            ..low
        };
        self.tree.update(&relinked.hash()?, low_index as usize)?;
        self.records[low_index as usize] = relinked;
        let index = self.next_index();
        let path = self.path(index)?;
        let record = MemberRecord {
            member: item.member,
            next: low.next,
            lists: item.lists,
            escrow_key: item.escrow_key,
        };
        self.tree.append(&record.hash()?)?;
        self.records.push(record);
        Ok(RecordUpdateInputs {
            exists: false,
            next: low.next,
            index,
            path,
            low: Some(LowRecord {
                member: low.member,
                next: low.next,
                lists: low.lists,
                escrow_key: low.escrow_key,
                index: low_index,
                path: low_path,
            }),
        })
    }

    fn low_of(&self, member: &[u8; 32]) -> Result<u64, MemberRegistryError> {
        self.records
            .iter()
            // Canonical big-endian field elements sort by their byte order.
            .position(|record| record.member < *member && *member < record.next)
            .map(|index| index as u64)
            .ok_or(MemberRegistryError::OutOfRange)
    }
}

fn check_member(member: &[u8; 32]) -> Result<(), MemberRegistryError> {
    if *member == [0; 32] || *member >= FIELD_MAX {
        return Err(MemberRegistryError::OutOfRange);
    }
    Ok(())
}

/// The batch shape the program admits.
pub fn check_batch(items: &[MemberUpdate]) -> Result<(), MemberRegistryError> {
    if !(1..=MAX_MEMBER_BATCH).contains(&items.len())
        || items
            .windows(2)
            .any(|pair| pair[0].member >= pair[1].member)
    {
        return Err(MemberRegistryError::Batch);
    }
    Ok(())
}

/// Node writes over one base root, so the paths of later items in a batch follow the
/// earlier writes without a full tree. Base paths come from the indexer at that root.
pub struct RegistryOverlay {
    base_next_index: u64,
    append_path: Vec<[u8; 32]>,
    /// Nodes of the empty leaf at `base_next_index` up to the root, under the base root.
    append_nodes: Vec<[u8; 32]>,
    nodes: HashMap<(usize, u64), [u8; 32]>,
}

impl RegistryOverlay {
    /// `append_path` opens the empty leaf at `next_index` under the base root.
    pub fn new(next_index: u64, append_path: Vec<[u8; 32]>) -> Result<Self, MemberRegistryError> {
        if append_path.len() != MEMBER_REGISTRY_HEIGHT || next_index >= MEMBER_REGISTRY_CAPACITY {
            return Err(MemberRegistryError::Path);
        }
        let zero = Poseidon::zero_bytes();
        let mut append_nodes = Vec::with_capacity(MEMBER_REGISTRY_HEIGHT + 1);
        let mut node = zero[0];
        let mut index = next_index;
        for sibling in &append_path {
            append_nodes.push(node);
            node = if index & 1 == 0 {
                Poseidon::hashv(&[&node, sibling])?
            } else {
                Poseidon::hashv(&[sibling, &node])?
            };
            index >>= 1;
        }
        append_nodes.push(node);
        Ok(Self {
            base_next_index: next_index,
            append_path,
            append_nodes,
            nodes: HashMap::new(),
        })
    }

    /// The current siblings of `index`. `base` is its path under the base root, `None`
    /// for a leaf at or past the base append index.
    pub fn path(
        &self,
        index: u64,
        base: Option<&[[u8; 32]]>,
    ) -> Result<Vec<[u8; 32]>, MemberRegistryError> {
        if index >= MEMBER_REGISTRY_CAPACITY
            || base.is_some_and(|base| base.len() != MEMBER_REGISTRY_HEIGHT)
            || (base.is_none() && index < self.base_next_index)
        {
            return Err(MemberRegistryError::Path);
        }
        let zero = Poseidon::zero_bytes();
        let mut path = Vec::with_capacity(MEMBER_REGISTRY_HEIGHT);
        for level in 0..MEMBER_REGISTRY_HEIGHT {
            let sibling = (index >> level) ^ 1;
            let node = match (self.nodes.get(&(level, sibling)), base) {
                (Some(node), _) => *node,
                (None, Some(base)) => base[level],
                // Past the base append index every leaf is empty, the base paths of
                // `base_next_index` cover the rest.
                (None, None) if sibling == self.base_next_index >> level => {
                    self.append_nodes[level]
                }
                (None, None) if sibling << level >= self.base_next_index => zero[level],
                (None, None) => self.append_path[level],
            };
            path.push(node);
        }
        Ok(path)
    }

    /// Writes `leaf` at `index` along `path`, the current siblings, and returns the new root.
    pub fn write(
        &mut self,
        index: u64,
        leaf: [u8; 32],
        path: &[[u8; 32]],
    ) -> Result<[u8; 32], MemberRegistryError> {
        if index >= MEMBER_REGISTRY_CAPACITY || path.len() != MEMBER_REGISTRY_HEIGHT {
            return Err(MemberRegistryError::Path);
        }
        let mut node = leaf;
        let mut position = index;
        for (level, sibling) in path.iter().enumerate() {
            self.nodes.insert((level, position), node);
            node = if position & 1 == 0 {
                Poseidon::hashv(&[&node, sibling])?
            } else {
                Poseidon::hashv(&[sibling, &node])?
            };
            position >>= 1;
        }
        self.nodes.insert((MEMBER_REGISTRY_HEIGHT, 0), node);
        Ok(node)
    }
}

/// The root `path` reaches from `leaf` at `index`.
pub fn root_of(
    index: u64,
    leaf: [u8; 32],
    path: &[[u8; 32]],
) -> Result<[u8; 32], MemberRegistryError> {
    MerklePath {
        index,
        siblings: path,
    }
    .root_of(leaf)
    .map_err(|_| MemberRegistryError::Path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{MemberOpening, MEMBER_REGISTRY_EMPTY_ROOT};

    fn member(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    fn lists(tree: &MemberRegistryTree, byte: u8) -> Option<u64> {
        tree.find(&member(byte)).map(|(_, record)| record.lists)
    }

    #[test]
    fn a_fresh_tree_is_the_pinned_empty_root() {
        let tree = MemberRegistryTree::new().unwrap();
        assert_eq!(tree.root(), MEMBER_REGISTRY_EMPTY_ROOT);
        assert_eq!(tree.next_index(), 1);
        assert_eq!(tree.append_path().unwrap().len(), MEMBER_REGISTRY_HEIGHT);
    }

    #[test]
    fn a_batch_inserts_in_member_order_and_rewrites_in_place() {
        let mut tree = MemberRegistryTree::new().unwrap();
        let items = tree.list_items(&[(member(9), 1), (member(4), 2)]).unwrap();
        assert_eq!(items[0].member, member(4));
        assert_eq!(items[0].index, 1);
        assert_eq!(items[1].index, 2);
        let empty = tree.root();
        let inputs = tree.apply(&items).unwrap();
        assert_ne!(tree.root(), empty);
        assert!(inputs.iter().all(|input| !input.exists));
        assert_eq!(inputs[1].low.as_ref().unwrap().member, member(4));
        assert_eq!(lists(&tree, 4), Some(2));
        assert_eq!(lists(&tree, 9), Some(1));

        let rewrite = tree.list_items(&[(member(4), 6)]).unwrap();
        let inputs = tree.apply(&rewrite).unwrap();
        assert!(inputs[0].exists && inputs[0].low.is_none());
        assert_eq!(lists(&tree, 4), Some(6));
        assert_eq!(tree.next_index(), 3);
    }

    #[test]
    fn the_program_checks_fail_before_any_write() {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply(&tree.list_items(&[(member(5), 1)]).unwrap())
            .unwrap();
        let before = tree.root();
        let mut stale = tree.list_items(&[(member(5), 3)]).unwrap();
        stale[0].old_lists = 0;
        assert_eq!(tree.apply(&stale), Err(MemberRegistryError::Mismatch));
        let mut misplaced = tree.list_items(&[(member(7), 3)]).unwrap();
        misplaced[0].index = 5;
        assert_eq!(tree.apply(&misplaced), Err(MemberRegistryError::Mismatch));
        let unordered = [
            tree.list_items(&[(member(9), 1)]).unwrap()[0],
            tree.list_items(&[(member(7), 1)]).unwrap()[0],
        ];
        assert_eq!(tree.apply(&unordered), Err(MemberRegistryError::Batch));
        assert_eq!(tree.apply(&[]), Err(MemberRegistryError::Batch));
        assert_eq!(tree.root(), before);
    }

    #[test]
    fn openings_verify_present_and_absent_members() {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply(&tree.list_items(&[(member(4), 2), (member(9), 1)]).unwrap())
            .unwrap();
        let root = tree.root();
        match tree.opening(&member(4)).unwrap() {
            Opening::Present {
                record,
                index,
                path,
            } => {
                let opening = MemberOpening::Present {
                    record,
                    path: MerklePath {
                        index,
                        siblings: &path,
                    },
                };
                assert_eq!(opening.verify(&root, &member(4)), Ok((2, [0; 32])));
                assert_eq!(record.next, member(9));
            }
            absent => panic!("{absent:?}"),
        }
        match tree.opening(&member(7)).unwrap() {
            Opening::Absent {
                low,
                low_index,
                path,
            } => {
                let opening = MemberOpening::Absent {
                    low,
                    path: MerklePath {
                        index: low_index,
                        siblings: &path,
                    },
                };
                assert_eq!(opening.verify(&root, &member(7)), Ok((0, [0; 32])));
                assert_eq!(low.member, member(4));
            }
            present => panic!("{present:?}"),
        }
        assert_eq!(tree.opening(&[0; 32]), Err(MemberRegistryError::OutOfRange));
    }

    #[test]
    fn a_registration_keeps_the_lists_and_sets_the_key() {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply(&tree.list_items(&[(member(4), 5)]).unwrap())
            .unwrap();
        let registered = tree.register_item(&member(4), member(0x44)).unwrap();
        assert_eq!((registered.old_lists, registered.lists), (5, 5));
        assert_eq!(registered.index, 1);
        let fresh = tree.register_item(&member(6), member(0x66)).unwrap();
        assert_eq!(fresh.index, 2);
        assert_eq!(fresh.lists, 0);
        tree.apply(&[registered]).unwrap();
        tree.apply(&[fresh]).unwrap();
        assert_eq!(tree.find(&member(4)).unwrap().1.escrow_key, member(0x44));
    }

    /// The overlay reproduces every path the reference tree hands out during a batch.
    #[test]
    fn the_overlay_tracks_the_reference_tree_through_a_batch() {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply(
            &tree
                .list_items(&[(member(10), 1), (member(40), 1)])
                .unwrap(),
        )
        .unwrap();
        let base = tree.clone();
        let items = tree
            .list_items(&[
                (member(10), 3),
                (member(20), 1),
                (member(50), 2),
                (member(60), 4),
            ])
            .unwrap();
        let inputs = tree.apply(&items).unwrap();
        let mut overlay =
            RegistryOverlay::new(base.next_index(), base.append_path().unwrap()).unwrap();
        let mut root = base.root();
        for (item, input) in items.iter().zip(&inputs) {
            if let Some(low) = &input.low {
                let low_base = base.path(low.index).unwrap();
                let low_path = overlay.path(low.index, Some(&low_base)).unwrap();
                assert_eq!(low_path, low.path);
                let relinked = MemberRecord {
                    member: low.member,
                    next: item.member,
                    lists: low.lists,
                    escrow_key: low.escrow_key,
                };
                root = overlay
                    .write(low.index, relinked.hash().unwrap(), &low_path)
                    .unwrap();
                let path = overlay.path(input.index, None).unwrap();
                assert_eq!(path, input.path);
                assert_eq!(
                    root_of(input.index, Poseidon::zero_bytes()[0], &path).unwrap(),
                    root
                );
            } else {
                let path = overlay
                    .path(input.index, Some(&base.path(input.index).unwrap()))
                    .unwrap();
                assert_eq!(path, input.path);
            }
            let record = MemberRecord {
                member: item.member,
                next: input.next,
                lists: item.lists,
                escrow_key: item.escrow_key,
            };
            root = overlay
                .write(input.index, record.hash().unwrap(), &input.path)
                .unwrap();
        }
        assert_eq!(root, tree.root());
    }
}
