use std::collections::{BTreeMap, HashMap};

use custom_ring_interface::{
    QueueEntry, FIELD_MAX, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT,
};
use zolana_hasher::primitives::right_align;
use zolana_ring_member_registry::{
    quad_node, IndexedRecord, MemberRecord, MemberRegistryTree, NodePosition, OpeningCheck,
    QuadPath, RecordOpening, RecordStore, RecordTree, RecordTreeError, ZERO_SUBTREES,
};
use zolana_ring_policy::ListId;

fn member(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

fn write(byte: u8, mask: u64, value: u64) -> QueueEntry {
    QueueEntry {
        member: member(byte),
        mask,
        value,
        escrow_key: [0; 32],
    }
}

fn escrow(byte: u8, key: u8) -> QueueEntry {
    let bit = ListId::Escrow.record_bit();
    QueueEntry {
        member: member(byte),
        mask: bit,
        value: bit,
        escrow_key: member(key),
    }
}

fn record(tree: &MemberRegistryTree, byte: u8) -> Option<MemberRecord> {
    tree.record(&member(byte))
        .unwrap()
        .map(|indexed| indexed.record)
}

const ALLOW: u64 = 1 << 0;
const BLOCK: u64 = 1 << 1;

#[test]
fn a_fresh_tree_is_the_registry_genesis_root() {
    for level in 0..ZERO_SUBTREES.len() - 1 {
        let zero = ZERO_SUBTREES[level];
        assert_eq!(quad_node(&[zero; 4]).unwrap(), ZERO_SUBTREES[level + 1]);
    }
    let tree = MemberRegistryTree::new().unwrap();
    assert_eq!(tree.root().unwrap(), MEMBER_REGISTRY_EMPTY_ROOT);
    assert_eq!(tree.next_index().unwrap(), 1);
}

#[test]
fn an_insert_relinks_the_low_record_and_fills_the_next_index() {
    let mut tree = MemberRegistryTree::new().unwrap();
    let first = tree.apply([0; 32], &[write(9, ALLOW, ALLOW)]).unwrap();
    let relinked = tree.root().unwrap();
    let inputs = tree
        .apply(first.chain_end, &[write(4, BLOCK, BLOCK)])
        .unwrap();
    let insert = inputs.writes[0];
    assert!(!insert.exists);
    assert_eq!(insert.slot.index, 2);
    assert_eq!(insert.low.member, [0; 32]);
    assert_eq!(insert.low.next, member(9));
    assert_eq!(insert.old_next, member(9));
    assert_eq!(
        insert.low_path.root(insert.low.hash().unwrap()),
        Ok(relinked)
    );
    assert_eq!(record(&tree, 4).map(|record| record.next), Some(member(9)));
    assert_eq!(
        tree.records()[0].next,
        member(4),
        "the sentinel now links to the lower member"
    );
    assert_eq!((inputs.old_next_index, inputs.new_next_index), (2, 3));
    assert_eq!(inputs.new_root, tree.root().unwrap());
}

#[test]
fn an_update_keeps_the_list_bits_outside_its_mask() {
    let mut tree = MemberRegistryTree::new().unwrap();
    tree.apply([0; 32], &[write(5, ALLOW | BLOCK, ALLOW | BLOCK)])
        .unwrap();
    let inputs = tree.apply([0; 32], &[write(5, BLOCK, 0)]).unwrap();
    let update = inputs.writes[0];
    assert!(update.exists);
    assert_eq!((update.old_lists, update.slot.index), (ALLOW | BLOCK, 1));
    assert_eq!(update.low, MemberRecord::default());
    assert_eq!(record(&tree, 5).map(|record| record.lists), Some(ALLOW));
    assert_eq!(inputs.new_next_index, inputs.old_next_index);
}

#[test]
fn an_absent_member_whose_write_leaves_no_list_stays_absent() {
    let mut tree = MemberRegistryTree::new().unwrap();
    let before = tree.root().unwrap();
    let inputs = tree.apply([0; 32], &[write(7, ALLOW, 0)]).unwrap();
    let noop = inputs.writes[0];
    assert!(!noop.exists);
    assert_eq!(noop.low, MemberRecord::SENTINEL);
    assert_eq!(noop.low_path.root(noop.low.hash().unwrap()), Ok(before));
    assert_eq!((inputs.new_root, inputs.new_next_index), (before, 1));
    assert_eq!(record(&tree, 7), None);
}

#[test]
fn a_second_escrow_key_leaves_the_first_in_place() {
    let mut tree = MemberRegistryTree::new().unwrap();
    tree.apply([0; 32], &[escrow(3, 0x31), escrow(3, 0x32)])
        .unwrap();
    let escrowed = record(&tree, 3).unwrap();
    assert_eq!(escrowed.escrow_key, member(0x31));
    assert_eq!(escrowed.lists, ListId::Escrow.record_bit());
}

#[test]
fn the_tree_refuses_writes_the_program_never_queues() {
    let mut tree = MemberRegistryTree::new().unwrap();
    let before = tree.clone();
    assert_eq!(
        tree.apply([0; 32], &[write(6, ALLOW, ALLOW | BLOCK)]),
        Err(RecordTreeError::ValueOutsideMask)
    );
    let mut zero = write(6, ALLOW, ALLOW);
    zero.member = [0; 32];
    assert_eq!(
        tree.apply([0; 32], &[zero]),
        Err(RecordTreeError::MemberOutOfRange)
    );
    let mut max = zero;
    max.member = FIELD_MAX;
    assert_eq!(
        tree.apply([0; 32], &[max]),
        Err(RecordTreeError::MemberOutOfRange)
    );
    assert_eq!(tree, before);
    assert_eq!(
        QuadPath::sibling_positions(MEMBER_REGISTRY_CAPACITY),
        Err(RecordTreeError::IndexOutOfRange)
    );
}

#[test]
fn openings_resolve_present_and_absent_members_under_their_root() {
    let mut tree = MemberRegistryTree::new().unwrap();
    tree.apply([0; 32], &[write(4, ALLOW, ALLOW), write(9, BLOCK, BLOCK)])
        .unwrap();
    let root = tree.root().unwrap();
    let [four, five, seven, nine, ten] = [4, 5, 7, 9, 10].map(member);
    let present = tree.opening(&four).unwrap();
    let check = |opening, member| OpeningCheck {
        opening,
        root: &root,
        member,
    };
    assert_eq!(check(&present, &four).verify(), Ok(record(&tree, 4)));
    let absent = tree.opening(&seven).unwrap();
    assert!(matches!(absent, RecordOpening::Absent { low, .. } if low.member == four));
    assert_eq!(check(&absent, &seven).verify(), Ok(None));
    for outside in [&four, &nine, &ten] {
        assert_eq!(
            check(&absent, outside).verify(),
            Err(RecordTreeError::NotBracketed)
        );
    }
    assert_eq!(
        check(&present, &five).verify(),
        Err(RecordTreeError::NotBracketed)
    );
    let stale = OpeningCheck {
        opening: &present,
        root: &MEMBER_REGISTRY_EMPTY_ROOT,
        member: &four,
    };
    assert_eq!(stale.verify(), Err(RecordTreeError::RootMismatch));
}

#[test]
fn records_rebuild_the_tree_they_came_from() {
    let mut tree = MemberRegistryTree::new().unwrap();
    let entries: Vec<QueueEntry> = (1..=40).map(|byte| write(byte * 5, ALLOW, ALLOW)).collect();
    tree.apply([0; 32], &entries).unwrap();
    let rebuilt = MemberRegistryTree::from_records(tree.records().to_vec()).unwrap();
    assert_eq!(rebuilt, tree);
    let mut duplicated = tree.records().to_vec();
    duplicated.push(duplicated[1]);
    assert_eq!(
        MemberRegistryTree::from_records(duplicated),
        Err(RecordTreeError::DuplicateMember)
    );
    assert_eq!(
        MemberRegistryTree::from_records(tree.records()[1..].to_vec()),
        Err(RecordTreeError::MissingSentinel)
    );
}

/// A store holding only what `sibling_positions` names for a batch, as the indexer preloads it.
#[derive(Default)]
struct PreloadedStore {
    next_index: u64,
    nodes: HashMap<NodePosition, [u8; 32]>,
    records: BTreeMap<[u8; 32], IndexedRecord>,
}

impl PreloadedStore {
    fn for_batch(tree: &MemberRegistryTree, entries: &[QueueEntry]) -> Self {
        let next_index = tree.next_index().unwrap();
        let mut store = Self {
            next_index,
            ..Self::default()
        };
        store.nodes.insert(NodePosition::ROOT, tree.root().unwrap());
        let mut indexes: Vec<u64> = (next_index..next_index + entries.len() as u64).collect();
        for entry in entries {
            let indexed = match tree.record(&entry.member).unwrap() {
                Some(indexed) => indexed,
                None => tree.low_record(&entry.member).unwrap(),
            };
            store.records.insert(indexed.record.member, indexed);
            indexes.push(indexed.index);
        }
        for index in indexes {
            for at in QuadPath::sibling_positions(index)
                .unwrap()
                .into_iter()
                .flatten()
            {
                if !at.is_empty(next_index) {
                    store.nodes.insert(at, tree.node(at).unwrap());
                }
            }
        }
        store
    }
}

impl RecordStore for PreloadedStore {
    type Error = RecordTreeError;

    fn next_index(&self) -> Result<u64, RecordTreeError> {
        Ok(self.next_index)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], RecordTreeError> {
        self.nodes
            .get(&at)
            .copied()
            .ok_or(RecordTreeError::NodeMissing {
                level: at.level,
                position: at.position,
            })
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), RecordTreeError> {
        self.nodes.insert(at, node);
        Ok(())
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, RecordTreeError> {
        Ok(self.records.get(member).copied())
    }

    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, RecordTreeError> {
        self.records
            .range(..*member)
            .next_back()
            .map(|(_, indexed)| *indexed)
            .ok_or(RecordTreeError::NotBracketed)
    }

    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), RecordTreeError> {
        self.next_index = self.next_index.max(index + 1);
        self.records
            .insert(record.member, IndexedRecord { index, record });
        Ok(())
    }
}

#[test]
fn a_store_preloaded_by_sibling_positions_applies_like_the_full_tree() {
    let mut tree = MemberRegistryTree::new().unwrap();
    let seeded: Vec<QueueEntry> = (1..=30).map(|byte| write(byte * 7, ALLOW, ALLOW)).collect();
    tree.apply([0; 32], &seeded).unwrap();
    let batch = [
        write(50, BLOCK, BLOCK),
        write(51, ALLOW, ALLOW),
        write(7, ALLOW, 0),
        escrow(52, 9),
        write(53, ALLOW, 0),
    ];
    let mut store = PreloadedStore::for_batch(&tree, &batch);
    let expected = tree.clone().apply([5; 32], &batch).unwrap();
    assert_eq!(store.apply([5; 32], &batch), Ok(expected));

    let mut short = PreloadedStore::for_batch(&tree, &batch);
    let low = tree.low_record(&batch[0].member).unwrap().index;
    let needed = QuadPath::sibling_positions(low).unwrap()[0][0];
    assert!(short.nodes.remove(&needed).is_some());
    assert!(matches!(
        short.apply([5; 32], &batch),
        Err(RecordTreeError::NodeMissing { .. })
    ));
}

#[test]
fn a_full_tree_applies_updates_and_no_ops_but_no_insert() {
    let sentinel = IndexedRecord {
        index: 0,
        record: MemberRecord {
            next: member(10),
            ..MemberRecord::SENTINEL
        },
    };
    let present = IndexedRecord {
        index: 5,
        record: MemberRecord {
            member: member(10),
            next: FIELD_MAX,
            lists: ALLOW,
            escrow_key: [0; 32],
        },
    };
    let mut full = PreloadedStore {
        next_index: MEMBER_REGISTRY_CAPACITY,
        ..PreloadedStore::default()
    };
    full.nodes.insert(NodePosition::ROOT, [2; 32]);
    for indexed in [sentinel, present] {
        full.records.insert(indexed.record.member, indexed);
        let positions = QuadPath::sibling_positions(indexed.index).unwrap();
        full.nodes
            .extend(positions.into_iter().flatten().map(|at| (at, [1; 32])));
    }
    let frozen = ListId::Frozen.record_bit();
    let inputs = full
        .apply([0; 32], &[write(10, BLOCK, BLOCK), write(7, frozen, 0)])
        .unwrap();
    assert!(inputs.writes[0].exists);
    let noop = inputs.writes[1];
    assert!(!noop.exists);
    assert_eq!(noop.slot, noop.low_path);
    assert_eq!(inputs.new_next_index, MEMBER_REGISTRY_CAPACITY);
    assert_eq!(
        full.apply([0; 32], &[write(7, frozen, frozen)]),
        Err(RecordTreeError::Full)
    );
}
