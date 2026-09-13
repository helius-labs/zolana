//! The member -> current-record-nullifier map, an indexed Merkle tree whose leaf
//! is `Poseidon(member, next_member, nullifier)`. Registration proves a member
//! absent between a low element and its successor and inserts the member's
//! genesis record, a transfer replaces the member's nullifier with its successor.
//! Off chain the whole tree lives here, on chain only the root, advanced in
//! lockstep with the SPP transfer against the exact current root. The circuit,
//! the program and the clients all agree with this reference.

use thiserror::Error;
use zolana_hasher::Poseidon;
use zolana_merkle_tree::MerkleTree;

/// BN254 scalar field order minus one, the sentinel high member closing the list.
pub const FIELD_MAX: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

/// The root of the sentinel-only tree, the value a ring's head map initializes to.
pub use custom_ring_interface::HEAD_MAP_EMPTY_ROOT as EMPTY_ROOT;
pub use custom_ring_interface::{head_map_leaf, HEAD_MAP_HEIGHT};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeadMapError {
    #[error("head map hashing failed")]
    Hashing,
    #[error("head map tree operation failed")]
    Tree,
    #[error("member falls outside the low element's range")]
    OutOfRange,
    #[error("member is already registered")]
    AlreadyRegistered,
    #[error("member is not registered")]
    Unregistered,
    #[error("the consumed nullifier is not the member's head")]
    HeadMismatch,
}

/// One sorted-list element, ordered by `member`, `next` points at the successor member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Element {
    index: usize,
    member: [u8; 32],
    next: [u8; 32],
    nullifier: [u8; 32],
}

impl Element {
    fn leaf(&self) -> Result<[u8; 32], HeadMapError> {
        head_map_leaf(&self.member, &self.next, &self.nullifier).map_err(|_| HeadMapError::Hashing)
    }
}

/// Proves the member absent under `old_root` and inserts its genesis, yielding `new_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterWitness {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub member: [u8; 32],
    pub genesis: [u8; 32],
    pub low_member: [u8; 32],
    pub low_next: [u8; 32],
    pub low_nullifier: [u8; 32],
    pub low_index: u64,
    pub low_proof: Vec<[u8; 32]>,
    pub new_index: u64,
    pub new_proof: Vec<[u8; 32]>,
}

/// Proves the member's leaf holds `spent` under `old_root` and writes `successor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferWitness {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub member: [u8; 32],
    pub next: [u8; 32],
    pub spent: [u8; 32],
    pub successor: [u8; 32],
    pub index: u64,
    pub proof: Vec<[u8; 32]>,
}

/// The off-chain reference tree, its root is the only on-chain state.
#[derive(Clone)]
pub struct HeadMap {
    tree: MerkleTree<Poseidon>,
    elements: Vec<Element>,
}

impl HeadMap {
    /// A fresh map holding only the sentinel element `member 0 -> next FIELD_MAX`.
    pub fn new() -> Result<Self, HeadMapError> {
        let mut tree = MerkleTree::<Poseidon>::new(HEAD_MAP_HEIGHT, 0);
        let sentinel = Element {
            index: 0,
            member: [0; 32],
            next: FIELD_MAX,
            nullifier: [0; 32],
        };
        tree.append(&sentinel.leaf()?)
            .map_err(|_| HeadMapError::Tree)?;
        Ok(Self {
            tree,
            elements: vec![sentinel],
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// The current nullifier of a registered member.
    pub fn head(&self, member: &[u8; 32]) -> Option<[u8; 32]> {
        self.elements
            .iter()
            .find(|element| &element.member == member)
            .map(|element| element.nullifier)
    }

    /// Splices the covering low element and appends the member's genesis.
    pub fn register(
        &mut self,
        member: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<RegisterWitness, HeadMapError> {
        let mut staged = self.clone();
        let witness = staged.register_inner(member, genesis)?;
        *self = staged;
        Ok(witness)
    }

    fn register_inner(
        &mut self,
        member: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<RegisterWitness, HeadMapError> {
        if self.elements.iter().any(|element| element.member == member) {
            return Err(HeadMapError::AlreadyRegistered);
        }
        let low_position = self.covering_element(&member)?;
        let low = self.elements[low_position];
        let old_root = self.tree.root();
        let low_proof = self
            .tree
            .get_proof_of_leaf(low.index, true)
            .map_err(|_| HeadMapError::Tree)?;

        // The low element's successor pointer swings to the new member.
        let spliced = Element {
            next: member,
            ..low
        };
        self.tree
            .update(&spliced.leaf()?, low.index)
            .map_err(|_| HeadMapError::Tree)?;
        self.elements[low_position].next = member;

        // The new element lands at the append cursor, proven against the empty leaf.
        let new_index = self.elements.len();
        let new_proof = self
            .tree
            .get_proof_of_leaf(new_index, true)
            .map_err(|_| HeadMapError::Tree)?;
        let element = Element {
            index: new_index,
            member,
            next: low.next,
            nullifier: genesis,
        };
        self.tree
            .append(&element.leaf()?)
            .map_err(|_| HeadMapError::Tree)?;
        self.elements.push(element);

        Ok(RegisterWitness {
            old_root,
            new_root: self.tree.root(),
            member,
            genesis,
            low_member: low.member,
            low_next: low.next,
            low_nullifier: low.nullifier,
            low_index: low.index as u64,
            low_proof,
            new_index: new_index as u64,
            new_proof,
        })
    }

    /// The successor pointer stays fixed, only the nullifier advances.
    pub fn transfer(
        &mut self,
        member: &[u8; 32],
        spent: &[u8; 32],
        successor: [u8; 32],
    ) -> Result<TransferWitness, HeadMapError> {
        let position = self
            .elements
            .iter()
            .position(|element| &element.member == member)
            .ok_or(HeadMapError::Unregistered)?;
        let element = self.elements[position];
        if &element.nullifier != spent {
            return Err(HeadMapError::HeadMismatch);
        }
        let old_root = self.tree.root();
        let proof = self
            .tree
            .get_proof_of_leaf(element.index, true)
            .map_err(|_| HeadMapError::Tree)?;
        let updated = Element {
            nullifier: successor,
            ..element
        };
        self.tree
            .update(&updated.leaf()?, element.index)
            .map_err(|_| HeadMapError::Tree)?;
        self.elements[position].nullifier = successor;

        Ok(TransferWitness {
            old_root,
            new_root: self.tree.root(),
            member: *member,
            next: element.next,
            spent: *spent,
            successor,
            index: element.index as u64,
            proof,
        })
    }

    /// The element whose half-open range `[member, next)` covers `member`.
    fn covering_element(&self, member: &[u8; 32]) -> Result<usize, HeadMapError> {
        self.elements
            .iter()
            .position(|element| less(&element.member, member) && less(member, &element.next))
            .ok_or(HeadMapError::OutOfRange)
    }
}

/// Canonical big-endian field elements sort by their byte order.
fn less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    #[test]
    fn a_fresh_map_is_the_pinned_empty_root() {
        let map = HeadMap::new().expect("map");
        assert_eq!(map.root(), EMPTY_ROOT);
        assert_eq!(map.head(&[0; 32]), Some([0; 32]));
    }

    #[test]
    fn registration_records_the_genesis_and_advances_the_root() {
        let mut map = HeadMap::new().expect("map");
        let empty = map.root();
        let witness = map.register(member(5), member(50)).expect("register");
        assert_eq!(witness.old_root, empty);
        assert_eq!(witness.new_root, map.root());
        assert_ne!(map.root(), empty);
        assert_eq!(map.head(&member(5)), Some(member(50)));
    }

    #[test]
    fn a_repeated_registration_is_refused() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(5), member(50)).expect("register");
        assert_eq!(
            map.register(member(5), member(51)),
            Err(HeadMapError::AlreadyRegistered)
        );
    }

    #[test]
    fn two_members_splice_the_sorted_list_in_order() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(9), member(90)).expect("first");
        // The second member falls between the sentinel and the first, covered by the sentinel.
        map.register(member(4), member(40)).expect("second");
        assert_eq!(map.head(&member(9)), Some(member(90)));
        assert_eq!(map.head(&member(4)), Some(member(40)));
    }

    #[test]
    fn a_transfer_advances_only_the_member_head() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(5), member(50)).expect("register");
        let before = map.root();
        let witness = map
            .transfer(&member(5), &member(50), member(51))
            .expect("transfer");
        assert_eq!(witness.old_root, before);
        assert_eq!(witness.new_root, map.root());
        assert_eq!(map.head(&member(5)), Some(member(51)));
    }

    #[test]
    fn a_transfer_off_the_head_or_an_unregistered_member_is_refused() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(5), member(50)).expect("register");
        assert_eq!(
            map.transfer(&member(5), &member(99), member(51)),
            Err(HeadMapError::HeadMismatch)
        );
        assert_eq!(
            map.transfer(&member(7), &member(70), member(71)),
            Err(HeadMapError::Unregistered)
        );
    }

    fn insert_of(witness: &RegisterWitness) -> custom_ring_interface::HeadMapInsert<'_> {
        custom_ring_interface::HeadMapInsert {
            root: &witness.old_root,
            append_index: witness.new_index,
            member: &witness.member,
            genesis: &witness.genesis,
            low_member: &witness.low_member,
            low_next: &witness.low_next,
            low_nullifier: &witness.low_nullifier,
            low_index: witness.low_index,
            low_proof: &witness.low_proof,
            new_proof: &witness.new_proof,
        }
    }

    #[test]
    fn register_witnesses_reach_the_reference_root_on_chain() {
        let mut map = HeadMap::new().expect("map");
        let first = map.register(member(4), member(40)).expect("first");
        assert_eq!(insert_of(&first).verify(), Ok(first.new_root));
        // The second member's low element is a real member, not the sentinel.
        let second = map.register(member(9), member(90)).expect("second");
        assert_eq!(insert_of(&second).verify(), Ok(second.new_root));
    }

    #[test]
    fn an_out_of_range_member_is_refused_on_chain() {
        let mut map = HeadMap::new().expect("map");
        let witness = map.register(member(5), member(50)).expect("register");
        let mut tampered = witness.clone();
        tampered.member = [0; 32];
        assert_eq!(
            insert_of(&tampered).verify(),
            Err(custom_ring_interface::HeadMapError::OutOfRange)
        );
    }

    fn transfer_of(witness: &TransferWitness) -> custom_ring_interface::HeadMapTransfer<'_> {
        custom_ring_interface::HeadMapTransfer {
            root: &witness.old_root,
            member: &witness.member,
            next: &witness.next,
            spent: &witness.spent,
            successor: &witness.successor,
            index: witness.index,
            proof: &witness.proof,
        }
    }

    #[test]
    fn transfer_witnesses_reach_the_reference_root() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(5), member(50)).expect("register");
        let witness = map
            .transfer(&member(5), &member(50), member(51))
            .expect("transfer");
        assert_eq!(transfer_of(&witness).verify(), Ok(witness.new_root));
    }

    #[test]
    fn failed_registration_does_not_splice_the_predecessor() {
        let mut map = HeadMap::new().expect("map");
        map.register(member(5), member(50)).expect("register");
        let before = map.root();
        assert_eq!(
            map.register(member(3), [0xff; 32]),
            Err(HeadMapError::Hashing)
        );
        assert_eq!(map.root(), before);
        assert_eq!(map.head(&member(5)), Some(member(50)));
        assert_eq!(map.head(&member(3)), None);
        let witness = map.register(member(3), member(30)).expect("retry");
        assert_eq!(witness.old_root, before);
        assert_eq!(insert_of(&witness).verify(), Ok(map.root()));
    }

    #[test]
    fn a_stale_root_or_wrong_proof_length_is_refused_on_chain() {
        use custom_ring_interface::HeadMapError;
        let mut map = HeadMap::new().expect("map");
        let register = map.register(member(5), member(50)).expect("register");
        let transfer = map
            .transfer(&member(5), &member(50), member(51))
            .expect("transfer");

        let mut stale = register.clone();
        stale.old_root = [9; 32];
        assert_eq!(insert_of(&stale).verify(), Err(HeadMapError::RootMismatch));

        let mut short = register.clone();
        short.low_proof.pop();
        assert_eq!(insert_of(&short).verify(), Err(HeadMapError::ProofLength));

        let mut occupied = register.clone();
        occupied.new_proof[0] = [7; 32];
        assert_eq!(
            insert_of(&occupied).verify(),
            Err(HeadMapError::SlotOccupied)
        );

        let mut stale_transfer = transfer.clone();
        stale_transfer.old_root = [9; 32];
        assert_eq!(
            transfer_of(&stale_transfer).verify(),
            Err(HeadMapError::RootMismatch)
        );

        // A successor swapped in for the consumed leaf no longer opens the root.
        let mut wrong_spent = transfer.clone();
        wrong_spent.spent = wrong_spent.successor;
        assert_eq!(
            transfer_of(&wrong_spent).verify(),
            Err(HeadMapError::RootMismatch)
        );
    }
}
