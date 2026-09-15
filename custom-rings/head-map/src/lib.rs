//! Reconstructs member head transitions against the root and append cursor stored on chain.

use custom_ring_interface::{HeadMapLeaf, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT};
use thiserror::Error;
use zolana_hasher::{primitives::BN254_SCALAR_MODULUS_BE, HasherError, Poseidon};
use zolana_merkle_tree::{MerkleTree, ReferenceMerkleTreeError};

/// BN254 scalar field order minus one, the sentinel high member closing the list.
pub const FIELD_MAX: [u8; 32] = {
    let mut max = BN254_SCALAR_MODULUS_BE;
    max[31] -= 1;
    max
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeadMapError {
    #[error("head map hashing failed")]
    Hashing,
    #[error("head map tree operation failed")]
    Tree,
    #[error("head map is full")]
    Full,
    #[error("member falls outside the low element's range")]
    OutOfRange,
    #[error("member is already registered")]
    AlreadyRegistered,
    #[error("member is not registered")]
    Unregistered,
    #[error("the consumed nullifier is not the member's head")]
    HeadMismatch,
}

impl From<HasherError> for HeadMapError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

impl From<ReferenceMerkleTreeError> for HeadMapError {
    fn from(error: ReferenceMerkleTreeError) -> Self {
        match error {
            ReferenceMerkleTreeError::Hasher(_) => Self::Hashing,
            _ => Self::Tree,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    pub member: [u8; 32],
    pub genesis: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadTransfer {
    pub member: [u8; 32],
    pub spent: [u8; 32],
    pub successor: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterProofInputs {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProofInputs {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub member: [u8; 32],
    pub next: [u8; 32],
    pub spent: [u8; 32],
    pub successor: [u8; 32],
    pub index: u64,
    pub proof: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct HeadMap {
    tree: MerkleTree<Poseidon>,
    elements: Vec<IndexedHead>,
}

impl HeadMap {
    pub fn new() -> Result<Self, HeadMapError> {
        let mut tree = MerkleTree::<Poseidon>::new(HEAD_MAP_HEIGHT, 0);
        let sentinel = IndexedHead {
            index: 0,
            member: [0; 32],
            next: FIELD_MAX,
            nullifier: [0; 32],
        };
        tree.append(&sentinel.leaf()?)?;
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

    /// Every fallible step runs before the first tree write.
    pub fn register(
        &mut self,
        registration: Registration,
    ) -> Result<RegisterProofInputs, HeadMapError> {
        let Registration { member, genesis } = registration;
        if self.elements.iter().any(|element| element.member == member) {
            return Err(HeadMapError::AlreadyRegistered);
        }
        let low_position = self.covering_element(&member)?;
        let new_index = self.elements.len();
        if new_index as u64 >= HEAD_MAP_CAPACITY {
            return Err(HeadMapError::Full);
        }
        let low = self.elements[low_position];
        let spliced = IndexedHead {
            next: member,
            ..low
        };
        let element = IndexedHead {
            index: new_index,
            member,
            next: low.next,
            nullifier: genesis,
        };
        let spliced_leaf = spliced.leaf()?;
        let element_leaf = element.leaf()?;

        let old_root = self.tree.root();
        let low_proof = self.tree.get_proof_of_leaf(low.index, true)?;
        self.tree.update(&spliced_leaf, low.index)?;
        self.elements[low_position].next = member;
        let new_proof = self.tree.get_proof_of_leaf(new_index, true)?;
        self.tree.append(&element_leaf)?;
        self.elements.push(element);

        Ok(RegisterProofInputs {
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
        transfer: HeadTransfer,
    ) -> Result<TransferProofInputs, HeadMapError> {
        let HeadTransfer {
            member,
            spent,
            successor,
        } = transfer;
        let position = self
            .elements
            .iter()
            .position(|element| element.member == member)
            .ok_or(HeadMapError::Unregistered)?;
        let element = self.elements[position];
        if element.nullifier != spent {
            return Err(HeadMapError::HeadMismatch);
        }
        let updated = IndexedHead {
            nullifier: successor,
            ..element
        };
        let updated_leaf = updated.leaf()?;

        let old_root = self.tree.root();
        let proof = self.tree.get_proof_of_leaf(element.index, true)?;
        self.tree.update(&updated_leaf, element.index)?;
        self.elements[position].nullifier = successor;

        Ok(TransferProofInputs {
            old_root,
            new_root: self.tree.root(),
            member,
            next: element.next,
            spent,
            successor,
            index: element.index as u64,
            proof,
        })
    }

    fn covering_element(&self, member: &[u8; 32]) -> Result<usize, HeadMapError> {
        self.elements
            .iter()
            // Canonical big-endian field elements sort by their byte order.
            .position(|element| element.member < *member && *member < element.next)
            .ok_or(HeadMapError::OutOfRange)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedHead {
    index: usize,
    member: [u8; 32],
    next: [u8; 32],
    nullifier: [u8; 32],
}

impl IndexedHead {
    fn leaf(&self) -> Result<[u8; 32], HasherError> {
        HeadMapLeaf {
            member: &self.member,
            next: &self.next,
            nullifier: &self.nullifier,
        }
        .hash()
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{
        HeadMapInsert, HeadMapTransfer, HeadMapVerifyError, HEAD_MAP_EMPTY_ROOT,
    };

    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    fn registration(member_byte: u8, genesis_byte: u8) -> Registration {
        Registration {
            member: member(member_byte),
            genesis: member(genesis_byte),
        }
    }

    fn head_transfer(member_byte: u8, spent_byte: u8, successor_byte: u8) -> HeadTransfer {
        HeadTransfer {
            member: member(member_byte),
            spent: member(spent_byte),
            successor: member(successor_byte),
        }
    }

    #[test]
    fn a_fresh_map_is_the_pinned_empty_root() {
        let map = HeadMap::new().expect("map");
        assert_eq!(map.root(), HEAD_MAP_EMPTY_ROOT);
        assert_eq!(map.head(&[0; 32]), Some([0; 32]));
    }

    #[test]
    fn registration_records_the_genesis_and_advances_the_root() {
        let mut map = HeadMap::new().expect("map");
        let empty = map.root();
        let inputs = map.register(registration(5, 50)).expect("register");
        assert_eq!(inputs.old_root, empty);
        assert_eq!(inputs.new_root, map.root());
        assert_ne!(map.root(), empty);
        assert_eq!(map.head(&member(5)), Some(member(50)));
    }

    #[test]
    fn a_repeated_registration_is_refused() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(5, 50)).expect("register");
        assert_eq!(
            map.register(registration(5, 51)),
            Err(HeadMapError::AlreadyRegistered)
        );
    }

    #[test]
    fn two_members_splice_the_sorted_list_in_order() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(9, 90)).expect("first");
        map.register(registration(4, 40)).expect("second");
        assert_eq!(map.head(&member(9)), Some(member(90)));
        assert_eq!(map.head(&member(4)), Some(member(40)));
    }

    #[test]
    fn a_transfer_advances_only_the_member_head() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(5, 50)).expect("register");
        let before = map.root();
        let inputs = map.transfer(head_transfer(5, 50, 51)).expect("transfer");
        assert_eq!(inputs.old_root, before);
        assert_eq!(inputs.new_root, map.root());
        assert_eq!(map.head(&member(5)), Some(member(51)));
    }

    #[test]
    fn a_transfer_off_the_head_or_an_unregistered_member_is_refused() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(5, 50)).expect("register");
        assert_eq!(
            map.transfer(head_transfer(5, 99, 51)),
            Err(HeadMapError::HeadMismatch)
        );
        assert_eq!(
            map.transfer(head_transfer(7, 70, 71)),
            Err(HeadMapError::Unregistered)
        );
    }

    fn insert_of(inputs: &RegisterProofInputs) -> HeadMapInsert<'_> {
        HeadMapInsert {
            root: &inputs.old_root,
            append_index: inputs.new_index,
            member: &inputs.member,
            genesis: &inputs.genesis,
            low_member: &inputs.low_member,
            low_next: &inputs.low_next,
            low_nullifier: &inputs.low_nullifier,
            low_index: inputs.low_index,
            low_proof: &inputs.low_proof,
            new_proof: &inputs.new_proof,
        }
    }

    #[test]
    fn register_proof_inputs_reach_the_reference_root_on_chain() {
        let mut map = HeadMap::new().expect("map");
        let first = map.register(registration(4, 40)).expect("first");
        assert_eq!(insert_of(&first).verify(), Ok(first.new_root));
        let second = map.register(registration(9, 90)).expect("second");
        assert_eq!(insert_of(&second).verify(), Ok(second.new_root));
    }

    #[test]
    fn an_out_of_range_member_is_refused_on_chain() {
        let mut map = HeadMap::new().expect("map");
        let inputs = map.register(registration(5, 50)).expect("register");
        let mut tampered = inputs.clone();
        tampered.member = [0; 32];
        assert_eq!(
            insert_of(&tampered).verify(),
            Err(HeadMapVerifyError::OutOfRange)
        );
    }

    fn transfer_of(inputs: &TransferProofInputs) -> HeadMapTransfer<'_> {
        HeadMapTransfer {
            root: &inputs.old_root,
            member: &inputs.member,
            next: &inputs.next,
            spent: &inputs.spent,
            successor: &inputs.successor,
            index: inputs.index,
            proof: &inputs.proof,
        }
    }

    #[test]
    fn transfer_proof_inputs_reach_the_reference_root() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(5, 50)).expect("register");
        let inputs = map.transfer(head_transfer(5, 50, 51)).expect("transfer");
        assert_eq!(transfer_of(&inputs).verify(), Ok(inputs.new_root));
    }

    #[test]
    fn failed_registration_does_not_splice_the_predecessor() {
        let mut map = HeadMap::new().expect("map");
        map.register(registration(5, 50)).expect("register");
        let before = map.root();
        assert_eq!(
            map.register(Registration {
                member: member(3),
                genesis: [0xff; 32],
            }),
            Err(HeadMapError::Hashing)
        );
        assert_eq!(map.root(), before);
        assert_eq!(map.head(&member(5)), Some(member(50)));
        assert_eq!(map.head(&member(3)), None);
        let inputs = map.register(registration(3, 30)).expect("retry");
        assert_eq!(inputs.old_root, before);
        assert_eq!(insert_of(&inputs).verify(), Ok(map.root()));
    }

    #[test]
    fn a_stale_root_or_wrong_proof_length_is_refused_on_chain() {
        let mut map = HeadMap::new().expect("map");
        let register = map.register(registration(5, 50)).expect("register");
        let transfer = map.transfer(head_transfer(5, 50, 51)).expect("transfer");

        let mut stale = register.clone();
        stale.old_root = [9; 32];
        assert_eq!(
            insert_of(&stale).verify(),
            Err(HeadMapVerifyError::RootMismatch)
        );

        let mut short = register.clone();
        short.low_proof.pop();
        assert_eq!(
            insert_of(&short).verify(),
            Err(HeadMapVerifyError::ProofLength)
        );

        let mut occupied = register.clone();
        occupied.new_proof[0] = [7; 32];
        assert_eq!(
            insert_of(&occupied).verify(),
            Err(HeadMapVerifyError::SlotOccupied)
        );

        let mut stale_transfer = transfer.clone();
        stale_transfer.old_root = [9; 32];
        assert_eq!(
            transfer_of(&stale_transfer).verify(),
            Err(HeadMapVerifyError::RootMismatch)
        );

        let mut wrong_spent = transfer.clone();
        wrong_spent.spent = wrong_spent.successor;
        assert_eq!(
            transfer_of(&wrong_spent).verify(),
            Err(HeadMapVerifyError::RootMismatch)
        );
    }
}
