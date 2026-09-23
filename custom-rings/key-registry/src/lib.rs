//! Reconstructs key registry insertions against the root and append cursor stored on chain.

use custom_ring_interface::{KeyRegistryLeaf, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT};
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
pub enum KeyRegistryError {
    #[error("key registry hashing failed")]
    Hashing,
    #[error("key registry tree operation failed")]
    Tree,
    #[error("key registry is full")]
    Full,
    #[error("member falls outside the low element's range")]
    OutOfRange,
    #[error("member is already registered")]
    AlreadyRegistered,
    #[error("member is not registered")]
    Unregistered,
}

impl From<HasherError> for KeyRegistryError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

impl From<ReferenceMerkleTreeError> for KeyRegistryError {
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
    pub key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterProofInputs {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub member: [u8; 32],
    pub key: [u8; 32],
    pub low_member: [u8; 32],
    pub low_next: [u8; 32],
    pub low_key: [u8; 32],
    pub low_index: u64,
    pub low_proof: Vec<[u8; 32]>,
    pub new_index: u64,
    pub new_proof: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberOpening {
    pub next: [u8; 32],
    pub key: [u8; 32],
    pub index: u64,
    pub proof: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct KeyRegistryTree {
    tree: MerkleTree<Poseidon>,
    elements: Vec<IndexedKey>,
}

impl KeyRegistryTree {
    pub fn new() -> Result<Self, KeyRegistryError> {
        let mut tree = MerkleTree::<Poseidon>::new(KEY_REGISTRY_HEIGHT, 0);
        let sentinel = IndexedKey {
            index: 0,
            member: [0; 32],
            next: FIELD_MAX,
            key: [0; 32],
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

    /// Every fallible step runs before the first tree write.
    pub fn register(
        &mut self,
        registration: Registration,
    ) -> Result<RegisterProofInputs, KeyRegistryError> {
        let Registration { member, key } = registration;
        if self.elements.iter().any(|element| element.member == member) {
            return Err(KeyRegistryError::AlreadyRegistered);
        }
        let low_position = self.covering_element(&member)?;
        let new_index = self.elements.len();
        if new_index as u64 >= KEY_REGISTRY_CAPACITY {
            return Err(KeyRegistryError::Full);
        }
        let low = self.elements[low_position];
        let spliced = IndexedKey {
            next: member,
            ..low
        };
        let element = IndexedKey {
            index: new_index,
            member,
            next: low.next,
            key,
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
            key,
            low_member: low.member,
            low_next: low.next,
            low_key: low.key,
            low_index: low.index as u64,
            low_proof,
            new_index: new_index as u64,
            new_proof,
        })
    }

    pub fn member_proof(&self, member: &[u8; 32]) -> Result<MemberOpening, KeyRegistryError> {
        let element = self
            .elements
            .iter()
            .find(|element| &element.member == member)
            .ok_or(KeyRegistryError::Unregistered)?;
        Ok(MemberOpening {
            next: element.next,
            key: element.key,
            index: element.index as u64,
            proof: self.tree.get_proof_of_leaf(element.index, true)?,
        })
    }

    fn covering_element(&self, member: &[u8; 32]) -> Result<usize, KeyRegistryError> {
        self.elements
            .iter()
            // Canonical big-endian field elements sort by their byte order.
            .position(|element| element.member < *member && *member < element.next)
            .ok_or(KeyRegistryError::OutOfRange)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedKey {
    index: usize,
    member: [u8; 32],
    next: [u8; 32],
    key: [u8; 32],
}

impl IndexedKey {
    fn leaf(&self) -> Result<[u8; 32], HasherError> {
        KeyRegistryLeaf {
            member: &self.member,
            next: &self.next,
            key: &self.key,
        }
        .hash()
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{
        KeyRegistryInsert, KeyRegistryVerifyError, MerklePath, KEY_REGISTRY_EMPTY_ROOT,
    };

    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    fn registration(member_byte: u8, key_byte: u8) -> Registration {
        Registration {
            member: member(member_byte),
            key: member(key_byte),
        }
    }

    fn registered_key(tree: &KeyRegistryTree, member_byte: u8) -> Option<[u8; 32]> {
        tree.member_proof(&member(member_byte))
            .ok()
            .map(|opening| opening.key)
    }

    #[test]
    fn a_fresh_tree_is_the_pinned_empty_root() {
        let tree = KeyRegistryTree::new().expect("tree");
        assert_eq!(tree.root(), KEY_REGISTRY_EMPTY_ROOT);
        assert_eq!(registered_key(&tree, 0), Some([0; 32]));
    }

    #[test]
    fn registration_records_the_key_and_advances_the_root() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        let empty = tree.root();
        let inputs = tree.register(registration(5, 50)).expect("register");
        assert_eq!(inputs.old_root, empty);
        assert_eq!(inputs.new_root, tree.root());
        assert_ne!(tree.root(), empty);
        assert_eq!(registered_key(&tree, 5), Some(member(50)));
    }

    #[test]
    fn a_repeated_registration_is_refused() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        tree.register(registration(5, 50)).expect("register");
        assert_eq!(
            tree.register(registration(5, 51)),
            Err(KeyRegistryError::AlreadyRegistered)
        );
    }

    #[test]
    fn two_members_splice_the_sorted_list_in_order() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        tree.register(registration(9, 90)).expect("first");
        tree.register(registration(4, 40)).expect("second");
        assert_eq!(registered_key(&tree, 9), Some(member(90)));
        assert_eq!(registered_key(&tree, 4), Some(member(40)));
    }

    #[test]
    fn a_member_proof_opens_the_member_leaf_under_the_current_root() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        tree.register(registration(9, 90)).expect("first");
        tree.register(registration(4, 40)).expect("second");
        let opening = tree.member_proof(&member(4)).expect("member");
        let leaf = KeyRegistryLeaf {
            member: &member(4),
            next: &opening.next,
            key: &opening.key,
        }
        .hash()
        .expect("leaf");
        let path = MerklePath {
            index: opening.index,
            siblings: &opening.proof,
        };
        assert_eq!(path.root_of(leaf), Ok(tree.root()));
        assert_eq!(opening.next, member(9));
        assert_eq!(
            tree.member_proof(&member(7)),
            Err(KeyRegistryError::Unregistered)
        );
    }

    fn insert_of(inputs: &RegisterProofInputs) -> KeyRegistryInsert<'_> {
        KeyRegistryInsert {
            root: &inputs.old_root,
            append_index: inputs.new_index,
            member: &inputs.member,
            key: &inputs.key,
            low_member: &inputs.low_member,
            low_next: &inputs.low_next,
            low_key: &inputs.low_key,
            low_index: inputs.low_index,
            low_proof: &inputs.low_proof,
            new_proof: &inputs.new_proof,
        }
    }

    #[test]
    fn register_proof_inputs_reach_the_reference_root_on_chain() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        let first = tree.register(registration(4, 40)).expect("first");
        assert_eq!(insert_of(&first).verify(), Ok(first.new_root));
        let second = tree.register(registration(9, 90)).expect("second");
        assert_eq!(insert_of(&second).verify(), Ok(second.new_root));
    }

    #[test]
    fn an_out_of_range_member_is_refused_on_chain() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        let inputs = tree.register(registration(5, 50)).expect("register");
        let mut tampered = inputs.clone();
        tampered.member = [0; 32];
        assert_eq!(
            insert_of(&tampered).verify(),
            Err(KeyRegistryVerifyError::OutOfRange)
        );
    }

    #[test]
    fn failed_registration_does_not_splice_the_predecessor() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        tree.register(registration(5, 50)).expect("register");
        let before = tree.root();
        assert_eq!(
            tree.register(Registration {
                member: member(3),
                key: [0xff; 32],
            }),
            Err(KeyRegistryError::Hashing)
        );
        assert_eq!(tree.root(), before);
        assert_eq!(registered_key(&tree, 5), Some(member(50)));
        assert_eq!(registered_key(&tree, 3), None);
        let inputs = tree.register(registration(3, 30)).expect("retry");
        assert_eq!(inputs.old_root, before);
        assert_eq!(insert_of(&inputs).verify(), Ok(tree.root()));
    }

    #[test]
    fn a_stale_root_or_wrong_proof_length_is_refused_on_chain() {
        let mut tree = KeyRegistryTree::new().expect("tree");
        let register = tree.register(registration(5, 50)).expect("register");

        let mut stale = register.clone();
        stale.old_root = [9; 32];
        assert_eq!(
            insert_of(&stale).verify(),
            Err(KeyRegistryVerifyError::RootMismatch)
        );

        let mut short = register.clone();
        short.low_proof.pop();
        assert_eq!(
            insert_of(&short).verify(),
            Err(KeyRegistryVerifyError::ProofLength)
        );

        let mut occupied = register.clone();
        occupied.new_proof[0] = [7; 32];
        assert_eq!(
            insert_of(&occupied).verify(),
            Err(KeyRegistryVerifyError::SlotOccupied)
        );
    }
}
