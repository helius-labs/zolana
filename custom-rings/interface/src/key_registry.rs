use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, HasherError, Poseidon,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{base_public_input::pack33_to_2fe, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};

/// Matches the circuit height and the on-chain tree.
pub const KEY_REGISTRY_HEIGHT: usize = 40;
pub const KEY_REGISTRY_CAPACITY: u64 = 1 << KEY_REGISTRY_HEIGHT;

/// Binds encrypted nullifier-key enrollment to the member, auditor and registry
/// transition.
pub struct RegisterKeyPublicInput<'a> {
    pub registry_old_root: &'a [u8; 32],
    pub registry_new_root: &'a [u8; 32],
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub new_index: u64,
}

impl RegisterKeyPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let auditor = pack33_to_2fe(self.auditor_pk);
        let eph = pack33_to_2fe(self.eph_pk);
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        create_hash_chain_from_slice(&[
            *self.registry_old_root,
            *self.registry_new_root,
            *self.member,
            *self.nullifier_pk,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            ct_hash,
            right_align(&self.new_index.to_be_bytes()),
        ])
    }
}

pub struct RegisteredKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl RegisteredKey<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        Poseidon::hashv(&[self.nullifier_pk, &ct_hash])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRegistryVerifyError {
    Hashing,
    ProofLength,
    OutOfRange,
    RootMismatch,
    SlotOccupied,
}

impl From<HasherError> for KeyRegistryVerifyError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

pub struct KeyRegistryLeaf<'a> {
    pub member: &'a [u8; 32],
    pub next: &'a [u8; 32],
    pub key: &'a [u8; 32],
}

impl KeyRegistryLeaf<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[self.member, self.next, self.key])
    }
}

/// Leaf position and sibling hashes reconstructing an indexed-tree root.
pub struct MerklePath<'a> {
    pub index: u64,
    pub siblings: &'a [[u8; 32]],
}

impl MerklePath<'_> {
    pub fn root_of(&self, leaf: [u8; 32]) -> Result<[u8; 32], KeyRegistryVerifyError> {
        self.check()?;
        let mut index = self.index;
        let mut node = leaf;
        for sibling in self.siblings {
            node = if index & 1 == 0 {
                Poseidon::hashv(&[&node[..], &sibling[..]])?
            } else {
                Poseidon::hashv(&[&sibling[..], &node[..]])?
            };
            index >>= 1;
        }
        Ok(node)
    }

    fn check(&self) -> Result<(), KeyRegistryVerifyError> {
        if self.siblings.len() != KEY_REGISTRY_HEIGHT {
            return Err(KeyRegistryVerifyError::ProofLength);
        }
        if self.index >= KEY_REGISTRY_CAPACITY {
            return Err(KeyRegistryVerifyError::OutOfRange);
        }
        Ok(())
    }
}

pub struct KeyRegistryInsert<'a> {
    pub root: &'a [u8; 32],
    pub append_index: u64,
    pub member: &'a [u8; 32],
    pub key: &'a [u8; 32],
    pub low_member: &'a [u8; 32],
    pub low_next: &'a [u8; 32],
    pub low_key: &'a [u8; 32],
    pub low_index: u64,
    pub low_proof: &'a [[u8; 32]],
    pub new_proof: &'a [[u8; 32]],
}

impl KeyRegistryInsert<'_> {
    /// `root` is not checked against chain state.
    pub fn verify(&self) -> Result<[u8; 32], KeyRegistryVerifyError> {
        // 1. Validate positions and canonical field encodings before hashing
        // the witness.
        let low_path = MerklePath {
            index: self.low_index,
            siblings: self.low_proof,
        };
        let new_path = MerklePath {
            index: self.append_index,
            siblings: self.new_proof,
        };
        low_path.check()?;
        new_path.check()?;
        // Slot 0 is the sentinel.
        if self.append_index == 0 {
            return Err(KeyRegistryVerifyError::OutOfRange);
        }
        if [
            self.root,
            self.member,
            self.key,
            self.low_member,
            self.low_next,
            self.low_key,
        ]
        .into_iter()
        .chain(self.low_proof)
        .chain(self.new_proof)
        .any(|field| !is_canonical_bn254_scalar_be(field))
        {
            return Err(KeyRegistryVerifyError::OutOfRange);
        }
        // 2. Prove the member absent inside an authenticated predecessor
        // interval.
        if !(self.low_member < self.member && self.member < self.low_next) {
            return Err(KeyRegistryVerifyError::OutOfRange);
        }
        let low_old = KeyRegistryLeaf {
            member: self.low_member,
            next: self.low_next,
            key: self.low_key,
        }
        .hash()?;
        if &low_path.root_of(low_old)? != self.root {
            return Err(KeyRegistryVerifyError::RootMismatch);
        }
        // 3. Splice the predecessor link and append only into a proven empty
        // slot.
        let low_new = KeyRegistryLeaf {
            member: self.low_member,
            next: self.member,
            key: self.low_key,
        }
        .hash()?;
        let spliced = low_path.root_of(low_new)?;
        let empty = Poseidon::zero_bytes()[0];
        if new_path.root_of(empty)? != spliced {
            return Err(KeyRegistryVerifyError::SlotOccupied);
        }
        let member_leaf = KeyRegistryLeaf {
            member: self.member,
            next: self.low_next,
            key: self.key,
        }
        .hash()?;
        new_path.root_of(member_leaf)
    }
}
