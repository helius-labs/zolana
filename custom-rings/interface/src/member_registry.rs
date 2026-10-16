//! The member registry, an indexed Merkle tree keyed by owner tag. Each record carries
//! the member's list bitmap and, when the ring escrows keys, its sealed nullifier key.

use thiserror::Error;
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{is_canonical_bn254_scalar_be, right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, HasherError, Poseidon,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{instruction::MemberUpdate, pack_2fe, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};

/// Matches the circuit height and the on-chain tree.
pub const MEMBER_REGISTRY_HEIGHT: usize = 20;
pub const MEMBER_REGISTRY_CAPACITY: u64 = 1 << MEMBER_REGISTRY_HEIGHT;
/// Items one update proof rewrites, a circuit width.
pub const MAX_MEMBER_BATCH: usize = 16;
/// Curator registries one policy reads, a circuit width.
pub const N_FOREIGN: usize = zolana_ring_policy::N_FOREIGN;

/// BN254 scalar field order minus one, the sentinel high member closing the list.
pub const FIELD_MAX: [u8; 32] = {
    let mut max = BN254_SCALAR_MODULUS_BE;
    max[31] -= 1;
    max
};

/// Root of the sentinel-only registry, the value a fresh registry initializes to.
pub const MEMBER_REGISTRY_EMPTY_ROOT: [u8; 32] = [
    0x27, 0x47, 0x2d, 0x6d, 0x13, 0x03, 0x74, 0x8e, 0x81, 0x79, 0x95, 0x7c, 0xa7, 0xc4, 0x14, 0x99,
    0xa1, 0x35, 0x16, 0xf1, 0x56, 0x08, 0x8e, 0x45, 0x50, 0xb9, 0x69, 0xf2, 0x50, 0x9a, 0xf2, 0x1c,
];

/// One leaf, `Poseidon(member, next, lists, escrow_key)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    /// Bit `i` marks list id `i + 1`.
    pub lists: u64,
    /// `EscrowKey::hash`, zero until the member registers a key.
    pub escrow_key: [u8; 32],
}

impl MemberRecord {
    /// Leaf 0, every member sorts between it and `FIELD_MAX`.
    pub const SENTINEL: Self = Self {
        member: [0; 32],
        next: FIELD_MAX,
        lists: 0,
        escrow_key: [0; 32],
    };

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &self.member,
            &self.next,
            &right_align(&self.lists.to_be_bytes()),
            &self.escrow_key,
        ])
    }
}

/// The record field a registered key sets, `Poseidon(nullifier_pk, ct_hash)`.
pub struct EscrowKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl EscrowKey<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        Poseidon::hashv(&[self.nullifier_pk, &ct_hash])
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MemberRegistryVerifyError {
    #[error("member registry hashing failed")]
    Hashing,
    #[error("member registry path has the wrong length")]
    PathLength,
    #[error("member registry index or field is out of range")]
    OutOfRange,
    #[error("member registry path does not reach the root")]
    RootMismatch,
    #[error("the low record does not bracket the member")]
    NotBracketed,
}

impl From<HasherError> for MemberRegistryVerifyError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

/// Leaf position and sibling hashes reconstructing a root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerklePath<'a> {
    pub index: u64,
    pub siblings: &'a [[u8; 32]],
}

impl MerklePath<'_> {
    pub fn root_of(&self, leaf: [u8; 32]) -> Result<[u8; 32], MemberRegistryVerifyError> {
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

    fn check(&self) -> Result<(), MemberRegistryVerifyError> {
        if self.siblings.len() != MEMBER_REGISTRY_HEIGHT {
            return Err(MemberRegistryVerifyError::PathLength);
        }
        if self.index >= MEMBER_REGISTRY_CAPACITY {
            return Err(MemberRegistryVerifyError::OutOfRange);
        }
        if self
            .siblings
            .iter()
            .any(|s| !is_canonical_bn254_scalar_be(s))
        {
            return Err(MemberRegistryVerifyError::OutOfRange);
        }
        Ok(())
    }
}

/// A member's state under one root, the record itself or the low record bracketing an absent member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberOpening<'a> {
    Present {
        record: MemberRecord,
        path: MerklePath<'a>,
    },
    Absent {
        low: MemberRecord,
        path: MerklePath<'a>,
    },
}

impl MemberOpening<'_> {
    /// The lists and escrow key of `member` under `root`, zero when absent.
    pub fn verify(
        &self,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<(u64, [u8; 32]), MemberRegistryVerifyError> {
        let (leaf, path, resolved) = match self {
            Self::Present { record, path } => {
                if record.member != *member {
                    return Err(MemberRegistryVerifyError::NotBracketed);
                }
                (*record, *path, (record.lists, record.escrow_key))
            }
            Self::Absent { low, path } => {
                if !(low.member < *member && *member < low.next) {
                    return Err(MemberRegistryVerifyError::NotBracketed);
                }
                (*low, *path, (0, [0; 32]))
            }
        };
        for field in [&leaf.member, &leaf.next, &leaf.escrow_key, member] {
            if !is_canonical_bn254_scalar_be(field) {
                return Err(MemberRegistryVerifyError::OutOfRange);
            }
        }
        if path.root_of(leaf.hash()?)? != *root {
            return Err(MemberRegistryVerifyError::RootMismatch);
        }
        Ok(resolved)
    }
}

/// Binds encrypted nullifier-key enrollment to the member, auditor and registry transition.
pub struct RegisterKeyPublicInput<'a> {
    pub registry_old_root: &'a [u8; 32],
    pub registry_new_root: &'a [u8; 32],
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    /// The member's record index, the append slot on a first registration.
    pub index: u64,
}

impl RegisterKeyPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let auditor = pack_2fe(self.auditor_pk);
        let eph = pack_2fe(self.eph_pk);
        create_hash_chain_from_slice(&[
            *self.registry_old_root,
            *self.registry_new_root,
            *self.member,
            *self.nullifier_pk,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            ciphertext_hash(self.ciphertext)?,
            right_align(&self.index.to_be_bytes()),
        ])
    }
}

/// Binds a batch of record rewrites to the registry transition, items past the count hash as zeros.
pub struct UpdateMembersPublicInput<'a> {
    pub old_root: &'a [u8; 32],
    pub new_root: &'a [u8; 32],
    pub items: &'a [MemberUpdate],
}

impl UpdateMembersPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        if !(1..=MAX_MEMBER_BATCH).contains(&self.items.len()) {
            return Err(HasherError::InvalidNumFields);
        }
        let mut items = [[0u8; 32]; 1 + MAX_MEMBER_BATCH * 6];
        items[0] = right_align(&(self.items.len() as u64).to_be_bytes());
        for (slot, item) in self.items.iter().enumerate() {
            items[1 + slot * 6..7 + slot * 6].copy_from_slice(&[
                item.member,
                right_align(&item.old_lists.to_be_bytes()),
                item.old_escrow_key,
                right_align(&item.lists.to_be_bytes()),
                item.escrow_key,
                right_align(&item.index.to_be_bytes()),
            ]);
        }
        create_hash_chain_from_slice(&[
            *self.old_root,
            *self.new_root,
            create_hash_chain_from_slice(&items)?,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_root_is_the_sentinel_under_zero_siblings() {
        let zero = Poseidon::zero_bytes();
        let path = MerklePath {
            index: 0,
            siblings: &zero[..MEMBER_REGISTRY_HEIGHT],
        };
        assert_eq!(
            path.root_of(MemberRecord::SENTINEL.hash().unwrap()),
            Ok(MEMBER_REGISTRY_EMPTY_ROOT)
        );
    }

    #[test]
    fn the_batch_statement_takes_one_to_sixteen_items() {
        let item = MemberUpdate {
            member: right_align(&[1]),
            old_lists: 0,
            old_escrow_key: [0; 32],
            lists: 1,
            escrow_key: [0; 32],
            index: 1,
        };
        let input = UpdateMembersPublicInput {
            old_root: &[1; 32],
            new_root: &[2; 32],
            items: &[],
        };
        assert_eq!(input.hash(), Err(HasherError::InvalidNumFields));
        let full = vec![item; MAX_MEMBER_BATCH];
        assert!(UpdateMembersPublicInput {
            items: &full,
            ..input
        }
        .hash()
        .is_ok());
        let over = vec![item; MAX_MEMBER_BATCH + 1];
        assert_eq!(
            UpdateMembersPublicInput {
                items: &over,
                ..input
            }
            .hash(),
            Err(HasherError::InvalidNumFields)
        );
    }
}
