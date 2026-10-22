//! Record tree constants and the queued record writes the program chains, the tree
//! lives in `zolana-ring-member-registry`.

use zolana_hasher::{
    primitives::{hash_bytes, right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, HasherError, Poseidon,
};
use zolana_ring_policy::ListId;

use crate::{domain, error::CustomRingError, AUDIT_CIPHERTEXT_LEN};

pub const QUAD_ARITY: usize = 4;
pub const QUAD_HEIGHT: usize = 10;
pub const MEMBER_REGISTRY_CAPACITY: u64 = 1 << (2 * QUAD_HEIGHT);
/// Writes the larger apply key proves.
pub const APPLY_BATCH: usize = 16;
/// Member writes pending at once, the rest of a batch is the authority's reserve.
pub const MEMBER_QUEUE_LIMIT: u64 = 8;
/// The last leaves, kept for authority writes once members fill the rest.
pub const AUTHORITY_RESERVED_LEAVES: u64 = 1 << 16;
/// The insert fee of a new ring, enough to open an empty authority account.
pub const DEFAULT_INSERT_FEE: u64 = 1_000_000;
pub const QUEUE_CAPACITY: usize = APPLY_BATCH;
/// Slots before anyone applies a partial queue, and between two permissionless applications.
pub const APPLY_DELAY_SLOTS: u64 = 150;
/// Slots a curator root below the floor stays admissible after the floor rose.
pub const GRACE_SLOTS: u64 = 750;

/// `q - 1`, the sentinel's next, every member sorts strictly below it.
pub const FIELD_MAX: [u8; 32] = {
    let mut max = BN254_SCALAR_MODULUS_BE;
    max[31] -= 1;
    max
};

/// Root of the tree holding only the sentinel, the first history entry of a registry.
pub const MEMBER_REGISTRY_EMPTY_ROOT: [u8; 32] = [
    0x26, 0xbe, 0xcf, 0x71, 0x2d, 0xb6, 0x19, 0xda, 0x22, 0x3e, 0xcf, 0x9b, 0x8f, 0xd6, 0xc1, 0x9a,
    0x6f, 0x81, 0xf2, 0x81, 0xe4, 0xd7, 0xac, 0xec, 0x9d, 0x6a, 0xb3, 0xaf, 0x79, 0x72, 0x29, 0x46,
];

const _: () = assert!(QUEUE_CAPACITY as u64 == 2 * MEMBER_QUEUE_LIMIT);

/// The sentinel `(0, q - 1)` brackets every member in `[1, q - 2]` strictly.
pub fn check_member(member: &[u8; 32]) -> Result<(), CustomRingError> {
    if *member == [0; 32] || *member >= FIELD_MAX {
        return Err(CustomRingError::MemberOutOfRange);
    }
    Ok(())
}

/// The record field a registered key sets, `Poseidon(nullifier_pk, hash_bytes(ciphertext))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl EscrowKey<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[self.nullifier_pk, &hash_bytes(self.ciphertext)?])
    }
}

/// One queued masked write, `lists' = (lists & !mask) | value`, the escrow key fills once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueEntry {
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    pub escrow_key: [u8; 32],
}

impl QueueEntry {
    pub fn escrow(member: [u8; 32], key: &EscrowKey<'_>) -> Result<Self, CustomRingError> {
        check_member(&member)?;
        let bit = ListId::Escrow.record_bit();
        Ok(Self {
            member,
            mask: bit,
            value: bit,
            escrow_key: key.hash()?,
        })
    }

    /// `Poseidon(CRQW, member, mask, value, escrow_key)`, mirror
    /// `prover/server/custom_rings/circuits/registry/apply.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::QUEUE_WRITE),
            &self.member,
            &right_align(&self.mask.to_be_bytes()),
            &right_align(&self.value.to_be_bytes()),
            &self.escrow_key,
        ])
    }
}

/// `chain(p) = Poseidon(chain(p - 1), entry_p)` from `chain(-1) = 0`.
pub fn queue_chain(previous: &[u8; 32], entry: &QueueEntry) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[previous, &entry.hash()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        right_align(&[byte])
    }

    #[test]
    fn members_lie_strictly_between_the_sentinel_bounds() {
        // `q - 2`, the modulus ends in `f0000001`.
        let mut below_max = FIELD_MAX;
        below_max[28] -= 1;
        below_max[29..].fill(0xff);
        assert_eq!(check_member(&member(1)), Ok(()));
        assert_eq!(check_member(&below_max), Ok(()));
        for outside in [[0; 32], FIELD_MAX, BN254_SCALAR_MODULUS_BE] {
            assert_eq!(
                check_member(&outside),
                Err(CustomRingError::MemberOutOfRange)
            );
        }
    }

    #[test]
    fn an_escrow_entry_sets_the_escrow_bit_and_the_key() {
        let key = EscrowKey {
            nullifier_pk: &member(4),
            ciphertext: &[5; AUDIT_CIPHERTEXT_LEN],
        };
        let entry = QueueEntry::escrow(member(3), &key).unwrap();
        let bit = ListId::Escrow.record_bit();
        assert_eq!(
            (entry.mask, entry.value, entry.escrow_key),
            (bit, bit, key.hash().unwrap())
        );
        assert_ne!(
            entry.hash(),
            QueueEntry {
                escrow_key: [0; 32],
                ..entry
            }
            .hash()
        );
    }
}
