use custom_ring_interface::{QueueEntry, FIELD_MAX};
use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

use crate::RecordTreeError;

/// One leaf, `Poseidon(member, next, lists, escrow_key)`, mirror `prover/server/circuits/records`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    /// Bit `id - 1` marks list `id`.
    pub lists: u64,
    /// `EscrowKey::hash` once registered, zero before.
    pub escrow_key: [u8; 32],
}

impl MemberRecord {
    /// Leaf 0, every member sorts strictly between it and `FIELD_MAX`.
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

    /// List bits outside the mask keep their value, a registered key is final.
    #[must_use]
    pub fn written(self, entry: &QueueEntry) -> Self {
        let escrow_key = if self.escrow_key == [0; 32] {
            entry.escrow_key
        } else {
            self.escrow_key
        };
        Self {
            lists: (self.lists & !entry.mask) | entry.value,
            escrow_key,
            ..self
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lists == 0 && self.escrow_key == [0; 32]
    }

    pub fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member < *member && *member < self.next
    }
}

pub(crate) fn check_member(member: &[u8; 32]) -> Result<(), RecordTreeError> {
    custom_ring_interface::check_member(member).map_err(|_| RecordTreeError::MemberOutOfRange)
}
