use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::right_align,
    HasherError,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{AUDIT_CIPHERTEXT_LEN, AUDIT_DISCLOSURE_FIELD_COUNT, TAGGED_X25519_KEY_LEN};

/// The audit statement, each value from the forwarded SPP content, the ring
/// config or the published message, so a proof binds only this transaction.
pub struct CustomRingBasePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub output_hashes: &'a [[u8; 32]],
    pub salt: &'a [u8; 16],
    pub disclosure: &'a [[u8; 32]],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldPair {
    pub lo: [u8; 32],
    pub hi: [u8; 32],
}

impl CustomRingBasePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    /// The chain order of `prover/server/custom_rings/circuits/base/circuit.go`.
    pub fn elements(&self) -> Result<[[u8; 32]; 11], HasherError> {
        let tx = pack_2fe(self.tx_viewing_pk);
        let auditor = pack_2fe(self.auditor_pk);
        let eph = pack_2fe(self.eph_pk);
        if self.disclosure.len() != AUDIT_DISCLOSURE_FIELD_COUNT {
            return Err(HasherError::InvalidInputLength(
                AUDIT_DISCLOSURE_FIELD_COUNT,
                self.disclosure.len(),
            ));
        }
        Ok([
            *self.private_tx_hash,
            tx.lo,
            tx.hi,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            ciphertext_hash(self.ciphertext)?,
            create_hash_chain_4_from_slice(self.output_hashes)?,
            right_align(self.salt),
            create_hash_chain_4_from_slice(self.disclosure)?,
        ])
    }
}

/// `lo = 0x00 || bytes[..31]` and `hi` the rest right aligned, as Go `Pack32/33To2FECircuit`.
pub fn pack_2fe<const N: usize>(bytes: &[u8; N]) -> FieldPair {
    const { assert!(N == 32 || N == 33) };
    let (head, tail) = bytes.split_at(31);
    let mut pair = FieldPair {
        lo: [0; 32],
        hi: [0; 32],
    };
    pair.lo[1..].copy_from_slice(head);
    pair.hi[32 - tail.len()..].copy_from_slice(tail);
    pair
}
