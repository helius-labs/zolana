use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::right_align,
    HasherError,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{AUDIT_CIPHERTEXT_LEN, SHORT_AUDIT_MIN_INPUTS, TAGGED_X25519_KEY_LEN};

/// The audit statement the confidential base keys prove.
pub const AUDIT_PUBLIC_INPUT_ELEMENTS: usize = 12;
/// The base statement, the audit elements with the output body chain at `BODY_CHAIN_INDEX`.
pub const BASE_PUBLIC_INPUT_ELEMENTS: usize = AUDIT_PUBLIC_INPUT_ELEMENTS + 1;
pub const BODY_CHAIN_INDEX: usize = 8;
/// Spent notes the narrow anonymous base key opens, the wide key opens `AUDIT_INPUT_SLOTS`.
pub const BASE_ANONYMOUS_INPUT_SLOTS: usize = 4;

/// The base key the ring mode and the settled shape select, the program and the SDK
/// pick through this one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseCircuit {
    Base,
    WideAnonymous,
    Confidential,
    CompactConfidential,
}

impl BaseCircuit {
    pub const fn select(anonymous: bool, inputs: usize, outputs: usize) -> Self {
        if anonymous && inputs > BASE_ANONYMOUS_INPUT_SLOTS {
            Self::WideAnonymous
        } else if anonymous || outputs != 2 {
            Self::Base
        } else if inputs >= SHORT_AUDIT_MIN_INPUTS {
            Self::CompactConfidential
        } else {
            Self::Confidential
        }
    }

    /// The confidential keys prove the audit elements without the body chain.
    pub fn public_input_hash(
        self,
        statement: &CustomRingBasePublicInput<'_>,
    ) -> Result<[u8; 32], HasherError> {
        match self {
            Self::Confidential | Self::CompactConfidential => {
                create_hash_chain_from_slice(&statement.audit_elements()?)
            }
            Self::Base | Self::WideAnonymous => statement.hash(),
        }
    }
}

/// The audit statement, each value from the forwarded SPP content, the ring
/// config or the published message, so a proof binds only this transaction.
pub struct CustomRingBasePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    /// One entry per published output in slot order, `hash_bytes` of the exact
    /// 105-byte scheme-9 body in an anonymous ring, zero for a scheme-3 slot and
    /// for every slot of a ring that is not anonymous. Same length as `output_hashes`.
    pub output_body_hashes: &'a [[u8; 32]],
    /// Folded with `HashChain4`, which does not hash the length: `[a, b]` and
    /// `[a, b, 0]` hash alike. Distinct lists stay distinct only because every
    /// entry is a published SPP output hash, which SPP rejects when zero
    /// (`ZeroOutputUtxoHash`) in the same transaction.
    pub output_hashes: &'a [[u8; 32]],
    pub salt: &'a [u8; 16],
    /// The caller checks the field count against the ring mode and shape.
    pub disclosure: &'a [[u8; 32]],
    /// Discloses the hidden sender and every input opening.
    pub anonymous: bool,
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
    pub fn elements(&self) -> Result<[[u8; 32]; BASE_PUBLIC_INPUT_ELEMENTS], HasherError> {
        let audit = self.audit_elements()?;
        let mut elements = [[0u8; 32]; BASE_PUBLIC_INPUT_ELEMENTS];
        elements[..BODY_CHAIN_INDEX].copy_from_slice(&audit[..BODY_CHAIN_INDEX]);
        elements[BODY_CHAIN_INDEX] = create_hash_chain_4_from_slice(self.output_body_hashes)?;
        elements[BODY_CHAIN_INDEX + 1..].copy_from_slice(&audit[BODY_CHAIN_INDEX..]);
        Ok(elements)
    }

    /// The chain order of `base.Audit.Define`, the statement the confidential base keys prove.
    pub fn audit_elements(&self) -> Result<[[u8; 32]; AUDIT_PUBLIC_INPUT_ELEMENTS], HasherError> {
        let tx = pack_2fe(self.tx_viewing_pk);
        let auditor = pack_2fe(self.auditor_pk);
        let eph = pack_2fe(self.eph_pk);
        let disclosure_hash = create_hash_chain_4_from_slice(self.disclosure)?;
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
            disclosure_hash,
            right_align(&[u8::from(self.anonymous)]),
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
