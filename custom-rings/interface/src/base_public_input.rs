use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{pack_be, right_align},
    HasherError,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{AUDIT_CIPHERTEXT_LEN, AUDIT_DISCLOSURE_FIELD_COUNT, COMPRESSED_P256_KEY_LEN};

/// Inputs of the auditor circuit's single public input.
///
/// The chain order is pinned by the circuit's package comment
/// (`prover/server/custom_rings/circuits/base/circuit.go`) and is
/// numbered 1..11 there; [`CustomRingBasePublicInput::hash`] mirrors it element for
/// element. Recomputing the hash on-chain from values the program itself trusts
/// -- `private_tx_hash` and `tx_viewing_pk` from the forwarded SPP content, the
/// auditor key from the ring config account, the ephemeral key and ciphertext
/// from the published message -- is what binds the proof to this transaction: a
/// proof for any other transaction, viewing key, auditor, or ciphertext hashes
/// to a different public input and fails verification.
pub struct CustomRingBasePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub output_hashes: &'a [[u8; 32]],
    pub salt: &'a [u8; 16],
    pub disclosure: &'a [[u8; 32]],
}

impl CustomRingBasePublicInput<'_> {
    /// Input order binds the audit statement.
    /// `HashChain([private_tx_hash, tx_pk_lo, tx_pk_hi, auditor_lo, auditor_hi,
    /// eph_lo, eph_hi, ct_hash, output_hash_chain, salt, disclosure_hash])`.
    ///
    /// `create_hash_chain_from_slice` is the Rust twin of the circuit's
    /// `gadget.HashChain`, and `ciphertext_hash` (i.e. `hash_bytes`, 31-byte
    /// big-endian chunking) the twin of its `gadget.HashBytes`. This is the one
    /// canonical implementation: the SDK builds its proof inputs through it
    /// rather than duplicating the chain.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    /// The chain elements, in the order the circuit assembles them.
    pub fn elements(&self) -> Result<[[u8; 32]; 11], HasherError> {
        let [tx_lo, tx_hi] = pack_be::<33, 2>(self.tx_viewing_pk);
        let [auditor_lo, auditor_hi] = pack_be::<33, 2>(self.auditor_pk);
        let [eph_lo, eph_hi] = pack_be::<33, 2>(self.eph_pk);
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        let output_hash_chain = create_hash_chain_4_from_slice(self.output_hashes)?;
        if self.disclosure.len() != AUDIT_DISCLOSURE_FIELD_COUNT {
            return Err(HasherError::InvalidInputLength(
                AUDIT_DISCLOSURE_FIELD_COUNT,
                self.disclosure.len(),
            ));
        }
        let disclosure_hash = create_hash_chain_from_slice(self.disclosure)?;
        Ok([
            *self.private_tx_hash,
            tx_lo,
            tx_hi,
            auditor_lo,
            auditor_hi,
            eph_lo,
            eph_hi,
            ct_hash,
            output_hash_chain,
            right_align(self.salt),
            disclosure_hash,
        ])
    }
}
