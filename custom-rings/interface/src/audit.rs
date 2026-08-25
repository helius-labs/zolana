use zolana_hasher::{hash_chain::create_hash_chain_from_slice, HasherError};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};

/// Inputs of the auditor circuit's single public input.
///
/// The chain order is pinned by the circuit's package comment
/// (`prover/server/circuits/custom_ring/audit/circuit.go`) and is
/// numbered 1..8 there; [`AuditPublicInput::hash`] mirrors it element for
/// element. Recomputing the hash on-chain from values the program itself trusts
/// -- `private_tx_hash` and `tx_viewing_pk` from the forwarded SPP payload, the
/// auditor key from the ring config account, the ephemeral key and ciphertext
/// from the published message -- is what binds the proof to this transaction: a
/// proof for any other transaction, viewing key, auditor, or ciphertext hashes
/// to a different public input and fails verification.
pub struct AuditPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldPair {
    pub lo: [u8; 32],
    pub hi: [u8; 32],
}

impl AuditPublicInput<'_> {
    /// Input order binds the audit statement.
    /// `HashChain([private_tx_hash, tx_pk_lo, tx_pk_hi, auditor_lo, auditor_hi,
    /// eph_lo, eph_hi, ct_hash])`.
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
    pub fn elements(&self) -> Result<[[u8; 32]; 8], HasherError> {
        let tx = pack33_to_2fe(self.tx_viewing_pk);
        let auditor = pack33_to_2fe(self.auditor_pk);
        let eph = pack33_to_2fe(self.eph_pk);
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        Ok([
            *self.private_tx_hash,
            tx.lo,
            tx.hi,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            ct_hash,
        ])
    }
}

/// Mirrors `Pack32To2FECircuit`: `lo = 0x00 || bytes[0..31]` (byte 0 is the most
/// significant data byte) and `hi = bytes[31]`, both as 32-byte big-endian field
/// elements.
pub fn pack32_to_2fe(bytes: &[u8; 32]) -> FieldPair {
    let mut lo = [0u8; 32];
    lo[1..].copy_from_slice(&bytes[..31]);
    FieldPair {
        lo,
        hi: right_align(&bytes[31..]),
    }
}

/// Split a 33-byte SEC1-compressed P256 key into the two BN254 field elements
/// the auditor circuit hashes.
///
/// Mirrors `Pack33To2FECircuit` in
/// `prover/server/circuits/custom_ring/audit/pack.go`.
///
/// ```text
/// lo = 0x00 || key[0..31]        (the SEC1 prefix is the most significant data byte)
/// hi = key[31] * 256 + key[32]
/// ```
///
/// A 33-byte key does not fit one field element, and the split is injective
/// because every input byte is 8 bits wide, so the pair binds the key uniquely.
pub fn pack33_to_2fe(bytes: &[u8; 33]) -> FieldPair {
    // Constant ranges over a fixed-size array: the compiler proves both fit.
    let mut lo = [0u8; 32];
    lo[1..].copy_from_slice(&bytes[..31]);
    FieldPair {
        lo,
        hi: right_align(&bytes[31..]),
    }
}

fn right_align(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}
