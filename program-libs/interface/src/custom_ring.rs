use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use wincode::{SchemaRead, SchemaWrite};
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, sha256::Sha256, Hasher, HasherError,
};

use crate::{instruction::TransactIxData, merge_utils::ciphertext_hash};

pub mod tag {
    pub const CREATE_CONFIG: u8 = 1;
    pub const INIT_SPP_RING_CONFIG: u8 = 2;
    pub const TRANSACT: u8 = 3;
    /// Ring deposits carry no proof and are forwarded to SPP byte for byte, so
    /// the dispatcher matches SPP's own deposit tag instead of a program-local
    /// one: the client builds the SPP-shaped instruction and only re-targets the
    /// program id.
    pub const DEPOSIT: u8 = crate::instruction::tag::RING_DEPOSIT;
    pub const GRANT_READER: u8 = 4;
    pub const REVOKE_READER: u8 = 5;
}

/// Covers the on-chain SEC1 decompression of the auditor key.
pub const CREATE_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 450_000;
/// Covers the on-chain SEC1 decompression of a P256 reader key.
pub const READER_COMPUTE_UNIT_LIMIT: u32 = 450_000;
pub const INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;

pub const CONFIG_PDA_SEED: &[u8] = b"config";
pub const READER_RECORD_PDA_SEED: &[u8] = b"reader";
pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
/// Discriminator of [`RingProgramConfig`]. Value 0 stays reserved for
/// uninitialized accounts.
pub const RING_PROGRAM_CONFIG: u8 = 1;
pub const READER_RECORD: u8 = 2;

/// SEC1-compressed public key length.
pub const COMPRESSED_P256_KEY_LEN: usize = 33;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
/// `eph_pk_compressed(33) || ciphertext(32)`.
pub const AUDITOR_MESSAGE_LEN: usize = COMPRESSED_P256_KEY_LEN + AUDIT_CIPHERTEXT_LEN;

/// The ring's singleton config: who may register the ring with SPP, and the
/// auditor key every `transact` must verifiably encrypt the transaction viewing
/// secret key to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor P256 public key in SEC1 compressed form (`0x02`/`0x03 || x`).
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
    pub bump: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ReaderRecord {
    pub discriminator: u8,
    pub reader: ReaderKeyBytes,
    pub bump: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReaderIxData {
    pub reader: ReaderKeyBytes,
}

/// Groth16 proof of the `auditor_key_encryption` circuit. The circuit's emulated
/// P256 arithmetic adds one BSB22 commitment, so the commitment and its
/// proof-of-knowledge are not optional here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AuditProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Wire format of tag 3: the ring's own proof followed by the SPP payload this
/// ring forwards verbatim.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: AuditProof,
    pub transact: TransactIxData,
}

/// Inputs of the auditor circuit's single public input.
///
/// The chain order is pinned by the circuit's package comment
/// (`prover/server/circuits/custom_ring/auditor_key_encryption/circuit.go`) and is
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

impl RingProgramConfig {
    pub const SEED: &'static [u8] = CONFIG_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl ReaderRecord {
    pub const SEED: &'static [u8] = READER_RECORD_PDA_SEED;
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn seed_hash(reader: &ReaderKeyBytes) -> Result<[u8; 32], HasherError> {
        Sha256::hash(reader)
    }
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
        let tx = pack33_to_2fe(self.tx_viewing_pk);
        let auditor = pack33_to_2fe(self.auditor_pk);
        let eph = pack33_to_2fe(self.eph_pk);
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        create_hash_chain_from_slice(&[
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

// Every field is byte-typed (`Address` is a 32-byte, align-1 newtype), so the
// struct carries no padding: its `Pod` image is exactly its field bytes and
// `SIZE` is the on-chain account length.
const _: () = assert!(RingProgramConfig::SIZE == 67);
const _: () = assert!(core::mem::align_of::<RingProgramConfig>() == 1);
const _: () = assert!(ReaderRecord::SIZE == 36);
const _: () = assert!(core::mem::align_of::<ReaderRecord>() == 1);

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
/// `prover/server/circuits/custom_ring/auditor_key_encryption/pack.go`.
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
