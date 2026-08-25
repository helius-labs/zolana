use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::TransactIxData;

use crate::{ReaderKeyBytes, COMPRESSED_P256_KEY_LEN};

pub mod tag {
    pub const CREATE_CONFIG: u8 = 1;
    pub const INIT_SPP_RING_CONFIG: u8 = 2;
    pub const TRANSACT: u8 = 3;
    /// Ring deposits carry no proof and are forwarded to SPP byte for byte, so
    /// the dispatcher matches SPP's own deposit tag instead of a program-local
    /// one: the client builds the SPP-shaped instruction and only re-targets the
    /// program id.
    pub const DEPOSIT: u8 = zolana_interface::instruction::tag::RING_DEPOSIT;
    pub const GRANT_READ_ACCESS: u8 = 4;
    pub const REVOKE_READ_ACCESS: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
}

pub const CREATE_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const READ_ACCESS_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_AUTHORITY_COMPUTE_UNIT_LIMIT: u32 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReaderIxData {
    pub reader: ReaderKeyBytes,
}

/// Groth16 proof of the custom-ring circuit. The circuit's emulated P256
/// arithmetic adds one BSB22 commitment, so the commitment and its
/// proof-of-knowledge are not optional here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingProof {
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
    pub proof: CustomRingProof,
    pub transact: TransactIxData,
}
