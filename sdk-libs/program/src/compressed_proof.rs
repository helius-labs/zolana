use wincode::{SchemaRead, SchemaWrite};

/// The application proof carried by an instruction: compressed A, B and C.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}
