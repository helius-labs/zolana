use wincode::{SchemaRead, SchemaWrite};

/// A Groth16 proof compressed to 128 bytes: A and C as compressed G1 points and
/// B as a compressed G2 point, the layout a program decompresses before
/// verifying its own circuit's proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}
