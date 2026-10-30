use wincode::{SchemaRead, SchemaWrite};

/// The application proof carried by an instruction: compressed A, B and C.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), derive(serde::Serialize, tsify::Tsify))]
pub struct CompressedProof {
    #[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), serde(with = "spr_keypair::serde_helpers::bytes"), tsify(type = "Uint8Array"))]
    pub a: [u8; 32],
    #[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), serde(with = "spr_keypair::serde_helpers::bytes"), tsify(type = "Uint8Array"))]
    pub b: [u8; 64],
    #[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), serde(with = "spr_keypair::serde_helpers::bytes"), tsify(type = "Uint8Array"))]
    pub c: [u8; 32],
}
