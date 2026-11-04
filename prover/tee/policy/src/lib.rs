//! The operator side of the signed TEE prover policy: build and sign a release
//! part, verify a part or a served file, and keep a release in force with a
//! freshness part. Every check is `spr-prover-tee`'s own verifier against the
//! release keys the Rust client pins, so this crate accepts exactly what clients
//! accept.

pub mod freshness;
pub mod kms;
pub mod manifest;
pub mod pins;
pub mod release;
