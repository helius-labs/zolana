//! Groth16 proving over the proving keys gnark's trusted setup produced.
//!
//! The key bytes, the deployed verifying keys, and the `POST /prove` JSON stay
//! as they are. Only the arithmetic runs here, on arkworks.

#![forbid(unsafe_code)]

mod error;
mod json;
mod key;
mod prove;
mod reader;
mod verify;

pub use error::Error;
pub use json::proof_json;
pub use key::{parse_transfer_key, Domain, ProvingKey, TransferHeader, TransferKey, VerifyingKey};
pub use prove::{prove, prove_with_randomness, Assignment, Proof};
pub use verify::verify;
