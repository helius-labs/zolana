//! Zolana protocol operations over Xark and native Rust values.
//!
//! This crate uses `core` and `alloc`. Xark's native execution and proving
//! dependencies still require `std` at the pinned revision.

#![no_std]

extern crate alloc;

mod array_vec;
mod codec;
mod error;
mod hash;
mod owner;
pub mod protocol;

pub use array_vec::{ArrayVec, PaddedInput};
pub use codec::EncryptionCodec;
pub use error::{CircuitError, CircuitErrorKind};
pub use hash::{hash_bytes, nonzero_hash_chain, poseidon};
pub use owner::{ShieldedAddress, SigningPubkey, UtxoOwner};
pub use xark;
pub use xark::{Field, Input, input, require, require_eq};
#[cfg(all(feature = "serde", not(xark), not(xark_client)))]
pub use owner::wire::field as field_serde;

#[cfg(not(xark))]
pub fn to_bytes(value: &Field) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (target, limb) in out.rchunks_exact_mut(8).zip(value.to_limbs()) {
        target.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

#[cfg(not(xark))]
pub fn from_decimal(encoded: &str) -> Result<Field, CircuitError> {
    let value = Field::try_from_str(encoded).map_err(|_| CircuitErrorKind::NonCanonicalField)?;
    if value.to_decimal() != encoded { return Err(CircuitErrorKind::NonCanonicalField.into()); }
    Ok(value)
}

#[cfg(not(xark))]
pub fn from_bytes(bytes: &[u8; 32]) -> Result<Field, CircuitError> {
    let value = Field::from_be_bytes(bytes);
    if to_bytes(&value) != *bytes { return Err(CircuitErrorKind::NonCanonicalField.into()); }
    Ok(value)
}

pub mod hasher {
    pub const DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"DATA");
    pub const UNIQUE_DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"UNIQ");
    pub const CLOSED_DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"CLSD");
}
