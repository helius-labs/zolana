//! # zolana-hasher
//!
//! Trait for generic hash function usage on Solana.
//!
//! | Type | Description |
//! |------|-------------|
//! | [`Hasher`] | Trait with `hash`, `hashv`, and `zero_bytes` |
//! | [`Poseidon`] | Poseidon hash over BN254 |
//! | [`Keccak`] | Keccak-256 hash |
//! | [`Sha256`] | SHA-256 hash |
//! | [`HasherError`] | Error type for hash operations |
//! | [`hash_chain`] | Sequential hash chaining |
//! | [`primitives`] | Fixed-length byte packing and Poseidon commitments |
//! | [`zero_bytes`] | Precomputed zero-leaf hashes per hasher |

#![allow(unexpected_cfgs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(feature = "alloc")]
#[cfg(not(feature = "std"))]
pub use alloc::{string::String, vec, vec::Vec};
#[cfg(feature = "std")]
pub use std::{string::String, vec, vec::Vec};

pub mod bigint;
pub mod errors;
pub mod hash_chain;
pub mod keccak;
pub mod poseidon;
pub mod primitives;
pub mod sha256;
pub mod syscalls;
pub mod zero_bytes;

pub use keccak::Keccak;
pub use poseidon::Poseidon;
pub use sha256::Sha256;

pub use crate::errors::HasherError;
use crate::zero_bytes::ZeroBytes;

pub const HASH_BYTES: usize = 32;

pub type Hash = [u8; HASH_BYTES];

pub trait Hasher {
    const ID: u8;
    fn hash(val: &[u8]) -> Result<Hash, HasherError>;
    fn hashv(vals: &[&[u8]]) -> Result<Hash, HasherError>;
    fn zero_bytes() -> ZeroBytes;
}
