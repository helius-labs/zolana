#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod bounded_slice;
pub mod cyclic_slice;
pub mod errors;
mod util;

pub use util::{add_padding, ZeroCopyTraits};
