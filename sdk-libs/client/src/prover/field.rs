use num_bigint::BigUint;
pub use zolana_hasher::primitives::right_align;
use zolana_hasher::primitives::right_align_slice as hasher_right_align_slice;

use crate::error::ClientError;

pub fn right_align_slice(bytes: &[u8]) -> Result<[u8; 32], ClientError> {
    hasher_right_align_slice(bytes).map_err(|_| ClientError::FieldTooLong)
}

pub fn be(value: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(value)
}
