use num_bigint::BigUint;

use crate::error::ClientError;

pub fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 32) };
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(bytes);
    out
}

pub fn right_align_slice(bytes: &[u8]) -> Result<[u8; 32], ClientError> {
    if bytes.len() > 32 {
        return Err(ClientError::FieldTooLong);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

pub fn be(value: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(value)
}
