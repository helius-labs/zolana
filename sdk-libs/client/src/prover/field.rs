use num_bigint::BigUint;

use crate::error::ClientError;

pub fn right_align_slice(bytes: &[u8]) -> Result<[u8; 32], ClientError> {
    if bytes.len() > 32 {
        return Err(ClientError::ValueTooLong);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

pub fn be(value: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(value)
}

/// `value` as the prover reads a field element: `0x`, then its lowercase hex
/// digits without leading zeros.
pub fn hex_biguint(value: &BigUint) -> String {
    format!("0x{}", value.to_str_radix(16))
}

/// [`hex_biguint`] of a big-endian field element.
pub fn hex_field(field: &[u8; 32]) -> String {
    hex_biguint(&be(field))
}
