use num_bigint::BigUint;

use crate::error::ClientError;

/// BN254 scalar-field modulus (Fr), big-endian. Poseidon and circuit witnesses
/// are elements of this field; a 32-byte value at or above it is not one.
const BN254_SCALAR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

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

/// Big-endian read with no range check. Use for values that are not BN254 field
/// elements (P256 coordinates and signature limbs). Circuit witnesses that must
/// be field elements go through [`checked_be`].
pub fn be(value: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(value)
}

/// Big-endian read that refuses a value at or above the BN254 scalar modulus.
/// Mirrors TypeScript `bytesField` on an already-aligned 32-byte buffer.
pub fn checked_be(value: &[u8; 32]) -> Result<BigUint, ClientError> {
    if value >= &BN254_SCALAR_MODULUS_BE {
        return Err(ClientError::InvalidField);
    }
    Ok(be(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_be_accepts_below_modulus_and_refuses_at_and_above() {
        let mut below = BN254_SCALAR_MODULUS_BE;
        below[31] = 0x00;
        assert_eq!(checked_be(&below).unwrap(), be(&below));
        assert!(matches!(
            checked_be(&BN254_SCALAR_MODULUS_BE),
            Err(ClientError::InvalidField)
        ));
        assert!(matches!(
            checked_be(&[0xff; 32]),
            Err(ClientError::InvalidField)
        ));
    }
}
