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
        return Err(ClientError::ValueTooLong);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

pub fn be(value: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(value)
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex(value: &[u8; 32]) -> String {
    let Some(first) = value.iter().position(|byte| *byte != 0) else {
        return "0x0".into();
    };
    let mut encoded = String::with_capacity(2 + (32 - first) * 2);
    encoded.push_str("0x");
    if value[first] >= 16 {
        encoded.push(HEX_DIGITS[usize::from(value[first] >> 4)] as char);
    }
    encoded.push(HEX_DIGITS[usize::from(value[first] & 15)] as char);
    append_hex(&mut encoded, &value[first + 1..]);
    encoded
}

pub(crate) fn hex_fixed(value: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    append_hex(&mut encoded, value);
    encoded
}

fn append_hex(encoded: &mut String, bytes: &[u8]) {
    for byte in bytes {
        encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(HEX_DIGITS[usize::from(byte & 15)] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_matches_biguint_encoding() {
        assert_eq!(hex(&[0; 32]), "0x0");
        assert_eq!(hex_fixed(&[0; 32]), format!("0x{:064x}", 0));
        for first in 0..32 {
            for byte in 1..=255 {
                let mut value = [0; 32];
                value[first..].fill(byte);
                assert_eq!(hex(&value), format!("0x{}", be(&value).to_str_radix(16)));
                assert_eq!(hex_fixed(&value), format!("0x{:064x}", be(&value)));
            }
        }
    }
}
