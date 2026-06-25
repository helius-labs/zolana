use num_bigint::BigUint;
use zolana_keypair::hash::poseidon;

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

pub fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ClientError> {
    let mut iter = items.iter();
    let mut acc = match iter.next() {
        Some(first) => *first,
        None => return Ok([0u8; 32]),
    };
    for item in iter {
        acc = poseidon(&[&acc, item]).map_err(|e| ClientError::Hasher(e.to_string()))?;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_empty_and_single() {
        assert_eq!(hash_chain(&[]).unwrap(), [0u8; 32]);
        let mut x = [0u8; 32];
        x[31] = 7;
        assert_eq!(hash_chain(&[x]).unwrap(), x);
    }

    #[test]
    fn hash_chain_two_matches_poseidon() {
        let mut a = [0u8; 32];
        a[31] = 1;
        let mut b = [0u8; 32];
        b[31] = 2;
        let expected = poseidon(&[&a, &b]).unwrap();
        assert_eq!(hash_chain(&[a, b]).unwrap(), expected);
    }
}
