use num_bigint::{BigInt, BigUint, Sign};
use solana_address::Address;
use zolana_keypair::hash::{hash_field, poseidon};

use crate::error::ClientError;

pub const BN254_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn modulus() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("valid BN254 modulus literal")
}

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

pub fn signed_to_field(value: i128) -> [u8; 32] {
    let m = BigInt::from_biguint(Sign::Plus, modulus());
    let v = BigInt::from(value);
    let reduced = ((v % &m) + &m) % &m;
    let (_, bytes) = reduced.to_bytes_be();
    right_align_slice(&bytes).expect("reduced value fits in the field")
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], ClientError> {
    hash_field(asset.as_array()).map_err(ClientError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_transaction::SOL_MINT;

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

    #[test]
    fn signed_to_field_negative_one_is_modulus_minus_one() {
        let m = modulus();
        let expected = &m - 1u32;
        let got = be(&signed_to_field(-1));
        assert_eq!(got, expected);
    }

    #[test]
    fn signed_to_field_positive_passthrough() {
        assert_eq!(be(&signed_to_field(5)), BigUint::from(5u32));
        assert_eq!(signed_to_field(0), [0u8; 32]);
    }

    #[test]
    fn sol_asset_field_matches_circuit_constant() {
        let sol_asset_dec =
            "14744269619966411208579211824598458697587494354926760081771325075741142829156";
        let expected = BigUint::parse_bytes(sol_asset_dec.as_bytes(), 10).unwrap();
        let got = be(&asset_field(&SOL_MINT).unwrap());
        assert_eq!(got, expected);
    }
}
