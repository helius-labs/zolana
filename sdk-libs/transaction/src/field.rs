//! BN254 scalar-field arithmetic over 32-byte big-endian elements: the
//! additive Poseidon-pad ciphers and signed settlement amounts.

use num_bigint::BigUint;
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

fn modulus() -> BigUint {
    BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE)
}

/// Right-aligns a value already reduced below the modulus.
fn to_bytes(value: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (out, byte) in out
        .iter_mut()
        .rev()
        .zip(value.to_bytes_be().into_iter().rev())
    {
        *out = byte;
    }
    out
}

/// `a + b mod p`.
pub fn field_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let p = modulus();
    to_bytes(&((BigUint::from_bytes_be(a) + BigUint::from_bytes_be(b)) % &p))
}

/// `a - b mod p`.
pub fn field_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let p = modulus();
    let a = BigUint::from_bytes_be(a) % &p;
    let b = BigUint::from_bytes_be(b) % &p;
    to_bytes(&((a + &p - b) % &p))
}
