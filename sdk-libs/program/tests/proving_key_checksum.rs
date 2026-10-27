#![cfg(feature = "client")]

use zolana_program::proof::{check_proving_key, ProvingKeyChecksumMismatch};

// SHA-256("abc"), independent of the implementation under test.
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

#[test]
fn accepts_exact_key_bytes() {
    assert_eq!(check_proving_key(b"abc", &ABC_SHA256), Ok(()), "known SHA-256 vector");
}

#[test]
fn rejects_same_length_changed_key() {
    assert_eq!(check_proving_key(b"abd", &ABC_SHA256), Err(ProvingKeyChecksumMismatch), "same-length substitution");
}

#[test]
fn rejects_trailing_key_bytes() {
    assert_eq!(check_proving_key(b"abc\0", &ABC_SHA256), Err(ProvingKeyChecksumMismatch), "the digest must cover every byte");
}
