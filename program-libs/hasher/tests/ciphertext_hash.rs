use zolana_hasher::{primitives::ciphertext_hash, HasherError};

fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// The 71-byte merge ciphertext fixture emitted by the Go circuit host
// (prover/server/circuits/spp_merge TestPrintMergeVector), validated against the
// circuit via test.IsSolved; also pinned in interface and keypair tests.
const CIPHERTEXT_HEX: &str = "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202";
const CT_HASH_HEX: &str = "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453";

#[cfg(feature = "poseidon")]
#[test]
fn matches_the_circuit_vector() {
    let ciphertext = hex_to_vec(CIPHERTEXT_HEX);
    let got = ciphertext_hash(&ciphertext).unwrap();
    assert_eq!(got.to_vec(), hex_to_vec(CT_HASH_HEX));
}

#[cfg(feature = "poseidon")]
#[test]
fn accepts_the_full_12_chunk_width() {
    assert!(ciphertext_hash(&[7u8; 192]).is_ok());
}

#[test]
fn empty_input_is_rejected() {
    assert_eq!(ciphertext_hash(&[]), Err(HasherError::EmptyInput));
}

#[test]
fn input_longer_than_192_bytes_is_rejected() {
    assert_eq!(
        ciphertext_hash(&[0u8; 193]),
        Err(HasherError::InvalidInputLength(192, 193))
    );
}
