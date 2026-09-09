//! Canonical `no_std`-compatible fixed-length byte commitments shared by the
//! merge program, SDK, and circuits.

use zolana_hasher::{
    primitives::{hash_bytes, p256_owner_identity},
    HasherError,
};

const P256_PUBKEY_LEN: usize = 33;

fn parse_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(HasherError::InvalidInputLength(usize::from(prefix), 0));
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&compressed[1..]);
    Ok(x)
}

/// Proof-input hash of a complete SEC1-compressed P256 viewing key.
pub fn pk_field_compressed(compressed: &[u8; P256_PUBKEY_LEN]) -> Result<[u8; 32], HasherError> {
    parse_compressed(compressed)?;
    hash_bytes(compressed)
}

/// Owner identity of a SEC1-compressed P256 key:
/// [`p256_owner_identity`] over its 32-byte x-coordinate. SEC1 parity is
/// validated but intentionally excluded from the identity.
pub fn owner_proof_input_hash_compressed(
    compressed: &[u8; P256_PUBKEY_LEN],
) -> Result<[u8; 32], HasherError> {
    p256_owner_identity(&parse_compressed(compressed)?)
}

/// Fixed-length ciphertext proof-input hash.
pub fn ciphertext_hash<const N: usize>(ciphertext: &[u8; N]) -> Result<[u8; 32], HasherError> {
    hash_bytes(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec1(prefix: u8) -> [u8; 33] {
        let mut key = [0u8; 33];
        key[0] = prefix;
        for (index, byte) in key.iter_mut().enumerate().skip(1) {
            *byte = index as u8;
        }
        key
    }

    #[test]
    fn rejects_invalid_sec1_prefix() {
        let mut key = sec1(0x02);
        key[0] = 0x04;
        assert!(pk_field_compressed(&key).is_err());
        assert!(owner_proof_input_hash_compressed(&key).is_err());
    }

    #[test]
    fn viewing_hash_binds_parity_but_owner_hash_does_not() {
        let even = sec1(0x02);
        let mut odd = even;
        odd[0] = 0x03;
        assert_ne!(
            pk_field_compressed(&even).unwrap(),
            pk_field_compressed(&odd).unwrap()
        );
        assert_eq!(
            owner_proof_input_hash_compressed(&even).unwrap(),
            owner_proof_input_hash_compressed(&odd).unwrap()
        );
    }

    #[test]
    fn owner_hash_is_the_tagged_p256_identity_of_the_x_coordinate() {
        let key = sec1(0x02);
        let mut x = [0u8; 32];
        x.copy_from_slice(&key[1..]);
        assert_eq!(
            owner_proof_input_hash_compressed(&key).unwrap(),
            p256_owner_identity(&x).unwrap()
        );
        assert_ne!(
            owner_proof_input_hash_compressed(&key).unwrap(),
            hash_bytes(&x).unwrap()
        );
    }
}
