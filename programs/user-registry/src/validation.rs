use pinocchio::error::ProgramError;
use zolana_interface::user_registry::state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN};

use crate::{
    constants::BN254_FR_MODULUS,
    error::{fail, UserRegistryError},
};

pub fn validate_p256_pubkey(pubkey: &[u8; P256_PUBKEY_LEN]) -> Result<(), ProgramError> {
    if !matches!(pubkey[0], 0x02 | 0x03) {
        return Err(fail(UserRegistryError::InvalidP256Prefix));
    }
    Ok(())
}

pub fn validate_optional_p256_pubkey(
    pubkey: &Option<[u8; P256_PUBKEY_LEN]>,
) -> Result<(), ProgramError> {
    if let Some(pubkey) = pubkey {
        validate_p256_pubkey(pubkey)?;
    }
    Ok(())
}

pub fn validate_canonical_nullifier_pubkey(
    nullifier_pubkey: &[u8; NULLIFIER_PUBKEY_LEN],
) -> Result<(), ProgramError> {
    if !bytes_be_lt(nullifier_pubkey, &BN254_FR_MODULUS) {
        return Err(fail(UserRegistryError::NonCanonicalNullifierPubkey));
    }
    Ok(())
}

fn bytes_be_lt(left: &[u8; 32], right: &[u8; 32]) -> bool {
    for (l, r) in left.iter().zip(right.iter()) {
        match l.cmp(r) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_p256_prefixes() {
        for prefix in [0x00u8, 0x01, 0x04, 0x05, 0xFF] {
            let mut key = [0u8; P256_PUBKEY_LEN];
            key[0] = prefix;
            assert!(
                validate_p256_pubkey(&key).is_err(),
                "prefix {prefix:#04x} must be rejected"
            );
        }
        for prefix in [0x02u8, 0x03] {
            let mut key = [0u8; P256_PUBKEY_LEN];
            key[0] = prefix;
            assert!(
                validate_p256_pubkey(&key).is_ok(),
                "prefix {prefix:#04x} must be accepted"
            );
        }
    }

    #[test]
    fn rejects_nullifier_at_field_modulus() {
        let mut at_modulus = BN254_FR_MODULUS;
        assert!(validate_canonical_nullifier_pubkey(&at_modulus).is_err());
        at_modulus[31] = 0;
        assert!(validate_canonical_nullifier_pubkey(&at_modulus).is_ok());
    }
}
