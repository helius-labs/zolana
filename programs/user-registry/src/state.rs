use pinocchio::error::ProgramError;
pub use zolana_interface::user_registry::state::{
    SyncDelegateEntry, UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN,
};

use crate::{
    constants::BN254_FR_MODULUS,
    error::{fail, UserRegistryError},
};

pub fn validate_p256_pubkey(pubkey: &[u8; P256_PUBKEY_LEN]) -> Result<(), ProgramError> {
    // SEC1 compressed encoding: the only valid prefix bytes are 0x02 and 0x03.
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
    fn space_for_empty_entries() {
        assert_eq!(UserRecord::space_for(0), 170);
    }

    #[test]
    fn space_for_covers_max_serialized_size() {
        let record = UserRecord {
            owner: [7u8; 32],
            bump: 254,
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [9u8; 32],
            viewing_pubkey: [3u8; 33],
            sync_delegate: Some([5u8; 32]),
            entries: vec![
                SyncDelegateEntry {
                    sync_pubkey: [2u8; 33],
                    viewing_pubkey: [4u8; 33],
                    created_at: 42,
                };
                3
            ],
        };
        let body = borsh::to_vec(&record).unwrap();
        assert_eq!(
            UserRecord::DISCRIMINATOR_LEN + body.len(),
            UserRecord::space_for(3)
        );
    }

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

    #[test]
    fn sender_viewing_pubkey_uses_active_sync_delegate_entry() {
        let record = UserRecord {
            owner: [0u8; 32],
            bump: 255,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: Some([9u8; 32]),
            entries: vec![SyncDelegateEntry {
                sync_pubkey: [3u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 0,
            }],
        };
        assert_eq!(record.sender_viewing_pubkey(), [4u8; 33]);
    }

    #[test]
    fn sender_viewing_pubkey_falls_back_after_revoke() {
        let record = UserRecord {
            owner: [0u8; 32],
            bump: 255,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: None,
            entries: vec![SyncDelegateEntry {
                sync_pubkey: [3u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 0,
            }],
        };
        assert_eq!(record.sender_viewing_pubkey(), [2u8; 33]);
    }
}
