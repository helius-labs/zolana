use anchor_lang::prelude::*;

use crate::{constants::BN254_FR_MODULUS, error::UserRegistryError};

pub const P256_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

/// One published sync-delegate key pair. Appended on appoint or key rotation.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace)]
pub struct SyncDelegateEntry {
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub created_at: i64,
}

#[account]
pub struct UserRecord {
    pub owner: Pubkey,
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub sync_delegate: Option<Pubkey>,
    pub entries: Vec<SyncDelegateEntry>,
}

impl UserRecord {
    pub const DISCRIMINATOR_LEN: usize = 8;

    pub fn space_for(num_entries: usize) -> usize {
        Self::DISCRIMINATOR_LEN
            + Self::fixed_body_len()
            + 4
            + num_entries * SyncDelegateEntry::INIT_SPACE
    }

    fn fixed_body_len() -> usize {
        // owner + owner_p256 option + nullifier + viewing + sync_delegate option
        32 + (1 + P256_PUBKEY_LEN) + NULLIFIER_PUBKEY_LEN + P256_PUBKEY_LEN + (1 + 32)
    }

    pub fn sender_viewing_pubkey(&self) -> [u8; P256_PUBKEY_LEN] {
        if self.sync_delegate.is_some() {
            self.entries
                .last()
                .map(|entry| entry.viewing_pubkey)
                .unwrap_or(self.viewing_pubkey)
        } else {
            self.viewing_pubkey
        }
    }
}

pub fn validate_p256_pubkey(pubkey: &[u8; P256_PUBKEY_LEN]) -> Result<()> {
    // SEC1 compressed encoding: the only valid prefix bytes are 0x02 and 0x03.
    require!(
        matches!(pubkey[0], 0x02 | 0x03),
        UserRegistryError::InvalidP256Prefix
    );
    Ok(())
}

pub fn validate_optional_p256_pubkey(pubkey: &Option<[u8; P256_PUBKEY_LEN]>) -> Result<()> {
    if let Some(pubkey) = pubkey {
        validate_p256_pubkey(pubkey)?;
    }
    Ok(())
}

pub fn validate_canonical_nullifier_pubkey(
    nullifier_pubkey: &[u8; NULLIFIER_PUBKEY_LEN],
) -> Result<()> {
    require!(
        bytes_be_lt(nullifier_pubkey, &BN254_FR_MODULUS),
        UserRegistryError::NonCanonicalNullifierPubkey
    );
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
        assert_eq!(UserRecord::space_for(0), 176);
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
            owner: Pubkey::default(),
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: Some(Pubkey::new_unique()),
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
            owner: Pubkey::default(),
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
