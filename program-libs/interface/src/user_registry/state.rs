use borsh::{BorshDeserialize, BorshSerialize};

pub const P256_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

/// One sync-delegate epoch: the delegate wallet at append time plus its keys.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncDelegateEntry {
    pub delegate: [u8; 32],
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub created_at: i64,
}

impl SyncDelegateEntry {
    pub const SERIALIZED_LEN: usize = 32 + P256_PUBKEY_LEN + P256_PUBKEY_LEN + 8;
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub owner: [u8; 32],
    pub bump: u8,
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub sync_delegate: Option<[u8; 32]>,
    pub entries: Vec<SyncDelegateEntry>,
}

impl UserRecord {
    pub const DISCRIMINATOR: u8 = 1;
    pub const DISCRIMINATOR_LEN: usize = 1;

    pub fn space_for(num_entries: usize) -> usize {
        Self::DISCRIMINATOR_LEN
            + 32
            + 1
            + (1 + P256_PUBKEY_LEN)
            + NULLIFIER_PUBKEY_LEN
            + P256_PUBKEY_LEN
            + (1 + 32)
            + 4
            + num_entries * SyncDelegateEntry::SERIALIZED_LEN
    }

    pub fn from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        match data.split_first() {
            Some((&Self::DISCRIMINATOR, body)) => Self::deserialize(&mut &*body),
            _ => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "missing user record discriminator",
            )),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_serializes_delegate_before_keys() {
        let entry = SyncDelegateEntry {
            delegate: [1u8; 32],
            sync_pubkey: [2u8; 33],
            viewing_pubkey: [3u8; 33],
            created_at: 99,
        };
        let bytes = borsh::to_vec(&entry).unwrap();
        assert_eq!(bytes.len(), SyncDelegateEntry::SERIALIZED_LEN);
        assert_eq!(&bytes[..32], &[1u8; 32]);
    }

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
                    delegate: [5u8; 32],
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
    fn sender_viewing_pubkey_uses_active_sync_delegate_entry() {
        let record = UserRecord {
            owner: [0u8; 32],
            bump: 255,
            owner_p256: None,
            nullifier_pubkey: [1u8; 32],
            viewing_pubkey: [2u8; 33],
            sync_delegate: Some([9u8; 32]),
            entries: vec![SyncDelegateEntry {
                delegate: [9u8; 32],
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
                delegate: [9u8; 32],
                sync_pubkey: [3u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 0,
            }],
        };
        assert_eq!(record.sender_viewing_pubkey(), [2u8; 33]);
    }
}
