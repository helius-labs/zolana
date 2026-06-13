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
