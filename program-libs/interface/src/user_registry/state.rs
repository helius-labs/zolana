use borsh::{BorshDeserialize, BorshSerialize};

pub const P256_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SyncDelegateEntry {
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub created_at: i64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub owner: [u8; 32],
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub sync_delegate: Option<[u8; 32]>,
    pub entries: Vec<SyncDelegateEntry>,
}

impl UserRecord {
    pub const DISCRIMINATOR_LEN: usize = 8;

    pub fn from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        if data.len() < Self::DISCRIMINATOR_LEN {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "account data shorter than the expected discriminator",
            ));
        }
        Self::try_from_slice(&data[Self::DISCRIMINATOR_LEN..])
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
