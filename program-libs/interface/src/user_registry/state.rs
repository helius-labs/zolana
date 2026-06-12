use borsh::{BorshDeserialize, BorshSerialize};

pub const P256_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SyncDelegateEntry {
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub created_at: i64,
}

/// Read-only mirror of the on-chain Anchor `UserRecord` account body. Field
/// order and borsh layout are locked to the program by a parity test in
/// `light-program-test`. Use [`UserRecord::from_account_data`] to parse raw
/// account bytes; the body is preceded by an 8-byte Anchor discriminator.
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
    /// Length of the Anchor account discriminator prepended on-chain.
    pub const DISCRIMINATOR_LEN: usize = 8;

    /// Deserialize from raw account data, skipping the 8-byte Anchor account
    /// discriminator. Returns an error if the data is too short or malformed.
    pub fn from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        if data.len() < Self::DISCRIMINATOR_LEN {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "account data shorter than the Anchor discriminator",
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
