use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey as Address;

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
    pub owner: Address,
    pub bump: u8,
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    pub sync_delegate: Option<[u8; 32]>,
    pub entries: Vec<SyncDelegateEntry>,
    /// Per-user merge opt-in: when `false` `merge_transact` is rejected for this
    /// owner; when `true` any caller may run `merge_transact` for this owner
    /// (see shielded-pool spec).
    pub merging_enabled: bool,
}

/// Binds one P256 owner identity to the single record allowed to carry it.
///
/// Owner identity drops the SEC1 parity prefix (`owner_pk_field_compressed`), so
/// `0x02 || x` and `0x03 || x` are the same owner and the claim is keyed by `x`
/// alone. `owner` is the registered Solana owner whose record holds the key; the
/// registry refuses to hand the same identity to a second record, which is what
/// lets `merge_transact` treat the `owner_p256` in a canonical record as that
/// record's own key.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256OwnerClaim {
    pub owner: Address,
    pub bump: u8,
}

impl P256OwnerClaim {
    pub const DISCRIMINATOR: u8 = 2;
    pub const DISCRIMINATOR_LEN: usize = 1;
    pub const SPACE: usize = Self::DISCRIMINATOR_LEN + 32 + 1;

    pub fn try_from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        match data.split_first() {
            Some((&Self::DISCRIMINATOR, body)) => Self::deserialize(&mut &*body),
            _ => Err(invalid_user_record(
                "missing p256 owner claim discriminator",
            )),
        }
    }
}

/// The 32-byte x-coordinate of a SEC1-compressed P256 key: the owner identity the
/// claim and the merge rail both key on.
pub const fn owner_p256_identity(owner_p256: &[u8; P256_PUBKEY_LEN]) -> [u8; 32] {
    let mut identity = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        identity[i] = owner_p256[i + 1];
        i += 1;
    }
    identity
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
            + 1 // merging_enabled bool
    }

    pub fn try_from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        match data.split_first() {
            Some((&Self::DISCRIMINATOR, body)) => Self::deserialize(&mut &*body),
            _ => Err(invalid_user_record("missing user record discriminator")),
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

fn invalid_user_record(message: &'static str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}
