use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey as Address;

pub const P256_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub owner: Address,
    pub bump: u8,
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
    /// Per-user merge opt-in: when `false` `merge_transact` is rejected for this
    /// owner; when `true` any caller may run `merge_transact` for this owner
    /// (see shielded-pool spec).
    pub merging_enabled: bool,
}

impl UserRecord {
    pub const DISCRIMINATOR: u8 = 1;
    pub const DISCRIMINATOR_LEN: usize = 1;
    pub const SIZE: usize = Self::DISCRIMINATOR_LEN
        + 32
        + 1
        + (1 + P256_PUBKEY_LEN)
        + NULLIFIER_PUBKEY_LEN
        + P256_PUBKEY_LEN
        + 1;

    pub fn try_from_account_data(data: &[u8]) -> borsh::io::Result<Self> {
        if data.len() != Self::SIZE {
            return Err(invalid_user_record("invalid user record size"));
        }
        match data.split_first() {
            Some((&Self::DISCRIMINATOR, body)) => Self::deserialize(&mut &*body),
            _ => Err(invalid_user_record("missing user record discriminator")),
        }
    }
}

fn invalid_user_record(message: &'static str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}
