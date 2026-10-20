use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey as Address;

pub const VIEWING_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub owner: Address,
    pub bump: u8,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; VIEWING_PUBKEY_LEN],
    /// Per-user merge opt-in and the encryption scheme every `merge_transact`
    /// output for this owner must use. `Disabled` rejects `merge_transact`; any
    /// other scheme lets any caller run it with exactly that scheme (see
    /// shielded-pool spec).
    pub merge_encryption: MergeEncryptionScheme,
}

/// The merge output encryption scheme an owner accepts. A delegated merger
/// cannot choose the scheme: the shielded pool rejects a merge whose scheme
/// differs from the owner's record.
///
/// One byte, with the discriminants of the former `merging_enabled: bool`
/// (`false` = 0, `true` = 1), so records written before the scheme existed
/// decode unchanged. Borsh rejects any other byte.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MergeEncryptionScheme {
    Disabled = 0,
    /// Poseidon counter mode under the owner's nullifier-secret-derived key.
    PoseidonCtrV1 = 1,
}

impl MergeEncryptionScheme {
    /// Decodes a scheme byte with the record's own borsh encoding; `None` for
    /// a byte no scheme has.
    pub fn from_byte(byte: u8) -> Option<Self> {
        Self::try_from_slice(&[byte]).ok()
    }
}

impl UserRecord {
    pub const DISCRIMINATOR: u8 = 1;
    pub const DISCRIMINATOR_LEN: usize = 1;
    pub const SIZE: usize =
        Self::DISCRIMINATOR_LEN + 32 + 1 + NULLIFIER_PUBKEY_LEN + VIEWING_PUBKEY_LEN + 1;

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
