use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey as Address;

pub const VIEWING_PUBKEY_LEN: usize = 33;
pub const NULLIFIER_PUBKEY_LEN: usize = 32;

/// Retains the existing Ed25519 registry wire byte without accepting retired owner keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReservedOwnerKey;

impl BorshSerialize for ReservedOwnerKey {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&[0])
    }
}

impl BorshDeserialize for ReservedOwnerKey {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self),
            _ => Err(invalid_user_record("unsupported registry owner key")),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub owner: Address,
    pub bump: u8,
    pub reserved_owner: ReservedOwnerKey,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; VIEWING_PUBKEY_LEN],
    /// Per-user merge opt-in: when `false` `merge_transact` is rejected for this
    /// owner. When `true` any caller may run `merge_transact` for this owner
    /// (see shielded-pool spec).
    pub merging_enabled: bool,
}

impl UserRecord {
    pub const DISCRIMINATOR: u8 = 1;
    pub const DISCRIMINATOR_LEN: usize = 1;
    // Preserve the existing account allocation, including 33 unused padding bytes.
    pub const SIZE: usize =
        Self::DISCRIMINATOR_LEN + 32 + 1 + 1 + 33 + NULLIFIER_PUBKEY_LEN + VIEWING_PUBKEY_LEN + 1;

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
