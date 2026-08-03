//! Decoder for the Squads smart-account program's `Settings` account.
//!
//! Layout (Anchor borsh, from the upstream program source
//! Squads-Protocol/smart-account-program,
//! `programs/squads_smart_account_program/src/state/settings.rs`):
//! discriminator[8] | seed u128 | settings_authority | threshold u16 |
//! time_lock u32 | transaction_index u64 | stale_transaction_index u64 |
//! archival_authority Option<Pubkey> | archivable_after u64 | bump u8 |
//! signers Vec<{ key, permissions mask u8 }> | (trailing fields unused here).
//!
//! Parsed sequentially because the borsh `Option` shifts the signers offset.
//!
//! Two layout facts are pinned against REAL accounts by the localnet test
//! `created_settings_accounts_decode_to_their_creation_members`
//! (`program-tests/spp-test-validator/tests/lifecycle.rs`), which creates
//! settings accounts on a validator running the mainnet-dumped program binary
//! and asserts the decoded member keys equal the creation keys:
//!
//! - The discriminator is the legacy Anchor scheme
//!   `sha256("account:Settings")[0..8]` — still the default `Discriminator`
//!   derivation in the pinned anchor-lang 1.1 the program is built with.
//! - `archivable_after` (u64) sits between `archival_authority` and `bump`:
//!   a wrong position would shift the signers vec and break the member
//!   assertion.

use std::fmt;

use solana_pubkey::Pubkey;

/// Legacy Anchor account discriminator: `sha256("account:Settings")[0..8]`.
pub const SETTINGS_ACCOUNT_DISCRIMINATOR: [u8; 8] =
    [0xdf, 0xb3, 0xa3, 0xbe, 0xb1, 0xe0, 0x43, 0xad];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// The account data ends before `field` is fully read.
    Truncated { field: &'static str },
    /// A cursor advance overflowed (corrupt length prefix).
    OffsetOverflow { field: &'static str },
    /// The first 8 bytes are not the legacy Anchor `Settings` discriminator.
    DiscriminatorMismatch,
    /// The borsh option tag of `archival_authority` is neither 0 nor 1.
    UnknownArchivalAuthorityTag(u8),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(f, "settings account truncated at {field}"),
            Self::OffsetOverflow { field } => {
                write!(f, "settings account offset overflow at {field}")
            }
            Self::DiscriminatorMismatch => write!(f, "settings account discriminator mismatch"),
            Self::UnknownArchivalAuthorityTag(tag) => {
                write!(
                    f,
                    "settings account has an unknown archival_authority tag {tag}"
                )
            }
        }
    }
}

impl std::error::Error for SettingsError {}

fn take<'a>(
    data: &'a [u8],
    cursor: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], SettingsError> {
    let end = cursor
        .checked_add(len)
        .ok_or(SettingsError::OffsetOverflow { field })?;
    let bytes = data
        .get(*cursor..end)
        .ok_or(SettingsError::Truncated { field })?;
    *cursor = end;
    Ok(bytes)
}

/// Decode the `seed` a Squads smart-account `Settings` account was created
/// with. See the module docs for the pinned layout.
pub fn settings_seed(data: &[u8]) -> Result<u128, SettingsError> {
    let mut cursor = 0;
    let discriminator = take(data, &mut cursor, 8, "discriminator")?;
    if discriminator != SETTINGS_ACCOUNT_DISCRIMINATOR {
        return Err(SettingsError::DiscriminatorMismatch);
    }
    Ok(u128::from_le_bytes(
        take(data, &mut cursor, 16, "seed")?
            .try_into()
            .expect("16 bytes"),
    ))
}

/// Decode the signer (member) keys of a Squads smart-account `Settings`
/// account. See the module docs for the pinned layout.
pub fn settings_member_keys(data: &[u8]) -> Result<Vec<Pubkey>, SettingsError> {
    let mut cursor = 0;
    let discriminator = take(data, &mut cursor, 8, "discriminator")?;
    if discriminator != SETTINGS_ACCOUNT_DISCRIMINATOR {
        return Err(SettingsError::DiscriminatorMismatch);
    }
    take(data, &mut cursor, 16, "seed")?;
    take(data, &mut cursor, 32, "settings_authority")?;
    take(data, &mut cursor, 2, "threshold")?;
    take(data, &mut cursor, 4, "time_lock")?;
    take(data, &mut cursor, 8, "transaction_index")?;
    take(data, &mut cursor, 8, "stale_transaction_index")?;
    match take(data, &mut cursor, 1, "archival_authority tag")? {
        [0] => {}
        [1] => {
            take(data, &mut cursor, 32, "archival_authority")?;
        }
        [tag] => return Err(SettingsError::UnknownArchivalAuthorityTag(*tag)),
        _ => unreachable!("one byte was read"),
    }
    take(data, &mut cursor, 8, "archivable_after")?;
    take(data, &mut cursor, 1, "bump")?;
    let signer_count = u32::from_le_bytes(
        take(data, &mut cursor, 4, "signers length")?
            .try_into()
            .expect("4 bytes"),
    );
    let mut keys = Vec::with_capacity(signer_count.min(1024) as usize);
    for _ in 0..signer_count {
        let key = take(data, &mut cursor, 32, "signer key")?;
        take(data, &mut cursor, 1, "signer permissions")?;
        keys.push(Pubkey::new_from_array(key.try_into().expect("32 bytes")));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    /// Squads `Settings` account bytes per the pinned layout (module docs),
    /// with `signers` members.
    fn settings_fixture(archival_authority: Option<Pubkey>, signers: &[(Pubkey, u8)]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&SETTINGS_ACCOUNT_DISCRIMINATOR);
        data.extend_from_slice(&1u128.to_le_bytes()); // seed
        data.extend_from_slice(&[0u8; 32]); // settings_authority
        data.extend_from_slice(&1u16.to_le_bytes()); // threshold
        data.extend_from_slice(&0u32.to_le_bytes()); // time_lock
        data.extend_from_slice(&0u64.to_le_bytes()); // transaction_index
        data.extend_from_slice(&0u64.to_le_bytes()); // stale_transaction_index
        match archival_authority {
            Some(authority) => {
                data.push(1);
                data.extend_from_slice(&authority.to_bytes());
            }
            None => data.push(0),
        }
        data.extend_from_slice(&0u64.to_le_bytes()); // archivable_after
        data.push(255); // bump
        data.extend_from_slice(&(signers.len() as u32).to_le_bytes());
        for (key, mask) in signers {
            data.extend_from_slice(&key.to_bytes());
            data.push(*mask);
        }
        data
    }

    #[test]
    fn discriminator_is_the_legacy_anchor_scheme() {
        // anchor-lang 1.1 (pinned by the workspace) still derives the default
        // account discriminator as sha256("account:<Name>")[0..8].
        let expected = Sha256::digest(b"account:Settings");
        assert_eq!(SETTINGS_ACCOUNT_DISCRIMINATOR, expected[..8]);
    }

    #[test]
    fn decodes_settings_member_keys() {
        let members = [(Pubkey::new_unique(), 0b111), (Pubkey::new_unique(), 0b001)];
        let data = settings_fixture(None, &members);
        let keys = settings_member_keys(&data).expect("valid settings");
        assert_eq!(keys, [members[0].0, members[1].0]);
    }

    #[test]
    fn decodes_settings_with_archival_authority_set() {
        // A set archival_authority occupies 32 bytes and shifts the signers.
        let member = Pubkey::new_unique();
        let data = settings_fixture(Some(Pubkey::new_unique()), &[(member, 0b111)]);
        let keys = settings_member_keys(&data).expect("valid settings");
        assert_eq!(keys, [member]);
    }

    #[test]
    fn settings_decoder_fails_closed() {
        let member = Pubkey::new_unique();
        let data = settings_fixture(None, &[(member, 0b111)]);
        // Truncated inside the signers vec.
        assert!(settings_member_keys(&data[..data.len() - 10]).is_err());
        // Wrong discriminator.
        let mut bad_discriminator = data.clone();
        *bad_discriminator.get_mut(7).expect("discriminator byte") ^= 0xff;
        assert_eq!(
            settings_member_keys(&bad_discriminator),
            Err(SettingsError::DiscriminatorMismatch)
        );
        // Unknown archival_authority option tag (byte 78: after the 8-byte
        // discriminator and the fixed seed/authority/threshold/lock/index
        // fields).
        let mut bad_tag = data;
        *bad_tag.get_mut(78).expect("option tag byte") = 9;
        assert_eq!(
            settings_member_keys(&bad_tag),
            Err(SettingsError::UnknownArchivalAuthorityTag(9))
        );
    }
}
