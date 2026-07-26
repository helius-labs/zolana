use pinocchio::{address::Address, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, merge_utils::owner_pk_field_compressed};
use zolana_user_registry_interface::{state::UserRecord, USER_REGISTRY_PROGRAM_ID};

use crate::instructions::hash::solana_pk_hash;

/// Validated accounts for `merge_transact`, in loader order: `input_tree` and
/// `output_tree` (writable), `payer` (signer, pays fees), `user_record`
/// (read-only).
pub struct MergeTransactAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub user_record: &'a AccountView,
}

impl<'a> MergeTransactAccounts<'a> {
    pub fn validate_and_parse(
        _program_id: &Address,
        accounts: &'a mut [AccountView],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        let payer = iter.next_signer("payer")?;
        let user_record = iter.next_account("user_record")?;
        let system_program = iter.next_account("system_program")?;
        if !pinocchio_system::check_id(system_program.address()) {
            return Err(ShieldedPoolError::InvalidSystemProgram.into());
        }
        Ok(Self {
            input_tree,
            output_tree,
            payer,
            user_record,
        })
    }
}

/// The registry-derived owner identity public inputs: the already-derived
/// `pk_field` of the signing key and its owner-pubkey index tag. Feeding these
/// into the recomputed public-input hash binds the proof to the registered key.
///
/// `signing_view_tag` is the owner-pubkey index tag for the merged output (the
/// confidential default-zone tag): the signing key's 32-byte x-coordinate for a
/// P256 owner, or the full ed25519 key. Rail-selected like `signing_pk_field`.
pub struct UserPkFields {
    pub signing_pk_field: [u8; 32],
    pub signing_view_tag: [u8; 32],
    pub merging_enabled: bool,
}

/// Load and validate the `user_record`: owned by the registry program with a
/// valid `UserRecord` discriminator/body. Returns the per-user `merging_enabled`
/// opt-in alongside the rail-selected owner identity; the processor rejects the
/// merge when it is `false`. The owner identity is rail-selected by `eddsa_owner`:
/// a Solana owner derives `signing_pk_field` from the registry account `owner`
/// (ed25519), a P256 owner from `owner_p256`.
#[inline(never)]
pub fn load_user_record(
    account: &AccountView,
    eddsa_owner: bool,
) -> Result<UserPkFields, ProgramError> {
    let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
    if !account.owned_by(&registry_id) {
        return Err(ShieldedPoolError::InvalidUserRecord.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidUserRecord)?;
    let record = UserRecord::try_from_account_data(&data)
        .map_err(|_| ShieldedPoolError::InvalidUserRecord)?;
    let merging_enabled = record.merging_enabled;
    let mut signing_view_tag = [0u8; 32];
    let signing_pk_field = if eddsa_owner {
        signing_view_tag.copy_from_slice(record.owner.as_array());
        solana_pk_hash(record.owner.as_array())?
    } else {
        let owner_p256 = record
            .owner_p256
            .ok_or(ShieldedPoolError::InvalidUserRecord)?;
        signing_view_tag.copy_from_slice(&owner_p256[1..]);
        owner_pk_field_compressed(&owner_p256).map_err(|_| ShieldedPoolError::InvalidUserRecord)?
    };
    Ok(UserPkFields {
        signing_pk_field,
        signing_view_tag,
        merging_enabled,
    })
}

#[cfg(test)]
mod tests {
    use pinocchio::error::ProgramError;
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    use super::*;

    #[test]
    fn rejects_invalid_system_program_with_specific_error() {
        let mut accounts = [
            get_account_view([1; 32], crate::ID.to_bytes(), false, true, false, vec![]),
            get_account_view([2; 32], crate::ID.to_bytes(), false, true, false, vec![]),
            get_account_view([3; 32], [0; 32], true, true, false, vec![]),
            get_account_view([4; 32], [0; 32], false, false, false, vec![]),
            get_account_view([5; 32], [0; 32], false, false, true, vec![]),
        ];

        let error = match MergeTransactAccounts::validate_and_parse(&crate::ID, &mut accounts) {
            Ok(_) => panic!("invalid System Program must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidSystemProgram as u32)
        );
    }
}
