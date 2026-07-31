use pinocchio::{address::Address, error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{error::ShieldedPoolError, merge_utils::owner_proof_input_hash_compressed};
use zolana_user_registry_interface::{
    state::UserRecord, USER_RECORD_SEED, USER_REGISTRY_PROGRAM_ID,
};

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
    pub fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
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

/// Load and validate the `user_record`: owned by the registry program, stored at
/// the canonical PDA for its owner, and containing a valid `UserRecord`
/// discriminator/body. Returns the per-user `merging_enabled` opt-in alongside
/// the rail-selected owner identity; the processor rejects the merge when it is
/// `false`. The owner identity is rail-selected by `eddsa_owner`: a Solana owner
/// derives `signing_pk_field` from the registry account `owner` (ed25519), a P256
/// owner from `owner_p256`.
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
    let (expected_record, expected_bump) =
        Address::find_program_address(&[USER_RECORD_SEED, record.owner.as_ref()], &registry_id);
    if account.address() != &expected_record || record.bump != expected_bump {
        return Err(ShieldedPoolError::InvalidUserRecord.into());
    }
    let merging_enabled = record.merging_enabled;
    let mut signing_view_tag = [0u8; 32];
    let signing_pk_field = if eddsa_owner {
        signing_view_tag.copy_from_slice(record.owner.as_array());
        hash_bytes(record.owner.as_array())?
    } else {
        let owner_p256 = record
            .owner_p256
            .ok_or(ShieldedPoolError::InvalidUserRecord)?;
        signing_view_tag.copy_from_slice(&owner_p256[1..]);
        owner_proof_input_hash_compressed(&owner_p256)
            .map_err(|_| ShieldedPoolError::InvalidUserRecord)?
    };
    Ok(UserPkFields {
        signing_pk_field,
        signing_view_tag,
        merging_enabled,
    })
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
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

        let error = match MergeTransactAccounts::validate_and_parse(&mut accounts) {
            Ok(_) => panic!("invalid System Program must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidSystemProgram as u32)
        );
    }

    fn user_record_data(record: &UserRecord) -> Vec<u8> {
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize record"));
        data.resize(UserRecord::SIZE, 0);
        data
    }

    #[test]
    fn loads_only_the_canonical_registry_pda() {
        let owner = [7u8; 32];
        let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
        let (record_address, bump) =
            Address::find_program_address(&[USER_RECORD_SEED, &owner], &registry_id);
        let record = UserRecord {
            owner: owner.into(),
            bump,
            owner_p256: None,
            nullifier_pubkey: [8u8; 32],
            viewing_pubkey: [2u8; 33],
            merging_enabled: true,
        };
        let account = get_account_view(
            record_address.to_bytes(),
            USER_REGISTRY_PROGRAM_ID,
            false,
            false,
            false,
            user_record_data(&record),
        );

        let loaded = load_user_record(&account, true).expect("canonical registry record");

        assert!(loaded.merging_enabled);
        assert_eq!(loaded.signing_view_tag, owner);
    }

    #[test]
    fn rejects_program_owned_record_at_a_noncanonical_address() {
        let owner = [7u8; 32];
        let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
        let (_record_address, bump) =
            Address::find_program_address(&[USER_RECORD_SEED, &owner], &registry_id);
        let record = UserRecord {
            owner: owner.into(),
            bump,
            owner_p256: None,
            nullifier_pubkey: [8u8; 32],
            viewing_pubkey: [2u8; 33],
            merging_enabled: true,
        };
        let account = get_account_view(
            [9u8; 32],
            USER_REGISTRY_PROGRAM_ID,
            false,
            false,
            false,
            user_record_data(&record),
        );

        let error = match load_user_record(&account, true) {
            Ok(_) => panic!("noncanonical record must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidUserRecord as u32)
        );
    }

    #[test]
    fn rejects_wrong_user_record_discriminator() {
        let owner = [7u8; 32];
        let registry_id = Address::from(USER_REGISTRY_PROGRAM_ID);
        let (record_address, bump) =
            Address::find_program_address(&[USER_RECORD_SEED, &owner], &registry_id);
        let record = UserRecord {
            owner: owner.into(),
            bump,
            owner_p256: None,
            nullifier_pubkey: [8u8; 32],
            viewing_pubkey: [2u8; 33],
            merging_enabled: true,
        };
        let mut data = user_record_data(&record);
        data[0] = UserRecord::DISCRIMINATOR.wrapping_add(1);
        let account = get_account_view(
            record_address.to_bytes(),
            USER_REGISTRY_PROGRAM_ID,
            false,
            false,
            false,
            data,
        );

        assert_eq!(
            load_user_record(&account, true).map(|_| ()),
            Err(ProgramError::Custom(
                ShieldedPoolError::InvalidUserRecord as u32
            ))
        );
    }
}
