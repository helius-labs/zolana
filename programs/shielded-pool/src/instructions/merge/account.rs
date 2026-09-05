use crate::instructions::shared::caused_by;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{error::ShieldedPoolError, merge_utils::owner_proof_input_hash_compressed};
use zolana_user_registry_interface::{
    state::UserRecord, USER_RECORD_SEED, USER_REGISTRY_PROGRAM_ID,
};

/// Validated accounts for `merge_transact`, in loader order: `input_tree` and
/// `output_tree` (writable), `payer` (signer, pays fees), `user_record`
/// (read-only), System Program, the program account (for the `emit_event`
/// self-CPI), then one writable nullifier PDA per input.
pub struct MergeTransactAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub user_record: &'a AccountView,
    pub nullifier_pdas: &'a mut [AccountView],
}

impl<'a> MergeTransactAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        input_count: usize,
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
        let shielded_pool_program = iter.next_account("shielded_pool_program")?;
        if !address_eq(shielded_pool_program.address(), &crate::ID) {
            return Err(ProgramError::IncorrectProgramId);
        }
        // One contiguous slice, sized by the instruction's declared input
        // count rather than by a compile-time constant.
        let nullifier_pdas = iter.next_slice_mut(input_count, "nullifier_pda")?;
        if !iter.iterator_is_empty() {
            return Err(ShieldedPoolError::InvalidMergeShape.into());
        }
        Ok(Self {
            input_tree,
            output_tree,
            payer,
            user_record,
            nullifier_pdas,
        })
    }
}

/// The registry-derived owner identity public inputs: the already-derived
/// `pk_field` of the signing key and its owner-pubkey index tag. Feeding these
/// into the recomputed public-input hash binds the proof to the registered key.
///
/// `signing_view_tag` is the owner-pubkey index tag for the merged output (the
/// confidential default-ring tag): the signing key's 32-byte x-coordinate for a
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
        .map_err(caused_by(ShieldedPoolError::InvalidUserRecord))?;
    let record = UserRecord::try_from_account_data(&data)
        .map_err(caused_by(ShieldedPoolError::InvalidUserRecord))?;
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
            .map_err(caused_by(ShieldedPoolError::InvalidUserRecord))?
    };
    Ok(UserPkFields {
        signing_pk_field,
        signing_view_tag,
        merging_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    fn account(address: [u8; 32], signer: bool, writable: bool) -> AccountView {
        get_account_view(address, [0; 32], signer, writable, false, Vec::new())
    }

    #[test]
    fn rejects_accounts_after_declared_nullifier_pdas() {
        let mut accounts = [
            account([1; 32], false, true),
            account([2; 32], false, true),
            account([3; 32], true, false),
            account([4; 32], false, false),
            account([0; 32], false, false),
            account(crate::ID.to_bytes(), false, false),
            account([5; 32], false, true),
            account([6; 32], false, false),
        ];

        let error = match MergeTransactAccounts::validate_and_parse(&mut accounts, 1) {
            Ok(_) => panic!("trailing account must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidMergeShape as u32)
        );
    }
}
