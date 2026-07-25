use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::instruction::UpdateKeysData;

use super::{
    common::{check_record_pda_with_bump, check_system_program, read_record, write_record},
    p256_identity::P256IdentityClaim,
};
use crate::error::{fail, UserRegistryError};

/// Updates the shielded keys stored in an existing user record.
///
/// Accounts: `[record (writable), owner (signer)]`, plus `[system_program,
/// p256_claim (writable), p256_identity_record]` when `data.owner_p256` is set,
/// which claims that owner identity for this record exactly as registration does.
/// The previously claimed identity stays reserved for this owner, so a rotation is
/// reversible.
pub fn process_update_keys(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateKeysData,
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let (fixed, p256_accounts) = tail.split_at_mut(1);
    let owner = &fixed[0];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;
    if state.owner.as_array() != owner.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }

    if let Some(owner_p256) = data.owner_p256 {
        if p256_accounts.len() < 3 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let (system_program, rest) = p256_accounts.split_at_mut(1);
        let (claim, identity_record) = rest.split_at_mut(1);
        let claim = &mut claim[0];
        let identity_record = &identity_record[0];
        check_system_program(&system_program[0])?;
        P256IdentityClaim {
            claim,
            identity_record,
            payer: owner,
            owner_p256,
            record_owner: *owner.address(),
        }
        .bind(program_id)?;
    }

    state.owner_p256 = data.owner_p256;
    state.nullifier_pubkey = data.nullifier_pubkey;
    state.viewing_pubkey = data.viewing_pubkey;
    write_record(record, &state)
}
