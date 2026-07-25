use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::{instruction::RegisterData, UserRecord};

use super::{
    common::{check_record_pda, check_system_program, create_record_account, write_record},
    p256_identity::P256IdentityClaim,
};
use crate::error::{fail, UserRegistryError};

/// Creates a per-owner record with static shielded keys and no sync delegate.
///
/// Accounts: `[record (writable), owner (writable signer), system_program]`, plus
/// `[p256_claim (writable), p256_identity_record]` when `data.owner_p256` is set:
/// the record's owner identity must be exclusively its own, see
/// [`P256IdentityClaim`].
pub fn process_register(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: RegisterData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let (fixed, p256_accounts) = tail.split_at_mut(2);
    let owner = &fixed[0];
    let system_program = &fixed[1];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !record.is_writable() {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    check_system_program(system_program)?;

    let owner_address = *owner.address();
    let bump = check_record_pda(record, &owner_address, program_id)?;

    if record.owned_by(program_id) || !record.is_data_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    if let Some(owner_p256) = data.owner_p256 {
        if p256_accounts.len() < 2 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let (claim, identity_record) = p256_accounts.split_at_mut(1);
        let claim = &mut claim[0];
        let identity_record = &identity_record[0];
        P256IdentityClaim {
            claim,
            identity_record,
            payer: owner,
            owner_p256,
            record_owner: owner_address,
        }
        .bind(program_id)?;
    }

    create_record_account(
        record,
        owner,
        &owner_address,
        bump,
        UserRecord::space_for(0),
        program_id,
    )?;

    let state = UserRecord {
        owner: (*owner_address.as_array()).into(),
        bump,
        owner_p256: data.owner_p256,
        nullifier_pubkey: data.nullifier_pubkey,
        viewing_pubkey: data.viewing_pubkey,
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled: false,
    };
    write_record(record, &state)
}
