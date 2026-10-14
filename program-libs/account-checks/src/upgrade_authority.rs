use solana_account_view::AccountView;
use solana_address::Address;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_program_error::ProgramError;
use solana_sdk_ids::bpf_loader_upgradeable;

/// Whether `authority` is the nonzero upgrade authority of the loader-v3 program
/// `program_id`. Another loader, an unset or zero authority and malformed state are `false`.
pub fn is_upgrade_authority(
    program_id: &Address,
    authority: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> Result<bool, ProgramError> {
    if program.address() != program_id || !program.owned_by(&bpf_loader_upgradeable::ID) {
        return Ok(false);
    }
    let Some(UpgradeableLoaderState::Program {
        programdata_address,
    }) = loader_state(program)?
    else {
        return Ok(false);
    };
    if program_data.address().as_array() != programdata_address.as_array()
        || !program_data.owned_by(&bpf_loader_upgradeable::ID)
    {
        return Ok(false);
    }
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address: Some(upgrade_authority),
        ..
    }) = loader_state(program_data)?
    else {
        return Ok(false);
    };
    let upgrade_authority = upgrade_authority.to_bytes();
    Ok(upgrade_authority != [0; 32] && upgrade_authority == authority.address().to_bytes())
}

/// bincode reads only the enum, the trailing ELF bytes of program data stay untouched.
fn loader_state(account: &AccountView) -> Result<Option<UpgradeableLoaderState>, ProgramError> {
    let data = account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    Ok(
        bincode::serde::decode_from_slice(&data, bincode::config::legacy())
            .ok()
            .map(|(state, _)| state),
    )
}
