use custom_ring_interface::SetPausedIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, UpdateRingConfigData};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, validate_spp_program},
        shared::cpi_spp_signed,
    },
};

#[inline(never)]
pub fn process_set_paused_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetPausedIxData { paused } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let paused = match paused {
        0 => false,
        1 => true,
        _ => return Err(CustomRingError::InvalidInstructionData.into()),
    };

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let spp_program = iter.next_account("spp_program")?;

    load_authorized_config(program_id, config_account, authority)?;
    validate_spp_program(core::slice::from_ref(spp_program))?;

    let instruction_data = encode_instruction(
        tag::UPDATE_RING_CONFIG,
        &UpdateRingConfigData {
            ring_authority_transact_is_enabled: false,
            paused,
        },
    );
    // The ring auth PDA is also SPP's ring authority.
    cpi_spp_signed(program_id, &[&*ring_auth, &*ring_auth], &instruction_data)
}
