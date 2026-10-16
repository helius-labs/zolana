use custom_ring_interface::SetPausedIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, UpdateRingConfigData};

use crate::instructions::{
    loader::{load_authorized_config, validate_spp_program},
    shared::{cpi_spp, parse},
};

#[inline(never)]
pub fn process_set_paused_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetPausedIxData { paused } = parse(data)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let spp_program = iter.next_account("spp_program")?;

    load_authorized_config(program_id, config, authority)?;
    validate_spp_program(core::slice::from_ref(spp_program))?;
    let data = encode_instruction(tag::UPDATE_RING_CONFIG, &UpdateRingConfigData { paused });
    // The ring auth PDA is also SPP's ring authority.
    cpi_spp(program_id, &[&*ring_auth, &*ring_auth], &data)
}
