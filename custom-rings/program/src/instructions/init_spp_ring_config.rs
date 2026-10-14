use custom_ring_interface::{CustomRingError, PolicyConfig};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::instructions::{
    loader::{load, load_authorized_config, validate_spp_program},
    shared::{cpi_spp, SppSigners},
};

/// Creates SPP's `RingConfig` at the ring's own `ring_auth` PDA, the one point
/// where SPP checks the ring's identity.
#[inline(never)]
pub fn process_init_spp_ring_config_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let system_program = iter.next_account("system_program")?;
    let spp_program = iter.next_account("spp_program")?;

    let has_policy = load_authorized_config(program_id, config, authority)?.has_policy;
    validate_spp_program(core::slice::from_ref(spp_program))?;
    if has_policy != 0 {
        load::<PolicyConfig>(program_id, iter.next_account("policy_config")?)?;
    }

    // Rail off and config inert until governance runs `set_ring_activation`, SPP
    // admin actions on the ring pass only through the ring program.
    let data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        &CreateRingConfigData {
            program_id: *program_id,
            authority: *ring_auth.address(),
        },
    );
    // SPP's create layout is `[payer, protocol_config, ring_config(w, s), system_program]`.
    let cpi_accounts = [&*payer, &*protocol_config, &*ring_auth, &*system_program];
    cpi_spp(
        program_id,
        cpi_accounts.as_slice(),
        &data,
        SppSigners::RingAuth,
    )
}
