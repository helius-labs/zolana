use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::instructions::{
    loader::{load_authorized_config, load_registry, validate_spp_program},
    shared::{no_data, RingAuth},
};

/// Creates SPP's `RingConfig` at `ring_auth`, the one point where SPP checks the ring's identity.
#[inline(never)]
pub fn process_init_spp_ring_config_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let system_program = iter.next_account("system_program")?;
    let spp_program = iter.next_account("spp_program")?;

    // 1. The config authority registers a policy ring only once its table is set.
    let has_policy = load_authorized_config(program_id, config, authority)?.has_policy();
    validate_spp_program(core::slice::from_ref(spp_program))?;
    if has_policy {
        load_registry(program_id, iter.next_account("registry")?)?.policy_hash()?;
    }
    // 2. The program signs as the ring PDA.
    let placed = RingAuth::derive(program_id)?.check_account(ring_auth)?;

    let data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        // Rail off and config inert until governance runs `set_ring_activation`.
        &CreateRingConfigData {
            program_id: *program_id,
            // SPP admin actions on the ring pass only through the ring program.
            authority: *ring_auth.address(),
        },
    );
    let cpi_accounts = [&*payer, &*protocol_config, &*ring_auth, &*system_program];
    placed.invoke(cpi_accounts.as_slice(), &data)
}
