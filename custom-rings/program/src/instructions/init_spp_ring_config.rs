use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, validate_spp_program},
        shared::cpi_spp_signed,
    },
};

/// Registers this ring with SPP by creating its `RingConfig` account -- which is
/// the ring's own `ring_auth` PDA -- through a CPI that PDA signs.
///
/// SPP checks the `ring_auth` derivation at creation time and never again, so
/// this is the single point where the ring's identity is bound on the SPP side.
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
    let config_account = iter.next_account("config")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let system_program = iter.next_account("system_program")?;
    let spp_program = iter.next_account("spp_program")?;

    let ring_authority = load_authorized_config(program_id, config_account, authority)?.authority;
    // The borrow is scoped so the config account is not still borrowed across the
    // CPI.

    validate_spp_program(core::slice::from_ref(spp_program))?;

    let instruction_data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        // The authority-transact rail is governance-owned and starts off; this
        // ring never wants it, since every transaction has to carry an auditor
        // proof. The config is also created inert on a permissioned pool, so
        // governance admits the ring with `set_ring_activation` afterwards.
        &CreateRingConfigData {
            program_id: *program_id,
            authority: ring_authority,
        },
    );

    // SPP's create loader expects exactly `[payer(s), protocol_config,
    // ring_config(w + signer), system_program]`. Our own account list also
    // carries the authority, the ring config and the SPP program, so the CPI list
    // is selected explicitly instead of forwarded whole.
    let cpi_accounts = [&*payer, &*protocol_config, &*ring_auth, &*system_program];
    cpi_spp_signed(program_id, cpi_accounts.as_slice(), &instruction_data)
}
