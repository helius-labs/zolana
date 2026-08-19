use pinocchio::{address::address_eq, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, validate_spp_program},
        shared::cpi_spp_signed,
    },
};

/// Registers this ring with SPP by creating its `RingConfig` account -- which is
/// the ring's own `ring_auth` PDA -- through a CPI that PDA signs.
///
/// SPP checks the `ring_auth` derivation at creation time and never again, so
/// this is the single point where the ring's identity is bound on the SPP side.
#[inline(never)]
pub fn process_init_spp_ring_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
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

    // The borrow is scoped so the config account is not still borrowed across the
    // CPI.
    let ring_authority = {
        let config = load_config(config_account)?;
        if !address_eq(&config.authority, authority.address()) {
            return Err(CustomRingError::UnauthorizedAuthority.into());
        }
        config.authority
    };

    validate_spp_program(core::slice::from_ref(spp_program))?;

    let instruction_data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        &CreateRingConfigData {
            program_id: crate::ID,
            authority: ring_authority,
            // This ring exposes no authority-transact rail: every transaction has
            // to carry an auditor proof, so the shortcut stays disabled.
            ring_authority_transact_is_enabled: false,
        },
    );

    // SPP's create loader expects exactly `[payer(s), protocol_config,
    // ring_config(w + signer), system_program]`. Our own account list also
    // carries the authority, the ring config and the SPP program, so the CPI list
    // is selected explicitly instead of forwarded whole.
    let cpi_accounts = [&*payer, &*protocol_config, &*ring_auth, &*system_program];
    cpi_spp_signed(cpi_accounts.as_slice(), &instruction_data)
}
