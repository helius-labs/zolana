use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};
use zolana_squads_interface::{error::SquadsRingError, RING_AUTH_PDA_SEED};

use super::loader::load_ring_config;
use crate::shared::{
    cpi::{invoke_ring_signed, validate_spp_program},
    pda::verify_pda,
};

/// `init_spp_ring_config` (tag 16): register this ring with the SPP by
/// creating its `ring_config` account there. Must run once before any
/// settlement can go through the SPP.
///
/// Accounts: `[authority (signer, writable, fee payer), ring_config
/// (readonly, this program's own config), protocol_config (readonly, SPP's),
/// ring_auth (writable, the SPP account being created), system_program
/// (readonly), spp_program (readonly)]`.
///
/// Only the recorded `ring_config.authority` may run this. `ring_auth` is this
/// program's own canonical `[b"ring_auth"]` PDA -- verified here, then signed
/// for via `invoke_signed` so SPP sees a real signature on the account it
/// creates.
#[inline(never)]
pub fn process_init_spp_ring_config_ix(
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let authority = accounts
        .first()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_config = accounts
        .get(1)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let protocol_config = accounts
        .get(2)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_auth = accounts
        .get(3)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let system_program = accounts
        .get(4)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let spp_program = accounts
        .get(5)
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let config = load_ring_config(ring_config)?;
    if config.authority == Address::default() {
        return Err(SquadsRingError::ConfigFrozen.into());
    }
    if authority.address() != &config.authority {
        return Err(SquadsRingError::AuthorityMismatch.into());
    }

    let ring_auth_bump = verify_pda(ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_spp_program(spp_program)?;

    // SPP's `create_ring_config` treats `data.program_id` as the ring program
    // whose `ring_auth` PDA is being registered -- this program's own id, not
    // SPP's. `authority` is this ring's SPP-side authority. The ring-authority
    // rail is enabled: smart-account-owned spends (sync `transact` and async
    // `execute_proposal`) settle signatureless through SPP's
    // `ring_authority_transact`, which this program CPIs only after verifying the
    // ring proof (and, async, an approved proposal).
    let spp_config_data = CreateRingConfigData {
        program_id: crate::ID,
        authority: config.authority,
        ring_authority_transact_is_enabled: true,
    };
    let instruction_data = encode_instruction(tag::CREATE_RING_CONFIG, &spp_config_data);

    // SPP's `process_create_ring_config` account order is
    // `[payer, protocol_config, ring_config, system_program]`, where SPP's
    // `ring_config` slot takes this ring's `ring_auth` PDA, not the Squads
    // config above. `invoke_ring_signed` flips it to signer and signs for it.
    let cpi_accounts: [&AccountView; 4] = [authority, protocol_config, ring_auth, system_program];
    invoke_ring_signed::<4>(&cpi_accounts, &instruction_data, ring_auth_bump)
}
