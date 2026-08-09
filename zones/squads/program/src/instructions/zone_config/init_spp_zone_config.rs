use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{encode_instruction, tag, CreateRingConfigData};
use zolana_squads_interface::{error::SquadsZoneError, RING_AUTH_PDA_SEED};

use super::loader::load_zone_config;
use crate::shared::{
    cpi::{invoke_zone_signed, validate_spp_program},
    pda::verify_pda,
};

/// `init_spp_zone_config` (tag 16): register this zone with the SPP by
/// creating its `zone_config` account there. Must run once before any
/// settlement can go through the SPP.
///
/// Accounts: `[authority (signer, writable, fee payer), zone_config
/// (readonly, this program's own config), protocol_config (readonly, SPP's),
/// ring_auth (writable, the SPP account being created), system_program
/// (readonly), spp_program (readonly)]`.
///
/// Only the recorded `zone_config.authority` may run this. `ring_auth` is this
/// program's own canonical `[b"ring_auth"]` PDA -- verified here, then signed
/// for via `invoke_signed` so SPP sees a real signature on the account it
/// creates.
#[inline(never)]
pub fn process_init_spp_zone_config_ix(
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let authority = accounts
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = accounts
        .get(1)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let protocol_config = accounts
        .get(2)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let ring_auth = accounts
        .get(3)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let system_program = accounts
        .get(4)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let spp_program = accounts
        .get(5)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let config = load_zone_config(zone_config)?;
    if config.authority == Address::default() {
        return Err(SquadsZoneError::ConfigFrozen.into());
    }
    if authority.address() != &config.authority {
        return Err(SquadsZoneError::AuthorityMismatch.into());
    }

    let ring_auth_bump = verify_pda(ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_spp_program(spp_program)?;

    // SPP's `create_zone_config` treats `data.program_id` as the zone program
    // whose `ring_auth` PDA is being registered -- this program's own id, not
    // SPP's. `authority` is this zone's SPP-side authority. The zone-authority
    // rail is enabled: smart-account-owned spends (sync `transact` and async
    // `execute_proposal`) settle signatureless through SPP's
    // `zone_authority_transact`, which this program CPIs only after verifying the
    // zone proof (and, async, an approved proposal).
    let zone_config_data = CreateRingConfigData {
        program_id: crate::ID,
        authority: config.authority,
        ring_authority_transact_is_enabled: true,
    };
    let instruction_data = encode_instruction(tag::CREATE_RING_CONFIG, &zone_config_data);

    // SPP's `process_create_zone_config` account order is
    // `[payer, protocol_config, zone_config, system_program]`. `zone_config` is
    // this zone's `ring_auth` PDA, which `invoke_zone_signed` flips to signer
    // and signs for.
    let cpi_accounts: [&AccountView; 4] = [authority, protocol_config, ring_auth, system_program];
    invoke_zone_signed::<4>(&cpi_accounts, &instruction_data, ring_auth_bump)
}
