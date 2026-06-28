use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateZoneConfigData,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};

use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_create_zone_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = CreateZoneConfigData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("payer")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let zone_config = iter.next_mut("zone_config")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    // The zone config account IS the zone's `zone_auth` PDA. It must sign its own
    // creation (the zone CPIs this instruction with `invoke_signed(["zone_auth",
    // bump])`), and this is the SOLE place the derivation is ever checked. Every
    // later zone instruction only loads the account by discriminator and requires
    // its signature -- never re-deriving.
    if !zone_config.is_signer() {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    // Canonical derivation (find_program_address): never trust a bump from
    // instruction data for account creation.
    let (expected, zone_auth_bump) = derive_zone_auth(&data.program_id);
    if *zone_config.address() != expected {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }

    {
        let protocol = load_protocol_config(protocol_config)?;
        if !protocol.allows_permissionless_zone_creation()
            && protocol
                .check_zone_creation_authority(payer.address())
                .is_err()
        {
            return Err(ShieldedPoolError::UnauthorizedCaller.into());
        }
    }

    // `zone_config`'s signature is propagated from the zone program's outer
    // `invoke_signed`, so SPP supplies no seeds; it only sets owner = SPP so the
    // program can store the config in the zone's own PDA.
    pinocchio_system::create_account_with_minimum_balance(
        zone_config,
        ZoneConfig::SIZE,
        &crate::ID,
        payer,
        None,
    )
    .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;

    let mut bytes = zone_config
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let cfg: &mut ZoneConfig = bytemuck::from_bytes_mut(&mut bytes[..]);
    cfg.discriminator = ZONE_CONFIG;
    cfg.authority = data.authority;
    cfg.program_id = data.program_id;
    cfg.zone_authority_transact_is_enabled = u8::from(data.zone_authority_transact_is_enabled);
    cfg.bump = zone_auth_bump;
    Ok(())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_zone_auth(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[zolana_interface::ZONE_AUTH_PDA_SEED], program_id)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_zone_auth(_program_id: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}
