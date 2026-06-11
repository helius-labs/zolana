use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::{
    instruction::{CreateZoneConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData},
    state::{discriminator::ZONE_CONFIG, ZONE_CONFIG_ACCOUNT_LEN},
    ZONE_AUTH_PDA_SEED, SPP_ZONE_CONFIG_PDA_SEED,
};

use crate::{error::ShieldedPoolError, instructions::loader};

pub fn process_create_zone_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateZoneConfigData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (payer_slice, tail) = accounts.split_at_mut(1);
    let payer = &payer_slice[0];
    let (config_slice, auth_slice) = tail.split_at_mut(1);
    let config = &mut config_slice[0];
    let zone_auth = &auth_slice[0];

    if !payer.is_signer()
        || !config.is_writable()
        || !config.owned_by(program_id)
        || config.data_len() < ZONE_CONFIG_ACCOUNT_LEN
        || !zone_auth.is_signer()
    {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    validate_zone_auth(zone_auth, &data)?;
    validate_zone_config_address(config, program_id, &data)?;

    let bytes = loader::account_data_mut(config);
    if bytes[..ZONE_CONFIG_ACCOUNT_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    write_zone_config(
        bytes,
        &data.authority,
        data.zone_authority_transact_is_enabled,
        data.zone_config_bump,
    );
    Ok(())
}

pub fn process_update_zone_config_owner(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateZoneConfigOwnerData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts)?;
    let current = read_zone_config(config)?;
    if authority.address().as_ref() != current.authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let bytes = loader::account_data_mut(config);
    write_zone_config(
        bytes,
        &data.new_authority,
        current.zone_authority_transact_is_enabled,
        current.bump,
    );
    Ok(())
}

pub fn process_update_zone_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateZoneConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts)?;
    let current = read_zone_config(config)?;
    if authority.address().as_ref() != current.authority || current.authority == [0u8; 32] {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let bytes = loader::account_data_mut(config);
    write_zone_config(
        bytes,
        &current.authority,
        data.zone_authority_transact_is_enabled,
        current.bump,
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub struct ZoneConfigState {
    pub authority: [u8; 32],
    pub zone_authority_transact_is_enabled: bool,
    pub bump: u8,
}

pub fn read_zone_config(account: &AccountView) -> Result<ZoneConfigState, ProgramError> {
    if account.data_len() < ZONE_CONFIG_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let bytes = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
    if bytes[0] != ZONE_CONFIG {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&bytes[8..40]);
    Ok(ZoneConfigState {
        authority,
        zone_authority_transact_is_enabled: bytes[40] != 0,
        bump: bytes[41],
    })
}

fn load_authority_and_config<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
) -> Result<(&'a AccountView, &'a mut AccountView), ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (authority_slice, config_slice) = accounts.split_at_mut(1);
    let authority = &authority_slice[0];
    let config = &mut config_slice[0];
    if !authority.is_signer()
        || !config.is_writable()
        || !config.owned_by(program_id)
        || config.data_len() < ZONE_CONFIG_ACCOUNT_LEN
    {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok((authority, config))
}

fn write_zone_config(bytes: &mut [u8], authority: &[u8; 32], enabled: bool, bump: u8) {
    bytes[..ZONE_CONFIG_ACCOUNT_LEN].fill(0);
    bytes[0] = ZONE_CONFIG;
    bytes[8..40].copy_from_slice(authority);
    bytes[40] = u8::from(enabled);
    bytes[41] = bump;
}

fn validate_zone_auth(
    zone_auth: &AccountView,
    data: &CreateZoneConfigData,
) -> Result<(), ProgramError> {
    let bump = [data.zone_auth_bump];
    let policy_program_id = Address::from(data.policy_program_id);
    let expected =
        create_program_address(&[ZONE_AUTH_PDA_SEED, bump.as_slice()], &policy_program_id)?;
    if *zone_auth.address() != expected {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(())
}

fn validate_zone_config_address(
    config: &AccountView,
    program_id: &Address,
    data: &CreateZoneConfigData,
) -> Result<(), ProgramError> {
    let bump = [data.zone_config_bump];
    let expected = create_program_address(
        &[
            SPP_ZONE_CONFIG_PDA_SEED,
            data.policy_program_id.as_slice(),
            bump.as_slice(),
        ],
        program_id,
    )?;
    if *config.address() != expected {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(())
}

fn create_program_address(seeds: &[&[u8]], program_id: &Address) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(seeds, program_id)
            .map_err(|_| ShieldedPoolError::InvalidZoneConfig.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (seeds, program_id);
        Err(ShieldedPoolError::InvalidZoneConfig.into())
    }
}
