use bytemuck::Zeroable;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::{
        CreateProtocolConfigData, CreateZoneConfigData, PauseTreeData, UpdateProtocolConfigData,
        UpdateZoneConfigData, UpdateZoneConfigOwnerData,
    },
    state::{
        discriminator::{PROTOCOL_CONFIG, TREE_ACCOUNT_DISCRIMINATOR, ZONE_CONFIG},
        ProtocolConfig, ZoneConfig, PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES,
    },
    SPP_PROTOCOL_CONFIG_PDA_SEED, SPP_ZONE_CONFIG_PDA_SEED,
};
use zolana_tree::TreeAccount;

use crate::{error::ShieldedPoolError, instructions::loader};

pub fn process_create_protocol_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateProtocolConfigData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let authority = &head[0];
    let (config_slice, _) = tail.split_at_mut(1);
    let config = &mut config_slice[0];

    if !authority.is_signer() || !config.is_writable() {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    if !authority_matches(authority, &data.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    validate_merge_authorities(&data.merge_authorities)?;

    let (expected, bump) = protocol_config_pda(program_id)?;
    if *config.address() != expected {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    create_config_pda(authority, config, program_id, bump)?;

    let bytes = loader::account_data_mut(config);
    write_protocol_config(bytes, &data.authority, &data.merge_authorities)?;
    Ok(())
}

pub fn process_update_protocol_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateProtocolConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts, true)?;
    let current = read_protocol_config(program_id, config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    validate_merge_authorities(&data.merge_authorities)?;

    let bytes = loader::account_data_mut(config);
    write_protocol_config(bytes, &data.authority, &data.merge_authorities)?;
    Ok(())
}

pub fn process_pause_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: PauseTreeData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let (head, tail) = accounts.split_at_mut(2);
    let authority = &head[0];
    let config = &head[1];
    let tree = &mut tail[0];

    if !authority.is_signer() || !tree.is_writable() || !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let current = read_protocol_config(program_id, config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    let mut tree_account =
        TreeAccount::from_account_view_mut_allow_paused(tree, program_id, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(ShieldedPoolError::from)?;
    tree_account.set_paused(data.paused);
    Ok(())
}

pub fn process_create_zone_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateZoneConfigData,
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (payer_slice, tail) = accounts.split_at_mut(1);
    let payer = &payer_slice[0];
    let (config_slice, tail) = tail.split_at_mut(1);
    let config = &mut config_slice[0];
    let zone_auth = &tail[0];

    if !payer.is_signer() || !config.is_writable() {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    validate_zone_auth(zone_auth, &data.program_id, data.zone_auth_bump)?;

    let (expected, bump) = zone_config_pda(program_id, &data.program_id)?;
    if *config.address() != expected || data.zone_config_bump != bump {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    create_zone_config_pda(payer, config, program_id, &data.program_id, bump)?;

    let bytes = loader::account_data_mut(config);
    write_zone_config(
        bytes,
        &data.authority,
        data.zone_authority_transact_is_enabled,
        bump,
    )
}

pub fn process_update_zone_config_owner(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateZoneConfigOwnerData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_zone_config(program_id, accounts)?;
    let current = read_zone_config(config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let bytes = loader::account_data_mut(config);
    write_zone_config(bytes, &data.new_authority, current.enabled(), current.bump)
}

pub fn process_update_zone_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateZoneConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_zone_config(program_id, accounts)?;
    let current = read_zone_config(config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let bytes = loader::account_data_mut(config);
    write_zone_config(
        bytes,
        &current.authority,
        data.zone_authority_transact_is_enabled,
        current.bump,
    )
}

fn protocol_config_pda(program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], program_id)
        .ok_or_else(|| ShieldedPoolError::InvalidProtocolConfig.into())
}

fn zone_config_pda(
    program_id: &Address,
    policy_program_id: &[u8; 32],
) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(&[SPP_ZONE_CONFIG_PDA_SEED, policy_program_id], program_id)
        .ok_or_else(|| ShieldedPoolError::InvalidZoneConfig.into())
}

fn create_config_pda(
    payer: &AccountView,
    config: &mut AccountView,
    program_id: &Address,
    bump: u8,
) -> ProgramResult {
    let bump = [bump];
    let seeds = [Seed::from(SPP_PROTOCOL_CONFIG_PDA_SEED), Seed::from(&bump)];
    create_pda(
        payer,
        config,
        program_id,
        ProtocolConfig::SIZE,
        &seeds,
        ShieldedPoolError::InvalidProtocolConfig,
    )
}

fn create_zone_config_pda(
    payer: &AccountView,
    config: &mut AccountView,
    program_id: &Address,
    policy_program_id: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    let bump = [bump];
    let seeds = [
        Seed::from(SPP_ZONE_CONFIG_PDA_SEED),
        Seed::from(policy_program_id.as_slice()),
        Seed::from(&bump),
    ];
    create_pda(
        payer,
        config,
        program_id,
        ZoneConfig::SIZE,
        &seeds,
        ShieldedPoolError::InvalidZoneConfig,
    )
}

fn create_pda(
    payer: &AccountView,
    account: &mut AccountView,
    program_id: &Address,
    space: usize,
    seeds: &[Seed],
    error: ShieldedPoolError,
) -> ProgramResult {
    if account.data_len() != 0 {
        return Err(error.into());
    }
    // Minimum-balance helper handles the cold path (attacker-donated lamports)
    // that a raw CreateAccount would fail on, preventing creation DoS.
    let signer = Signer::from(seeds);
    pinocchio_system::create_account_with_minimum_balance_signed(
        account,
        space,
        program_id,
        payer,
        None,
        core::slice::from_ref(&signer),
    )
    .map_err(|_| error.into())
}

fn load_authority_and_config<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    config_writable: bool,
) -> Result<(&'a AccountView, &'a mut AccountView), ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let authority = &head[0];
    let config = &mut tail[0];
    if !authority.is_signer()
        || !config.owned_by(program_id)
        || config.data_len() != ProtocolConfig::SIZE
        || (config_writable && !config.is_writable())
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    Ok((authority, config))
}

fn load_authority_and_zone_config<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
) -> Result<(&'a AccountView, &'a mut AccountView), ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let authority = &head[0];
    let config = &mut tail[0];
    if !authority.is_signer()
        || !config.is_writable()
        || !config.owned_by(program_id)
        || config.data_len() != ZoneConfig::SIZE
    {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok((authority, config))
}

pub fn read_protocol_config(
    program_id: &Address,
    account: &AccountView,
) -> Result<ProtocolConfig, ProgramError> {
    let (expected, _) = protocol_config_pda(program_id)?;
    if *account.address() != expected
        || !account.owned_by(program_id)
        || account.data_len() != ProtocolConfig::SIZE
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let bytes = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;
    if bytes[0] != PROTOCOL_CONFIG {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    // Owned copy: `ProtocolConfig` is `Copy`, so the borrow is released here.
    Ok(*bytemuck::from_bytes::<ProtocolConfig>(
        &bytes[..ProtocolConfig::SIZE],
    ))
}

fn write_protocol_config(
    bytes: &mut [u8],
    authority: &[u8; 32],
    merge_authorities: &[[u8; 32]],
) -> Result<(), ProgramError> {
    validate_merge_authorities(merge_authorities)?;
    let cfg: &mut ProtocolConfig = bytemuck::from_bytes_mut(&mut bytes[..ProtocolConfig::SIZE]);
    *cfg = ProtocolConfig::zeroed();
    cfg.discriminator = PROTOCOL_CONFIG;
    cfg.authority = *authority;
    cfg.merge_authority_count = merge_authorities.len() as u64;
    for (index, authority) in merge_authorities.iter().enumerate() {
        cfg.merge_authorities[index] = *authority;
    }
    Ok(())
}

fn read_zone_config(account: &AccountView) -> Result<ZoneConfig, ProgramError> {
    if account.data_len() != ZoneConfig::SIZE {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let bytes = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
    if bytes[0] != ZONE_CONFIG {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    // Owned copy: `ZoneConfig` is `Copy`, so the borrow is released here.
    Ok(*bytemuck::from_bytes::<ZoneConfig>(
        &bytes[..ZoneConfig::SIZE],
    ))
}

fn write_zone_config(
    bytes: &mut [u8],
    authority: &[u8; 32],
    enabled: bool,
    bump: u8,
) -> ProgramResult {
    if bytes.len() != ZoneConfig::SIZE {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let cfg: &mut ZoneConfig = bytemuck::from_bytes_mut(&mut bytes[..ZoneConfig::SIZE]);
    *cfg = ZoneConfig::zeroed();
    cfg.discriminator = ZONE_CONFIG;
    cfg.authority = *authority;
    cfg.zone_authority_transact_is_enabled = u8::from(enabled);
    cfg.bump = bump;
    Ok(())
}

fn validate_zone_auth(
    zone_auth: &AccountView,
    policy_program_id: &[u8; 32],
    zone_auth_bump: u8,
) -> ProgramResult {
    if !zone_auth.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let bump = [zone_auth_bump];
    let expected = derive_zone_auth(policy_program_id, &bump)?;
    if *zone_auth.address() != expected {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(())
}

fn derive_zone_auth(policy_program_id: &[u8; 32], bump: &[u8; 1]) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(
            &[zolana_interface::ZONE_AUTH_PDA_SEED, bump.as_slice()],
            &Address::from(*policy_program_id),
        )
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (policy_program_id, bump);
        Err(ShieldedPoolError::InvalidZoneConfig.into())
    }
}

fn validate_merge_authorities(merge_authorities: &[[u8; 32]]) -> Result<(), ProgramError> {
    if merge_authorities.len() > PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    Ok(())
}

fn authority_matches(account: &AccountView, authority: &[u8; 32]) -> bool {
    account.address().as_ref() == authority
}
