use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::rent::{ACCOUNT_STORAGE_OVERHEAD, DEFAULT_LAMPORTS_PER_BYTE},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::{CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData},
    state::{
        discriminator::PROTOCOL_CONFIG, PROTOCOL_CONFIG_ACCOUNT_LEN,
        PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES,
    },
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{create_tree::init::set_tree_paused, loader},
};

pub fn process_create_protocol_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateProtocolConfigData,
) -> ProgramResult {
    // [authority(signer+payer), protocol_config(PDA, created here), system_program].
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
    // The creator names the initial authority and must sign as it.
    if !authority_matches(authority, &data.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    validate_merge_authorities(&data.merge_authorities)?;

    // The config is the singleton authority oracle, so it lives at a canonical
    // PDA the program creates itself — a caller can't substitute a config that
    // names a different authority.
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

    let bytes = loader::account_data_mut(tree);
    set_tree_paused(bytes, data.paused).map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    Ok(())
}

pub fn assert_tree_not_paused(tree: &AccountView) -> ProgramResult {
    let bytes = tree
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    if crate::instructions::create_tree::init::is_tree_paused(&bytes)
        .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?
    {
        return Err(ShieldedPoolError::TreePaused.into());
    }
    Ok(())
}

pub struct ProtocolConfigState {
    pub authority: [u8; 32],
    pub merge_authorities: Vec<[u8; 32]>,
}

/// Canonical protocol-config PDA + bump: `[SPP_PROTOCOL_CONFIG_PDA_SEED]`.
fn protocol_config_pda(program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], program_id)
        .ok_or_else(|| ShieldedPoolError::InvalidProtocolConfig.into())
}

fn create_config_pda(
    payer: &AccountView,
    config: &AccountView,
    program_id: &Address,
    bump: u8,
) -> ProgramResult {
    if config.data_len() != 0 {
        // The singleton already exists; do not reinitialize it.
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let bump = [bump];
    let space = PROTOCOL_CONFIG_ACCOUNT_LEN as u64;
    let lamports = (ACCOUNT_STORAGE_OVERHEAD + space) * DEFAULT_LAMPORTS_PER_BYTE;
    let seeds = [Seed::from(SPP_PROTOCOL_CONFIG_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    pinocchio_system::instructions::CreateAccount {
        from: payer,
        to: config,
        lamports,
        space,
        owner: program_id,
    }
    .invoke_signed(core::slice::from_ref(&signer))
    .map_err(|_| ShieldedPoolError::InvalidProtocolConfig.into())
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
        || config.data_len() < PROTOCOL_CONFIG_ACCOUNT_LEN
        || (config_writable && !config.is_writable())
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    Ok((authority, config))
}

pub fn read_protocol_config(
    program_id: &Address,
    account: &AccountView,
) -> Result<ProtocolConfigState, ProgramError> {
    // Pin the authority oracle to the canonical PDA: a substituted config that
    // names a different authority is rejected here, wherever the config is read.
    let (expected, _) = protocol_config_pda(program_id)?;
    if *account.address() != expected
        || !account.owned_by(program_id)
        || account.data_len() < PROTOCOL_CONFIG_ACCOUNT_LEN
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let bytes = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;
    if bytes[0] != PROTOCOL_CONFIG {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&bytes[8..40]);
    let merge_authorities = read_merge_authorities(&bytes)?;
    Ok(ProtocolConfigState {
        authority,
        merge_authorities,
    })
}

fn write_protocol_config(
    bytes: &mut [u8],
    authority: &[u8; 32],
    merge_authorities: &[[u8; 32]],
) -> Result<(), ProgramError> {
    validate_merge_authorities(merge_authorities)?;
    bytes[..PROTOCOL_CONFIG_ACCOUNT_LEN].fill(0);
    bytes[0] = PROTOCOL_CONFIG;
    bytes[8..40].copy_from_slice(authority);
    bytes[40..48].copy_from_slice(&(merge_authorities.len() as u64).to_le_bytes());
    for (index, authority) in merge_authorities.iter().enumerate() {
        let offset = 48 + index * 32;
        bytes[offset..offset + 32].copy_from_slice(authority);
    }
    Ok(())
}

fn validate_merge_authorities(merge_authorities: &[[u8; 32]]) -> Result<(), ProgramError> {
    if merge_authorities.len() > PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    Ok(())
}

fn read_merge_authorities(bytes: &[u8]) -> Result<Vec<[u8; 32]>, ProgramError> {
    let mut count = [0u8; 8];
    count.copy_from_slice(&bytes[40..48]);
    let count = u64::from_le_bytes(count) as usize;
    if count > PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }

    let mut authorities = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 48 + index * 32;
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&bytes[offset..offset + 32]);
        authorities.push(authority);
    }
    Ok(authorities)
}

fn authority_matches(account: &AccountView, authority: &[u8; 32]) -> bool {
    account.address().as_ref() == authority
}
