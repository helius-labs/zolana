use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::{
    instruction::{CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData},
    state::{discriminator::PROTOCOL_CONFIG, PROTOCOL_CONFIG_ACCOUNT_LEN},
};

use crate::{error::ShieldedPoolError, instructions::create_pool_tree::init::set_pool_tree_paused};

pub fn process_create_protocol_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateProtocolConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts, true)?;
    if !authority_matches(authority, &data.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    // SAFETY: `config` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { config.borrow_unchecked_mut() };
    if bytes[..PROTOCOL_CONFIG_ACCOUNT_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    write_protocol_config(bytes, &data.authority);
    Ok(())
}

pub fn process_update_protocol_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateProtocolConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts, true)?;
    let current = read_protocol_config(config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    // SAFETY: `config` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { config.borrow_unchecked_mut() };
    write_protocol_config(bytes, &data.new_authority);
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

    if !authority.is_signer()
        || !config.owned_by(program_id)
        || !tree.is_writable()
        || !tree.owned_by(program_id)
    {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let current = read_protocol_config(config)?;
    if !authority_matches(authority, &current.authority) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    // SAFETY: `tree` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { tree.borrow_unchecked_mut() };
    set_pool_tree_paused(bytes, data.paused)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    Ok(())
}

pub fn assert_tree_not_paused(tree: &AccountView) -> ProgramResult {
    let bytes = tree
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    if crate::instructions::create_pool_tree::init::is_pool_tree_paused(&bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?
    {
        return Err(ShieldedPoolError::PoolTreePaused.into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct ProtocolConfigState {
    pub authority: [u8; 32],
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

pub fn read_protocol_config(account: &AccountView) -> Result<ProtocolConfigState, ProgramError> {
    if account.data_len() < PROTOCOL_CONFIG_ACCOUNT_LEN {
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
    Ok(ProtocolConfigState { authority })
}

fn write_protocol_config(bytes: &mut [u8], authority: &[u8; 32]) {
    bytes[..PROTOCOL_CONFIG_ACCOUNT_LEN].fill(0);
    bytes[0] = PROTOCOL_CONFIG;
    bytes[8..40].copy_from_slice(authority);
}

fn authority_matches(account: &AccountView, authority: &[u8; 32]) -> bool {
    account.address().as_ref() == authority
}
