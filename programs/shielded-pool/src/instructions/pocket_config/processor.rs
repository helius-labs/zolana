use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::{
    instruction::{CreatePocketConfigData, UpdatePocketConfigData, UpdatePocketConfigOwnerData},
    state::{discriminator::POCKET_CONFIG, POCKET_CONFIG_ACCOUNT_LEN},
    POCKET_AUTH_PDA_SEED, SPP_POCKET_CONFIG_PDA_SEED,
};

use crate::error::ShieldedPoolError;

pub fn process_create_pocket_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreatePocketConfigData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (payer_slice, tail) = accounts.split_at_mut(1);
    let payer = &payer_slice[0];
    let (config_slice, auth_slice) = tail.split_at_mut(1);
    let config = &mut config_slice[0];
    let pocket_auth = &auth_slice[0];

    if !payer.is_signer()
        || !config.is_writable()
        || !config.owned_by(program_id)
        || config.data_len() < POCKET_CONFIG_ACCOUNT_LEN
        || !pocket_auth.is_signer()
    {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    validate_pocket_auth(pocket_auth, &data)?;
    validate_pocket_config_address(config, program_id, &data)?;

    // SAFETY: `config` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { config.borrow_unchecked_mut() };
    if bytes[..POCKET_CONFIG_ACCOUNT_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    write_pocket_config(
        bytes,
        &data.authority,
        data.pocket_authority_transact_is_enabled,
        data.pocket_config_bump,
    );
    Ok(())
}

pub fn process_update_pocket_config_owner(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdatePocketConfigOwnerData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts)?;
    let current = read_pocket_config(config)?;
    if authority.address().as_ref() != current.authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    // SAFETY: `config` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { config.borrow_unchecked_mut() };
    write_pocket_config(
        bytes,
        &data.new_authority,
        current.pocket_authority_transact_is_enabled,
        current.bump,
    );
    Ok(())
}

pub fn process_update_pocket_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdatePocketConfigData,
) -> ProgramResult {
    let (authority, config) = load_authority_and_config(program_id, accounts)?;
    let current = read_pocket_config(config)?;
    if authority.address().as_ref() != current.authority || current.authority == [0u8; 32] {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    // SAFETY: `config` is writable and uniquely borrowed from `accounts`.
    let bytes = unsafe { config.borrow_unchecked_mut() };
    write_pocket_config(
        bytes,
        &current.authority,
        data.pocket_authority_transact_is_enabled,
        current.bump,
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub struct PocketConfigState {
    pub authority: [u8; 32],
    pub pocket_authority_transact_is_enabled: bool,
    pub bump: u8,
}

pub fn read_pocket_config(account: &AccountView) -> Result<PocketConfigState, ProgramError> {
    if account.data_len() < POCKET_CONFIG_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    let bytes = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidPocketConfig)?;
    if bytes[0] != POCKET_CONFIG {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&bytes[8..40]);
    Ok(PocketConfigState {
        authority,
        pocket_authority_transact_is_enabled: bytes[40] != 0,
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
        || config.data_len() < POCKET_CONFIG_ACCOUNT_LEN
    {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    Ok((authority, config))
}

fn write_pocket_config(bytes: &mut [u8], authority: &[u8; 32], enabled: bool, bump: u8) {
    bytes[..POCKET_CONFIG_ACCOUNT_LEN].fill(0);
    bytes[0] = POCKET_CONFIG;
    bytes[8..40].copy_from_slice(authority);
    bytes[40] = u8::from(enabled);
    bytes[41] = bump;
}

fn validate_pocket_auth(
    pocket_auth: &AccountView,
    data: &CreatePocketConfigData,
) -> Result<(), ProgramError> {
    let bump = [data.pocket_auth_bump];
    let policy_program_id = Address::from(data.policy_program_id);
    let expected =
        create_program_address(&[POCKET_AUTH_PDA_SEED, bump.as_slice()], &policy_program_id)?;
    if *pocket_auth.address() != expected {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    Ok(())
}

fn validate_pocket_config_address(
    config: &AccountView,
    program_id: &Address,
    data: &CreatePocketConfigData,
) -> Result<(), ProgramError> {
    let bump = [data.pocket_config_bump];
    let expected = create_program_address(
        &[
            SPP_POCKET_CONFIG_PDA_SEED,
            data.policy_program_id.as_slice(),
            bump.as_slice(),
        ],
        program_id,
    )?;
    if *config.address() != expected {
        return Err(ShieldedPoolError::InvalidPocketConfig.into());
    }
    Ok(())
}

fn create_program_address(seeds: &[&[u8]], program_id: &Address) -> Result<Address, ProgramError> {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        Address::create_program_address(seeds, program_id)
            .map_err(|_| ShieldedPoolError::InvalidPocketConfig.into())
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (seeds, program_id);
        Err(ShieldedPoolError::InvalidPocketConfig.into())
    }
}
