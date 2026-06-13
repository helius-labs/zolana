use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::rent::{ACCOUNT_STORAGE_OVERHEAD, DEFAULT_LAMPORTS_PER_BYTE},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::CreateSplInterfaceData, SHIELDED_POOL_CPI_AUTHORITY,
    SPL_ASSET_COUNTER_ACCOUNT_LEN, SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_ACCOUNT_LEN,
    SPL_ASSET_REGISTRY_ASSET_ID_END, SPL_ASSET_REGISTRY_ASSET_ID_OFFSET, SPL_ASSET_REGISTRY_MAGIC,
    SPL_ASSET_REGISTRY_MAGIC_END, SPL_ASSET_REGISTRY_MAGIC_OFFSET, SPL_ASSET_REGISTRY_MINT_END,
    SPL_ASSET_REGISTRY_MINT_OFFSET, SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED,
    SPL_TOKEN_PROGRAM_ID,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{loader, protocol_config::processor::read_protocol_config},
    log::log,
};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);
const SPL_TOKEN_ACCOUNT_LEN: u64 = 165;
const SPL_INITIALIZE_ACCOUNT3_DISCRIMINATOR: u8 = 18;
const FIRST_SPL_ASSET_ID: u64 = 2;

pub fn process_create_spl_interface(
    program_id: &Address,
    accounts: &mut [AccountView],
    _data: CreateSplInterfaceData,
) -> ProgramResult {
    if accounts.len() < 9 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let (head, tail) = accounts.split_at_mut(2);
    let authority = &head[0];
    let protocol_config = &head[1];
    let (counter_slice, tail) = tail.split_at_mut(1);
    let asset_counter = &mut counter_slice[0];
    let (registry_slice, tail) = tail.split_at_mut(1);
    let registry = &mut registry_slice[0];
    let (mint_slice, tail) = tail.split_at_mut(1);
    let mint = &mint_slice[0];
    let (vault_slice, tail) = tail.split_at_mut(1);
    let vault = &mut vault_slice[0];
    let (cpi_authority_slice, tail) = tail.split_at_mut(1);
    let cpi_authority = &cpi_authority_slice[0];
    let (system_program_slice, tail) = tail.split_at_mut(1);
    let system_program = &system_program_slice[0];
    let token_program = &tail[0];

    if !authority.is_signer()
        || !asset_counter.is_writable()
        || !registry.is_writable()
        || !vault.is_writable()
        || *system_program.address() != SYSTEM_PROGRAM_ID
        || *token_program.address() != Address::from(SPL_TOKEN_PROGRAM_ID)
        || *cpi_authority.address() != Address::from(SHIELDED_POOL_CPI_AUTHORITY)
    {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    let config = read_protocol_config(program_id, protocol_config)?;
    if authority.address().as_ref() != config.authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    let (expected_counter, counter_bump) = derive_pda_1(SPL_ASSET_COUNTER_PDA_SEED, program_id)?;
    let (expected_registry, registry_bump) = derive_pda_2(
        SPL_ASSET_REGISTRY_PDA_SEED,
        mint.address().as_ref(),
        program_id,
    )?;
    let (expected_vault, vault_bump) = derive_pda_2(
        SPL_ASSET_VAULT_PDA_SEED,
        mint.address().as_ref(),
        program_id,
    )?;

    if *asset_counter.address() != expected_counter
        || *registry.address() != expected_registry
        || *vault.address() != expected_vault
    {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    create_pda_account_if_needed(
        authority,
        asset_counter,
        SPL_ASSET_COUNTER_ACCOUNT_LEN as u64,
        program_id,
        &[SPL_ASSET_COUNTER_PDA_SEED],
        counter_bump,
    )?;
    let asset_id = next_asset_id(program_id, asset_counter)?;

    create_pda_account_if_needed(
        authority,
        registry,
        SPL_ASSET_REGISTRY_ACCOUNT_LEN as u64,
        program_id,
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.address().as_ref()],
        registry_bump,
    )?;
    write_asset_registry(program_id, registry, mint.address(), asset_id)?;
    bump_asset_counter(program_id, asset_counter, asset_id)?;

    create_pda_account_if_needed(
        authority,
        vault,
        SPL_TOKEN_ACCOUNT_LEN,
        token_program.address(),
        &[SPL_ASSET_VAULT_PDA_SEED, mint.address().as_ref()],
        vault_bump,
    )?;
    initialize_token_vault(token_program, vault, mint, cpi_authority)?;

    Ok(())
}

fn next_asset_id(program_id: &Address, counter: &mut AccountView) -> Result<u64, ProgramError> {
    if !counter.owned_by(program_id) || counter.data_len() < SPL_ASSET_COUNTER_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    let counter_data = loader::account_data_mut(counter);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&counter_data[..8]);
    match u64::from_le_bytes(bytes) {
        0 => Ok(FIRST_SPL_ASSET_ID),
        id if id >= FIRST_SPL_ASSET_ID => Ok(id),
        _ => Err(ShieldedPoolError::InvalidSplAssetRegistry.into()),
    }
}

fn bump_asset_counter(
    program_id: &Address,
    counter: &mut AccountView,
    assigned_asset_id: u64,
) -> Result<(), ProgramError> {
    if !counter.owned_by(program_id) || counter.data_len() < SPL_ASSET_COUNTER_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }
    let next = assigned_asset_id
        .checked_add(1)
        .ok_or(ShieldedPoolError::InvalidSplAssetRegistry)?;
    loader::account_data_mut(counter)[..8].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

fn create_pda_account_if_needed(
    payer: &AccountView,
    account: &AccountView,
    space: u64,
    owner: &Address,
    seed_prefix: &[&[u8]],
    bump: u8,
) -> ProgramResult {
    if account.data_len() != 0 {
        return Ok(());
    }

    let bump = [bump];
    let lamports = (ACCOUNT_STORAGE_OVERHEAD + space) * DEFAULT_LAMPORTS_PER_BYTE;
    match seed_prefix {
        [seed] => {
            let seeds = [Seed::from(*seed), Seed::from(&bump)];
            let signer = Signer::from(&seeds);
            pinocchio_system::instructions::CreateAccount {
                from: payer,
                to: account,
                lamports,
                space,
                owner,
            }
            .invoke_signed(core::slice::from_ref(&signer))
        }
        [seed_a, seed_b] => {
            let seeds = [Seed::from(*seed_a), Seed::from(*seed_b), Seed::from(&bump)];
            let signer = Signer::from(&seeds);
            pinocchio_system::instructions::CreateAccount {
                from: payer,
                to: account,
                lamports,
                space,
                owner,
            }
            .invoke_signed(core::slice::from_ref(&signer))
        }
        _ => Err(ProgramError::InvalidArgument),
    }
    .map_err(|_| {
        log("create_spl_interface: PDA account creation failed");
        ProgramError::from(ShieldedPoolError::InvalidSplAssetRegistry)
    })
}

fn derive_pda_1(seed: &[u8], program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(&[seed], program_id)
        .ok_or(ShieldedPoolError::InvalidSplAssetRegistry.into())
}

fn derive_pda_2(
    seed_a: &[u8],
    seed_b: &[u8],
    program_id: &Address,
) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(&[seed_a, seed_b], program_id)
        .ok_or(ShieldedPoolError::InvalidSplAssetRegistry.into())
}

fn write_asset_registry(
    program_id: &Address,
    registry: &mut AccountView,
    mint: &Address,
    asset_id: u64,
) -> Result<(), ProgramError> {
    if !registry.owned_by(program_id) || registry.data_len() < SPL_ASSET_REGISTRY_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    let registry_data = loader::account_data_mut(registry);
    if registry_data[..SPL_ASSET_REGISTRY_ACCOUNT_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }
    registry_data[..SPL_ASSET_REGISTRY_ACCOUNT_LEN].fill(0);
    registry_data[SPL_ASSET_REGISTRY_MAGIC_OFFSET..SPL_ASSET_REGISTRY_MAGIC_END]
        .copy_from_slice(&SPL_ASSET_REGISTRY_MAGIC);
    registry_data[SPL_ASSET_REGISTRY_MINT_OFFSET..SPL_ASSET_REGISTRY_MINT_END]
        .copy_from_slice(mint.as_ref());
    registry_data[SPL_ASSET_REGISTRY_ASSET_ID_OFFSET..SPL_ASSET_REGISTRY_ASSET_ID_END]
        .copy_from_slice(&asset_id.to_le_bytes());
    Ok(())
}

fn initialize_token_vault(
    token_program: &AccountView,
    vault: &AccountView,
    mint: &AccountView,
    cpi_authority: &AccountView,
) -> ProgramResult {
    let instruction_accounts = [
        InstructionAccount::writable(vault.address()),
        InstructionAccount::readonly(mint.address()),
    ];
    let mut instruction_data = [0u8; 33];
    instruction_data[0] = SPL_INITIALIZE_ACCOUNT3_DISCRIMINATOR;
    instruction_data[1..33].copy_from_slice(cpi_authority.address().as_ref());
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &instruction_accounts,
        data: &instruction_data,
    };
    invoke_signed(&instruction, &[vault, mint], &[]).map_err(|_| {
        log("create_spl_interface: SPL vault initialization failed");
        ProgramError::from(ShieldedPoolError::InvalidSplAssetRegistry)
    })
}
