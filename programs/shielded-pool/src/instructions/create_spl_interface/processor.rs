use pinocchio::{
    cpi::{invoke, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    SHIELDED_POOL_CPI_AUTHORITY, SPL_ASSET_COUNTER_ACCOUNT_LEN, SPL_ASSET_COUNTER_PDA_SEED,
    SPL_ASSET_REGISTRY_ACCOUNT_LEN, SPL_ASSET_REGISTRY_ASSET_ID_END,
    SPL_ASSET_REGISTRY_ASSET_ID_OFFSET, SPL_ASSET_REGISTRY_MAGIC, SPL_ASSET_REGISTRY_MAGIC_END,
    SPL_ASSET_REGISTRY_MAGIC_OFFSET, SPL_ASSET_REGISTRY_MINT_END, SPL_ASSET_REGISTRY_MINT_OFFSET,
    SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_ACCOUNT_LEN,
    SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{loader, protocol_config::processor::read_protocol_config},
    log::log,
};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);
const FIRST_SPL_ASSET_ID: u64 = 2;

pub fn process_create_spl_interface(
    program_id: &Address,
    accounts: &mut [AccountView],
) -> ProgramResult {
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if accounts.len() != 8 {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
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
    let (system_program_slice, tail) = tail.split_at_mut(1);
    let system_program = &system_program_slice[0];
    let token_program = &tail[0];

    if !authority.is_signer()
        || !asset_counter.is_writable()
        || !registry.is_writable()
        || !vault.is_writable()
        || *system_program.address() != SYSTEM_PROGRAM_ID
        || *token_program.address() != Address::from(SPL_TOKEN_PROGRAM_ID)
    {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    let config = read_protocol_config(program_id, protocol_config)?;
    if authority.address().as_ref() != config.authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    let (expected_counter, counter_bump) = derive_pda(&[SPL_ASSET_COUNTER_PDA_SEED], program_id)?;
    let (expected_registry, registry_bump) = derive_pda(
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.address().as_ref()],
        program_id,
    )?;
    let (expected_vault, vault_bump) = derive_pda(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.address().as_ref()],
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
        SPL_ASSET_COUNTER_ACCOUNT_LEN,
        program_id,
        &[SPL_ASSET_COUNTER_PDA_SEED],
        counter_bump,
    )?;
    let asset_id = next_asset_id(program_id, asset_counter)?;

    create_pda_account_if_needed(
        authority,
        registry,
        SPL_ASSET_REGISTRY_ACCOUNT_LEN,
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
    initialize_token_vault(token_program, vault, mint)?;

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
    account: &mut AccountView,
    space: usize,
    owner: &Address,
    seed_prefix: &[&[u8]],
    bump: u8,
) -> ProgramResult {
    if account.data_len() != 0 {
        return Ok(());
    }

    let bump = [bump];
    // Use the minimum-balance helper so creation survives the cold path where an
    // attacker pre-funds the PDA with lamports (top-up + allocate + assign);
    // a raw CreateAccount would fail on a donated balance and DoS this admin ix.
    let result = match seed_prefix {
        [seed] => {
            let seeds = [Seed::from(*seed), Seed::from(&bump)];
            pinocchio_system::create_account_with_minimum_balance_signed(
                account,
                space,
                owner,
                payer,
                None,
                &[Signer::from(&seeds)],
            )
        }
        [seed_a, seed_b] => {
            let seeds = [Seed::from(*seed_a), Seed::from(*seed_b), Seed::from(&bump)];
            pinocchio_system::create_account_with_minimum_balance_signed(
                account,
                space,
                owner,
                payer,
                None,
                &[Signer::from(&seeds)],
            )
        }
        _ => Err(ProgramError::InvalidArgument),
    };
    result.map_err(|_| {
        log("create_spl_interface: PDA account creation failed");
        ProgramError::from(ShieldedPoolError::InvalidSplAssetRegistry)
    })
}

fn derive_pda<const N: usize>(
    seeds: &[&[u8]; N],
    program_id: &Address,
) -> Result<(Address, u8), ProgramError> {
    Address::derive_program_address(seeds, program_id)
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
) -> ProgramResult {
    let instruction_accounts = [
        InstructionAccount::writable(vault.address()),
        InstructionAccount::readonly(mint.address()),
    ];
    let mut instruction_data = [0u8; 33];
    instruction_data[0] = SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR;
    instruction_data[1..33].copy_from_slice(&SHIELDED_POOL_CPI_AUTHORITY);
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &instruction_accounts,
        data: &instruction_data,
    };
    invoke(&instruction, &[vault, mint]).map_err(|_| {
        log("create_spl_interface: SPL vault initialization failed");
        ProgramError::from(ShieldedPoolError::InvalidSplAssetRegistry)
    })
}
