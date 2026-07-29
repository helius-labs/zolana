//! Example dapp for the sanctioned batching pattern: app policy checks plus a
//! CPI into shielded-pool `BatchTransact`. The app proof never enters the fold.
//! A mixed-key app+SPP fold gives no CU gain (docs/batching/no-boost.md). A
//! same-vk batch of N pure-shielded transfers saves CU and settles atomically.

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::invoke_with_bounds,
    instruction::{InstructionAccount, InstructionView},
};
use pinocchio::{
    address::{address_eq, declare_id},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_interface::{instruction::tag::BATCH_TRANSACT, SHIELDED_POOL_PROGRAM_ID};

declare_id!("DNaxCngzaV7do7fnFSLv8KpkoYDksdAnKpNcKhoQwpsh");

pub const PAYOUT_CONFIG_SEED: &[u8] = b"payout_config";
const CONFIG_DISCRIMINATOR: u8 = 1;
/// Config layout: discriminator, admin address, bump.
const CONFIG_SIZE: usize = 1 + 32 + 1;

pub mod tag {
    pub const INIT: u8 = 0;
    pub const PAYOUT: u8 = 1;
}

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *ix_tag {
        tag::INIT => process_init_ix(accounts),
        tag::PAYOUT => process_payout_ix(accounts, payload),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Create the config PDA and store the admin. Accounts:
/// `[payer (signer), admin (signer), config PDA, system program]`.
pub fn process_init_ix(accounts: &mut [AccountView]) -> ProgramResult {
    let [payer, admin, config, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected, bump) = derive_config(&crate::ID)?;
    if config.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    create_config_account(payer, config, bump)?;
    let mut data = config
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    if data.len() != CONFIG_SIZE || data[0] != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    data[0] = CONFIG_DISCRIMINATOR;
    data[1..33].copy_from_slice(admin.address().as_ref());
    data[33] = bump;
    Ok(())
}

/// Enforce the app policy, then settle all entries in one same-vk RLC.
/// Accounts: `[admin (signer), config, spp accounts...]` where the spp
/// accounts follow the `BatchTransact` builder layout (payer, input tree,
/// output tree, system placeholder, extra signers, shielded-pool program
/// last). `batch_bytes` is the `BatchTransact` body (count byte plus framed
/// entries) and passes through verbatim.
pub fn process_payout_ix(accounts: &mut [AccountView], batch_bytes: &[u8]) -> ProgramResult {
    let (admin, rest) = accounts
        .split_first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (config, spp_accounts) = rest
        .split_first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !config.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = config
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    if data.len() != CONFIG_SIZE || data[0] != CONFIG_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if admin.address().as_ref() != &data[1..33] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    drop(data);

    cpi_spp_batch_transact(spp_accounts, batch_bytes)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_config(program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Ok(Address::find_program_address(
        &[PAYOUT_CONFIG_SEED],
        program_id,
    ))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_config(_program_id: &Address) -> Result<(Address, u8), ProgramError> {
    unimplemented!("derive_config requires Solana runtime syscalls")
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn create_config_account(
    payer: &AccountView,
    config: &mut AccountView,
    bump: u8,
) -> ProgramResult {
    use pinocchio::cpi::{Seed, Signer};
    let bump_seed = [bump];
    let seeds = [
        Seed::from(PAYOUT_CONFIG_SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        config,
        CONFIG_SIZE,
        &crate::ID,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn create_config_account(
    _payer: &AccountView,
    _config: &mut AccountView,
    _bump: u8,
) -> ProgramResult {
    unimplemented!("create_config_account requires Solana runtime syscalls")
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn cpi_spp_batch_transact(spp_accounts: &[AccountView], batch_bytes: &[u8]) -> ProgramResult {
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if spp_program_account.address() != &spp_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Signer privileges pass through: the fee payer signed the outer
    // transaction, and each entry's eddsa signer index resolves to it.
    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(account.address(), account.is_writable(), account.is_signer())
        })
        .collect();
    let mut instruction_data = Vec::with_capacity(1 + batch_bytes.len());
    instruction_data.push(BATCH_TRANSACT);
    instruction_data.extend_from_slice(batch_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };
    invoke_with_bounds::<16, _>(&instruction, spp_accounts)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn cpi_spp_batch_transact(_spp_accounts: &[AccountView], _batch_bytes: &[u8]) -> ProgramResult {
    unimplemented!("cpi_spp_batch_transact requires Solana runtime syscalls")
}
