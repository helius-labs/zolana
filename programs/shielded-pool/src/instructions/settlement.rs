use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::{
        TransactIxData, PUBLIC_AMOUNT_DEPOSIT, PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
    },
    SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED, SPL_ASSET_REGISTRY_ACCOUNT_LEN, SPL_ASSET_REGISTRY_MAGIC,
    SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_PROGRAM_ID,
};

use crate::{error::ShieldedPoolError, log::log};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);
const SPL_TOKEN_ACCOUNT_LEN: usize = 165;
const SPL_TOKEN_ACCOUNT_INITIALIZED: u8 = 1;
const SPL_TOKEN_TRANSFER_DISCRIMINATOR: u8 = 3;

pub struct SettlementAccounts<'a> {
    pub signer: &'a AccountView,
    pub solana_owner_pubkeys: Vec<[u8; 32]>,
    pub system_program: Option<&'a AccountView>,
    pub cpi_authority: Option<&'a AccountView>,
    pub cpi_authority_bump: Option<u8>,
    pub user_sol_account: Option<&'a AccountView>,
    pub user_spl_token_account: Option<&'a AccountView>,
    pub spl_token_interface: Option<&'a AccountView>,
    pub spl_asset_registry: Option<&'a AccountView>,
    pub token_program: Option<&'a AccountView>,
}

impl<'a> SettlementAccounts<'a> {
    pub const fn empty(signer: &'a AccountView) -> Self {
        Self {
            signer,
            solana_owner_pubkeys: Vec::new(),
            system_program: None,
            cpi_authority: None,
            cpi_authority_bump: None,
            user_sol_account: None,
            user_spl_token_account: None,
            spl_token_interface: None,
            spl_asset_registry: None,
            token_program: None,
        }
    }
}

pub fn settle_public_amounts(
    program_id: &Address,
    accounts: &SettlementAccounts<'_>,
    data: &TransactIxData,
) -> ProgramResult {
    let sol_amount = data.public_sol_amount.unwrap_or(0);
    let spl_amount = data.public_spl_amount.unwrap_or(0);

    match data.public_amount_mode {
        PUBLIC_AMOUNT_NONE => {
            if sol_amount != 0 || spl_amount != 0 || data.relayer_fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            return Ok(());
        }
        PUBLIC_AMOUNT_DEPOSIT => {
            if sol_amount == 0 && spl_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            if data.relayer_fee != 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        PUBLIC_AMOUNT_WITHDRAW => {
            if sol_amount == 0 && spl_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            // Relayer fees are paid in SOL, so SPL-only withdrawals cannot carry one.
            if data.relayer_fee != 0 && sol_amount == 0 {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
        }
        _ => return Err(ShieldedPoolError::InvalidTransactShape.into()),
    }

    if sol_amount != 0 {
        settle_sol(
            accounts,
            data.public_amount_mode,
            sol_amount,
            data.relayer_fee,
        )?;
    }
    if spl_amount != 0 {
        settle_spl(program_id, accounts, data.public_amount_mode, spl_amount)?;
    }

    Ok(())
}

fn settle_sol(
    accounts: &SettlementAccounts<'_>,
    public_amount_mode: u8,
    amount: u64,
    relayer_fee: u16,
) -> ProgramResult {
    let system_program = required(accounts.system_program)?;
    let cpi_authority = required(accounts.cpi_authority)?;
    let user_sol_account = required(accounts.user_sol_account)?;
    let relayer_fee = relayer_fee as u64;

    if *system_program.address() != SYSTEM_PROGRAM_ID
        || !cpi_authority.is_writable()
        || !user_sol_account.is_writable()
        || !cpi_authority.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    if public_amount_mode == PUBLIC_AMOUNT_DEPOSIT
        && *user_sol_account.address() != *accounts.signer.address()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    if public_amount_mode == PUBLIC_AMOUNT_WITHDRAW
        && relayer_fee != 0
        && !accounts.signer.is_writable()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let result = match public_amount_mode {
        PUBLIC_AMOUNT_DEPOSIT => pinocchio_system::instructions::Transfer {
            from: user_sol_account,
            to: cpi_authority,
            lamports: amount,
        }
        .invoke(),
        PUBLIC_AMOUNT_WITHDRAW => {
            let bump = [required(accounts.cpi_authority_bump)?];
            let seeds = [
                Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
                Seed::from(&bump),
            ];
            let signer = Signer::from(&seeds);
            pinocchio_system::instructions::Transfer {
                from: cpi_authority,
                to: user_sol_account,
                lamports: amount,
            }
            .invoke_signed(core::slice::from_ref(&signer))?;

            if relayer_fee != 0 {
                pinocchio_system::instructions::Transfer {
                    from: cpi_authority,
                    to: accounts.signer,
                    lamports: relayer_fee,
                }
                .invoke_signed(core::slice::from_ref(&signer))?;
            }

            Ok(())
        }
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    };

    result.map_err(|_| {
        log("transact: SOL public settlement failed");
        ProgramError::from(ShieldedPoolError::PublicSettlementFailed)
    })
}

fn settle_spl(
    program_id: &Address,
    accounts: &SettlementAccounts<'_>,
    public_amount_mode: u8,
    amount: u64,
) -> ProgramResult {
    let cpi_authority = required(accounts.cpi_authority)?;
    let user_token = required(accounts.user_spl_token_account)?;
    let vault = required(accounts.spl_token_interface)?;
    let registry = required(accounts.spl_asset_registry)?;
    let token_program = required(accounts.token_program)?;
    let spl_token_program_id = Address::from(SPL_TOKEN_PROGRAM_ID);

    if *token_program.address() != spl_token_program_id
        || !user_token.is_writable()
        || !vault.is_writable()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let user_token_state = read_token_account(user_token, token_program.address())?;
    let vault_state = read_token_account(vault, token_program.address())?;
    let registry_state = read_asset_registry(registry)?;

    if !registry.owned_by(program_id)
        || registry_state.mint != user_token_state.mint
        || registry_state.mint != vault_state.mint
        || vault_state.owner != *cpi_authority.address()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    // Pin the vault to its canonical per-mint PDA. owner+mint alone would accept
    // any cpi-authority-owned token account of the right mint, so deposits and
    // withdrawals for a mint could hit different accounts and split liquidity.
    let (expected_vault, _) = Address::derive_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, registry_state.mint.as_ref()],
        program_id,
    )
    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    if *vault.address() != expected_vault {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let result = match public_amount_mode {
        PUBLIC_AMOUNT_DEPOSIT => {
            if user_token_state.owner != *accounts.signer.address() {
                return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
            }
            invoke_token_transfer(
                token_program,
                user_token,
                vault,
                accounts.signer,
                amount,
                &[],
            )
        }
        PUBLIC_AMOUNT_WITHDRAW => {
            let bump = [required(accounts.cpi_authority_bump)?];
            let seeds = [
                Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
                Seed::from(&bump),
            ];
            let signer = Signer::from(&seeds);
            invoke_token_transfer(
                token_program,
                vault,
                user_token,
                cpi_authority,
                amount,
                core::slice::from_ref(&signer),
            )
        }
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    };

    result.map_err(|_| {
        log("transact: SPL public settlement failed");
        ProgramError::from(ShieldedPoolError::PublicSettlementFailed)
    })
}

fn invoke_token_transfer(
    token_program: &AccountView,
    from: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    signers: &[Signer],
) -> ProgramResult {
    let instruction_accounts = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_TOKEN_TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &instruction_accounts,
        data: &instruction_data,
    };
    invoke_signed(&instruction, &[from, to, authority], signers)
}

#[derive(Clone, Copy)]
struct TokenAccountState {
    mint: Address,
    owner: Address,
}

fn read_token_account(
    account: &AccountView,
    token_program: &Address,
) -> Result<TokenAccountState, ProgramError> {
    if !account.owned_by(token_program) || account.data_len() != SPL_TOKEN_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    if data[108] != SPL_TOKEN_ACCOUNT_INITIALIZED {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    Ok(TokenAccountState {
        mint: address_from_slice(&data[0..32]),
        owner: address_from_slice(&data[32..64]),
    })
}

#[derive(Clone, Copy)]
struct AssetRegistryState {
    mint: Address,
}

fn read_asset_registry(account: &AccountView) -> Result<AssetRegistryState, ProgramError> {
    if account.data_len() < SPL_ASSET_REGISTRY_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    if data[0..8] != SPL_ASSET_REGISTRY_MAGIC[..] {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(AssetRegistryState {
        mint: address_from_slice(&data[8..40]),
    })
}

pub fn spl_asset_pubkey(accounts: &SettlementAccounts<'_>) -> Result<Address, ProgramError> {
    let registry = required(accounts.spl_asset_registry)?;
    Ok(read_asset_registry(registry)?.mint)
}

fn address_from_slice(bytes: &[u8]) -> Address {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Address::from(out)
}

fn required<T: Copy>(value: Option<T>) -> Result<T, ProgramError> {
    value.ok_or_else(|| ShieldedPoolError::InvalidSettlementAccounts.into())
}
