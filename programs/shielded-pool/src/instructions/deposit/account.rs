use light_account_checks::AccountIterator;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::deposit::CpiSignerData,
    state::SplAssetRegistry, SHIELDED_POOL_CPI_AUTHORITY, SPL_ASSET_VAULT_PDA_SEED,
    SPL_TOKEN_PROGRAM_ID,
};

use crate::instructions::{
    settlement::{
        read_token_account, validate_sol_interface, Settlement, SettlementAccountsSol,
        SettlementAccountsSpl,
    },
    shared::verify_cpi_signer,
};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

/// Validated accounts for a proofless deposit. `deposit` carries no SPP
/// proof, so the settlement accounts the proof would otherwise constrain (vault
/// PDA, asset registry, token-account mints/owners) are verified here on-chain.
pub struct DepositAccounts<'a> {
    pub tree: &'a mut AccountView,
    /// Reuses `transact`'s settlement shape; proofless deposits only ever produce
    /// the deposit variants (SOL into the interface, SPL into the vault).
    pub settlement: Settlement<'a>,
    /// Deposited asset: the SPL mint, or all-zero for native SOL.
    pub asset: [u8; 32],
}

impl<'a> DepositAccounts<'a> {
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &'a mut [AccountView],
        cpi_signer: Option<CpiSignerData>,
        cpi_signer_seed: &[u8],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let tree = iter.next_mut("tree")?;
        let depositor = iter.next_account("depositor")?;

        if let Some(signer) = cpi_signer {
            let account = iter.next_account("cpi_signer")?;
            verify_cpi_signer(
                account.address(),
                &signer.program_id,
                signer.bump,
                cpi_signer_seed,
                ShieldedPoolError::InvalidSettlementAccounts,
            )?;
        }

        // SOL settlement is 3 accounts, SPL is 4; with the trailing program
        // account that is 4 (SOL) or 5 (SPL) remaining. Pick the branch by
        // count and let each validator pin its own accounts. Malformed counts
        // fall out of the reads below: too few hits NotEnoughAccountKeys, too
        // many leaves the iterator non-empty (InvalidSettlementAccounts).
        let needs_spl = iter.len().saturating_sub(iter.position()) >= 5;

        let (settlement, asset) = if needs_spl {
            let user_token = iter.next_account("user_token")?;
            let vault = iter.next_account("vault")?;
            let registry = iter.next_account("registry")?;
            let token_program = iter.next_account("token_program")?;
            let mint = validate_spl(
                program_id,
                depositor,
                user_token,
                vault,
                registry,
                token_program,
            )?;
            (
                Settlement::Spl(SettlementAccountsSpl {
                    cpi_authority: None,
                    vault,
                    recipient: depositor,
                    user_token_account: user_token,
                    token_program,
                }),
                mint,
            )
        } else {
            let system_program = iter.next_account("system_program")?;
            let sol_interface = iter.next_account("sol_interface")?;
            let user_sol = iter.next_account("user_sol")?;
            let bump = validate_sol(
                program_id,
                depositor,
                system_program,
                sol_interface,
                user_sol,
            )?;
            (
                Settlement::Sol(SettlementAccountsSol {
                    sol_interface,
                    sol_interface_bump: bump,
                    recipient: user_sol,
                }),
                [0u8; 32],
            )
        };

        let program_account = iter.next_account("program")?;
        if !address_eq(program_account.address(), program_id) {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        if !iter.iterator_is_empty() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        Ok(Self {
            tree,
            settlement,
            asset,
        })
    }
}

/// Validate the native-SOL deposit accounts and return the interface PDA bump.
fn validate_sol(
    program_id: &Address,
    depositor: &AccountView,
    system_program: &AccountView,
    sol_interface: &AccountView,
    user_sol: &AccountView,
) -> Result<u8, ProgramError> {
    if !address_eq(system_program.address(), &SYSTEM_PROGRAM_ID)
        || !sol_interface.is_writable()
        || !user_sol.is_writable()
        || !sol_interface.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    // Deposit lamports leave the depositor; pin the funder to the signer.
    if !address_eq(user_sol.address(), depositor.address()) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    validate_sol_interface(program_id, sol_interface)
}

/// Validate the SPL deposit accounts and return the deposited mint. The vault is
/// pinned to its canonical per-mint PDA: owner+mint alone would accept any
/// cpi-authority-owned token account of the right mint, splitting liquidity.
fn validate_spl(
    program_id: &Address,
    depositor: &AccountView,
    user_token: &AccountView,
    vault: &AccountView,
    registry: &AccountView,
    token_program: &AccountView,
) -> Result<[u8; 32], ProgramError> {
    let spl_token_program_id = Address::from(SPL_TOKEN_PROGRAM_ID);
    if !address_eq(token_program.address(), &spl_token_program_id)
        || !user_token.is_writable()
        || !vault.is_writable()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let user_token_state = read_token_account(user_token, token_program.address())?;
    let vault_state = read_token_account(vault, token_program.address())?;
    let mint = read_asset_registry_mint(registry, program_id)?;
    let cpi_authority = SHIELDED_POOL_CPI_AUTHORITY;

    if mint != user_token_state.mint
        || mint != vault_state.mint
        || vault_state.owner != cpi_authority
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let (expected_vault, _) =
        Address::derive_program_address(&[SPL_ASSET_VAULT_PDA_SEED, mint.as_slice()], program_id)
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    if !address_eq(vault.address(), &expected_vault) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    // Deposit tokens leave the depositor's token account.
    if user_token_state.owner != depositor.address().to_bytes() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    Ok(mint)
}

fn read_asset_registry_mint(
    account: &AccountView,
    program_id: &Address,
) -> Result<[u8; 32], ProgramError> {
    if !account.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    let registry: &SplAssetRegistry = bytemuck::try_from_bytes(&data)
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    registry
        .check_discriminator()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    Ok(registry.mint.to_bytes())
}
