use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};
use spl_token_2022_interface::{extension::PodStateWithExtensions, pod::PodAccount};
use zolana_interface::{
    error::ShieldedPoolError, SHIELDED_POOL_CPI_AUTHORITY_BUMP,
    SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED, SPL_TOKEN_TRANSFER_CHECKED_DISCRIMINATOR,
};

use super::account::{SplDepositAccounts, SplWithdrawalAccounts};

pub struct SplTransferCpi<'a> {
    pub token_program: &'a AccountView,
    pub from: &'a AccountView,
    pub mint: &'a AccountView,
    pub to: &'a AccountView,
    pub authority: &'a AccountView,
    pub amount: u64,
    pub decimals: u8,
}

impl SplTransferCpi<'_> {
    #[inline(always)]
    pub fn invoke(self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(self, signers: &[Signer]) -> ProgramResult {
        let instruction_accounts = [
            InstructionAccount::writable(self.from.address()),
            InstructionAccount::readonly(self.mint.address()),
            InstructionAccount::writable(self.to.address()),
            InstructionAccount::readonly_signer(self.authority.address()),
        ];
        let mut instruction_data = [0u8; 10];
        instruction_data[0] = SPL_TOKEN_TRANSFER_CHECKED_DISCRIMINATOR;
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());
        instruction_data[9] = self.decimals;
        let instruction = InstructionView {
            program_id: self.token_program.address(),
            accounts: &instruction_accounts,
            data: &instruction_data,
        };
        invoke_signed(
            &instruction,
            &[self.from, self.mint, self.to, self.authority],
            signers,
        )
    }
}

#[inline(never)]
#[profile]
pub fn settle_spl_deposit(settlement: &SplDepositAccounts<'_>, amount: u64) -> ProgramResult {
    let interface_amount_before = token_account_amount(settlement.spl_interface_account)?;
    SplTransferCpi {
        token_program: settlement.token_program_account,
        from: settlement.user_token_account,
        mint: settlement.mint_account,
        to: settlement.spl_interface_account,
        authority: settlement.token_authority_account,
        amount,
        decimals: settlement.decimals,
    }
    .invoke()?;

    let interface_amount_after = token_account_amount(settlement.spl_interface_account)?;
    let expected_interface_amount = interface_amount_before
        .checked_add(amount)
        .ok_or(ShieldedPoolError::PublicSettlementFailed)?;
    if interface_amount_after != expected_interface_amount {
        return Err(ShieldedPoolError::PublicSettlementFailed.into());
    }

    Ok(())
}

#[inline(never)]
#[profile]
pub fn settle_spl_withdrawal(settlement: &SplWithdrawalAccounts<'_>, amount: u64) -> ProgramResult {
    let bump = [SHIELDED_POOL_CPI_AUTHORITY_BUMP];
    let seeds = [
        Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    SplTransferCpi {
        token_program: settlement.token_program_account,
        from: settlement.spl_interface_account,
        mint: settlement.mint_account,
        to: settlement.user_token_account,
        authority: settlement.cpi_authority_account,
        amount,
        decimals: settlement.decimals,
    }
    .invoke_signed(core::slice::from_ref(&signer))
}

/// Read the transferable base balance. Token-2022 extension balances such as
/// `withheld_amount` deliberately do not count as vault collateral.
fn token_account_amount(account: &AccountView) -> Result<u64, ProgramError> {
    let data = account
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    let state = PodStateWithExtensions::<PodAccount>::unpack(&data)
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    Ok(u64::from(state.base.amount))
}
