use light_program_profiler::profile;
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};
use rings_interface::{
    SHIELDED_POOL_CPI_AUTHORITY_BUMP, SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED,
    SPL_TOKEN_TRANSFER_DISCRIMINATOR,
};

use super::account::SettlementAccountsSpl;

pub struct SplTransferCpi<'a> {
    pub token_program: &'a AccountView,
    pub from: &'a AccountView,
    pub to: &'a AccountView,
    pub authority: &'a AccountView,
    pub amount: u64,
}

impl SplTransferCpi<'_> {
    #[inline(always)]
    pub fn invoke(self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(self, signers: &[Signer]) -> ProgramResult {
        let instruction_accounts = [
            InstructionAccount::writable(self.from.address()),
            InstructionAccount::writable(self.to.address()),
            InstructionAccount::readonly_signer(self.authority.address()),
        ];
        let mut instruction_data = [0u8; 9];
        instruction_data[0] = SPL_TOKEN_TRANSFER_DISCRIMINATOR;
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());
        let instruction = InstructionView {
            program_id: self.token_program.address(),
            accounts: &instruction_accounts,
            data: &instruction_data,
        };
        invoke_signed(&instruction, &[self.from, self.to, self.authority], signers)
    }
}

#[inline(never)]
#[profile]
pub fn settle_spl(settlement: &SettlementAccountsSpl<'_>, amount: u64) -> ProgramResult {
    match settlement.cpi_authority {
        Some(cpi_authority) => {
            let bump = [SHIELDED_POOL_CPI_AUTHORITY_BUMP];
            let seeds = [
                Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
                Seed::from(&bump),
            ];
            let signer = Signer::from(&seeds);
            SplTransferCpi {
                token_program: settlement.token_program,
                from: settlement.vault,
                to: settlement.user_token_account,
                authority: cpi_authority,
                amount,
            }
            .invoke_signed(core::slice::from_ref(&signer))
        }
        None => SplTransferCpi {
            token_program: settlement.token_program,
            from: settlement.user_token_account,
            to: settlement.vault,
            authority: settlement.recipient,
            amount,
        }
        .invoke(),
    }
}
