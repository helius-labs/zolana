use light_account_checks::{checks::check_signer, AccountIterator};
use pinocchio::{address::Address, error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::TransactIxDataRef,
};

use crate::instructions::{
    settlement::{
        validate_cpi_authority, validate_sol_interface, validate_spl_settlement, Settlement,
        SettlementAccountsSol, SettlementAccountsSpl,
    },
    shared::{verify_cpi_signer, CPI_SIGNER_SEED},
};

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub tree: &'a mut AccountView,
    pub settlement: Option<Settlement<'a>>,
    pub spl_mint: Option<[u8; 32]>,
}

impl<'a> TransactAccounts<'a> {
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let payer: &AccountView = iter.next_signer("payer")?;
        let tree = iter.next_mut("tree")?;

        if let Some(signer) = ix.cpi_signer.as_ref() {
            let account: &AccountView = iter.next_signer("cpi_signer")?;
            verify_cpi_signer(
                account.address(),
                &signer.program_id,
                signer.bump,
                CPI_SIGNER_SEED,
                ShieldedPoolError::UnauthorizedCaller,
            )?;
        }

        let mut spl_mint = None;
        let settlement = if ix.is_deposit_or_withdrawal() {
            if ix.is_spl() {
                let cpi_authority = if ix.is_deposit() {
                    None
                } else {
                    Some(validate_cpi_authority(iter.next_account("cpi_authority")?)?)
                };
                let vault = iter.next_account("vault")?;
                let recipient = iter.next_account("recipient")?;
                let user_token_account = iter.next_account("user_token_account")?;
                let token_program = iter.next_account("token_program")?;
                spl_mint = Some(validate_spl_settlement(
                    program_id,
                    vault,
                    user_token_account,
                    token_program,
                )?);
                Some(Settlement::Spl(SettlementAccountsSpl {
                    cpi_authority,
                    vault,
                    recipient,
                    user_token_account,
                    token_program,
                }))
            } else {
                let sol_interface = iter.next_account("sol_interface")?;
                let sol_interface_bump = validate_sol_interface(program_id, sol_interface)?;
                let recipient = iter.next_account("recipient")?;
                Some(Settlement::Sol(SettlementAccountsSol {
                    sol_interface,
                    sol_interface_bump,
                    recipient,
                }))
            }
        } else {
            None
        };

        Ok(Self {
            payer,
            tree,
            settlement,
            spl_mint,
        })
    }
}

#[inline(always)]
pub fn validate_input_signer(account: &AccountView) -> Result<[u8; 32], ProgramError> {
    check_signer(account)?;
    Ok(account.address().to_bytes())
}
