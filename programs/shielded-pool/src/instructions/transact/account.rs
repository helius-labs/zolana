use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::TransactIxDataRef,
};

use crate::instructions::settlement::{
    validate_cpi_authority, validate_sol_interface, validate_spl_settlement, Settlement,
    SettlementAccountsSol, SettlementAccountsSpl,
};

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub tree: &'a mut AccountView,
    pub settlement: Option<Settlement<'a>>,
    pub spl_mint: Option<[u8; 32]>,
}

impl<'a> TransactAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);

        let payer: &AccountView = iter.next_signer("payer")?;
        let tree = iter.next_mut("tree")?;

        Self::from_iter(iter, ix, payer, tree)
    }

    /// Parse the cpi-signer and settlement accounts from an iterator already
    /// advanced past `payer` and `tree`. `zone_transact` reuses this after
    /// peeling off its extra `ZoneConfig` signer, so the two instructions share
    /// one settlement-account validation.
    pub(crate) fn from_iter(
        mut iter: AccountIterator<'a>,
        ix: &TransactIxDataRef<'_>,
        payer: &'a AccountView,
        tree: &'a mut AccountView,
    ) -> Result<Self, ProgramError> {
        if ix.cpi_signer.is_some() {
            return Err(ShieldedPoolError::ProgramCpiSignerDisabled.into());
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
                    &crate::ID,
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
                let sol_interface_bump = validate_sol_interface(&crate::ID, sol_interface)?;
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
