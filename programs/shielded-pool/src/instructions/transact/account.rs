use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{PublicLeg, TransactIxDataRef},
        validate_public_legs,
    },
};

use crate::instructions::settlement::{
    validate_cpi_authority, validate_sol_interface, validate_spl_settlement, Settlement,
    SettlementAccountsSol, SettlementAccountsSpl,
};

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub tree: &'a mut AccountView,
    pub settlements: Vec<Settlement<'a>>,
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

    /// 1. Validate spl interface transfers.
    pub(crate) fn from_iter(
        mut iter: AccountIterator<'a>,
        ix: &TransactIxDataRef<'_>,
        payer: &'a AccountView,
        tree: &'a mut AccountView,
    ) -> Result<Self, ProgramError> {
        // Check no zero amounts and less than 255.
        validate_public_legs(&ix.public_legs)?;

        let mut settlements = Vec::with_capacity(ix.public_legs.len());
        for leg in &ix.public_legs {
            let settlement = match leg {
                PublicLeg::Spl {
                    is_deposit,
                    vault_bump,
                    ..
                } => {
                    let cpi_authority = if *is_deposit {
                        None
                    } else {
                        // Withdrawals move funds spl interface -> user, program cpi authority pda needs to sign.
                        Some(validate_cpi_authority(iter.next_account("cpi_authority")?)?)
                    };
                    let vault = iter.next_account("vault")?;
                    let recipient = iter.next_account("recipient")?;
                    let user_token_account = iter.next_account("user_token_account")?;
                    let token_program = iter.next_account("token_program")?;
                    let mint = validate_spl_settlement(
                        &crate::ID,
                        vault,
                        user_token_account,
                        token_program,
                        *vault_bump,
                    )?;
                    Settlement::Spl(SettlementAccountsSpl {
                        cpi_authority,
                        mint,
                        vault,
                        recipient,
                        user_token_account,
                        token_program,
                    })
                }
                PublicLeg::Sol { .. } => {
                    let sol_interface = iter.next_account("sol_interface")?;
                    let sol_interface_bump = validate_sol_interface(sol_interface)?;
                    let recipient = iter.next_account("recipient")?;
                    Settlement::Sol(SettlementAccountsSol {
                        sol_interface,
                        sol_interface_bump,
                        recipient,
                    })
                }
            };
            settlements.push(settlement);
        }
        let system_program = iter.next_account("system_program")?; // TODO: move before loop
        if !pinocchio_system::check_id(system_program.address()) {
            return Err(ShieldedPoolError::InvalidSystemProgram.into());
        }

        Ok(Self {
            payer,
            tree,
            settlements,
        })
    }
}
