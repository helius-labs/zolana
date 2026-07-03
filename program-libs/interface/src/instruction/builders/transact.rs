use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY, SOL_INTERFACE_PUBKEY,
};

/// SOL accounts for a `transact` that moves a public SOL amount. The
/// `sol_interface` custody PDA is canonical, so only the `recipient` varies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSolWithdrawal {
    pub recipient: Pubkey,
}

/// SPL accounts for a `transact` that moves a public SPL amount. `cpi_authority`
/// is present only for withdrawals (the program signs the token transfer out of
/// the vault); shields omit it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactSplWithdrawal {
    pub cpi_authority: Option<Pubkey>,
    pub spl_token_interface: Pubkey,
    pub recipient: Pubkey,
    pub user_token_account: Pubkey,
    pub token_program: Pubkey,
}

/// Public-amount accounts for a `transact`. A pure shielded transfer carries no
/// public amount (`Transact::withdrawal == None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactWithdrawal {
    Sol(TransactSolWithdrawal),
    Spl(TransactSplWithdrawal),
}

/// Builder for the `transact` instruction. The account layout mirrors the
/// program loader (`TransactAccounts::validate_and_parse`): `payer`, `tree`, the
/// optional public-amount accounts (present iff the data carries a public
/// amount), and the program account last for the `emit_event` self-CPI.
pub struct Transact {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub withdrawal: Option<TransactWithdrawal>,
    pub data: TransactIxData,
}

impl Transact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.tree, false),
        ];
        match &self.withdrawal {
            Some(TransactWithdrawal::Sol(sol)) => {
                accounts.push(AccountMeta::new(SOL_INTERFACE_PUBKEY, false));
                accounts.push(AccountMeta::new(sol.recipient, false));
                // System program for the `settle_sol` Transfer CPI.
                accounts.push(AccountMeta::new_readonly(Pubkey::default(), false));
            }
            Some(TransactWithdrawal::Spl(spl)) => {
                if let Some(cpi_authority) = spl.cpi_authority {
                    accounts.push(AccountMeta::new_readonly(cpi_authority, false));
                }
                accounts.push(AccountMeta::new(spl.spl_token_interface, false));
                accounts.push(AccountMeta::new(spl.recipient, false));
                accounts.push(AccountMeta::new(spl.user_token_account, false));
                accounts.push(AccountMeta::new_readonly(spl.token_program, false));
            }
            None => {}
        }
        // Program account, loadable for the `emit_event` self-CPI.
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
