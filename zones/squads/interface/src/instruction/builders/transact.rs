//! `transact` (tag 0) instruction builder (spec: squads `transact`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Withdrawal settlement accounts, selecting the asset rail. Forwarded after the
/// tree account to SPP's `zone_transact`, which settles a negative public amount.
/// Shared by `transact` and `execute_proposal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactWithdrawal {
    /// Native SOL: SPP moves lamports from `sol_interface` to `recipient`,
    /// signing the transfer, so the system program is forwarded for that CPI.
    Sol {
        sol_interface: Pubkey,
        recipient: Pubkey,
    },
    /// SPL: SPP moves tokens from the per-mint `vault` to `user_token_account`,
    /// signed by `cpi_authority`.
    Spl {
        cpi_authority: Pubkey,
        vault: Pubkey,
        recipient: Pubkey,
        user_token_account: Pubkey,
        token_program: Pubkey,
    },
}

impl TransactWithdrawal {
    /// Append this rail's settlement account metas in SPP's `zone_transact`
    /// settlement order.
    pub fn push_account_metas(&self, accounts: &mut Vec<AccountMeta>) {
        match *self {
            TransactWithdrawal::Sol {
                sol_interface,
                recipient,
            } => {
                accounts.push(AccountMeta::new(sol_interface, false));
                accounts.push(AccountMeta::new(recipient, false));
                accounts.push(AccountMeta::new_readonly(Pubkey::default(), false));
            }
            TransactWithdrawal::Spl {
                cpi_authority,
                vault,
                recipient,
                user_token_account,
                token_program,
            } => {
                accounts.push(AccountMeta::new_readonly(cpi_authority, false));
                accounts.push(AccountMeta::new(vault, false));
                accounts.push(AccountMeta::new(recipient, false));
                accounts.push(AccountMeta::new(user_token_account, false));
                accounts.push(AccountMeta::new_readonly(token_program, false));
            }
        }
    }
}

/// Builder for the `transact` instruction.
///
/// Account order: `payer`, `co_signer`, `zone_config`,
/// `sender_viewing_key_account`, an optional `recipient_viewing_key_account`
/// (transfer only), `zone_auth`, `spp_program`, then the `tree_accounts` tail.
/// For a withdrawal the recipient viewing key account is absent and the
/// settlement accounts follow the (single) tree account, surfaced via
/// `withdrawal`.
pub struct Transact {
    pub payer: Pubkey,
    pub co_signer: Pubkey,
    pub zone_config: Pubkey,
    pub sender_viewing_key_account: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    pub recipient_viewing_key_account: Option<Pubkey>,
    /// Withdrawal settlement accounts, present only for a withdrawal.
    pub withdrawal: Option<TransactWithdrawal>,
    pub zone_auth: Pubkey,
    pub spp_program: Pubkey,
    /// SPP tree accounts touched by the transaction; remaining accounts.
    pub tree_accounts: Vec<Pubkey>,
    pub data: TransactIxData,
}

impl Transact {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.co_signer, true),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new_readonly(self.sender_viewing_key_account, false),
        ];
        if let Some(recipient) = self.recipient_viewing_key_account {
            accounts.push(AccountMeta::new_readonly(recipient, false));
        }
        accounts.push(AccountMeta::new_readonly(self.zone_auth, false));
        accounts.push(AccountMeta::new_readonly(self.spp_program, false));
        for tree in &self.tree_accounts {
            accounts.push(AccountMeta::new(*tree, false));
        }
        if let Some(withdrawal) = &self.withdrawal {
            withdrawal.push_account_metas(&mut accounts);
        }

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
