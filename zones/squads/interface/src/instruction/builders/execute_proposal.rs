//! `execute_proposal` (tag 13) instruction builder (spec: squads
//! `execute_proposal`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::TransactWithdrawal, tag, ExecuteProposalIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `execute_proposal` instruction.
///
/// Account order mirrors the spec's `execute_proposal` "Accounts" list: `payer`,
/// `co_signer`, `zone_config`, `proposal`, `sender_viewing_key_account`, an
/// optional `recipient_viewing_key_account` (transfer only), `rent_recipient`,
/// `zone_auth`, `spp_program`, then the `tree_accounts` tail, with the withdrawal
/// settlement accounts following the tree for a withdrawal.
pub struct ExecuteProposal {
    pub payer: Pubkey,
    pub co_signer: Pubkey,
    pub zone_config: Pubkey,
    pub proposal: Pubkey,
    pub sender_viewing_key_account: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    pub recipient_viewing_key_account: Option<Pubkey>,
    /// Withdrawal settlement accounts, present only for a withdrawal.
    pub withdrawal: Option<TransactWithdrawal>,
    pub rent_recipient: Pubkey,
    pub zone_auth: Pubkey,
    pub spp_program: Pubkey,
    /// SPP Tree accounts touched by the transaction; remaining accounts.
    pub tree_accounts: Vec<Pubkey>,
    pub data: ExecuteProposalIxData,
}

impl ExecuteProposal {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::EXECUTE_PROPOSAL];
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
            AccountMeta::new(self.proposal, false),
            AccountMeta::new_readonly(self.sender_viewing_key_account, false),
        ];
        if let Some(recipient) = self.recipient_viewing_key_account {
            accounts.push(AccountMeta::new_readonly(recipient, false));
        }
        accounts.push(AccountMeta::new(self.rent_recipient, false));
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
