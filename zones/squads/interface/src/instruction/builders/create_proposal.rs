//! `create_proposal` (tag 11) instruction builder (spec: squads
//! `create_proposal`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateProposalIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `create_proposal` instruction.
///
/// Account order mirrors the spec's `create_proposal` "Accounts" list:
/// `fee_payer`, `proposal`, `viewing_key_account`, `system_program`, `owner`.
pub struct CreateProposal {
    pub fee_payer: Pubkey,
    pub proposal: Pubkey,
    pub viewing_key_account: Pubkey,
    pub system_program: Pubkey,
    pub owner: Pubkey,
    pub data: CreateProposalIxData,
}

impl CreateProposal {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::CREATE_PROPOSAL];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let accounts = vec![
            AccountMeta::new(self.fee_payer, true),
            AccountMeta::new(self.proposal, false),
            AccountMeta::new_readonly(self.viewing_key_account, false),
            AccountMeta::new_readonly(self.system_program, false),
            AccountMeta::new_readonly(self.owner, true),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
