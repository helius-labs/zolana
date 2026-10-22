//! `execute_proposal` (tag 13) instruction builder (spec: squads
//! `execute_proposal`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, ExecuteProposalIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `execute_proposal` instruction.
///
/// Account order: `payer`, `co_signer`, `ring_config`, `proposal`,
/// `sender_viewing_key_account`, an optional `recipient_viewing_key_account`
/// (transfer only), `rent_recipient`, then `spp_accounts`: the SPP
/// `ring_transact` / `ring_authority_transact` account list, forwarded
/// unchanged.
pub struct ExecuteProposal {
    pub payer: Pubkey,
    pub co_signer: Pubkey,
    pub ring_config: Pubkey,
    pub proposal: Pubkey,
    pub sender_viewing_key_account: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    pub recipient_viewing_key_account: Option<Pubkey>,
    pub rent_recipient: Pubkey,
    pub spp_accounts: Vec<AccountMeta>,
    pub data: ExecuteProposalIxData,
}

impl ExecuteProposal {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::EXECUTE_PROPOSAL];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.co_signer, true),
            AccountMeta::new_readonly(self.ring_config, false),
            AccountMeta::new(self.proposal, false),
            AccountMeta::new_readonly(self.sender_viewing_key_account, false),
        ];
        if let Some(recipient) = self.recipient_viewing_key_account {
            accounts.push(AccountMeta::new_readonly(recipient, false));
        }
        accounts.push(AccountMeta::new(self.rent_recipient, false));
        accounts.extend(self.spp_accounts.iter().cloned());

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
