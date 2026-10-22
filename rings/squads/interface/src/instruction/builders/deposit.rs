//! `deposit` (tag 1) instruction builder (spec: squads `deposit`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, DepositIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `deposit` instruction.
///
/// Account order: `recipient_viewing_key_account`, then `spp_accounts`: the SPP
/// `ring_deposit` account list for the single asset in `data.asset`, forwarded
/// unchanged (as produced by `zolana_program::instruction::RingDeposit`).
pub struct Deposit {
    pub recipient_viewing_key_account: Pubkey,
    pub spp_accounts: Vec<AccountMeta>,
    pub data: DepositIxData,
}

impl Deposit {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::DEPOSIT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        let mut accounts = vec![AccountMeta::new_readonly(
            self.recipient_viewing_key_account,
            false,
        )];
        accounts.extend(self.spp_accounts.iter().cloned());

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
