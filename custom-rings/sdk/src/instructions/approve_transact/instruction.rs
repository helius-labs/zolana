use custom_ring_program::instructions::approve_transact::{
    ApproveTransactIxData, APPROVAL_PDA_SEED,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{config_pda, tag, PROGRAM_ID};

/// The approval account of the transact with `private_tx_hash`.
pub fn approval_pda(private_tx_hash: &[u8; 32]) -> Address {
    Address::find_program_address(&[APPROVAL_PDA_SEED, private_tx_hash], &PROGRAM_ID).0
}

/// The approver signs off one transact; `transact` spends the approval.
pub struct ApproveTransact {
    /// The config's approver.
    pub approver: Address,
    /// Pays the approval account's rent, refunded to the transact's payer.
    pub payer: Address,
    pub private_tx_hash: [u8; 32],
}

impl ApproveTransact {
    pub fn instruction(self) -> Instruction {
        let mut data = vec![tag::APPROVE_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&ApproveTransactIxData {
                private_tx_hash: self.private_tx_hash,
            })
            .expect("approve_transact instruction data is fixed size"),
        );
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.approver, true),
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(approval_pda(&self.private_tx_hash), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data,
        }
    }
}
