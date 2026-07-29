use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};

/// Initialize a batch queue (tag 54). The queue account is created in the same
/// transaction with the program as owner and
/// `state::batch_queue::QUEUE_ACCOUNT_SIZE` bytes.
pub struct CreateBatchQueue {
    pub payer: Pubkey,
    pub operator: Pubkey,
    pub queue: Pubkey,
    /// Confidential eddsa shape: inputs, outputs, public slots.
    pub circuit: (u8, u8, u8),
}

impl CreateBatchQueue {
    pub fn instruction(&self) -> Instruction {
        let (inputs, outputs, slots) = self.circuit;
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.operator, true),
                AccountMeta::new(self.queue, false),
            ],
            data: vec![tag::CREATE_BATCH_QUEUE, 0, inputs, outputs, slots],
        }
    }
}

/// Enqueue one pure-shielded entry (tag 55). The entry's eddsa signers co-sign
/// this transaction, which records the spend authorization in the queue.
/// Signer index 0 is the operator. List additional signers only for entries
/// whose inputs name other owners.
pub struct EnqueueTransact {
    pub operator: Pubkey,
    pub queue: Pubkey,
    /// Extra signer accounts at index 2 and up.
    pub entry_signers: Vec<Pubkey>,
    pub data: TransactIxData,
}

impl EnqueueTransact {
    pub fn instruction(&self) -> Instruction {
        let mut data = vec![tag::ENQUEUE_TRANSACT];
        data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("transact serialization is infallible"),
        );
        let mut accounts = vec![
            AccountMeta::new_readonly(self.operator, true),
            AccountMeta::new(self.queue, false),
        ];
        for signer in &self.entry_signers {
            accounts.push(AccountMeta::new_readonly(*signer, true));
        }
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        }
    }
}

/// Verify every enqueued entry in one RLC (tag 56).
pub struct ExecuteBatchVerify {
    pub operator: Pubkey,
    pub queue: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
}

impl ExecuteBatchVerify {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.operator, true),
                AccountMeta::new(self.queue, false),
                AccountMeta::new(self.input_tree, false),
                AccountMeta::new(self.output_tree, false),
            ],
            data: vec![tag::EXECUTE_BATCH_VERIFY],
        }
    }
}

/// Apply a slice of verified entries (tag 57). The operator pays the forester
/// fees, so it is writable. The trailing program account serves the per-entry
/// event self-CPI.
pub struct ApplyBatch {
    pub operator: Pubkey,
    pub queue: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
}

impl ApplyBatch {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.operator, true),
                AccountMeta::new(self.queue, false),
                AccountMeta::new(self.input_tree, false),
                AccountMeta::new(self.output_tree, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            ],
            data: vec![tag::APPLY_BATCH],
        }
    }
}

/// Close an applied or empty queue (tag 58).
pub struct CloseBatchQueue {
    pub operator: Pubkey,
    pub queue: Pubkey,
    pub rent_recipient: Pubkey,
}

impl CloseBatchQueue {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.operator, true),
                AccountMeta::new(self.queue, false),
                AccountMeta::new(self.rent_recipient, false),
            ],
            data: vec![tag::CLOSE_BATCH_QUEUE],
        }
    }
}
