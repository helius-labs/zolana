use pinocchio::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_program::{instruction::Transact, CompressedProof};

use crate::{circuits::escrow_authority, instructions::withdraw::WithdrawArgs, tag, ID};

pub struct EscrowInstruction {
    pub creator: Address,
    pub tree: Address,
    pub proof: CompressedProof,
    pub transact: TransactIxData,
}

impl EscrowInstruction {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        ProgramTransact {
            tag: tag::ESCROW,
            args: wincode::serialize(&self.proof)?,
            accounts: vec![AccountMeta::new_readonly(self.creator, true)],
            creator: self.creator,
            tree: self.tree,
        }
        .instruction(self.transact)
    }
}

pub struct WithdrawInstruction {
    pub creator: Address,
    pub tree: Address,
    pub proof: CompressedProof,
    pub unlock_timestamp: u64,
    pub transact: TransactIxData,
}

impl WithdrawInstruction {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        ProgramTransact {
            tag: tag::WITHDRAW,
            args: wincode::serialize(&WithdrawArgs {
                proof: self.proof,
                unlock_timestamp: self.unlock_timestamp,
            })?,
            accounts: vec![
                AccountMeta::new(self.creator, true),
                AccountMeta::new_readonly(self.creator, true),
            ],
            creator: self.creator,
            tree: self.tree,
        }
        .instruction(self.transact)
    }
}

struct ProgramTransact {
    tag: u8,
    args: Vec<u8>,
    accounts: Vec<AccountMeta>,
    creator: Address,
    tree: Address,
}

impl ProgramTransact {
    fn instruction(self, data: TransactIxData) -> Result<Instruction, wincode::Error> {
        let Self {
            tag,
            args,
            mut accounts,
            creator,
            tree,
        } = self;
        let transact_data = data.serialize()?;
        let transact = Transact {
            payer: creator,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data,
        };
        accounts.extend(transact.cpi_accounts(&[*escrow_authority(&creator).pda()]));
        let mut instruction_data = vec![tag];
        instruction_data.extend(args);
        instruction_data.extend(transact_data);
        Ok(Instruction {
            program_id: ID,
            accounts,
            data: instruction_data,
        })
    }
}
