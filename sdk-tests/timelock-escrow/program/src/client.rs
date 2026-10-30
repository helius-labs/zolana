use pinocchio::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::instruction::instruction_data::transact::TransactIxData;
use spr_program::{instruction::Transact, CompressedProof};

use crate::{
    circuits::escrow_authority,
    instructions::{escrow::EscrowArgs, withdraw::WithdrawArgs},
    tag, ID,
};

pub struct EscrowInstruction {
    pub creator: Address,
    pub tree: Address,
    pub proof: CompressedProof,
    pub viewing_pubkey: [u8; 33],
    pub transact: TransactIxData,
}

impl EscrowInstruction {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        ProgramTransact {
            tag: tag::ESCROW,
            args: wincode::serialize(&EscrowArgs {
                proof: self.proof,
                viewing_pubkey: self.viewing_pubkey,
            })?,
            accounts: vec![AccountMeta::new_readonly(self.creator, true)],
            // The creator owns the spent inputs, so the SPP proof binds it as
            // an owner signer ahead of the escrow authority PDA.
            owner_signers: vec![self.creator],
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
            owner_signers: Vec::new(),
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
    owner_signers: Vec<Address>,
    creator: Address,
    tree: Address,
}

impl ProgramTransact {
    fn instruction(self, data: TransactIxData) -> Result<Instruction, wincode::Error> {
        let Self {
            tag,
            args,
            mut accounts,
            owner_signers,
            creator,
            tree,
        } = self;
        let transact_data = data.serialize()?;
        let transact = Transact {
            payer: creator,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers,
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
