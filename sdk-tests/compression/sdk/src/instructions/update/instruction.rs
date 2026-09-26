use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::instruction_data::transact::TransactProof, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::{compression::CompressedAccountMeta, instruction::nullifier_pda_accounts};

use crate::{account_pda, err, tag, UpdateIxData};

pub struct Update {
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    /// The UTXO being spent, with the root indexes it is proven against.
    pub meta: CompressedAccountMeta,
    /// Nullifier of the UTXO being spent, whose nullifier PDA the transaction
    /// creates.
    pub input_nullifier: [u8; 32],
    pub old_value: u64,
    pub version: u64,
    pub new_value: u64,
    pub proof: TransactProof,
}

impl Update {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            input_tree,
            output_tree,
            meta,
            input_nullifier,
            old_value,
            version,
            new_value,
            proof,
        } = self;

        let serialized_ix = wincode::serialize(&UpdateIxData {
            old_value,
            version,
            new_value,
            meta,
            proof,
        })
        .map_err(err)?;

        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(output_tree, false),
            AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new(input_tree, false),
        ];
        accounts.extend(nullifier_pda_accounts(&input_tree, [&input_nullifier]));
        accounts.push(AccountMeta::new_readonly(account_pda(&payer), false));
        let mut instruction_data = vec![tag::UPDATE];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: compression_example_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
