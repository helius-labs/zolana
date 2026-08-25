use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{account_pda, err, tag, UpdateIxData};

pub struct Update {
    pub payer: Address,
    pub tree: Address,
    pub old_value: u64,
    pub version: u64,
    pub new_value: u64,
    pub spp_proof: TransactIxData,
}

impl Update {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            old_value,
            version,
            new_value,
            spp_proof,
        } = self;

        let [input] = spp_proof.inputs.as_slice() else {
            return Err(anyhow!("SPP transact must spend exactly one input"));
        };
        let serialized_ix = wincode::serialize(&UpdateIxData {
            old_value,
            version,
            new_value,
            nullifier_tree_root_index: input.nullifier_tree_root_index,
            utxo_tree_root_index: input.utxo_tree_root_index,
            proof: spp_proof.proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(account_pda(&payer), false),
        ];
        let mut instruction_data = vec![tag::UPDATE];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: compression_example_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
