use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{instruction_data::transact::TransactProof, nullifier_pda_accounts},
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::{account_address, account_pda, err, tag, CreateIxData};

pub struct Create {
    pub payer: Address,
    pub tree: Address,
    pub new_value: u64,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: TransactProof,
}

impl Create {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            new_value,
            nullifier_tree_root_index,
            utxo_tree_root_index,
            proof,
        } = self;

        let serialized_ix = wincode::serialize(&CreateIxData {
            new_value,
            nullifier_tree_root_index,
            utxo_tree_root_index,
            proof,
        })
        .map_err(err)?;

        let pda = account_pda(&payer);
        let nullifier = account_address(&pda)?;
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Address::default(), false),
        ];
        accounts.extend(nullifier_pda_accounts(&tree, [&nullifier]));
        accounts.push(AccountMeta::new_readonly(pda, false));
        let mut instruction_data = vec![tag::CREATE];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: compression_example_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
