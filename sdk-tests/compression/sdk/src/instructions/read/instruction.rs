use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::pda::nullifier_pda;

use crate::{err, tag, ReadIxData, ReadProof};

pub struct Read {
    pub authority: Address,
    pub tree: Address,
    pub value: u64,
    pub version: u64,
    pub blinding: [u8; 32],
    /// Nullifier of the UTXO being read; its nullifier PDA must not exist.
    pub nullifier: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: ReadProof,
}

impl Read {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            authority,
            tree,
            value,
            version,
            blinding,
            nullifier,
            nullifier_tree_root_index,
            utxo_tree_root_index,
            proof,
        } = self;

        let serialized_ix = wincode::serialize(&ReadIxData {
            value,
            version,
            blinding,
            nullifier_tree_root_index,
            utxo_tree_root_index,
            proof,
        })
        .map_err(err)?;
        let mut instruction_data = vec![tag::READ];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: compression_example_program::ID,
            accounts: vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(tree, false),
                AccountMeta::new_readonly(nullifier_pda(&tree, &nullifier).0, false),
            ],
            data: instruction_data,
        })
    }
}
