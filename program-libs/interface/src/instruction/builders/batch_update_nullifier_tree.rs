use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData, CompressedProof},
    pda, PROGRAM_ID_PUBKEY,
};

pub struct BatchUpdateNullifierTree {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub new_root: [u8; 32],
    pub old_root: [u8; 32],
    pub zkp_batch_index: u16,
    pub compressed_proof_a: [u8; 32],
    pub compressed_proof_b: [u8; 64],
    pub compressed_proof_c: [u8; 32],
}

impl BatchUpdateNullifierTree {
    pub fn instruction(&self) -> Instruction {
        let data = BatchUpdateNullifierTreeData {
            new_root: self.new_root,
            old_root: self.old_root,
            zkp_batch_index: self.zkp_batch_index,
            compressed_proof: CompressedProof {
                a: self.compressed_proof_a,
                b: self.compressed_proof_b,
                c: self.compressed_proof_c,
            },
        };

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            ],
            data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data),
        }
    }
}
