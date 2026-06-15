use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, ProoflessShieldIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

/// Build a direct (non-zone) proofless SOL shield instruction. The pool's CPI
/// authority PDA doubles as the SOL vault, so the depositor signs and also
/// appears as the writable funding source; the canonical SPP program id is
/// passed back as the trailing program account the handler expects.
pub fn proofless_shield(
    tree: Pubkey,
    depositor: Pubkey,
    data: &ProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ],
        data: encode_instruction(tag::PROOFLESS_SHIELD, data),
    }
}
