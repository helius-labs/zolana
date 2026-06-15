use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, ZoneProoflessShieldIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

/// Build a zone-mediated proofless SOL shield instruction. Unlike the direct
/// path this targets the zone program (which CPIs into the pool), so the zone
/// program id and its zone-auth PDA are caller-supplied; the canonical SPP
/// program id and CPI authority remain fixed protocol constants.
pub fn zone_proofless_shield(
    zone_program_id: Pubkey,
    zone_auth: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    data: &ZoneProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id: zone_program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(zone_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ],
        data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, data),
    }
}
