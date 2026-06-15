use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, ZoneProoflessShieldIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

pub fn zone_proofless_shield(
    zone_program_id: Pubkey,
    zone_auth: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    data: &ZoneProoflessShieldIxData,
) -> Instruction {
    build_zone_proofless_shield(zone_program_id, zone_auth, tree, depositor, data, false)
}

pub fn zone_proofless_shield_cpi(
    zone_auth: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    data: &ZoneProoflessShieldIxData,
) -> Instruction {
    build_zone_proofless_shield(
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        zone_auth,
        tree,
        depositor,
        data,
        true,
    )
}

fn build_zone_proofless_shield(
    program_id: Pubkey,
    zone_auth: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    data: &ZoneProoflessShieldIxData,
    zone_auth_signer: bool,
) -> Instruction {
    let mut instruction_data = vec![tag::ZONE_PROOFLESS_SHIELD];
    instruction_data.extend_from_slice(
        &data
            .serialize()
            .expect("zone proofless ix data serialization is infallible"),
    );

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(zone_auth, zone_auth_signer),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ],
        data: instruction_data,
    }
}
