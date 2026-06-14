use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{encode_instruction, tag, ProoflessShieldIxData, ZoneProoflessShieldIxData},
    ZONE_AUTH_PDA_SEED,
};

pub const ZONE_TEST_PROGRAM_ID: [u8; 32] = *b"zone_test_program_aaaaaaaaaaaaaa";

pub fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

pub fn zone_auth_pda(zone_program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], zone_program_id)
}

pub fn proofless_shield_sol_instruction(
    program_id: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    cpi_authority: Pubkey,
    data: &ProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(cpi_authority, false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: encode_instruction(tag::PROOFLESS_SHIELD, data),
    }
}

pub fn zone_proofless_shield_sol_instruction(
    shielded_pool_program_id: Pubkey,
    zone_program_id: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    zone_auth: Pubkey,
    cpi_authority: Pubkey,
    data: &ZoneProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id: zone_program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(zone_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(cpi_authority, false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(shielded_pool_program_id, false),
        ],
        data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, data),
    }
}
