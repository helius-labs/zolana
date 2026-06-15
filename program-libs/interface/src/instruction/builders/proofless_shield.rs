use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, ProoflessShieldIxData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

pub struct ProoflessShieldSplAccounts {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub cpi_authority: Pubkey,
    pub user_token: Pubkey,
    pub vault: Pubkey,
    pub registry: Pubkey,
    pub token_program: Pubkey,
    pub shielded_pool_program: Pubkey,
}

impl ProoflessShieldSplAccounts {
    pub fn account_metas(self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
            AccountMeta::new_readonly(self.cpi_authority, false),
            AccountMeta::new(self.user_token, false),
            AccountMeta::new(self.vault, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new_readonly(self.token_program, false),
            AccountMeta::new_readonly(self.shielded_pool_program, false),
        ]
    }
}

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
        accounts: proofless_shield_sol_account_metas(tree, depositor),
        data: proofless_shield_data(data),
    }
}

pub fn proofless_shield_sol_account_metas(tree: Pubkey, depositor: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
        AccountMeta::new(depositor, false),
        AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
    ]
}

pub fn proofless_shield_spl(
    accounts: ProoflessShieldSplAccounts,
    data: &ProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: accounts.account_metas(),
        data: proofless_shield_data(data),
    }
}

fn proofless_shield_data(data: &ProoflessShieldIxData) -> Vec<u8> {
    let mut instruction_data = vec![tag::PROOFLESS_SHIELD];
    instruction_data.extend_from_slice(
        &data
            .serialize()
            .expect("proofless ix data serialization is infallible"),
    );
    instruction_data
}
