use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::sol_interface_pda;
use crate::{
    instruction::{tag, ProoflessShieldIxData},
    SHIELDED_POOL_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProoflessShieldAccounts {
    pub tree: Pubkey,
    pub depositor: Pubkey,
    pub spl: Option<ProoflessShieldSplAccounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProoflessShieldSplAccounts {
    pub user_token: Pubkey,
    pub vault: Pubkey,
    pub registry: Pubkey,
    pub token_program: Pubkey,
}

impl ProoflessShieldAccounts {
    pub fn sol(tree: Pubkey, depositor: Pubkey) -> Self {
        Self {
            tree,
            depositor,
            spl: None,
        }
    }

    pub fn spl(tree: Pubkey, depositor: Pubkey, spl: ProoflessShieldSplAccounts) -> Self {
        Self {
            tree,
            depositor,
            spl: Some(spl),
        }
    }

    pub fn account_metas(self) -> Vec<AccountMeta> {
        let mut accounts = vec![
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.depositor, true),
        ];
        match self.spl {
            Some(spl) => accounts.extend([
                AccountMeta::new(spl.user_token, false),
                AccountMeta::new(spl.vault, false),
                AccountMeta::new_readonly(spl.registry, false),
                AccountMeta::new_readonly(spl.token_program, false),
            ]),
            None => accounts.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(sol_interface_pda(), false),
                AccountMeta::new(self.depositor, false),
            ]),
        }
        accounts.push(AccountMeta::new_readonly(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            false,
        ));
        accounts
    }
}

pub fn proofless_shield(
    accounts: ProoflessShieldAccounts,
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
